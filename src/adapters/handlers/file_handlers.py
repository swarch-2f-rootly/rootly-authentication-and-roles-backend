"""
File upload FastAPI route handlers.
Handles profile photo upload and management endpoints.
"""

from uuid import UUID
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Response
from sqlalchemy.ext.asyncio import AsyncSession

from core.ports.file_storage import FileStorage
from core.ports.user_service import UserService
from core.ports.logger import Logger
from core.ports.exceptions import (
    UserNotFoundError,
    FileTooLargeError,
    InvalidFileTypeError,
    ExternalServiceError,
    ValidationError
)
from .models import (
    FileUploadResponse,
    FileMetadataResponse,
    ErrorResponse
)
from .dependencies import get_file_storage, get_user_service, get_logger, get_db_session
from .auth_handlers import get_current_user_required

router = APIRouter(prefix="/api/v1/users", tags=["file-management"])


async def get_file_storage_dependency() -> FileStorage:
    """Dependency injection for file storage."""
    return await get_file_storage()


async def get_user_service_dependency(session: AsyncSession = Depends(get_db_session)) -> UserService:
    """Dependency injection for user service."""
    return await get_user_service(session)


@router.post("/{user_id}/photo", response_model=FileUploadResponse)
async def upload_profile_photo(
    user_id: UUID,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user_required),
    file_storage: FileStorage = Depends(get_file_storage_dependency),
    user_service: UserService = Depends(get_user_service_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    Upload a profile photo for a user.

    Users can upload their own profile photo or admins can upload for any user.
    """
    try:
        logger.info("Starting profile photo upload", user_id=str(user_id),
                   filename=file.filename, content_type=file.content_type, requester_id=current_user.get('id'))

        # Check authorization - users can only upload their own photo unless they have admin permissions
        current_user_id = current_user.get('id')
        if str(user_id) != current_user_id:
            # TODO: Check if user has admin permissions
            # For now, allow self-upload only
            logger.warn("Unauthorized photo upload attempt", user_id=str(user_id), requester_id=current_user_id)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "FORBIDDEN",
                    "message": "You can only upload photos for your own profile",
                    "timestamp": "AuthorizationError"
                }
            )

        # Validate file
        if not file.filename:
            raise ValidationError("Filename is required")

        # Read file content
        file_content = await file.read()
        file_size = len(file_content)
        logger.debug("File content read", file_size=file_size)

        # Validate file size
        logger.debug("Validating file size", file_size=file_size)
        if not await file_storage.validate_file_size(file_size):
            logger.warn("File size validation failed", file_size=file_size)
            raise FileTooLargeError("File size exceeds maximum allowed limit")

        # Validate file type
        content_type = file.content_type or "application/octet-stream"
        logger.debug("Validating file type", content_type=content_type, filename=file.filename)

        if not await file_storage.validate_file_type(content_type, file.filename):
            logger.warn("File type validation failed", content_type=content_type, filename=file.filename)
            raise InvalidFileTypeError("File type not allowed for profile photos")

        # Upload file
        logger.debug("Calling file storage upload", user_id=str(user_id))
        upload_result = await file_storage.upload_profile_photo(
            user_id=user_id,
            file_data=file_content,
            filename=file.filename,
            content_type=content_type,
            file_size=file_size
        )
        file_url = upload_result["url"]
        unique_filename = upload_result["filename"]
        logger.info("File uploaded to storage", user_id=str(user_id), file_url=file_url, filename=unique_filename)

        # Update user profile with photo filename (not URL)
        logger.debug("Updating user profile with photo filename", user_id=str(user_id), filename=unique_filename)
        updated_user = await user_service.update_user_profile_photo_filename(
            user_id=user_id,
            profile_photo_filename=unique_filename
        )
        logger.debug("User profile updated with photo filename", user_id=str(user_id))

        response = FileUploadResponse(
            filename=file.filename,
            url=file_url,
            content_type=content_type,
            size=len(file_content),
            uploaded_at=datetime.now()
        )

        logger.info("Profile photo uploaded successfully", user_id=str(user_id), filename=file.filename)
        return response

    except UserNotFoundError as e:
        logger.warn("User not found for photo upload", user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "USER_NOT_FOUND",
                "message": str(e),
                "timestamp": "UserNotFoundError"
            }
        )
    except FileTooLargeError as e:
        logger.warn("File too large for upload", user_id=str(user_id), filename=file.filename, size=len(file_content))
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "error": "FILE_TOO_LARGE",
                "message": str(e),
                "timestamp": "FileTooLargeError"
            }
        )
    except InvalidFileTypeError as e:
        logger.warn("Invalid file type for upload", user_id=str(user_id), filename=file.filename, content_type=content_type)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "INVALID_FILE_TYPE",
                "message": str(e),
                "timestamp": "InvalidFileTypeError"
            }
        )
    except ExternalServiceError as e:
        logger.error("External service error during upload", error=str(e), user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "EXTERNAL_SERVICE_ERROR",
                "message": str(e),
                "timestamp": "ExternalServiceError"
            }
        )
    except ValidationError as e:
        logger.warn("Validation error during upload", user_id=str(user_id), error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "VALIDATION_ERROR",
                "message": str(e),
                "timestamp": "ValidationError"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Upload profile photo error", error=str(e), user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Failed to upload profile photo",
                "timestamp": "Exception"
            }
        )


@router.delete("/{user_id}/photo", status_code=status.HTTP_204_NO_CONTENT)
async def delete_profile_photo(
    user_id: UUID,
    current_user: dict = Depends(get_current_user_required),
    file_storage: FileStorage = Depends(get_file_storage_dependency),
    user_service: UserService = Depends(get_user_service_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    Delete a user's profile photo.

    Users can delete their own profile photo or admins can delete any user's photo.
    """
    try:
        logger.info("Starting profile photo deletion", user_id=str(user_id), requester_id=current_user.get('id'))

        # Check authorization - users can only delete their own photo unless they have admin permissions
        current_user_id = current_user.get('id')
        if str(user_id) != current_user_id:
            # TODO: Check if user has admin permissions
            # For now, allow self-delete only
            logger.warn("Unauthorized photo delete attempt", user_id=str(user_id), requester_id=current_user_id)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "FORBIDDEN",
                    "message": "You can only delete photos from your own profile",
                    "timestamp": "AuthorizationError"
                }
            )

        # Get user to find current photo filename
        logger.debug("Retrieving user to check current photo", user_id=str(user_id))
        user = await user_service.get_user_by_id(user_id)
        if not user:
            logger.warn("User not found for photo deletion", user_id=str(user_id))
            raise UserNotFoundError(f"User with ID {user_id} not found")

        if not user.profile_photo_url:
            # No photo to delete, consider it successful
            logger.info("No profile photo to delete for user", user_id=str(user_id))
            return

        # Get filename from user profile
        filename = user.profile_photo_filename
        if not filename:
            logger.info("No profile photo to delete for user", user_id=str(user_id))
            return
        logger.debug("Using filename from user profile", user_id=str(user_id), filename=filename)

        # Delete file from storage
        logger.debug("Calling file storage to delete photo", user_id=str(user_id), filename=filename)
        success = await file_storage.delete_profile_photo(user_id, filename)

        if success:
            # Update user profile to remove photo filename
            logger.debug("Updating user profile to remove photo filename", user_id=str(user_id))
            await user_service.update_user_profile_photo_filename(user_id=user_id, profile_photo_filename=None)
            logger.info("Profile photo deleted successfully", user_id=str(user_id), filename=filename, requester_id=current_user.get('id'))
        else:
            logger.warn("Profile photo not found in storage", user_id=str(user_id), filename=filename)
            # Still remove filename from user profile even if file wasn't found
            await user_service.update_user_profile_photo_filename(user_id=user_id, profile_photo_filename=None)
            logger.info("User profile updated to remove photo reference", user_id=str(user_id), requester_id=current_user.get('id'))

        return

    except UserNotFoundError as e:
        logger.warn("User not found for photo delete", user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "USER_NOT_FOUND",
                "message": str(e),
                "timestamp": "UserNotFoundError"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Delete profile photo error", error=str(e), user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Failed to delete profile photo",
                "timestamp": "Exception"
            }
        )


@router.get("/{user_id}/photo/metadata", response_model=FileMetadataResponse)
async def get_profile_photo_metadata(
    user_id: UUID,
    current_user: dict = Depends(get_current_user_required),
    file_storage: FileStorage = Depends(get_file_storage_dependency),
    user_service: UserService = Depends(get_user_service_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    Get metadata for a user's profile photo.

    Users can view metadata of their own profile photo or admins can view any user's photo metadata.
    """
    try:
        logger.info("Starting profile photo metadata retrieval", user_id=str(user_id), requester_id=current_user.get('id'))

        # Check authorization - users can only view their own photo metadata unless they have admin permissions
        current_user_id = current_user.get('id')
        if str(user_id) != current_user_id:
            # TODO: Check if user has admin permissions
            # For now, allow self-access only
            logger.warn("Unauthorized metadata access attempt", user_id=str(user_id), requester_id=current_user_id)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "FORBIDDEN",
                    "message": "You can only access metadata for your own profile photo",
                    "timestamp": "AuthorizationError"
                }
            )

        # Get user
        logger.debug("Retrieving user for photo metadata", user_id=str(user_id))
        user = await user_service.get_user_by_id(user_id)
        if not user or not user.profile_photo_url:
            logger.warn("User or profile photo not found", user_id=str(user_id), has_user=user is not None, has_photo_url=bool(user.profile_photo_url if user else False))
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "NOT_FOUND",
                    "message": "Profile photo not found",
                    "timestamp": "Exception"
                }
            )

        # Get filename from user profile
        filename = user.profile_photo_filename
        if not filename:
            logger.warn("No profile photo filename found", user_id=str(user_id))
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "NOT_FOUND",
                    "message": "Profile photo not found",
                    "timestamp": "Exception"
                }
            )
        logger.debug("Using filename from user profile", user_id=str(user_id), filename=filename)

        # Get file metadata
        logger.debug("Retrieving file metadata from storage", user_id=str(user_id), filename=filename)
        metadata = await file_storage.get_file_metadata(user_id, filename)

        if not metadata:
            logger.warn("File metadata not found in storage", user_id=str(user_id), filename=filename)
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "NOT_FOUND",
                    "message": "Profile photo metadata not found",
                    "timestamp": "Exception"
                }
            )

        logger.debug("File metadata retrieved", user_id=str(user_id), filename=filename, size=metadata.get('size', 0))
        response = FileMetadataResponse(
            filename=filename,
            size=metadata.get('size', 0),
            content_type=metadata.get('content_type', 'application/octet-stream'),
            last_modified=metadata.get('last_modified', datetime.now()),
            url=user.profile_photo_url
        )

        logger.info("Profile photo metadata retrieved successfully", user_id=str(user_id), filename=filename, size=metadata.get('size', 0), requester_id=current_user.get('id'))
        return response

    except UserNotFoundError as e:
        logger.warn("User not found for metadata request", user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "USER_NOT_FOUND",
                "message": str(e),
                "timestamp": "UserNotFoundError"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Get profile photo metadata error", error=str(e), user_id=str(user_id))
        raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": "INTERNAL_ERROR",
                    "message": "Failed to retrieve profile photo metadata",
                    "timestamp": "Exception"
                }
            )


@router.get("/{user_id}/photo", response_class=Response)
async def get_profile_photo(
    user_id: UUID,
    current_user: dict = Depends(get_current_user_required),
    file_storage: FileStorage = Depends(get_file_storage_dependency),
    user_service: UserService = Depends(get_user_service_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    Get a user's profile photo.

    Users can view their own profile photo or admins can view any user's photo.
    Returns the image file directly as binary content.
    """
    try:
        logger.info("Starting profile photo retrieval", user_id=str(user_id), requester_id=current_user.get('id'))

        # Check authorization - users can only view their own photo unless they have admin permissions
        current_user_id = current_user.get('id')
        if str(user_id) != current_user_id:
            # TODO: Check if user has admin permissions
            # For now, allow self-access only
            logger.warn("Unauthorized photo access attempt", user_id=str(user_id), requester_id=current_user_id)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "FORBIDDEN",
                    "message": "You can only access your own profile photo",
                    "timestamp": "AuthorizationError"
                }
            )

        # Get user
        logger.debug("Retrieving user for photo retrieval", user_id=str(user_id))
        user = await user_service.get_user_by_id(user_id)
        if not user or not user.profile_photo_filename:
            logger.warn("User or profile photo not found", user_id=str(user_id), has_user=user is not None, has_photo_filename=bool(user.profile_photo_filename if user else False))
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "NOT_FOUND",
                    "message": "Profile photo not found",
                    "timestamp": "Exception"
                }
            )

        # Get filename from user profile
        filename = user.profile_photo_filename
        if not filename:
            logger.warn("No profile photo filename found", user_id=str(user_id))
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "NOT_FOUND",
                    "message": "Profile photo not found",
                    "timestamp": "Exception"
                }
            )
        logger.debug("Using filename from user profile", user_id=str(user_id), filename=filename)

        # Get file content
        logger.debug("Retrieving file content from storage", user_id=str(user_id), filename=filename)
        file_content = await file_storage.get_file_content(user_id, filename)

        if not file_content:
            logger.warn("File content not found in storage", user_id=str(user_id), filename=filename)
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "error": "NOT_FOUND",
                    "message": "Profile photo not found in storage",
                    "timestamp": "Exception"
                }
            )

        # Get metadata to determine content type
        logger.debug("Retrieving file metadata for content type", user_id=str(user_id), filename=filename)
        metadata = await file_storage.get_file_metadata(user_id, filename)
        content_type = metadata.get('content_type', 'application/octet-stream') if metadata else 'application/octet-stream'

        logger.info("Profile photo served successfully", user_id=str(user_id), filename=filename, size=len(file_content), content_type=content_type, requester_id=current_user.get('id'))
        return Response(content=file_content, media_type=content_type)

    except UserNotFoundError as e:
        logger.warn("User not found for photo request", user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "USER_NOT_FOUND",
                "message": str(e),
                "timestamp": "UserNotFoundError"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Get profile photo error", error=str(e), user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Failed to retrieve profile photo",
                "timestamp": "Exception"
            }
        )
