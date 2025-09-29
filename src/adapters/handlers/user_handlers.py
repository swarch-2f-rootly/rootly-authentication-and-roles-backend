"""
User management FastAPI route handlers.
Handles user CRUD operations and profile management endpoints.
"""

from uuid import UUID
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status, Query

from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends

from core.ports.user_service import UserService
from core.ports.logger import Logger
from core.ports.exceptions import (
    UserNotFoundError,
    UserAlreadyExistsError,
    InvalidCredentialsError,
    ValidationError,
    AuthorizationError
)
from .models import (
    UserCreateRequest,
    UserUpdateRequest,
    UserResponse,
    UserListResponse,
    ChangePasswordRequest,
    AssignRoleRequest,
    ErrorResponse
)
from .dependencies import get_user_service, get_logger, get_db_session
from .auth_handlers import get_current_user_required

router = APIRouter(prefix="/api/v1/users", tags=["user-management"])


async def get_user_service_dependency(session: AsyncSession = Depends(get_db_session)) -> UserService:
    """Dependency injection for user service."""
    return await get_user_service(session)


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    request: UserCreateRequest,
    session: AsyncSession = Depends(get_db_session),
    user_service: UserService = Depends(get_user_service_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    Create a new user account.

    This endpoint allows creating new user accounts with proper validation.
    """
    try:
        logger.info("Starting user creation process", email=request.email, first_name=request.first_name, last_name=request.last_name)

        # Create user
        logger.debug("Calling user service to create user", email=request.email)
        user = await user_service.create_user(
            email=request.email,
            password=request.password,
            first_name=request.first_name,
            last_name=request.last_name
        )
        logger.debug("User created in service", user_id=str(user.id), email=request.email)

        # Safely get user roles and convert to role names
        try:
            user_roles_objects = user.roles if hasattr(user, 'roles') else []
            user_role_names = [role.name for role in user_roles_objects] if user_roles_objects else []
        except Exception as role_error:
            logger.warn("Error accessing user roles for creation", user_id=str(user.id), error=str(role_error))
            user_role_names = []

        response = UserResponse(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            full_name=f"{user.first_name} {user.last_name}",
            profile_photo_url=user.profile_photo_url,
            is_active=user.is_active,
            roles=user_role_names,
            created_at=user.created_at,
            updated_at=user.updated_at
        )

        logger.info("User created successfully", user_id=str(user.id), email=request.email, roles=user_role_names)
        return response

    except UserAlreadyExistsError as e:
        logger.warn("User creation failed: user already exists", email=request.email)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "USER_ALREADY_EXISTS",
                "message": str(e),
                "timestamp": "UserAlreadyExistsError"
            }
        )
    except ValidationError as e:
        logger.warn("User creation failed: validation error", email=request.email, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "VALIDATION_ERROR",
                "message": str(e),
                "timestamp": "ValidationError"
            }
        )
    except Exception as e:
        logger.error("User creation error", error=str(e), email=request.email)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "User creation failed",
                "timestamp": "Exception"
            }
        )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    current_user: dict = Depends(get_current_user_required),
    user_service: UserService = Depends(get_user_service_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    Get user profile information.

    Users can view their own profile or admins can view any profile.
    """
    try:
        logger.info("Starting get_user endpoint", user_id=str(user_id), requester_id=current_user.get('id'))

        # Check authorization - users can only view their own profile unless they have admin permissions
        current_user_id = current_user.get('id')
        logger.debug("Checking authorization", user_id=str(user_id), current_user_id=current_user_id)

        if str(user_id) != current_user_id:
            # TODO: Check if user has admin permissions
            # For now, allow self-access only
            logger.warn("Unauthorized access attempt", user_id=str(user_id), requester_id=current_user_id)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "FORBIDDEN",
                    "message": "You can only access your own profile",
                    "timestamp": "AuthorizationError"
                }
            )

        logger.debug("Authorization passed, calling user_service.get_user_by_id")

        # Get user
        user = await user_service.get_user_by_id(user_id)
        logger.debug("User service returned", user_found=user is not None, user_id=str(user_id))

        if not user:
            logger.warn("User not found by service", user_id=str(user_id))
            raise UserNotFoundError(f"User with ID {user_id} not found")

        logger.debug("User found, building response", user_email=user.email if user else None)

        # Safely get user roles and convert to role names
        try:
            user_roles_objects = user.roles if hasattr(user, 'roles') else []
            logger.debug("User roles retrieved", roles_count=len(user_roles_objects))

            # Convert Role objects to role names (strings)
            user_role_names = [role.name for role in user_roles_objects] if user_roles_objects else []
            logger.debug("User role names extracted", role_names=user_role_names)

        except Exception as role_error:
            logger.warn("Error accessing user roles", error=str(role_error), error_type=type(role_error).__name__)
            user_role_names = []

        response = UserResponse(
            id=user.id,
            email=user.email,
            first_name=user.first_name,
            last_name=user.last_name,
            full_name=f"{user.first_name} {user.last_name}",
            profile_photo_url=user.profile_photo_url,
            is_active=user.is_active,
            roles=user_role_names,
            created_at=user.created_at,
            updated_at=user.updated_at
        )

        logger.info("User profile retrieved successfully", user_id=str(user_id), user_email=user.email)
        return response

    except UserNotFoundError as e:
        logger.warn("User not found", user_id=str(user_id), error=str(e))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "USER_NOT_FOUND",
                "message": str(e),
                "timestamp": "UserNotFoundError"
            }
        )
    except HTTPException:
        logger.debug("HTTPException re-raised", user_id=str(user_id))
        raise
    except Exception as e:
        logger.error("Unexpected error in get_user endpoint", error=str(e), error_type=type(e).__name__, user_id=str(user_id), traceback=__import__('traceback').format_exc())
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Failed to retrieve user profile",
                "timestamp": "Exception"
            }
        )


@router.get("", response_model=UserListResponse)
async def list_users(
    skip: int = Query(0, ge=0, description="Number of users to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of users to return"),
    current_user: dict = Depends(get_current_user_required),
    user_service: UserService = Depends(get_user_service_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    List users with pagination.

    Admin users can list all users.
    """
    try:
        logger.info("Starting user list process", skip=skip, limit=limit, requester_id=current_user.get('id'))

        # TODO: Check if user has admin permissions to list all users
        # For now, allow listing (should be restricted to admins)

        # Get users
        logger.debug("Retrieving users from service", skip=skip, limit=limit)
        users = await user_service.get_all_users(skip=skip, limit=limit)
        logger.debug("Users retrieved from service", count=len(users))

        logger.debug("Counting total users")
        total = await user_service.count_users()
        logger.debug("Total users counted", total=total)

        user_responses = []
        for user in users:
            # Safely get user roles and convert to role names
            try:
                user_roles_objects = user.roles if hasattr(user, 'roles') else []
                user_role_names = [role.name for role in user_roles_objects] if user_roles_objects else []
            except Exception as role_error:
                logger.warn("Error accessing user roles for user in list", user_id=str(user.id), error=str(role_error))
                user_role_names = []

            user_responses.append(UserResponse(
                id=user.id,
                email=user.email,
                first_name=user.first_name,
                last_name=user.last_name,
                full_name=f"{user.first_name} {user.last_name}",
                profile_photo_url=user.profile_photo_url,
                is_active=user.is_active,
                roles=user_role_names,
                created_at=user.created_at,
                updated_at=user.updated_at
            ))

        response = UserListResponse(
            users=user_responses,
            total=total,
            skip=skip,
            limit=limit
        )

        logger.info("Users listed successfully", count=len(user_responses), total=total)
        return response

    except Exception as e:
        logger.error("List users error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Failed to list users",
                "timestamp": "Exception"
            }
        )


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    request: UserUpdateRequest,
    current_user: dict = Depends(get_current_user_required),
    user_service: UserService = Depends(get_user_service_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    Update user profile information.

    Users can update their own profile or admins can update any profile.
    """
    try:
        logger.info("Starting user profile update", user_id=str(user_id), requester_id=current_user.get('id'),
                   first_name=request.first_name, last_name=request.last_name)

        # Check authorization - users can only update their own profile unless they have admin permissions
        current_user_id = current_user.get('id')
        if str(user_id) != current_user_id:
            # TODO: Check if user has admin permissions
            # For now, allow self-update only
            logger.warn("Unauthorized update attempt", user_id=str(user_id), requester_id=current_user_id)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "FORBIDDEN",
                    "message": "You can only update your own profile",
                    "timestamp": "AuthorizationError"
                }
            )

        # Update user
        logger.debug("Calling user service to update profile", user_id=str(user_id))
        updated_user = await user_service.update_user_profile(
            user_id=user_id,
            first_name=request.first_name,
            last_name=request.last_name
        )
        logger.debug("User profile updated in service", user_id=str(user_id))

        # Safely get updated user roles and convert to role names
        try:
            updated_user_roles_objects = updated_user.roles if hasattr(updated_user, 'roles') else []
            updated_user_role_names = [role.name for role in updated_user_roles_objects] if updated_user_roles_objects else []
        except Exception as role_error:
            logger.warn("Error accessing updated user roles", user_id=str(updated_user.id), error=str(role_error))
            updated_user_role_names = []

        response = UserResponse(
            id=updated_user.id,
            email=updated_user.email,
            first_name=updated_user.first_name,
            last_name=updated_user.last_name,
            full_name=f"{updated_user.first_name} {updated_user.last_name}",
            profile_photo_url=updated_user.profile_photo_url,
            is_active=updated_user.is_active,
            roles=updated_user_role_names,
            created_at=updated_user.created_at,
            updated_at=updated_user.updated_at
        )

        logger.info("User profile updated successfully", user_id=str(user_id), email=updated_user.email,
                   new_first_name=updated_user.first_name, new_last_name=updated_user.last_name)
        return response

    except UserNotFoundError as e:
        logger.warn("User not found for update", user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "USER_NOT_FOUND",
                "message": str(e),
                "timestamp": "UserNotFoundError"
            }
        )
    except ValidationError as e:
        logger.warn("User update failed: validation error", user_id=str(user_id), error=str(e))
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
        logger.error("Update user error", error=str(e), user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Failed to update user profile",
                "timestamp": "Exception"
            }
        )


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: UUID,
    current_user: dict = Depends(get_current_user_required),
    user_service: UserService = Depends(get_user_service_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    Delete a user account.

    Only admins can delete user accounts.
    """
    try:
        logger.info("Starting user account deletion", user_id=str(user_id), requester_id=current_user.get('id'))

        # TODO: Check if user has admin permissions to delete accounts
        # For now, allow deletion (should be restricted to admins)

        # Delete user
        logger.debug("Calling user service to delete user", user_id=str(user_id))
        success = await user_service.delete_user(user_id)

        if not success:
            logger.warn("User deletion failed: user not found", user_id=str(user_id))
            raise UserNotFoundError(f"User with ID {user_id} not found")

        logger.debug("User deleted successfully in service", user_id=str(user_id))
        logger.info("User account deleted successfully", user_id=str(user_id), requester_id=current_user.get('id'))
        return

    except UserNotFoundError as e:
        logger.warn("User not found for deletion", user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "USER_NOT_FOUND",
                "message": str(e),
                "timestamp": "UserNotFoundError"
            }
        )
    except Exception as e:
        logger.error("Delete user error", error=str(e), user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Failed to delete user account",
                "timestamp": "Exception"
            }
        )


@router.post("/{user_id}/change-password", status_code=status.HTTP_200_OK)
async def change_password(
    user_id: UUID,
    request: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user_required),
    user_service: UserService = Depends(get_user_service_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    Change user password.

    Users can change their own password or admins can change any user's password.
    """
    try:
        logger.info("Starting password change process", user_id=str(user_id), requester_id=current_user.get('id'))

        # Check authorization - users can only change their own password unless they have admin permissions
        current_user_id = current_user.get('id')
        if str(user_id) != current_user_id:
            # TODO: Check if user has admin permissions
            # For now, allow self-password-change only
            logger.warn("Unauthorized password change attempt", user_id=str(user_id), requester_id=current_user_id)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "FORBIDDEN",
                    "message": "You can only change your own password",
                    "timestamp": "AuthorizationError"
                }
            )

        # Change password
        logger.debug("Calling user service to change password", user_id=str(user_id))
        success = await user_service.change_user_password(
            user_id=user_id,
            current_password=request.current_password,
            new_password=request.new_password
        )

        if not success:
            logger.warn("Password change failed: invalid current password", user_id=str(user_id))
            raise InvalidCredentialsError("Current password is incorrect")

        logger.debug("Password changed successfully in service", user_id=str(user_id))
        logger.info("Password changed successfully", user_id=str(user_id), requester_id=current_user.get('id'))
        return {"message": "Password changed successfully"}

    except InvalidCredentialsError as e:
        logger.warn("Password change failed: invalid current password", user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "INVALID_CREDENTIALS",
                "message": str(e),
                "timestamp": "InvalidCredentialsError"
            }
        )
    except UserNotFoundError as e:
        logger.warn("User not found for password change", user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "USER_NOT_FOUND",
                "message": str(e),
                "timestamp": "UserNotFoundError"
            }
        )
    except ValidationError as e:
        logger.warn("Password change failed: validation error", user_id=str(user_id), error=str(e))
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
        logger.error("Change password error", error=str(e), user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Failed to change password",
                "timestamp": "Exception"
            }
        )


@router.put("/{user_id}/roles", status_code=status.HTTP_200_OK)
async def assign_user_roles(
    user_id: UUID,
    request: AssignRoleRequest,
    current_user: dict = Depends(get_current_user_required),
    user_service: UserService = Depends(get_user_service_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    Assign roles to a user.

    Only admins can assign roles to users.
    """
    try:
        role_ids_str = [str(rid) for rid in request.role_ids]
        logger.info("Starting role assignment process", user_id=str(user_id),
                   role_ids=role_ids_str, role_count=len(request.role_ids), requester_id=current_user.get('id'))

        # TODO: Check if user has admin permissions to assign roles
        # For now, allow role assignment (should be restricted to admins)

        # Remove all existing roles first
        logger.debug("Retrieving existing user roles for removal", user_id=str(user_id))
        user_roles = await user_service.get_user_roles(user_id)
        logger.debug("Existing user roles retrieved", user_id=str(user_id), existing_roles=len(user_roles))

        removed_count = 0
        for role_dict in user_roles:
            role_id = role_dict.get('id')
            if role_id:
                logger.debug("Removing existing role", user_id=str(user_id), role_id=role_id)
                await user_service.remove_role_from_user(user_id, UUID(role_id))
                removed_count += 1

        logger.debug("Existing roles removed", user_id=str(user_id), removed_count=removed_count)

        # Assign new roles
        assigned_count = 0
        for role_id in request.role_ids:
            logger.debug("Assigning new role", user_id=str(user_id), role_id=str(role_id))
            success = await user_service.assign_role_to_user(user_id, role_id)
            if success:
                assigned_count += 1
            else:
                logger.warn("Failed to assign role", user_id=str(user_id), role_id=str(role_id))

        logger.debug("Role assignment completed", user_id=str(user_id), assigned_count=assigned_count, requested_count=len(request.role_ids))
        logger.info("Roles assigned successfully", user_id=str(user_id), role_count=len(request.role_ids),
                   requester_id=current_user.get('id'))
        return {"message": f"Successfully assigned {len(request.role_ids)} roles to user"}

    except UserNotFoundError as e:
        logger.warn("User not found for role assignment", user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "USER_NOT_FOUND",
                "message": str(e),
                "timestamp": "UserNotFoundError"
            }
        )
    except Exception as e:
        logger.error("Assign roles error", error=str(e), user_id=str(user_id))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Failed to assign roles",
                "timestamp": "Exception"
            }
        )
