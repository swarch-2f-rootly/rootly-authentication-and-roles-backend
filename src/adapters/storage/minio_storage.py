"""
MinIO storage implementation for file operations.
Handles profile photo uploads and management using MinIO S3-compatible storage.
"""

import os
from typing import BinaryIO, Dict, Any, Optional
from uuid import UUID
from datetime import datetime
import mimetypes

from minio import Minio
from minio.error import S3Error

from core.ports.file_storage import FileStorage
from core.ports.logger import Logger
from core.ports.exceptions import (
    FileTooLargeError,
    InvalidFileTypeError,
    ExternalServiceError
)
from config.settings import get_settings


class MinIOStorage(FileStorage):
    """
    MinIO implementation of the file storage interface.
    """

    def __init__(self, logger: Logger):
        """
        Initialize MinIO storage.

        Args:
            logger: Logger instance
        """
        self.logger = logger
        self.settings = get_settings()

        # Initialize MinIO client
        self.client = Minio(
            endpoint=self.settings.minio.endpoint,
            access_key=self.settings.minio.access_key,
            secret_key=self.settings.minio.secret_key,
            secure=self.settings.minio.secure
        )

        self.bucket_name = self.settings.minio.bucket_name

        # Ensure bucket exists
        self._ensure_bucket_exists()

    def _ensure_bucket_exists(self) -> None:
        """Ensure the profile photos bucket exists."""
        try:
            if not self.client.bucket_exists(self.bucket_name):
                self.client.make_bucket(self.bucket_name)
                self.logger.info("Created MinIO bucket", bucket=self.bucket_name)
        except S3Error as e:
            self.logger.error("Failed to create/check MinIO bucket", error=str(e))
            raise ExternalServiceError(
                "MinIO",
                f"Failed to initialize storage bucket: {str(e)}"
            )

    async def upload_profile_photo(
        self,
        user_id: UUID,
        file_data: BinaryIO,
        filename: str,
        content_type: str,
        file_size: int
    ) -> str:
        """
        Upload a profile photo for a user.

        Args:
            user_id: User's unique identifier
            file_data: File binary data
            filename: Original filename
            content_type: MIME content type
            file_size: File size in bytes

        Returns:
            URL of the uploaded file

        Raises:
            FileTooLargeError: If file exceeds size limit
            InvalidFileTypeError: If file type is not allowed
            ExternalServiceError: If upload fails
        """
        try:
            # Validate file type
            if not await self.validate_file_type(content_type, filename):
                raise InvalidFileTypeError(self.settings.file_upload.allowed_image_types)

            # Validate file size
            if not await self.validate_file_size(file_size):
                raise FileTooLargeError(self.settings.file_upload.max_profile_photo_size_mb)

            # Generate unique filename
            unique_filename = await self.generate_unique_filename(filename, user_id)

            # Create object name with user directory structure
            object_name = f"uploads/{user_id}/{unique_filename}"

            # Set metadata
            metadata = {
                "user_id": str(user_id),
                "original_filename": filename,
                "content_type": content_type,
                "uploaded_at": datetime.now().isoformat()
            }

            # Upload file
            file_data.seek(0)  # Ensure we're at the beginning of the file
            self.client.put_object(
                bucket_name=self.bucket_name,
                object_name=object_name,
                data=file_data,
                length=file_size,
                content_type=content_type,
                metadata=metadata
            )

            # Generate URL
            file_url = self._get_file_url(object_name)

            self.logger.info(
                "Profile photo uploaded successfully",
                user_id=str(user_id),
                filename=unique_filename,
                size=file_size
            )

            return file_url

        except (FileTooLargeError, InvalidFileTypeError):
            raise
        except S3Error as e:
            self.logger.error("MinIO upload error", error=str(e), user_id=str(user_id))
            raise ExternalServiceError("MinIO", f"Failed to upload file: {str(e)}")
        except Exception as e:
            self.logger.error("Profile photo upload error", error=str(e), user_id=str(user_id))
            raise ExternalServiceError("MinIO", f"Upload failed: {str(e)}")

    async def delete_profile_photo(self, user_id: UUID, filename: str) -> bool:
        """
        Delete a user's profile photo.

        Args:
            user_id: User's unique identifier
            filename: Name of the file to delete

        Returns:
            True if file was deleted, False if not found
        """
        try:
            object_name = f"uploads/{user_id}/{filename}"

            # Check if object exists
            try:
                self.client.stat_object(self.bucket_name, object_name)
            except S3Error as e:
                if e.code == 'NoSuchKey':
                    self.logger.warn("Profile photo not found for deletion", user_id=str(user_id), filename=filename)
                    return False
                raise

            # Delete the object
            self.client.remove_object(self.bucket_name, object_name)

            self.logger.info("Profile photo deleted", user_id=str(user_id), filename=filename)
            return True

        except S3Error as e:
            self.logger.error("MinIO delete error", error=str(e), user_id=str(user_id), filename=filename)
            raise ExternalServiceError("MinIO", f"Failed to delete file: {str(e)}")
        except Exception as e:
            self.logger.error("Profile photo delete error", error=str(e), user_id=str(user_id), filename=filename)
            return False

    async def get_profile_photo_url(self, user_id: UUID, filename: str) -> Optional[str]:
        """
        Get the URL for a user's profile photo.

        Args:
            user_id: User's unique identifier
            filename: Name of the file

        Returns:
            URL of the profile photo if exists, None otherwise
        """
        try:
            object_name = f"uploads/{user_id}/{filename}"

            # Check if object exists
            self.client.stat_object(self.bucket_name, object_name)

            # Generate presigned URL (expires in 1 hour)
            url = self.client.presigned_get_object(
                bucket_name=self.bucket_name,
                object_name=object_name,
                expires=3600  # 1 hour
            )

            return url

        except S3Error as e:
            if e.code == 'NoSuchKey':
                return None
            self.logger.error("MinIO get URL error", error=str(e), user_id=str(user_id), filename=filename)
            raise ExternalServiceError("MinIO", f"Failed to get file URL: {str(e)}")
        except Exception as e:
            self.logger.error("Get profile photo URL error", error=str(e), user_id=str(user_id), filename=filename)
            return None

    async def validate_file_type(self, content_type: str, filename: str) -> bool:
        """
        Validate if a file type is allowed for profile photos.

        Args:
            content_type: MIME content type
            filename: Original filename

        Returns:
            True if file type is allowed, False otherwise
        """
        # Check MIME type
        allowed_types = self.settings.file_upload.allowed_image_types
        if content_type.split('/')[1].lower() not in allowed_types:
            return False

        # Also check file extension as additional validation
        file_ext = os.path.splitext(filename)[1].lower().lstrip('.')
        if file_ext not in allowed_types:
            return False

        return True

    async def validate_file_size(self, file_size: int) -> bool:
        """
        Validate if a file size is within allowed limits.

        Args:
            file_size: File size in bytes

        Returns:
            True if file size is allowed, False otherwise
        """
        max_size = self.settings.file_upload.max_profile_photo_size_bytes
        return file_size <= max_size

    async def generate_unique_filename(self, original_filename: str, user_id: UUID) -> str:
        """
        Generate a unique filename for a user's profile photo.

        Args:
            original_filename: Original filename from upload
            user_id: User's unique identifier

        Returns:
            Unique filename for storage
        """
        # Get file extension
        file_ext = os.path.splitext(original_filename)[1].lower()

        # Generate timestamp-based unique name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_id = str(user_id)[:8]  # Use first 8 chars of user ID

        return f"profile_{unique_id}_{timestamp}{file_ext}"

    async def get_file_metadata(self, user_id: UUID, filename: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata for a stored file.

        Args:
            user_id: User's unique identifier
            filename: Name of the file

        Returns:
            File metadata dictionary if exists, None otherwise
        """
        try:
            object_name = f"uploads/{user_id}/{filename}"

            # Get object stats
            stat = self.client.stat_object(self.bucket_name, object_name)

            metadata = {
                "filename": filename,
                "size": stat.size,
                "content_type": stat.content_type,
                "last_modified": stat.last_modified.isoformat(),
                "etag": stat.etag,
                "metadata": stat.metadata
            }

            return metadata

        except S3Error as e:
            if e.code == 'NoSuchKey':
                return None
            self.logger.error("MinIO get metadata error", error=str(e), user_id=str(user_id), filename=filename)
            raise ExternalServiceError("MinIO", f"Failed to get file metadata: {str(e)}")
        except Exception as e:
            self.logger.error("Get file metadata error", error=str(e), user_id=str(user_id), filename=filename)
            return None

    async def list_user_files(self, user_id: UUID) -> list:
        """
        List all files for a user.

        Args:
            user_id: User's unique identifier

        Returns:
            List of file information dictionaries
        """
        try:
            prefix = f"uploads/{user_id}/"
            files = []

            # List objects with prefix
            objects = self.client.list_objects(self.bucket_name, prefix=prefix)

            for obj in objects:
                files.append({
                    "filename": obj.object_name.split('/')[-1],
                    "size": obj.size,
                    "last_modified": obj.last_modified.isoformat(),
                    "content_type": getattr(obj, 'content_type', 'application/octet-stream')
                })

            return files

        except S3Error as e:
            self.logger.error("MinIO list files error", error=str(e), user_id=str(user_id))
            raise ExternalServiceError("MinIO", f"Failed to list files: {str(e)}")
        except Exception as e:
            self.logger.error("List user files error", error=str(e), user_id=str(user_id))
            return []

    async def get_file_content(self, user_id: UUID, filename: str) -> Optional[bytes]:
        """
        Get the binary content of a stored file.

        Args:
            user_id: User's unique identifier
            filename: Name of the file

        Returns:
            File content as bytes if exists, None otherwise
        """
        try:
            object_name = f"uploads/{user_id}/{filename}"

            # Check if object exists and get it
            try:
                response = self.client.get_object(self.bucket_name, object_name)
                # Read all data from the response
                file_data = response.read()
                response.close()
                response.release_conn()

                self.logger.info("File content retrieved", user_id=str(user_id), filename=filename, size=len(file_data))
                return file_data

            except S3Error as e:
                if e.code == 'NoSuchKey':
                    self.logger.warn("File not found for content retrieval", user_id=str(user_id), filename=filename)
                    return None
                raise

        except S3Error as e:
            self.logger.error("MinIO get content error", error=str(e), user_id=str(user_id), filename=filename)
            raise ExternalServiceError("MinIO", f"Failed to get file content: {str(e)}")
        except Exception as e:
            self.logger.error("Get file content error", error=str(e), user_id=str(user_id), filename=filename)
            return None

    async def health_check(self) -> bool:
        """
        Check if the file storage service is healthy.

        Returns:
            True if service is healthy, False otherwise
        """
        try:
            # Try to list objects to check connectivity
            self.client.list_objects(self.bucket_name, max_keys=1)
            return True

        except Exception as e:
            self.logger.error("MinIO health check failed", error=str(e))
            return False

    async def get_storage_info(self) -> Dict[str, Any]:
        """
        Get information about the storage service.

        Returns:
            Dictionary with storage service information
        """
        try:
            # Get bucket info
            bucket_info = {
                "endpoint": self.settings.minio.endpoint,
                "bucket_name": self.bucket_name,
                "secure": self.settings.minio.secure,
                "healthy": await self.health_check()
            }

            # Try to get bucket stats
            try:
                objects = list(self.client.list_objects(self.bucket_name))
                bucket_info["total_objects"] = len(objects)
            except:
                bucket_info["total_objects"] = "unknown"

            return bucket_info

        except Exception as e:
            self.logger.error("Get storage info error", error=str(e))
            return {"error": str(e)}

    def _get_file_url(self, object_name: str) -> str:
        """
        Generate a file URL.

        Args:
            object_name: Object name in the bucket

        Returns:
            File URL
        """
        if self.settings.minio.secure:
            protocol = "https"
        else:
            protocol = "http"

        return f"{protocol}://{self.settings.minio.endpoint}/{self.bucket_name}/{object_name}"
