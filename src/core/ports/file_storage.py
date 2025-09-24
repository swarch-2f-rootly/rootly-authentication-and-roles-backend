"""
File storage interface.
Defines the contract for file storage operations using MinIO.
"""

from abc import ABC, abstractmethod
from typing import BinaryIO, Dict, Any, Optional
from uuid import UUID


class FileStorage(ABC):
    """
    File storage interface defining file upload/download operations.
    """

    @abstractmethod
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
        pass

    @abstractmethod
    async def delete_profile_photo(self, user_id: UUID, filename: str) -> bool:
        """
        Delete a user's profile photo.

        Args:
            user_id: User's unique identifier
            filename: Name of the file to delete

        Returns:
            True if file was deleted, False if not found
        """
        pass

    @abstractmethod
    async def get_profile_photo_url(self, user_id: UUID, filename: str) -> Optional[str]:
        """
        Get the URL for a user's profile photo.

        Args:
            user_id: User's unique identifier
            filename: Name of the file

        Returns:
            URL of the profile photo if exists, None otherwise
        """
        pass

    @abstractmethod
    async def validate_file_type(self, content_type: str, filename: str) -> bool:
        """
        Validate if a file type is allowed for profile photos.

        Args:
            content_type: MIME content type
            filename: Original filename

        Returns:
            True if file type is allowed, False otherwise
        """
        pass

    @abstractmethod
    async def validate_file_size(self, file_size: int) -> bool:
        """
        Validate if a file size is within allowed limits.

        Args:
            file_size: File size in bytes

        Returns:
            True if file size is allowed, False otherwise
        """
        pass

    @abstractmethod
    async def generate_unique_filename(self, original_filename: str, user_id: UUID) -> str:
        """
        Generate a unique filename for a user's profile photo.

        Args:
            original_filename: Original filename from upload
            user_id: User's unique identifier

        Returns:
            Unique filename for storage
        """
        pass

    @abstractmethod
    async def get_file_metadata(self, user_id: UUID, filename: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata for a stored file.

        Args:
            user_id: User's unique identifier
            filename: Name of the file

        Returns:
            File metadata dictionary if exists, None otherwise
        """
        pass

    @abstractmethod
    async def list_user_files(self, user_id: UUID) -> list:
        """
        List all files for a user.

        Args:
            user_id: User's unique identifier

        Returns:
            List of file information dictionaries
        """
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if the file storage service is healthy.

        Returns:
            True if service is healthy, False otherwise
        """
        pass

    @abstractmethod
    async def get_storage_info(self) -> Dict[str, Any]:
        """
        Get information about the storage service.

        Returns:
            Dictionary with storage service information
        """
        pass
