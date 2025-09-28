"""
User service interface.
Defines the contract for user management operations.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from uuid import UUID

from ..domain.user import User


class UserService(ABC):
    """
    User service interface defining user management operations.
    """

    @abstractmethod
    async def create_user(
        self,
        email: str,
        password: str,
        first_name: str,
        last_name: str
    ) -> User:
        """
        Create a new user account.

        Args:
            email: User's email address
            password: User's password (will be hashed)
            first_name: User's first name
            last_name: User's last name

        Returns:
            Created user entity

        Raises:
            UserAlreadyExistsError: If email already exists
            PasswordTooWeakError: If password doesn't meet requirements
            ValidationError: If input data is invalid

        Note:
            Profile photos should be managed through dedicated file upload endpoints,
            not through user creation.
        """
        pass

    @abstractmethod
    async def get_user_by_id(self, user_id: UUID) -> Optional[User]:
        """
        Get a user by their ID.

        Args:
            user_id: User's unique identifier

        Returns:
            User entity if found, None otherwise
        """
        pass

    @abstractmethod
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get a user by their email address.

        Args:
            email: User's email address

        Returns:
            User entity if found, None otherwise
        """
        pass

    @abstractmethod
    async def get_all_users(self, skip: int = 0, limit: int = 100) -> List[User]:
        """
        Get all users with pagination.

        Args:
            skip: Number of users to skip
            limit: Maximum number of users to return

        Returns:
            List of user entities
        """
        pass

    @abstractmethod
    async def update_user_profile(
        self,
        user_id: UUID,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None
    ) -> User:
        """
        Update a user's profile information.

        Args:
            user_id: User's unique identifier
            first_name: New first name
            last_name: New last name

        Returns:
            Updated user entity

        Raises:
            UserNotFoundError: If user doesn't exist
            ValidationError: If input data is invalid

        Note:
            Profile photos should be managed through dedicated file upload endpoints,
            not through this general profile update method.
        """
        pass

    @abstractmethod
    async def update_user_profile_photo_filename(
        self,
        user_id: UUID,
        profile_photo_filename: Optional[str]
    ) -> User:
        """
        Update a user's profile photo filename.

        This method should only be used by file upload endpoints,
        not by general user profile update operations.

        Args:
            user_id: User's unique identifier
            profile_photo_filename: New profile photo filename (or None to remove)

        Returns:
            Updated user entity

        Raises:
            UserNotFoundError: If user doesn't exist
        """
        pass

    @abstractmethod
    async def change_user_password(
        self,
        user_id: UUID,
        current_password: str,
        new_password: str
    ) -> bool:
        """
        Change a user's password.

        Args:
            user_id: User's unique identifier
            current_password: Current password for verification
            new_password: New password

        Returns:
            True if password was changed successfully

        Raises:
            UserNotFoundError: If user doesn't exist
            InvalidCredentialsError: If current password is wrong
            PasswordTooWeakError: If new password doesn't meet requirements
        """
        pass

    @abstractmethod
    async def delete_user(self, user_id: UUID) -> bool:
        """
        Delete a user account.

        Args:
            user_id: User's unique identifier

        Returns:
            True if user was deleted, False if not found
        """
        pass

    @abstractmethod
    async def activate_user(self, user_id: UUID) -> bool:
        """
        Activate a user account.

        Args:
            user_id: User's unique identifier

        Returns:
            True if user was activated, False if not found or already active
        """
        pass

    @abstractmethod
    async def deactivate_user(self, user_id: UUID) -> bool:
        """
        Deactivate a user account.

        Args:
            user_id: User's unique identifier

        Returns:
            True if user was deactivated, False if not found or already inactive
        """
        pass

    @abstractmethod
    async def assign_role_to_user(self, user_id: UUID, role_id: UUID) -> bool:
        """
        Assign a role to a user.

        Args:
            user_id: User's unique identifier
            role_id: Role's unique identifier

        Returns:
            True if role was assigned successfully

        Raises:
            UserNotFoundError: If user doesn't exist
            RoleNotFoundError: If role doesn't exist
        """
        pass

    @abstractmethod
    async def remove_role_from_user(self, user_id: UUID, role_id: UUID) -> bool:
        """
        Remove a role from a user.

        Args:
            user_id: User's unique identifier
            role_id: Role's unique identifier

        Returns:
            True if role was removed successfully

        Raises:
            UserNotFoundError: If user doesn't exist
            RoleNotFoundError: If role doesn't exist
        """
        pass

    @abstractmethod
    async def get_user_roles(self, user_id: UUID) -> List[dict]:
        """
        Get all roles assigned to a user.

        Args:
            user_id: User's unique identifier

        Returns:
            List of role dictionaries
        """
        pass

    @abstractmethod
    async def get_users_with_role(self, role_id: UUID, skip: int = 0, limit: int = 100) -> List[User]:
        """
        Get all users that have a specific role.

        Args:
            role_id: Role's unique identifier
            skip: Number of users to skip
            limit: Maximum number of users to return

        Returns:
            List of user entities
        """
        pass

    @abstractmethod
    async def count_users(self) -> int:
        """
        Count total number of users.

        Returns:
            Total number of users
        """
        pass

    @abstractmethod
    async def count_active_users(self) -> int:
        """
        Count total number of active users.

        Returns:
            Total number of active users
        """
        pass
