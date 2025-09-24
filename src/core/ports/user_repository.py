"""
User repository interface.
Defines the contract for user data access operations.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from uuid import UUID

from ..domain.user import User


class UserRepository(ABC):
    """
    User repository interface defining data access operations for users.
    """

    @abstractmethod
    async def save(self, user: User) -> User:
        """
        Save a user to the repository.

        Args:
            user: User entity to save

        Returns:
            Saved user entity with updated fields
        """
        pass

    @abstractmethod
    async def find_by_id(self, user_id: UUID) -> Optional[User]:
        """
        Find a user by their ID.

        Args:
            user_id: User's unique identifier

        Returns:
            User entity if found, None otherwise
        """
        pass

    @abstractmethod
    async def find_by_email(self, email: str) -> Optional[User]:
        """
        Find a user by their email address.

        Args:
            email: User's email address

        Returns:
            User entity if found, None otherwise
        """
        pass

    @abstractmethod
    async def find_all(self, skip: int = 0, limit: int = 100) -> List[User]:
        """
        Find all users with pagination.

        Args:
            skip: Number of users to skip
            limit: Maximum number of users to return

        Returns:
            List of user entities
        """
        pass

    @abstractmethod
    async def find_active_users(self, skip: int = 0, limit: int = 100) -> List[User]:
        """
        Find all active users with pagination.

        Args:
            skip: Number of users to skip
            limit: Maximum number of users to return

        Returns:
            List of active user entities
        """
        pass

    @abstractmethod
    async def exists_by_email(self, email: str) -> bool:
        """
        Check if a user exists with the given email.

        Args:
            email: Email address to check

        Returns:
            True if user exists, False otherwise
        """
        pass

    @abstractmethod
    async def exists_by_id(self, user_id: UUID) -> bool:
        """
        Check if a user exists with the given ID.

        Args:
            user_id: User ID to check

        Returns:
            True if user exists, False otherwise
        """
        pass

    @abstractmethod
    async def update(self, user: User) -> User:
        """
        Update an existing user.

        Args:
            user: User entity with updated data

        Returns:
            Updated user entity
        """
        pass

    @abstractmethod
    async def delete(self, user_id: UUID) -> bool:
        """
        Delete a user by their ID.

        Args:
            user_id: User's unique identifier

        Returns:
            True if user was deleted, False if not found
        """
        pass

    @abstractmethod
    async def count(self) -> int:
        """
        Count total number of users.

        Returns:
            Total number of users
        """
        pass

    @abstractmethod
    async def count_active(self) -> int:
        """
        Count total number of active users.

        Returns:
            Total number of active users
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
            True if assignment was successful, False otherwise
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
            True if removal was successful, False otherwise
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
    async def get_users_by_role(self, role_id: UUID, skip: int = 0, limit: int = 100) -> List[User]:
        """
        Get all users assigned to a specific role.

        Args:
            role_id: Role's unique identifier
            skip: Number of users to skip
            limit: Maximum number of users to return

        Returns:
            List of user entities
        """
        pass
