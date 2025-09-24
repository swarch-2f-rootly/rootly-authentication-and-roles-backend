"""
Permission repository interface.
Defines the contract for permission data access operations.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from uuid import UUID

from ..domain.permission import Permission


class PermissionRepository(ABC):
    """
    Permission repository interface defining data access operations for permissions.
    """

    @abstractmethod
    async def save(self, permission: Permission) -> Permission:
        """
        Save a permission to the repository.

        Args:
            permission: Permission entity to save

        Returns:
            Saved permission entity with updated fields
        """
        pass

    @abstractmethod
    async def find_by_id(self, permission_id: UUID) -> Optional[Permission]:
        """
        Find a permission by its ID.

        Args:
            permission_id: Permission's unique identifier

        Returns:
            Permission entity if found, None otherwise
        """
        pass

    @abstractmethod
    async def find_by_name(self, name: str) -> Optional[Permission]:
        """
        Find a permission by its name.

        Args:
            name: Permission name

        Returns:
            Permission entity if found, None otherwise
        """
        pass

    @abstractmethod
    async def find_by_resource(self, resource: str) -> List[Permission]:
        """
        Find all permissions for a specific resource.

        Args:
            resource: Resource name

        Returns:
            List of permission entities for the resource
        """
        pass

    @abstractmethod
    async def find_by_resource_and_action(self, resource: str, action: str) -> List[Permission]:
        """
        Find permissions by resource and action.

        Args:
            resource: Resource name
            action: HTTP action (GET, POST, PUT, DELETE)

        Returns:
            List of permission entities
        """
        pass

    @abstractmethod
    async def find_all(self, skip: int = 0, limit: int = 100) -> List[Permission]:
        """
        Find all permissions with pagination.

        Args:
            skip: Number of permissions to skip
            limit: Maximum number of permissions to return

        Returns:
            List of permission entities
        """
        pass

    @abstractmethod
    async def exists_by_name(self, name: str) -> bool:
        """
        Check if a permission exists with the given name.

        Args:
            name: Permission name to check

        Returns:
            True if permission exists, False otherwise
        """
        pass

    @abstractmethod
    async def exists_by_id(self, permission_id: UUID) -> bool:
        """
        Check if a permission exists with the given ID.

        Args:
            permission_id: Permission ID to check

        Returns:
            True if permission exists, False otherwise
        """
        pass

    @abstractmethod
    async def update(self, permission: Permission) -> Permission:
        """
        Update an existing permission.

        Args:
            permission: Permission entity with updated data

        Returns:
            Updated permission entity
        """
        pass

    @abstractmethod
    async def delete(self, permission_id: UUID) -> bool:
        """
        Delete a permission by its ID.

        Args:
            permission_id: Permission's unique identifier

        Returns:
            True if permission was deleted, False if not found
        """
        pass

    @abstractmethod
    async def count(self) -> int:
        """
        Count total number of permissions.

        Returns:
            Total number of permissions
        """
        pass

    @abstractmethod
    async def count_by_resource(self, resource: str) -> int:
        """
        Count permissions by resource.

        Args:
            resource: Resource name

        Returns:
            Number of permissions for the resource
        """
        pass
