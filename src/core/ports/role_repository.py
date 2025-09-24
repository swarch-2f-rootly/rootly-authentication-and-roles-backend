"""
Role repository interface.
Defines the contract for role data access operations.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from uuid import UUID

from ..domain.role import Role


class RoleRepository(ABC):
    """
    Role repository interface defining data access operations for roles.
    """

    @abstractmethod
    async def save(self, role: Role) -> Role:
        """
        Save a role to the repository.

        Args:
            role: Role entity to save

        Returns:
            Saved role entity with updated fields
        """
        pass

    @abstractmethod
    async def find_by_id(self, role_id: UUID) -> Optional[Role]:
        """
        Find a role by its ID.

        Args:
            role_id: Role's unique identifier

        Returns:
            Role entity if found, None otherwise
        """
        pass

    @abstractmethod
    async def find_by_name(self, name: str) -> Optional[Role]:
        """
        Find a role by its name.

        Args:
            name: Role name

        Returns:
            Role entity if found, None otherwise
        """
        pass

    @abstractmethod
    async def find_all(self, skip: int = 0, limit: int = 100) -> List[Role]:
        """
        Find all roles with pagination.

        Args:
            skip: Number of roles to skip
            limit: Maximum number of roles to return

        Returns:
            List of role entities
        """
        pass

    @abstractmethod
    async def exists_by_name(self, name: str) -> bool:
        """
        Check if a role exists with the given name.

        Args:
            name: Role name to check

        Returns:
            True if role exists, False otherwise
        """
        pass

    @abstractmethod
    async def exists_by_id(self, role_id: UUID) -> bool:
        """
        Check if a role exists with the given ID.

        Args:
            role_id: Role ID to check

        Returns:
            True if role exists, False otherwise
        """
        pass

    @abstractmethod
    async def update(self, role: Role) -> Role:
        """
        Update an existing role.

        Args:
            role: Role entity with updated data

        Returns:
            Updated role entity
        """
        pass

    @abstractmethod
    async def delete(self, role_id: UUID) -> bool:
        """
        Delete a role by its ID.

        Args:
            role_id: Role's unique identifier

        Returns:
            True if role was deleted, False if not found
        """
        pass

    @abstractmethod
    async def count(self) -> int:
        """
        Count total number of roles.

        Returns:
            Total number of roles
        """
        pass

    @abstractmethod
    async def assign_permission_to_role(self, role_id: UUID, permission_id: UUID) -> bool:
        """
        Assign a permission to a role.

        Args:
            role_id: Role's unique identifier
            permission_id: Permission's unique identifier

        Returns:
            True if assignment was successful, False otherwise
        """
        pass

    @abstractmethod
    async def remove_permission_from_role(self, role_id: UUID, permission_id: UUID) -> bool:
        """
        Remove a permission from a role.

        Args:
            role_id: Role's unique identifier
            permission_id: Permission's unique identifier

        Returns:
            True if removal was successful, False otherwise
        """
        pass

    @abstractmethod
    async def get_role_permissions(self, role_id: UUID) -> List[dict]:
        """
        Get all permissions assigned to a role.

        Args:
            role_id: Role's unique identifier

        Returns:
            List of permission dictionaries
        """
        pass

    @abstractmethod
    async def get_roles_by_permission(self, permission_id: UUID, skip: int = 0, limit: int = 100) -> List[Role]:
        """
        Get all roles that have a specific permission.

        Args:
            permission_id: Permission's unique identifier
            skip: Number of roles to skip
            limit: Maximum number of roles to return

        Returns:
            List of role entities
        """
        pass
