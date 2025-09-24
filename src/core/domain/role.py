"""
Role domain entity following Domain-Driven Design principles.
Represents a role with associated permissions in the authorization system.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List
from uuid import UUID, uuid4


@dataclass
class Role:
    """
    Role entity representing a user role with permissions.

    Roles define what actions users can perform in the system.
    """

    # Identity
    id: UUID = field(default_factory=uuid4)

    # Core attributes
    name: str = ""
    description: str = ""

    # Audit fields
    created_at: datetime = field(default_factory=datetime.now)

    # Relationships (loaded on demand)
    _permissions: List['Permission'] = field(default_factory=list)

    def __post_init__(self):
        """Validate role data after initialization."""
        self._validate()

    def _validate(self) -> None:
        """Validate role data integrity."""
        if not self.name:
            raise ValueError("Role name is required")

        if not self.description:
            raise ValueError("Role description is required")

        # Role name should be lowercase and contain only letters, numbers, and underscores
        if not self.name.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Role name can only contain letters, numbers, underscores, and hyphens")

        if len(self.name) < 2:
            raise ValueError("Role name must be at least 2 characters")

    @property
    def permissions(self) -> List['Permission']:
        """Get role's assigned permissions."""
        return self._permissions.copy()

    def add_permission(self, permission: 'Permission') -> None:
        """Add a permission to the role."""
        if permission not in self._permissions:
            self._permissions.append(permission)

    def remove_permission(self, permission: 'Permission') -> None:
        """Remove a permission from the role."""
        if permission in self._permissions:
            self._permissions.remove(permission)

    def has_permission(self, resource: str, action: str, scope: str = "own") -> bool:
        """Check if role has a specific permission."""
        return any(
            perm.resource == resource and
            perm.action == action and
            perm.scope == scope
            for perm in self._permissions
        )

    def get_permissions_by_resource(self, resource: str) -> List['Permission']:
        """Get all permissions for a specific resource."""
        return [perm for perm in self._permissions if perm.resource == resource]

    def can_access_resource(self, resource: str, action: str, scope: str = "own") -> bool:
        """Check if role can access a resource with specific action and scope."""
        return self.has_permission(resource, action, scope)

    def to_dict(self) -> dict:
        """Convert role to dictionary representation."""
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "permissions": [perm.to_dict() for perm in self._permissions],
            "permission_count": len(self._permissions),
            "created_at": self.created_at.isoformat()
        }
