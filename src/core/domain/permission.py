"""
Permission domain entity following Domain-Driven Design principles.
Represents a granular permission in the authorization system.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Literal
from uuid import UUID, uuid4


PermissionScope = Literal["own", "all"]
PermissionAction = Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]


@dataclass
class Permission:
    """
    Permission value object representing a granular access right.

    Permissions define specific actions that can be performed on resources
    with defined scopes (own data vs all data).
    """

    # Identity
    id: UUID = field(default_factory=uuid4)

    # Core attributes
    name: str = ""
    resource: str = ""
    action: PermissionAction = "GET"
    scope: PermissionScope = "own"

    # Audit fields
    created_at: datetime = field(default_factory=datetime.now)

    def __post_init__(self):
        """Validate permission data after initialization."""
        self._validate()

    def _validate(self) -> None:
        """Validate permission data integrity."""
        if not self.name:
            raise ValueError("Permission name is required")

        if not self.resource:
            raise ValueError("Resource is required")

        if not self.action:
            raise ValueError("Action is required")

        if self.scope not in ["own", "all"]:
            raise ValueError("Scope must be either 'own' or 'all'")

        # Permission name format validation - allow colons for resource:action:scope format
        if not self.name.replace("_", "").replace("-", "").replace(".", "").replace(":", "").isalnum():
            raise ValueError("Permission name can only contain letters, numbers, underscores, hyphens, dots, and colons")

        # Resource name validation
        if not self.resource.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Resource name can only contain letters, numbers, underscores, and hyphens")

    @property
    def full_name(self) -> str:
        """Get the full permission name in format: resource:action:scope."""
        return f"{self.resource}:{self.action}:{self.scope}"

    def matches(self, resource: str, action: str, scope: str = "own") -> bool:
        """Check if this permission matches the given parameters."""
        return (
            self.resource == resource and
            self.action == action and
            self.scope == scope
        )

    def is_read_permission(self) -> bool:
        """Check if this is a read permission."""
        return self.action in ["GET", "HEAD", "OPTIONS"]

    def is_write_permission(self) -> bool:
        """Check if this is a write permission."""
        return self.action in ["POST", "PUT", "PATCH"]

    def is_delete_permission(self) -> bool:
        """Check if this is a delete permission."""
        return self.action == "DELETE"

    def can_access_resource(self, resource: str, action: str, scope: str = "own") -> bool:
        """Check if this permission allows access to a specific resource action."""
        return self.matches(resource, action, scope)

    def to_dict(self) -> dict:
        """Convert permission to dictionary representation."""
        return {
            "id": str(self.id),
            "name": self.name,
            "resource": self.resource,
            "action": self.action,
            "scope": self.scope,
            "full_name": self.full_name,
            "created_at": self.created_at.isoformat()
        }

    def __str__(self) -> str:
        """String representation of the permission."""
        return self.full_name

    def __repr__(self) -> str:
        """Detailed string representation of the permission."""
        return f"Permission(name='{self.name}', resource='{self.resource}', action='{self.action}', scope='{self.scope}')"


# Predefined common permissions
def create_common_permissions() -> List[Permission]:
    """Create a set of common permissions for the system."""
    permissions = []

    resources = ["users", "roles", "permissions", "analytics", "sensors", "reports"]
    actions = ["GET", "POST", "PUT", "DELETE"]
    scopes = ["own", "all"]

    for resource in resources:
        for action in actions:
            for scope in scopes:
                name = f"{resource}:{action}:{scope}"
                permission = Permission(
                    name=name,
                    resource=resource,
                    action=action,  # type: ignore
                    scope=scope  # type: ignore
                )
                permissions.append(permission)

    return permissions


# Administrative permissions
ADMIN_PERMISSIONS = [
    Permission(name="users:manage:all", resource="users", action="POST", scope="all"),
    Permission(name="users:manage:all", resource="users", action="PUT", scope="all"),
    Permission(name="users:manage:all", resource="users", action="DELETE", scope="all"),
    Permission(name="roles:manage:all", resource="roles", action="POST", scope="all"),
    Permission(name="roles:manage:all", resource="roles", action="PUT", scope="all"),
    Permission(name="roles:manage:all", resource="roles", action="DELETE", scope="all"),
    Permission(name="permissions:manage:all", resource="permissions", action="POST", scope="all"),
    Permission(name="permissions:manage:all", resource="permissions", action="PUT", scope="all"),
    Permission(name="permissions:manage:all", resource="permissions", action="DELETE", scope="all"),
    Permission(name="system:admin:all", resource="system", action="GET", scope="all"),
    Permission(name="system:admin:all", resource="system", action="POST", scope="all"),
    Permission(name="system:admin:all", resource="system", action="PUT", scope="all"),
    Permission(name="system:admin:all", resource="system", action="DELETE", scope="all"),
]
