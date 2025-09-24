"""
Permission SQLAlchemy model.
"""

from sqlalchemy import Column, String
from sqlalchemy.orm import relationship

from .base import BaseModel


class Permission(BaseModel):
    """Permission model for granular access control."""

    __tablename__ = "permissions"

    # Core permission information
    name = Column(String(100), unique=True, nullable=False, index=True)
    resource = Column(String(100), nullable=False, index=True)  # API resource (users, analytics, sensors)
    action = Column(String(50), nullable=False)  # HTTP method (GET, POST, PUT, DELETE)
    scope = Column(String(20), nullable=False, index=True)  # Access scope (own, all)

    # Relationships
    role_permissions = relationship("RolePermission", back_populates="permission", cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        """Initialize permission with validation."""
        super().__init__(**kwargs)

        # Basic validation
        if not self.name:
            raise ValueError("Permission name is required")

        if not self.resource:
            raise ValueError("Resource is required")

        if not self.action:
            raise ValueError("Action is required")

        if self.scope not in ["own", "all"]:
            raise ValueError("Scope must be either 'own' or 'all'")

        # Permission name format validation
        if not self.name.replace("_", "").replace("-", "").replace(".", "").isalnum():
            raise ValueError("Permission name can only contain letters, numbers, underscores, hyphens, and dots")

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
        """Convert permission to dictionary."""
        data = super().to_dict()
        # Add computed fields
        data['full_name'] = self.full_name
        return data

    def __repr__(self):
        """String representation of the permission."""
        return f"<Permission(id={self.id}, name='{self.name}', resource='{self.resource}', action='{self.action}', scope='{self.scope}')>"

    def __str__(self) -> str:
        """String representation of the permission."""
        return self.full_name
