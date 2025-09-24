"""
Role SQLAlchemy model.
"""

from sqlalchemy import Column, String, Text
from sqlalchemy.orm import relationship

from .base import BaseModel


class Role(BaseModel):
    """Role model for user role management."""

    __tablename__ = "roles"

    # Core role information
    name = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(Text)

    # Relationships
    user_roles = relationship("UserRole", back_populates="role", cascade="all, delete-orphan")
    role_permissions = relationship("RolePermission", back_populates="role", cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        """Initialize role with validation."""
        super().__init__(**kwargs)

        # Basic validation
        if not self.name:
            raise ValueError("Role name is required")

        if not self.description:
            raise ValueError("Role description is required")

        # Role name validation
        if not self.name.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Role name can only contain letters, numbers, underscores, and hyphens")

        if len(self.name) < 2:
            raise ValueError("Role name must be at least 2 characters")

    def to_dict(self) -> dict:
        """Convert role to dictionary."""
        data = super().to_dict()
        # Add permission count
        data['permission_count'] = len(self.role_permissions) if self.role_permissions else 0
        return data

    def __repr__(self):
        """String representation of the role."""
        return f"<Role(id={self.id}, name='{self.name}')>"
