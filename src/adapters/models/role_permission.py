"""
Role-Permission junction table SQLAlchemy model.
"""

from sqlalchemy import Column, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import Base


class RolePermission(Base):
    """Junction table for many-to-many relationship between roles and permissions."""

    __tablename__ = "role_permissions"

    # Composite primary key
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission_id = Column(UUID(as_uuid=True), ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)

    # Additional metadata
    assigned_at = Column(DateTime(timezone=True), default=None)

    # Relationships
    role = relationship("Role", back_populates="role_permissions")
    permission = relationship("Permission", back_populates="role_permissions")

    def __init__(self, **kwargs):
        """Initialize RolePermission with assignment timestamp."""
        from datetime import datetime
        super().__init__(**kwargs)
        if not self.assigned_at:
            self.assigned_at = datetime.now()

    def to_dict(self) -> dict:
        """Convert RolePermission to dictionary."""
        return {
            "role_id": str(self.role_id),
            "permission_id": str(self.permission_id),
            "assigned_at": self.assigned_at.isoformat() if self.assigned_at else None
        }

    def __repr__(self):
        """String representation of the RolePermission."""
        return f"<RolePermission(role_id={self.role_id}, permission_id={self.permission_id})>"
