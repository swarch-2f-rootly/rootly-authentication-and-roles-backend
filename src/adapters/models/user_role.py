"""
User-Role junction table SQLAlchemy model.
"""

from sqlalchemy import Column, DateTime, ForeignKey, Table
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import Base


class UserRole(Base):
    """Junction table for many-to-many relationship between users and roles."""

    __tablename__ = "user_roles"

    # Composite primary key
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)

    # Additional metadata
    assigned_at = Column(DateTime(timezone=True), default=None)

    # Relationships
    user = relationship("User", back_populates="user_roles")
    role = relationship("Role", back_populates="user_roles")

    def __init__(self, **kwargs):
        """Initialize UserRole with assignment timestamp."""
        from datetime import datetime
        super().__init__(**kwargs)
        if not self.assigned_at:
            self.assigned_at = datetime.now()

    def to_dict(self) -> dict:
        """Convert UserRole to dictionary."""
        return {
            "user_id": str(self.user_id),
            "role_id": str(self.role_id),
            "assigned_at": self.assigned_at.isoformat() if self.assigned_at else None
        }

    def __repr__(self):
        """String representation of the UserRole."""
        return f"<UserRole(user_id={self.user_id}, role_id={self.role_id})>"
