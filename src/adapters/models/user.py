"""
User SQLAlchemy model.
"""

from sqlalchemy import Column, String, Boolean, Text, DateTime
from sqlalchemy.orm import relationship

from .base import BaseModel


class User(BaseModel):
    """User model for authentication and user management."""

    __tablename__ = "users"

    # Core user information
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)

    # Profile information
    profile_photo_url = Column(String(500))  # MinIO URL stored as string

    # Account status
    is_active = Column(Boolean, default=True, nullable=False, index=True)

    # Relationships
    user_roles = relationship("UserRole", back_populates="user", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        """Initialize user with validation."""
        super().__init__(**kwargs)

        # Basic validation
        if not self.email or "@" not in self.email:
            raise ValueError("Valid email is required")

        if not self.first_name or len(self.first_name) < 2:
            raise ValueError("First name must be at least 2 characters")

        if not self.last_name or len(self.last_name) < 2:
            raise ValueError("Last name must be at least 2 characters")

    @property
    def full_name(self) -> str:
        """Get user's full name."""
        return f"{self.first_name} {self.last_name}"

    def to_dict(self) -> dict:
        """Convert user to dictionary (excluding sensitive data)."""
        data = super().to_dict()
        # Remove password hash from dictionary representation
        data.pop('password_hash', None)
        # Add computed fields
        data['full_name'] = self.full_name
        return data

    def __repr__(self):
        """String representation of the user."""
        return f"<User(id={self.id}, email='{self.email}', active={self.is_active})>"
