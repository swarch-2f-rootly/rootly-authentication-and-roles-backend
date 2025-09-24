"""
Refresh Token SQLAlchemy model.
"""

from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from .base import BaseModel


class RefreshToken(BaseModel):
    """Refresh token model for JWT token management."""

    __tablename__ = "refresh_tokens"

    # Token information
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(255), unique=True, nullable=False, index=True)

    # Expiration
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)

    # Relationships
    user = relationship("User", back_populates="refresh_tokens")

    def __init__(self, **kwargs):
        """Initialize refresh token with validation."""
        super().__init__(**kwargs)

        # Basic validation
        if not self.user_id:
            raise ValueError("User ID is required")

        if not self.token_hash:
            raise ValueError("Token hash is required")

        if not self.expires_at:
            raise ValueError("Expiration time is required")

    def is_expired(self) -> bool:
        """Check if the token is expired."""
        from datetime import datetime
        return datetime.now(self.expires_at.tzinfo) >= self.expires_at

    def to_dict(self) -> dict:
        """Convert refresh token to dictionary."""
        data = super().to_dict()
        # Add computed fields
        data['is_expired'] = self.is_expired()
        return data

    def __repr__(self):
        """String representation of the refresh token."""
        return f"<RefreshToken(id={self.id}, user_id={self.user_id}, expired={self.is_expired()})>"
