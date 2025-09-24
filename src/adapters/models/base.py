"""
Base SQLAlchemy model with common functionality.
"""

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class BaseModel(Base):
    """Base model with common fields and methods."""

    __abstract__ = True

    # Common fields
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    created_at = Column(DateTime(timezone=True), default=datetime.now)
    updated_at = Column(DateTime(timezone=True), default=datetime.now, onupdate=datetime.now)

    def __init__(self, **kwargs):
        """Initialize model with keyword arguments."""
        super().__init__(**kwargs)
        if not self.id:
            self.id = uuid4()

    def update_timestamp(self):
        """Update the updated_at timestamp."""
        self.updated_at = datetime.now()

    def to_dict(self) -> dict:
        """Convert model to dictionary."""
        return {
            column.name: getattr(self, column.name)
            for column in self.__table__.columns
        }

    def __repr__(self):
        """String representation of the model."""
        return f"<{self.__class__.__name__}(id={self.id})>"
