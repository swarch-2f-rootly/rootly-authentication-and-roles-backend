"""
User domain entity following Domain-Driven Design principles.
Represents a user in the authentication and authorization system.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
from uuid import UUID, uuid4


@dataclass
class User:
    """
    User aggregate root representing a system user.

    This is the central entity for user management, containing all
    user-related information and behavior.
    """

    # Identity
    id: UUID = field(default_factory=uuid4)

    # Core attributes
    email: str = ""
    password_hash: str = ""
    first_name: str = ""
    last_name: str = ""
    profile_photo_filename: Optional[str] = None

    # Status
    is_active: bool = True

    # Audit fields
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    # Relationships (loaded on demand)
    _roles: List['Role'] = field(default_factory=list)

    def __post_init__(self):
        """Validate user data after initialization."""
        self._validate()

    def _validate(self) -> None:
        """Validate user data integrity."""
        if not self.email:
            raise ValueError("Email is required")

        if not self.first_name:
            raise ValueError("First name is required")

        if not self.last_name:
            raise ValueError("Last name is required")

        if len(self.first_name) < 2:
            raise ValueError("First name must be at least 2 characters")

        if len(self.last_name) < 2:
            raise ValueError("Last name must be at least 2 characters")

        # Email format validation (basic)
        if "@" not in self.email or "." not in self.email:
            raise ValueError("Invalid email format")

    @property
    def full_name(self) -> str:
        """Get user's full name."""
        return f"{self.first_name} {self.last_name}"

    @property
    def roles(self) -> List['Role']:
        """Get user's assigned roles."""
        return self._roles.copy()

    @property
    def profile_photo_url(self) -> Optional[str]:
        """Get the complete profile photo URL pointing to the service endpoint."""
        if not self.profile_photo_filename:
            return None

        # Return service endpoint URL for client access
        return f"http://localhost:8001/api/v1/users/{self.id}/photo"

    def assign_role(self, role: 'Role') -> None:
        """Assign a role to the user."""
        if role not in self._roles:
            self._roles.append(role)
            self.updated_at = datetime.now()

    def remove_role(self, role: 'Role') -> None:
        """Remove a role from the user."""
        if role in self._roles:
            self._roles.remove(role)
            self.updated_at = datetime.now()

    def has_role(self, role_name: str) -> bool:
        """Check if user has a specific role."""
        return any(role.name == role_name for role in self._roles)

    def has_permission(self, resource: str, action: str, scope: str = "own") -> bool:
        """Check if user has a specific permission."""
        for role in self._roles:
            if role.has_permission(resource, action, scope):
                return True
        return False

    def get_permissions(self) -> List['Permission']:
        """Get all permissions from user's roles."""
        permissions = []
        for role in self._roles:
            permissions.extend(role.permissions)
        return list(set(permissions))  # Remove duplicates

    def activate(self) -> None:
        """Activate the user account."""
        self.is_active = True
        self.updated_at = datetime.now()

    def deactivate(self) -> None:
        """Deactivate the user account."""
        self.is_active = False
        self.updated_at = datetime.now()

    def update_profile(
        self,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        profile_photo_filename: Optional[str] = None
    ) -> None:
        """Update user profile information."""
        if first_name is not None:
            self.first_name = first_name
        if last_name is not None:
            self.last_name = last_name
        if profile_photo_filename is not None:
            self.profile_photo_filename = profile_photo_filename

        self.updated_at = datetime.now()
        self._validate()

    def change_password(self, new_password_hash: str) -> None:
        """Change user's password hash."""
        if not new_password_hash:
            raise ValueError("Password hash cannot be empty")

        self.password_hash = new_password_hash
        self.updated_at = datetime.now()

    def to_dict(self) -> dict:
        """Convert user to dictionary representation."""
        return {
            "id": str(self.id),
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "full_name": self.full_name,
            "profile_photo_url": self.profile_photo_url,
            "is_active": self.is_active,
            "roles": [role.name for role in self._roles],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }
