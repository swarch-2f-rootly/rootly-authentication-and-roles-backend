"""
Authentication service interface.
Defines the contract for authentication operations.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from uuid import UUID

from ..domain.auth_token import AuthToken
from ..domain.user import User


class AuthService(ABC):
    """
    Authentication service interface defining authentication operations.
    """

    @abstractmethod
    async def authenticate_user(self, email: str, password: str) -> AuthToken:
        """
        Authenticate a user with email and password.

        Args:
            email: User's email address
            password: User's password

        Returns:
            Authentication token pair if successful

        Raises:
            InvalidCredentialsError: If credentials are invalid
            AccountLockedError: If account is locked
            AccountInactiveError: If account is inactive
        """
        pass

    @abstractmethod
    async def refresh_access_token(self, refresh_token: str) -> AuthToken:
        """
        Refresh an access token using a refresh token.

        Args:
            refresh_token: Valid refresh token

        Returns:
            New authentication token pair

        Raises:
            InvalidTokenError: If refresh token is invalid
            TokenExpiredError: If refresh token is expired
        """
        pass

    @abstractmethod
    async def validate_access_token(self, access_token: str) -> Dict[str, Any]:
        """
        Validate an access token and return its payload.

        Args:
            access_token: JWT access token

        Returns:
            Token payload if valid

        Raises:
            InvalidTokenError: If token is invalid
            TokenExpiredError: If token is expired
        """
        pass

    @abstractmethod
    async def revoke_refresh_token(self, refresh_token: str) -> bool:
        """
        Revoke a refresh token (logout).

        Args:
            refresh_token: Refresh token to revoke

        Returns:
            True if token was revoked, False if not found
        """
        pass

    @abstractmethod
    async def revoke_all_user_tokens(self, user_id: UUID) -> int:
        """
        Revoke all refresh tokens for a user.

        Args:
            user_id: User's unique identifier

        Returns:
            Number of tokens revoked
        """
        pass

    @abstractmethod
    async def hash_password(self, password: str) -> str:
        """
        Hash a password using bcrypt.

        Args:
            password: Plain text password

        Returns:
            Hashed password string
        """
        pass

    @abstractmethod
    async def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.

        Args:
            password: Plain text password
            hashed_password: Hashed password

        Returns:
            True if password matches hash, False otherwise
        """
        pass

    @abstractmethod
    async def validate_password_strength(self, password: str) -> bool:
        """
        Validate password strength requirements.

        Args:
            password: Password to validate

        Returns:
            True if password meets requirements, False otherwise

        Raises:
            PasswordTooWeakError: If password doesn't meet requirements
        """
        pass

    @abstractmethod
    async def get_current_user(self, access_token: str) -> Optional[User]:
        """
        Get the current authenticated user from access token.

        Args:
            access_token: JWT access token

        Returns:
            User entity if token is valid, None otherwise
        """
        pass

    @abstractmethod
    async def check_user_permission(
        self,
        user_id: UUID,
        resource: str,
        action: str,
        scope: str = "own"
    ) -> bool:
        """
        Check if a user has a specific permission.

        Args:
            user_id: User's unique identifier
            resource: Resource name
            action: Action (GET, POST, PUT, DELETE)
            scope: Permission scope ("own" or "all")

        Returns:
            True if user has permission, False otherwise
        """
        pass

    @abstractmethod
    async def authorize_user_action(
        self,
        access_token: str,
        resource: str,
        action: str,
        scope: str = "own",
        resource_owner_id: Optional[UUID] = None
    ) -> bool:
        """
        Authorize a user action based on token and permissions.

        Args:
            access_token: JWT access token
            resource: Resource name
            action: Action (GET, POST, PUT, DELETE)
            scope: Permission scope ("own" or "all")
            resource_owner_id: ID of the resource owner (for "own" scope)

        Returns:
            True if action is authorized, False otherwise

        Raises:
            AuthorizationError: If user is not authorized
            InvalidTokenError: If token is invalid
        """
        pass
