"""
Authentication service implementation.
Handles JWT token creation, validation, and user authentication.
"""

import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from uuid import UUID

from ..domain.auth_token import AuthToken
from ..domain.user import User
from ..ports.auth_service import AuthService
from ..ports.user_repository import UserRepository
from ..ports.refresh_token_repository import RefreshTokenRepository
from ..ports.logger import Logger
from ..ports.exceptions import (
    InvalidCredentialsError,
    AccountLockedError,
    AccountInactiveError,
    InvalidTokenError,
    TokenExpiredError,
    AuthorizationError,
    UserNotFoundError
)
from .password_service import PasswordService
from config.settings import get_settings


class AuthServiceImpl(AuthService):
    """
    Authentication service implementation using JWT tokens and bcrypt.
    """

    def __init__(
        self,
        user_repository: UserRepository,
        refresh_token_repository: RefreshTokenRepository,
        password_service: PasswordService,
        logger: Logger
    ):
        """
        Initialize authentication service.

        Args:
            user_repository: User repository instance
            refresh_token_repository: Refresh token repository instance
            password_service: Password service instance
            logger: Logger instance
        """
        self.user_repository = user_repository
        self.refresh_token_repository = refresh_token_repository
        self.password_service = password_service
        self.logger = logger
        self.settings = get_settings()

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
        self.logger.info("Attempting user authentication", email=email)

        try:
            # Find user by email
            user = await self.user_repository.find_by_email(email)
            if not user:
                self.logger.warn("Authentication failed: user not found", email=email)
                raise InvalidCredentialsError()

            # Check if account is active
            if not user.is_active:
                self.logger.warn("Authentication failed: account inactive", user_id=str(user.id))
                raise AccountInactiveError()

            # Verify password
            password_valid = await self.password_service.verify_password(
                password, user.password_hash
            )

            if not password_valid:
                self.logger.warn("Authentication failed: invalid password", user_id=str(user.id))
                raise InvalidCredentialsError()

            # Get user roles and permissions
            user_roles = await self.user_repository.get_user_roles(user.id)
            role_names = [role['name'] for role in user_roles]

            # Get user permissions
            permissions = user.get_permissions()
            permission_names = [perm.full_name for perm in permissions]

            # Create token pair
            token_pair = AuthToken.create_token_pair(
                user_id=user.id,
                email=user.email,
                roles=role_names,
                permissions=permission_names,
                secret_key=self.settings.jwt.secret_key,
                access_expires_delta=timedelta(minutes=self.settings.jwt.access_token_expire_minutes),
                refresh_expires_delta=timedelta(days=self.settings.jwt.refresh_token_expire_days),
                algorithm=self.settings.jwt.algorithm
            )

            # Store refresh token hash
            token_hash = hashlib.sha256(token_pair.refresh_token.encode()).hexdigest()
            expires_at = token_pair.refresh_token_expires_at

            await self.refresh_token_repository.save_refresh_token(
                user.id, token_hash, expires_at
            )

            self.logger.info("User authenticated successfully", user_id=str(user.id))
            return token_pair

        except (InvalidCredentialsError, AccountInactiveError):
            raise
        except Exception as e:
            self.logger.error("Authentication error", error=str(e))
            raise InvalidCredentialsError()

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
        self.logger.info("Attempting token refresh")

        try:
            # Validate refresh token
            payload = AuthToken.validate_refresh_token(
                refresh_token,
                self.settings.jwt.secret_key,
                self.settings.jwt.algorithm
            )

            user_id = UUID(payload['sub'])
            token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

            # Check if token exists in database and is not expired
            token_valid = await self.refresh_token_repository.validate_refresh_token(
                user_id, token_hash
            )

            if not token_valid:
                self.logger.warn("Token refresh failed: invalid or expired token", user_id=str(user_id))
                raise InvalidTokenError("Refresh token is invalid or expired")

            # Get user
            user = await self.user_repository.find_by_id(user_id)
            if not user or not user.is_active:
                self.logger.warn("Token refresh failed: user not found or inactive", user_id=str(user_id))
                raise InvalidTokenError("User not found or inactive")

            # Get user roles and permissions
            user_roles = await self.user_repository.get_user_roles(user.id)
            role_names = [role['name'] for role in user_roles]
            permissions = user.get_permissions()
            permission_names = [perm.full_name for perm in permissions]

            # Create new token pair
            new_token_pair = AuthToken.create_token_pair(
                user_id=user.id,
                email=user.email,
                roles=role_names,
                permissions=permission_names,
                secret_key=self.settings.jwt.secret_key,
                access_expires_delta=timedelta(minutes=self.settings.jwt.access_token_expire_minutes),
                refresh_expires_delta=timedelta(days=self.settings.jwt.refresh_token_expire_days),
                algorithm=self.settings.jwt.algorithm
            )

            # Revoke old refresh token
            await self.refresh_token_repository.revoke_refresh_token(user_id, token_hash)

            # Store new refresh token hash
            new_token_hash = hashlib.sha256(new_token_pair.refresh_token.encode()).hexdigest()
            new_expires_at = new_token_pair.refresh_token_expires_at

            await self.refresh_token_repository.save_refresh_token(
                user.id, new_token_hash, new_expires_at
            )

            self.logger.info("Token refreshed successfully", user_id=str(user.id))
            return new_token_pair

        except (InvalidTokenError, TokenExpiredError):
            raise
        except Exception as e:
            self.logger.error("Token refresh error", error=str(e))
            raise InvalidTokenError("Failed to refresh token")

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
        try:
            payload = AuthToken.validate_access_token(
                access_token,
                self.settings.jwt.secret_key,
                self.settings.jwt.algorithm
            )

            return payload

        except Exception as e:
            self.logger.error("Token validation error", error=str(e))
            raise InvalidTokenError("Invalid access token")

    async def revoke_refresh_token(self, refresh_token: str) -> bool:
        """
        Revoke a refresh token (logout).

        Args:
            refresh_token: Refresh token to revoke

        Returns:
            True if token was revoked, False if not found
        """
        try:
            # Decode token to get user_id
            payload = AuthToken.validate_refresh_token(
                refresh_token,
                self.settings.jwt.secret_key,
                self.settings.jwt.algorithm
            )

            user_id = UUID(payload['sub'])
            token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

            result = await self.refresh_token_repository.revoke_refresh_token(
                user_id, token_hash
            )

            if result:
                self.logger.info("Refresh token revoked", user_id=str(user_id))
            else:
                self.logger.warn("Refresh token not found for revocation", user_id=str(user_id))

            return result

        except Exception as e:
            self.logger.error("Token revocation error", error=str(e))
            return False

    async def revoke_all_user_tokens(self, user_id: UUID) -> int:
        """
        Revoke all refresh tokens for a user.

        Args:
            user_id: User's unique identifier

        Returns:
            Number of tokens revoked
        """
        try:
            count = await self.refresh_token_repository.revoke_all_user_tokens(user_id)
            self.logger.info("All user tokens revoked", user_id=str(user_id), count=count)
            return count

        except Exception as e:
            self.logger.error("Revoke all tokens error", error=str(e), user_id=str(user_id))
            return 0

    async def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt."""
        return await self.password_service.hash_password(password)

    async def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return await self.password_service.verify_password(password, hashed_password)

    async def validate_password_strength(self, password: str) -> bool:
        """Validate password strength requirements."""
        return await self.password_service.validate_password_strength(password)

    async def get_current_user(self, access_token: str) -> Optional[User]:
        """
        Get the current authenticated user from access token.

        Args:
            access_token: JWT access token

        Returns:
            User entity if token is valid, None otherwise
        """
        try:
            payload = await self.validate_access_token(access_token)
            user_id = UUID(payload['sub'])

            user = await self.user_repository.find_by_id(user_id)
            if user and user.is_active:
                return user

            return None

        except Exception:
            return None

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
        try:
            user = await self.user_repository.find_by_id(user_id)
            if not user or not user.is_active:
                return False

            return user.has_permission(resource, action, scope)

        except Exception as e:
            self.logger.error("Permission check error", error=str(e), user_id=str(user_id))
            return False

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
        try:
            # Validate token and get user
            payload = await self.validate_access_token(access_token)
            user_id = UUID(payload['sub'])

            user = await self.user_repository.find_by_id(user_id)
            if not user or not user.is_active:
                raise AuthorizationError("User not found or inactive")

            # Check permission
            has_permission = user.has_permission(resource, action, scope)

            # For "own" scope, check if user owns the resource
            if scope == "own" and resource_owner_id and user_id != resource_owner_id:
                # User doesn't own the resource and doesn't have "all" scope permission
                if not user.has_permission(resource, action, "all"):
                    raise AuthorizationError("Access denied: insufficient permissions")

            if not has_permission:
                raise AuthorizationError("Access denied: insufficient permissions")

            return True

        except (InvalidTokenError, AuthorizationError):
            raise
        except Exception as e:
            self.logger.error("Authorization error", error=str(e))
            raise AuthorizationError("Authorization failed")
