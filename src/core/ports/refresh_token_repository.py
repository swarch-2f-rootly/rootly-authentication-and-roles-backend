"""
Refresh token repository interface.
Defines the contract for refresh token data access operations.
"""

from abc import ABC, abstractmethod
from typing import Optional
from uuid import UUID
from datetime import datetime


class RefreshTokenRepository(ABC):
    """
    Refresh token repository interface defining data access operations for refresh tokens.
    """

    @abstractmethod
    async def save_refresh_token(
        self,
        user_id: UUID,
        token_hash: str,
        expires_at: datetime
    ) -> bool:
        """
        Save a hashed refresh token for a user.

        Args:
            user_id: User's unique identifier
            token_hash: SHA256 hash of the refresh token
            expires_at: Token expiration timestamp

        Returns:
            True if token was saved successfully
        """
        pass

    @abstractmethod
    async def validate_refresh_token(self, user_id: UUID, token_hash: str) -> bool:
        """
        Validate if a refresh token exists and is not expired.

        Args:
            user_id: User's unique identifier
            token_hash: SHA256 hash of the refresh token

        Returns:
            True if token is valid, False otherwise
        """
        pass

    @abstractmethod
    async def revoke_refresh_token(self, user_id: UUID, token_hash: str) -> bool:
        """
        Revoke a specific refresh token.

        Args:
            user_id: User's unique identifier
            token_hash: SHA256 hash of the refresh token

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
    async def cleanup_expired_tokens(self) -> int:
        """
        Clean up expired refresh tokens from the database.

        Returns:
            Number of tokens cleaned up
        """
        pass

    @abstractmethod
    async def get_user_active_tokens_count(self, user_id: UUID) -> int:
        """
        Get the count of active refresh tokens for a user.

        Args:
            user_id: User's unique identifier

        Returns:
            Number of active tokens for the user
        """
        pass

    @abstractmethod
    async def get_token_expiration(self, user_id: UUID, token_hash: str) -> Optional[datetime]:
        """
        Get the expiration time for a specific token.

        Args:
            user_id: User's unique identifier
            token_hash: SHA256 hash of the refresh token

        Returns:
            Token expiration datetime if found, None otherwise
        """
        pass
