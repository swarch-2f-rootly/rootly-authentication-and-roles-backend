"""
PostgreSQL refresh token repository implementation.
Handles refresh token data access operations.
"""

import hashlib
from typing import Optional
from uuid import UUID
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, func, and_

from core.ports.refresh_token_repository import RefreshTokenRepository
from core.ports.logger import Logger
from core.ports.exceptions import RepositoryError
from ..models import RefreshToken as RefreshTokenModel


class PostgresRefreshTokenRepository(RefreshTokenRepository):
    """
    PostgreSQL implementation of the refresh token repository interface.
    """

    def __init__(self, session: AsyncSession, logger: Logger):
        """
        Initialize PostgreSQL refresh token repository.

        Args:
            session: SQLAlchemy async session
            logger: Logger instance
        """
        self.session = session
        self.logger = logger

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
        try:
            self.logger.debug("Saving refresh token", user_id=str(user_id))

            refresh_token = RefreshTokenModel(
                user_id=user_id,
                token_hash=token_hash,
                expires_at=expires_at
            )
            self.session.add(refresh_token)
            await self.session.commit()

            return True

        except Exception as e:
            await self.session.rollback()
            self.logger.error("Save refresh token error", error=str(e), user_id=str(user_id))
            raise RepositoryError(f"Failed to save refresh token: {str(e)}")

    async def validate_refresh_token(self, user_id: UUID, token_hash: str) -> bool:
        """
        Validate if a refresh token exists and is not expired.

        Args:
            user_id: User's unique identifier
            token_hash: SHA256 hash of the refresh token

        Returns:
            True if token is valid, False otherwise
        """
        try:
            self.logger.debug("Validating refresh token", user_id=str(user_id))

            result = await self.session.execute(
                select(RefreshTokenModel).where(
                    and_(
                        RefreshTokenModel.user_id == user_id,
                        RefreshTokenModel.token_hash == token_hash,
                        RefreshTokenModel.expires_at > datetime.now()
                    )
                )
            )
            token_model = result.scalar_one_or_none()
            return token_model is not None

        except Exception as e:
            self.logger.error("Validate refresh token error", error=str(e), user_id=str(user_id))
            return False

    async def revoke_refresh_token(self, user_id: UUID, token_hash: str) -> bool:
        """
        Revoke a specific refresh token.

        Args:
            user_id: User's unique identifier
            token_hash: SHA256 hash of the refresh token

        Returns:
            True if token was revoked, False if not found
        """
        try:
            self.logger.debug("Revoking refresh token", user_id=str(user_id))

            result = await self.session.execute(
                delete(RefreshTokenModel).where(
                    and_(
                        RefreshTokenModel.user_id == user_id,
                        RefreshTokenModel.token_hash == token_hash
                    )
                )
            )
            await self.session.commit()

            return result.rowcount > 0

        except Exception as e:
            await self.session.rollback()
            self.logger.error("Revoke refresh token error", error=str(e), user_id=str(user_id))
            raise RepositoryError(f"Failed to revoke refresh token: {str(e)}")

    async def revoke_all_user_tokens(self, user_id: UUID) -> int:
        """
        Revoke all refresh tokens for a user.

        Args:
            user_id: User's unique identifier

        Returns:
            Number of tokens revoked
        """
        try:
            self.logger.debug("Revoking all user tokens", user_id=str(user_id))

            result = await self.session.execute(
                delete(RefreshTokenModel).where(
                    RefreshTokenModel.user_id == user_id
                )
            )
            await self.session.commit()

            return result.rowcount

        except Exception as e:
            await self.session.rollback()
            self.logger.error("Revoke all user tokens error", error=str(e), user_id=str(user_id))
            raise RepositoryError(f"Failed to revoke all user tokens: {str(e)}")

    async def cleanup_expired_tokens(self) -> int:
        """
        Clean up expired refresh tokens from the database.

        Returns:
            Number of tokens cleaned up
        """
        try:
            self.logger.debug("Cleaning up expired tokens")

            result = await self.session.execute(
                delete(RefreshTokenModel).where(
                    RefreshTokenModel.expires_at <= datetime.now()
                )
            )
            await self.session.commit()

            return result.rowcount

        except Exception as e:
            await self.session.rollback()
            self.logger.error("Cleanup expired tokens error", error=str(e))
            raise RepositoryError(f"Failed to cleanup expired tokens: {str(e)}")

    async def get_user_active_tokens_count(self, user_id: UUID) -> int:
        """
        Get the count of active refresh tokens for a user.

        Args:
            user_id: User's unique identifier

        Returns:
            Number of active tokens for the user
        """
        try:
            result = await self.session.execute(
                select(func.count()).where(
                    and_(
                        RefreshTokenModel.user_id == user_id,
                        RefreshTokenModel.expires_at > datetime.now()
                    )
                )
            )
            return result.scalar() or 0

        except Exception as e:
            self.logger.error("Get user active tokens count error", error=str(e), user_id=str(user_id))
            return 0

    async def get_token_expiration(self, user_id: UUID, token_hash: str) -> Optional[datetime]:
        """
        Get the expiration time for a specific token.

        Args:
            user_id: User's unique identifier
            token_hash: SHA256 hash of the refresh token

        Returns:
            Token expiration datetime if found, None otherwise
        """
        try:
            result = await self.session.execute(
                select(RefreshTokenModel.expires_at).where(
                    and_(
                        RefreshTokenModel.user_id == user_id,
                        RefreshTokenModel.token_hash == token_hash
                    )
                )
            )
            expiration = result.scalar_one_or_none()
            return expiration

        except Exception as e:
            self.logger.error("Get token expiration error", error=str(e), user_id=str(user_id))
            return None
