"""
Dependency injection providers for handlers.
Provides factory functions for service dependencies.
"""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from core.ports.user_repository import UserRepository
from core.ports.refresh_token_repository import RefreshTokenRepository
from core.ports.role_repository import RoleRepository
from core.ports.permission_repository import PermissionRepository
from core.ports.user_service import UserService
from core.ports.file_storage import FileStorage
from core.ports.logger import Logger
from core.services.password_service import PasswordService
from core.services.user_service import UserService as UserServiceImplementation
from adapters.repositories.postgres_user_repository import PostgresUserRepository
from adapters.repositories.postgres_refresh_token_repository import PostgresRefreshTokenRepository
from adapters.repositories.postgres_role_repository import PostgresRoleRepository
from adapters.repositories.postgres_permission_repository import PostgresPermissionRepository
from adapters.logger.standard_logger import StandardLogger
from config.settings import get_settings

settings = get_settings()

# Global instances for singleton pattern
_engine = None
_logger = None


def get_engine():
    """Get or create database engine singleton."""
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            settings.database.url,
            echo=settings.debug,
            pool_size=settings.database.pool_size,
            max_overflow=settings.database.max_overflow,
            pool_timeout=settings.database.pool_timeout,
            pool_recycle=settings.database.pool_recycle
        )
    return _engine


async def get_logger() -> Logger:
    """Get logger singleton."""
    global _logger
    if _logger is None:
        _logger = StandardLogger("auth", settings.log_level)
    return _logger


def get_async_session_factory():
    """Get async session factory."""
    engine = get_engine()
    return sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False
    )


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for database session.

    Yields:
        Database session
    """
    session_factory = get_async_session_factory()
    async with session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        else:
            # Auto-commit on successful completion
            try:
                await session.commit()
            except Exception:
                await session.rollback()
                raise
        finally:
            await session.close()


async def get_user_repository(session: AsyncSession) -> UserRepository:
    """
    Dependency for user repository.

    Args:
        session: Database session

    Returns:
        User repository instance
    """
    logger = await get_logger()
    return PostgresUserRepository(session, logger)


async def get_refresh_token_repository(session: AsyncSession) -> RefreshTokenRepository:
    """
    Dependency for refresh token repository.

    Args:
        session: Database session

    Returns:
        Refresh token repository instance
    """
    logger = await get_logger()
    return PostgresRefreshTokenRepository(session, logger)


async def get_password_service() -> PasswordService:
    """
    Dependency for password service.

    Returns:
        Password service instance
    """
    logger = await get_logger()
    return PasswordService(logger)


async def get_role_repository(session: AsyncSession) -> RoleRepository:
    """
    Dependency for role repository.

    Args:
        session: Database session

    Returns:
        Role repository instance
    """
    logger = await get_logger()
    return PostgresRoleRepository(session, logger)


async def get_permission_repository(session: AsyncSession) -> PermissionRepository:
    """
    Dependency for permission repository.

    Args:
        session: Database session

    Returns:
        Permission repository instance
    """
    logger = await get_logger()
    return PostgresPermissionRepository(session, logger)


async def get_user_service(session: AsyncSession) -> UserService:
    """
    Dependency for user service.

    Args:
        session: Database session

    Returns:
        User service instance
    """
    user_repo = await get_user_repository(session)
    role_repo = await get_role_repository(session)
    password_service = await get_password_service()
    logger = await get_logger()

    return UserServiceImplementation(user_repo, role_repo, password_service, logger)


async def get_file_storage() -> FileStorage:
    """
    Dependency for file storage.

    Returns:
        File storage instance
    """
    from adapters.storage.minio_storage import MinIOStorage
    logger = await get_logger()
    return MinIOStorage(logger)
