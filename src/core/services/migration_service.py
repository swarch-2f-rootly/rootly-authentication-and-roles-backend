"""
Migration service for automatic database schema management.
Handles Alembic migrations and database initialization.
"""

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from ..ports.logger import Logger
from config.settings import get_settings


class MigrationService:
    """Service for managing database migrations and initialization."""

    def __init__(self, logger: Logger):
        """
        Initialize migration service.

        Args:
            logger: Logger instance
        """
        self.logger = logger
        self.settings = get_settings()
        
        # Get project root directory
        self.project_root = Path(__file__).parent.parent.parent.parent
        self.alembic_cfg_path = self.project_root / "alembic.ini"
        
    def _get_alembic_config(self) -> Config:
        """Get Alembic configuration."""
        alembic_cfg = Config(str(self.alembic_cfg_path))
        alembic_cfg.set_main_option("sqlalchemy.url", self.settings.database.url)
        
        # Set script location relative to project root
        script_location = str(self.project_root / "migrations")
        alembic_cfg.set_main_option("script_location", script_location)
        
        return alembic_cfg

    async def wait_for_database(self, timeout: int = 60) -> bool:
        """
        Wait for database to be available.

        Args:
            timeout: Maximum seconds to wait

        Returns:
            True if database is available, False otherwise
        """
        self.logger.info(f"Waiting for database to be ready (timeout: {timeout}s)...")

        engine = create_async_engine(
            self.settings.database.url,
            pool_pre_ping=True,
            pool_timeout=5
        )

        for i in range(timeout):
            try:
                async with engine.connect() as conn:
                    await conn.execute(text("SELECT 1"))
                
                self.logger.info("Database is ready!")
                await engine.dispose()
                return True
                
            except Exception as e:
                if i < 5:  # Only log details for first few attempts
                    self.logger.debug(f"Database not ready: {str(e)}")
                else:
                    self.logger.debug(f"Database not ready, waiting... ({i+1}/{timeout})")
                
                await asyncio.sleep(1)

        self.logger.error(f"Database connection timeout after {timeout} seconds")
        await engine.dispose()
        return False

    async def get_current_revision(self) -> Optional[str]:
        """
        Get current database revision.

        Returns:
            Current revision ID or None if not set
        """
        try:
            engine = create_async_engine(self.settings.database.url)
            
            async with engine.connect() as conn:
                # Check if alembic_version table exists
                result = await conn.execute(text(
                    "SELECT EXISTS ("
                    "SELECT FROM information_schema.tables "
                    "WHERE table_name = 'alembic_version'"
                    ")"
                ))
                table_exists = result.scalar()
                
                if not table_exists:
                    await engine.dispose()
                    return None
                
                # Get current revision
                result = await conn.execute(text("SELECT version_num FROM alembic_version"))
                revision = result.scalar()
                
            await engine.dispose()
            return revision
            
        except Exception as e:
            self.logger.error(f"Failed to get current revision: {str(e)}")
            return None

    def get_head_revision(self) -> Optional[str]:
        """
        Get head revision from migration scripts.

        Returns:
            Head revision ID or None if no migrations exist
        """
        try:
            alembic_cfg = self._get_alembic_config()
            script_dir = ScriptDirectory.from_config(alembic_cfg)
            head_revision = script_dir.get_current_head()
            return head_revision
            
        except Exception as e:
            self.logger.error(f"Failed to get head revision: {str(e)}")
            return None

    async def database_exists(self) -> bool:
        """
        Check if database tables exist.

        Returns:
            True if core tables exist, False otherwise
        """
        try:
            engine = create_async_engine(self.settings.database.url)
            
            async with engine.connect() as conn:
                # Check for core tables
                result = await conn.execute(text(
                    "SELECT COUNT(*) FROM information_schema.tables "
                    "WHERE table_name IN ('users', 'roles', 'permissions')"
                ))
                table_count = result.scalar()
                
            await engine.dispose()
            return table_count >= 3
            
        except Exception as e:
            self.logger.debug(f"Database existence check failed: {str(e)}")
            return False

    def create_initial_migration(self) -> bool:
        """
        Create initial migration if no migrations exist.

        Returns:
            True if migration was created or already exists, False on error
        """
        try:
            alembic_cfg = self._get_alembic_config()
            script_dir = ScriptDirectory.from_config(alembic_cfg)
            
            # Check if any migrations exist
            revisions = list(script_dir.walk_revisions())
            if revisions:
                self.logger.info("Migrations already exist, skipping initial migration creation")
                return True
            
            self.logger.info("Creating initial migration...")
            
            # Create initial migration with autogenerate
            command.revision(
                alembic_cfg,
                message="Initial migration - create all tables",
                autogenerate=True
            )
            
            self.logger.info("Initial migration created successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create initial migration: {str(e)}")
            return False

    async def run_migrations(self) -> bool:
        """
        Run pending migrations to head.

        Returns:
            True if migrations completed successfully, False on error
        """
        try:
            import asyncio

            alembic_cfg = self._get_alembic_config()

            self.logger.info("Running database migrations...")

            # Run synchronous Alembic command in thread pool
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, command.upgrade, alembic_cfg, "head")

            self.logger.info("Database migrations completed successfully")
            return True

        except Exception as e:
            self.logger.error(f"Failed to run migrations: {str(e)}")
            return False

    async def needs_migration(self) -> bool:
        """
        Check if database needs migration.

        Returns:
            True if migration is needed, False otherwise
        """
        try:
            current_revision = await self.get_current_revision()
            head_revision = self.get_head_revision()
            
            # If no current revision, we need to migrate
            if current_revision is None:
                return True
            
            # If no head revision, no migrations available
            if head_revision is None:
                return False
            
            # Compare revisions
            return current_revision != head_revision
            
        except Exception as e:
            self.logger.error(f"Failed to check migration status: {str(e)}")
            return True  # Assume migration is needed on error

    async def initialize_database(self) -> bool:
        """
        Initialize database using Alembic migrations.

        This method checks if migrations are needed and runs them if necessary.
        If no migrations are needed, it does nothing (database is already up to date).

        Returns:
            True if initialization was successful, False otherwise
        """
        try:
            self.logger.info("Starting database initialization with Alembic...")

            # Wait for database to be available
            if not await self.wait_for_database():
                self.logger.error("Database is not available")
                return False

            # Check if Alembic is configured (migrations directory exists)
            migrations_dir = self.project_root / "migrations"
            if not migrations_dir.exists():
                self.logger.error("Alembic migrations directory not found")
                return False

            # Check if migration is needed
            if await self.needs_migration():
                self.logger.info("Database needs migration, running migrations...")
                if not await self.run_migrations():
                    self.logger.error("Failed to run migrations")
                    return False
                self.logger.info("Database migrations completed successfully")
            else:
                self.logger.info("Database is already up to date, no migration needed")

            return True

        except Exception as e:
            self.logger.error(f"Database initialization failed: {str(e)}")
            return False

    async def create_tables_directly(self) -> bool:
        """
        Create all tables directly using SQLAlchemy metadata.

        Returns:
            True if tables were created successfully, False otherwise
        """
        try:
            # Import models to ensure they're registered with Base
            from adapters.models.user import User
            from adapters.models.role import Role
            from adapters.models.permission import Permission
            from adapters.models.user_role import UserRole
            from adapters.models.role_permission import RolePermission
            from adapters.models.refresh_token import RefreshToken
            from adapters.models.base import Base
            
            engine = create_async_engine(self.settings.database.url)
            
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            
            await engine.dispose()
            self.logger.info("Database tables created successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create tables: {str(e)}")
            return False

    async def has_alembic_setup(self) -> bool:
        """
        Check if Alembic is properly set up.

        Returns:
            True if Alembic is set up, False otherwise
        """
        try:
            # Check if migrations directory exists
            migrations_dir = self.project_root / "migrations"
            if not migrations_dir.exists():
                return False
            
            # Check if alembic_version table exists
            engine = create_async_engine(self.settings.database.url)
            
            async with engine.connect() as conn:
                result = await conn.execute(text(
                    "SELECT EXISTS ("
                    "SELECT FROM information_schema.tables "
                    "WHERE table_name = 'alembic_version'"
                    ")"
                ))
                table_exists = result.scalar()
                
            await engine.dispose()
            return table_exists
            
        except Exception as e:
            self.logger.debug(f"Alembic setup check failed: {str(e)}")
            return False

    async def setup_alembic_baseline(self) -> bool:
        """
        Set up Alembic baseline after creating tables directly.

        Returns:
            True if baseline was created successfully, False otherwise
        """
        try:
            self.logger.info("Setting up Alembic baseline...")
            
            # Create alembic_version table and mark as current
            engine = create_async_engine(self.settings.database.url)
            
            async with engine.connect() as conn:
                # Create alembic_version table
                await conn.execute(text(
                    "CREATE TABLE IF NOT EXISTS alembic_version ("
                    "version_num VARCHAR(32) NOT NULL PRIMARY KEY"
                    ")"
                ))
                
                # Insert baseline version (empty for now, can be updated when first migration is created)
                await conn.execute(text(
                    "INSERT INTO alembic_version (version_num) VALUES ('head') "
                    "ON CONFLICT (version_num) DO NOTHING"
                ))
                
                await conn.commit()
                
            await engine.dispose()
            self.logger.info("Alembic baseline created successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to set up Alembic baseline: {str(e)}")
            return False

    def generate_migration(self, message: str) -> bool:
        """
        Generate a new migration with the given message.

        Args:
            message: Migration message

        Returns:
            True if migration was generated successfully, False otherwise
        """
        try:
            alembic_cfg = self._get_alembic_config()
            
            self.logger.info(f"Generating migration: {message}")
            
            command.revision(
                alembic_cfg,
                message=message,
                autogenerate=True
            )
            
            self.logger.info("Migration generated successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to generate migration: {str(e)}")
            return False
