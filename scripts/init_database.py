#!/usr/bin/env python3
"""
Database initialization script for the Authentication Service.
Creates tables, indexes, and initial data.
"""

import asyncio
import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# Add the src directory to the path
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from adapters.models import Base, Role, Permission, RolePermission
from adapters.logger.standard_logger import StandardLogger
from config.settings import get_settings

settings = get_settings()
logger = StandardLogger("db_init", settings.log_level)


async def create_tables(engine):
    """Create all database tables."""
    try:
        logger.info("Creating database tables...")

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        logger.info("Database tables created successfully")
        return True

    except Exception as e:
        logger.error("Failed to create tables", error=str(e))
        return False


async def create_initial_roles_permissions(session: AsyncSession):
    """Create initial roles and permissions."""
    try:
        logger.info("Creating initial roles and permissions...")

        # Define initial permissions
        permissions_data = [
            # User permissions
            {"name": "users:read:own", "resource": "users", "action": "GET", "scope": "own"},
            {"name": "users:read:all", "resource": "users", "action": "GET", "scope": "all"},
            {"name": "users:create:all", "resource": "users", "action": "POST", "scope": "all"},
            {"name": "users:update:own", "resource": "users", "action": "PUT", "scope": "own"},
            {"name": "users:update:all", "resource": "users", "action": "PUT", "scope": "all"},
            {"name": "users:delete:own", "resource": "users", "action": "DELETE", "scope": "own"},
            {"name": "users:delete:all", "resource": "users", "action": "DELETE", "scope": "all"},

            # Analytics permissions
            {"name": "analytics:read:all", "resource": "analytics", "action": "GET", "scope": "all"},
            {"name": "analytics:export:all", "resource": "analytics", "action": "POST", "scope": "all"},

            # Sensor permissions
            {"name": "sensors:read:all", "resource": "sensors", "action": "GET", "scope": "all"},
            {"name": "sensors:update:all", "resource": "sensors", "action": "PUT", "scope": "all"},
            {"name": "sensors:create:all", "resource": "sensors", "action": "POST", "scope": "all"},
            {"name": "sensors:delete:all", "resource": "sensors", "action": "DELETE", "scope": "all"},

            # Role permissions
            {"name": "roles:read:all", "resource": "roles", "action": "GET", "scope": "all"},
            {"name": "roles:create:all", "resource": "roles", "action": "POST", "scope": "all"},
            {"name": "roles:update:all", "resource": "roles", "action": "PUT", "scope": "all"},
            {"name": "roles:delete:all", "resource": "roles", "action": "DELETE", "scope": "all"},

            # Permission permissions
            {"name": "permissions:read:all", "resource": "permissions", "action": "GET", "scope": "all"},
            {"name": "permissions:create:all", "resource": "permissions", "action": "POST", "scope": "all"},
            {"name": "permissions:update:all", "resource": "permissions", "action": "PUT", "scope": "all"},
            {"name": "permissions:delete:all", "resource": "permissions", "action": "DELETE", "scope": "all"},

            # System permissions
            {"name": "system:admin:all", "resource": "system", "action": "GET", "scope": "all"},
            {"name": "system:admin:all", "resource": "system", "action": "POST", "scope": "all"},
            {"name": "system:admin:all", "resource": "system", "action": "PUT", "scope": "all"},
            {"name": "system:admin:all", "resource": "system", "action": "DELETE", "scope": "all"},
        ]

        # Create permissions
        permissions = []
        for perm_data in permissions_data:
            permission = Permission(**perm_data)
            session.add(permission)
            permissions.append(permission)

        await session.commit()

        # Define initial roles
        roles_data = [
            {
                "name": "farmer",
                "description": "Basic user role for farmers",
                "permissions": ["users:read:own", "users:update:own", "users:delete:own", "analytics:read:all", "sensors:read:all"]
            },
            {
                "name": "technician",
                "description": "Technician role with sensor management capabilities",
                "permissions": ["users:read:own", "users:update:own", "users:delete:own", "analytics:read:all", "sensors:read:all", "sensors:update:all", "sensors:create:all", "analytics:export:all"]
            },
            {
                "name": "manager",
                "description": "Manager role with user and reporting capabilities",
                "permissions": ["users:read:all", "users:create:all", "users:update:all", "analytics:read:all", "sensors:read:all", "sensors:update:all", "sensors:create:all", "analytics:export:all", "reports:admin:all"]
            },
            {
                "name": "admin",
                "description": "Administrator role with full system access",
                "permissions": ["users:read:all", "users:create:all", "users:update:all", "users:delete:all", "analytics:read:all", "sensors:read:all", "sensors:update:all", "sensors:create:all", "sensors:delete:all", "roles:read:all", "roles:create:all", "roles:update:all", "roles:delete:all", "permissions:read:all", "permissions:create:all", "permissions:update:all", "permissions:delete:all", "system:admin:all", "analytics:export:all", "reports:admin:all"]
            }
        ]

        # Create roles and assign permissions
        for role_data in roles_data:
            role = Role(
                name=role_data["name"],
                description=role_data["description"]
            )
            session.add(role)
            await session.commit()  # Commit to get role ID

            # Assign permissions to role
            for perm_name in role_data["permissions"]:
                permission = next((p for p in permissions if p.name == perm_name), None)
                if permission:
                    role_permission = RolePermission(role_id=role.id, permission_id=permission.id)
                    session.add(role_permission)

            await session.commit()

        logger.info("Initial roles and permissions created successfully")
        return True

    except Exception as e:
        await session.rollback()
        logger.error("Failed to create initial data", error=str(e))
        return False


async def create_indexes(engine):
    """Create additional database indexes for performance."""
    try:
        logger.info("Creating additional indexes...")

        # Execute raw SQL for indexes
        index_queries = [
            "CREATE INDEX IF NOT EXISTS idx_users_email_active ON users(email) WHERE is_active = true;",
            "CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);",
            "CREATE INDEX IF NOT EXISTS idx_users_updated_at ON users(updated_at);",
            "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_expires ON refresh_tokens(user_id, expires_at);",
            "CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);",
            "CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);",
            "CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);",
            "CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);",
            "CREATE INDEX IF NOT EXISTS idx_permissions_resource_action ON permissions(resource, action);",
        ]

        async with engine.begin() as conn:
            for query in index_queries:
                await conn.execute(query)

        logger.info("Additional indexes created successfully")
        return True

    except Exception as e:
        logger.error("Failed to create indexes", error=str(e))
        return False


async def main():
    """Main initialization function."""
    logger.info("Starting database initialization...")

    # Create async engine
    engine = create_async_engine(
        settings.database.url,
        echo=settings.debug,
        pool_size=settings.database.pool_size,
        max_overflow=settings.database.max_overflow,
        pool_timeout=settings.database.pool_timeout,
        pool_recycle=settings.database.pool_recycle
    )

    # Create session factory
    async_session_factory = sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False
    )

    try:
        # Create tables
        if not await create_tables(engine):
            logger.error("Failed to create tables")
            return False

        # Create initial data
        async with async_session_factory() as session:
            if not await create_initial_roles_permissions(session):
                logger.error("Failed to create initial data")
                return False

        # Create indexes
        if not await create_indexes(engine):
            logger.error("Failed to create indexes")
            return False

        logger.info("Database initialization completed successfully!")
        return True

    except Exception as e:
        logger.error("Database initialization failed", error=str(e))
        return False

    finally:
        await engine.dispose()


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)
