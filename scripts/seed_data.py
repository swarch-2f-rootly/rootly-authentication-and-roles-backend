#!/usr/bin/env python3
"""
Seed data script for the Authentication Service.
Creates initial users and test data.
"""

import asyncio
import os
from uuid import uuid4

# Add the src directory to the path
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from adapters.models import User, Role, UserRole
from core.services.password_service import PasswordService
from adapters.logger.standard_logger import StandardLogger
from config.settings import get_settings

settings = get_settings()
logger = StandardLogger("seed_data", settings.log_level)


async def create_admin_user(session: AsyncSession, password_service: PasswordService):
    """Create default admin user."""
    try:
        logger.info("Creating default admin user...")

        # Check if admin user already exists
        from sqlalchemy import select
        result = await session.execute(
            select(User).where(User.email == "admin@rootly.com")
        )
        existing_admin = result.scalar_one_or_none()

        if existing_admin:
            logger.info("Admin user already exists")
            return existing_admin

        # Get admin role
        result = await session.execute(
            select(Role).where(Role.name == "admin")
        )
        admin_role = result.scalar_one_or_none()

        if not admin_role:
            logger.error("Admin role not found. Please run init_database.py first.")
            return None

        # Create admin user
        admin_password = "Admin123!"  # Default password - should be changed in production
        hashed_password = await password_service.hash_password(admin_password)

        admin_user = User(
            email="admin@rootly.com",
            password_hash=hashed_password,
            first_name="System",
            last_name="Administrator"
        )

        session.add(admin_user)
        await session.commit()
        await session.refresh(admin_user)

        # Assign admin role
        user_role = UserRole(user_id=admin_user.id, role_id=admin_role.id)
        session.add(user_role)
        await session.commit()

        logger.info("Default admin user created successfully")
        logger.info("Email: admin@rootly.com")
        logger.info("Password: Admin123!")
        logger.warn("⚠️  Please change the default password immediately!")

        return admin_user

    except Exception as e:
        await session.rollback()
        logger.error("Failed to create admin user", error=str(e))
        return None


async def create_test_users(session: AsyncSession, password_service: PasswordService):
    """Create test users for different roles."""
    try:
        logger.info("Creating test users...")

        test_users_data = [
            {
                "email": "farmer@rootly.com",
                "password": "Farmer123!",
                "first_name": "Juan",
                "last_name": "Farmer",
                "role": "farmer"
            },
            {
                "email": "tech@rootly.com",
                "password": "Tech123!",
                "first_name": "Maria",
                "last_name": "Technician",
                "role": "technician"
            },
            {
                "email": "manager@rootly.com",
                "password": "Manager123!",
                "first_name": "Carlos",
                "last_name": "Manager",
                "role": "manager"
            }
        ]

        created_users = []

        for user_data in test_users_data:
            # Check if user already exists
            from sqlalchemy import select
            result = await session.execute(
                select(User).where(User.email == user_data["email"])
            )
            existing_user = result.scalar_one_or_none()

            if existing_user:
                logger.info(f"Test user {user_data['email']} already exists")
                continue

            # Get role
            result = await session.execute(
                select(Role).where(Role.name == user_data["role"])
            )
            role = result.scalar_one_or_none()

            if not role:
                logger.warn(f"Role {user_data['role']} not found, skipping user {user_data['email']}")
                continue

            # Create user
            hashed_password = await password_service.hash_password(user_data["password"])

            user = User(
                email=user_data["email"],
                password_hash=hashed_password,
                first_name=user_data["first_name"],
                last_name=user_data["last_name"]
            )

            session.add(user)
            await session.commit()
            await session.refresh(user)

            # Assign role
            user_role = UserRole(user_id=user.id, role_id=role.id)
            session.add(user_role)
            await session.commit()

            created_users.append(user_data)
            logger.info(f"Created test user: {user_data['email']}")

        if created_users:
            logger.info("Test users created successfully:")
            for user in created_users:
                logger.info(f"  - {user['email']}: {user['password']} (Role: {user['role']})")

        return created_users

    except Exception as e:
        await session.rollback()
        logger.error("Failed to create test users", error=str(e))
        return []


async def main():
    """Main seed data function."""
    logger.info("Starting database seeding...")

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

    # Initialize password service
    password_service = PasswordService(logger)

    try:
        async with async_session_factory() as session:
            # Create admin user
            admin_user = await create_admin_user(session, password_service)
            if not admin_user:
                logger.error("Failed to create admin user")
                return False

            # Create test users
            test_users = await create_test_users(session, password_service)

        logger.info("Database seeding completed successfully!")
        logger.info("=" * 50)
        logger.info("Default Users Created:")
        logger.info("Admin: admin@rootly.com / Admin123!")
        logger.info("Farmer: farmer@rootly.com / Farmer123!")
        logger.info("Technician: tech@rootly.com / Tech123!")
        logger.info("Manager: manager@rootly.com / Manager123!")
        logger.warn("⚠️  Remember to change default passwords in production!")
        logger.info("=" * 50)

        return True

    except Exception as e:
        logger.error("Database seeding failed", error=str(e))
        return False

    finally:
        await engine.dispose()


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)
