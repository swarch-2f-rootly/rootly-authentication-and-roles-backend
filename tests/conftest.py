"""
Pytest configuration and fixtures for authentication service tests.
"""

import asyncio
import sys
import os
from pathlib import Path
import pytest
import pytest_asyncio
from typing import AsyncGenerator, Generator, List
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

# Add src directory to Python path
project_root = Path(__file__).parent.parent
src_path = project_root / 'src'
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Import models and services
from adapters.models.base import Base
from adapters.models.user import User as UserModel
from adapters.models.role import Role as RoleModel
from adapters.models.permission import Permission as PermissionModel
from core.domain.user import User
from core.domain.role import Role
from core.domain.permission import Permission
from core.services.auth_service import AuthService
from core.services.user_service import UserService
from core.services.password_service import PasswordService
from core.services.migration_service import MigrationService
from core.services.seed_service import SeedService
from adapters.logger.standard_logger import StandardLogger
from config.settings import get_settings


# Test database URL - using in-memory SQLite for speed
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

settings = get_settings()


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def test_engine():
    """Create test database engine."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        pool_pre_ping=True
    )
    
    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    # Clean up
    await engine.dispose()


@pytest_asyncio.fixture
async def test_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session."""
    session_factory = sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )
    
    async with session_factory() as session:
        yield session
        await session.rollback()


@pytest.fixture
def mock_logger():
    """Mock logger for testing."""
    return StandardLogger("test", "DEBUG")


@pytest.fixture
def mock_password_service(mock_logger):
    """Mock password service for testing."""
    return PasswordService(mock_logger)


@pytest_asyncio.fixture
async def test_user(test_session: AsyncSession, mock_password_service: PasswordService) -> User:
    """Create a test user."""
    # Create test user in database
    hashed_password = await mock_password_service.hash_password("testpass123")
    
    user_model = UserModel(
        email="test@example.com",
        password_hash=hashed_password,
        first_name="Test",
        last_name="User",
        is_active=True
    )
    
    test_session.add(user_model)
    await test_session.commit()
    await test_session.refresh(user_model)
    
    # Convert to domain entity
    return User(
        id=user_model.id,
        email=user_model.email,
        password_hash=user_model.password_hash,
        first_name=user_model.first_name,
        last_name=user_model.last_name,
        is_active=user_model.is_active,
        created_at=user_model.created_at,
        updated_at=user_model.updated_at
    )


@pytest_asyncio.fixture
async def test_role(test_session: AsyncSession) -> Role:
    """Create a test role."""
    role_model = RoleModel(
        name="test_role",
        description="Test role for testing"
    )
    
    test_session.add(role_model)
    await test_session.commit()
    await test_session.refresh(role_model)
    
    return Role(
        id=role_model.id,
        name=role_model.name,
        description=role_model.description,
        created_at=role_model.created_at
    )


@pytest_asyncio.fixture
async def test_permission(test_session: AsyncSession) -> Permission:
    """Create a test permission."""
    permission_model = PermissionModel(
        name="test:read:own",
        resource="test",
        action="GET",
        scope="own"
    )
    
    test_session.add(permission_model)
    await test_session.commit()
    await test_session.refresh(permission_model)
    
    return Permission(
        id=permission_model.id,
        name=permission_model.name,
        resource=permission_model.resource,
        action=permission_model.action,
        scope=permission_model.scope,
        created_at=permission_model.created_at
    )


@pytest.fixture
def client():
    """Create test client for integration tests."""
    from src.main import app
    return TestClient(app)


# Mock implementations for unit testing
class MockUserRepository:
    """Mock user repository for unit tests."""
    
    def __init__(self):
        self.users = {}
        self.roles = {}
    
    async def save(self, user: User) -> User:
        self.users[user.id] = user
        return user
    
    async def find_by_id(self, user_id) -> User:
        return self.users.get(user_id)
    
    async def find_by_email(self, email: str) -> User:
        for user in self.users.values():
            if user.email == email:
                return user
        return None
    
    async def exists_by_email(self, email: str) -> bool:
        return any(user.email == email for user in self.users.values())

    async def find_all(self, skip: int = 0, limit: int = 10) -> List[User]:
        users_list = list(self.users.values())
        return users_list[skip:skip + limit]

    async def count_active(self) -> int:
        return len([u for u in self.users.values() if u.is_active])

    async def update(self, user: User) -> User:
        if user.id in self.users:
            self.users[user.id] = user
        return user

    async def delete(self, user_id) -> bool:
        if user_id in self.users:
            del self.users[user_id]
            return True
        return False

    async def get_user_roles(self, user_id) -> List[dict]:
        """Mock get_user_roles method."""
        return [{"name": "farmer", "id": str(uuid4())}]

    async def exists_by_id(self, user_id) -> bool:
        """Mock exists_by_id method."""
        return user_id in self.users

    async def assign_role_to_user(self, user_id, role_id) -> bool:
        """Mock assign_role_to_user method."""
        return True


class MockRefreshTokenRepository:
    """Mock refresh token repository for unit tests."""
    
    def __init__(self):
        self.tokens = {}
    
    async def save_refresh_token(self, user_id, token_hash: str, expires_at) -> bool:
        self.tokens[token_hash] = {
            'user_id': user_id,
            'expires_at': expires_at
        }
        return True
    
    async def find_by_token_hash(self, token_hash: str):
        return self.tokens.get(token_hash)
    
    async def delete_by_token_hash(self, token_hash: str) -> bool:
        if token_hash in self.tokens:
            del self.tokens[token_hash]
            return True
        return False


@pytest.fixture
def mock_user_repository():
    """Mock user repository fixture."""
    return MockUserRepository()


@pytest.fixture
def mock_refresh_token_repository():
    """Mock refresh token repository fixture."""
    return MockRefreshTokenRepository()


@pytest.fixture
def mock_role_repository():
    """Mock role repository fixture."""
    repo = AsyncMock()
    repo.find_by_id = AsyncMock()
    repo.find_by_name = AsyncMock()
    repo.find_all = AsyncMock(return_value=[])
    repo.exists_by_id = AsyncMock()
    return repo
