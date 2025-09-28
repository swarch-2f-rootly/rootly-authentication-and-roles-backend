"""
Unit tests for UserService.
"""

import pytest
import pytest_asyncio
import sys
from pathlib import Path
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

# Add src directory to Python path
project_root = Path(__file__).parent.parent.parent
src_path = project_root / 'src'
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from core.services.user_service import UserService
from core.domain.user import User
from core.ports.exceptions import PasswordTooWeakError
from core.domain.role import Role
from core.ports.exceptions import (
    UserAlreadyExistsError,
    UserNotFoundError,
    ValidationError,
    InvalidCredentialsError
)


class TestUserService:
    """Test cases for UserService."""

    @pytest.fixture
    def user_service(self, mock_user_repository, mock_role_repository, mock_password_service, mock_logger):
        """Create UserService instance for testing."""
        return UserService(
            user_repository=mock_user_repository,
            role_repository=mock_role_repository,
            password_service=mock_password_service,
            logger=mock_logger
        )

    @pytest.fixture
    def test_user_entity(self):
        """Create test user entity."""
        return User(
            id=uuid4(),
            email="test@example.com",
            password_hash="$2b$12$hashed_password",
            first_name="Test",
            last_name="User",
            is_active=True,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            _roles=[]
        )

    @pytest.fixture
    def test_role_entity(self):
        """Create test role entity."""
        return Role(
            id=uuid4(),
            name="farmer",
            description="Basic farmer role",
            created_at=datetime.now()
        )



    @pytest.mark.asyncio
    async def test_create_user_invalid_email(
        self, 
        user_service, 
        mock_user_repository
    ):
        """Test user creation with invalid email."""
        # Setup mock
        mock_user_repository.exists_by_email = AsyncMock(return_value=False)
        
        # Test user creation with invalid email
        with pytest.raises(ValidationError):
            await user_service.create_user(
                email="invalid-email",
                password="password123",
                first_name="Test",
                last_name="User"
            )


    @pytest.mark.asyncio
    async def test_get_user_by_id_success(
        self, 
        user_service, 
        test_user_entity, 
        mock_user_repository
    ):
        """Test successful user retrieval by ID."""
        # Setup mock
        mock_user_repository.find_by_id = AsyncMock(return_value=test_user_entity)
        
        # Test user retrieval
        result = await user_service.get_user_by_id(test_user_entity.id)
        
        # Assertions
        assert result == test_user_entity
        mock_user_repository.find_by_id.assert_called_once_with(test_user_entity.id)

    @pytest.mark.asyncio
    async def test_get_user_by_id_not_found(
        self, 
        user_service, 
        mock_user_repository
    ):
        """Test user retrieval when user not found."""
        # Setup mock
        user_id = uuid4()
        mock_user_repository.find_by_id = AsyncMock(return_value=None)
        
        # Test user retrieval with non-existent user
        result = await user_service.get_user_by_id(user_id)
        assert result is None

    @pytest.mark.asyncio
    async def test_get_user_by_email_success(
        self, 
        user_service, 
        test_user_entity, 
        mock_user_repository
    ):
        """Test successful user retrieval by email."""
        # Setup mock
        mock_user_repository.find_by_email = AsyncMock(return_value=test_user_entity)
        
        # Test user retrieval
        result = await user_service.get_user_by_email(test_user_entity.email)
        
        # Assertions
        assert result == test_user_entity
        mock_user_repository.find_by_email.assert_called_once_with(test_user_entity.email)

    @pytest.mark.asyncio
    async def test_get_user_by_email_not_found(
        self, 
        user_service, 
        mock_user_repository
    ):
        """Test user retrieval by email when user not found."""
        # Setup mock
        mock_user_repository.find_by_email = AsyncMock(return_value=None)
        
        # Test user retrieval with non-existent email
        result = await user_service.get_user_by_email("nonexistent@example.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_update_user_profile_success(
        self, 
        user_service, 
        test_user_entity, 
        mock_user_repository
    ):
        """Test successful user profile update."""
        # Setup mocks
        mock_user_repository.find_by_id = AsyncMock(return_value=test_user_entity)
        
        updated_user = User(
            id=test_user_entity.id,
            email=test_user_entity.email,
            password_hash=test_user_entity.password_hash,
            first_name="Updated",
            last_name="Name",
            is_active=test_user_entity.is_active,
            created_at=test_user_entity.created_at,
            updated_at=datetime.now()
        )
        mock_user_repository.update = AsyncMock(return_value=updated_user)
        
        # Test profile update
        result = await user_service.update_user_profile(
            user_id=test_user_entity.id,
            first_name="Updated",
            last_name="Name"
        )
        
        # Assertions
        assert isinstance(result, User)
        assert result.first_name == "Updated"
        assert result.last_name == "Name"
        
        # Verify mocks were called
        mock_user_repository.find_by_id.assert_called_once_with(test_user_entity.id)
        mock_user_repository.update.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_user_profile_not_found(
        self, 
        user_service, 
        mock_user_repository
    ):
        """Test user profile update when user not found."""
        # Setup mock
        user_id = uuid4()
        mock_user_repository.find_by_id = AsyncMock(return_value=None)
        
        # Test profile update with non-existent user
        with pytest.raises(UserNotFoundError):
            await user_service.update_user_profile(
                user_id=user_id,
                first_name="Updated"
            )


    @pytest.mark.asyncio
    async def test_change_password_invalid_current(
        self, 
        user_service, 
        test_user_entity, 
        mock_user_repository, 
        mock_password_service
    ):
        """Test password change with invalid current password."""
        # Setup mocks
        mock_user_repository.find_by_id = AsyncMock(return_value=test_user_entity)
        mock_password_service.verify_password = AsyncMock(return_value=False)
        
        # Test password change with invalid current password
        with pytest.raises(InvalidCredentialsError):
            await user_service.change_password(
                user_id=test_user_entity.id,
                current_password="wrong_password",
                new_password="new_password123"
            )

    @pytest.mark.asyncio
    async def test_activate_user_success(
        self, 
        user_service, 
        test_user_entity, 
        mock_user_repository
    ):
        """Test successful user activation."""
        # Make user inactive first
        test_user_entity.is_active = False
        
        # Setup mocks
        mock_user_repository.find_by_id = AsyncMock(return_value=test_user_entity)
        
        activated_user = User(
            id=test_user_entity.id,
            email=test_user_entity.email,
            password_hash=test_user_entity.password_hash,
            first_name=test_user_entity.first_name,
            last_name=test_user_entity.last_name,
            is_active=True,
            created_at=test_user_entity.created_at,
            updated_at=datetime.now()
        )
        mock_user_repository.update = AsyncMock(return_value=activated_user)
        
        # Test user activation
        result = await user_service.activate_user(test_user_entity.id)

        # Assertions
        assert result is True
        
        # Verify mocks were called
        mock_user_repository.find_by_id.assert_called_once_with(test_user_entity.id)
        mock_user_repository.update.assert_called_once()

    @pytest.mark.asyncio
    async def test_deactivate_user_success(
        self, 
        user_service, 
        test_user_entity, 
        mock_user_repository
    ):
        """Test successful user deactivation."""
        # Setup mocks
        mock_user_repository.find_by_id = AsyncMock(return_value=test_user_entity)
        
        deactivated_user = User(
            id=test_user_entity.id,
            email=test_user_entity.email,
            password_hash=test_user_entity.password_hash,
            first_name=test_user_entity.first_name,
            last_name=test_user_entity.last_name,
            is_active=False,
            created_at=test_user_entity.created_at,
            updated_at=datetime.now()
        )
        mock_user_repository.update = AsyncMock(return_value=deactivated_user)
        
        # Test user deactivation
        result = await user_service.deactivate_user(test_user_entity.id)

        # Assertions
        assert result is True
        
        # Verify mocks were called
        mock_user_repository.find_by_id.assert_called_once_with(test_user_entity.id)
        mock_user_repository.update.assert_called_once()


    @pytest.mark.asyncio
    async def test_delete_user_not_found(
        self, 
        user_service, 
        mock_user_repository
    ):
        """Test user deletion when user not found."""
        # Setup mock
        user_id = uuid4()
        mock_user_repository.find_by_id = AsyncMock(return_value=None)
        
        # Test user deletion with non-existent user
        result = await user_service.delete_user(user_id)
        assert result is False

    @pytest.mark.asyncio
    async def test_list_users_success(
        self, 
        user_service, 
        mock_user_repository
    ):
        """Test successful user listing."""
        # Create test users
        users = [
            User(id=uuid4(), email="user1@example.com", password_hash="hash1", 
                 first_name="User", last_name="One", is_active=True, 
                 created_at=datetime.now(), updated_at=datetime.now()),
            User(id=uuid4(), email="user2@example.com", password_hash="hash2", 
                 first_name="User", last_name="Two", is_active=True, 
                 created_at=datetime.now(), updated_at=datetime.now())
        ]
        
        # Setup mock
        mock_user_repository.find_all = AsyncMock(return_value=users)
        
        # Test user listing
        result = await user_service.list_users(skip=0, limit=10)
        
        # Assertions
        assert isinstance(result, list)
        assert len(result) == 2
        assert all(isinstance(user, User) for user in result)
        
        # Verify mock was called
        mock_user_repository.find_all.assert_called_once_with(skip=0, limit=10)


    @pytest.mark.asyncio
    async def test_assign_role_to_user_user_not_found(
        self, 
        user_service, 
        mock_user_repository
    ):
        """Test role assignment when user not found."""
        # Setup mock
        user_id = uuid4()
        role_id = uuid4()
        mock_user_repository.exists_by_id = AsyncMock(return_value=False)

        # Test role assignment with non-existent user
        with pytest.raises(UserNotFoundError):
            await user_service.assign_role_to_user(user_id, role_id)
