"""
Unit tests for AuthService.
"""

import pytest
import pytest_asyncio
import sys
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import uuid4

# Add src directory to Python path
project_root = Path(__file__).parent.parent.parent
src_path = project_root / 'src'
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from core.services.auth_service import AuthService
from core.domain.user import User
from core.domain.auth_token import AuthToken
from core.ports.exceptions import (
    InvalidCredentialsError,
    AccountInactiveError,
    InvalidTokenError,
    TokenExpiredError
)


class TestAuthService:
    """Test cases for AuthService."""

    @pytest.fixture
    def auth_service(self, mock_user_repository, mock_refresh_token_repository, mock_password_service, mock_logger):
        """Create AuthService instance for testing."""
        return AuthService(
            user_repository=mock_user_repository,
            refresh_token_repository=mock_refresh_token_repository,
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
    def inactive_user_entity(self):
        """Create inactive test user entity."""
        return User(
            id=uuid4(),
            email="inactive@example.com",
            password_hash="$2b$12$hashed_password",
            first_name="Inactive",
            last_name="User",
            is_active=False,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            _roles=[]
        )


    @pytest.mark.asyncio
    async def test_authenticate_user_invalid_email(
        self, 
        auth_service, 
        mock_user_repository
    ):
        """Test authentication with invalid email."""
        # Setup mock
        mock_user_repository.find_by_email = AsyncMock(return_value=None)
        
        # Test authentication with invalid email
        with pytest.raises(InvalidCredentialsError):
            await auth_service.authenticate_user("invalid@example.com", "testpass123")

    @pytest.mark.asyncio
    async def test_authenticate_user_inactive_account(
        self, 
        auth_service, 
        inactive_user_entity, 
        mock_user_repository
    ):
        """Test authentication with inactive account."""
        # Setup mock
        mock_user_repository.find_by_email = AsyncMock(return_value=inactive_user_entity)
        
        # Test authentication with inactive account
        with pytest.raises(AccountInactiveError):
            await auth_service.authenticate_user("inactive@example.com", "testpass123")

    @pytest.mark.asyncio
    async def test_authenticate_user_invalid_password(
        self, 
        auth_service, 
        test_user_entity, 
        mock_user_repository, 
        mock_password_service
    ):
        """Test authentication with invalid password."""
        # Setup mocks
        mock_user_repository.find_by_email = AsyncMock(return_value=test_user_entity)
        mock_password_service.verify_password = AsyncMock(return_value=False)
        
        # Test authentication with invalid password
        with pytest.raises(InvalidCredentialsError):
            await auth_service.authenticate_user("test@example.com", "wrongpassword")



    @pytest.mark.asyncio
    async def test_validate_access_token_invalid(
        self, 
        auth_service
    ):
        """Test access token validation with invalid token."""
        with patch('jwt.decode') as mock_jwt_decode:
            from jose import jwt as jose_jwt
            mock_jwt_decode.side_effect = jose_jwt.JWTError()
            
            # Test token validation with invalid token
            with pytest.raises(InvalidTokenError):
                await auth_service.validate_access_token("invalid_token")


    @pytest.mark.asyncio
    async def test_refresh_access_token_invalid(
        self, 
        auth_service, 
        mock_refresh_token_repository
    ):
        """Test access token refresh with invalid refresh token."""
        # Setup mock
        mock_refresh_token_repository.find_by_token_hash = AsyncMock(return_value=None)
        
        # Test token refresh with invalid refresh token
        with pytest.raises(InvalidTokenError):
            await auth_service.refresh_access_token("invalid_refresh_token")



    @pytest.mark.asyncio
    async def test_revoke_refresh_token_not_found(
        self, 
        auth_service, 
        mock_refresh_token_repository
    ):
        """Test refresh token revocation with non-existent token."""
        # Setup mock
        mock_refresh_token_repository.delete_by_token_hash = AsyncMock(return_value=False)
        
        # Test token revocation with non-existent token
        result = await auth_service.revoke_refresh_token("nonexistent_token")
        
        # Assertions
        assert result is False


    @pytest.mark.asyncio
    async def test_get_current_user_invalid_token(
        self, 
        auth_service
    ):
        """Test current user retrieval with invalid token."""
        with patch('jwt.decode') as mock_jwt_decode:
            from jose import jwt as jose_jwt
            mock_jwt_decode.side_effect = jose_jwt.JWTError()
            
            # Test get current user with invalid token
            result = await auth_service.get_current_user("invalid_token")
            
            # Assertions
            assert result is None

    @pytest.mark.asyncio
    async def test_get_current_user_not_found(
        self, 
        auth_service, 
        mock_user_repository
    ):
        """Test current user retrieval when user not found in database."""
        # Setup mock
        mock_user_repository.find_by_id = AsyncMock(return_value=None)
        
        test_payload = {
            "sub": str(uuid4()),
            "email": "test@example.com",
            "roles": ["farmer"],
            "exp": datetime.utcnow() + timedelta(minutes=15)
        }
        
        with patch('jwt.decode') as mock_jwt_decode:
            mock_jwt_decode.return_value = test_payload
            
            # Test get current user when user not found
            result = await auth_service.get_current_user("valid_token")
            
            # Assertions
            assert result is None
