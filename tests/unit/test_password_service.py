"""
Unit tests for PasswordService.
"""

import pytest
import pytest_asyncio
import sys
from pathlib import Path

# Add src directory to Python path
project_root = Path(__file__).parent.parent.parent
src_path = project_root / 'src'
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from core.services.password_service import PasswordService


class TestPasswordService:
    """Test cases for PasswordService."""

    @pytest.fixture
    def password_service(self, mock_logger):
        """Create PasswordService instance for testing."""
        return PasswordService(mock_logger)

    @pytest.mark.asyncio
    async def test_hash_password_success(self, password_service):
        """Test successful password hashing."""
        password = "testpassword123"
        
        # Test password hashing
        hashed = await password_service.hash_password(password)
        
        # Assertions
        assert isinstance(hashed, str)
        assert hashed.startswith("$2b$")
        assert len(hashed) > 50  # bcrypt hashes are typically 60 characters
        assert hashed != password  # Ensure it's actually hashed

    @pytest.mark.asyncio
    async def test_hash_password_different_results(self, password_service):
        """Test that hashing the same password produces different results (due to salt)."""
        password = "testpassword123"
        
        # Hash the same password twice
        hash1 = await password_service.hash_password(password)
        hash2 = await password_service.hash_password(password)
        
        # Assertions
        assert hash1 != hash2  # Different due to different salts
        # Both hashes can verify the same password
        assert await password_service.verify_password(password, hash1)
        assert await password_service.verify_password(password, hash2)

    @pytest.mark.asyncio
    async def test_verify_password_correct(self, password_service):
        """Test password verification with correct password."""
        password = "testpassword123"
        
        # Hash password first
        hashed = await password_service.hash_password(password)
        
        # Test verification with correct password
        result = await password_service.verify_password(password, hashed)
        
        # Assertions
        assert result is True

    @pytest.mark.asyncio
    async def test_verify_password_incorrect(self, password_service):
        """Test password verification with incorrect password."""
        correct_password = "testpassword123"
        incorrect_password = "wrongpassword"
        
        # Hash correct password
        hashed = await password_service.hash_password(correct_password)
        
        # Test verification with incorrect password
        result = await password_service.verify_password(incorrect_password, hashed)
        
        # Assertions
        assert result is False

    @pytest.mark.asyncio
    async def test_verify_password_empty_password(self, password_service):
        """Test password verification with empty password."""
        password = "testpassword123"
        
        # Hash password
        hashed = await password_service.hash_password(password)
        
        # Test verification with empty password
        result = await password_service.verify_password("", hashed)
        
        # Assertions
        assert result is False

    @pytest.mark.asyncio
    async def test_verify_password_invalid_hash(self, password_service):
        """Test password verification with invalid hash."""
        password = "testpassword123"
        invalid_hash = "invalid_hash_format"
        
        # Test verification with invalid hash
        result = await password_service.verify_password(password, invalid_hash)
        
        # Assertions
        assert result is False

    def test_validate_password_strength_strong(self, password_service):
        """Test password strength validation with strong password."""
        strong_passwords = [
            "StrongPass123!",
            "MySecureP@ssw0rd",
            "Complex1ty!",
            "Str0ng#Pass",
            "SecurePassword123$"
        ]
        
        for password in strong_passwords:
            result = password_service.validate_password_strength(password)
            assert result is True, f"Password {password} should be considered strong"

    def test_validate_password_strength_weak(self, password_service):
        """Test password strength validation with weak passwords."""
        weak_passwords = [
            "weak",           # Too short
            "password",       # Too common, no numbers/symbols
            "12345678",       # Only numbers
            "PASSWORD",       # Only uppercase
            "password123",    # No symbols, no uppercase
            "Password",       # No numbers, no symbols
            "Pass!",          # Too short
            "",               # Empty
            "   ",            # Only spaces
        ]

        for password in weak_passwords:
            with pytest.raises(Exception):  # Should raise PasswordTooWeakError
                password_service.validate_password_strength(password)

    def test_validate_password_strength_edge_cases(self, password_service):
        """Test password strength validation with edge cases."""
        # Cases that should fail (too short)
        failing_cases = ["A1a!"]  # Exactly 4 characters (too short)

        # Cases that should pass
        passing_cases = [
            "A1a!1234",     # Exactly 8 characters (minimum)
            "A" * 127 + "1a!",  # Very long but valid
            "Tëst123!",     # Unicode characters
            "Test 123!",    # Space character
        ]

        for password in failing_cases:
            with pytest.raises(Exception):  # Should raise PasswordTooWeakError
                password_service.validate_password_strength(password)

        for password in passing_cases:
            result = password_service.validate_password_strength(password)
            assert result is True, f"Password '{password}' should be considered valid"

    @pytest.mark.asyncio
    async def test_hash_password_empty_input(self, password_service):
        """Test password hashing with empty input."""
        # Test with empty string
        with pytest.raises(ValueError, match="Password cannot be empty"):
            await password_service.hash_password("")
        
        # Test with None
        with pytest.raises(ValueError, match="Password cannot be empty"):
            await password_service.hash_password(None)

    @pytest.mark.asyncio
    async def test_verify_password_none_inputs(self, password_service):
        """Test password verification with None inputs."""
        # Test with None password
        result = await password_service.verify_password(None, "$2b$12$validhash")
        assert result is False
        
        # Test with None hash
        result = await password_service.verify_password("password", None)
        assert result is False
        
        # Test with both None
        result = await password_service.verify_password(None, None)
        assert result is False

    def test_get_password_requirements(self, password_service):
        """Test getting password requirements."""
        requirements = password_service.get_password_requirements()
        
        # Assertions
        assert isinstance(requirements, dict)
        assert "min_length" in requirements
        assert "require_uppercase" in requirements
        assert "require_lowercase" in requirements
        assert "require_digit" in requirements
        assert "require_special" in requirements
        
        # Check default values
        assert requirements["min_length"] == 8
        assert requirements["require_uppercase"] is True
        assert requirements["require_lowercase"] is True
        assert requirements["require_digit"] is True
        assert requirements["require_special"] is True

    @pytest.mark.asyncio
    async def test_performance_multiple_hashes(self, password_service):
        """Test performance with multiple password hashes."""
        import time
        
        passwords = [f"testpass{i}!" for i in range(5)]
        
        start_time = time.time()
        
        # Hash multiple passwords
        hashes = []
        for password in passwords:
            hashed = await password_service.hash_password(password)
            hashes.append(hashed)
        
        end_time = time.time()
        
        # Assertions
        assert len(hashes) == len(passwords)
        assert all(isinstance(h, str) for h in hashes)
        assert len(set(hashes)) == len(hashes)  # All hashes should be unique
        
        # Performance should be reasonable (less than 5 seconds for 5 hashes)
        assert (end_time - start_time) < 5.0

    @pytest.mark.asyncio
    async def test_bcrypt_rounds_configuration(self, password_service):
        """Test that bcrypt rounds are properly configured."""
        password = "testpassword123"
        
        # Hash password
        hashed = await password_service.hash_password(password)
        
        # Check that the hash contains the expected rounds
        # bcrypt hashes have format: $2b$rounds$salthash
        parts = hashed.split('$')
        assert len(parts) == 4
        assert parts[1] == '2b'  # bcrypt variant
        rounds = int(parts[2])
        assert rounds >= 10  # Should use at least 10 rounds for security
        assert rounds <= 15  # Should not be too high for performance
