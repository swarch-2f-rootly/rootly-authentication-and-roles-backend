"""
Password service implementation.
Handles password hashing, verification, and strength validation.
"""

import re
import bcrypt
from typing import Optional

from ..ports.logger import Logger
from ..ports.exceptions import PasswordTooWeakError


class PasswordService:
    """
    Password service for handling password operations.
    """

    def __init__(self, logger: Logger):
        """
        Initialize password service.

        Args:
            logger: Logger instance for logging operations
        """
        self.logger = logger

    async def hash_password(self, password: str) -> str:
        """
        Hash a password using bcrypt.

        Args:
            password: Plain text password

        Returns:
            Hashed password string
        """
        try:
            # Generate salt and hash password
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

            # Return as string
            return hashed.decode('utf-8')
        except Exception as e:
            self.logger.error("Failed to hash password", error=str(e))
            raise PasswordTooWeakError("Failed to process password")

    async def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.

        Args:
            password: Plain text password
            hashed_password: Hashed password string

        Returns:
            True if password matches hash, False otherwise
        """
        try:
            # Verify password against hash
            return bcrypt.checkpw(
                password.encode('utf-8'),
                hashed_password.encode('utf-8')
            )
        except Exception as e:
            self.logger.error("Failed to verify password", error=str(e))
            return False

    async def validate_password_strength(self, password: str) -> bool:
        """
        Validate password strength requirements.

        Password must:
        - Be at least 8 characters long
        - Contain at least one uppercase letter
        - Contain at least one lowercase letter
        - Contain at least one digit
        - Contain at least one special character

        Args:
            password: Password to validate

        Returns:
            True if password meets requirements

        Raises:
            PasswordTooWeakError: If password doesn't meet requirements
        """
        if not password:
            raise PasswordTooWeakError("Password cannot be empty")

        if len(password) < 8:
            raise PasswordTooWeakError("Password must be at least 8 characters long")

        # Check for required character types
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password))

        if not has_uppercase:
            raise PasswordTooWeakError("Password must contain at least one uppercase letter")

        if not has_lowercase:
            raise PasswordTooWeakError("Password must contain at least one lowercase letter")

        if not has_digit:
            raise PasswordTooWeakError("Password must contain at least one digit")

        if not has_special:
            raise PasswordTooWeakError("Password must contain at least one special character")

        return True

    async def is_password_compromised(self, password: str) -> bool:
        """
        Check if password is in common password lists.
        This is a basic implementation - in production, you might want to
        use a service like HaveIBeenPwned API.

        Args:
            password: Password to check

        Returns:
            True if password appears to be compromised
        """
        # Common weak passwords to check against
        common_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            '1234567890', 'password1', 'qwerty123', 'welcome123'
        }

        # Check if password is in common list
        if password.lower() in common_passwords:
            self.logger.warn("Password found in common password list", password_length=len(password))
            return True

        return False

    async def generate_secure_password(self, length: int = 12) -> str:
        """
        Generate a secure random password.

        Args:
            length: Desired password length (minimum 8)

        Returns:
            Secure random password string
        """
        import secrets
        import string

        if length < 8:
            length = 8

        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = '!@#$%^&*()_+-=[]{}|;:,.<>?'

        # Ensure at least one character from each set
        password_chars = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]

        # Fill remaining length with random characters
        all_chars = lowercase + uppercase + digits + special
        password_chars.extend(secrets.choice(all_chars) for _ in range(length - 4))

        # Shuffle the characters
        secrets.SystemRandom().shuffle(password_chars)

        return ''.join(password_chars)
