"""
JWT Authentication Token domain entity.
Represents JWT tokens and their metadata in the authentication system.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from uuid import UUID
import jwt
from jose import JWTError


@dataclass
class AuthToken:
    """
    JWT Authentication Token value object.

    Represents access and refresh tokens with their metadata
    and provides methods for token creation and validation.
    """

    # Token data
    access_token: str = ""
    refresh_token: str = ""
    token_type: str = "bearer"

    # Token metadata
    user_id: Optional[UUID] = None
    email: str = ""
    roles: list = field(default_factory=list)
    permissions: list = field(default_factory=list)

    # Expiration times
    access_token_expires_at: Optional[datetime] = None
    refresh_token_expires_at: Optional[datetime] = None

    # Issued at
    issued_at: datetime = field(default_factory=datetime.now)

    @classmethod
    def create_access_token(
        cls,
        data: Dict[str, Any],
        secret_key: str,
        algorithm: str = "HS256",
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create a JWT access token.

        Args:
            data: Token payload data
            secret_key: JWT secret key
            algorithm: JWT algorithm
            expires_delta: Token expiration time delta

        Returns:
            Encoded JWT token string
        """
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.now() + expires_delta
        else:
            expire = datetime.now() + timedelta(minutes=15)

        to_encode.update({"exp": expire, "iat": datetime.now(), "type": "access"})

        encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)
        return encoded_jwt

    @classmethod
    def create_refresh_token(
        cls,
        data: Dict[str, Any],
        secret_key: str,
        algorithm: str = "HS256",
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create a JWT refresh token.

        Args:
            data: Token payload data
            secret_key: JWT secret key
            algorithm: JWT algorithm
            expires_delta: Token expiration time delta

        Returns:
            Encoded JWT token string
        """
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.now() + expires_delta
        else:
            expire = datetime.now() + timedelta(days=7)

        to_encode.update({"exp": expire, "iat": datetime.now(), "type": "refresh"})

        encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)
        return encoded_jwt

    @classmethod
    def create_token_pair(
        cls,
        user_id: UUID,
        email: str,
        roles: list,
        permissions: list,
        secret_key: str,
        access_expires_delta: Optional[timedelta] = None,
        refresh_expires_delta: Optional[timedelta] = None,
        algorithm: str = "HS256"
    ) -> 'AuthToken':
        """
        Create a complete access and refresh token pair.

        Args:
            user_id: User UUID
            email: User email
            roles: User roles list
            permissions: User permissions list
            secret_key: JWT secret key
            access_expires_delta: Access token expiration delta
            refresh_expires_delta: Refresh token expiration delta
            algorithm: JWT algorithm

        Returns:
            AuthToken instance with both tokens
        """
        token_data = {
            "sub": str(user_id),
            "email": email,
            "roles": roles,
            "permissions": permissions
        }

        access_token = cls.create_access_token(
            token_data, secret_key, algorithm, access_expires_delta
        )

        refresh_token = cls.create_refresh_token(
            token_data, secret_key, algorithm, refresh_expires_delta
        )

        # Calculate expiration times
        access_expires = datetime.now() + (access_expires_delta or timedelta(minutes=15))
        refresh_expires = datetime.now() + (refresh_expires_delta or timedelta(days=7))

        return cls(
            access_token=access_token,
            refresh_token=refresh_token,
            user_id=user_id,
            email=email,
            roles=roles,
            permissions=permissions,
            access_token_expires_at=access_expires,
            refresh_token_expires_at=refresh_expires
        )

    @classmethod
    def decode_token(
        cls,
        token: str,
        secret_key: str,
        algorithm: str = "HS256"
    ) -> Dict[str, Any]:
        """
        Decode and validate a JWT token.

        Args:
            token: JWT token string
            secret_key: JWT secret key
            algorithm: JWT algorithm

        Returns:
            Decoded token payload

        Raises:
            JWTError: If token is invalid or expired
        """
        try:
            payload = jwt.decode(token, secret_key, algorithms=[algorithm])
            return payload
        except JWTError as e:
            raise JWTError(f"Token validation failed: {str(e)}")

    @classmethod
    def validate_access_token(
        cls,
        token: str,
        secret_key: str,
        algorithm: str = "HS256"
    ) -> Dict[str, Any]:
        """
        Validate an access token and return its payload.

        Args:
            token: Access token string
            secret_key: JWT secret key
            algorithm: JWT algorithm

        Returns:
            Token payload if valid

        Raises:
            JWTError: If token is invalid
        """
        payload = cls.decode_token(token, secret_key, algorithm)

        if payload.get("type") != "access":
            raise JWTError("Token is not an access token")

        return payload

    @classmethod
    def validate_refresh_token(
        cls,
        token: str,
        secret_key: str,
        algorithm: str = "HS256"
    ) -> Dict[str, Any]:
        """
        Validate a refresh token and return its payload.

        Args:
            token: Refresh token string
            secret_key: JWT secret key
            algorithm: JWT algorithm

        Returns:
            Token payload if valid

        Raises:
            JWTError: If token is invalid
        """
        payload = cls.decode_token(token, secret_key, algorithm)

        if payload.get("type") != "refresh":
            raise JWTError("Token is not a refresh token")

        return payload

    def is_access_token_expired(self) -> bool:
        """Check if access token is expired."""
        if not self.access_token_expires_at:
            return True
        return datetime.now() >= self.access_token_expires_at

    def is_refresh_token_expired(self) -> bool:
        """Check if refresh token is expired."""
        if not self.refresh_token_expires_at:
            return True
        return datetime.now() >= self.refresh_token_expires_at

    def to_dict(self) -> Dict[str, Any]:
        """Convert token to dictionary representation."""
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
            "user_id": str(self.user_id) if self.user_id else None,
            "email": self.email,
            "roles": self.roles,
            "permissions": self.permissions,
            "access_token_expires_at": self.access_token_expires_at.isoformat() if self.access_token_expires_at else None,
            "refresh_token_expires_at": self.refresh_token_expires_at.isoformat() if self.refresh_token_expires_at else None,
            "issued_at": self.issued_at.isoformat()
        }
