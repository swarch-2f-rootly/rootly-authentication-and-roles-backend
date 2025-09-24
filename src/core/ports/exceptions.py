"""
Domain exceptions for the authentication service.
Provides specific exception types for different error scenarios.
"""

from typing import Any, Dict, Optional


class AuthenticationServiceError(Exception):
    """Base exception for authentication service errors."""

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        status_code: int = 500
    ):
        self.message = message
        self.details = details or {}
        self.status_code = status_code
        super().__init__(self.message)


class AuthenticationError(AuthenticationServiceError):
    """Authentication-related errors."""

    def __init__(
        self,
        message: str = "Authentication failed",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, details, 401)


class AuthorizationError(AuthenticationServiceError):
    """Authorization-related errors."""

    def __init__(
        self,
        message: str = "Insufficient permissions",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, details, 403)


class ValidationError(AuthenticationServiceError):
    """Input validation errors."""

    def __init__(
        self,
        message: str = "Validation failed",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, details, 400)


class UserNotFoundError(AuthenticationServiceError):
    """User not found errors."""

    def __init__(
        self,
        message: str = "User not found",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, details, 404)


class UserAlreadyExistsError(AuthenticationServiceError):
    """User already exists errors."""

    def __init__(
        self,
        message: str = "User already exists",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, details, 409)


class InvalidCredentialsError(AuthenticationError):
    """Invalid login credentials."""

    def __init__(
        self,
        message: str = "Invalid email or password",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, details)


class AccountLockedError(AuthenticationError):
    """Account locked due to too many failed attempts."""

    def __init__(
        self,
        message: str = "Account is temporarily locked",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, details)


class AccountInactiveError(AuthenticationError):
    """Account is inactive/deactivated."""

    def __init__(
        self,
        message: str = "Account is inactive",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, details)


class TokenExpiredError(AuthenticationError):
    """JWT token has expired."""

    def __init__(
        self,
        message: str = "Token has expired",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, details)


class InvalidTokenError(AuthenticationError):
    """Invalid or malformed JWT token."""

    def __init__(
        self,
        message: str = "Invalid token",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, details)


class FileUploadError(AuthenticationServiceError):
    """File upload related errors."""

    def __init__(
        self,
        message: str = "File upload failed",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, details, 400)


class FileTooLargeError(FileUploadError):
    """File exceeds maximum allowed size."""

    def __init__(
        self,
        max_size_mb: int,
        details: Optional[Dict[str, Any]] = None
    ):
        message = f"File size exceeds maximum allowed size of {max_size_mb}MB"
        super().__init__(message, details)


class InvalidFileTypeError(FileUploadError):
    """File type is not allowed."""

    def __init__(
        self,
        allowed_types: list,
        details: Optional[Dict[str, Any]] = None
    ):
        message = f"File type not allowed. Allowed types: {', '.join(allowed_types)}"
        super().__init__(message, details)


class RepositoryError(AuthenticationServiceError):
    """Database or repository related errors."""

    def __init__(
        self,
        message: str = "Database operation failed",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, details, 500)


class ExternalServiceError(AuthenticationServiceError):
    """External service (MinIO, etc.) related errors."""

    def __init__(
        self,
        service_name: str,
        message: str = "External service error",
        details: Optional[Dict[str, Any]] = None,
        status_code: int = 502
    ):
        self.service_name = service_name
        super().__init__(message, details, status_code)


class RoleNotFoundError(AuthenticationServiceError):
    """Role not found errors."""

    def __init__(
        self,
        message: str = "Role not found",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, details, 404)


class PermissionNotFoundError(AuthenticationServiceError):
    """Permission not found errors."""

    def __init__(
        self,
        message: str = "Permission not found",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, details, 404)


class InsufficientPermissionsError(AuthorizationError):
    """User lacks required permissions."""

    def __init__(
        self,
        required_permissions: list,
        details: Optional[Dict[str, Any]] = None
    ):
        message = f"Insufficient permissions. Required: {', '.join(required_permissions)}"
        super().__init__(message, details)


class PasswordTooWeakError(ValidationError):
    """Password does not meet complexity requirements."""

    def __init__(
        self,
        message: str = "Password does not meet complexity requirements",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, details)


class EmailAlreadyExistsError(UserAlreadyExistsError):
    """Email address is already registered."""

    def __init__(
        self,
        message: str = "Email address is already registered",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message, details)
