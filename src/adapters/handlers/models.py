"""
Pydantic models for API request/response handling.
Defines the data structures for API communication.
"""

from datetime import datetime
from typing import List, Optional
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field, validator


# Authentication Models
class LoginRequest(BaseModel):
    """Login request model."""
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=1, description="User's password")


class TokenResponse(BaseModel):
    """Token response model."""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiration time in seconds")
    user: dict = Field(..., description="User information")


class RefreshTokenRequest(BaseModel):
    """Refresh token request model."""
    refresh_token: str = Field(..., description="Valid refresh token")


class LogoutRequest(BaseModel):
    """Logout request model."""
    refresh_token: str = Field(..., description="Refresh token to revoke")


# User Management Models
class UserCreateRequest(BaseModel):
    """User creation request model."""
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=8, description="User's password")
    first_name: str = Field(..., min_length=2, max_length=100, description="User's first name")
    last_name: str = Field(..., min_length=2, max_length=100, description="User's last name")

    @validator('password')
    def validate_password_strength(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(char.islower() for char in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain at least one digit')
        if not any(char in '!@#$%^&*()_+-=[]{}|;:,.<>?' for char in v):
            raise ValueError('Password must contain at least one special character')
        return v


class UserUpdateRequest(BaseModel):
    """User update request model."""
    first_name: Optional[str] = Field(None, min_length=2, max_length=100, description="User's first name")
    last_name: Optional[str] = Field(None, min_length=2, max_length=100, description="User's last name")


class UserResponse(BaseModel):
    """User response model."""
    id: UUID = Field(..., description="User's unique identifier")
    email: EmailStr = Field(..., description="User's email address")
    first_name: str = Field(..., description="User's first name")
    last_name: str = Field(..., description="User's last name")
    full_name: str = Field(..., description="User's full name")
    profile_photo_url: Optional[str] = Field(None, description="Profile photo URL")
    is_active: bool = Field(..., description="Whether the user account is active")
    roles: List[str] = Field(default_factory=list, description="User's roles")
    created_at: datetime = Field(..., description="Account creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")


class UserListResponse(BaseModel):
    """User list response model."""
    users: List[UserResponse] = Field(..., description="List of users")
    total: int = Field(..., description="Total number of users")
    skip: int = Field(..., description="Number of users skipped")
    limit: int = Field(..., description="Maximum number of users returned")


# Password Management Models
class ChangePasswordRequest(BaseModel):
    """Change password request model."""
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, description="New password")

    @validator('new_password')
    def validate_password_strength(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(char.islower() for char in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain at least one digit')
        if not any(char in '!@#$%^&*()_+-=[]{}|;:,.<>?' for char in v):
            raise ValueError('Password must contain at least one special character')
        return v


# Role Management Models
class RoleResponse(BaseModel):
    """Role response model."""
    id: UUID = Field(..., description="Role's unique identifier")
    name: str = Field(..., description="Role name")
    description: str = Field(..., description="Role description")
    permissions: List[dict] = Field(default_factory=list, description="Role permissions")
    permission_count: int = Field(..., description="Number of permissions")
    created_at: datetime = Field(..., description="Role creation timestamp")


class RoleListResponse(BaseModel):
    """Role list response model."""
    roles: List[RoleResponse] = Field(..., description="List of roles")
    total: int = Field(..., description="Total number of roles")


class AssignRoleRequest(BaseModel):
    """Assign role request model."""
    role_ids: List[UUID] = Field(..., description="List of role IDs to assign")


# Permission Models
class PermissionResponse(BaseModel):
    """Permission response model."""
    id: UUID = Field(..., description="Permission's unique identifier")
    name: str = Field(..., description="Permission name")
    resource: str = Field(..., description="Resource name")
    action: str = Field(..., description="HTTP action")
    scope: str = Field(..., description="Permission scope")
    full_name: str = Field(..., description="Full permission name")
    created_at: datetime = Field(..., description="Permission creation timestamp")


class PermissionListResponse(BaseModel):
    """Permission list response model."""
    permissions: List[PermissionResponse] = Field(..., description="List of permissions")
    total: int = Field(..., description="Total number of permissions")


# File Upload Models
class FileUploadResponse(BaseModel):
    """File upload response model."""
    filename: str = Field(..., description="Uploaded file name")
    url: str = Field(..., description="File access URL")
    content_type: str = Field(..., description="File content type")
    size: int = Field(..., description="File size in bytes")
    uploaded_at: datetime = Field(..., description="Upload timestamp")


class FileMetadataResponse(BaseModel):
    """File metadata response model."""
    filename: str = Field(..., description="File name")
    size: int = Field(..., description="File size in bytes")
    content_type: str = Field(..., description="File content type")
    last_modified: datetime = Field(..., description="Last modification timestamp")
    url: Optional[str] = Field(None, description="File access URL")


# Error Response Models
class ErrorResponse(BaseModel):
    """Generic error response model."""
    error: str = Field(..., description="Error code")
    message: str = Field(..., description="Error message")
    details: Optional[dict] = Field(None, description="Additional error details")
    timestamp: str = Field(..., description="Error timestamp")


class ValidationErrorResponse(BaseModel):
    """Validation error response model."""
    error: str = Field(default="VALIDATION_ERROR", description="Error type")
    message: str = Field(..., description="Error message")
    details: dict = Field(..., description="Validation error details")
    timestamp: str = Field(..., description="Error timestamp")


# Health Check Models
class HealthCheckResponse(BaseModel):
    """Health check response model."""
    status: str = Field(..., description="Service status")
    service: str = Field(..., description="Service name")
    version: str = Field(..., description="Service version")
    database: str = Field(..., description="Database status")
    minio: str = Field(..., description="MinIO storage status")
    timestamp: datetime = Field(..., description="Health check timestamp")


# Statistics Models
class UserStatsResponse(BaseModel):
    """User statistics response model."""
    total_users: int = Field(..., description="Total number of users")
    active_users: int = Field(..., description="Number of active users")
    inactive_users: int = Field(..., description="Number of inactive users")


class SystemStatsResponse(BaseModel):
    """System statistics response model."""
    users: UserStatsResponse = Field(..., description="User statistics")
    total_roles: int = Field(..., description="Total number of roles")
    total_permissions: int = Field(..., description="Total number of permissions")
    storage_info: dict = Field(..., description="Storage service information")
