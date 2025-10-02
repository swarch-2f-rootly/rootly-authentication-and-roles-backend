"""
Application settings configuration.
Provides configuration management with environment variables.
"""

import os
from typing import List, Optional


class DatabaseSettings:
    """Database configuration settings."""

    def __init__(self):
        self.url = os.getenv("DATABASE_URL", "postgresql+asyncpg://admin:admin123@db-authentication-and-roles:5432/authentication_and_roles_db")
        self.pool_size = int(os.getenv("DATABASE_POOL_SIZE", "10"))
        self.max_overflow = int(os.getenv("DATABASE_MAX_OVERFLOW", "20"))
        self.pool_timeout = int(os.getenv("DATABASE_POOL_TIMEOUT", "30"))
        self.pool_recycle = int(os.getenv("DATABASE_POOL_RECYCLE", "1800"))


class JWTSettings:
    """JWT token configuration settings."""

    def __init__(self):
        self.secret_key = os.getenv("JWT_SECRET_KEY", "test-jwt-secret-key-for-development-only-32-chars-minimum")
        self.access_token_expire_minutes = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "240"))
        self.refresh_token_expire_days = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"))
        self.algorithm = "HS256"


class MinIOSettings:
    """MinIO object storage configuration settings."""

    def __init__(self):
        self.endpoint = os.getenv("MINIO_ENDPOINT", "stg-authentication-and-roles:9000")
        self.access_key = os.getenv("MINIO_ACCESS_KEY", "admin")
        self.secret_key = os.getenv("MINIO_SECRET_KEY", "admin123")
        self.bucket_name = os.getenv("MINIO_BUCKET_NAME", "user-profiles")
        self.secure = os.getenv("MINIO_SECURE", "false").lower() == "true"


class SecuritySettings:
    """Security-related configuration settings."""

    def __init__(self):
        self.bcrypt_rounds = int(os.getenv("BCRYPT_ROUNDS", "12"))
        self.max_login_attempts = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
        self.lockout_duration_minutes = int(os.getenv("LOCKOUT_DURATION_MINUTES", "30"))
        self.max_concurrent_sessions = int(os.getenv("MAX_CONCURRENT_SESSIONS", "5"))


class FileUploadSettings:
    """File upload configuration settings."""

    def __init__(self):
        self.max_profile_photo_size_mb = int(os.getenv("MAX_PROFILE_PHOTO_SIZE_MB", "5"))
        self.allowed_image_types = os.getenv("ALLOWED_IMAGE_TYPES", "jpeg,jpg,png,webp").split(",")

    @property
    def max_profile_photo_size_bytes(self) -> int:
        """Get maximum file size in bytes."""
        return self.max_profile_photo_size_mb * 1024 * 1024


class AppSettings:
    """Main application settings."""

    def __init__(self):
        # Basic app settings
        self.name = os.getenv("APP_NAME", "rootly Authentication Service")
        self.version = os.getenv("APP_VERSION", "1.0.0")
        self.debug = os.getenv("DEBUG", "false").lower() == "true"
        self.environment = os.getenv("ENVIRONMENT", "production")

        # Server settings
        self.host = os.getenv("HOST", "0.0.0.0")
        self.port = int(os.getenv("PORT", "8000"))
        self.api_base_url = os.getenv("API_BASE_URL", "http://localhost:8001")

        # CORS settings
        cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:8080,*")
        self.cors_origins = [origin.strip() for origin in cors_origins.split(",")]

        # Logging settings
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        self.log_format = os.getenv("LOG_FORMAT", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")

        # Nested settings
        self.database = DatabaseSettings()
        self.jwt = JWTSettings()
        self.minio = MinIOSettings()
        self.security = SecuritySettings()
        self.file_upload = FileUploadSettings()


# Global settings instance
_settings = None


def get_settings() -> AppSettings:
    """Get the global application settings instance."""
    global _settings
    if _settings is None:
        _settings = AppSettings()
    return _settings
