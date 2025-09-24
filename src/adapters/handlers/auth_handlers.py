"""
Authentication FastAPI route handlers.
Handles authentication-related HTTP endpoints.
"""

from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from core.ports.auth_service import AuthService
from core.ports.logger import Logger
from core.ports.exceptions import (
    InvalidCredentialsError,
    AccountLockedError,
    AccountInactiveError,
    InvalidTokenError,
    TokenExpiredError
)
from .models import (
    LoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    LogoutRequest,
    ErrorResponse
)
from config.settings import get_settings

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])
security = HTTPBearer()
settings = get_settings()


from .dependencies import (
    get_user_repository,
    get_refresh_token_repository,
    get_password_service,
    get_logger,
    get_db_session
)


async def get_auth_service_dependency(session: AsyncSession = Depends(get_db_session)) -> AuthService:
    """Dependency injection for auth service."""
    from core.services.auth_service_impl import AuthServiceImpl

    user_repo = await get_user_repository(session)
    refresh_token_repo = await get_refresh_token_repository(session)
    password_service = await get_password_service()
    logger = await get_logger()

    return AuthServiceImpl(user_repo, refresh_token_repo, password_service, logger)


async def get_logger() -> Logger:
    """Dependency injection for logger."""
    from adapters.logger.standard_logger import StandardLogger
    return StandardLogger("auth")


@router.post("/login", response_model=TokenResponse)
async def login(
    request: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    User login endpoint.

    Authenticates a user with email and password, returning access and refresh tokens.
    """
    try:
        logger.info("Login attempt", email=request.email)

        # Authenticate user
        token_pair = await auth_service.authenticate_user(
            request.email,
            request.password
        )

        # Calculate expiration time for response
        expires_in = int(settings.jwt.access_token_expire_minutes * 60)

        # Get user info for response
        user = await auth_service.get_current_user(token_pair.access_token)
        user_info = user.to_dict() if user else {}

        response = TokenResponse(
            access_token=token_pair.access_token,
            refresh_token=token_pair.refresh_token,
            token_type=token_pair.token_type,
            expires_in=expires_in,
            user=user_info
        )

        logger.info("Login successful", email=request.email)
        return response

    except InvalidCredentialsError as e:
        logger.warn("Login failed: invalid credentials", email=request.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "AUTHENTICATION_FAILED",
                "message": str(e),
                "timestamp": "InvalidCredentialsError"
            }
        )
    except AccountLockedError as e:
        logger.warn("Login failed: account locked", email=request.email)
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail={
                "error": "ACCOUNT_LOCKED",
                "message": str(e),
                "timestamp": "AccountLockedError"
            }
        )
    except AccountInactiveError as e:
        logger.warn("Login failed: account inactive", email=request.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "ACCOUNT_INACTIVE",
                "message": str(e),
                "timestamp": "AccountInactiveError"
            }
        )
    except Exception as e:
        logger.error("Login error", error=str(e), email=request.email)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Authentication service temporarily unavailable",
                "timestamp": "Exception"
            }
        )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: RefreshTokenRequest,
    auth_service: AuthService = Depends(get_auth_service_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    Refresh access token endpoint.

    Exchanges a valid refresh token for new access and refresh tokens.
    """
    try:
        logger.info("Token refresh attempt")

        # Refresh token
        new_token_pair = await auth_service.refresh_access_token(
            request.refresh_token
        )

        # Calculate expiration time for response
        expires_in = int(settings.jwt.access_token_expire_minutes * 60)

        # Get user info for response
        user = await auth_service.get_current_user(new_token_pair.access_token)
        user_info = user.to_dict() if user else {}

        response = TokenResponse(
            access_token=new_token_pair.access_token,
            refresh_token=new_token_pair.refresh_token,
            token_type=new_token_pair.token_type,
            expires_in=expires_in,
            user=user_info
        )

        logger.info("Token refresh successful")
        return response

    except InvalidTokenError as e:
        logger.warn("Token refresh failed: invalid token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "INVALID_TOKEN",
                "message": str(e),
                "timestamp": "InvalidTokenError"
            }
        )
    except TokenExpiredError as e:
        logger.warn("Token refresh failed: token expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "TOKEN_EXPIRED",
                "message": str(e),
                "timestamp": "TokenExpiredError"
            }
        )
    except Exception as e:
        logger.error("Token refresh error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Token refresh service temporarily unavailable",
                "timestamp": "Exception"
            }
        )


@router.post("/logout")
async def logout(
    request: LogoutRequest,
    auth_service: AuthService = Depends(get_auth_service_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    User logout endpoint.

    Revokes the provided refresh token.
    """
    try:
        logger.info("Logout attempt")

        # Revoke refresh token
        success = await auth_service.revoke_refresh_token(request.refresh_token)

        if success:
            logger.info("Logout successful")
            return {
                "message": "Successfully logged out",
                "success": True
            }
        else:
            logger.warn("Logout failed: token not found")
            return {
                "message": "Token not found or already revoked",
                "success": False
            }

    except Exception as e:
        logger.error("Logout error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Logout service temporarily unavailable",
                "timestamp": "Exception"
            }
        )


@router.post("/validate")
async def validate_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    auth_service: AuthService = Depends(get_auth_service_dependency),
    logger: Logger = Depends(get_logger)
):
    """
    Token validation endpoint.

    Validates an access token and returns token payload if valid.
    """
    try:
        logger.info("Token validation attempt")

        # Extract token
        token = credentials.credentials

        # Validate token
        payload = await auth_service.validate_access_token(token)

        logger.info("Token validation successful")
        return {
            "valid": True,
            "payload": payload,
            "message": "Token is valid"
        }

    except InvalidTokenError as e:
        logger.warn("Token validation failed: invalid token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "INVALID_TOKEN",
                "message": str(e),
                "timestamp": "InvalidTokenError"
            }
        )
    except TokenExpiredError as e:
        logger.warn("Token validation failed: token expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "TOKEN_EXPIRED",
                "message": str(e),
                "timestamp": "TokenExpiredError"
            }
        )
    except Exception as e:
        logger.error("Token validation error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "INTERNAL_ERROR",
                "message": "Token validation service temporarily unavailable",
                "timestamp": "Exception"
            }
        )


async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    auth_service: AuthService = Depends(get_auth_service_dependency),
    logger: Logger = Depends(get_logger)
) -> Optional[dict]:
    """
    Get current user from token (optional authentication).

    Returns user info if token is valid, None if no token or invalid token.
    """
    if not credentials:
        return None

    try:
        token = credentials.credentials
        user = await auth_service.get_current_user(token)

        if user:
            return user.to_dict()
        return None

    except Exception:
        return None


async def get_current_user_required(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    auth_service: AuthService = Depends(get_auth_service_dependency),
    logger: Logger = Depends(get_logger)
) -> dict:
    """
    Get current user from token (required authentication).

    Returns user info if token is valid, raises HTTPException if not.
    """
    try:
        token = credentials.credentials
        user = await auth_service.get_current_user(token)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "INVALID_TOKEN",
                    "message": "Invalid or expired token",
                    "timestamp": "InvalidTokenError"
                }
            )

        return user.to_dict()

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Get current user error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "AUTHENTICATION_ERROR",
                "message": "Authentication failed",
                "timestamp": "Exception"
            }
        )
