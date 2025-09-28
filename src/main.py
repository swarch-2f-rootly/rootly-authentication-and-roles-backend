"""
Main application entry point for the Authentication Service.
Sets up FastAPI app with dependency injection and error handling.
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime
import logging

from config.settings import get_settings
from adapters.logger.standard_logger import StandardLogger
from core.ports.logger import Logger
from core.ports.exceptions import (
    AuthenticationServiceError,
    InvalidCredentialsError,
    AuthorizationError,
    ValidationError,
    UserNotFoundError,
    UserAlreadyExistsError,
    RoleNotFoundError,
    FileTooLargeError,
    InvalidFileTypeError,
    RepositoryError,
    ExternalServiceError
)
from adapters.handlers.auth_handlers import router as auth_router
from adapters.handlers.user_handlers import router as user_router
from adapters.handlers.role_handlers import router as role_router
from adapters.handlers.file_handlers import router as file_router

# Import services for database initialization
from core.services.migration_service import MigrationService
from core.services.seed_service import SeedService

# Load settings
settings = get_settings()

# Configure logging using our custom logger
logger: Logger = StandardLogger("auth", settings.log_level)

# Configure standard Python logging to suppress noisy messages
logging.getLogger("uvicorn").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


async def initialize_database():
    """Initialize database with automatic migration checking and seeding."""
    try:
        logger.info("🔧 Initializing database...")

        # Initialize migration service
        migration_service = MigrationService(logger)

        # Check and run migrations automatically if needed
        if not await migration_service.initialize_database():
            logger.error("Database migration failed!")
            raise RuntimeError("Database migration failed")

        # Initialize seed service
        seed_service = SeedService(logger)

        # Run seeding
        if not await seed_service.seed_database():
            logger.error("Database seeding failed!")
            raise RuntimeError("Database seeding failed")

        logger.info("Database seeding completed successfully")

        # Create test users in development environment
        if settings.environment in ["development", "dev"]:
            logger.info("Creating test users for development...")
            await seed_service.create_test_users()
        elif settings.debug:
            logger.info("Creating test users for debug environment...")
            await seed_service.create_test_users()

        logger.info("Database initialization completed successfully!")

    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting Authentication Service...")

    # Startup logic
    logger.info(f"Service configured for environment: {settings.environment}")
    logger.info(f"CORS origins: {settings.cors_origins}")

    # Initialize database with migrations and seeding
    await initialize_database()

    yield

    # Shutdown logic
    logger.info("Shutting down Authentication Service...")


# Create FastAPI application
app = FastAPI(
    title=settings.name,
    description="Comprehensive authentication and user management service for the agricultural monitoring platform",
    version=settings.version,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Include routers
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(role_router)
app.include_router(file_router)


# Global exception handlers
@app.exception_handler(InvalidCredentialsError)
async def invalid_credentials_handler(request: Request, exc: InvalidCredentialsError):
    """Handle invalid credentials errors."""
    return JSONResponse(
        status_code=401,
        content={
            "error": "AUTHENTICATION_FAILED",
            "message": str(exc),
            "details": exc.details,
            "timestamp": str(exc.__class__.__name__)
        }
    )


@app.exception_handler(AuthorizationError)
async def authorization_handler(request: Request, exc: AuthorizationError):
    """Handle authorization errors."""
    return JSONResponse(
        status_code=403,
        content={
            "error": "AUTHORIZATION_FAILED",
            "message": str(exc),
            "details": exc.details,
            "timestamp": str(exc.__class__.__name__)
        }
    )


@app.exception_handler(ValidationError)
async def validation_handler(request: Request, exc: ValidationError):
    """Handle validation errors."""
    return JSONResponse(
        status_code=400,
        content={
            "error": "VALIDATION_FAILED",
            "message": str(exc),
            "details": exc.details,
            "timestamp": str(exc.__class__.__name__)
        }
    )


@app.exception_handler(UserNotFoundError)
async def user_not_found_handler(request: Request, exc: UserNotFoundError):
    """Handle user not found errors."""
    return JSONResponse(
        status_code=404,
        content={
            "error": "USER_NOT_FOUND",
            "message": str(exc),
            "details": exc.details,
            "timestamp": str(exc.__class__.__name__)
        }
    )


@app.exception_handler(UserAlreadyExistsError)
async def user_already_exists_handler(request: Request, exc: UserAlreadyExistsError):
    """Handle user already exists errors."""
    return JSONResponse(
        status_code=409,
        content={
            "error": "USER_ALREADY_EXISTS",
            "message": str(exc),
            "details": exc.details,
            "timestamp": str(exc.__class__.__name__)
        }
    )


@app.exception_handler(RoleNotFoundError)
async def role_not_found_handler(request: Request, exc: RoleNotFoundError):
    """Handle role not found errors."""
    return JSONResponse(
        status_code=404,
        content={
            "error": "ROLE_NOT_FOUND",
            "message": str(exc),
            "details": exc.details,
            "timestamp": str(exc.__class__.__name__)
        }
    )


@app.exception_handler(FileTooLargeError)
async def file_too_large_handler(request: Request, exc: FileTooLargeError):
    """Handle file too large errors."""
    return JSONResponse(
        status_code=413,
        content={
            "error": "FILE_TOO_LARGE",
            "message": str(exc),
            "details": exc.details,
            "timestamp": str(exc.__class__.__name__)
        }
    )


@app.exception_handler(InvalidFileTypeError)
async def invalid_file_type_handler(request: Request, exc: InvalidFileTypeError):
    """Handle invalid file type errors."""
    return JSONResponse(
        status_code=400,
        content={
            "error": "INVALID_FILE_TYPE",
            "message": str(exc),
            "details": exc.details,
            "timestamp": str(exc.__class__.__name__)
        }
    )


@app.exception_handler(RepositoryError)
async def repository_error_handler(request: Request, exc: RepositoryError):
    """Handle repository/database errors."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "DATABASE_ERROR",
            "message": "Database operation failed",
            "details": exc.details,
            "timestamp": str(exc.__class__.__name__)
        }
    )


@app.exception_handler(ExternalServiceError)
async def external_service_handler(request: Request, exc: ExternalServiceError):
    """Handle external service errors."""
    return JSONResponse(
        status_code=502,
        content={
            "error": "EXTERNAL_SERVICE_ERROR",
            "message": f"Service '{exc.service_name}' is unavailable",
            "details": exc.details,
            "timestamp": str(exc.__class__.__name__)
        }
    )


@app.exception_handler(AuthenticationServiceError)
async def authentication_service_error_handler(request: Request, exc: AuthenticationServiceError):
    """Handle general authentication service errors."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "SERVICE_ERROR",
            "message": exc.message,
            "details": exc.details,
            "timestamp": str(exc.__class__.__name__)
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected errors."""
    logger.error("Unhandled exception", error=str(exc), path=request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "error": "INTERNAL_ERROR",
            "message": "An unexpected error occurred",
            "details": None,
            "timestamp": "Exception"
        }
    )


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with service information."""
    return {
        "service": settings.name,
        "version": settings.version,
        "description": "Comprehensive authentication and user management service",
        "environment": settings.environment,
        "endpoints": {
            "docs": "/docs",
            "redoc": "/redoc",
            "health": "/health",
            "auth": {
                "login": "/api/v1/auth/login",
                "refresh": "/api/v1/auth/refresh",
                "logout": "/api/v1/auth/logout",
                "validate": "/api/v1/auth/validate"
            }
        }
    }


# Health check endpoint
@app.get("/health")
async def health_check():
    """Service health check."""
    try:
        # Basic health check - in production, you'd check database connectivity
        return {
            "status": "healthy",
            "service": "authentication",
            "version": settings.version,
            "environment": settings.environment,
            "database": "unknown",  # Would check actual DB connection
            "minio": "unknown",     # Would check actual MinIO connection
            "timestamp": str(datetime.now().isoformat())
        }
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "service": "authentication",
                "error": str(e),
                "timestamp": str(datetime.now().isoformat())
            }
        )


if __name__ == "__main__":
    import uvicorn

    # Run the application
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )
