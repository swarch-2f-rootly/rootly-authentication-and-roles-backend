# Rootly Authentication & User Management Service

A comprehensive authentication and user management service built with FastAPI, following Hexagonal Architecture principles. This service provides secure user authentication, authorization, profile management, and role-based access control for the agricultural monitoring platform.

## 🏗️ Architecture

This service follows **Hexagonal Architecture (Ports and Adapters)** with clear separation of concerns:

```
src/
├── core/                          # Business Logic Layer
│   ├── domain/                    # Domain Entities (User, Role, Permission, AuthToken)
│   ├── ports/                     # Interfaces/Ports (contracts)
│   └── services/                  # Application Services (business logic)
├── adapters/                      # Infrastructure Layer
│   ├── handlers/                  # HTTP API Controllers (FastAPI routes)
│   ├── repositories/              # Data Access Implementations (PostgreSQL)
│   ├── storage/                   # File Storage (MinIO)
│   └── logger/                    # Logging Infrastructure
├── config/                        # Configuration Management
└── main.py                        # Application Entry Point
```

## 🚀 Features

### Authentication & Authorization
- **JWT-based Authentication**: Secure token-based authentication with access and refresh tokens
- **Password Security**: bcrypt hashing with configurable rounds
- **Role-Based Access Control (RBAC)**: Hierarchical permission system
- **Token Management**: Secure refresh token rotation and revocation

### User Management
- **User Registration**: Secure user account creation with validation
- **Profile Management**: Update user profiles and upload profile photos
- **Account Management**: Activate/deactivate user accounts
- **Password Management**: Secure password changes with validation

### File Storage
- **MinIO Integration**: S3-compatible object storage for profile photos
- **File Validation**: Type and size validation for uploads
- **Secure Storage**: Isolated bucket with access controls

### Security Features
- **Input Validation**: Comprehensive request validation
- **Error Handling**: Structured error responses
- **CORS Support**: Configurable cross-origin resource sharing
- **Rate Limiting**: Protection against brute force attacks
- **Audit Logging**: Comprehensive logging for security events

## 📋 API Endpoints

### Authentication Endpoints
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/refresh` - Refresh access token
- `POST /api/v1/auth/logout` - User logout
- `POST /api/v1/auth/validate` - Validate access token

### User Management Endpoints (Planned)
- `POST /api/v1/users` - Create user account
- `GET /api/v1/users/{user_id}` - Get user profile
- `PUT /api/v1/users/{user_id}` - Update user profile
- `DELETE /api/v1/users/{user_id}` - Delete user account
- `POST /api/v1/users/{user_id}/change-password` - Change password

### File Upload Endpoints (Planned)
- `POST /api/v1/users/{user_id}/photo` - Upload profile photo
- `DELETE /api/v1/users/{user_id}/photo` - Delete profile photo

## 🛠️ Technology Stack

- **Python 3.11**: Modern Python with async support
- **FastAPI**: High-performance web framework with automatic API documentation
- **PostgreSQL**: Relational database for user data and sessions
- **SQLAlchemy**: ORM with async support for database operations
- **MinIO**: S3-compatible object storage for file uploads
- **JWT**: JSON Web Tokens for authentication
- **bcrypt**: Password hashing for security
- **Docker**: Containerization for deployment

## 🔧 Configuration

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql+asyncpg://user:password@db:5432/auth_db

# JWT Configuration
JWT_SECRET_KEY=your-secret-key-here
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# MinIO Configuration
MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=user
MINIO_SECRET_KEY=password
MINIO_BUCKET_NAME=user-profiles

# Application
APP_ENV=production
LOG_LEVEL=INFO
```

### Docker Configuration

The service is fully containerized and integrates with the rootly deployment:

```yaml
authentication-backend:
  build:
    context: ../rootly-authentication-and-roles-backend
    dockerfile: Dockerfile
  ports:
    - "8001:8000"
  depends_on:
    postgres:
      condition: service_healthy
    minio-auth:
      condition: service_healthy
  environment:
    - DATABASE_URL=postgresql+asyncpg://auth_user:auth_password123@postgres:5432/auth_db
    - MINIO_ENDPOINT=minio-auth:9000
    - JWT_SECRET_KEY=your-secret-key-here
```

## 🚀 Quick Start

### Using Docker Compose

1. **Clone the repository** and navigate to the deployment directory:
   ```bash
   cd rootly-deployment
   ```

2. **Start the services**:
   ```bash
   docker-compose up -d
   ```

3. **Access the service**:
   - API Documentation: http://localhost:8001/docs
   - Health Check: http://localhost:8001/health
   - Authentication Service: http://localhost:8001/

### Local Development

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Run the service**:
   ```bash
   uvicorn src.main:app --reload
   ```

## 🧪 Testing

### Running Tests

```bash
# Unit tests
pytest tests/unit/ -v

# Integration tests
pytest tests/integration/ -v

# All tests with coverage
pytest --cov=src --cov-report=html
```

### Test Structure

```
tests/
├── unit/                          # Unit tests for individual components
│   ├── test_auth_service.py       # Authentication service tests
│   ├── test_user_service.py       # User service tests
│   ├── test_password_service.py   # Password service tests
│   └── test_domain_entities.py    # Domain entity tests
└── integration/                   # Integration tests
    ├── test_auth_flow.py          # Complete authentication flow
    ├── test_user_management.py    # User management operations
    └── test_file_upload.py        # File upload functionality
```

## 📚 API Documentation

Once the service is running, visit:
- **Swagger UI**: http://localhost:8001/docs
- **ReDoc**: http://localhost:8001/redoc
- **OpenAPI Schema**: http://localhost:8001/openapi.json

## 🔒 Security Considerations

- **Password Requirements**: Minimum 8 characters with mixed case, numbers, and special characters
- **JWT Expiration**: Access tokens expire in 15 minutes, refresh tokens in 7 days
- **Token Rotation**: Refresh tokens are rotated on each use for enhanced security
- **Input Validation**: All inputs are validated using Pydantic models
- **File Upload Security**: Strict MIME type validation and size limits
- **Database Security**: Parameterized queries prevent SQL injection
- **HTTPS**: TLS encryption for production deployments

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin feature/your-feature-name`
5. Submit a pull request

## 📝 License

This project is part of the Rootly Agricultural Monitoring Platform.

## 📞 Support

For questions or issues:
- Check the API documentation at `/docs`
- Review the logs for error details
- Contact the development team

---

**Built with ❤️ for modern agricultural monitoring systems**
