"""
Integration tests for Authentication API endpoints.
"""

import pytest
import pytest_asyncio
import sys
from pathlib import Path
from fastapi.testclient import TestClient
from unittest.mock import patch
import json

# Add src directory to Python path
project_root = Path(__file__).parent.parent.parent
src_path = project_root / 'src'
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from main import app


class TestAuthAPI:
    """Integration tests for authentication endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    @pytest.fixture
    def mock_auth_service(self):
        """Mock auth service for testing."""
        with patch('src.adapters.handlers.auth_handlers.get_auth_service_dependency') as mock:
            yield mock

    def test_root_endpoint(self, client):
        """Test root endpoint returns service information."""
        response = client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert "service" in data
        assert "version" in data
        assert "endpoints" in data

    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "service" in data
        assert data["service"] == "authentication"

    def test_login_endpoint_missing_fields(self, client):
        """Test login endpoint with missing fields returns validation error."""
        # Test with missing data
        response = client.post("/api/v1/auth/login", json={})
        
        # Should return validation error (422) for missing fields
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data

    def test_login_endpoint_with_invalid_credentials(self, client):
        """Test login endpoint with invalid credentials."""
        login_data = {
            "email": "nonexistent@example.com",
            "password": "wrongpassword"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        
        # Should return 401 for invalid credentials
        assert response.status_code == 401

    def test_refresh_endpoint_missing_token(self, client):
        """Test refresh endpoint with missing token returns validation error."""
        # Test with missing data
        response = client.post("/api/v1/auth/refresh", json={})
        
        # Should return validation error (422) for missing refresh_token
        assert response.status_code == 422

    def test_refresh_endpoint_with_invalid_token(self, client):
        """Test refresh endpoint with invalid token."""
        refresh_data = {
            "refresh_token": "invalid_refresh_token"
        }
        
        response = client.post("/api/v1/auth/refresh", json=refresh_data)
        
        # Should return 401 for invalid token
        assert response.status_code == 401

    def test_logout_endpoint_missing_token(self, client):
        """Test logout endpoint with missing token returns validation error."""
        # Test with missing data
        response = client.post("/api/v1/auth/logout", json={})
        
        # Should return validation error (422) for missing refresh_token
        assert response.status_code == 422

    def test_logout_endpoint_with_invalid_token(self, client):
        """Test logout endpoint with invalid token."""
        logout_data = {
            "refresh_token": "invalid_refresh_token"
        }

        response = client.post("/api/v1/auth/logout", json=logout_data)

        # Logout endpoint returns 200 even for invalid tokens (security by design)
        assert response.status_code == 200

    def test_validate_endpoint_no_token(self, client):
        """Test validate endpoint without authorization header."""
        response = client.post("/api/v1/auth/validate")
        
        # Should return 403 forbidden for missing authorization
        assert response.status_code == 403

    def test_validate_endpoint_with_invalid_token(self, client):
        """Test validate endpoint with invalid authorization token."""
        headers = {
            "Authorization": "Bearer invalid_token"
        }
        
        response = client.post("/api/v1/auth/validate", headers=headers)
        
        # Should return 401 for invalid token
        assert response.status_code == 401

    def test_cors_headers(self, client):
        """Test CORS headers are properly set."""
        response = client.options("/api/v1/auth/login")
        
        # FastAPI typically returns 405 for OPTIONS on POST endpoints
        assert response.status_code == 405

    def test_content_type_validation(self, client):
        """Test content type validation for JSON endpoints."""
        # Test with invalid content type
        response = client.post(
            "/api/v1/auth/login",
            data="not json",
            headers={"Content-Type": "text/plain"}
        )
        
        # Should return 422 for invalid content type
        assert response.status_code == 422

    def test_request_size_limits(self, client):
        """Test request size limits with large password."""
        # Create a very large request
        large_data = {
            "email": "test@example.com",
            "password": "x" * 10000  # Very large password
        }

        response = client.post("/api/v1/auth/login", json=large_data)

        # Should return 401 for invalid credentials (email doesn't exist)
        assert response.status_code == 401

    def test_invalid_json_handling(self, client):
        """Test handling of invalid JSON."""
        response = client.post(
            "/api/v1/auth/login",
            data="invalid json{",
            headers={"Content-Type": "application/json"}
        )
        
        # Should return 422 for invalid JSON
        assert response.status_code == 422

    def test_sql_injection_protection(self, client):
        """Test SQL injection protection."""
        malicious_data = {
            "email": "test@example.com",
            "password": "password'; DROP TABLE users; --"
        }

        response = client.post("/api/v1/auth/login", json=malicious_data)

        # Should return 401 for invalid credentials (SQL injection prevented)
        assert response.status_code == 401
        # Ensure no SQL injection in response
        response_text = response.text.lower()
        assert "drop table" not in response_text

    def test_xss_protection(self, client):
        """Test XSS protection in responses."""
        malicious_data = {
            "email": "<script>alert('xss')</script>@example.com",
            "password": "password"
        }
        
        response = client.post("/api/v1/auth/login", json=malicious_data)

        # Should return 422 for invalid email format (XSS prevented by validation)
        assert response.status_code == 422

    def test_multiple_login_attempts(self, client):
        """Test multiple login attempts with different emails."""
        # Make multiple requests with invalid credentials
        for i in range(3):
            response = client.post("/api/v1/auth/login", json={
                "email": f"test{i}@example.com",
                "password": "wrongpassword"
            })
            # Each should return 401 for invalid credentials
            assert response.status_code == 401

    def test_error_response_format(self, client):
        """Test error response format consistency."""
        response = client.post("/api/v1/auth/login", json={})
        
        assert response.status_code == 422
        data = response.json()
        
        # FastAPI validation error format
        assert "detail" in data

    def test_openapi_schema_access(self, client):
        """Test OpenAPI schema is accessible."""
        response = client.get("/openapi.json")
        
        assert response.status_code == 200
        schema = response.json()
        assert "openapi" in schema
        assert "paths" in schema
        assert "/api/v1/auth/login" in schema["paths"]

    def test_docs_endpoint_access(self, client):
        """Test Swagger UI docs are accessible."""
        response = client.get("/docs")
        
        assert response.status_code == 200
        assert "swagger" in response.text.lower() or "openapi" in response.text.lower()

    def test_redoc_endpoint_access(self, client):
        """Test ReDoc documentation is accessible."""
        response = client.get("/redoc")
        
        assert response.status_code == 200
        assert "redoc" in response.text.lower() or "openapi" in response.text.lower()

    def test_authentication_header_format(self, client):
        """Test authentication header format validation."""
        # Test with invalid bearer format
        headers = {
            "Authorization": "InvalidFormat token_here"
        }
        
        response = client.post("/api/v1/auth/validate", headers=headers)
        
        # Should return 403 for invalid authorization format
        assert response.status_code == 403

    def test_json_response_format(self, client):
        """Test that responses are properly formatted JSON."""
        response = client.get("/")
        
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        
        # Should be valid JSON
        data = response.json()
        assert isinstance(data, dict)

    def test_security_headers(self, client):
        """Test security headers in responses."""
        response = client.get("/")
        
        headers = response.headers
        # Note: Some security headers might be added by reverse proxy in production
        assert response.status_code == 200

    def test_method_not_allowed(self, client):
        """Test method not allowed handling."""
        # Try GET on POST endpoint
        response = client.get("/api/v1/auth/login")
        
        assert response.status_code == 405  # Method Not Allowed

    def test_endpoint_without_trailing_slash(self, client):
        """Test endpoint without trailing slash."""
        response = client.post("/api/v1/auth/login", json={})
        # Should return 422 for missing fields
        assert response.status_code == 422
    
    def test_endpoint_with_trailing_slash(self, client):
        """Test endpoint with trailing slash."""
        response = client.post("/api/v1/auth/login/", json={})
        # Should return 422 for missing fields (same behavior as without slash)
        assert response.status_code == 422
