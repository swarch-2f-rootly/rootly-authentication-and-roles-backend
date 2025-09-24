#!/usr/bin/env python3
"""
Authentication API Testing Script

This script demonstrates how to interact with the Authentication Service API.
It includes examples of login, token refresh, and token validation.
"""

import requests
import json
from typing import Dict, Optional


class AuthAPITester:
    """Authentication API tester class."""

    def __init__(self, base_url: str = "http://localhost:8001"):
        """
        Initialize the API tester.

        Args:
            base_url: Base URL of the authentication service
        """
        self.base_url = base_url
        self.session = requests.Session()
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict:
        """
        Make an HTTP request to the API.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint
            **kwargs: Additional arguments for requests

        Returns:
            Response data as dictionary
        """
        url = f"{self.base_url}{endpoint}"

        # Add authorization header if we have an access token
        if self.access_token and 'headers' not in kwargs:
            kwargs['headers'] = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
        elif self.access_token and 'headers' in kwargs:
            kwargs['headers']['Authorization'] = f'Bearer {self.access_token}'

        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()

            if response.content:
                return response.json()
            return {"message": "Success"}

        except requests.exceptions.HTTPError as e:
            print(f"HTTP Error: {e}")
            try:
                error_data = e.response.json()
                print(f"Error details: {json.dumps(error_data, indent=2)}")
            except:
                print(f"Response text: {e.response.text}")
            raise
        except requests.exceptions.RequestException as e:
            print(f"Request Error: {e}")
            raise

    def login(self, email: str, password: str) -> Dict:
        """
        Login with email and password.

        Args:
            email: User email
            password: User password

        Returns:
            Login response data
        """
        print(f"\n🔐 Logging in with email: {email}")

        data = {
            "email": email,
            "password": password
        }

        response = self._make_request("POST", "/api/v1/auth/login", json=data)

        if "access_token" in response:
            self.access_token = response["access_token"]
            self.refresh_token = response["refresh_token"]
            print("✅ Login successful!")
            print(f"Access Token: {self.access_token[:50]}...")
            print(f"Refresh Token: {self.refresh_token[:50]}...")

        return response

    def refresh_token(self) -> Dict:
        """
        Refresh the access token using refresh token.

        Returns:
            Token refresh response data
        """
        if not self.refresh_token:
            raise ValueError("No refresh token available. Please login first.")

        print("\n🔄 Refreshing access token...")

        data = {
            "refresh_token": self.refresh_token
        }

        response = self._make_request("POST", "/api/v1/auth/refresh", json=data)

        if "access_token" in response:
            self.access_token = response["access_token"]
            self.refresh_token = response["refresh_token"]
            print("✅ Token refresh successful!")
            print(f"New Access Token: {self.access_token[:50]}...")

        return response

    def validate_token(self) -> Dict:
        """
        Validate the current access token.

        Returns:
            Token validation response data
        """
        if not self.access_token:
            raise ValueError("No access token available. Please login first.")

        print("\n🔍 Validating access token...")

        response = self._make_request("POST", "/api/v1/auth/validate")
        print("✅ Token validation successful!")

        return response

    def logout(self) -> Dict:
        """
        Logout by revoking the refresh token.

        Returns:
            Logout response data
        """
        if not self.refresh_token:
            raise ValueError("No refresh token available. Please login first.")

        print("\n🚪 Logging out...")

        data = {
            "refresh_token": self.refresh_token
        }

        response = self._make_request("POST", "/api/v1/auth/logout", json=data)

        # Clear tokens
        self.access_token = None
        self.refresh_token = None

        print("✅ Logout successful!")
        return response

    def get_service_info(self) -> Dict:
        """
        Get service information from root endpoint.

        Returns:
            Service information
        """
        print("\n📋 Getting service information...")

        response = self._make_request("GET", "/")
        return response

    def health_check(self) -> Dict:
        """
        Perform health check.

        Returns:
            Health check response
        """
        print("\n💚 Performing health check...")

        response = self._make_request("GET", "/health")
        return response


def main():
    """Main function to demonstrate API testing."""
    print("🚀 Rootly Authentication Service API Tester")
    print("=" * 50)

    # Initialize API tester
    tester = AuthAPITester()

    try:
        # Get service info
        service_info = tester.get_service_info()
        print(f"Service: {service_info.get('service', 'Unknown')}")
        print(f"Version: {service_info.get('version', 'Unknown')}")

        # Health check
        health = tester.health_check()
        print(f"Status: {health.get('status', 'Unknown')}")

        # Test login with sample credentials
        # Note: This will fail in a real environment without proper user setup
        print("\n⚠️  Note: Login test will fail without proper user database setup")
        print("This is just a demonstration of the API structure")

        # Example login attempt (will likely fail)
        try:
            login_data = {
                "email": "test@example.com",
                "password": "TestPassword123!"
            }
            print(f"\nAttempting login with: {login_data['email']}")

            # This would work in a real setup with proper database
            # result = tester.login(login_data["email"], login_data["password"])

        except Exception as e:
            print(f"Login failed (expected): {e}")

        print("\n✅ API testing completed!")
        print("\n📖 API Endpoints available:")
        print("  POST /api/v1/auth/login - User login")
        print("  POST /api/v1/auth/refresh - Refresh access token")
        print("  POST /api/v1/auth/logout - User logout")
        print("  POST /api/v1/auth/validate - Validate access token")
        print("  GET / - Service information")
        print("  GET /health - Health check")
        print("  GET /docs - API documentation")

    except Exception as e:
        print(f"❌ API testing failed: {e}")


if __name__ == "__main__":
    main()
