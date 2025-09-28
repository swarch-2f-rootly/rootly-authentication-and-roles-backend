#!/bin/bash

# Docker entrypoint script for authentication service
# The application now handles database initialization automatically

set -e

echo "Starting Authentication Service..."

# Start the application
# Database migrations and seeding are now handled automatically in the application startup
echo "Starting FastAPI application..."
exec uvicorn src.main:app --host 0.0.0.0 --port 8000
