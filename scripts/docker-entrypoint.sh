#!/bin/bash

# Docker entrypoint script for authentication service
# Automatically initializes database if needed, then starts the application

set -e

echo "🚀 Starting Authentication Service initialization..."

# Run database initialization if needed
echo "🔧 Checking database initialization..."
if python /app/scripts/init_db_on_startup.py; then
    echo "✅ Database initialization check completed successfully!"
else
    echo "❌ Database initialization failed!"
    exit 1
fi

# Start the application
echo "🚀 Starting FastAPI application..."
exec uvicorn src.main:app --host 0.0.0.0 --port 8000
