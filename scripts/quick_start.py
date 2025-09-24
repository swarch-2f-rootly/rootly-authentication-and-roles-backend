#!/usr/bin/env python3
"""
Quick start script for the Authentication Service.
Sets up the database and starts the service for testing.
"""

import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path

# Add the src directory to the path
sys.path.append(str(Path(__file__).parent.parent / 'src'))

from adapters.logger.standard_logger import StandardLogger

logger = StandardLogger("quick_start", "INFO")


def run_command(command: str, description: str) -> bool:
    """Run a shell command and return success status."""
    try:
        logger.info(f"Running: {description}")
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        logger.info(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ {description} failed")
        logger.error(f"Error: {e.stderr}")
        return False


async def init_database():
    """Initialize the database with tables and seed data."""
    try:
        logger.info("Initializing database...")

        # Run database initialization
        init_script = Path(__file__).parent / 'init_database.py'
        if not init_script.exists():
            logger.error("Database initialization script not found")
            return False

        # Run the script
        result = subprocess.run([sys.executable, str(init_script)],
                              capture_output=True, text=True)

        if result.returncode == 0:
            logger.info("✅ Database initialization completed")
            return True
        else:
            logger.error("❌ Database initialization failed")
            logger.error(f"Error: {result.stderr}")
            return False

    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")
        return False


async def seed_database():
    """Seed the database with initial data."""
    try:
        logger.info("Seeding database with test data...")

        # Run data seeding
        seed_script = Path(__file__).parent / 'seed_data.py'
        if not seed_script.exists():
            logger.error("Database seeding script not found")
            return False

        # Run the script
        result = subprocess.run([sys.executable, str(seed_script)],
                              capture_output=True, text=True)

        if result.returncode == 0:
            logger.info("✅ Database seeding completed")
            return True
        else:
            logger.error("❌ Database seeding failed")
            logger.error(f"Error: {result.stderr}")
            return False

    except Exception as e:
        logger.error(f"Database seeding error: {str(e)}")
        return False


def start_service():
    """Start the authentication service."""
    try:
        logger.info("Starting authentication service...")

        # Check if we're in the right directory
        service_dir = Path(__file__).parent.parent
        os.chdir(service_dir)

        # Start the service
        logger.info("🚀 Starting service with uvicorn...")
        logger.info("Service will be available at: http://localhost:8000")
        logger.info("API Documentation: http://localhost:8000/docs")
        logger.info("Health Check: http://localhost:8000/health")
        logger.info("")
        logger.info("Press Ctrl+C to stop the service")
        logger.info("=" * 50)

        # Run uvicorn
        os.system("uvicorn src.main:app --reload --host 0.0.0.0 --port 8000")

    except KeyboardInterrupt:
        logger.info("Service stopped by user")
    except Exception as e:
        logger.error(f"Service startup error: {str(e)}")


async def main():
    """Main quick start function."""
    print("🚀 Rootly Authentication Service - Quick Start")
    print("=" * 50)

    # Check if we're running with Docker Compose
    use_docker = "--docker" in sys.argv

    if use_docker:
        logger.info("Using Docker Compose setup...")

        # Start services with Docker Compose
        if not run_command("docker-compose -f docker-compose.test.yml up -d", "Starting Docker services"):
            logger.error("Failed to start Docker services")
            return

        # Wait for services to be ready
        logger.info("Waiting for services to be ready...")
        time.sleep(30)

        # Initialize database
        if not await init_database():
            logger.error("Failed to initialize database")
            return

        # Seed database
        if not await seed_database():
            logger.error("Failed to seed database")
            return

        logger.info("✅ Setup completed successfully!")
        logger.info("")
        logger.info("Service URLs:")
        logger.info("  API: http://localhost:8001")
        logger.info("  Docs: http://localhost:8001/docs")
        logger.info("  Health: http://localhost:8001/health")
        logger.info("")
        logger.info("Test users created:")
        logger.info("  Admin: admin@rootly.com / Admin123!")
        logger.info("  Farmer: farmer@rootly.com / Farmer123!")
        logger.info("  Technician: tech@rootly.com / Tech123!")
        logger.info("  Manager: manager@rootly.com / Manager123!")
        logger.info("")
        logger.info("To stop services: docker-compose -f docker-compose.test.yml down")

    else:
        logger.info("Using local setup...")

        # Check if database is available
        logger.info("Please ensure PostgreSQL is running and configured in .env")

        # Initialize database
        if not await init_database():
            logger.error("Failed to initialize database")
            return

        # Seed database
        if not await seed_database():
            logger.error("Failed to seed database")
            return

        # Start the service
        start_service()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Quick start interrupted by user")
    except Exception as e:
        logger.error(f"Quick start failed: {str(e)}")
        sys.exit(1)
