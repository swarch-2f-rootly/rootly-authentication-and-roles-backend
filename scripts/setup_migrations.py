#!/usr/bin/env python3
"""
Script to set up Alembic migrations inside the container.
This script runs after the database tables are created.
"""

import sys
import os
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, '/app/src')

from core.services.migration_service import MigrationService
from adapters.logger.standard_logger import StandardLogger


def main():
    """Set up Alembic migrations."""
    logger = StandardLogger("setup_migrations")
    migration_service = MigrationService(logger)
    
    logger.info("Setting up Alembic migrations...")
    
    try:
        # Check if migrations directory exists
        migrations_dir = Path("/app/migrations")
        if not migrations_dir.exists():
            logger.info("Migrations directory not found, creating...")
            migrations_dir.mkdir(parents=True)
            
            # Create versions subdirectory
            versions_dir = migrations_dir / "versions"
            versions_dir.mkdir(exist_ok=True)
        
        # Try to create a baseline migration if none exists
        versions_dir = migrations_dir / "versions"
        if not any(versions_dir.glob("*.py")):
            logger.info("No migrations found, creating baseline migration...")
            
            # Try to generate initial migration
            if migration_service.generate_migration("Initial migration - baseline"):
                logger.info("Baseline migration created successfully!")
            else:
                logger.warning("Could not create baseline migration, but continuing...")
        else:
            logger.info("Migrations already exist, skipping creation")
        
        logger.info("Migration setup completed!")
        return True
        
    except Exception as e:
        logger.error(f"Migration setup failed: {str(e)}")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
