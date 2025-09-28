#!/usr/bin/env python3
"""
Utility script to create new migrations manually during development.
Usage: python scripts/create_migration.py "Description of changes"
"""

import sys
import os
from pathlib import Path

# Add the src directory to the path
project_root = Path(__file__).parent.parent
src_path = project_root / 'src'
sys.path.insert(0, str(src_path))

from core.services.migration_service import MigrationService
from adapters.logger.standard_logger import StandardLogger


def main():
    """Create a new migration."""
    if len(sys.argv) != 2:
        print("Usage: python scripts/create_migration.py \"Description of changes\"")
        sys.exit(1)
    
    message = sys.argv[1]
    
    logger = StandardLogger("migration_create")
    migration_service = MigrationService(logger)
    
    print(f"Creating migration: {message}")
    
    if migration_service.generate_migration(message):
        print("Migration created successfully!")
    else:
        print("Failed to create migration!")
        sys.exit(1)


if __name__ == "__main__":
    main()
