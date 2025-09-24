#!/usr/bin/env python3
"""
Development runner script for the Authentication Service.
Configures PYTHONPATH and runs the application.
"""

import os
import sys

# Add project root and src directory to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(project_root, 'src')

if project_root not in sys.path:
    sys.path.insert(0, project_root)
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Now we can import from src
from src.main import app
import uvicorn

if __name__ == "__main__":
    # Get settings for configuration
    from src.config.settings import get_settings
    settings = get_settings()

    print("🚀 Starting Authentication Service in development mode...")
    print(f"📍 Project root: {project_root}")
    print(f"📁 Source path: {src_path}")
    print(f"🌐 Server will run on: http://{settings.host}:{settings.port}")

    # Run the application
    uvicorn.run(
        "src.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )
