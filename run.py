#!/usr/bin/env python3
"""Convenience entry point: ``python run.py`` launches the dashboard.

Equivalent to ``python -m app.server`` but works from the project root without
needing to remember the module path.
"""
from app.server import main

if __name__ == "__main__":
    main()
