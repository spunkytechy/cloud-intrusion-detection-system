"""
database/__init__.py
====================
Makes `database` a Python package and exposes the shared db instance
and helper utilities so other modules can import cleanly:

    from database import db
    from database.db import init_db, get_db_stats, check_db_connection
    from database.seed import run_seed
    from database.migrations_helper import run_migrations
"""

from database.db import check_db_connection, db, get_db_stats, init_db
from database.migrations_helper import (
    check_migration_status,
    create_migration,
    init_migrations_folder,
    run_migrations,
)
from database.seed import run_seed

__all__ = [
    "check_db_connection",
    "check_migration_status",
    "create_migration",
    "db",
    "get_db_stats",
    "init_db",
    "init_migrations_folder",
    "run_migrations",
    "run_seed",
]
