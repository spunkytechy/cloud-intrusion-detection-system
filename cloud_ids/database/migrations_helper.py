"""
database/migrations_helper.py - Flask-Migrate / Alembic Helpers
=================================================================
Provides programmatic wrappers around Flask-Migrate commands so
migrations can be triggered from code (CI pipelines, startup scripts)
as well as the CLI.

Flask-Migrate CLI quick reference
----------------------------------
  flask db init          → create the migrations/ folder (run once)
  flask db migrate -m "" → auto-generate a migration script from model changes
  flask db upgrade       → apply pending migrations to the database
  flask db downgrade     → roll back the last migration
  flask db history       → list all migration revisions
  flask db current       → show the current revision applied to the DB
  flask db stamp head    → mark DB as up-to-date without running migrations

Usage (programmatic):
    from database.migrations_helper import run_migrations, check_migration_status
    from app import create_app
    app = create_app()
    with app.app_context():
        run_migrations()
"""

import logging
import os
import subprocess
import sys

logger = logging.getLogger(__name__)


def run_migrations() -> bool:
    """
    Apply all pending Alembic migrations to the database.

    Equivalent to: flask db upgrade

    Returns:
        bool: True if migrations applied successfully, False on error.
    """
    logger.info("Running database migrations (flask db upgrade)...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "flask", "db", "upgrade"],
            capture_output=True,
            text=True,
            check=True,
        )
        logger.info("Migrations output:\n%s", result.stdout)
        return True
    except subprocess.CalledProcessError as exc:
        logger.error(
            "Migration failed.\nstdout: %s\nstderr: %s",
            exc.stdout,
            exc.stderr,
        )
        return False


def create_migration(message: str = "auto migration") -> bool:
    """
    Auto-generate a new migration script from model changes.

    Equivalent to: flask db migrate -m "<message>"

    Args:
        message: Short description of the change (used in filename).

    Returns:
        bool: True if migration script created successfully.
    """
    logger.info("Generating migration: '%s'", message)
    try:
        result = subprocess.run(
            [sys.executable, "-m", "flask", "db", "migrate", "-m", message],
            capture_output=True,
            text=True,
            check=True,
        )
        logger.info("Migration script output:\n%s", result.stdout)
        return True
    except subprocess.CalledProcessError as exc:
        logger.error(
            "Migration generation failed.\nstdout: %s\nstderr: %s",
            exc.stdout,
            exc.stderr,
        )
        return False


def check_migration_status() -> dict:
    """
    Return the current migration status of the database.

    Equivalent to: flask db current

    Returns:
        dict with keys:
          - current_revision : active Alembic revision hash or None
          - status           : "ok" | "error"
          - message          : human-readable status
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "flask", "db", "current"],
            capture_output=True,
            text=True,
            check=True,
        )
        revision = result.stdout.strip() or "none"
        return {
            "status": "ok",
            "current_revision": revision,
            "message": f"Current DB revision: {revision}",
        }
    except subprocess.CalledProcessError as exc:
        return {
            "status": "error",
            "current_revision": None,
            "message": exc.stderr.strip(),
        }


def get_migration_history() -> list:
    """
    Return a list of all Alembic revision strings in history order.

    Equivalent to: flask db history

    Returns:
        list[str]: Revision lines from Alembic history output.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "flask", "db", "history"],
            capture_output=True,
            text=True,
            check=True,
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return lines
    except subprocess.CalledProcessError as exc:
        logger.error("Could not retrieve migration history: %s", exc.stderr)
        return []


def init_migrations_folder() -> bool:
    """
    Initialise the Alembic migrations folder if it does not exist.

    Equivalent to: flask db init
    Only needs to be run once per project.

    Returns:
        bool: True if successful or already initialised.
    """
    migrations_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "migrations",
    )

    if os.path.exists(migrations_path):
        logger.info("Migrations folder already exists at: %s", migrations_path)
        return True

    logger.info("Initialising migrations folder...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "flask", "db", "init"],
            capture_output=True,
            text=True,
            check=True,
        )
        logger.info("Migrations folder initialised:\n%s", result.stdout)
        return True
    except subprocess.CalledProcessError as exc:
        logger.error(
            "flask db init failed.\nstdout: %s\nstderr: %s",
            exc.stdout,
            exc.stderr,
        )
        return False
