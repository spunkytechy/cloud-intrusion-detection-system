"""
database/db.py - Database Layer
================================
Provides:
  - The shared SQLAlchemy `db` instance (imported by models & app.py)
  - `init_db(app)`        : creates all tables and seeds initial data
  - `check_db_connection` : health-check callable (used by /api/v1/health)
  - `get_db_stats`        : returns row counts per table for the dashboard
  - `TimestampMixin`      : reusable created_at / updated_at columns
  - `BaseModel`           : abstract base all models inherit from

Architecture note:
  `db` is created here (not in app.py) so models can import it without
  importing the entire Flask application, preventing circular imports.
"""

import logging
from datetime import datetime, timezone

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, SQLAlchemyError

logger = logging.getLogger(__name__)

# ==============================================================================
# SHARED DB INSTANCE
# All models and app.py import this single object.
# ==============================================================================
db = SQLAlchemy()


# ==============================================================================
# TIMESTAMP MIXIN
# Automatically adds created_at / updated_at to any model that inherits it.
# ==============================================================================
class TimestampMixin:
    """
    Mixin that adds created_at and updated_at columns to a model.

    Usage:
        class MyModel(TimestampMixin, db.Model):
            ...
    """

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        comment="UTC timestamp when the record was created",
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        comment="UTC timestamp when the record was last modified",
    )


# ==============================================================================
# BASE MODEL
# Adds shared helper methods available on every model.
# ==============================================================================
class BaseModel(db.Model):
    """
    Abstract base class for all Cloud IDS models.

    Provides:
      - save()   : add to session and commit
      - delete() : delete from session and commit
      - to_dict(): serialize column values to a plain dict
    """

    # Mark as abstract so SQLAlchemy does not create a table for it
    __abstract__ = True

    def save(self) -> "BaseModel":
        """
        Persist the current instance to the database.

        Returns:
            self — allows method chaining: obj.save().to_dict()

        Raises:
            SQLAlchemyError: if the commit fails (session is rolled back).
        """
        try:
            db.session.add(self)
            db.session.commit()
            return self
        except SQLAlchemyError as exc:
            db.session.rollback()
            logger.error("save() failed for %s: %s", self.__class__.__name__, exc)
            raise

    def delete(self) -> None:
        """
        Remove the current instance from the database.

        Raises:
            SQLAlchemyError: if the commit fails (session is rolled back).
        """
        try:
            db.session.delete(self)
            db.session.commit()
        except SQLAlchemyError as exc:
            db.session.rollback()
            logger.error("delete() failed for %s: %s", self.__class__.__name__, exc)
            raise

    def to_dict(self) -> dict:
        """
        Serialize all mapped columns to a Python dictionary.

        DateTime values are converted to ISO-8601 strings.
        Binary/password fields are excluded automatically.

        Returns:
            dict: column_name → value mapping.
        """
        result = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            # Never serialise password hashes or secret fields
            if column.name in ("password_hash", "secret", "totp_secret"):
                continue
            # Convert datetime to ISO string for JSON serialisation
            if isinstance(value, datetime):
                value = value.isoformat()
            result[column.name] = value
        return result

    @classmethod
    def get_by_id(cls, record_id: int):
        """
        Fetch a single record by primary key.

        Args:
            record_id: Integer primary key.

        Returns:
            Model instance or None.
        """
        return cls.query.get(record_id)

    @classmethod
    def get_all(cls) -> list:
        """Return all records for this model."""
        return cls.query.all()

    @classmethod
    def count(cls) -> int:
        """Return total number of records in the table."""
        return cls.query.count()

    def __repr__(self) -> str:
        """Generic representation using the model class name and primary key."""
        pk_cols = [c.name for c in self.__table__.primary_key.columns]
        pk_vals = {c: getattr(self, c, "?") for c in pk_cols}
        return f"<{self.__class__.__name__} {pk_vals}>"


# ==============================================================================
# DATABASE INITIALISATION
# ==============================================================================
def init_db(app: Flask) -> None:
    """
    Create all database tables defined by SQLAlchemy models, then seed
    default data (detection rules + admin user) on first run.

    Must be called inside an active application context.
    Typically invoked from app.py → create_app() → _init_database().

    Sequence:
        1. Import all model classes so SQLAlchemy registers their metadata.
        2. db.create_all() — creates any tables that don't exist yet
           (idempotent; existing tables are not dropped or modified).
        3. run_seed(app)   — inserts default rows if tables are empty.

    Args:
        app: Active Flask application instance (needed by seeder for config).
    """
    # ----------------------------------------------------------------
    # Step 1: Import all models so SQLAlchemy registers their table
    # metadata before create_all() is called. Order matters for FKs.
    # ----------------------------------------------------------------
    from models.alert import Alert  # noqa: F401
    from models.audit_log import AuditLog  # noqa: F401
    from models.detection_rule import DetectionRule  # noqa: F401
    from models.traffic_log import TrafficLog  # noqa: F401
    from models.user import User  # noqa: F401

    # ----------------------------------------------------------------
    # Step 2: Create tables
    # ----------------------------------------------------------------
    try:
        db.create_all()
        logger.info("All database tables created / verified.")
    except OperationalError as exc:
        logger.error(
            "Cannot connect to the database. " "Check DATABASE_URL in .env. Error: %s",
            exc,
        )
        raise
    except SQLAlchemyError as exc:
        logger.error("Failed to create database tables: %s", exc)
        raise

    # ----------------------------------------------------------------
    # Step 3: Seed default data (safe to call on every startup —
    # the seeder checks for existing rows before inserting).
    # ----------------------------------------------------------------
    try:
        from database.seed import run_seed

        run_seed(app)
    except Exception as exc:
        # Seeding failure is non-fatal — app can still run without seed data
        logger.warning("Database seeding encountered an error (non-fatal): %s", exc)


# ==============================================================================
# HEALTH CHECK
# ==============================================================================
def check_db_connection() -> dict:
    """
    Execute a lightweight SQL query to verify the database is reachable.

    Returns:
        dict with keys:
          - status  : "ok" | "error"
          - message : human-readable status string
          - latency : query round-trip time in milliseconds (float)
    """
    import time

    start = time.perf_counter()
    try:
        db.session.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return {
            "status": "ok",
            "message": "Database connection is healthy.",
            "latency_ms": latency_ms,
        }
    except OperationalError as exc:
        return {
            "status": "error",
            "message": f"Database unreachable: {exc}",
            "latency_ms": None,
        }
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Unexpected database error: {exc}",
            "latency_ms": None,
        }


# ==============================================================================
# DATABASE STATISTICS
# ==============================================================================
def get_db_stats() -> dict:
    """
    Return row counts for all core tables.
    Used by the dashboard to display summary statistics.

    Returns:
        dict: table_name → row count (int). Returns -1 if a table query fails.
    """
    from models.alert import Alert
    from models.audit_log import AuditLog
    from models.detection_rule import DetectionRule
    from models.traffic_log import TrafficLog
    from models.user import User

    stats = {}
    table_models = {
        "users": User,
        "traffic_logs": TrafficLog,
        "alerts": Alert,
        "detection_rules": DetectionRule,
        "audit_logs": AuditLog,
    }

    for table_name, model_class in table_models.items():
        try:
            stats[table_name] = model_class.query.count()
        except SQLAlchemyError as exc:
            logger.warning("Could not count rows in %s: %s", table_name, exc)
            stats[table_name] = -1

    return stats
