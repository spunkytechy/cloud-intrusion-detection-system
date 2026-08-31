"""
config.py - Application Configuration Module
=============================================
Defines configuration classes for different environments:
  - BaseConfig    : shared settings for all environments
  - DevelopmentConfig : local development overrides
  - TestingConfig : isolated test environment
  - ProductionConfig  : hardened production settings

The active config is selected via the FLASK_ENV environment variable.
All sensitive values are read from environment variables (never hard-coded).
"""

import os
from datetime import timedelta

from dotenv import load_dotenv

# Load .env file into environment before reading any values
load_dotenv()


# ==============================================================================
# Helper: read a required env variable and raise clearly if missing
# ==============================================================================
def _require_env(key: str) -> str:
    """Return the value of an environment variable or raise RuntimeError."""
    value = os.environ.get(key)
    if not value:
        raise RuntimeError(
            f"Required environment variable '{key}' is not set. "
            f"Check your .env file."
        )
    return value


# ==============================================================================
# BASE CONFIGURATION
# Shared by all environments. Subclasses override what they need.
# ==============================================================================
class BaseConfig:
    """Base configuration — common settings across all environments."""

    # ------------------------------------------------------------------
    # Flask Core
    # ------------------------------------------------------------------
    SECRET_KEY: str = os.environ.get(
        "SECRET_KEY", "fallback-dev-secret-key-replace-in-prod"
    )
    APP_NAME: str = os.environ.get("APP_NAME", "Cloud IDS")
    APP_HOST: str = os.environ.get("APP_HOST", "0.0.0.0")
    APP_PORT: int = int(os.environ.get("APP_PORT", 5000))

    # ------------------------------------------------------------------
    # Database — SQLAlchemy
    # ------------------------------------------------------------------
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL",
        "postgresql+psycopg2://postgres:CHANGE_ME@localhost:5432/cloud_ids_db",
    )
    # Disable modification tracking (saves memory; Flask-SQLAlchemy owns this)
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    # Connection pool settings for reliability under load
    SQLALCHEMY_ENGINE_OPTIONS: dict = {
        "pool_size": 10,  # max persistent connections
        "max_overflow": 20,  # extra connections beyond pool_size
        "pool_timeout": 30,  # seconds to wait for a connection
        "pool_recycle": 1800,  # recycle connections every 30 min
        "pool_pre_ping": True,  # test connections before using them
    }

    # ------------------------------------------------------------------
    # JWT Configuration
    # ------------------------------------------------------------------
    JWT_SECRET_KEY: str = os.environ.get(
        "JWT_SECRET_KEY", "fallback-jwt-secret-replace-in-prod"
    )
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        seconds=int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRES", 3600))
    )
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(
        seconds=int(os.environ.get("JWT_REFRESH_TOKEN_EXPIRES", 86400))
    )
    JWT_TOKEN_LOCATION: list = ["headers", "cookies"]
    JWT_COOKIE_SECURE: bool = False  # True in production (HTTPS only)
    JWT_COOKIE_CSRF_PROTECT: bool = True

    # ------------------------------------------------------------------
    # Session / Cookie Security
    # ------------------------------------------------------------------
    SESSION_COOKIE_SECURE: bool = (
        os.environ.get("SESSION_COOKIE_SECURE", "False").lower() == "true"
    )
    SESSION_COOKIE_HTTPONLY: bool = True  # JS cannot access session cookie
    SESSION_COOKIE_SAMESITE: str = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # ------------------------------------------------------------------
    # Flask-Login
    # ------------------------------------------------------------------
    LOGIN_VIEW: str = "auth.login"  # redirect target for @login_required
    LOGIN_MESSAGE: str = "Please log in to access this page."
    LOGIN_MESSAGE_CATEGORY: str = "warning"

    # ------------------------------------------------------------------
    # Flask-Mail (SMTP alert notifications)
    # ------------------------------------------------------------------
    MAIL_SERVER: str = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT: int = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS: bool = os.environ.get("MAIL_USE_TLS", "True").lower() == "true"
    # Flask-Mail 0.10 calls int(app.config['MAIL_DEBUG']) — must not be None
    MAIL_DEBUG: int = int(os.environ.get("MAIL_DEBUG", 0))
    MAIL_USERNAME: str = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD: str = os.environ.get("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER: str = os.environ.get("MAIL_DEFAULT_SENDER", "")
    ALERT_EMAIL_RECIPIENT: str = os.environ.get("ALERT_EMAIL_RECIPIENT", "")

    # ------------------------------------------------------------------
    # Redis / Celery (background detection tasks)
    # ------------------------------------------------------------------
    REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    CELERY_BROKER_URL: str = os.environ.get(
        "CELERY_BROKER_URL", "redis://localhost:6379/0"
    )
    CELERY_RESULT_BACKEND: str = os.environ.get(
        "CELERY_RESULT_BACKEND", "redis://localhost:6379/1"
    )
    CELERY_TASK_SERIALIZER: str = "json"
    CELERY_RESULT_SERIALIZER: str = "json"
    CELERY_ACCEPT_CONTENT: list = ["json"]
    CELERY_TIMEZONE: str = "UTC"

    # ------------------------------------------------------------------
    # Flask-Limiter (rate limiting)
    # ------------------------------------------------------------------
    RATELIMIT_DEFAULT: str = os.environ.get(
        "RATELIMIT_DEFAULT", "200 per day;50 per hour"
    )
    # Use in-memory storage by default so app works without Redis.
    # Switch to redis://... in production via the RATELIMIT_STORAGE_URL env var.
    RATELIMIT_STORAGE_URL: str = os.environ.get(
        "RATELIMIT_STORAGE_URL", "memory://"
    )
    RATELIMIT_HEADERS_ENABLED: bool = True  # expose X-RateLimit-* headers

    # ------------------------------------------------------------------
    # Packet Capture Settings
    # ------------------------------------------------------------------
    # Master switch — set to False to boot the web UI without starting
    # the Scapy sniffer (useful on machines without Npcap / admin rights).
    ENABLE_PACKET_CAPTURE: bool = (
        os.environ.get("ENABLE_PACKET_CAPTURE", "True").lower() == "true"
    )
    CAPTURE_INTERFACE: str = os.environ.get("CAPTURE_INTERFACE", "Ethernet")
    CAPTURE_FILTER: str = os.environ.get("CAPTURE_FILTER", "ip")
    PACKET_BUFFER_SIZE: int = int(os.environ.get("PACKET_BUFFER_SIZE", 10000))

    # PacketAnalyzer batching — how many rows to buffer before flushing
    # to the DB, and the max seconds a row can sit in the buffer.
    ANALYZER_BATCH_SIZE: int = int(os.environ.get("ANALYZER_BATCH_SIZE", 50))
    ANALYZER_FLUSH_INTERVAL: float = float(
        os.environ.get("ANALYZER_FLUSH_INTERVAL", 2.0)
    )

    # Suspicious-IP registry — how long a detected IP stays flagged so
    # subsequent packets from it are stored as 'suspicious', and how
    # far back the AlertGenerator back-writes existing traffic rows.
    SUSPICIOUS_IP_TTL_SECONDS: int = int(
        os.environ.get("SUSPICIOUS_IP_TTL_SECONDS", 300)
    )
    SUSPICIOUS_BACKFILL_WINDOW_SECONDS: int = int(
        os.environ.get("SUSPICIOUS_BACKFILL_WINDOW_SECONDS", 300)
    )

    # ------------------------------------------------------------------
    # Detection Engine Thresholds
    # ------------------------------------------------------------------
    PORT_SCAN_THRESHOLD: int = int(os.environ.get("PORT_SCAN_THRESHOLD", 20))
    PORT_SCAN_WINDOW: int = int(os.environ.get("PORT_SCAN_WINDOW", 10))
    BRUTE_FORCE_THRESHOLD: int = int(os.environ.get("BRUTE_FORCE_THRESHOLD", 5))
    BRUTE_FORCE_WINDOW: int = int(os.environ.get("BRUTE_FORCE_WINDOW", 60))
    DDOS_THRESHOLD: int = int(os.environ.get("DDOS_THRESHOLD", 1000))
    DDOS_WINDOW: int = int(os.environ.get("DDOS_WINDOW", 1))
    TRAFFIC_SPIKE_MULTIPLIER: int = int(os.environ.get("TRAFFIC_SPIKE_MULTIPLIER", 3))

    # ------------------------------------------------------------------
    # Security
    # ------------------------------------------------------------------
    BCRYPT_LOG_ROUNDS: int = int(os.environ.get("BCRYPT_LOG_ROUNDS", 12))
    MFA_ENABLED: bool = os.environ.get("MFA_ENABLED", "True").lower() == "true"
    MFA_ISSUER: str = os.environ.get("MFA_ISSUER", "CloudIDS")
    # IP addresses permanently blocked at application level
    IP_BLACKLIST: list = []

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "DEBUG")
    LOG_FILE: str = os.environ.get("LOG_FILE", "logs/cloud_ids.log")
    LOG_MAX_BYTES: int = int(os.environ.get("LOG_MAX_BYTES", 10 * 1024 * 1024))  # 10 MB
    LOG_BACKUP_COUNT: int = int(os.environ.get("LOG_BACKUP_COUNT", 10))

    # ------------------------------------------------------------------
    # Admin Seed Account
    # ------------------------------------------------------------------
    ADMIN_USERNAME: str = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_EMAIL: str = os.environ.get("ADMIN_EMAIL", "admin@cloudids.local")
    ADMIN_PASSWORD: str = os.environ.get("ADMIN_PASSWORD", "Admin@123!ChangeMe")

    # ------------------------------------------------------------------
    # AWS
    # ------------------------------------------------------------------
    AWS_REGION: str = os.environ.get("AWS_REGION", "us-east-1")
    AWS_S3_BUCKET: str = os.environ.get("AWS_S3_BUCKET", "cloud-ids-backups")

    # ------------------------------------------------------------------
    # SocketIO
    # ------------------------------------------------------------------
    SOCKETIO_ASYNC_MODE: str = "threading"  # works on Windows without eventlet
    SOCKETIO_CORS_ALLOWED_ORIGINS: str = "*"  # lock down to domain in production

    # ------------------------------------------------------------------
    # WTForms CSRF
    # ------------------------------------------------------------------
    WTF_CSRF_ENABLED: bool = True
    WTF_CSRF_TIME_LIMIT: int = 3600  # CSRF token valid for 1 hour

    # ------------------------------------------------------------------
    # Pagination
    # ------------------------------------------------------------------
    ITEMS_PER_PAGE: int = 25


# ==============================================================================
# DEVELOPMENT CONFIGURATION
# ==============================================================================
class DevelopmentConfig(BaseConfig):
    """Development settings — verbose logging, no HTTPS enforcement."""

    DEBUG: bool = True
    TESTING: bool = False

    # Relax security for local dev
    WTF_CSRF_ENABLED: bool = True
    SESSION_COOKIE_SECURE: bool = False
    JWT_COOKIE_SECURE: bool = False

    # More verbose SQL for debugging
    SQLALCHEMY_ECHO: bool = False  # Set True to log every SQL statement

    # Lower bcrypt rounds = faster logins during dev
    BCRYPT_LOG_ROUNDS: int = 4

    LOG_LEVEL: str = "DEBUG"


# ==============================================================================
# TESTING CONFIGURATION
# ==============================================================================
class TestingConfig(BaseConfig):
    """Testing settings — in-memory SQLite, CSRF disabled, fast hashing."""

    DEBUG: bool = True
    TESTING: bool = True

    # Use in-memory SQLite so tests never touch the real DB
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"

    # SQLite does not support pool_size/max_overflow — clear engine options
    SQLALCHEMY_ENGINE_OPTIONS: dict = {}

    # Disable CSRF for test client form submissions
    WTF_CSRF_ENABLED: bool = False

    # Minimal bcrypt rounds for speed in test suite
    BCRYPT_LOG_ROUNDS: int = 4

    # Use synchronous mode so tests don't need eventlet
    SOCKETIO_ASYNC_MODE = "threading"

    # Suppress email sending in tests
    MAIL_SUPPRESS_SEND: bool = True

    LOG_LEVEL: str = "WARNING"


# ==============================================================================
# PRODUCTION CONFIGURATION
# ==============================================================================
class ProductionConfig(BaseConfig):
    """Production settings — strict security, HTTPS enforced, hardened cookies."""

    DEBUG: bool = False
    TESTING: bool = False

    # Enforce HTTPS-only cookies
    SESSION_COOKIE_SECURE: bool = True
    JWT_COOKIE_SECURE: bool = True
    SESSION_COOKIE_SAMESITE: str = "Strict"

    # Stricter CORS for SocketIO (set to your actual domain)
    SOCKETIO_CORS_ALLOWED_ORIGINS: str = os.environ.get(
        "ALLOWED_ORIGINS", "https://yourdomain.com"
    )

    # Full bcrypt strength in production
    BCRYPT_LOG_ROUNDS: int = 12

    # Disable SQL echo in production
    SQLALCHEMY_ECHO: bool = False

    LOG_LEVEL: str = "WARNING"

    # Require all secrets to be explicitly set in production
    @classmethod
    def validate(cls) -> None:
        """Raise RuntimeError if any required production secret is missing."""
        required = ["SECRET_KEY", "JWT_SECRET_KEY", "DATABASE_URL"]
        for key in required:
            _require_env(key)


# ==============================================================================
# CONFIG REGISTRY
# Maps FLASK_ENV values to their configuration class.
# Usage: app.config.from_object(config_by_name[os.environ.get("FLASK_ENV")])
# ==============================================================================
config_by_name: dict = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    # default falls back to development
    "default": DevelopmentConfig,
}


def get_config() -> type:
    """
    Return the correct configuration class based on FLASK_ENV.

    Returns:
        type: One of DevelopmentConfig, TestingConfig, or ProductionConfig.
    """
    env = os.environ.get("FLASK_ENV", "development").lower()
    cfg = config_by_name.get(env, DevelopmentConfig)

    # Validate required secrets when running in production
    if env == "production" and hasattr(cfg, "validate"):
        cfg.validate()

    return cfg


# Convenience alias used by app.py
Config = get_config()
