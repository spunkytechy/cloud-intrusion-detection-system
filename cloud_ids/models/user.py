"""
models/user.py - User Model
============================
Represents an authenticated user of the Cloud IDS dashboard.

Fields:
  id            - Primary key
  username      - Unique login name
  email         - Unique email address
  password_hash - bcrypt/pbkdf2 hash (never plain text)
  role          - "admin" | "analyst" | "viewer"
  is_active     - Account enabled flag
  totp_secret   - Base32 MFA secret (pyotp)
  mfa_enabled   - Whether MFA is active for this account
  last_login    - Timestamp of most recent successful login
  login_attempts- Consecutive failed logins (brute-force lockout)
  locked_until  - Datetime until account is locked after too many failures
  created_at    - Auto timestamp (TimestampMixin)
  updated_at    - Auto timestamp (TimestampMixin)
"""

from datetime import datetime, timedelta, timezone

import pyotp
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from database.db import BaseModel, TimestampMixin, db


class User(TimestampMixin, BaseModel, UserMixin):
    """
    Cloud IDS user account.

    Inherits:
      - UserMixin    : Flask-Login integration (is_authenticated, etc.)
      - BaseModel    : save(), delete(), to_dict()
      - TimestampMixin: created_at, updated_at
    """

    __tablename__ = "users"

    # ------------------------------------------------------------------
    # Columns
    # ------------------------------------------------------------------
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    username = db.Column(
        db.String(64),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique login username",
    )
    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique email address",
    )
    password_hash = db.Column(
        db.String(256),
        nullable=False,
        comment="Hashed password — never store plain text",
    )

    # Role-based access control
    # admin   : full access (manage rules, users, settings)
    # analyst : can view and acknowledge alerts
    # viewer  : read-only dashboard access
    role = db.Column(
        db.String(20),
        nullable=False,
        default="viewer",
        comment="User role: admin | analyst | viewer",
    )

    is_active = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
        comment="False = account disabled",
    )

    # MFA (TOTP)
    totp_secret = db.Column(
        db.String(64),
        nullable=True,
        comment="Base32 TOTP secret for MFA (pyotp)",
    )
    mfa_enabled = db.Column(
        db.Boolean,
        nullable=False,
        default=False,
        comment="Whether TOTP MFA is active for this user",
    )

    # Login tracking
    last_login = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp of last successful login",
    )
    login_attempts = db.Column(
        db.Integer,
        nullable=False,
        default=0,
        comment="Consecutive failed login attempts",
    )
    locked_until = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
        comment="Account locked until this UTC datetime",
    )

    # ------------------------------------------------------------------
    # Relationships (defined in later phases when other models exist)
    # ------------------------------------------------------------------
    # alerts = db.relationship("Alert", backref="creator", lazy="dynamic")

    # ------------------------------------------------------------------
    # Password helpers
    # ------------------------------------------------------------------
    def set_password(self, plain_password: str) -> None:
        """
        Hash and store a password.

        Args:
            plain_password: The user's chosen plain-text password.
        """
        self.password_hash = generate_password_hash(
            plain_password,
            method="pbkdf2:sha256",
            salt_length=16,
        )

    def check_password(self, plain_password: str) -> bool:
        """
        Verify a plain-text password against the stored hash.

        Args:
            plain_password: Password entered at login.

        Returns:
            bool: True if password matches.
        """
        return check_password_hash(self.password_hash, plain_password)

    # ------------------------------------------------------------------
    # Account lockout helpers
    # ------------------------------------------------------------------
    MAX_FAILED_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15

    def record_failed_login(self) -> None:
        """
        Increment the failed login counter and lock the account
        if MAX_FAILED_ATTEMPTS is reached.
        """
        self.login_attempts += 1
        if self.login_attempts >= self.MAX_FAILED_ATTEMPTS:
            self.locked_until = datetime.now(timezone.utc) + timedelta(
                minutes=self.LOCKOUT_DURATION_MINUTES
            )
        self.save()

    def record_successful_login(self) -> None:
        """Reset failed attempt counter and update last_login timestamp."""
        self.login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.now(timezone.utc)
        self.save()

    @property
    def is_locked(self) -> bool:
        """
        True if the account is currently locked due to failed login attempts.
        Automatically clears the lock once the lockout period expires.
        """
        if self.locked_until is None:
            return False
        if datetime.now(timezone.utc) > self.locked_until:
            # Lock has expired — clear it
            self.locked_until = None
            self.login_attempts = 0
            return False
        return True

    # ------------------------------------------------------------------
    # MFA (TOTP) helpers
    # ------------------------------------------------------------------
    def generate_totp_secret(self) -> str:
        """
        Generate and store a new TOTP secret.

        Returns:
            str: Base32 secret (show to user for QR code enrollment).
        """
        self.totp_secret = pyotp.random_base32()
        return self.totp_secret

    def get_totp_uri(self, issuer: str = "CloudIDS") -> str:
        """
        Build the otpauth:// URI for QR code generation.

        Args:
            issuer: The service name shown in authenticator apps.

        Returns:
            str: otpauth URI string.
        """
        if not self.totp_secret:
            raise ValueError("TOTP secret not set. Call generate_totp_secret() first.")
        totp = pyotp.TOTP(self.totp_secret)
        return totp.provisioning_uri(name=self.email, issuer_name=issuer)

    def verify_totp(self, token: str) -> bool:
        """
        Verify a 6-digit TOTP token submitted at login.

        Args:
            token: 6-digit string from authenticator app.

        Returns:
            bool: True if token is valid within the time window.
        """
        if not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        # valid_window=1 allows one 30-second window tolerance
        return totp.verify(token, valid_window=1)

    # ------------------------------------------------------------------
    # Role helpers
    # ------------------------------------------------------------------
    def is_admin(self) -> bool:
        """Return True if the user has the admin role."""
        return self.role == "admin"

    def is_analyst(self) -> bool:
        """Return True if the user has the analyst or admin role."""
        return self.role in ("admin", "analyst")

    # ------------------------------------------------------------------
    # Flask-Login required methods
    # ------------------------------------------------------------------
    def get_id(self) -> str:
        """Return the user id as a string (Flask-Login requirement)."""
        return str(self.id)

    # ------------------------------------------------------------------
    # Serialisation (overrides BaseModel to hide sensitive fields)
    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        """Return a safe dict representation (no password or TOTP secret)."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "mfa_enabled": self.mfa_enabled,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
