"""
models/audit_log.py - Audit Log Model
======================================
Immutable record of every significant action performed inside the system.

Audit logs are append-only — no update or delete operations are permitted.
They serve as a tamper-evident trail for security investigations and
compliance purposes.

Fields:
  id          - Primary key
  user_id     - FK to users.id (null for system/unauthenticated actions)
  username    - Snapshot of the username at time of action (denormalised)
  action      - Short action code (e.g. "login", "rule_updated")
  target      - What the action was performed on (e.g. "DetectionRule:3")
  ip_address  - IP from which the action originated
  user_agent  - Browser/client user-agent string
  details     - JSON string with additional context
  timestamp   - UTC datetime of the action
"""

import json
from datetime import datetime, timezone

from database.db import db


class AuditLog(db.Model):
    """
    Immutable audit trail entry.

    Does NOT inherit BaseModel because audit logs must never be
    modified or deleted — save() and delete() are intentionally absent.
    """

    __tablename__ = "audit_logs"

    __table_args__ = (
        db.Index("ix_audit_user_id", "user_id"),
        db.Index("ix_audit_timestamp", "timestamp"),
        db.Index("ix_audit_action", "action"),
        db.Index("ix_audit_ip", "ip_address"),
    )

    # ------------------------------------------------------------------
    # Common action codes
    # ------------------------------------------------------------------
    ACTION_LOGIN = "login"
    ACTION_LOGOUT = "logout"
    ACTION_LOGIN_FAILED = "login_failed"
    ACTION_LOGIN_LOCKED = "login_locked"
    ACTION_REGISTER = "register"
    ACTION_PASSWORD_CHANGE = "password_change"
    ACTION_MFA_ENABLED = "mfa_enabled"
    ACTION_MFA_DISABLED = "mfa_disabled"
    ACTION_RULE_CREATED = "rule_created"
    ACTION_RULE_UPDATED = "rule_updated"
    ACTION_RULE_TOGGLED = "rule_toggled"
    ACTION_ALERT_ACK = "alert_acknowledged"
    ACTION_ALERT_RESOLVED = "alert_resolved"
    ACTION_ALERT_FP = "alert_false_positive"
    ACTION_USER_CREATED = "user_created"
    ACTION_USER_UPDATED = "user_updated"
    ACTION_USER_DELETED = "user_deleted"
    ACTION_EXPORT = "data_exported"
    ACTION_BACKUP = "backup_created"
    ACTION_SYSTEM = "system_event"

    # ------------------------------------------------------------------
    # Columns
    # ------------------------------------------------------------------
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="FK to users.id — null for unauthenticated or system actions",
    )
    username = db.Column(
        db.String(64),
        nullable=True,
        comment="Username snapshot at action time (preserved if user is deleted)",
    )
    action = db.Column(
        db.String(50),
        nullable=False,
        comment="Short action identifier code",
    )
    target = db.Column(
        db.String(128),
        nullable=True,
        comment="Entity affected, e.g. 'Alert:42' or 'DetectionRule:3'",
    )
    ip_address = db.Column(
        db.String(45),
        nullable=True,
        comment="Client IP address at time of action",
    )
    user_agent = db.Column(
        db.String(256),
        nullable=True,
        comment="HTTP User-Agent string",
    )
    details = db.Column(
        db.Text,
        nullable=True,
        comment="JSON-encoded additional context for the action",
    )
    timestamp = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        comment="UTC datetime when the action occurred",
    )

    # ------------------------------------------------------------------
    # Factory method — the only sanctioned way to create audit records
    # ------------------------------------------------------------------
    @classmethod
    def log(
        cls,
        action: str,
        user_id: int = None,
        username: str = None,
        target: str = None,
        ip_address: str = None,
        user_agent: str = None,
        details: dict = None,
    ) -> "AuditLog":
        """
        Create and persist a new audit log entry.

        Args:
            action     : Action code (use ACTION_* constants).
            user_id    : Optional FK to the acting user.
            username   : Username snapshot.
            target     : Entity affected (e.g. "Alert:5").
            ip_address : Client IP.
            user_agent : Browser user-agent string.
            details    : Extra context as a plain dict (auto-serialised to JSON).

        Returns:
            AuditLog: The persisted instance.
        """
        entry = cls(
            action=action,
            user_id=user_id,
            username=username,
            target=target,
            ip_address=ip_address,
            user_agent=user_agent,
            details=json.dumps(details) if details else None,
            timestamp=datetime.now(timezone.utc),
        )
        db.session.add(entry)
        db.session.commit()
        return entry

    def get_details(self) -> dict:
        """
        Deserialise the JSON details field.

        Returns:
            dict: Parsed details, or empty dict if null/invalid.
        """
        if not self.details:
            return {}
        try:
            return json.loads(self.details)
        except (ValueError, TypeError):
            return {}

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------
    @classmethod
    def get_recent(cls, limit: int = 100) -> list:
        """Return the `limit` most recent audit entries."""
        return cls.query.order_by(cls.timestamp.desc()).limit(limit).all()

    @classmethod
    def get_by_user(cls, user_id: int, limit: int = 50) -> list:
        """Return recent audit entries for a specific user."""
        return (
            cls.query.filter_by(user_id=user_id)
            .order_by(cls.timestamp.desc())
            .limit(limit)
            .all()
        )

    @classmethod
    def get_failed_logins(cls, ip_address: str = None, limit: int = 50) -> list:
        """Return failed login entries, optionally filtered by IP."""
        q = cls.query.filter_by(action=cls.ACTION_LOGIN_FAILED)
        if ip_address:
            q = q.filter_by(ip_address=ip_address)
        return q.order_by(cls.timestamp.desc()).limit(limit).all()

    def to_dict(self) -> dict:
        """Serialise the audit log entry to a plain dict."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.username,
            "action": self.action,
            "target": self.target,
            "ip_address": self.ip_address,
            "details": self.get_details(),
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} action={self.action} user={self.username}>"
