"""
alerts/generator.py - AlertGenerator
======================================
Creates Alert records, emits SocketIO events for real-time dashboard
updates, and sends email notifications for critical/high alerts.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Prevent duplicate alerts for the same IP+type within a short window
_recent_alerts: dict = {}   # key: "type:ip" → last_fired timestamp
DEDUP_SECONDS = 30          # suppress duplicate alert within 30s


class AlertGenerator:
    """Static factory — creates, saves, and broadcasts alerts."""

    @staticmethod
    def create(threat_type: str, source_ip: str, severity: str, message: str) -> None:
        """
        Persist a new Alert, emit a SocketIO event, and optionally send email.

        Args:
            threat_type : one of Alert.THREAT_* constants
            source_ip   : attacking IP address
            severity    : critical | high | medium | low
            message     : human-readable description
        """
        # Deduplication — don't spam identical alerts
        key = f"{threat_type}:{source_ip}"
        now = datetime.now(timezone.utc)
        last = _recent_alerts.get(key)
        if last and (now.timestamp() - last) < DEDUP_SECONDS:
            return
        _recent_alerts[key] = now.timestamp()

        try:
            from database.db import db
            from models.alert import Alert

            alert = Alert(
                threat_type   = threat_type,
                source_ip     = source_ip,
                severity      = severity,
                message       = message,
                time_detected = now,
            )
            db.session.add(alert)
            db.session.commit()
            logger.info("Alert created [%s] %s — %s", severity.upper(), threat_type, source_ip)

            # Broadcast to connected dashboard clients
            AlertGenerator._emit(alert)

            # Send email for critical and high severity
            if severity in ("critical", "high"):
                AlertGenerator._send_email(alert)

        except Exception as exc:
            logger.error("AlertGenerator.create error: %s", exc)

    @staticmethod
    def _emit(alert) -> None:
        """Push a real-time SocketIO event to all connected clients."""
        try:
            from app import socketio
            payload = {
                "alert_id":    alert.alert_id,
                "threat_type": alert.threat_type,
                "source_ip":   alert.source_ip,
                "severity":    alert.severity,
                "message":     alert.message,
                "time":        alert.time_detected.isoformat(),
            }
            socketio.emit("new_alert", payload, namespace="/ids")
        except Exception as exc:
            logger.warning("SocketIO emit failed: %s", exc)

    @staticmethod
    def _send_email(alert) -> None:
        """Send an email notification for high/critical alerts."""
        try:
            from flask import current_app
            from flask_mail import Message
            from app import mail

            recipient = current_app.config.get("ALERT_EMAIL_RECIPIENT", "")
            if not recipient:
                return

            subject = f"[Cloud IDS] {alert.severity.upper()} — {alert.threat_type.replace('_',' ').title()}"
            body = (
                f"Threat Type : {alert.threat_type}\n"
                f"Source IP   : {alert.source_ip}\n"
                f"Severity    : {alert.severity.upper()}\n"
                f"Time        : {alert.time_detected.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
                f"Details:\n{alert.message}\n\n"
                f"Log in to your Cloud IDS dashboard to review and acknowledge this alert."
            )
            msg = Message(subject=subject, recipients=[recipient], body=body)
            mail.send(msg)
            alert.email_sent = True
            from database.db import db
            db.session.commit()
            logger.info("Alert email sent to %s", recipient)
        except Exception as exc:
            logger.warning("Alert email failed: %s", exc)
