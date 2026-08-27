"""
alerts/generator.py - AlertGenerator
======================================
Creates Alert records, emits SocketIO events for real-time dashboard
updates, sends email notifications for critical/high alerts, and
back-writes TrafficLog.status for the offending IP so the /logs
page and the suspicious filter reflect the issue immediately.

Design notes:
  - Called from background detection threads that already hold an app
    context (via BaseDetector._fire_alert → AlertGenerator.create()).
    AlertGenerator must NOT open a second nested app_context.
  - _emit() and _send_email() are also called inside that context, so they
    resolve SocketIO/Mail from current_app.extensions instead of importing
    app.py directly, which would create duplicate extension instances.
"""

import logging
from datetime import datetime, timezone, timedelta

from flask import current_app
from sqlalchemy import update

from packet_capture.state import mark_suspicious

logger = logging.getLogger(__name__)

# Duplicate-suppression table: key = "threat_type:source_ip" -> last-fired timestamp
_recent_alerts: dict = {}
DEDUP_SECONDS = 30


class AlertGenerator:
    """Static factory — saves, broadcasts, and optionally emails alerts."""

    @staticmethod
    def create(
        threat_type: str,
        source_ip: str,
        severity: str,
        message: str,
    ) -> None:
        """
        Persist a new Alert, emit a SocketIO event, back-write related
        TrafficLog rows, and optionally send email.

        Must be called while an app context is already active.
        """
        key = f"{threat_type}:{source_ip}"
        now = datetime.now(timezone.utc)
        last = _recent_alerts.get(key)
        if last and (now.timestamp() - last) < DEDUP_SECONDS:
            logger.debug("Alert suppressed (dedup): %s", key)
            return
        _recent_alerts[key] = now.timestamp()

        try:
            from database.db import db
            from models.alert import Alert

            alert = Alert(
                threat_type=threat_type,
                source_ip=source_ip,
                severity=severity,
                message=message,
                time_detected=now,
            )
            db.session.add(alert)
            db.session.commit()
            logger.info(
                "Alert created [%s] %s from %s — %s",
                severity.upper(),
                threat_type,
                source_ip,
                message,
            )
        except Exception as exc:
            logger.error("AlertGenerator DB insert failed: %s", exc, exc_info=True)
            try:
                from database.db import db
                db.session.rollback()
            except Exception:
                pass
            return

        try:
            ttl = int(current_app.config.get("SUSPICIOUS_IP_TTL_SECONDS", 300))
        except Exception:
            ttl = 300
        mark_suspicious(source_ip, ttl_seconds=ttl)
        AlertGenerator._backfill_traffic_status(source_ip)
        AlertGenerator._emit(alert)

        if severity in ("critical", "high"):
            AlertGenerator._send_email(alert)

    @staticmethod
    def _backfill_traffic_status(source_ip: str) -> None:
        """Mark recent rows from the offending IP as suspicious."""
        try:
            from database.db import db
            from models.traffic_log import TrafficLog

            window = int(
                current_app.config.get("SUSPICIOUS_BACKFILL_WINDOW_SECONDS", 300)
            )
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=window)

            stmt = (
                update(TrafficLog)
                .where(TrafficLog.source_ip == source_ip)
                .where(TrafficLog.status == TrafficLog.STATUS_NORMAL)
                .where(TrafficLog.timestamp >= cutoff)
                .values(status=TrafficLog.STATUS_SUSPICIOUS)
            )
            result = db.session.execute(stmt)
            db.session.commit()
            if result.rowcount:
                logger.info(
                    "Back-wrote %d TrafficLog rows to suspicious for %s.",
                    result.rowcount,
                    source_ip,
                )
        except Exception as exc:
            logger.warning("TrafficLog back-write failed for %s: %s", source_ip, exc)
            try:
                from database.db import db
                db.session.rollback()
            except Exception:
                pass

    @staticmethod
    def _emit(alert) -> None:
        """Emit a 'new_alert' event to all connected /ids clients."""
        try:
            socketio = current_app.extensions.get("socketio")
            if socketio is None:
                logger.debug("SocketIO extension not registered; skipping emit.")
                return
            payload = {
                "alert_id": alert.alert_id,
                "threat_type": alert.threat_type,
                "source_ip": alert.source_ip,
                "severity": alert.severity,
                "message": alert.message,
                "time": alert.time_detected.isoformat(),
            }
            socketio.emit("new_alert", payload, namespace="/ids")
            logger.debug("SocketIO new_alert emitted for alert %s", alert.alert_id)
        except Exception as exc:
            logger.warning("SocketIO emit failed: %s", exc)

    @staticmethod
    def _send_email(alert) -> None:
        """Send an SMTP email for critical/high alerts when configured."""
        try:
            recipient = (current_app.config.get("ALERT_EMAIL_RECIPIENT", "") or "").strip()
            username = (current_app.config.get("MAIL_USERNAME", "") or "").strip()
            password = (current_app.config.get("MAIL_PASSWORD", "") or "").strip()
            server = (current_app.config.get("MAIL_SERVER", "") or "").strip()
            port = current_app.config.get("MAIL_PORT")

            placeholders = {"", "CHANGE_ME"}
            if (
                recipient in placeholders
                or username in placeholders
                or password in placeholders
                or server in placeholders
                or not isinstance(port, int)
                or port <= 0
            ):
                logger.debug("Email skipped — mail configuration is incomplete.")
                return

            mail = current_app.extensions.get("mail")
            if mail is None:
                logger.debug("Mail extension not registered; skipping email.")
                return

            from flask_mail import Message

            subject = (
                f"[Cloud IDS] {alert.severity.upper()} — "
                f"{alert.threat_type.replace('_', ' ').title()}"
            )
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

            from database.db import db
            alert.email_sent = True
            db.session.commit()
            logger.info("Alert email sent to %s for alert %s", recipient, alert.alert_id)
        except Exception as exc:
            logger.warning("Alert email failed: %s", exc)
