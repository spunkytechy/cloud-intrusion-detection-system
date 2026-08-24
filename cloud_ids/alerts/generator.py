"""
alerts/generator.py - AlertGenerator
======================================
Creates Alert records, emits SocketIO events for real-time dashboard
updates, sends email notifications for critical/high alerts, and
back-writes TrafficLog.status for the offending IP so the /logs
page and its "suspicious" filter reflect reality immediately.

Design notes
------------
- We never do ``from app import ...`` here. When ``python app.py`` is the
  entry point, ``app`` is loaded as ``__main__`` and a second import
  under the name ``app`` would create duplicate extension instances.
  Instead we resolve SocketIO / Mail via ``current_app.extensions``,
  which app.py populates during startup.

- On every alert, we do three things in addition to the DB insert:
    1. Emit a ``new_alert`` SocketIO event on the /ids namespace.
    2. Register the source IP in the suspicious-IP registry so future
       TrafficLog rows from that IP are stored as 'suspicious'.
    3. Back-write existing recent TrafficLog rows from that IP to
       'suspicious' so the logs page shows the retroactive picture.
"""

import logging
from datetime import datetime, timezone, timedelta

from flask import current_app
from sqlalchemy import update

from packet_capture.state import mark_suspicious

logger = logging.getLogger(__name__)

# Prevent duplicate alerts for the same IP+type within a short window
_recent_alerts: dict = {}   # key: "type:ip" → last_fired UTC timestamp
DEDUP_SECONDS = 30          # suppress duplicate alert within 30s


class AlertGenerator:
    """Static factory — creates, saves, broadcasts, and enriches alerts."""

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    @staticmethod
    def create(threat_type: str, source_ip: str, severity: str, message: str) -> None:
        """
        Persist a new Alert, emit a SocketIO event, back-write related
        TrafficLog rows, and optionally send email.

        Args:
            threat_type : one of Alert.THREAT_* constants
            source_ip   : offending IP address
            severity    : critical | high | medium | low
            message     : human-readable description
        """
        # ---------- Deduplicate identical alerts ----------
        key = f"{threat_type}:{source_ip}"
        now = datetime.now(timezone.utc)
        last = _recent_alerts.get(key)
        if last and (now.timestamp() - last) < DEDUP_SECONDS:
            return
        _recent_alerts[key] = now.timestamp()

        # ---------- Persist the alert ----------
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
            logger.info(
                "Alert created [%s] %s — %s",
                severity.upper(), threat_type, source_ip,
            )
        except Exception as exc:
            logger.error("AlertGenerator DB insert failed: %s", exc, exc_info=True)
            try:
                from database.db import db
                db.session.rollback()
            except Exception:
                pass
            return

        # ---------- Register IP for future packet tagging ----------
        try:
            ttl = int(current_app.config.get("SUSPICIOUS_IP_TTL_SECONDS", 300))
        except Exception:
            ttl = 300
        mark_suspicious(source_ip, ttl_seconds=ttl)

        # ---------- Back-write recent TrafficLog rows ----------
        AlertGenerator._backfill_traffic_status(source_ip)

        # ---------- Broadcast to dashboard clients ----------
        AlertGenerator._emit(alert)

        # ---------- Email for high/critical ----------
        if severity in ("critical", "high"):
            AlertGenerator._send_email(alert)

    # ------------------------------------------------------------------
    # Back-write recent traffic logs so the /logs page reflects the
    # newly-discovered threat immediately.
    # ------------------------------------------------------------------
    @staticmethod
    def _backfill_traffic_status(source_ip: str) -> None:
        """
        UPDATE traffic_logs SET status='suspicious'
        WHERE source_ip = :ip
          AND status    = 'normal'
          AND timestamp >= now() - :window

        Bounded to a single UPDATE statement so it stays fast even
        under heavy insert pressure.
        """
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
                    result.rowcount, source_ip,
                )
        except Exception as exc:
            logger.warning("TrafficLog back-write failed for %s: %s", source_ip, exc)
            try:
                from database.db import db
                db.session.rollback()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # SocketIO broadcast
    # ------------------------------------------------------------------
    @staticmethod
    def _emit(alert) -> None:
        """Push a real-time SocketIO event to all connected clients."""
        try:
            socketio = current_app.extensions.get("socketio")
            if socketio is None:
                logger.debug("SocketIO extension not registered; skipping emit.")
                return
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

    # ------------------------------------------------------------------
    # Email notification (best effort — never blocks alert flow)
    # ------------------------------------------------------------------
    @staticmethod
    def _send_email(alert) -> None:
        """Send an email notification for high/critical alerts."""
        try:
            recipient = current_app.config.get("ALERT_EMAIL_RECIPIENT", "") or ""
            username  = current_app.config.get("MAIL_USERNAME", "") or ""
            password  = current_app.config.get("MAIL_PASSWORD", "") or ""
            server    = current_app.config.get("MAIL_SERVER", "") or ""
            port      = current_app.config.get("MAIL_PORT")

            # Silently skip when mail isn't fully configured (common in dev).
            # Placeholders from .env.example also count as "not configured".
            placeholders = {"", "CHANGE_ME"}
            if (recipient in placeholders or username in placeholders
                    or password in placeholders or server in placeholders
                    or not isinstance(port, int) or port <= 0):
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
                f"Log in to your Cloud IDS dashboard to review and "
                f"acknowledge this alert."
            )
            msg = Message(subject=subject, recipients=[recipient], body=body)
            mail.send(msg)

            # Mark the alert as emailed
            alert.email_sent = True
            from database.db import db
            db.session.commit()
            logger.info("Alert email sent to %s", recipient)
        except Exception as exc:
            logger.warning("Alert email failed: %s", exc)
