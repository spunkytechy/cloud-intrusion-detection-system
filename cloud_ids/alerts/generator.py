"""
alerts/generator.py - AlertGenerator
======================================
Creates Alert records, emits SocketIO events for real-time dashboard
updates, and sends email notifications for critical/high alerts.

Design notes:
  - Called from background detection threads that already hold an app
    context (via BaseDetector._fire_alert → with self.app.app_context()).
    AlertGenerator must NOT open a second nested app_context — SQLAlchemy
    sessions are not re-entrant; nesting contexts creates a new session
    that can't see the outer transaction and causes DetachedInstanceError.

  - _emit() and _send_email() are also called inside the same context, so
    they use flask.current_app / the module-level socketio/mail objects
    directly without re-entering a context.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── Duplicate-suppression table ───────────────────────────────────────────────
# key: "threat_type:source_ip"  →  last-fired POSIX timestamp
_recent_alerts: dict = {}
DEDUP_SECONDS   = 30        # minimum seconds between identical alerts


class AlertGenerator:
    """Static factory — saves, broadcasts, and optionally emails alerts."""

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    @staticmethod
    def create(
        threat_type: str,
        source_ip:   str,
        severity:    str,
        message:     str,
    ) -> None:
        """
        Persist a new Alert and broadcast it in real time.

        MUST be called while an app context is already active (which is
        the case when called from BaseDetector._fire_alert or from an
        HTTP request handler).

        Args:
            threat_type : e.g. "port_scan", "ddos" …
            source_ip   : attacking/suspicious source address
            severity    : "critical" | "high" | "medium" | "low"
            message     : human-readable description
        """
        # ── Deduplication ──────────────────────────────────────────
        key  = f"{threat_type}:{source_ip}"
        now  = datetime.now(timezone.utc)
        last = _recent_alerts.get(key)
        if last and (now.timestamp() - last) < DEDUP_SECONDS:
            logger.debug("Alert suppressed (dedup): %s", key)
            return
        _recent_alerts[key] = now.timestamp()

        # ── Persist ────────────────────────────────────────────────
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
                "ALERT [%s] %s from %s — %s",
                severity.upper(), threat_type, source_ip, message,
            )

            # ── Real-time broadcast ───────────────────────────────
            AlertGenerator._emit(alert)

            # ── Email for high/critical ───────────────────────────
            if severity in ("critical", "high"):
                AlertGenerator._send_email(alert)

        except Exception as exc:
            logger.error("AlertGenerator.create failed: %s", exc, exc_info=True)
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
        """
        Emit 'new_alert' event to all connected /ids namespace clients.
        Importing socketio at call-time avoids the circular-import that
        occurs at module load when alerts/generator.py is imported before
        app.py finishes initialising.
        """
        try:
            from app import socketio
            socketio.emit(
                "new_alert",
                {
                    "alert_id":    alert.alert_id,
                    "threat_type": alert.threat_type,
                    "source_ip":   alert.source_ip,
                    "severity":    alert.severity,
                    "message":     alert.message,
                    "time":        alert.time_detected.isoformat(),
                },
                namespace="/ids",
            )
            logger.debug("SocketIO new_alert emitted for alert %s", alert.alert_id)
        except Exception as exc:
            logger.warning("SocketIO emit failed: %s", exc)

    # ------------------------------------------------------------------
    # Email notification
    # ------------------------------------------------------------------
    @staticmethod
    def _send_email(alert) -> None:
        """
        Send an SMTP email for critical/high alerts.
        Silently skips if MAIL_USERNAME or ALERT_EMAIL_RECIPIENT are
        not configured in .env.
        """
        try:
            from flask import current_app
            from flask_mail import Message
            from app import mail

            recipient = current_app.config.get("ALERT_EMAIL_RECIPIENT", "").strip()
            sender    = current_app.config.get("MAIL_USERNAME", "").strip()

            if not recipient or not sender:
                logger.debug(
                    "Email skipped — ALERT_EMAIL_RECIPIENT or MAIL_USERNAME not set."
                )
                return

            subject = (
                f"[Cloud IDS] {alert.severity.upper()} — "
                f"{alert.threat_type.replace('_', ' ').title()}"
            )
            body = (
                f"Threat Type : {alert.threat_type}\n"
                f"Source IP   : {alert.source_ip}\n"
                f"Severity    : {alert.severity.upper()}\n"
                f"Time        : {alert.time_detected.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                f"\nDetails:\n{alert.message}\n\n"
                f"Log in to your Cloud IDS dashboard to review this alert."
            )
            msg = Message(subject=subject, recipients=[recipient], body=body)
            mail.send(msg)

            # Mark email as sent
            from database.db import db
            alert.email_sent = True
            db.session.commit()

            logger.info("Alert email sent to %s for alert %s", recipient, alert.alert_id)

        except Exception as exc:
            logger.warning("Alert email failed: %s", exc)
