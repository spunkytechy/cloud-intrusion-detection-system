"""
database/seed.py - Database Seeder
====================================
Populates the database with:
  1. Default detection rules (5 rules matching the detection engine)
  2. Admin user account (credentials from .env)

Safe to run multiple times — uses "upsert" logic to avoid duplicates.
Called automatically by init_db() on first application start.
Can also be run manually:

    python -c "from database.seed import run_seed; from app import create_app; app=create_app()
    with app.app_context(): run_seed(app)"
"""

import logging

from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)


def run_seed(app) -> None:
    """
    Master seeder — runs all individual seed functions in the correct order.

    Args:
        app: Active Flask application instance (provides config + app context).
    """
    logger.info("Starting database seed...")
    _seed_detection_rules()
    _seed_admin_user(app)
    logger.info("Database seed complete.")


# ==============================================================================
# DETECTION RULES
# ==============================================================================
def _seed_detection_rules() -> None:
    """
    Insert the 5 default detection rules if the table is empty.

    Rules map 1-to-1 with DetectionEngine handlers.
    Administrators can update thresholds at runtime via the dashboard.
    """
    from database.db import db
    from models.detection_rule import DetectionRule

    try:
        if DetectionRule.query.count() > 0:
            logger.info("Detection rules already seeded — skipping.")
            return

        default_rules = [
            {
                "rule_name": "Port Scan Detection",
                "rule_type": DetectionRule.RULE_PORT_SCAN,
                "description": (
                    "Triggers when a single source IP contacts 20 or more "
                    "unique destination ports within a 10-second window. "
                    "Indicative of automated reconnaissance (nmap, masscan)."
                ),
                "threshold": 20,
                "window": 10,
                "severity": "high",
                "enabled": True,
            },
            {
                "rule_name": "Brute Force Detection",
                "rule_type": DetectionRule.RULE_BRUTE_FORCE,
                "description": (
                    "Triggers after 5 or more failed authentication attempts "
                    "from the same source IP within 60 seconds. "
                    "Indicative of password-guessing tools (Hydra, Medusa)."
                ),
                "threshold": 5,
                "window": 60,
                "severity": "high",
                "enabled": True,
            },
            {
                "rule_name": "DDoS Detection",
                "rule_type": DetectionRule.RULE_DDOS,
                "description": (
                    "Triggers when a single source IP sends more than 1000 "
                    "packets within a 1-second window. "
                    "Indicative of volumetric denial-of-service attacks."
                ),
                "threshold": 1000,
                "window": 1,
                "severity": "critical",
                "enabled": True,
            },
            {
                "rule_name": "Suspicious IP Activity",
                "rule_type": DetectionRule.RULE_SUSPICIOUS_IP,
                "description": (
                    "Triggers on any traffic from IPs on the internal "
                    "blacklist. Blacklist is managed via the Settings page "
                    "or the IP Blacklist API."
                ),
                "threshold": 1,
                "window": 0,
                "severity": "medium",
                "enabled": True,
            },
            {
                "rule_name": "Traffic Spike Detection",
                "rule_type": DetectionRule.RULE_TRAFFIC_SPIKE,
                "description": (
                    "Triggers when the current traffic rate is 3× or more "
                    "above the rolling 60-second baseline. "
                    "Indicative of sudden attack bursts or misconfigured hosts."
                ),
                "threshold": 3,
                "window": 60,
                "severity": "medium",
                "enabled": True,
            },
        ]

        for rule_data in default_rules:
            rule = DetectionRule(**rule_data)
            db.session.add(rule)

        db.session.commit()
        logger.info("Seeded %d default detection rules.", len(default_rules))

    except SQLAlchemyError as exc:
        db.session.rollback()
        logger.error("Failed to seed detection rules: %s", exc, exc_info=True)
        raise


# ==============================================================================
# ADMIN USER
# ==============================================================================
def _seed_admin_user(app) -> None:
    """
    Create the default admin account if no users exist.

    Credentials are read from the Flask app config (sourced from .env):
      ADMIN_USERNAME, ADMIN_EMAIL, ADMIN_PASSWORD

    Args:
        app: Active Flask application instance.
    """
    from database.db import db
    from models.user import User

    try:
        if User.query.count() > 0:
            logger.info("Users already exist — skipping admin seed.")
            return

        admin = User(
            username=app.config["ADMIN_USERNAME"],
            email=app.config["ADMIN_EMAIL"],
            role="admin",
            is_active=True,
            mfa_enabled=False,
        )
        # set_password() hashes using pbkdf2:sha256 with a random salt
        admin.set_password(app.config["ADMIN_PASSWORD"])

        db.session.add(admin)
        db.session.commit()
        logger.info(
            "Admin account created: username='%s' email='%s'",
            app.config["ADMIN_USERNAME"],
            app.config["ADMIN_EMAIL"],
        )

    except SQLAlchemyError as exc:
        db.session.rollback()
        logger.error("Failed to seed admin user: %s", exc, exc_info=True)
        raise


# ==============================================================================
# MANUAL RUN ENTRYPOINT
# python database/seed.py
# ==============================================================================
if __name__ == "__main__":
    import os
    import sys

    # Add project root to path so imports resolve
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    from app import create_app

    _app = create_app()
    with _app.app_context():
        run_seed(_app)
        print("Seed complete.")
