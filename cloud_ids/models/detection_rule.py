"""
models/detection_rule.py - Detection Rule Model
================================================
Stores configurable thresholds and rules for the Detection Engine.
Administrators can enable, disable, or tune rules from the dashboard
without restarting the application.

Fields:
  id          - Primary key
  rule_name   - Human-readable name (e.g. "Port Scan Detection")
  rule_type   - Internal type key matching DetectionEngine handlers
  description - What the rule detects
  threshold   - Numeric trigger value (e.g. 20 unique ports)
  window      - Time window in seconds the threshold applies to
  enabled     - Whether the rule is actively enforced
  severity    - Default severity of alerts raised by this rule
  created_at  - Auto timestamp (TimestampMixin)
  updated_at  - Auto timestamp (TimestampMixin)
"""

from database.db import BaseModel, TimestampMixin, db


class DetectionRule(TimestampMixin, BaseModel):
    """
    A configurable detection rule used by the Detection Engine.

    Rules are seeded during database initialisation and can be
    modified at runtime by administrators.
    """

    __tablename__ = "detection_rules"

    # ------------------------------------------------------------------
    # Rule type constants — must match DetectionEngine handler keys
    # ------------------------------------------------------------------
    RULE_PORT_SCAN = "port_scan"
    RULE_BRUTE_FORCE = "brute_force"
    RULE_DDOS = "ddos"
    RULE_SUSPICIOUS_IP = "suspicious_ip"
    RULE_TRAFFIC_SPIKE = "traffic_spike"

    # ------------------------------------------------------------------
    # Columns
    # ------------------------------------------------------------------
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    rule_name = db.Column(
        db.String(100),
        unique=True,
        nullable=False,
        comment="Human-readable rule name shown in the dashboard",
    )
    rule_type = db.Column(
        db.String(30),
        nullable=False,
        comment="Internal key used by the DetectionEngine to select the handler",
    )
    description = db.Column(
        db.Text,
        nullable=True,
        comment="Explains what traffic pattern this rule detects",
    )
    threshold = db.Column(
        db.Integer,
        nullable=False,
        default=10,
        comment="Number of events that trigger the rule (e.g. 20 port hits)",
    )
    window = db.Column(
        db.Integer,
        nullable=False,
        default=60,
        comment="Rolling time window in seconds the threshold applies to",
    )
    enabled = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
        comment="False = rule is disabled and will not fire alerts",
    )
    severity = db.Column(
        db.String(10),
        nullable=False,
        default="medium",
        comment="Default severity for alerts raised by this rule",
    )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def toggle(self) -> bool:
        """
        Flip the enabled state of the rule.

        Returns:
            bool: New enabled state after toggling.
        """
        self.enabled = not self.enabled
        self.save()
        return self.enabled

    @classmethod
    def get_enabled_rules(cls) -> list:
        """Return all currently enabled detection rules."""
        return cls.query.filter_by(enabled=True).all()

    @classmethod
    def get_by_type(cls, rule_type: str) -> "DetectionRule | None":
        """
        Fetch the rule for a given rule type.

        Args:
            rule_type: One of the RULE_* constants.

        Returns:
            DetectionRule instance or None.
        """
        return cls.query.filter_by(rule_type=rule_type).first()

    @classmethod
    def seed_default_rules(cls) -> None:
        """
        Insert the default detection rules if the table is empty.
        Called from database/db.py → init_db().
        """
        if cls.query.count() > 0:
            return  # Already seeded

        defaults = [
            {
                "rule_name": "Port Scan Detection",
                "rule_type": cls.RULE_PORT_SCAN,
                "description": "Alerts when a single source IP targets ≥20 unique ports within 10 seconds.",
                "threshold": 20,
                "window": 10,
                "severity": "high",
            },
            {
                "rule_name": "Brute Force Detection",
                "rule_type": cls.RULE_BRUTE_FORCE,
                "description": "Alerts after 5 failed authentication attempts from a single IP within 60 seconds.",
                "threshold": 5,
                "window": 60,
                "severity": "high",
            },
            {
                "rule_name": "DDoS Detection",
                "rule_type": cls.RULE_DDOS,
                "description": "Alerts when traffic from a single source exceeds 1000 packets per second.",
                "threshold": 1000,
                "window": 1,
                "severity": "critical",
            },
            {
                "rule_name": "Suspicious IP Activity",
                "rule_type": cls.RULE_SUSPICIOUS_IP,
                "description": "Flags traffic from IPs on the internal blacklist.",
                "threshold": 1,
                "window": 0,
                "severity": "medium",
            },
            {
                "rule_name": "Traffic Spike Detection",
                "rule_type": cls.RULE_TRAFFIC_SPIKE,
                "description": "Alerts when overall traffic volume spikes 3× above the rolling baseline.",
                "threshold": 3,
                "window": 60,
                "severity": "medium",
            },
        ]

        for rule_data in defaults:
            rule = DetectionRule(**rule_data)
            db.session.add(rule)

        db.session.commit()
