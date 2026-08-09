"""
detection/engine.py - DetectionEngine
======================================
Coordinates all threat detectors. Receives a parsed packet dict from
the PacketAnalyzer and runs it through every enabled rule.

Architecture:
  DetectionEngine
    ├── RuleManager          loads active rules from DB
    ├── ThreatClassifier     maps rule_type → severity
    └── Individual detectors (one per threat type)
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class DetectionEngine:
    """
    Main orchestrator. Runs every enabled detection rule against
    each incoming packet dict.
    """

    def __init__(self, app):
        self.app = app
        self.rule_manager   = RuleManager(app)
        self.classifier     = ThreatClassifier()

        # Map rule_type → detector instance
        self._detectors = {
            "port_scan":     PortScanDetector(app),
            "brute_force":   BruteForceDetector(app),
            "ddos":          DDoSDetector(app),
            "suspicious_ip": SuspiciousIPDetector(app),
            "traffic_spike": TrafficSpikeDetector(app),
        }

    def analyze(self, packet: dict) -> None:
        """
        Run all enabled detectors against a parsed packet.

        Args:
            packet: dict from PacketAnalyzer._parse_packet()
        """
        rules = self.rule_manager.get_enabled()
        for rule in rules:
            detector = self._detectors.get(rule["rule_type"])
            if detector:
                try:
                    detector.inspect(packet, rule)
                except Exception as exc:
                    logger.error("Detector %s error: %s", rule["rule_type"], exc)


# ==============================================================================
# RULE MANAGER
# ==============================================================================
class RuleManager:
    """Loads active detection rules from the database."""

    def __init__(self, app):
        self.app = app

    def get_enabled(self) -> list:
        """Return list of enabled rule dicts from DB."""
        try:
            with self.app.app_context():
                from models.detection_rule import DetectionRule
                rules = DetectionRule.query.filter_by(enabled=True).all()
                return [
                    {
                        "id":        r.id,
                        "rule_type": r.rule_type,
                        "threshold": r.threshold,
                        "window":    r.window,
                        "severity":  r.severity,
                    }
                    for r in rules
                ]
        except Exception as exc:
            logger.error("RuleManager error: %s", exc)
            return []


# ==============================================================================
# THREAT CLASSIFIER
# ==============================================================================
class ThreatClassifier:
    """Maps rule_type to a human-readable label and default severity."""

    LABELS = {
        "port_scan":     "Port Scan Detected",
        "brute_force":   "Brute Force Attack",
        "ddos":          "DDoS Attack",
        "suspicious_ip": "Suspicious IP Activity",
        "traffic_spike": "Traffic Spike Detected",
    }

    def label(self, rule_type: str) -> str:
        return self.LABELS.get(rule_type, rule_type.replace("_", " ").title())

    def message(self, rule_type: str, source_ip: str, count: int, window: int) -> str:
        if rule_type == "port_scan":
            return f"Port scan from {source_ip}: {count} unique ports in {window}s."
        if rule_type == "brute_force":
            return f"Brute force from {source_ip}: {count} attempts in {window}s."
        if rule_type == "ddos":
            return f"DDoS flood from {source_ip}: {count} packets in {window}s."
        if rule_type == "suspicious_ip":
            return f"Traffic from blacklisted IP: {source_ip}."
        if rule_type == "traffic_spike":
            return f"Traffic spike detected: {count}x above baseline from {source_ip}."
        return f"Threat detected from {source_ip}: {count} events."


# ==============================================================================
# BASE DETECTOR
# ==============================================================================
class BaseDetector:
    """
    Common logic shared by all detectors.
    Uses an in-memory sliding window (dict of ip → list[timestamp]) to
    count events per source IP within a rolling time window.
    """

    def __init__(self, app):
        self.app = app
        self._windows: dict = {}   # ip → list of UTC timestamps
        self._classifier = ThreatClassifier()

    def inspect(self, packet: dict, rule: dict) -> None:
        """Override in subclass."""
        raise NotImplementedError

    def _record(self, ip: str, window_secs: int, timestamp: datetime) -> int:
        """
        Record an event for ip, evict events older than window_secs,
        and return the current count within the window.
        """
        now = timestamp or datetime.now(timezone.utc)
        if ip not in self._windows:
            self._windows[ip] = []

        # Add current event
        self._windows[ip].append(now)

        # Evict events outside the rolling window
        cutoff = now.timestamp() - window_secs
        self._windows[ip] = [
            t for t in self._windows[ip]
            if t.timestamp() >= cutoff
        ]
        return len(self._windows[ip])

    def _fire_alert(self, rule: dict, source_ip: str, count: int) -> None:
        """Create an Alert record and broadcast via SocketIO."""
        rule_type = rule["rule_type"]
        severity  = rule["severity"]
        message   = self._classifier.message(
            rule_type, source_ip, count, rule["window"]
        )
        try:
            with self.app.app_context():
                from alerts.generator import AlertGenerator
                AlertGenerator.create(
                    threat_type=rule_type,
                    source_ip=source_ip,
                    severity=severity,
                    message=message,
                )
        except Exception as exc:
            logger.error("Alert fire error: %s", exc)


# ==============================================================================
# PORT SCAN DETECTOR
# Threshold: N unique destination ports from one IP in window seconds
# ==============================================================================
class PortScanDetector(BaseDetector):
    """Detects horizontal port scans from a single source IP."""

    def __init__(self, app):
        super().__init__(app)
        self._port_windows: dict = {}   # ip → set of ports (for uniqueness)
        self._time_windows: dict  = {}   # ip → list of timestamps

    def inspect(self, packet: dict, rule: dict) -> None:
        ip      = packet.get("source_ip")
        port    = packet.get("port")
        ts      = packet.get("timestamp", datetime.now(timezone.utc))
        window  = rule["window"]
        thresh  = rule["threshold"]

        if not ip or port is None:
            return

        now = ts
        if ip not in self._time_windows:
            self._time_windows[ip]  = []
            self._port_windows[ip]  = {}

        # Store port with its timestamp
        self._port_windows[ip][port] = now
        self._time_windows[ip].append(now)

        # Evict old entries
        cutoff = now.timestamp() - window
        self._port_windows[ip] = {
            p: t for p, t in self._port_windows[ip].items()
            if t.timestamp() >= cutoff
        }

        unique_ports = len(self._port_windows[ip])
        if unique_ports >= thresh:
            self._fire_alert(rule, ip, unique_ports)
            # Reset to prevent alert storm
            self._port_windows[ip] = {}


# ==============================================================================
# BRUTE FORCE DETECTOR
# Threshold: N packets to common auth ports from one IP in window seconds
# ==============================================================================
class BruteForceDetector(BaseDetector):
    """Detects repeated connection attempts to auth-related ports."""

    AUTH_PORTS = {21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 5432, 8080}

    def inspect(self, packet: dict, rule: dict) -> None:
        ip     = packet.get("source_ip")
        port   = packet.get("port")
        ts     = packet.get("timestamp", datetime.now(timezone.utc))
        window = rule["window"]
        thresh = rule["threshold"]

        if not ip or port not in self.AUTH_PORTS:
            return

        count = self._record(ip, window, ts)
        if count >= thresh:
            self._fire_alert(rule, ip, count)
            self._windows[ip] = []   # reset after firing


# ==============================================================================
# DDOS DETECTOR
# Threshold: N packets from one IP in 1 second
# ==============================================================================
class DDoSDetector(BaseDetector):
    """Detects volumetric flood from a single source IP."""

    def inspect(self, packet: dict, rule: dict) -> None:
        ip     = packet.get("source_ip")
        ts     = packet.get("timestamp", datetime.now(timezone.utc))
        window = rule["window"]    # typically 1 second
        thresh = rule["threshold"] # typically 1000

        if not ip:
            return

        count = self._record(ip, window, ts)
        if count >= thresh:
            self._fire_alert(rule, ip, count)
            self._windows[ip] = []


# ==============================================================================
# SUSPICIOUS IP DETECTOR
# Fires on any traffic from the IP blacklist
# ==============================================================================
class SuspiciousIPDetector(BaseDetector):
    """Flags any packet from a blacklisted IP address."""

    def __init__(self, app):
        super().__init__(app)
        self._alerted: set = set()   # avoid duplicate alerts per IP

    def inspect(self, packet: dict, rule: dict) -> None:
        ip = packet.get("source_ip")
        if not ip or ip in self._alerted:
            return

        try:
            with self.app.app_context():
                blacklist = self.app.config.get("IP_BLACKLIST", [])
                if ip in blacklist:
                    self._fire_alert(rule, ip, 1)
                    self._alerted.add(ip)
        except Exception as exc:
            logger.error("SuspiciousIPDetector error: %s", exc)


# ==============================================================================
# TRAFFIC SPIKE DETECTOR
# Fires when current rate exceeds baseline × multiplier
# ==============================================================================
class TrafficSpikeDetector(BaseDetector):
    """
    Detects sudden traffic spikes by comparing current-window rate
    against a rolling baseline average.
    """

    def __init__(self, app):
        super().__init__(app)
        self._global_window: list = []   # all timestamps for baseline
        self._last_baseline: float = 0.0
        self._baseline_samples: list = []

    def inspect(self, packet: dict, rule: dict) -> None:
        ip        = packet.get("source_ip")
        ts        = packet.get("timestamp", datetime.now(timezone.utc))
        window    = rule["window"]     # rolling window seconds (60)
        multiplier = rule["threshold"] # spike multiplier (3)

        now = ts
        self._global_window.append(now)

        # Keep only last window*2 seconds
        cutoff = now.timestamp() - (window * 2)
        self._global_window = [
            t for t in self._global_window if t.timestamp() >= cutoff
        ]

        # Current rate = packets in last `window` seconds
        recent_cutoff = now.timestamp() - window
        current_count = sum(
            1 for t in self._global_window
            if t.timestamp() >= recent_cutoff
        )

        # Baseline = packets in the window before that
        baseline_count = len(self._global_window) - current_count
        if baseline_count < 10:
            return  # not enough history yet

        if current_count >= baseline_count * multiplier:
            self._fire_alert(rule, ip or "multiple", current_count)
            # Reset to prevent alert storm
            self._global_window = []
