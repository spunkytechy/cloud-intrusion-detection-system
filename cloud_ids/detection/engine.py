"""
detection/engine.py - DetectionEngine
======================================
Coordinates all threat detectors. Receives a parsed packet dict from
the PacketAnalyzer and runs it through every enabled rule.

Architecture
------------
  DetectionEngine
    ├── RuleManager          loads active rules from DB (cached 30s)
    ├── ThreatClassifier     maps rule_type → severity + label + message
    └── Individual detectors one per threat type

Perf note
---------
`analyze()` is called once per captured packet, so anything expensive
must be cached or amortised:

* RuleManager caches the enabled-rules list for RULE_CACHE_TTL seconds
  (default 30) — rules almost never change at runtime.
* We open a single ``with app.app_context()`` here, at the top of
  analyze(), so no detector needs to open its own context per packet.
"""

import logging
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

RULE_CACHE_TTL = 30.0   # seconds


class DetectionEngine:
    """Main orchestrator. Runs every enabled detector against each packet."""

    def __init__(self, app):
        self.app = app
        self.rule_manager = RuleManager(app)
        self.classifier   = ThreatClassifier()

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
        Run every enabled detector against a parsed packet.

        A single app context is opened here so detectors and
        AlertGenerator can hit the DB / config without each
        opening their own context per packet.

        Args:
            packet: dict from PacketAnalyzer._parse_packet()
        """
        try:
            with self.app.app_context():
                rules = self.rule_manager.get_enabled()
                for rule in rules:
                    detector = self._detectors.get(rule["rule_type"])
                    if not detector:
                        continue
                    try:
                        detector.inspect(packet, rule)
                    except Exception as exc:
                        logger.error(
                            "Detector %s error: %s", rule["rule_type"], exc,
                        )
        except Exception as exc:
            logger.error("DetectionEngine.analyze error: %s", exc)


# ==============================================================================
# RULE MANAGER (cached)
# ==============================================================================
class RuleManager:
    """
    Loads active detection rules from the database, cached for
    RULE_CACHE_TTL seconds to avoid a DB round-trip per packet.

    Callers must invoke get_enabled() from inside an application context.
    invalidate() can be called to force a reload (e.g. from an admin
    action that toggles a rule).
    """

    def __init__(self, app):
        self.app = app
        self._cache: list = []
        self._cache_expires_at: float = 0.0
        self._lock = threading.Lock()

    def get_enabled(self) -> list:
        """Return list of enabled rule dicts (cached)."""
        now = datetime.now(timezone.utc).timestamp()
        with self._lock:
            if self._cache and now < self._cache_expires_at:
                return self._cache

            try:
                from models.detection_rule import DetectionRule
                rules = DetectionRule.query.filter_by(enabled=True).all()
                self._cache = [
                    {
                        "id":        r.id,
                        "rule_type": r.rule_type,
                        "threshold": r.threshold,
                        "window":    r.window,
                        "severity":  r.severity,
                    }
                    for r in rules
                ]
                self._cache_expires_at = now + RULE_CACHE_TTL
                return self._cache
            except Exception as exc:
                logger.error("RuleManager reload failed: %s", exc)
                # Serve stale cache if we have one, else empty
                return self._cache or []

    def invalidate(self) -> None:
        """Force the next get_enabled() call to reload from DB."""
        with self._lock:
            self._cache_expires_at = 0.0


# ==============================================================================
# THREAT CLASSIFIER
# ==============================================================================
class ThreatClassifier:
    """Maps rule_type to a human-readable label and default message."""

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
            return (
                f"Traffic spike detected: {count}× above baseline from {source_ip}."
            )
        return f"Threat detected from {source_ip}: {count} events."


# ==============================================================================
# BASE DETECTOR
# ==============================================================================
class BaseDetector:
    """
    Common sliding-window bookkeeping shared by most detectors.
    Uses an in-memory dict of ip → list[UTC datetime].

    Subclasses implement inspect(packet, rule) and call _fire_alert()
    when their threshold is met.
    """

    def __init__(self, app):
        self.app = app
        self._windows: dict = {}
        self._classifier = ThreatClassifier()

    def inspect(self, packet: dict, rule: dict) -> None:  # pragma: no cover
        raise NotImplementedError

    def _record(self, ip: str, window_secs: int, timestamp: datetime) -> int:
        """Record an event, evict old ones, return current count in window."""
        now = timestamp or datetime.now(timezone.utc)
        bucket = self._windows.setdefault(ip, [])
        bucket.append(now)
        cutoff = now.timestamp() - window_secs
        self._windows[ip] = [t for t in bucket if t.timestamp() >= cutoff]
        return len(self._windows[ip])

    def _fire_alert(self, rule: dict, source_ip: str, count: int) -> None:
        """
        Create an Alert record and broadcast via SocketIO.

        The caller (DetectionEngine.analyze) already holds an
        application context, so AlertGenerator can commit directly.
        """
        rule_type = rule["rule_type"]
        severity  = rule["severity"]
        message   = self._classifier.message(
            rule_type, source_ip, count, rule["window"],
        )
        try:
            from alerts.generator import AlertGenerator
            AlertGenerator.create(
                threat_type = rule_type,
                source_ip   = source_ip,
                severity    = severity,
                message     = message,
            )
        except Exception as exc:
            logger.error("Alert fire error: %s", exc, exc_info=True)


# ==============================================================================
# PORT SCAN DETECTOR
# ==============================================================================
class PortScanDetector(BaseDetector):
    """Detects horizontal port scans from a single source IP."""

    def __init__(self, app):
        super().__init__(app)
        self._port_windows: dict = {}   # ip → {port: last_seen_ts}

    def inspect(self, packet: dict, rule: dict) -> None:
        ip     = packet.get("source_ip")
        port   = packet.get("port")
        ts     = packet.get("timestamp", datetime.now(timezone.utc))
        window = rule["window"]
        thresh = rule["threshold"]

        if not ip or port is None:
            return

        ports = self._port_windows.setdefault(ip, {})
        ports[port] = ts

        cutoff = ts.timestamp() - window
        # Evict old ports
        self._port_windows[ip] = {p: t for p, t in ports.items()
                                  if t.timestamp() >= cutoff}

        unique_ports = len(self._port_windows[ip])
        if unique_ports >= thresh:
            self._fire_alert(rule, ip, unique_ports)
            self._port_windows[ip] = {}   # reset to prevent alert storm


# ==============================================================================
# BRUTE FORCE DETECTOR
# ==============================================================================
class BruteForceDetector(BaseDetector):
    """Detects repeated connection attempts to common auth ports."""

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
            self._windows[ip] = []


# ==============================================================================
# DDOS DETECTOR
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
# ==============================================================================
class SuspiciousIPDetector(BaseDetector):
    """Flags any packet from a blacklisted IP address."""

    def __init__(self, app):
        super().__init__(app)
        self._alerted: set = set()   # IPs already alerted on

    def inspect(self, packet: dict, rule: dict) -> None:
        ip = packet.get("source_ip")
        if not ip or ip in self._alerted:
            return

        # self.app.config points to the same dict Flask uses, so it
        # reflects live edits from /dashboard/settings — no extra
        # app_context needed since analyze() already opened one.
        blacklist = self.app.config.get("IP_BLACKLIST", [])
        if ip in blacklist:
            self._fire_alert(rule, ip, 1)
            self._alerted.add(ip)


# ==============================================================================
# TRAFFIC SPIKE DETECTOR
# ==============================================================================
class TrafficSpikeDetector(BaseDetector):
    """Detects sudden traffic spikes vs a rolling baseline."""

    def __init__(self, app):
        super().__init__(app)
        self._global_window: list = []

    def inspect(self, packet: dict, rule: dict) -> None:
        ip         = packet.get("source_ip")
        ts         = packet.get("timestamp", datetime.now(timezone.utc))
        window     = rule["window"]     # rolling window seconds (60)
        multiplier = rule["threshold"]  # spike multiplier (3)

        self._global_window.append(ts)

        # Keep the last 2× window seconds
        cutoff = ts.timestamp() - (window * 2)
        self._global_window = [t for t in self._global_window
                               if t.timestamp() >= cutoff]

        recent_cutoff = ts.timestamp() - window
        current_count = sum(1 for t in self._global_window
                            if t.timestamp() >= recent_cutoff)
        baseline_count = len(self._global_window) - current_count

        # Require a real baseline before spiking
        if baseline_count < 10:
            return

        if current_count >= baseline_count * multiplier:
            self._fire_alert(rule, ip or "multiple", current_count)
            self._global_window = []
