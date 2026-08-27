"""
detection/engine.py - DetectionEngine
======================================
Analyses parsed packet dicts and fires alerts when thresholds are exceeded.

This merge keeps the local app-context discipline and the contributor's
cached rule manager and suspicious-IP improvements.
"""

import logging
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

RULE_CACHE_TTL = 30.0


class DetectionEngine:
    """Runs every enabled detection rule against a single parsed packet dict."""

    def __init__(self, app):
        self.app = app
        self.rule_manager = RuleManager(app)
        self.classifier = ThreatClassifier()
        self._rules_cache: list = []
        self._cache_ts: float = 0.0
        self._CACHE_TTL: float = RULE_CACHE_TTL
        self._detectors = {
            "port_scan": PortScanDetector(app),
            "brute_force": BruteForceDetector(app),
            "ddos": DDoSDetector(app),
            "suspicious_ip": SuspiciousIPDetector(app),
            "traffic_spike": TrafficSpikeDetector(app),
        }

    def analyze(self, packet: dict) -> None:
        """Run all enabled detectors for a parsed packet while app context is active."""
        now = datetime.now(timezone.utc).timestamp()

        if now - self._cache_ts > self._CACHE_TTL:
            self._rules_cache = self.rule_manager.get_enabled()
            self._cache_ts = now
            logger.debug("Detection rules refreshed: %d active", len(self._rules_cache))

        for rule in self._rules_cache:
            detector = self._detectors.get(rule["rule_type"])
            if not detector:
                continue
            try:
                detector.inspect(packet, rule)
            except Exception as exc:
                logger.error(
                    "Detector %s raised an error: %s",
                    rule["rule_type"],
                    exc,
                    exc_info=True,
                )


class RuleManager:
    """Loads enabled detection rules from the database with a short cache."""

    def __init__(self, app):
        self.app = app
        self._cache: list = []
        self._cache_expires_at: float = 0.0
        self._lock = threading.Lock()

    def get_enabled(self) -> list:
        """Return enabled rule dicts from the DB, using the cache when fresh."""
        now = datetime.now(timezone.utc).timestamp()
        with self._lock:
            if self._cache and now < self._cache_expires_at:
                return self._cache

            try:
                from models.detection_rule import DetectionRule
                rules = DetectionRule.query.filter_by(enabled=True).all()
                self._cache = [
                    {
                        "id": r.id,
                        "rule_type": r.rule_type,
                        "threshold": r.threshold,
                        "window": r.window,
                        "severity": r.severity,
                    }
                    for r in rules
                ]
                self._cache_expires_at = now + RULE_CACHE_TTL
                return self._cache
            except Exception as exc:
                logger.error("RuleManager reload failed: %s", exc)
                return self._cache or []

    def invalidate(self) -> None:
        """Force the next get_enabled() call to reload from DB."""
        with self._lock:
            self._cache_expires_at = 0.0


class ThreatClassifier:
    """Maps rule_type to display labels and alert message strings."""

    LABELS = {
        "port_scan": "Port Scan Detected",
        "brute_force": "Brute Force Attack",
        "ddos": "DDoS Attack",
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


class BaseDetector:
    """Shared sliding-window bookkeeping used by all detectors."""

    def __init__(self, app):
        self.app = app
        self._windows: dict = {}
        self._classifier = ThreatClassifier()

    def inspect(self, packet: dict, rule: dict) -> None:  # pragma: no cover
        raise NotImplementedError

    def _record(self, ip: str, window_secs: int, ts: datetime) -> int:
        """Append ts, evict stale timestamps, and return the count in the window."""
        if ip not in self._windows:
            self._windows[ip] = []
        self._windows[ip].append(ts)

        cutoff = ts.timestamp() - window_secs
        self._windows[ip] = [t for t in self._windows[ip] if t.timestamp() >= cutoff]
        return len(self._windows[ip])

    def _fire_alert(self, rule: dict, source_ip: str, count: int) -> None:
        """Create an alert while the caller already owns the active app context."""
        rule_type = rule["rule_type"]
        severity = rule["severity"]
        message = self._classifier.message(rule_type, source_ip, count, rule["window"])

        logger.debug("_fire_alert: %s from %s (count=%d)", rule_type, source_ip, count)
        try:
            from alerts.generator import AlertGenerator
            AlertGenerator.create(
                threat_type=rule_type,
                source_ip=source_ip,
                severity=severity,
                message=message,
            )
        except Exception as exc:
            logger.error("_fire_alert failed for %s: %s", rule_type, exc, exc_info=True)


class PortScanDetector(BaseDetector):
    """Detects horizontal port scans."""

    def __init__(self, app):
        super().__init__(app)
        self._port_windows: dict = {}

    def inspect(self, packet: dict, rule: dict) -> None:
        ip = packet.get("source_ip")
        port = packet.get("port")
        ts = packet.get("timestamp") or datetime.now(timezone.utc)
        window = rule["window"]
        thresh = rule["threshold"]

        if not ip or port is None:
            return

        ports = self._port_windows.setdefault(ip, {})
        ports[port] = ts

        cutoff = ts.timestamp() - window
        self._port_windows[ip] = {p: t for p, t in ports.items() if t.timestamp() >= cutoff}

        unique_ports = len(self._port_windows[ip])
        if unique_ports >= thresh:
            self._fire_alert(rule, ip, unique_ports)
            self._port_windows[ip] = {}


class BruteForceDetector(BaseDetector):
    """Detects repeated connection attempts to common auth ports."""

    AUTH_PORTS = {21, 22, 23, 25, 110, 143, 389, 445, 3306, 3389, 5432, 8080}

    def inspect(self, packet: dict, rule: dict) -> None:
        ip = packet.get("source_ip")
        port = packet.get("port")
        ts = packet.get("timestamp") or datetime.now(timezone.utc)
        window = rule["window"]
        thresh = rule["threshold"]

        if not ip or port not in self.AUTH_PORTS:
            return

        count = self._record(ip, window, ts)
        logger.debug("BruteForce %s port %d: %d hits (threshold %d)", ip, port, count, thresh)

        if count >= thresh:
            self._fire_alert(rule, ip, count)
            self._windows[ip] = []


class DDoSDetector(BaseDetector):
    """Detects high-volume packet floods from a single source."""

    def inspect(self, packet: dict, rule: dict) -> None:
        ip = packet.get("source_ip")
        ts = packet.get("timestamp") or datetime.now(timezone.utc)
        window = rule["window"]
        thresh = rule["threshold"]

        if not ip:
            return

        count = self._record(ip, window, ts)
        logger.debug("DDoS %s: %d packets (threshold %d)", ip, count, thresh)

        if count >= thresh:
            self._fire_alert(rule, ip, count)
            self._windows[ip] = []


class SuspiciousIPDetector(BaseDetector):
    """Flags any traffic from a blacklisted source IP."""

    def __init__(self, app):
        super().__init__(app)
        self._alerted: set = set()

    def inspect(self, packet: dict, rule: dict) -> None:
        ip = packet.get("source_ip")
        if not ip or ip in self._alerted:
            return

        blacklist = self.app.config.get("IP_BLACKLIST", [])
        if ip in blacklist:
            logger.info("Suspicious IP detected: %s", ip)
            self._fire_alert(rule, ip, 1)
            self._alerted.add(ip)


class TrafficSpikeDetector(BaseDetector):
    """Detects sudden traffic volume spikes vs a rolling baseline."""

    def __init__(self, app):
        super().__init__(app)
        self._global_window: list = []

    def inspect(self, packet: dict, rule: dict) -> None:
        ip = packet.get("source_ip")
        ts = packet.get("timestamp") or datetime.now(timezone.utc)
        window = rule["window"]
        multiplier = rule["threshold"]

        self._global_window.append(ts)
        cutoff = ts.timestamp() - (window * 2)
        self._global_window = [t for t in self._global_window if t.timestamp() >= cutoff]

        recent_cutoff = ts.timestamp() - window
        current_count = sum(1 for t in self._global_window if t.timestamp() >= recent_cutoff)
        baseline_count = len(self._global_window) - current_count

        if baseline_count < 10:
            return

        if current_count >= baseline_count * multiplier:
            source_ip = ip or "multiple"
            logger.info(
                "Traffic spike: %d packets vs baseline %d (%.1fx)",
                current_count,
                baseline_count,
                current_count / max(baseline_count, 1),
            )
            self._fire_alert(rule, source_ip, current_count)
            self._global_window = []
