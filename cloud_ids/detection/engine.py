"""
detection/engine.py - DetectionEngine
======================================
Analyses parsed packet dicts and fires alerts when thresholds are exceeded.

IMPORTANT — app context contract:
  Every public method here is called from PacketAnalyzer._process_loop(),
  which already runs inside `with app.app_context()`.  Therefore NO method
  in this file should open a second app_context — doing so creates a new
  SQLAlchemy session that is isolated from the outer one and causes
  DetachedInstanceError / silent data loss.

  The only place an app_context is opened is PacketAnalyzer._process_loop.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# ==============================================================================
# DETECTION ENGINE — orchestrator
# ==============================================================================
class DetectionEngine:
    """
    Runs every enabled detection rule against a single parsed packet dict.
    Instantiated once by PacketAnalyzer and reused for the lifetime of the
    analyzer thread.
    """

    def __init__(self, app):
        self.app = app
        # Cache rules for 30 s to avoid a DB round-trip per packet
        self._rules_cache: list = []
        self._cache_ts: float   = 0.0
        self._CACHE_TTL: float  = 30.0   # seconds

        self._detectors = {
            "port_scan":     PortScanDetector(app),
            "brute_force":   BruteForceDetector(app),
            "ddos":          DDoSDetector(app),
            "suspicious_ip": SuspiciousIPDetector(app),
            "traffic_spike": TrafficSpikeDetector(app),
        }

    def analyze(self, packet: dict) -> None:
        """
        Run all enabled detectors.
        Called while an app context is already active.
        """
        now = datetime.now(timezone.utc).timestamp()

        # Refresh rule cache when stale
        if now - self._cache_ts > self._CACHE_TTL:
            self._rules_cache = RuleManager.get_enabled()
            self._cache_ts    = now
            logger.debug("Detection rules refreshed: %d active", len(self._rules_cache))

        for rule in self._rules_cache:
            detector = self._detectors.get(rule["rule_type"])
            if detector:
                try:
                    detector.inspect(packet, rule)
                except Exception as exc:
                    logger.error(
                        "Detector %s raised an error: %s",
                        rule["rule_type"], exc, exc_info=True,
                    )


# ==============================================================================
# RULE MANAGER — loads active rules from DB
# ==============================================================================
class RuleManager:
    """
    Static helper — returns enabled DetectionRule rows as plain dicts.
    Must be called while an app context is active.
    """

    @staticmethod
    def get_enabled() -> list:
        """
        Return list of enabled rule dicts from DB.
        No app_context() opened — relies on caller's context.
        """
        try:
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
            logger.error("RuleManager.get_enabled failed: %s", exc)
            return []


# ==============================================================================
# THREAT CLASSIFIER — human-readable labels & messages
# ==============================================================================
class ThreatClassifier:
    """Maps rule_type to display labels and alert message strings."""

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
            return f"Traffic spike: {count} packets (>{window}x baseline) from {source_ip}."
        return f"Threat detected from {source_ip}: {count} events."


# ==============================================================================
# BASE DETECTOR — shared sliding-window logic
# ==============================================================================
class BaseDetector:
    """
    Sliding-window event counter shared by all detectors.
    _fire_alert() calls AlertGenerator directly — NO nested app_context.
    """

    def __init__(self, app):
        self.app         = app
        self._windows: dict       = {}   # ip → [datetime, ...]
        self._classifier          = ThreatClassifier()

    def inspect(self, packet: dict, rule: dict) -> None:
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Rolling-window counter
    # ------------------------------------------------------------------
    def _record(self, ip: str, window_secs: int, ts: datetime) -> int:
        """
        Append ts to the window for ip, evict entries older than
        window_secs, and return the current in-window count.
        """
        if ip not in self._windows:
            self._windows[ip] = []
        self._windows[ip].append(ts)

        cutoff = ts.timestamp() - window_secs
        self._windows[ip] = [
            t for t in self._windows[ip] if t.timestamp() >= cutoff
        ]
        return len(self._windows[ip])

    # ------------------------------------------------------------------
    # Alert creation — called while app context is active (no re-entry)
    # ------------------------------------------------------------------
    def _fire_alert(self, rule: dict, source_ip: str, count: int) -> None:
        """
        Create an Alert via AlertGenerator.
        Caller (PacketAnalyzer._process_loop) already holds an app context.
        """
        rule_type = rule["rule_type"]
        severity  = rule["severity"]
        message   = self._classifier.message(
            rule_type, source_ip, count, rule["window"]
        )
        logger.debug(
            "_fire_alert: %s from %s (count=%d)", rule_type, source_ip, count
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
            logger.error("_fire_alert failed for %s: %s", rule_type, exc, exc_info=True)


# ==============================================================================
# PORT SCAN DETECTOR
# Fires when a single source hits ≥ threshold unique ports in window seconds
# ==============================================================================
class PortScanDetector(BaseDetector):
    """Detects horizontal port scans."""

    def __init__(self, app):
        super().__init__(app)
        # ip → {port: last_seen_datetime}
        self._port_windows: dict = {}

    def inspect(self, packet: dict, rule: dict) -> None:
        ip     = packet.get("source_ip")
        port   = packet.get("port")
        ts     = packet.get("timestamp") or datetime.now(timezone.utc)
        window = rule["window"]
        thresh = rule["threshold"]

        if not ip or port is None:
            return

        if ip not in self._port_windows:
            self._port_windows[ip] = {}

        # Record this port
        self._port_windows[ip][port] = ts

        # Evict stale entries
        cutoff = ts.timestamp() - window
        self._port_windows[ip] = {
            p: t for p, t in self._port_windows[ip].items()
            if t.timestamp() >= cutoff
        }

        unique_count = len(self._port_windows[ip])
        logger.debug("PortScan %s: %d unique ports (threshold %d)", ip, unique_count, thresh)

        if unique_count >= thresh:
            self._fire_alert(rule, ip, unique_count)
            self._port_windows[ip] = {}   # reset after firing


# ==============================================================================
# BRUTE FORCE DETECTOR
# Fires when ≥ threshold packets to auth ports arrive from one IP in window s
# ==============================================================================
class BruteForceDetector(BaseDetector):
    """Detects repeated connection attempts to authentication-related ports."""

    # Common services targeted by password-guessing tools
    AUTH_PORTS = {21, 22, 23, 25, 110, 143, 389, 445, 3306, 3389, 5432, 8080}

    def inspect(self, packet: dict, rule: dict) -> None:
        ip     = packet.get("source_ip")
        port   = packet.get("port")
        ts     = packet.get("timestamp") or datetime.now(timezone.utc)
        window = rule["window"]
        thresh = rule["threshold"]

        if not ip or port not in self.AUTH_PORTS:
            return

        count = self._record(ip, window, ts)
        logger.debug("BruteForce %s port %d: %d hits (threshold %d)", ip, port, count, thresh)

        if count >= thresh:
            self._fire_alert(rule, ip, count)
            self._windows[ip] = []   # reset


# ==============================================================================
# DDOS DETECTOR
# Fires when ≥ threshold packets arrive from one IP within window seconds
# ==============================================================================
class DDoSDetector(BaseDetector):
    """Detects high-volume packet floods from a single source."""

    def inspect(self, packet: dict, rule: dict) -> None:
        ip     = packet.get("source_ip")
        ts     = packet.get("timestamp") or datetime.now(timezone.utc)
        window = rule["window"]
        thresh = rule["threshold"]

        if not ip:
            return

        count = self._record(ip, window, ts)
        logger.debug("DDoS %s: %d packets (threshold %d)", ip, count, thresh)

        if count >= thresh:
            self._fire_alert(rule, ip, count)
            self._windows[ip] = []   # reset


# ==============================================================================
# SUSPICIOUS IP DETECTOR
# Fires once per IP when it appears on the runtime blacklist
# ==============================================================================
class SuspiciousIPDetector(BaseDetector):
    """Flags any traffic from a blacklisted source IP."""

    def __init__(self, app):
        super().__init__(app)
        self._alerted: set = set()   # IPs already alerted this session

    def inspect(self, packet: dict, rule: dict) -> None:
        ip = packet.get("source_ip")
        if not ip or ip in self._alerted:
            return

        # app.config is accessible without entering a new context
        blacklist = self.app.config.get("IP_BLACKLIST", [])
        if ip in blacklist:
            logger.info("Suspicious IP detected: %s", ip)
            self._fire_alert(rule, ip, 1)
            self._alerted.add(ip)


# ==============================================================================
# TRAFFIC SPIKE DETECTOR
# Fires when current-window rate ≥ threshold × baseline rate
# ==============================================================================
class TrafficSpikeDetector(BaseDetector):
    """Detects sudden traffic volume spikes vs a rolling baseline."""

    def __init__(self, app):
        super().__init__(app)
        self._global: list = []   # all recent timestamps for baseline

    def inspect(self, packet: dict, rule: dict) -> None:
        ts         = packet.get("timestamp") or datetime.now(timezone.utc)
        window     = rule["window"]       # e.g. 60 seconds
        multiplier = rule["threshold"]    # e.g. 3 × baseline

        self._global.append(ts)

        # Keep a rolling 2× window of history
        cutoff_all = ts.timestamp() - (window * 2)
        self._global = [t for t in self._global if t.timestamp() >= cutoff_all]

        # Current = packets in last `window` seconds
        cutoff_curr  = ts.timestamp() - window
        current_count = sum(1 for t in self._global if t.timestamp() >= cutoff_curr)

        # Baseline = packets in the window before that
        baseline_count = len(self._global) - current_count

        if baseline_count < 10:
            return  # not enough history

        if current_count >= baseline_count * multiplier:
            source_ip = packet.get("source_ip", "multiple")
            logger.info(
                "Traffic spike: %d packets vs baseline %d (%.1fx)",
                current_count, baseline_count,
                current_count / max(baseline_count, 1),
            )
            self._fire_alert(rule, source_ip, current_count)
            self._global = []   # reset to avoid alert storm
