"""
packet_capture/analyzer.py - PacketAnalyzer
=============================================
Reads raw packets from the shared queue, extracts fields, saves
TrafficLog records to the database, and hands them off to the
DetectionEngine for threat analysis.

Runs as a persistent background thread alongside the Flask app.
"""

import threading
import logging
import queue as _queue
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Reference to the global queue from sniffer.py
from packet_capture.sniffer import packet_queue

_analyzer_thread = None
_running = False


class PacketAnalyzer:
    """
    Consumes packets from packet_queue, extracts metadata,
    persists to TrafficLog, and triggers the DetectionEngine.
    """

    def __init__(self, app):
        """
        Args:
            app: Flask application instance (needed for app context on DB writes).
        """
        self.app = app
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Start the analyzer in a background thread."""
        global _analyzer_thread, _running
        if _running:
            return
        _running = True
        self._stop_event.clear()
        _analyzer_thread = threading.Thread(
            target=self._process_loop, daemon=True, name="PacketAnalyzer"
        )
        _analyzer_thread.start()
        logger.info("PacketAnalyzer started.")

    def stop(self) -> None:
        """Stop the analyzer thread."""
        global _running
        _running = False
        self._stop_event.set()
        logger.info("PacketAnalyzer stopped.")

    def _process_loop(self) -> None:
        """Main loop — drain the packet queue continuously."""
        from detection.engine import DetectionEngine
        engine = DetectionEngine(self.app)

        while not self._stop_event.is_set():
            try:
                packet = packet_queue.get(timeout=1)
                parsed = self._parse_packet(packet)
                if parsed:
                    self._save_log(parsed)
                    engine.analyze(parsed)
            except _queue.Empty:
                continue
            except Exception as exc:
                logger.error("Analyzer error: %s", exc)

    @staticmethod
    def _parse_packet(packet) -> dict | None:
        """
        Extract fields from a Scapy packet object.

        Returns:
            dict with keys: source_ip, destination_ip, protocol,
                            port, packet_size, timestamp, flags, raw_summary
            None if not an IP packet.
        """
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP

            if not packet.haslayer(IP):
                return None

            ip    = packet[IP]
            proto = "UNKNOWN"
            port  = None
            flags = None

            if packet.haslayer(TCP):
                proto = "TCP"
                port  = packet[TCP].dport
                flags = str(packet[TCP].flags)
            elif packet.haslayer(UDP):
                proto = "UDP"
                port  = packet[UDP].dport
            elif packet.haslayer(ICMP):
                proto = "ICMP"

            return {
                "source_ip":      ip.src,
                "destination_ip": ip.dst,
                "protocol":       proto,
                "port":           port,
                "packet_size":    len(packet),
                "timestamp":      datetime.now(timezone.utc),
                "flags":          flags,
                "raw_summary":    packet.summary()[:512],
            }
        except Exception as exc:
            logger.debug("Packet parse error: %s", exc)
            return None

    def _save_log(self, parsed: dict) -> None:
        """Persist parsed packet data as a TrafficLog record."""
        try:
            with self.app.app_context():
                from database.db import db
                from models.traffic_log import TrafficLog

                log = TrafficLog(
                    source_ip      = parsed["source_ip"],
                    destination_ip = parsed["destination_ip"],
                    protocol       = parsed["protocol"],
                    port           = parsed["port"],
                    packet_size    = parsed["packet_size"],
                    timestamp      = parsed["timestamp"],
                    flags          = parsed["flags"],
                    raw_summary    = parsed["raw_summary"],
                    status         = TrafficLog.STATUS_NORMAL,
                )
                db.session.add(log)
                db.session.commit()
        except Exception as exc:
            logger.error("TrafficLog save error: %s", exc)
