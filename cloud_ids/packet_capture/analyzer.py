"""
packet_capture/analyzer.py - PacketAnalyzer
=============================================
Drains the shared packet_queue, parses each Scapy packet, saves a
TrafficLog record, and runs the DetectionEngine — all inside a single
app context per packet so there is exactly one SQLAlchemy session.

Context ownership rule:
  PacketAnalyzer._process_loop opens ONE app_context per packet.
  Everything called from that loop (TrafficLog save, DetectionEngine,
  AlertGenerator) must NOT open a second context.
"""

import threading
import logging
import queue as _queue
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

from packet_capture.sniffer import packet_queue   # shared queue

_analyzer_thread = None
_running         = False


class PacketAnalyzer:
    """
    Background thread that consumes packets from packet_queue,
    enriches them, persists them, and triggers threat detection.
    """

    def __init__(self, app):
        self.app         = app
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Spawn the analyzer daemon thread."""
        global _analyzer_thread, _running
        if _running:
            logger.warning("PacketAnalyzer already running — ignoring duplicate start.")
            return

        _running = True
        self._stop_event.clear()
        _analyzer_thread = threading.Thread(
            target=self._process_loop,
            daemon=True,
            name="PacketAnalyzer",
        )
        _analyzer_thread.start()
        logger.info("PacketAnalyzer started.")

    def stop(self) -> None:
        """Stop the analyzer thread gracefully."""
        global _running
        _running = False
        self._stop_event.set()
        logger.info("PacketAnalyzer stopped.")

    # ------------------------------------------------------------------
    # Main processing loop
    # ------------------------------------------------------------------
    def _process_loop(self) -> None:
        """
        Drain packet_queue continuously.

        Each iteration:
          1. Pull one raw Scapy packet from the queue.
          2. Open a single app context.
          3. Parse the packet → dict.
          4. Save TrafficLog (inside the same context).
          5. Run DetectionEngine (inside the same context).
          6. Close the context (commits are done by save/generator).
        """
        from detection.engine import DetectionEngine
        engine = DetectionEngine(self.app)
        logger.info("PacketAnalyzer processing loop running.")

        while not self._stop_event.is_set():
            try:
                packet = packet_queue.get(timeout=1)
            except _queue.Empty:
                continue

            try:
                parsed = self._parse_packet(packet)
                if not parsed:
                    continue

                # ── Single app context for the full packet lifecycle ──
                with self.app.app_context():
                    self._save_log(parsed)
                    engine.analyze(parsed)

            except Exception as exc:
                logger.error("PacketAnalyzer loop error: %s", exc, exc_info=True)

    # ------------------------------------------------------------------
    # Packet parsing (pure — no DB, no context needed)
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_packet(packet) -> dict | None:
        """
        Extract IP/TCP/UDP/ICMP fields from a raw Scapy packet.

        Returns a plain dict or None if the packet is not an IP packet.
        """
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP

            if not packet.haslayer(IP):
                return None

            ip_layer = packet[IP]
            proto    = "UNKNOWN"
            port     = None
            flags    = None

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
                "source_ip":      ip_layer.src,
                "destination_ip": ip_layer.dst,
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

    # ------------------------------------------------------------------
    # Persistence (called inside an open app context)
    # ------------------------------------------------------------------
    @staticmethod
    def _save_log(parsed: dict) -> None:
        """
        Write a TrafficLog row for the parsed packet.
        Must be called while an app context is already active.
        """
        try:
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
            logger.error("TrafficLog save error: %s", exc, exc_info=True)
            try:
                from database.db import db
                db.session.rollback()
            except Exception:
                pass
