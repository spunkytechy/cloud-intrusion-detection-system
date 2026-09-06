"""
packet_capture/analyzer.py - PacketAnalyzer
=============================================
Drains the shared packet_queue, parses each Scapy packet, runs detection,
queues TrafficLog rows for batched persistence, and honors the suspicious-IP
registry so flagged sources are persisted as suspicious.
"""

import logging
import queue as _queue
import threading
from datetime import datetime, timezone
from typing import Optional

from packet_capture.sniffer import packet_queue
from packet_capture.state import is_suspicious, prune_expired

logger = logging.getLogger(__name__)

_analyzer_thread: Optional[threading.Thread] = None


class PacketAnalyzer:
    """Consumes packets, parses metadata, runs detection, and batches DB writes."""

    def __init__(self, app):
        self.app = app
        self._stop_event = threading.Event()
        self.batch_size = int(app.config.get("ANALYZER_BATCH_SIZE", 50))
        self.flush_interval = float(app.config.get("ANALYZER_FLUSH_INTERVAL", 2.0))
        self._buffer: list = []
        self._buffer_lock = threading.Lock()
        self._last_flush = datetime.now(timezone.utc).timestamp()

    def start(self) -> None:
        """Start the analyzer daemon. No-op if already running."""
        global _analyzer_thread
        if _analyzer_thread is not None and _analyzer_thread.is_alive():
            logger.warning("PacketAnalyzer already running — ignoring duplicate start().")
            return

        self._stop_event.clear()
        _analyzer_thread = threading.Thread(
            target=self._process_loop,
            daemon=True,
            name="PacketAnalyzer",
        )
        _analyzer_thread.start()
        logger.info(
            "PacketAnalyzer started (batch_size=%d, flush_interval=%.1fs).",
            self.batch_size,
            self.flush_interval,
        )

    def stop(self) -> None:
        """Signal the analyzer thread to stop and flush any pending rows."""
        self._stop_event.set()
        try:
            self._flush()
        except Exception as exc:
            logger.warning("Final flush during stop() failed: %s", exc)
        logger.info("PacketAnalyzer stop requested.")

    def _process_loop(self) -> None:
        """Drain the queue, analyze packets, and flush buffered logs."""
        from detection.engine import DetectionEngine

        engine = DetectionEngine(self.app)
        logger.info("PacketAnalyzer processing loop running.")

        prune_tick = 0
        while not self._stop_event.is_set():
            try:
                packet = packet_queue.get(timeout=0.5)
            except _queue.Empty:
                self._maybe_flush()
                continue

            try:
                parsed = self._parse_packet(packet)
                if parsed is None:
                    continue

                try:
                    with self.app.app_context():
                        engine.analyze(parsed)
                except Exception as exc:
                    logger.error("DetectionEngine.analyze failed: %s", exc)

                self._enqueue_log(parsed)
                self._maybe_flush()

                prune_tick += 1
                if prune_tick >= 500:
                    prune_expired()
                    prune_tick = 0
            except Exception as exc:
                logger.error("Analyzer loop error: %s", exc, exc_info=True)

        try:
            self._flush()
        except Exception as exc:
            logger.warning("Shutdown flush failed: %s", exc)

    @staticmethod
    def _parse_packet(packet) -> Optional[dict]:
        """Extract IP/TCP/UDP/ICMP fields from a raw Scapy packet."""
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore

            if not packet.haslayer(IP):
                return None

            ip = packet[IP]
            proto = "UNKNOWN"
            port: Optional[int] = None
            flags: Optional[str] = None

            if packet.haslayer(TCP):
                proto = "TCP"
                port = int(packet[TCP].dport)
                flags = str(packet[TCP].flags)
            elif packet.haslayer(UDP):
                proto = "UDP"
                port = int(packet[UDP].dport)
            elif packet.haslayer(ICMP):
                proto = "ICMP"

            return {
                "source_ip": ip.src,
                "destination_ip": ip.dst,
                "protocol": proto,
                "port": port,
                "packet_size": len(packet),
                "timestamp": datetime.now(timezone.utc),
                "flags": flags,
                "raw_summary": packet.summary()[:512],
            }
        except Exception as exc:
            logger.debug("Packet parse error: %s", exc)
            return None

    def _enqueue_log(self, parsed: dict) -> None:
        """Add a parsed packet to the in-memory flush buffer."""
        with self._buffer_lock:
            self._buffer.append(parsed)

    def _maybe_flush(self) -> None:
        """Flush the buffer if it's full or if the flush interval elapsed."""
        now = datetime.now(timezone.utc).timestamp()
        with self._buffer_lock:
            buffer_full = len(self._buffer) >= self.batch_size
            time_elapsed = (now - self._last_flush) >= self.flush_interval
            has_rows = len(self._buffer) > 0

        if has_rows and (buffer_full or time_elapsed):
            self._flush()

    def _flush(self) -> None:
        """Persist all buffered TrafficLog rows in one commit."""
        with self._buffer_lock:
            if not self._buffer:
                return
            rows_to_flush = self._buffer
            self._buffer = []
            self._last_flush = datetime.now(timezone.utc).timestamp()

        try:
            from database.db import db
            from models.traffic_log import TrafficLog

            with self.app.app_context():
                objects = []
                for row in rows_to_flush:
                    status = (
                        TrafficLog.STATUS_SUSPICIOUS
                        if is_suspicious(row["source_ip"])
                        else TrafficLog.STATUS_NORMAL
                    )
                    objects.append(
                        TrafficLog(
                            source_ip=row["source_ip"],
                            destination_ip=row["destination_ip"],
                            protocol=row["protocol"],
                            port=row["port"],
                            packet_size=row["packet_size"],
                            timestamp=row["timestamp"],
                            flags=row["flags"],
                            raw_summary=row["raw_summary"],
                            status=status,
                        )
                    )
                db.session.bulk_save_objects(objects)
                db.session.commit()
        except Exception as exc:
            logger.error(
                "TrafficLog batch flush failed (%d rows): %s",
                len(rows_to_flush),
                exc,
                exc_info=True,
            )
            try:
                from database.db import db
                db.session.rollback()
            except Exception:
                pass


