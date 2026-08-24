"""
packet_capture/analyzer.py - PacketAnalyzer
=============================================
Reads raw packets from the shared queue, extracts fields, and:

  1. Runs the DetectionEngine on every packet immediately, so detectors
     using sliding-window state fire with sub-second latency.

  2. Buffers TrafficLog rows and flushes them to the database in batches
     (ANALYZER_BATCH_SIZE or ANALYZER_FLUSH_INTERVAL, whichever hits
     first). A single commit per batch keeps up with high packet rates
     that would otherwise overflow packet_queue.

  3. Consults packet_capture.state.is_suspicious(ip) at save time so
     packets from an IP that recently tripped a detector are persisted
     with status='suspicious' instead of 'normal'. That is what makes
     the "Suspicious" filter on the /logs page actually work.

Runs as a persistent daemon thread alongside the Flask app.
"""

import logging
import queue as _queue
import threading
from datetime import datetime, timezone
from typing import Optional

from packet_capture.sniffer import packet_queue
from packet_capture.state import is_suspicious, prune_expired

logger = logging.getLogger(__name__)

# Module-level thread reference so a second start() is a no-op
_analyzer_thread: Optional[threading.Thread] = None


class PacketAnalyzer:
    """
    Consumes packets from packet_queue, extracts metadata, buffers
    TrafficLog inserts for batch commit, and triggers DetectionEngine
    on each parsed packet.
    """

    def __init__(self, app):
        """
        Args:
            app: Flask application instance (needed for app context on DB writes).
        """
        self.app = app
        self._stop_event = threading.Event()

        # Batching knobs — read from app config with sensible defaults
        self.batch_size     = int(app.config.get("ANALYZER_BATCH_SIZE", 50))
        self.flush_interval = float(app.config.get("ANALYZER_FLUSH_INTERVAL", 2.0))

        # In-memory buffer of pending TrafficLog rows (list of dicts)
        self._buffer: list = []
        self._buffer_lock = threading.Lock()
        self._last_flush = datetime.now(timezone.utc).timestamp()

    # ------------------------------------------------------------------
    # Public lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Start the analyzer daemon. No-op if already running."""
        global _analyzer_thread
        if _analyzer_thread is not None and _analyzer_thread.is_alive():
            logger.warning("Analyzer already running — skipping start().")
            return

        self._stop_event.clear()
        _analyzer_thread = threading.Thread(
            target=self._process_loop, daemon=True, name="PacketAnalyzer"
        )
        _analyzer_thread.start()
        logger.info(
            "PacketAnalyzer started (batch_size=%d, flush_interval=%.1fs).",
            self.batch_size, self.flush_interval,
        )

    def stop(self) -> None:
        """Signal the analyzer thread to stop and flush any pending rows."""
        self._stop_event.set()
        try:
            self._flush()
        except Exception as exc:
            logger.warning("Final flush during stop() failed: %s", exc)
        logger.info("PacketAnalyzer stop requested.")

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------
    def _process_loop(self) -> None:
        """Drain the packet queue, run detection, and batch DB writes."""
        # Lazy-import DetectionEngine to avoid circular imports at module load
        from detection.engine import DetectionEngine
        engine = DetectionEngine(self.app)

        prune_tick = 0

        while not self._stop_event.is_set():
            try:
                # Short timeout lets us check flush interval + stop flag
                # frequently even when traffic is quiet.
                packet = packet_queue.get(timeout=0.5)
            except _queue.Empty:
                self._maybe_flush()
                continue

            try:
                parsed = self._parse_packet(packet)
                if parsed is None:
                    continue

                # Run detectors first (they need real-time signal),
                # then buffer the row for batched insert.
                try:
                    engine.analyze(parsed)
                except Exception as exc:
                    logger.error("DetectionEngine.analyze failed: %s", exc)

                self._enqueue_log(parsed)

                # Flush on size or time
                self._maybe_flush()

                # Periodically prune the suspicious-IP registry
                prune_tick += 1
                if prune_tick >= 500:
                    prune_expired()
                    prune_tick = 0

            except Exception as exc:
                logger.error("Analyzer loop error: %s", exc, exc_info=True)

        # Final flush on shutdown
        try:
            self._flush()
        except Exception as exc:
            logger.warning("Shutdown flush failed: %s", exc)

    # ------------------------------------------------------------------
    # Packet parsing
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_packet(packet) -> Optional[dict]:
        """
        Extract fields from a Scapy packet object.

        Returns:
            dict with keys: source_ip, destination_ip, protocol, port,
                            packet_size, timestamp, flags, raw_summary
            None if the packet has no IP layer.
        """
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore

            if not packet.haslayer(IP):
                return None

            ip    = packet[IP]
            proto = "UNKNOWN"
            port: Optional[int] = None
            flags: Optional[str] = None

            if packet.haslayer(TCP):
                proto = "TCP"
                port  = int(packet[TCP].dport)
                flags = str(packet[TCP].flags)
            elif packet.haslayer(UDP):
                proto = "UDP"
                port  = int(packet[UDP].dport)
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

    # ------------------------------------------------------------------
    # Batching
    # ------------------------------------------------------------------
    def _enqueue_log(self, parsed: dict) -> None:
        """Add a parsed packet to the in-memory flush buffer."""
        with self._buffer_lock:
            self._buffer.append(parsed)

    def _maybe_flush(self) -> None:
        """Flush the buffer if it's full or if the flush interval elapsed."""
        now = datetime.now(timezone.utc).timestamp()
        with self._buffer_lock:
            buffer_full  = len(self._buffer) >= self.batch_size
            time_elapsed = (now - self._last_flush) >= self.flush_interval
            has_rows     = len(self._buffer) > 0

        if has_rows and (buffer_full or time_elapsed):
            self._flush()

    def _flush(self) -> None:
        """
        Persist all buffered TrafficLog rows in one commit.

        Row status is decided per-packet at flush time:
          - If the source_ip is currently in the suspicious registry,
            status = 'suspicious'.
          - Otherwise, status = 'normal'.
        """
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
                    objects.append(TrafficLog(
                        source_ip      = row["source_ip"],
                        destination_ip = row["destination_ip"],
                        protocol       = row["protocol"],
                        port           = row["port"],
                        packet_size    = row["packet_size"],
                        timestamp      = row["timestamp"],
                        flags          = row["flags"],
                        raw_summary    = row["raw_summary"],
                        status         = status,
                    ))

                # bulk_save_objects is the fastest INSERT path in
                # SQLAlchemy for objects we won't re-use in the session.
                db.session.bulk_save_objects(objects)
                db.session.commit()
        except Exception as exc:
            logger.error(
                "TrafficLog batch flush failed (%d rows): %s",
                len(rows_to_flush), exc, exc_info=True,
            )
            try:
                from database.db import db
                db.session.rollback()
            except Exception:
                pass
