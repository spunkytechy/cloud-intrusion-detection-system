"""
packet_capture/analyzer.py - PacketAnalyzer
=============================================
Drains packet_queue, parses Scapy packets, runs the DetectionEngine,
and batches TrafficLog rows into the database.

Context ownership rule
----------------------
  _flush() opens its own app context because it runs asynchronously
  relative to the detect step (it may fire on the flush-interval timer
  while no packet is being processed).

  The detect step (engine.analyze) opens its own app context per packet.
  These two contexts are always sequential, never nested, so there is
  exactly one SQLAlchemy session active at any point in the thread.

Suspicious-IP registry
----------------------
  At flush time, each buffered row is checked against the in-memory
  suspicious-IP registry (packet_capture.state.is_suspicious). If the
  source IP was flagged by the detection engine, the row is written as
  STATUS_SUSPICIOUS instead of STATUS_NORMAL.
"""

import logging
import queue as _queue
import threading
from datetime import datetime, timezone
from typing import Optional, List

from packet_capture.sniffer import packet_queue
from packet_capture.state import is_suspicious, prune_expired

logger = logging.getLogger(__name__)

_analyzer_thread: Optional[threading.Thread] = None


class PacketAnalyzer:
    """
    Background thread:
      1. Pops raw Scapy packets from packet_queue.
      2. Parses each packet into a plain dict.
      3. Runs DetectionEngine.analyze() inside an app context.
      4. Buffers the parsed dict.
      5. Flushes the buffer as a single bulk INSERT when the buffer
         reaches batch_size rows OR flush_interval seconds elapse.
    """

    def __init__(self, app):
        self.app            = app
        self._stop_event    = threading.Event()
        self.batch_size     = int(app.config.get("ANALYZER_BATCH_SIZE", 50))
        self.flush_interval = float(app.config.get("ANALYZER_FLUSH_INTERVAL", 2.0))
        self._buffer: List[dict] = []
        self._buffer_lock   = threading.Lock()
        self._last_flush    = datetime.now(timezone.utc).timestamp()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Spawn the analyzer daemon thread. No-op if already alive."""
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
        """Stop the analyzer and flush remaining buffered rows."""
        self._stop_event.set()
        try:
            self._flush()
        except Exception as exc:
            logger.warning("Final flush on stop() failed: %s", exc)
        logger.info("PacketAnalyzer stopped.")

    # ------------------------------------------------------------------
    # Processing loop
    # ------------------------------------------------------------------
    def _process_loop(self) -> None:
        """
        Main loop. Runs until stop() is called.

        For each packet:
          1. Parse it (pure, no DB).
          2. Open ONE app context → run DetectionEngine.analyze().
             The engine and AlertGenerator share this context.
          3. Enqueue the parsed dict in the memory buffer.
          4. Maybe flush the buffer to the DB (in a separate context).
        """
        from detection.engine import DetectionEngine

        engine     = DetectionEngine(self.app)
        prune_tick = 0

        logger.info("PacketAnalyzer processing loop running.")

        while not self._stop_event.is_set():
            # ── Pull a packet (or check for flush on idle) ──────────
            try:
                packet = packet_queue.get(timeout=0.5)
            except _queue.Empty:
                self._maybe_flush()
                continue

            try:
                parsed = self._parse_packet(packet)
                if parsed is None:
                    continue

                # ── Detect (own app context) ─────────────────────────
                try:
                    with self.app.app_context():
                        engine.analyze(parsed)
                except Exception as exc:
                    logger.error("DetectionEngine.analyze failed: %s", exc, exc_info=True)

                # ── Buffer for batched write ─────────────────────────
                with self._buffer_lock:
                    self._buffer.append(parsed)

                self._maybe_flush()

                # ── Periodic registry prune ──────────────────────────
                prune_tick += 1
                if prune_tick >= 500:
                    prune_expired()
                    prune_tick = 0

            except Exception as exc:
                logger.error("Analyzer loop error: %s", exc, exc_info=True)

        # Final flush on clean shutdown
        try:
            self._flush()
        except Exception as exc:
            logger.warning("Shutdown flush failed: %s", exc)

    # ------------------------------------------------------------------
    # Packet parsing (pure — no DB, no context)
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_packet(packet) -> Optional[dict]:
        """
        Extract fields from a raw Scapy packet.

        Returns a plain dict or None if the packet is not an IP packet.
        """
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore

            if not packet.haslayer(IP):
                return None

            ip    = packet[IP]
            proto = "UNKNOWN"
            port: Optional[int]  = None
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
    # Buffered batch flush
    # ------------------------------------------------------------------
    def _maybe_flush(self) -> None:
        """Flush if the buffer is full or the flush interval has elapsed."""
        now = datetime.now(timezone.utc).timestamp()
        with self._buffer_lock:
            full     = len(self._buffer) >= self.batch_size
            stale    = (now - self._last_flush) >= self.flush_interval
            has_rows = bool(self._buffer)

        if has_rows and (full or stale):
            self._flush()

    def _flush(self) -> None:
        """
        Drain the buffer and bulk-insert all rows into traffic_logs.

        Opens its own app context so this can be called both from the
        main processing loop (between packets) and from stop() after
        the loop exits.
        """
        # Atomically drain the buffer
        with self._buffer_lock:
            if not self._buffer:
                return
            rows        = self._buffer[:]
            self._buffer = []
            self._last_flush = datetime.now(timezone.utc).timestamp()

        try:
            from database.db import db
            from models.traffic_log import TrafficLog

            with self.app.app_context():
                objects = [
                    TrafficLog(
                        source_ip      = row["source_ip"],
                        destination_ip = row["destination_ip"],
                        protocol       = row["protocol"],
                        port           = row["port"],
                        packet_size    = row["packet_size"],
                        timestamp      = row["timestamp"],
                        flags          = row["flags"],
                        raw_summary    = row["raw_summary"],
                        # Mark suspicious if the detection engine flagged this IP
                        status = (
                            TrafficLog.STATUS_SUSPICIOUS
                            if is_suspicious(row["source_ip"])
                            else TrafficLog.STATUS_NORMAL
                        ),
                    )
                    for row in rows
                ]
                db.session.bulk_save_objects(objects)
                db.session.commit()
                logger.debug("Flushed %d TrafficLog rows to DB.", len(objects))

        except Exception as exc:
            logger.error(
                "TrafficLog batch flush failed (%d rows): %s",
                len(rows), exc, exc_info=True,
            )
            try:
                from database.db import db
                db.session.rollback()
            except Exception:
                pass
