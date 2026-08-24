"""
packet_capture/sniffer.py - PacketSniffer
==========================================
Captures live network packets using Scapy and pushes them into a
thread-safe queue for the PacketAnalyzer to consume.

State (running / interface / last error / counters) is reported
via packet_capture.state so the /dashboard and /api/v1/health
endpoints can show whether capture is healthy.

On Windows, Scapy requires Npcap (https://npcap.com) to be installed.
Run the application as Administrator for raw socket access.
"""

import queue
import logging
import threading
from datetime import datetime, timezone
from typing import Optional

from packet_capture.state import (
    set_capture_state,
    get_capture_state,
    increment_packets_seen,
    increment_packets_dropped,
)

logger = logging.getLogger(__name__)

# Global queue shared between sniffer and analyzer
packet_queue: "queue.Queue" = queue.Queue(maxsize=10000)

# Module-level references (single-instance sniffer per process)
_sniffer_instance: Optional["PacketSniffer"] = None
_sniffer_thread: Optional[threading.Thread] = None


class PacketSniffer:
    """
    Captures packets on a given network interface using Scapy.
    Runs in a background thread and puts raw packets onto packet_queue.
    """

    def __init__(self, interface: Optional[str] = None, packet_filter: str = "ip"):
        self.interface = interface        # None → Scapy picks default adapter
        self.packet_filter = packet_filter
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Start sniffing in a background thread. No-op if already running."""
        global _sniffer_thread
        if get_capture_state().get("running"):
            logger.warning("Sniffer already running — skipping start().")
            return

        self._stop_event.clear()
        _sniffer_thread = threading.Thread(
            target=self._sniff_loop, daemon=True, name="PacketSniffer"
        )
        _sniffer_thread.start()

        # State flip is done inside _sniff_loop once sniff() is about to
        # begin, so callers of start() should treat "running" as eventual.
        logger.info(
            "PacketSniffer thread launched (interface=%s, filter=%r).",
            self.interface or "auto",
            self.packet_filter,
        )

    def stop(self) -> None:
        """Signal the sniffer thread to stop."""
        self._stop_event.set()
        set_capture_state(running=False)
        logger.info("PacketSniffer stop requested.")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _handle_packet(self, packet) -> None:
        """Called by Scapy for every captured packet."""
        try:
            packet_queue.put_nowait(packet)
            increment_packets_seen(1)
        except queue.Full:
            increment_packets_dropped(1)  # drop when consumer can't keep up

    def _sniff_loop(self) -> None:
        """Main sniff loop — runs until stop() is called or an error occurs."""
        try:
            # Lazy import so the whole app can still boot on machines where
            # Scapy / Npcap isn't installed (health endpoint will surface it).
            from scapy.all import sniff  # type: ignore
        except Exception as exc:
            msg = f"Scapy import failed: {exc}. Install Npcap on Windows."
            logger.error(msg)
            set_capture_state(running=False, last_error=msg)
            return

        set_capture_state(
            running=True,
            interface=self.interface or "auto",
            started_at=datetime.now(timezone.utc).isoformat(),
            last_error=None,
        )
        logger.info(
            "PacketSniffer active on %s (filter=%r).",
            self.interface or "auto",
            self.packet_filter,
        )

        try:
            sniff(
                iface=self.interface,
                filter=self.packet_filter,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError as exc:
            msg = (
                f"Permission denied opening interface {self.interface!r}. "
                f"On Windows, run as Administrator. ({exc})"
            )
            logger.error(msg)
            set_capture_state(running=False, last_error=msg)
        except OSError as exc:
            msg = (
                f"OS error on interface {self.interface!r}: {exc}. "
                f"Verify the interface name and that Npcap is installed."
            )
            logger.error(msg)
            set_capture_state(running=False, last_error=msg)
        except Exception as exc:
            msg = f"Sniffer error: {exc}"
            logger.error(msg, exc_info=True)
            set_capture_state(running=False, last_error=msg)
        else:
            set_capture_state(running=False)
            logger.info("PacketSniffer loop exited cleanly.")


# ==============================================================================
# HELPERS
# ==============================================================================
def is_running() -> bool:
    """Return True if the sniffer is currently active."""
    return bool(get_capture_state().get("running"))


def get_sniffer_instance(app=None) -> PacketSniffer:
    """
    Build (or return cached) PacketSniffer from app config or env defaults.

    A single instance per process is kept so that repeated calls
    (e.g. from tests or reloader hooks) don't spawn duplicates.
    """
    global _sniffer_instance
    if _sniffer_instance is not None:
        return _sniffer_instance

    import os
    if app:
        interface  = app.config.get("CAPTURE_INTERFACE") or None
        pkt_filter = app.config.get("CAPTURE_FILTER", "ip")
    else:
        interface  = os.environ.get("CAPTURE_INTERFACE") or None
        pkt_filter = os.environ.get("CAPTURE_FILTER", "ip")

    # Empty string → None so Scapy picks its default adapter
    if not interface:
        interface = None

    _sniffer_instance = PacketSniffer(interface=interface, packet_filter=pkt_filter)
    return _sniffer_instance
