"""
packet_capture/sniffer.py - PacketSniffer
==========================================
Captures live network packets using Scapy and pushes them into a
thread-safe queue for the PacketAnalyzer to consume.

On Windows, Scapy requires Npcap (https://npcap.com) to be installed.
Run the application as Administrator for raw socket access.
"""

import threading
import queue
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Global queue shared between sniffer and analyzer
packet_queue = queue.Queue(maxsize=10000)

# Sniffer state
_sniffer_thread = None
_running = False


class PacketSniffer:
    """
    Captures packets on a given network interface using Scapy.
    Runs in a background thread and puts raw packets onto packet_queue.
    """

    def __init__(self, interface: str = None, packet_filter: str = "ip"):
        self.interface = interface      # None = Scapy picks default
        self.packet_filter = packet_filter
        self._stop_event = threading.Event()

    def _handle_packet(self, packet) -> None:
        """Called by Scapy for every captured packet."""
        try:
            if not packet_queue.full():
                packet_queue.put_nowait(packet)
        except queue.Full:
            pass  # drop packet if queue is full

    def start(self) -> None:
        """Start sniffing in a background thread."""
        global _sniffer_thread, _running
        if _running:
            logger.warning("Sniffer already running.")
            return

        _running = True
        self._stop_event.clear()
        _sniffer_thread = threading.Thread(
            target=self._sniff_loop, daemon=True, name="PacketSniffer"
        )
        _sniffer_thread.start()
        logger.info("PacketSniffer started on interface: %s", self.interface or "default")

    def stop(self) -> None:
        """Signal the sniffer thread to stop."""
        global _running
        _running = False
        self._stop_event.set()
        logger.info("PacketSniffer stopped.")

    def _sniff_loop(self) -> None:
        """Main sniff loop — runs until stop() is called."""
        try:
            from scapy.all import sniff
            sniff(
                iface=self.interface,
                filter=self.packet_filter,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except Exception as exc:
            logger.error("Sniffer error: %s", exc)
            global _running
            _running = False


def is_running() -> bool:
    """Return True if the sniffer is currently active."""
    return _running


def get_sniffer_instance(app=None) -> PacketSniffer:
    """
    Build a PacketSniffer from app config or environment defaults.
    If app is None, uses environment variable CAPTURE_INTERFACE.
    """
    import os
    interface = None
    pkt_filter = "ip"

    if app:
        interface  = app.config.get("CAPTURE_INTERFACE") or None
        pkt_filter = app.config.get("CAPTURE_FILTER", "ip")
    else:
        interface  = os.environ.get("CAPTURE_INTERFACE") or None
        pkt_filter = os.environ.get("CAPTURE_FILTER", "ip")

    # Empty string → None so Scapy uses default interface
    if not interface:
        interface = None

    return PacketSniffer(interface=interface, packet_filter=pkt_filter)
