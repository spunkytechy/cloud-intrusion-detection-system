"""
packet_capture/state.py - Shared Capture State + Suspicious IP Registry
========================================================================
Kept in its own module so both the packet pipeline (sniffer, analyzer)
and the alerting layer (alerts.generator) can share state without
importing app.py — that would create a circular dependency because
app.py imports the pipeline during create_app().

Two things live here:

1. capture_state
   --------------
   The current health of the packet-capture pipeline. Read by:
     - /api/v1/health          (JSON status)
     - /dashboard              (banner shown when capture is down)
   Written by the sniffer / analyzer as they start, stop, or error out.

2. Suspicious-IP registry
   ----------------------
   An in-memory dict of source_ip -> expiration timestamp. Populated
   by AlertGenerator.create() whenever a detector fires. Consulted by
   the analyzer when it writes a new TrafficLog row so that packets
   from a currently-flagged IP are stored with status='suspicious'
   instead of 'normal'.

   Cheap O(1) lookup, no DB round-trip on the hot path. Entries are
   pruned lazily on read.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Optional


# ==============================================================================
# CAPTURE STATE
# ==============================================================================
_state_lock = threading.Lock()
_capture_state: dict = {
    "enabled":     True,     # whether capture is enabled via config
    "running":     False,    # whether the sniffer thread is live
    "interface":   None,     # network interface being sniffed
    "started_at":  None,     # UTC datetime when the sniffer started
    "last_error":  None,     # last exception message, if any
    "packets_seen": 0,       # cumulative packets pushed to the queue
    "packets_dropped": 0,    # packets dropped because the queue was full
}


def set_capture_state(**kwargs) -> None:
    """
    Update one or more capture-state fields atomically.

    Only known keys are accepted; unknown keys are ignored to prevent
    typos from silently polluting the state dict.
    """
    with _state_lock:
        for key, value in kwargs.items():
            if key in _capture_state:
                _capture_state[key] = value


def get_capture_state() -> dict:
    """Return a shallow copy of the current capture-state dict."""
    with _state_lock:
        return dict(_capture_state)


def increment_packets_seen(n: int = 1) -> None:
    """Bump the packets_seen counter (called by the sniffer)."""
    with _state_lock:
        _capture_state["packets_seen"] += n


def increment_packets_dropped(n: int = 1) -> None:
    """Bump the packets_dropped counter (queue-full drops)."""
    with _state_lock:
        _capture_state["packets_dropped"] += n


# ==============================================================================
# SUSPICIOUS IP REGISTRY
# ==============================================================================
_suspicious_lock = threading.Lock()
_suspicious_ips: dict = {}   # source_ip -> expires_at (UTC datetime)


def mark_suspicious(ip: str, ttl_seconds: int = 300) -> None:
    """
    Flag an IP as suspicious for `ttl_seconds`. Any packet from this
    IP arriving before the TTL expires will be persisted with
    TrafficLog.STATUS_SUSPICIOUS.

    Args:
        ip:         Source IP to flag.
        ttl_seconds: How long the flag stays active (default 5 min).
    """
    if not ip:
        return
    expires_at = datetime.now(timezone.utc).timestamp() + ttl_seconds
    with _suspicious_lock:
        # Extend rather than shorten if we're already tracking this IP
        current = _suspicious_ips.get(ip, 0)
        _suspicious_ips[ip] = max(current, expires_at)


def is_suspicious(ip: str) -> bool:
    """
    Return True if `ip` is currently flagged suspicious.
    Expired entries are pruned on access.
    """
    if not ip:
        return False
    now = datetime.now(timezone.utc).timestamp()
    with _suspicious_lock:
        expires_at = _suspicious_ips.get(ip)
        if expires_at is None:
            return False
        if expires_at < now:
            _suspicious_ips.pop(ip, None)
            return False
        return True


def prune_expired() -> int:
    """
    Remove all expired suspicious-IP entries. Called periodically by
    the analyzer flush loop. Returns the number of entries pruned.
    """
    now = datetime.now(timezone.utc).timestamp()
    with _suspicious_lock:
        expired = [ip for ip, exp in _suspicious_ips.items() if exp < now]
        for ip in expired:
            _suspicious_ips.pop(ip, None)
        return len(expired)


def get_suspicious_snapshot() -> dict:
    """Return a copy of the current suspicious-IP map. Useful for the API."""
    with _suspicious_lock:
        return dict(_suspicious_ips)


def clear_all_suspicious() -> None:
    """Wipe the registry. Used by tests / admin reset."""
    with _suspicious_lock:
        _suspicious_ips.clear()
