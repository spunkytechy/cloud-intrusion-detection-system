"""
models/traffic_log.py - Traffic Log Model
==========================================
Stores every captured network packet as a structured record.

Fields:
  id             - Primary key
  source_ip      - Packet origin IP address
  destination_ip - Packet destination IP address
  protocol       - Network protocol (TCP, UDP, ICMP, etc.)
  port           - Destination port number
  packet_size    - Payload size in bytes
  timestamp      - When the packet was captured (UTC)
  status         - "normal" | "suspicious" | "blocked"
  flags          - TCP flags string (SYN, ACK, FIN, RST, etc.)
  country        - Geo-IP country of source_ip (optional)
  raw_summary    - Short Scapy packet summary string
"""

from datetime import datetime, timezone

from database.db import BaseModel, TimestampMixin, db


class TrafficLog(TimestampMixin, BaseModel):
    """
    Represents a single captured and analysed network packet.

    Inherits:
      - BaseModel     : save(), delete(), to_dict()
      - TimestampMixin: created_at, updated_at
    """

    __tablename__ = "traffic_logs"

    # Indexes on commonly filtered columns for fast dashboard queries
    __table_args__ = (
        db.Index("ix_traffic_source_ip", "source_ip"),
        db.Index("ix_traffic_timestamp", "timestamp"),
        db.Index("ix_traffic_status", "status"),
        db.Index("ix_traffic_protocol", "protocol"),
    )

    # ------------------------------------------------------------------
    # Columns
    # ------------------------------------------------------------------
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    source_ip = db.Column(
        db.String(45),  # supports IPv6 (max 45 chars)
        nullable=False,
        comment="Source IP address of the packet",
    )
    destination_ip = db.Column(
        db.String(45),
        nullable=False,
        comment="Destination IP address of the packet",
    )
    protocol = db.Column(
        db.String(10),
        nullable=False,
        default="UNKNOWN",
        comment="Network protocol: TCP | UDP | ICMP | DNS | HTTP | etc.",
    )
    port = db.Column(
        db.Integer,
        nullable=True,
        comment="Destination port number (null for ICMP)",
    )
    packet_size = db.Column(
        db.Integer,
        nullable=False,
        default=0,
        comment="Total packet size in bytes",
    )
    timestamp = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        comment="UTC datetime when the packet was captured",
    )
    status = db.Column(
        db.String(20),
        nullable=False,
        default="normal",
        comment="Packet classification: normal | suspicious | blocked",
    )
    flags = db.Column(
        db.String(20),
        nullable=True,
        comment="TCP flags (e.g. S, SA, FA, R)",
    )
    country = db.Column(
        db.String(64),
        nullable=True,
        comment="Geo-IP resolved country for source_ip",
    )
    raw_summary = db.Column(
        db.String(512),
        nullable=True,
        comment="Short Scapy packet summary for quick inspection",
    )

    # ------------------------------------------------------------------
    # Class-level status constants
    # ------------------------------------------------------------------
    STATUS_NORMAL = "normal"
    STATUS_SUSPICIOUS = "suspicious"
    STATUS_BLOCKED = "blocked"

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------
    @classmethod
    def get_recent(cls, limit: int = 100) -> list:
        """
        Return the most recent `limit` traffic log entries.

        Args:
            limit: Maximum number of records to return.

        Returns:
            List of TrafficLog instances ordered newest first.
        """
        return cls.query.order_by(cls.timestamp.desc()).limit(limit).all()

    @classmethod
    def get_suspicious(cls, limit: int = 100) -> list:
        """Return recent suspicious or blocked packets."""
        return (
            cls.query.filter(cls.status != cls.STATUS_NORMAL)
            .order_by(cls.timestamp.desc())
            .limit(limit)
            .all()
        )

    @classmethod
    def get_top_source_ips(cls, limit: int = 10) -> list:
        """
        Return the top `limit` source IPs by packet count.

        Returns:
            List of (source_ip, count) tuples.
        """
        from sqlalchemy import func

        return (
            db.session.query(cls.source_ip, func.count(cls.id).label("count"))
            .group_by(cls.source_ip)
            .order_by(func.count(cls.id).desc())
            .limit(limit)
            .all()
        )

    @classmethod
    def get_protocol_distribution(cls) -> list:
        """
        Return packet counts grouped by protocol.

        Returns:
            List of (protocol, count) tuples.
        """
        from sqlalchemy import func

        return (
            db.session.query(cls.protocol, func.count(cls.id).label("count"))
            .group_by(cls.protocol)
            .order_by(func.count(cls.id).desc())
            .all()
        )
