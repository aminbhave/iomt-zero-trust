"""
Traffic interception layer.

For the PoC the sidecar operates as an HTTP reverse proxy (FastAPI)
rather than a raw Scapy sniffer, making it portable across platforms
and easy to test.  The legacy device POSTs cleartext data to the
sidecar, which then tokenises, encrypts, and forwards it to the
cloud PEP.

A Scapy-based raw capture mode is provided as an optional helper for
demonstration on Raspberry Pi / Linux where the sidecar is configured
as the device's default gateway.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field


@dataclass
class PacketMetadata:
    """Metadata extracted from an intercepted cleartext packet."""
    device_id: str
    tenant_id: str
    payload_size: int
    timestamp: float = field(default_factory=time.time)
    source_ip: str = "127.0.0.1"
    seq: int = 0


def extract_metadata(raw_body: bytes, source_ip: str = "127.0.0.1") -> PacketMetadata:
    """Parse cleartext JSON from the legacy device and extract metadata."""
    try:
        data = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        data = {}

    return PacketMetadata(
        device_id=data.get("device_id", "unknown"),
        tenant_id=data.get("tenant_id", "unknown"),
        payload_size=len(raw_body),
        timestamp=data.get("timestamp", time.time()),
        source_ip=source_ip,
        seq=data.get("seq", 0),
    )
