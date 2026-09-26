"""
models.py
Shared data structures. Kept dependency-free (no scapy) so that detectors,
the IOC extractor, and unit tests can import PacketRecord without needing
scapy installed -- only pcap_parser.py (the actual pcap reader) needs it.
"""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class PacketRecord:
    index: int
    timestamp: float
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "OTHER"
    length: int = 0
    dns_query: Optional[str] = None
    http_host: Optional[str] = None
    http_path: Optional[str] = None
    payload_snippet: Optional[str] = None  # for plaintext-cred scanning

    @property
    def dt(self) -> datetime:
        return datetime.fromtimestamp(self.timestamp)
