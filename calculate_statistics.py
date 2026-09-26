"""
statistics.py
Calculates summary statistics from parsed PacketRecord objects.
This module contains no UI code and can be reused by the dashboard,
reports, and future CLI enhancements.
"""

from __future__ import annotations

from dataclasses import dataclass

from models import PacketRecord

@dataclass
class CaptureStatistics:
    total_packets: int
    capture_duration: float
    total_bytes: int
    unique_ips: int
    sessions: int
    protocol_count: int


def calculate_statistics(records: list[PacketRecord]) -> CaptureStatistics:
    if not records:
        return CaptureStatistics(
            total_packets=0,
            capture_duration=0.0,
            total_bytes=0,
            unique_ips=0,
            sessions=0,
            protocol_count=0,
        )

    total_packets = len(records)

    start_time = min(r.timestamp for r in records)
    end_time = max(r.timestamp for r in records)
    capture_duration = end_time - start_time

    total_bytes = sum(r.length for r in records)

    unique_ips = {
        ip
        for r in records
        for ip in (r.src_ip, r.dst_ip)
        if ip
    }

    sessions = {
        (r.src_ip, r.dst_ip)
        for r in records
        if r.src_ip and r.dst_ip
    }

    protocols = {
        r.protocol
        for r in records
        if r.protocol
    }

    return CaptureStatistics(
        total_packets=total_packets,
        capture_duration=capture_duration,
        total_bytes=total_bytes,
        unique_ips=len(unique_ips),
        sessions=len(sessions),
        protocol_count=len(protocols),
    )