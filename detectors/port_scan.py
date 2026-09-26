"""
detectors/port_scan.py
Flags a source IP as a likely port scanner if it contacts many distinct
destination ports (optionally across many destination IPs) within a short
time window. This is the classic Wireshark pain point: you'd normally build
this by hand with Statistics > Conversations + eyeballing patterns.
"""

from __future__ import annotations
from dataclasses import dataclass
from collections import defaultdict

from models import PacketRecord

DEFAULT_PORT_THRESHOLD = 15   # distinct dst ports from one src to trigger alert
DEFAULT_WINDOW_SECONDS = 10   # sliding window size


@dataclass
@dataclass
class PortScanAlert:
    src_ip: str
    distinct_ports: int
    window_start: float
    window_end: float
    dst_ips: set[str]
    severity: str = "MEDIUM"

    @property
    def timestamp(self):
        return self.window_start

    def summary(self) -> str:
        return (f"Possible port scan from {self.src_ip}: "
                f"{self.distinct_ports} distinct ports hit within "
                f"{self.window_end - self.window_start:.1f}s "
                f"across {len(self.dst_ips)} target(s).")


def detect_port_scans(
    records: list[PacketRecord],
    port_threshold: int = DEFAULT_PORT_THRESHOLD,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> list[PortScanAlert]:
    tcp_syn_like = [r for r in records if r.dst_port is not None and r.src_ip]
    tcp_syn_like.sort(key=lambda r: r.timestamp)

    alerts: list[PortScanAlert] = []
    seen_src_windows: set[tuple] = set()

    # sliding window per source IP
    by_src: dict[str, list[PacketRecord]] = defaultdict(list)
    for r in tcp_syn_like:
        by_src[r.src_ip].append(r)

    for src_ip, recs in by_src.items():
        recs.sort(key=lambda r: r.timestamp)
        start_idx = 0
        for end_idx in range(len(recs)):
            while recs[end_idx].timestamp - recs[start_idx].timestamp > window_seconds:
                start_idx += 1
            window = recs[start_idx:end_idx + 1]
            ports = {r.dst_port for r in window}
            if len(ports) >= port_threshold:
                key = (src_ip, round(window[0].timestamp))
                if key in seen_src_windows:
                    continue
                seen_src_windows.add(key)
                alerts.append(PortScanAlert(
                    src_ip=src_ip,
                    distinct_ports=len(ports),
                    window_start=window[0].timestamp,
                    window_end=window[-1].timestamp,
                    dst_ips={r.dst_ip for r in window if r.dst_ip},
                    severity="HIGH" if len(ports) >= port_threshold * 2 else "MEDIUM",
                ))

    return alerts
