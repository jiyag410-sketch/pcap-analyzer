"""
detectors/beaconing.py
Flags src->dst pairs that communicate at suspiciously regular intervals --
a classic sign of malware "beaconing" home to a C2 server. Wireshark has no
built-in equivalent; you'd need to export IO graphs and eyeball them.

Approach: for each (src_ip, dst_ip) pair, look at the gaps between
successive connections. If there are enough samples and the gaps are very
consistent (low coefficient of variation), flag it.
"""

from __future__ import annotations
from dataclasses import dataclass
from collections import defaultdict
import statistics

from models import PacketRecord

MIN_CONNECTIONS = 6          # need at least this many contacts to judge regularity
MAX_COEFF_VARIATION = 0.15   # lower = stricter "regularity" requirement


@dataclass
class BeaconAlert:
    src_ip: str
    dst_ip: str
    connection_count: int
    avg_interval_seconds: float
    coeff_variation: float
    severity: str = "MEDIUM"

    def summary(self) -> str:
        return (f"Possible beaconing: {self.src_ip} -> {self.dst_ip}, "
                f"{self.connection_count} connections, avg interval "
                f"{self.avg_interval_seconds:.1f}s, "
                f"regularity score {self.coeff_variation:.2f} (lower = more regular).")


def detect_beaconing(records: list[PacketRecord]) -> list[BeaconAlert]:
    pairs: dict[tuple[str, str], list[float]] = defaultdict(list)

    for r in records:
        if r.src_ip and r.dst_ip and r.dst_port:
            pairs[(r.src_ip, r.dst_ip)].append(r.timestamp)

    alerts: list[BeaconAlert] = []
    for (src, dst), times in pairs.items():
        times.sort()
        if len(times) < MIN_CONNECTIONS:
            continue

        intervals = [t2 - t1 for t1, t2 in zip(times, times[1:]) if t2 - t1 > 0]
        if len(intervals) < MIN_CONNECTIONS - 1:
            continue

        mean_interval = statistics.mean(intervals)
        if mean_interval == 0:
            continue
        stdev = statistics.pstdev(intervals)
        coeff_var = stdev / mean_interval

        if coeff_var <= MAX_COEFF_VARIATION:
            alerts.append(BeaconAlert(
                src_ip=src,
                dst_ip=dst,
                connection_count=len(times),
                avg_interval_seconds=mean_interval,
                coeff_variation=coeff_var,
                severity="HIGH" if coeff_var <= 0.05 else "MEDIUM",
            ))

    return alerts
