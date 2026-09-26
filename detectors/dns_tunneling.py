"""
detectors/dns_tunneling.py
Flags possible DNS tunneling: data smuggled inside DNS queries. Signs we
check for, per queried root domain:
  1. Abnormally high query volume to the same domain (tunneling needs many
     queries to move data).
  2. High average subdomain length (encoded data makes labels long).
  3. High character entropy in subdomains (base32/64-encoded data looks
     "random" compared to normal hostnames).
Wireshark shows raw DNS queries but does none of this correlation for you.
"""

from __future__ import annotations
from dataclasses import dataclass
from collections import defaultdict
import math

from models import PacketRecord

MIN_QUERIES_TO_DOMAIN = 20     # volume threshold
MIN_AVG_SUBDOMAIN_LEN = 25     # chars
MIN_ENTROPY = 3.5              # bits/char, typical English text is ~2.5-3.0


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _root_domain(fqdn: str) -> str:
    parts = fqdn.strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else fqdn


@dataclass
class DNSTunnelAlert:
    root_domain: str
    query_count: int
    avg_subdomain_length: float
    avg_entropy: float
    severity: str = "MEDIUM"

    def summary(self) -> str:
        return (f"Possible DNS tunneling via {self.root_domain}: "
                f"{self.query_count} queries, avg subdomain length "
                f"{self.avg_subdomain_length:.1f} chars, avg entropy "
                f"{self.avg_entropy:.2f} bits/char.")


def detect_dns_tunneling(records: list[PacketRecord]) -> list[DNSTunnelAlert]:
    by_domain: dict[str, list[str]] = defaultdict(list)

    for r in records:
        if not r.dns_query:
            continue
        root = _root_domain(r.dns_query)
        by_domain[root].append(r.dns_query)

    alerts: list[DNSTunnelAlert] = []
    for root, queries in by_domain.items():
        if len(queries) < MIN_QUERIES_TO_DOMAIN:
            continue

        subdomains = []
        for q in queries:
            prefix = q[: -len(root)].strip(".") if q.endswith(root) else q
            subdomains.append(prefix)

        avg_len = sum(len(s) for s in subdomains) / len(subdomains)
        avg_ent = sum(_entropy(s) for s in subdomains) / len(subdomains)

        if avg_len >= MIN_AVG_SUBDOMAIN_LEN and avg_ent >= MIN_ENTROPY:
            alerts.append(DNSTunnelAlert(
                root_domain=root,
                query_count=len(queries),
                avg_subdomain_length=avg_len,
                avg_entropy=avg_ent,
                severity="HIGH" if avg_ent >= 4.0 else "MEDIUM",
            ))

    return alerts
