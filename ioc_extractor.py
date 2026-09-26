"""
ioc_extractor.py
Pulls a clean, de-duplicated list of Indicators of Compromise (IOCs) out of
parsed packet records: IPs, domains, and full URLs. This is the thing
Wireshark makes you do by hand with Statistics > Endpoints + manual copy/paste.
"""

from __future__ import annotations
from dataclasses import dataclass, field

from models import PacketRecord

# RFC1918 / loopback / link-local ranges we don't care about for IOC purposes
_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.2", "172.30.", "172.31.", "192.168.", "127.", "169.254.")


def _is_private(ip: str) -> bool:
    return ip.startswith(_PRIVATE_PREFIXES)


@dataclass
class IOCReport:
    external_ips: set[str] = field(default_factory=set)
    internal_ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "external_ips": sorted(self.external_ips),
            "internal_ips": sorted(self.internal_ips),
            "domains": sorted(self.domains),
            "urls": sorted(self.urls),
        }


def extract_iocs(records: list[PacketRecord]) -> IOCReport:
    report = IOCReport()

    for r in records:
        for ip in (r.src_ip, r.dst_ip):
            if not ip:
                continue
            if _is_private(ip):
                report.internal_ips.add(ip)
            else:
                report.external_ips.add(ip)

        if r.dns_query:
            report.domains.add(r.dns_query)

        if r.http_host:
            report.domains.add(r.http_host)
            if r.http_path:
                report.urls.add(f"http://{r.http_host}{r.http_path}")

    return report
