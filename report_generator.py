"""
report_generator.py
Turns analysis results into a clean, shareable Markdown forensic report --
the thing you'd otherwise write up by hand after a Wireshark session.
Convert to PDF with `pandoc report.md -o report.pdf` if needed (see README).
"""

from __future__ import annotations
from collections import Counter
from datetime import datetime

from models import PacketRecord
from ioc_extractor import IOCReport
from detectors.port_scan import PortScanAlert
from detectors.beaconing import BeaconAlert
from detectors.dns_tunneling import DNSTunnelAlert
from detectors.plaintext_creds import CredAlert
from password_detector import CredentialFinding


def generate_report(
    pcap_name: str,
    records: list[PacketRecord],
    iocs: IOCReport,
    port_scan_alerts: list[PortScanAlert],
    beacon_alerts: list[BeaconAlert],
    dns_alerts: list[DNSTunnelAlert],
    cred_alerts: list[CredAlert],
    credential_findings: list[CredentialFinding] | None = None,
    case_number: str = "",
    evidence_number: str = "",
    case_title: str = "",
    investigator: str = "",
    organization: str = "",
    remarks: str = "",
) -> str:
    lines: list[str] = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines.append("# NETWORK FORENSIC ANALYSIS REPORT")
    lines.append("")

    lines.append("## CASE INFORMATION")
    lines.append("")

    lines.append(f"**Case Number:** {case_number or 'N/A'}")
    lines.append(f"**Evidence Number:** {evidence_number or 'N/A'}")
    lines.append(f"**Case Title:** {case_title or 'N/A'}")
    lines.append(f"**Investigator:** {investigator or 'N/A'}")
    lines.append(f"**Organization:** {organization or 'N/A'}")
    lines.append(f"**Evidence File:** {pcap_name}")
    lines.append(f"**Generated:** {now}")

    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## EXECUTIVE SUMMARY")
    lines.append("")
    protocol_counts = Counter(
        r.protocol for r in records if r.protocol
    )
    lines.append("\n## Protocol Distribution")

    for proto, count in protocol_counts.most_common():
        lines.append(
            f"- {proto}: {count} packets ({count/len(records)*100:.1f}%)"
        )
    
    lines.append(f"- Total packets analyzed: **{len(records)}**")
    if records:
        start = min(r.timestamp for r in records)
        end = max(r.timestamp for r in records)
        lines.append(f"- Capture window: **{datetime.fromtimestamp(start)} → "
                      f"{datetime.fromtimestamp(end)}**")
    lines.append(f"- External IPs seen: **{len(iocs.external_ips)}**")
    lines.append(f"- Domains seen: **{len(iocs.domains)}**")
    total_alerts = (
        len(port_scan_alerts)
        + len(beacon_alerts)
        + len(dns_alerts)
        + len(cred_alerts)
    )

    if total_alerts == 0:
        risk = "LOW"
    elif total_alerts <= 5:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    lines.append(f"- **Overall Risk Level:** {risk}")
    lines.append(f"- **Total alerts raised: {total_alerts}**\n")

    lines.append("## Alerts")

    lines.append(f"\n### Port Scan Alerts ({len(port_scan_alerts)})")
    if port_scan_alerts:
        for a in port_scan_alerts:
            lines.append(f"- **[{a.severity}]** {a.summary()}")
    else:
        lines.append("- None detected.")

    lines.append(f"\n### Beaconing / C2 Alerts ({len(beacon_alerts)})")
    if beacon_alerts:
        for a in beacon_alerts:
            lines.append(f"- **[{a.severity}]** {a.summary()}")
    else:
        lines.append("- None detected.")

    lines.append(f"\n### DNS Tunneling Alerts ({len(dns_alerts)})")
    if dns_alerts:
        for a in dns_alerts:
            lines.append(f"- **[{a.severity}]** {a.summary()}")
    else:
        lines.append("- None detected.")

    lines.append(f"\n### Plaintext Credential Alerts ({len(cred_alerts)})")
    if cred_alerts:
        for a in cred_alerts:
            lines.append(f"- **[{a.severity}]** {a.summary()}")
    else:
        lines.append("- None detected.")

    if credential_findings is not None:
        lines.append(f"\n### Credential & Password Analysis ({len(credential_findings)})")
        if credential_findings:
            for f in credential_findings:
                reused = " _(reused elsewhere in capture)_" if f.reused else ""
                lines.append(f"- **[{f.severity}]** {f.summary()}{reused}")
        else:
            lines.append("- None detected.")

    lines.append("\n## Indicators of Compromise (IOCs)")
    lines.append(f"\n### External IPs ({len(iocs.external_ips)})")
    lines.append(", ".join(sorted(iocs.external_ips)) or "None")

    lines.append(f"\n### Domains ({len(iocs.domains)})")
    lines.append(", ".join(sorted(iocs.domains)) or "None")

    lines.append(f"\n### URLs ({len(iocs.urls)})")
    lines.append("\n".join(f"- {u}" for u in sorted(iocs.urls)) or "None")

    return "\n".join(lines)


def save_report(report_text: str, out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report_text)
