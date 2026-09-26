"""
main.py
Command-line entry point -- run analysis from a terminal / CI pipeline
without needing the Streamlit UI. This is the "scriptable, automatable"
answer to Wireshark being GUI-only.

Usage:
    python main.py samples/capture.pcap
    python main.py samples/capture.pcap --report reports/out.md --max-packets 50000
"""

from __future__ import annotations
import argparse
import sys

from pcap_parser import parse_pcap
from ioc_extractor import extract_iocs
from detectors.port_scan import detect_port_scans
from detectors.beaconing import detect_beaconing
from detectors.dns_tunneling import detect_dns_tunneling
from detectors.plaintext_creds import detect_plaintext_creds
from report_generator import generate_report, save_report


def main() -> int:
    parser = argparse.ArgumentParser(description="PCAP forensic analyzer")
    parser.add_argument("pcap", help="Path to .pcap / .pcapng file")
    parser.add_argument("--report", default=None,
                         help="Path to write the Markdown report (default: prints alert summary only)")
    parser.add_argument("--max-packets", type=int, default=None,
                         help="Cap on number of packets parsed (useful for huge captures)")
    args = parser.parse_args()

    print(f"[*] Parsing {args.pcap} ...")
    records = parse_pcap(args.pcap, max_packets=args.max_packets)
    print(f"[+] Parsed {len(records)} packets")

    print("[*] Extracting IOCs ...")
    iocs = extract_iocs(records)

    print("[*] Running detectors ...")
    port_scan_alerts = detect_port_scans(records)
    beacon_alerts = detect_beaconing(records)
    dns_alerts = detect_dns_tunneling(records)
    cred_alerts = detect_plaintext_creds(records)

    total = len(port_scan_alerts) + len(beacon_alerts) + len(dns_alerts) + len(cred_alerts)
    print(f"[+] {total} total alerts "
          f"(port scan: {len(port_scan_alerts)}, beaconing: {len(beacon_alerts)}, "
          f"dns tunneling: {len(dns_alerts)}, plaintext creds: {len(cred_alerts)})")

    for a in port_scan_alerts + beacon_alerts + dns_alerts + cred_alerts:
        print(f"  - [{a.severity}] {a.summary()}")

    if args.report:
        report_text = generate_report(
            pcap_name=args.pcap,
            records=records,
            iocs=iocs,
            port_scan_alerts=port_scan_alerts,
            beacon_alerts=beacon_alerts,
            dns_alerts=dns_alerts,
            cred_alerts=cred_alerts,
        )
        save_report(report_text, args.report)
        print(f"[+] Report written to {args.report}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
