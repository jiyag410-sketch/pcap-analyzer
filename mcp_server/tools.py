"""
mcp_server/tools.py
Wrapper functions exposed as MCP tools. Every function here is a thin
adapter: it calls an existing, unmodified function from the project root
(pcap_parser, calculate_statistics, ioc_extractor, hashing, detectors/*,
report_generator, communication_graph) and converts the result into plain
JSON-serializable data (dicts/lists/str/numbers) for the MCP transport.

No detection thresholds, parsing rules, or report formatting logic live in
this file -- they all remain in their original modules, exactly as before.
"""

from __future__ import annotations

import os
import sys
from dataclasses import asdict
from typing import Optional

# Make the project root importable regardless of where this module is run from.
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from calculate_statistics import calculate_statistics  # noqa: E402
from communication_graph import build_graph  # noqa: E402
from detectors.beaconing import detect_beaconing  # noqa: E402
from detectors.dns_tunneling import detect_dns_tunneling  # noqa: E402
from detectors.plaintext_creds import detect_plaintext_creds  # noqa: E402
from detectors.port_scan import detect_port_scans  # noqa: E402
from hashing import calculate_hashes  # noqa: E402
from ioc_extractor import extract_iocs  # noqa: E402
from models import PacketRecord  # noqa: E402
from pcap_parser import parse_pcap  # noqa: E402
from report_generator import generate_report  # noqa: E402

# In-process cache so a sequence of tool calls against the same pcap
# (e.g. "calculate_statistics" then "detect_beaconing" then "generate_report")
# doesn't re-parse the file from scratch every time. Keyed on
# (absolute path, max_packets, file mtime) so edits/replacements invalidate it.
_records_cache: dict[tuple[str, Optional[int], float], list[PacketRecord]] = {}


class PcapToolError(Exception):
    """Raised for actionable, user-facing tool errors (bad path, unreadable file, etc)."""


def _resolve_and_check(pcap_path: str) -> str:
    abs_path = os.path.abspath(os.path.expanduser(pcap_path))
    if not os.path.isfile(abs_path):
        raise PcapToolError(
            f"No such file: '{pcap_path}'. Provide an absolute path or a path "
            "relative to the directory the MCP server was started from."
        )
    return abs_path


def _get_records(pcap_path: str, max_packets: Optional[int] = None) -> list[PacketRecord]:
    abs_path = _resolve_and_check(pcap_path)
    mtime = os.path.getmtime(abs_path)
    key = (abs_path, max_packets, mtime)

    if key not in _records_cache:
        try:
            _records_cache[key] = parse_pcap(abs_path, max_packets=max_packets)
        except Exception as exc:  # scapy raises various exception types for bad files
            raise PcapToolError(
                f"Failed to parse '{pcap_path}': {exc}. "
                "Confirm the file is a valid .pcap/.pcapng capture."
            ) from exc

    return _records_cache[key]


def _alert_to_dict(alert) -> dict:
    """Converts any of the detector alert dataclasses to a plain dict, including its summary."""
    d = asdict(alert)
    # dst_ips on PortScanAlert is a set -- not JSON serializable, convert to sorted list
    for k, v in list(d.items()):
        if isinstance(v, set):
            d[k] = sorted(v)
    d["summary"] = alert.summary()
    return d


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def analyze_pcap(pcap_path: str, max_packets: Optional[int] = None) -> dict:
    """
    Parses a pcap/pcapng file and returns basic parse-level facts: packet
    count and a preview of the first few records. Use this first to confirm
    a capture is readable before running statistics/detectors/reports on it.
    """
    records = _get_records(pcap_path, max_packets)
    preview = [
        {
            "index": r.index,
            "timestamp": r.timestamp,
            "src_ip": r.src_ip,
            "dst_ip": r.dst_ip,
            "protocol": r.protocol,
            "length": r.length,
        }
        for r in records[:10]
    ]
    return {"pcap_path": pcap_path, "packet_count": len(records), "preview": preview}


def calculate_statistics_tool(pcap_path: str, max_packets: Optional[int] = None) -> dict:
    """Returns summary capture statistics (packet count, duration, bytes, unique IPs, sessions, protocols)."""
    records = _get_records(pcap_path, max_packets)
    return asdict(calculate_statistics(records))


def extract_iocs_tool(pcap_path: str, max_packets: Optional[int] = None) -> dict:
    """Extracts Indicators of Compromise: external/internal IPs, domains, and URLs."""
    records = _get_records(pcap_path, max_packets)
    return extract_iocs(records).to_dict()


def detect_port_scan_tool(pcap_path: str, max_packets: Optional[int] = None) -> dict:
    """Detects likely port-scanning behavior (many distinct destination ports from one source in a short window)."""
    records = _get_records(pcap_path, max_packets)
    alerts = detect_port_scans(records)
    return {"alert_count": len(alerts), "alerts": [_alert_to_dict(a) for a in alerts]}


def detect_beaconing_tool(pcap_path: str, max_packets: Optional[int] = None) -> dict:
    """Detects possible C2 beaconing (suspiciously regular-interval connections between a host pair)."""
    records = _get_records(pcap_path, max_packets)
    alerts = detect_beaconing(records)
    return {"alert_count": len(alerts), "alerts": [_alert_to_dict(a) for a in alerts]}


def detect_dns_tunneling_tool(pcap_path: str, max_packets: Optional[int] = None) -> dict:
    """Detects possible DNS tunneling (high query volume + long, high-entropy subdomains to one root domain)."""
    records = _get_records(pcap_path, max_packets)
    alerts = detect_dns_tunneling(records)
    return {"alert_count": len(alerts), "alerts": [_alert_to_dict(a) for a in alerts]}


def detect_plaintext_credentials_tool(pcap_path: str, max_packets: Optional[int] = None) -> dict:
    """Scans packet payloads for cleartext credential patterns (HTTP form fields, FTP/Telnet auth, HTTP Basic auth)."""
    records = _get_records(pcap_path, max_packets)
    alerts = detect_plaintext_creds(records)
    return {"alert_count": len(alerts), "alerts": [_alert_to_dict(a) for a in alerts]}


def calculate_hash_tool(pcap_path: str) -> dict:
    """Computes MD5/SHA1/SHA256 of the pcap file itself, for evidence integrity/chain-of-custody purposes."""
    abs_path = _resolve_and_check(pcap_path)
    return calculate_hashes(abs_path)


def generate_network_graph_tool(pcap_path: str, max_packets: Optional[int] = None, top_n: int = 15) -> dict:
    """
    Builds the host communication graph and returns a JSON-friendly summary
    (top N nodes by connection count and the edge list with packet counts) --
    the same graph data communication_graph.py uses to render the interactive
    Plotly figure in the dashboard, just serialized instead of plotted.
    """
    records = _get_records(pcap_path, max_packets)
    graph = build_graph(records)

    if graph.number_of_nodes() == 0:
        return {"node_count": 0, "edge_count": 0, "top_nodes": [], "edges": []}

    top_nodes = sorted(graph.degree, key=lambda x: x[1], reverse=True)[:top_n]
    edges = [
        {"src": u, "dst": v, "packet_count": data.get("count", 1)}
        for u, v, data in graph.edges(data=True)
    ]

    return {
        "node_count": graph.number_of_nodes(),
        "edge_count": graph.number_of_edges(),
        "top_nodes": [{"ip": ip, "connections": degree} for ip, degree in top_nodes],
        "edges": edges,
    }


def generate_report_tool(pcap_path: str, max_packets: Optional[int] = None) -> dict:
    """Generates the full Markdown forensic report (identical to the Streamlit dashboard's Report tab)."""
    records = _get_records(pcap_path, max_packets)
    iocs = extract_iocs(records)
    port_scan_alerts = detect_port_scans(records)
    beacon_alerts = detect_beaconing(records)
    dns_alerts = detect_dns_tunneling(records)
    cred_alerts = detect_plaintext_creds(records)

    report_text = generate_report(
        pcap_name=os.path.basename(pcap_path),
        records=records,
        iocs=iocs,
        port_scan_alerts=port_scan_alerts,
        beacon_alerts=beacon_alerts,
        dns_alerts=dns_alerts,
        cred_alerts=cred_alerts,
    )
    return {"pcap_path": pcap_path, "report_markdown": report_text}


def summary_tool(pcap_path: str, max_packets: Optional[int] = None) -> dict:
    """
    One-call triage summary: stats, IOC counts, and alert counts from every
    detector, without the full alert detail. Good first call for "give me
    the headline picture of this capture" style requests.
    """
    records = _get_records(pcap_path, max_packets)
    stats = calculate_statistics(records)
    iocs = extract_iocs(records)
    port_scan_alerts = detect_port_scans(records)
    beacon_alerts = detect_beaconing(records)
    dns_alerts = detect_dns_tunneling(records)
    cred_alerts = detect_plaintext_creds(records)

    total_alerts = len(port_scan_alerts) + len(beacon_alerts) + len(dns_alerts) + len(cred_alerts)

    return {
        "pcap_path": pcap_path,
        "statistics": asdict(stats),
        "ioc_counts": {
            "external_ips": len(iocs.external_ips),
            "internal_ips": len(iocs.internal_ips),
            "domains": len(iocs.domains),
            "urls": len(iocs.urls),
        },
        "alert_counts": {
            "port_scan": len(port_scan_alerts),
            "beaconing": len(beacon_alerts),
            "dns_tunneling": len(dns_alerts),
            "plaintext_credentials": len(cred_alerts),
            "total": total_alerts,
        },
    }
