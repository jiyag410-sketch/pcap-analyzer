"""
mcp_server/server.py
MCP server entry point for the PCAP Forensic Analyzer.

Exposes the existing analysis pipeline (pcap_parser, calculate_statistics,
ioc_extractor, detectors/*, report_generator, communication_graph, hashing)
as MCP tools so an AI assistant (Claude Desktop, Claude Code, or any other
MCP client) can drive pcap analysis directly, without going through the
Streamlit dashboard.

The Streamlit dashboard (app.py) is completely independent of this server
and continues to work exactly as before -- this is a separate process that
happens to call the same underlying modules.

Run:
    python -m mcp_server.server                    # stdio transport (for local MCP clients)

Configure in a client (e.g. Claude Desktop's claude_desktop_config.json):
    {
      "mcpServers": {
        "pcap-analyzer": {
          "command": "python",
          "args": ["-m", "mcp_server.server"],
          "cwd": "/absolute/path/to/pcap-analyzer"
        }
      }
    }

NOTE: this package is named `mcp_server`, not `mcp` -- naming it `mcp`
would shadow the installed `mcp` SDK package (the one this file imports
FastMCP from), breaking that import. See MCP_INTEGRATION.md for details.
"""

from __future__ import annotations

import logging
from typing import Optional

from mcp.server.fastmcp import FastMCP

from mcp_server import tools as pcap_tools
from mcp_server.tools import PcapToolError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pcap_analyzer.mcp")

mcp = FastMCP(
    name="pcap-analyzer",
    instructions=(
        "Tools for forensic analysis of PCAP/PCAPNG network captures: parsing, "
        "traffic statistics, IOC extraction, threat detection (port scans, "
        "beaconing/C2, DNS tunneling, plaintext credentials), network graph "
        "summaries, evidence hashing, and Markdown report generation. All "
        "tools take a `pcap_path` pointing to a capture file on disk."
    ),
)


def _wrap(fn):
    """
    Converts a PcapToolError into a clear, actionable string result instead
    of letting the MCP transport raise a generic error -- so the assistant
    (and the person it's helping) gets a usable message rather than a stack trace.
    """

    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except PcapToolError as exc:
            logger.warning("Tool error in %s: %s", fn.__name__, exc)
            return {"error": str(exc)}

    wrapped.__name__ = fn.__name__
    wrapped.__doc__ = fn.__doc__
    return wrapped


@mcp.tool()
def analyze_pcap(pcap_path: str, max_packets: Optional[int] = None) -> dict:
    """Parse a pcap/pcapng file and return packet count plus a preview of the first records."""
    return _wrap(pcap_tools.analyze_pcap)(pcap_path, max_packets)


@mcp.tool()
def calculate_statistics(pcap_path: str, max_packets: Optional[int] = None) -> dict:
    """Return summary capture statistics: packet count, duration, bytes, unique IPs, sessions, protocol count."""
    return _wrap(pcap_tools.calculate_statistics_tool)(pcap_path, max_packets)


@mcp.tool()
def extract_iocs(pcap_path: str, max_packets: Optional[int] = None) -> dict:
    """Extract Indicators of Compromise: external IPs, internal IPs, domains, and URLs seen in the capture."""
    return _wrap(pcap_tools.extract_iocs_tool)(pcap_path, max_packets)


@mcp.tool()
def detect_port_scan(pcap_path: str, max_packets: Optional[int] = None) -> dict:
    """Detect likely port-scanning: one source hitting many distinct destination ports in a short window."""
    return _wrap(pcap_tools.detect_port_scan_tool)(pcap_path, max_packets)


@mcp.tool()
def detect_beaconing(pcap_path: str, max_packets: Optional[int] = None) -> dict:
    """Detect possible C2 beaconing: suspiciously regular-interval connections between a source/destination pair."""
    return _wrap(pcap_tools.detect_beaconing_tool)(pcap_path, max_packets)


@mcp.tool()
def detect_dns_tunneling(pcap_path: str, max_packets: Optional[int] = None) -> dict:
    """Detect possible DNS tunneling: high query volume with long, high-entropy subdomains to one root domain."""
    return _wrap(pcap_tools.detect_dns_tunneling_tool)(pcap_path, max_packets)


@mcp.tool()
def detect_plaintext_credentials(pcap_path: str, max_packets: Optional[int] = None) -> dict:
    """Scan packet payloads for cleartext credentials: HTTP form fields, FTP/Telnet auth, HTTP Basic auth."""
    return _wrap(pcap_tools.detect_plaintext_credentials_tool)(pcap_path, max_packets)


@mcp.tool()
def generate_report(pcap_path: str, max_packets: Optional[int] = None) -> dict:
    """Generate the full Markdown forensic report, identical to the Streamlit dashboard's Report tab."""
    return _wrap(pcap_tools.generate_report_tool)(pcap_path, max_packets)


@mcp.tool()
def generate_network_graph(pcap_path: str, max_packets: Optional[int] = None, top_n: int = 15) -> dict:
    """Return a JSON summary of the host communication graph: top N most-connected hosts and the edge list."""
    return _wrap(pcap_tools.generate_network_graph_tool)(pcap_path, max_packets, top_n)


@mcp.tool()
def calculate_hash(pcap_path: str) -> dict:
    """Compute MD5/SHA1/SHA256 of the pcap file for evidence integrity / chain-of-custody purposes."""
    return _wrap(pcap_tools.calculate_hash_tool)(pcap_path)


@mcp.tool()
def summary(pcap_path: str, max_packets: Optional[int] = None) -> dict:
    """One-call triage summary: statistics, IOC counts, and alert counts across all four detectors."""
    return _wrap(pcap_tools.summary_tool)(pcap_path, max_packets)


if __name__ == "__main__":
    mcp.run()
