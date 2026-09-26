"""
mcp_server/
Standalone MCP (Model Context Protocol) server package that exposes the
PCAP Forensic Analyzer's existing analysis pipeline as tools an AI
assistant can call directly (Claude Desktop, Claude Code, etc).

This package wraps -- never duplicates -- the logic in the project root:
pcap_parser.py, calculate_statistics.py, ioc_extractor.py, hashing.py,
detectors/*.py, report_generator.py, and communication_graph.py.

Run with:
    python -m mcp_server.server
"""
