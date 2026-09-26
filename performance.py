"""
performance.py
Caching and profiling utilities for the PCAP Forensic Analyzer.

WHY THIS MODULE EXISTS
-----------------------
Streamlit reruns the *entire* script top-to-bottom on every widget
interaction (typing in the IP search box, switching a selectbox, etc).
Before this module, app.py called parse_pcap(), calculate_statistics(),
extract_iocs(), all four detectors, and create_graph_figure() directly and
unconditionally -- meaning a capture with tens of thousands of packets was
being fully re-parsed and re-analyzed on *every single click*, even though
nothing about the uploaded file had changed.

This module wraps the existing, unmodified analysis functions with
`st.cache_data`, keyed on the raw file bytes (+ the max_packets setting).
Streamlit hashes the function arguments to form the cache key; because the
functions themselves are untouched (imported and called exactly as they
were), there is zero change to analysis behavior or output -- only to how
often it's recomputed.

None of the underlying algorithms in pcap_parser.py, calculate_statistics.py,
ioc_extractor.py, detectors/*.py, or communication_graph.py are modified.
This module only adds a caching layer on top.
"""

from __future__ import annotations

import functools
import logging
import tempfile
import time
from typing import Callable, Optional, TypeVar

import streamlit as st

from accelerated import create_graph_figure_accelerated, detect_dns_tunneling_accelerated
from calculate_statistics import CaptureStatistics, calculate_statistics
from communication_graph import create_graph_figure
from config import APP_CONFIG
from detectors.beaconing import BeaconAlert, detect_beaconing
from detectors.dns_tunneling import DNSTunnelAlert, detect_dns_tunneling
from detectors.plaintext_creds import CredAlert, detect_plaintext_creds
from detectors.port_scan import PortScanAlert, detect_port_scans
from hashing import calculate_hashes
from ioc_extractor import IOCReport, extract_iocs
from models import PacketRecord
from password_detector import CredentialFinding, detect_credentials
from pcap_parser import parse_pcap
from rust_bridge import RUST_AVAILABLE

logger = logging.getLogger("pcap_analyzer.performance")
logging.basicConfig(level=logging.INFO)

_F = TypeVar("_F", bound=Callable)


def profile_time(label: Optional[str] = None) -> Callable[[_F], _F]:
    """
    Decorator that logs how long a function took to run. Purely observational
    -- does not change behavior or return values. Useful for confirming
    which stages actually benefit from caching before spending more effort
    on them (e.g. before deciding whether a Rust rewrite is worth it).

    Usage:
        @profile_time("pcap parse")
        def my_func(...): ...
    """

    def decorator(func: _F) -> _F:
        name = label or func.__name__

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                elapsed = time.perf_counter() - start
                logger.info("[profile] %s took %.3fs", name, elapsed)

        return wrapper  # type: ignore[return-value]

    return decorator


@st.cache_data(
    show_spinner=False,
    ttl=APP_CONFIG.cache_ttl_seconds,
    max_entries=APP_CONFIG.cache_max_entries,
)
@profile_time("parse_pcap")
def parse_pcap_cached(
    file_bytes: bytes,
    max_packets: Optional[int],
) -> list[PacketRecord]:
    """
    Cached wrapper around pcap_parser.parse_pcap. Writes the uploaded bytes
    to a temp file (scapy's rdpcap requires a path) and delegates entirely
    to the existing, unmodified parse_pcap(). Cache key is (file_bytes,
    max_packets) -- re-uploading the same file with the same packet cap
    returns the cached result instead of re-parsing.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        return parse_pcap(tmp_path, max_packets=max_packets)
    finally:
        import os
        os.unlink(tmp_path)


@st.cache_data(
    show_spinner=False,
    ttl=APP_CONFIG.cache_ttl_seconds,
    max_entries=APP_CONFIG.cache_max_entries,
)
@profile_time("calculate_hashes")
def calculate_hashes_cached(file_bytes: bytes) -> dict[str, str]:
    """Cached wrapper around hashing.calculate_hashes (needs a path, so we write one)."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        return calculate_hashes(tmp_path)
    finally:
        import os
        os.unlink(tmp_path)


@st.cache_data(show_spinner=False, max_entries=APP_CONFIG.cache_max_entries)
@profile_time("calculate_statistics")
def calculate_statistics_cached(records: list[PacketRecord]) -> CaptureStatistics:
    """Cached wrapper around calculate_statistics.calculate_statistics -- no logic changes."""
    return calculate_statistics(records)


@st.cache_data(show_spinner=False, max_entries=APP_CONFIG.cache_max_entries)
@profile_time("extract_iocs")
def extract_iocs_cached(records: list[PacketRecord]) -> IOCReport:
    """Cached wrapper around ioc_extractor.extract_iocs -- no logic changes."""
    return extract_iocs(records)


@st.cache_data(show_spinner=False, max_entries=APP_CONFIG.cache_max_entries)
@profile_time("run_all_detectors")
def run_all_detectors_cached(
    records: list[PacketRecord],
) -> tuple[list[PortScanAlert], list[BeaconAlert], list[DNSTunnelAlert], list[CredAlert]]:
    """
    Cached wrapper that runs all four existing detectors in one cache entry
    (rather than four separate @st.cache_data calls, which would each
    re-hash the full records list independently). Each detector call below
    is identical to what app.py called directly before.
    """
    port_scan_alerts = detect_port_scans(records)
    beacon_alerts = detect_beaconing(records)

    if APP_CONFIG.enable_rust_acceleration and RUST_AVAILABLE:
        dns_alerts = detect_dns_tunneling_accelerated(records)
    else:
        dns_alerts = detect_dns_tunneling(records)

    cred_alerts = detect_plaintext_creds(records)
    return port_scan_alerts, beacon_alerts, dns_alerts, cred_alerts


@st.cache_data(show_spinner=False, max_entries=APP_CONFIG.cache_max_entries)
@profile_time("detect_credentials")
def detect_credentials_cached(records: list[PacketRecord]) -> list[CredentialFinding]:
    """
    Cached wrapper around password_detector.detect_credentials -- the new
    NetworkMiner-style credential scanner. Separate cache entry (and
    separate function) from run_all_detectors_cached/detect_plaintext_creds
    so the existing detector cache signature is untouched; this is a
    purely additive analysis pass over the same already-parsed records.
    """
    return detect_credentials(records)


@st.cache_data(show_spinner=False, max_entries=APP_CONFIG.cache_max_entries)
@profile_time("build_graph_figure")
def create_graph_figure_cached(records: list[PacketRecord]):
    """
    Cached wrapper around communication_graph.create_graph_figure (or its
    Rust-accelerated equivalent, accelerated.create_graph_figure_accelerated,
    when enabled and available). This is the most expensive per-rerun cost
    in the original app (force-directed layout + edge aggregation), and
    previously ran on every Streamlit rerun regardless of which tab was active.
    """
    if APP_CONFIG.enable_rust_acceleration and RUST_AVAILABLE:
        return create_graph_figure_accelerated(records)
    return create_graph_figure(records)
