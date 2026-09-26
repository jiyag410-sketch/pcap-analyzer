"""
rust_bridge.py
Bridge to the optional Rust acceleration extension (rust/, built via
maturin into `pcap_rust_accel`).

Design:
- If the compiled extension is importable, use it.
- If not (no Rust toolchain was available when this was deployed), fall back
  to a pure-Python implementation with IDENTICAL math -- the app must keep
  working with zero Rust toolchain present, per the original requirement.
- On import, run a correctness self-check comparing the two implementations
  on a handful of inputs. If they ever disagree, log a warning and force
  the pure-Python fallback rather than risk silently wrong detection output.

This module does not change detectors/dns_tunneling.py or
communication_graph.py -- those remain exactly as they were. This bridge
is consumed by new, additive wrapper functions (see performance.py's
*_accelerated functions), which are opt-in via config.APP_CONFIG.enable_rust_acceleration.
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from typing import Optional

logger = logging.getLogger("pcap_analyzer.rust_bridge")

RUST_AVAILABLE: bool
_backend: str

try:
    import pcap_rust_accel as _rust  # type: ignore

    RUST_AVAILABLE = True
    _backend = "rust"
except ImportError:
    _rust = None
    RUST_AVAILABLE = False
    _backend = "python"
    logger.info(
        "pcap_rust_accel extension not found -- falling back to pure-Python "
        "implementations. Build it with `cd rust && maturin build --release` "
        "and `pip install target/wheels/*.whl` to enable acceleration."
    )


# ---------------------------------------------------------------------------
# Pure-Python fallbacks -- same math as detectors/dns_tunneling.py::_entropy
# and communication_graph.py::build_graph's edge-counting loop. Kept here
# (not imported from those modules) so this bridge has no dependency on
# detector internals, and so the correctness self-check below is comparing
# two independent implementations, not the same code against itself.
# ---------------------------------------------------------------------------

def _entropy_python(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _batch_entropy_python(strings: list[str]) -> list[float]:
    return [_entropy_python(s) for s in strings]


def _aggregate_edges_python(pairs: list[tuple[str, str]]) -> list[tuple[str, str, int]]:
    order: list[tuple[str, str]] = []
    counts: dict[tuple[str, str], int] = {}
    for pair in pairs:
        if pair not in counts:
            order.append(pair)
            counts[pair] = 0
        counts[pair] += 1
    return [(src, dst, counts[(src, dst)]) for src, dst in order]


def _self_check() -> bool:
    """Compares Rust output against the Python fallback on fixed test inputs."""
    if not RUST_AVAILABLE:
        return True

    test_strings = ["", "a", "aaaa", "abc123", "x7z9q2w4v6", "example.com"]
    for s in test_strings:
        rust_val = _rust.shannon_entropy(s)
        py_val = _entropy_python(s)
        if abs(rust_val - py_val) > 1e-6:
            return False

    test_pairs = [("a", "b"), ("a", "b"), ("c", "d"), ("a", "b"), ("b", "a")]
    rust_edges = sorted(_rust.aggregate_edges(test_pairs))
    py_edges = sorted(_aggregate_edges_python(test_pairs))
    if rust_edges != py_edges:
        return False

    return True


if RUST_AVAILABLE and not _self_check():
    logger.warning(
        "pcap_rust_accel failed its correctness self-check against the "
        "Python reference implementation -- disabling Rust acceleration "
        "and using the pure-Python fallback instead."
    )
    RUST_AVAILABLE = False
    _backend = "python (self-check failed)"


def backend() -> str:
    """Returns which implementation is currently active: 'rust' or 'python'."""
    return _backend


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char. Rust-accelerated if available, else pure Python."""
    if RUST_AVAILABLE:
        return _rust.shannon_entropy(s)
    return _entropy_python(s)


def batch_shannon_entropy(strings: list[str]) -> list[float]:
    """Batched shannon_entropy -- avoids per-call FFI overhead when scoring many subdomains."""
    if RUST_AVAILABLE:
        return _rust.batch_shannon_entropy(strings)
    return _batch_entropy_python(strings)


def aggregate_edges(pairs: list[tuple[str, str]]) -> list[tuple[str, str, int]]:
    """
    Aggregates (src, dst) pairs into (src, dst, count) edges, preserving
    first-appearance order, matching communication_graph.py's edge-count
    semantics. Rust-accelerated if available, else pure Python.
    """
    if RUST_AVAILABLE:
        return _rust.aggregate_edges(pairs)
    return _aggregate_edges_python(pairs)
