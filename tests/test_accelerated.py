"""
tests/test_accelerated.py
Verifies the Rust-accelerated implementations in accelerated.py produce
output identical to the original, unmodified functions in
detectors/dns_tunneling.py and communication_graph.py.
"""

from __future__ import annotations

import random

from accelerated import build_graph_accelerated, detect_dns_tunneling_accelerated
from communication_graph import build_graph
from detectors.dns_tunneling import detect_dns_tunneling
from models import PacketRecord


def _dns_record(i: int, query: str) -> PacketRecord:
    return PacketRecord(
        index=i,
        timestamp=i * 0.01,
        src_ip="10.0.0.5",
        dst_ip="8.8.8.8",
        protocol="DNS",
        dns_query=query,
    )


def test_dns_tunneling_accelerated_matches_original_no_alert():
    records = [_dns_record(i, f"host{i}.example.com") for i in range(30)]
    assert detect_dns_tunneling(records) == detect_dns_tunneling_accelerated(records)


def test_dns_tunneling_accelerated_matches_original_with_alert():
    random.seed(1)
    charset = "abcdef0123456789"
    records = []
    for i in range(40):
        subdomain = "".join(random.choice(charset) for _ in range(40))
        records.append(_dns_record(i, f"{subdomain}.evil-tunnel.com"))

    original = detect_dns_tunneling(records)
    accelerated = detect_dns_tunneling_accelerated(records)

    assert len(original) == len(accelerated) == 1
    assert original[0].root_domain == accelerated[0].root_domain
    assert original[0].query_count == accelerated[0].query_count
    assert abs(original[0].avg_subdomain_length - accelerated[0].avg_subdomain_length) < 1e-9
    assert abs(original[0].avg_entropy - accelerated[0].avg_entropy) < 1e-6
    assert original[0].severity == accelerated[0].severity


def test_build_graph_accelerated_matches_original():
    random.seed(2)
    ips = [f"10.0.0.{i}" for i in range(1, 15)]
    records = []
    for i in range(500):
        src, dst = random.choice(ips), random.choice(ips)
        records.append(PacketRecord(index=i, timestamp=i * 0.001, src_ip=src, dst_ip=dst))

    g_original = build_graph(records)
    g_accelerated = build_graph_accelerated(records)

    original_edges = {(u, v): d["count"] for u, v, d in g_original.edges(data=True)}
    accelerated_edges = {(u, v): d["count"] for u, v, d in g_accelerated.edges(data=True)}

    assert original_edges == accelerated_edges
    assert set(g_original.nodes) == set(g_accelerated.nodes)


def test_build_graph_accelerated_empty_records():
    g = build_graph_accelerated([])
    assert len(g.nodes) == 0
