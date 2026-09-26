"""
accelerated.py
Rust-accelerated versions of the two hot paths identified in the
architecture review: DNS-tunneling entropy scoring and communication-graph
edge aggregation.

IMPORTANT: this module does NOT modify detectors/dns_tunneling.py or
communication_graph.py. Both remain exactly as they were. Instead, this
module imports their constants and small helpers (_root_domain,
MIN_QUERIES_TO_DOMAIN, etc.) and re-implements only the orchestration loop,
swapping the per-string entropy calculation and the edge-counting loop for
calls into rust_bridge (which itself falls back to pure Python if the Rust
extension isn't built).

Output is verified identical to the original functions -- see
tests/test_accelerated.py, which runs both implementations on the same
input and asserts equality. This is what makes it safe to use as a drop-in
replacement in performance.py, gated by config.APP_CONFIG.enable_rust_acceleration.
"""

from __future__ import annotations

from collections import defaultdict

import networkx as nx

import rust_bridge
from detectors.dns_tunneling import (
    MIN_AVG_SUBDOMAIN_LEN,
    MIN_ENTROPY,
    MIN_QUERIES_TO_DOMAIN,
    DNSTunnelAlert,
    _root_domain,
)
from models import PacketRecord


def detect_dns_tunneling_accelerated(records: list[PacketRecord]) -> list[DNSTunnelAlert]:
    """
    Identical detection logic/thresholds to detectors.dns_tunneling.detect_dns_tunneling,
    but scores all subdomains for a root domain in one batched Rust call
    instead of one Python function call per subdomain.
    """
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

        entropies = rust_bridge.batch_shannon_entropy(subdomains)
        avg_ent = sum(entropies) / len(entropies)

        if avg_len >= MIN_AVG_SUBDOMAIN_LEN and avg_ent >= MIN_ENTROPY:
            alerts.append(DNSTunnelAlert(
                root_domain=root,
                query_count=len(queries),
                avg_subdomain_length=avg_len,
                avg_entropy=avg_ent,
                severity="HIGH" if avg_ent >= 4.0 else "MEDIUM",
            ))

    return alerts


def build_graph_accelerated(records: list[PacketRecord]) -> nx.DiGraph:
    """
    Identical output to communication_graph.build_graph, but counts
    (src, dst) edges in one Rust pass instead of a per-record Python loop
    with dict/graph lookups.
    """
    pairs = [(r.src_ip, r.dst_ip) for r in records if r.src_ip and r.dst_ip]
    edges = rust_bridge.aggregate_edges(pairs)

    G = nx.DiGraph()
    for src, dst, count in edges:
        G.add_edge(src, dst, count=count)
    return G


def create_graph_figure_accelerated(records: list[PacketRecord]):
    """
    Same Plotly figure as communication_graph.create_graph_figure (same
    spring_layout params, same trace styling) -- only the edge-counting
    step that feeds the graph is accelerated. This intentionally does not
    monkey-patch communication_graph's shared module state: Streamlit can
    run multiple sessions concurrently in one process, and patching a
    module-level function would be a race condition across sessions. The
    figure-building code below is a verified-identical copy instead (see
    tests/test_accelerated.py, which asserts this produces the same trace
    data as the original for the same graph).
    """
    import plotly.graph_objects as go

    G = build_graph_accelerated(records)

    if len(G.nodes) == 0:
        return None

    pos = nx.spring_layout(G, seed=42, k=0.8)

    edge_x, edge_y = [], []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        mode="lines",
        hoverinfo="none",
        line=dict(width=1, color="#888"),
    )

    node_x, node_y, node_text, node_size = [], [], [], []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        degree = G.degree(node)
        node_size.append(15 + degree * 3)
        node_text.append(f"{node}<br>Connections: {degree}")

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        textposition="top center",
        text=list(G.nodes),
        hovertext=node_text,
        hoverinfo="text",
        marker=dict(
            size=node_size,
            color=node_size,
            colorscale="Turbo",
            line=dict(width=2),
            showscale=True,
            colorbar=dict(title="Connections"),
        ),
    )

    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(
        title="Network Communication Graph",
        showlegend=False,
        hovermode="closest",
        margin=dict(l=20, r=20, t=50, b=20),
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
    )

    return fig
