"""
communication_graph.py

Builds an interactive communication graph showing
which hosts communicated with each other.
"""

import networkx as nx
import plotly.graph_objects as go


def build_graph(records):

    G = nx.DiGraph()

    for r in records:

        if not r.src_ip or not r.dst_ip:
            continue

        if G.has_edge(r.src_ip, r.dst_ip):

            G[r.src_ip][r.dst_ip]["count"] += 1

        else:

            G.add_edge(
                r.src_ip,
                r.dst_ip,
                count=1,
            )

    return G


def create_graph_figure(records):

    G = build_graph(records)

    if len(G.nodes) == 0:
        return None

    pos = nx.spring_layout(
        G,
        seed=42,
        k=0.8,
    )

    edge_x = []
    edge_y = []

    for edge in G.edges():

        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]

        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(

        x=edge_x,
        y=edge_y,

        mode="lines",

        hoverinfo="none",

        line=dict(
            width=1,
            color="#888",
        ),
    )

    node_x = []
    node_y = []
    node_text = []
    node_size = []

    for node in G.nodes():

        x, y = pos[node]

        node_x.append(x)
        node_y.append(y)

        degree = G.degree(node)

        node_size.append(15 + degree * 3)

        node_text.append(
            f"{node}<br>"
            f"Connections: {degree}"
        )

    node_trace = go.Scatter(

        x=node_x,
        y=node_y,

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

            colorbar=dict(
                title="Connections"
            ),
        ),
    )

    fig = go.Figure(

        data=[
            edge_trace,
            node_trace,
        ]
    )

    fig.update_layout(

        title="Network Communication Graph",

        showlegend=False,

        hovermode="closest",

        margin=dict(
            l=20,
            r=20,
            t=50,
            b=20,
        ),

        xaxis=dict(
            visible=False,
        ),

        yaxis=dict(
            visible=False,
        ),
    )

    return fig