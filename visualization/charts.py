"""
charts.py
Creates Plotly charts for the PCAP Forensic Dashboard.
These functions only build figures—they do not display them.
"""

from __future__ import annotations

import pandas as pd
import plotly.express as px

from models import PacketRecord

def protocol_pie_chart(records: list[PacketRecord]):
    """
    Creates a pie chart showing protocol distribution.
    """

    if not records:
        return None

    protocol_df = pd.DataFrame(
        {
            "Protocol": [r.protocol for r in records]
        }
    )

    protocol_counts = (
        protocol_df["Protocol"]
        .value_counts()
        .reset_index()
    )

    protocol_counts.columns = ["Protocol", "Count"]

    fig = px.pie(
        protocol_counts,
        names="Protocol",
        values="Count",
        title="Protocol Distribution",
    )

    return fig
