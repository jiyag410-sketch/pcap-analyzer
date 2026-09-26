"""
ui_components.py
Reusable, presentation-only Streamlit components for the SOC-style theme.

These functions render HTML/CSS or restyle existing Plotly figures. None of
them contain analysis logic -- every function takes already-computed values
(stats, alert lists, figures) and only changes how they're displayed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import streamlit as st

from design_system import SEVERITY_COLOR_MAP, css_variables_block, plotly_dark_template

_THEME_CSS_PATH = Path(__file__).parent / "assets" / "theme.css"


def inject_theme() -> None:
    """
    Injects the CSS variable block (design_system) and the static
    stylesheet (assets/theme.css) into the page. Call once, near the top
    of app.py, before any other UI is rendered.
    """
    css = css_variables_block()
    if _THEME_CSS_PATH.exists():
        css += "\n" + _THEME_CSS_PATH.read_text(encoding="utf-8")
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


def render_hero_banner(title: str, subtitle: str) -> None:
    """Renders the gradient hero banner at the top of the dashboard."""
    st.markdown(
        f"""
        <div class="soc-hero">
            <h1>{title}</h1>
            <p>{subtitle}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metric_card(icon: str, label: str, value: str) -> None:
    """
    Renders a single glassmorphism metric card. Use inside st.columns(),
    one call per column, exactly like st.metric() is used today -- this is
    a drop-in visual replacement, not a change to what data is shown.
    """
    st.markdown(
        f"""
        <div class="soc-metric-card">
            <div class="soc-metric-icon">{icon}</div>
            <div class="soc-metric-label">{label}</div>
            <div class="soc-metric-value">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_status_chip(severity: str) -> str:
    """
    Returns (does not render directly) an HTML status chip for a given
    severity string ("HIGH", "MEDIUM", "LOW", "OK", "CRITICAL"). Intended
    for use inside st.markdown(..., unsafe_allow_html=True) calls or when
    building HTML tables. Falls back gracefully for unknown severities.
    """
    severity_upper = (severity or "").upper()
    color = SEVERITY_COLOR_MAP.get(severity_upper, SEVERITY_COLOR_MAP["LOW"])
    css_class = f"soc-chip-{severity_upper.lower()}" if severity_upper in SEVERITY_COLOR_MAP else "soc-chip-low"
    return f'<span class="soc-chip {css_class}">{severity_upper or "UNKNOWN"}</span>'


def render_section_header(icon: str, title: str, caption: Optional[str] = None) -> None:
    """Consistent section header used across tabs, replacing bare st.header/st.subheader calls."""
    st.markdown(f"### {icon} {title}")
    if caption:
        st.caption(caption)


def style_plotly_figure(fig):
    """
    Applies the SOC dark template to an already-built Plotly figure.
    Takes a figure returned by the existing chart functions (charts.py,
    communication_graph.py, or inline px calls in app.py) and restyles
    layout only -- traces/data are untouched.
    """
    if fig is None:
        return fig
    fig.update_layout(**plotly_dark_template()["layout"])
    return fig


def render_footer() -> None:
    """Renders the professional footer at the bottom of the dashboard."""
    st.markdown(
        """
        <div class="soc-footer">
            PCAP Forensic Analyzer &middot; Enterprise Edition &middot;
            For authorized security investigations only
        </div>
        """,
        unsafe_allow_html=True,
    )
