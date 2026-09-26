"""
theme_manager.py
Light/Dark theme toggle, implemented purely via CSS-variable injection --
no analysis logic touched. Default mode is "dark", i.e. the existing,
unmodified SOC theme from ui_components.inject_theme() / design_system.py.
Selecting "Light" swaps in ui_styles.light_css_variables_block() instead.

app.py should call render_theme_toggle() once in the sidebar and
inject_selected_theme() once near the top of the page, replacing the
previous unconditional `inject_theme()` call -- when the toggle is left
on "Dark" the visual output is byte-for-byte the same as before.
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from design_system import css_variables_block
from ui_styles import light_css_variables_block

_THEME_CSS_PATH = Path(__file__).parent / "assets" / "theme.css"
_SESSION_KEY = "soc_theme_mode"


def get_theme_mode() -> str:
    """Returns 'dark' or 'light'. Defaults to 'dark' (existing behavior)."""
    return st.session_state.get(_SESSION_KEY, "dark")


def render_theme_toggle() -> str:
    """
    Renders a sidebar radio for Light/Dark mode and returns the selected
    mode. Call once per run, before inject_selected_theme().
    """
    current = get_theme_mode()
    choice = st.sidebar.radio(
        "🎨 Theme",
        options=["Dark", "Light"],
        index=0 if current == "dark" else 1,
        horizontal=True,
    )
    mode = choice.lower()
    st.session_state[_SESSION_KEY] = mode
    return mode


def inject_selected_theme() -> None:
    """
    Injects the CSS variable block for the currently selected theme mode,
    followed by the shared, theme-agnostic assets/theme.css (which only
    ever references var(--...) tokens, never raw colors).
    """
    mode = get_theme_mode()
    css = light_css_variables_block() if mode == "light" else css_variables_block()

    if _THEME_CSS_PATH.exists():
        css += "\n" + _THEME_CSS_PATH.read_text(encoding="utf-8")

    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)
