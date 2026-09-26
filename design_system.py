"""
design_system.py
Design tokens for the enterprise SOC-style theme (colors, typography,
spacing, radii). This is the single source of truth for the visual
language -- ui_components.py and assets/theme.css both consume it.

Nothing in this module touches analysis logic; it is purely presentational.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ColorTokens:
    # Backgrounds -- deep navy/graphite, not pure black (matches Defender XDR / Cortex)
    bg_primary: str = "#0a0e17"
    bg_secondary: str = "#10151f"
    bg_surface: str = "rgba(255, 255, 255, 0.035)"
    bg_surface_hover: str = "rgba(255, 255, 255, 0.06)"
    border: str = "rgba(148, 163, 184, 0.12)"

    # Single restrained accent (calmer than a loud dual-tone gradient
    # everywhere) -- used sparingly for emphasis, not as a wall-to-wall wash
    accent_start: str = "#0891b2"   # cyan-600, slightly deeper/calmer
    accent_end: str = "#4f46e5"     # indigo-600
    accent_solid: str = "#22d3ee"

    # Severity palette
    severity_critical: str = "#f43f5e"
    severity_high: str = "#fb923c"
    severity_medium: str = "#facc15"
    severity_low: str = "#38bdf8"
    severity_ok: str = "#34d399"

    # Text
    text_primary: str = "#f1f5f9"
    text_secondary: str = "#94a3b8"
    text_muted: str = "#64748b"


@dataclass(frozen=True)
class TypographyTokens:
    font_family: str = (
        "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', "
        "system-ui, sans-serif"
    )
    font_family_mono: str = (
        "'JetBrains Mono', 'Fira Code', ui-monospace, SFMono-Regular, monospace"
    )
    # Larger, more confident scale -- editorial-style type rather than
    # cramped default-dashboard sizing
    size_hero: str = "2.75rem"
    size_h2: str = "1.6rem"
    size_body: str = "1rem"
    size_small: str = "0.82rem"
    weight_hero: str = "700"
    letter_spacing_hero: str = "-0.02em"


@dataclass(frozen=True)
class SpacingTokens:
    radius_sm: str = "10px"
    radius_md: str = "18px"
    radius_lg: str = "26px"
    gap_sm: str = "0.6rem"
    gap_md: str = "1.25rem"
    gap_lg: str = "2.25rem"


COLORS = ColorTokens()
TYPOGRAPHY = TypographyTokens()
SPACING = SpacingTokens()

SEVERITY_COLOR_MAP: dict[str, str] = {
    "CRITICAL": COLORS.severity_critical,
    "HIGH": COLORS.severity_high,
    "MEDIUM": COLORS.severity_medium,
    "LOW": COLORS.severity_low,
    "OK": COLORS.severity_ok,
}


def css_variables_block() -> str:
    """
    Renders all design tokens as a :root { --var: value; } CSS block.
    assets/theme.css references these variables, so this must be injected
    into the page *before* (or alongside) theme.css.
    """
    return f"""
    :root {{
        --bg-primary: {COLORS.bg_primary};
        --bg-secondary: {COLORS.bg_secondary};
        --bg-surface: {COLORS.bg_surface};
        --bg-surface-hover: {COLORS.bg_surface_hover};
        --border-color: {COLORS.border};

        --accent-start: {COLORS.accent_start};
        --accent-end: {COLORS.accent_end};
        --accent-solid: {COLORS.accent_solid};
        --accent-gradient: linear-gradient(135deg, {COLORS.accent_start}, {COLORS.accent_end});

        --severity-critical: {COLORS.severity_critical};
        --severity-high: {COLORS.severity_high};
        --severity-medium: {COLORS.severity_medium};
        --severity-low: {COLORS.severity_low};
        --severity-ok: {COLORS.severity_ok};

        --text-primary: {COLORS.text_primary};
        --text-secondary: {COLORS.text_secondary};
        --text-muted: {COLORS.text_muted};

        --font-family: {TYPOGRAPHY.font_family};
        --font-family-mono: {TYPOGRAPHY.font_family_mono};
        --size-hero: {TYPOGRAPHY.size_hero};
        --size-h2: {TYPOGRAPHY.size_h2};
        --size-body: {TYPOGRAPHY.size_body};
        --size-small: {TYPOGRAPHY.size_small};
        --weight-hero: {TYPOGRAPHY.weight_hero};
        --letter-spacing-hero: {TYPOGRAPHY.letter_spacing_hero};

        --radius-sm: {SPACING.radius_sm};
        --radius-md: {SPACING.radius_md};
        --radius-lg: {SPACING.radius_lg};
        --gap-sm: {SPACING.gap_sm};
        --gap-md: {SPACING.gap_md};
        --gap-lg: {SPACING.gap_lg};
    }}
    """


def plotly_dark_template() -> dict:
    """
    A Plotly layout template dict matching the SOC theme, applied via
    fig.update_layout(template=...) to figures that already exist
    (charts.py, communication_graph.py, and the inline px calls in app.py).
    No chart *data* logic is touched -- only layout/styling.
    """
    return {
        "layout": {
            "paper_bgcolor": "rgba(0,0,0,0)",
            "plot_bgcolor": "rgba(0,0,0,0)",
            "font": {"family": TYPOGRAPHY.font_family, "color": COLORS.text_primary},
            "title": {"font": {"size": 16, "color": COLORS.text_primary}},
            "legend": {"font": {"color": COLORS.text_secondary}},
            "xaxis": {
                "gridcolor": "rgba(148, 163, 184, 0.12)",
                "linecolor": COLORS.border,
                "color": COLORS.text_secondary,
            },
            "yaxis": {
                "gridcolor": "rgba(148, 163, 184, 0.12)",
                "linecolor": COLORS.border,
                "color": COLORS.text_secondary,
            },
            "colorway": [
                COLORS.accent_solid, COLORS.accent_end, COLORS.severity_high,
                COLORS.severity_medium, COLORS.severity_ok, COLORS.severity_critical,
            ],
        }
    }
