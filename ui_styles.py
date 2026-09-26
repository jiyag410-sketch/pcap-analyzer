"""
ui_styles.py
A second, brighter color palette for the dashboard, additive to
design_system.py. The existing dark SOC theme (design_system.COLORS) is
completely untouched and remains the default -- this module only adds a
light alternative that theme_manager.py can swap in.

Reuses ColorTokens/TypographyTokens/SpacingTokens from design_system.py
(same dataclasses, just different field values) so assets/theme.css --
which only references CSS variable names, never raw colors -- works
unmodified under either theme.
"""

from __future__ import annotations

from design_system import ColorTokens, SPACING, TYPOGRAPHY

LIGHT_COLORS = ColorTokens(
    bg_primary="#F8FAFC",
    bg_secondary="#FFFFFF",
    bg_surface="rgba(15, 23, 42, 0.035)",
    bg_surface_hover="rgba(15, 23, 42, 0.06)",
    border="rgba(100, 116, 139, 0.18)",

    accent_start="#3B82F6",   # blue
    accent_end="#06B6D4",     # cyan
    accent_solid="#3B82F6",

    severity_critical="#EF4444",
    severity_high="#F59E0B",
    severity_medium="#F59E0B",
    severity_low="#06B6D4",
    severity_ok="#10B981",

    text_primary="#0f172a",
    text_secondary="#475569",
    text_muted="#94a3b8",
)


def light_css_variables_block() -> str:
    """
    Same shape as design_system.css_variables_block(), but built from
    LIGHT_COLORS instead of the module-level dark COLORS. Typography and
    spacing tokens are shared with the dark theme -- only color changes.
    """
    c = LIGHT_COLORS
    return f"""
    :root {{
        --bg-primary: {c.bg_primary};
        --bg-secondary: {c.bg_secondary};
        --bg-surface: {c.bg_surface};
        --bg-surface-hover: {c.bg_surface_hover};
        --border-color: {c.border};

        --accent-start: {c.accent_start};
        --accent-end: {c.accent_end};
        --accent-solid: {c.accent_solid};
        --accent-gradient: linear-gradient(135deg, {c.accent_start}, {c.accent_end});

        --severity-critical: {c.severity_critical};
        --severity-high: {c.severity_high};
        --severity-medium: {c.severity_medium};
        --severity-low: {c.severity_low};
        --severity-ok: {c.severity_ok};

        --text-primary: {c.text_primary};
        --text-secondary: {c.text_secondary};
        --text-muted: {c.text_muted};

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

    /* Light-mode override for the radial hero background from theme.css,
       which hardcodes a dark #0d1320 -> var(--bg-primary) gradient. */
    .stApp {{
        background: radial-gradient(circle at 15% 0%, #eef2ff 0%, var(--bg-primary) 45%) fixed !important;
    }}

    /* Subtle low-opacity hexagonal-mesh cyber background, light-mode safe */
    .stApp::before {{
        content: "";
        position: fixed;
        inset: 0;
        pointer-events: none;
        z-index: 0;
        opacity: 0.05;
        background-image:
            linear-gradient(30deg, {c.accent_solid} 12%, transparent 12.5%, transparent 87%, {c.accent_solid} 87.5%, {c.accent_solid}),
            linear-gradient(150deg, {c.accent_solid} 12%, transparent 12.5%, transparent 87%, {c.accent_solid} 87.5%, {c.accent_solid}),
            linear-gradient(30deg, {c.accent_solid} 12%, transparent 12.5%, transparent 87%, {c.accent_solid} 87.5%, {c.accent_solid}),
            linear-gradient(150deg, {c.accent_solid} 12%, transparent 12.5%, transparent 87%, {c.accent_solid} 87.5%, {c.accent_solid});
        background-size: 44px 76px;
        background-position: 0 0, 0 0, 22px 38px, 22px 38px;
    }}
    """
