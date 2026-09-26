"""
config.py
Central, non-invasive configuration for the PCAP Forensic Analyzer.

This module intentionally does NOT contain detection thresholds (those
remain in detectors/*.py, where they already lived and are unit-tested)
or analysis logic. It only holds UI/app-level settings: page metadata,
theme toggle, and cache tuning -- so those knobs live in one place
instead of scattered across app.py.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AppConfig:
    """Application-level configuration. Import APP_CONFIG, don't instantiate directly."""

    # Page metadata
    page_title: str = "PCAP Forensic Analyzer"
    page_icon: str = "🛡"
    layout: str = "wide"

    # Feature flags
    enable_custom_theme: bool = True
    enable_performance_caching: bool = True
    enable_rust_acceleration: bool = True   # falls back to pure Python automatically if unavailable

    # Cache tuning (used by performance.py)
    cache_ttl_seconds: int = 3600          # evict cached analyses after 1 hour
    cache_max_entries: int = 8             # cap distinct captures held in cache at once

    # Misc
    max_upload_display_name_len: int = 60


APP_CONFIG = AppConfig()
