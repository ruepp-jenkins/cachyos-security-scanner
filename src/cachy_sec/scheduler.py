"""Scheduling policy as pure functions so it can be tested without Qt."""
from __future__ import annotations

from .settings import Settings


def interval_ms(s: Settings) -> int | None:
    """Timer period for periodic scans, or None when no periodic scan is wanted."""
    return s.interval_minutes * 60_000 if s.mode == "interval" else None


def scan_at_startup(s: Settings) -> bool:
    return s.mode != "manual" and s.scan_on_start


def scan_after_pkg_change(s: Settings) -> bool:
    return s.mode != "manual" and s.scan_after_pkg_changes
