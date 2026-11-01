"""Scheduling policy as pure functions so it can be tested without Qt."""
from __future__ import annotations

from .settings import Settings


def interval_ms(s: Settings) -> int | None:
    """Timer period for periodic package scans, or None when none is wanted."""
    return s.interval_minutes * 60_000 if s.scan_periodic else None


def scan_at_startup(s: Settings) -> bool:
    return s.scan_on_start


def binary_at_startup(s: Settings) -> bool:
    return s.binary_on_start


def scan_after_pkg_change(s: Settings) -> bool:
    return s.scan_after_pkg_changes


def anything_after_pkg_change(s: Settings) -> bool:
    return s.scan_after_pkg_changes or s.binary_after_pkg_changes


def pkg_delay_ms(s: Settings, since_last_scan_s: float | None) -> int:
    """Debounce before a package-change scan: the configured delay, stretched to honour the minimum gap."""
    delay = s.pkg_change_delay_seconds * 1000
    if since_last_scan_s is None:
        return delay
    wait = s.pkg_scan_min_gap_minutes * 60 - since_last_scan_s
    return max(delay, int(wait * 1000))


RETRY_AFTER_FAILURE_S = 3600


def binary_due(s: Settings, since_success_s: float | None, since_attempt_s: float | None = None) -> bool:
    """Periodic binary scan: due when no scan ever succeeded or the interval has passed since the last success
    (survives restarts). A failed attempt is retried only after an hour, not at every poll."""
    if not s.binary_periodic:
        return False
    if since_attempt_s is not None and since_attempt_s < RETRY_AFTER_FAILURE_S:
        return False
    return since_success_s is None or since_success_s >= s.binary_interval_minutes * 60


def binary_gap_ok(s: Settings, since_last_binary_s: float | None) -> bool:
    """Event-driven binary scans (start, package change, with a package scan) respect the minimum gap."""
    return since_last_binary_s is None or since_last_binary_s >= s.binary_min_gap_hours * 3600
