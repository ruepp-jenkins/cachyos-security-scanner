"""Bundled icons (SVG). Paths only, so this works without Qt (notifications, autostart)."""
from __future__ import annotations

from pathlib import Path

DIR = Path(__file__).parent / "icons"
APP, GOOD, BAD = "cachy-security-scanner", "status-good", "status-bad"
WARNING, ERROR, SKIPPED, UNKNOWN = "status-warning", "status-error", "status-skipped", "status-unknown"

# History status -> icon. Shields are results of a scanner (clean/warning/critical); everything else
# (error, skipped, unknown) is a system message and deliberately not a shield.
FOR_STATUS = {"clean": GOOD, "warning": WARNING, "critical": BAD, "error": ERROR, "skipped": SKIPPED, "unknown": UNKNOWN}
STATUS_RANK = {"clean": 0, "unknown": 1, "skipped": 2, "error": 3, "warning": 4, "critical": 5}  # sort order


def for_status(status: str) -> str:
    return path(FOR_STATUS.get(status, UNKNOWN))


def path(name: str) -> str:
    return str(DIR / f"{name}.svg")


def for_kind(kind: str) -> str:
    """Notification kind -> icon file: good = green, bad = red, anything else = neutral app icon."""
    return path({"good": GOOD, "bad": BAD}.get(kind, APP))
