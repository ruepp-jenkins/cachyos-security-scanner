"""Bundled icons (SVG). Paths only, so this works without Qt (notifications, autostart)."""
from __future__ import annotations

from pathlib import Path

DIR = Path(__file__).parent / "icons"
APP, GOOD, BAD = "cachy-security-scanner", "status-good", "status-bad"


def path(name: str) -> str:
    return str(DIR / f"{name}.svg")


def for_kind(kind: str) -> str:
    """Notification kind -> icon file: good = green, bad = red, anything else = neutral app icon."""
    return path({"good": GOOD, "bad": BAD}.get(kind, APP))
