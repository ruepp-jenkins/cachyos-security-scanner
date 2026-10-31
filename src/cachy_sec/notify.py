"""Desktop notifications through notify-send (freedesktop spec) – no Qt dependency."""
from __future__ import annotations

import subprocess

from . import icons


def notify(title: str, body: str, *, kind: str = "info", urgent: bool = False) -> None:
    """kind: "good" (green icon), "bad" (red icon) or "info" (neutral app icon)."""
    cmd = ["notify-send", "-a", "CachyOS Security Scanner", "-i", icons.for_kind(kind),
           "-u", "critical" if urgent else "normal", title, body]
    try:
        subprocess.run(cmd, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        pass
