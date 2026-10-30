"""Desktop notifications through notify-send (freedesktop spec) – no Qt dependency."""
from __future__ import annotations

import subprocess


def notify(title: str, body: str, *, urgent: bool = False) -> None:
    cmd = ["notify-send", "-a", "CachyOS Security Scanner", "-i",
           "security-low" if not urgent else "dialog-warning",
           "-u", "critical" if urgent else "normal", title, body]
    try:
        subprocess.run(cmd, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        pass
