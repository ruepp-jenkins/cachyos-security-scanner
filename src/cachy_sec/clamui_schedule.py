"""Optional helper: recurring ClamUI scans through a systemd *user* timer.

Created only on explicit user request from the settings dialog; removable again.
"""
from __future__ import annotations

import os
import shlex
from pathlib import Path

from .scanners.base import run, which

UNIT = "cachy-sec-clamui"


def unit_dir() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "systemd" / "user"


def render(paths: list[str], calendar: str = "weekly") -> tuple[str, str]:
    exe = which("clamui") or "clamui"
    args = " ".join(shlex.quote(os.path.expanduser(p)) for p in paths)
    service = f"[Unit]\nDescription=Regular ClamUI scan\n\n[Service]\nType=oneshot\nNice=19\nIOSchedulingClass=idle\nExecStart={exe} scan {args}\n"
    timer = f"[Unit]\nDescription=Regular ClamUI scan\n\n[Timer]\nOnCalendar={calendar}\nPersistent=true\nRandomizedDelaySec=1h\n\n[Install]\nWantedBy=timers.target\n"
    return service, timer


def enable(paths: list[str], calendar: str = "weekly") -> tuple[bool, str]:
    if not which("clamui"):
        return False, "ClamUI is not installed"
    service, timer = render(paths, calendar)
    d = unit_dir()
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{UNIT}.service").write_text(service)
    (d / f"{UNIT}.timer").write_text(timer)
    run(["systemctl", "--user", "daemon-reload"], 30)
    code, out = run(["systemctl", "--user", "enable", "--now", f"{UNIT}.timer"], 30)
    return code == 0, out[-300:]


def disable() -> tuple[bool, str]:
    run(["systemctl", "--user", "disable", "--now", f"{UNIT}.timer"], 30)
    for ext in ("service", "timer"):
        (unit_dir() / f"{UNIT}.{ext}").unlink(missing_ok=True)
    code, out = run(["systemctl", "--user", "daemon-reload"], 30)
    return code == 0, out[-300:]


def is_enabled() -> bool:
    return run(["systemctl", "--user", "is-enabled", f"{UNIT}.timer"], 15)[0] == 0
