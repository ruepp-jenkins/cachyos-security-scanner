"""Register / unregister the app in the user's XDG autostart (no root needed).

Enabling writes ~/.config/autostart/cachy-security-scanner.desktop. Disabling removes it, or, when the
package ships a system-wide entry (/etc/xdg/autostart), writes `Hidden=true` over it, which is the
standard XDG way for a user to opt out.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

NAME = "cachy-security-scanner.desktop"


def user_file() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "autostart" / NAME


def _system_files() -> list[Path]:
    dirs = (os.environ.get("XDG_CONFIG_DIRS") or "/etc/xdg").split(":")
    return [Path(d) / "autostart" / NAME for d in dirs if d]


def exec_line() -> str:
    exe = shutil.which("cachy-security-scanner")
    parts = [exe] if exe else [sys.executable, "-m", "cachy_sec.bootstrap"]
    return " ".join(f'"{p}"' if " " in p else p for p in parts)


def _render(hidden: bool = False) -> str:
    lines = ["[Desktop Entry]", "Type=Application", "Name=CachyOS Security Scanner",
             "Comment=Background scanner for compromised AUR packages", f"Exec={exec_line()}",
             "Icon=security-high", "Terminal=false", "X-GNOME-Autostart-Delay=10"]
    if hidden:
        lines.append("Hidden=true")
    return "\n".join(lines) + "\n"


def is_enabled() -> bool:
    f = user_file()
    if f.exists():
        try:
            return "Hidden=true" not in f.read_text()
        except OSError:
            return False
    return any(p.exists() for p in _system_files())


def set_enabled(enabled: bool) -> None:
    f = user_file()
    if enabled:
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(_render())
    elif any(p.exists() for p in _system_files()):
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(_render(hidden=True))
    else:
        f.unlink(missing_ok=True)


def apply(enabled: bool) -> None:
    """Idempotent; only touches the file when the effective state differs. Never raises."""
    try:
        if enabled != is_enabled():
            set_enabled(enabled)
        elif enabled and user_file().exists() and user_file().read_text() != _render():
            set_enabled(True)  # refresh a stale Exec path (e.g. after moving the install)
    except OSError:
        pass
