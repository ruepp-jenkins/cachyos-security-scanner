"""Desktop notifications through notify-send (freedesktop spec) – no Qt dependency."""
from __future__ import annotations

import subprocess
import threading
from typing import Callable

from . import icons

APP_NAME = "CachyOS Security Scanner"
ACTIONS = ("default", "history")  # clicking the notification itself, or its button
MAX_WAITING = 10  # notifications that wait for a click, each in its own thread
_waiting = 0
_lock = threading.Lock()


def _base(title: str, body: str, kind: str, urgent: bool) -> list[str]:
    return ["notify-send", "-a", APP_NAME, "-i", icons.for_kind(kind), "-u", "critical" if urgent else "normal", title, body]


def notify(title: str, body: str, *, kind: str = "info", urgent: bool = False,
           on_click: Callable[[], None] | None = None) -> threading.Thread | None:
    """kind: "good" (green icon), "bad" (red icon) or "info" (neutral app icon).

    on_click: called (from a helper thread) when the user clicks the notification or its "Open scan history" button.
    Needs a libnotify whose notify-send knows --action/--wait; without it the plain notification is shown instead.
    Returns the helper thread if one was started.
    """
    global _waiting
    cmd = _base(title, body, kind, urgent)
    if on_click is None:
        _run_plain(cmd)
        return None
    with _lock:
        if _waiting >= MAX_WAITING:
            on_click = None
        else:
            _waiting += 1
    if on_click is None:
        _run_plain(cmd)
        return None
    t = threading.Thread(target=_wait_for_click, args=(cmd, on_click), daemon=True, name="notification-click")
    t.start()
    return t


def _run_plain(cmd: list[str]) -> None:
    try:
        subprocess.run(cmd, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        pass


def _wait_for_click(cmd: list[str], on_click: Callable[[], None]) -> None:
    global _waiting
    try:
        action_args = ["--action=default=Open scan history", "--action=history=Open scan history", "--wait"]
        full = cmd[:-2] + action_args + cmd[-2:]  # options before the title and body
        try:
            p = subprocess.run(full, capture_output=True, text=True, timeout=24 * 3600, check=False)
        except (OSError, subprocess.SubprocessError):
            return
        if p.returncode != 0 and ("nknown option" in p.stderr or "nrecognized" in p.stderr):
            _run_plain(cmd)  # old libnotify: show it without the click feature
            return
        if p.stdout.strip() in ACTIONS:
            try:
                on_click()
            except Exception:  # noqa: BLE001 - a broken callback must not kill the helper thread silently
                pass
    finally:
        with _lock:
            _waiting -= 1
