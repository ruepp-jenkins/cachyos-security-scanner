"""Binary scan with the ClamAV daemon (`clamdscan`).

On request it runs in a terminal window: the user sees the live shell output and decides what to do. Scheduled
scans (settings) run in the background with the same log format, and the result lands in the history.
clamd must be running (e.g. `sudo systemctl enable --now clamav-daemon`).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

BACKGROUND_TIMEOUT = 6 * 3600

SCAN_SCRIPT = r'''
log=$1; shift
{
echo "clamdscan: scanning $# path(s) via clamd ($(date '+%F %T'))"
echo
clamdscan --fdpass --multiscan -i -- "$@" 2>&1
} | tee "$log"
rc=${PIPESTATUS[0]}
{
echo
case $rc in
  0) echo "Result: no threats found." ;;
  1) echo "Result: THREATS FOUND (listed above). Nothing was removed." ;;
  *) echo "Result: scan failed (exit $rc). Is clamd running?"
     echo "  sudo systemctl enable --now clamav-daemon" ;;
esac
} | tee -a "$log"
echo
read -r -p "Press Enter to close this window..." _
'''

# (binary, arguments placed before the command to run)
TERMINALS: list[tuple[str, list[str]]] = [
    ("xdg-terminal-exec", []),
    ("konsole", ["-e"]),
    ("gnome-terminal", ["--"]),
    ("xfce4-terminal", ["-x"]),
    ("kitty", []),
    ("alacritty", ["-e"]),
    ("foot", []),
    ("wezterm", ["start", "--"]),
    ("xterm", ["-e"]),
]


def _state_file() -> Path:
    from .. import history

    return history.history_dir().parent / "binary-last-scan"


def mark_scan() -> None:
    """Remember that a binary scan started now (scheduling relies on it; never raises)."""
    try:
        f = _state_file()
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(str(time.time()))
    except OSError:
        pass


def last_scan_time() -> float | None:
    try:
        return float(_state_file().read_text().strip())
    except (OSError, ValueError):
        return None


def seconds_since_last_scan() -> float | None:
    t = last_scan_time()
    return None if t is None else max(0.0, time.time() - t)


def existing_paths(paths: list[str]) -> list[str]:
    return [os.path.expanduser(p) for p in paths if os.path.exists(os.path.expanduser(p))]


def background_command(paths: list[str], low_priority: bool) -> list[str]:
    from .base import priority_prefix

    return (priority_prefix() if low_priority else []) + ["clamdscan", "--fdpass", "--multiscan", "-i", "--", *paths]


def run_background(paths: list[str], low_priority: bool = True, trigger: str = "scheduled") -> tuple[str, str]:
    """Scan without a terminal and write the log to the history. Returns (state, message) with state
    'clean', 'threats', 'error' or 'unavailable'. Blocking: call it from a worker thread. Never raises."""
    from .. import history

    if not available():
        return "unavailable", "clamdscan not found (install the 'clamav' package)"
    existing = existing_paths(paths)
    if not existing:
        return "unavailable", "none of the configured paths exist"
    mark_scan()
    try:
        log = history.new_binary_log_path()
        log.write_text(f"clamdscan: scanning {len(existing)} path(s) via clamd ({time.strftime('%F %T')}) [trigger: {trigger}]\n\n")
    except OSError:
        log = None

    def finish(text: str) -> None:
        if log is not None:
            try:
                with log.open("a") as f:
                    f.write(text)
            except OSError:
                pass

    try:
        p = subprocess.run(background_command(existing, low_priority), capture_output=True, text=True,
                           errors="replace", timeout=BACKGROUND_TIMEOUT, stdin=subprocess.DEVNULL)
        rc, out = p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        rc, out = 124, f"timed out after {BACKGROUND_TIMEOUT}s"
    except OSError as e:
        rc, out = 127, str(e)
    if rc == 0:
        finish(out + "\nResult: no threats found.\n")
        return "clean", "No threats found"
    if rc == 1:
        finish(out + "\nResult: THREATS FOUND (listed above). Nothing was removed.\n")
        return "threats", "Threats found – see the scan history"
    finish(out + f"\nResult: scan failed (exit {rc}). Is clamd running?\n  sudo systemctl enable --now clamav-daemon\n")
    return "error", f"Scan failed (exit {rc}). Is clamd running?"


def available() -> bool:
    return shutil.which("clamdscan") is not None


def find_terminal() -> tuple[str, list[str]] | None:
    for name, args in TERMINALS:
        path = shutil.which(name)
        if path:
            return path, args
    return None


def build_command(paths: list[str], log_path: str = "/dev/null") -> list[str] | None:
    """Full argv that opens a terminal running the scan, or None if no terminal emulator was found."""
    term = find_terminal()
    if term is None:
        return None
    existing = [os.path.expanduser(p) for p in paths if os.path.exists(os.path.expanduser(p))]
    if not existing:
        return None
    binary, pre = term
    return [binary, *pre, "bash", "-c", SCAN_SCRIPT, "clamdscan", log_path, *existing]


def launch(paths: list[str]) -> tuple[bool, str]:
    if not available():
        return False, "clamdscan not found (install the 'clamav' package)"
    from .. import history

    try:
        log = str(history.new_binary_log_path())
    except OSError:
        log = "/dev/null"
    cmd = build_command(paths, log)
    if cmd is None:
        return False, "no terminal emulator or none of the configured paths found"
    mark_scan()
    try:
        subprocess.Popen(cmd, start_new_session=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as e:
        return False, str(e)
    return True, "started"
