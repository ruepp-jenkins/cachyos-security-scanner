"""On-request binary scan with the ClamAV daemon (`clamdscan`), shown in a terminal window.

No parsing and no UI feedback here: the user sees the live shell output and decides what to do.
clamd must be running (e.g. `sudo systemctl enable --now clamav-daemon`).
"""
from __future__ import annotations

import os
import shutil
import subprocess

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
    try:
        subprocess.Popen(cmd, start_new_session=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as e:
        return False, str(e)
    return True, "started"
