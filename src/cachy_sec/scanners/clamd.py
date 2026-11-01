"""Binary scan with the ClamAV daemon (`clamdscan`).

On request it runs in a terminal window: the user sees the live shell output and decides what to do. Scheduled
scans (settings) run in the background with the same log format, and the result lands in the history.
clamd must be running (e.g. `sudo systemctl enable --now clamav-daemon`).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

from .. import scanopts
from ..settings import Settings

BACKGROUND_TIMEOUT = 6 * 3600

# clamdscan exits 2 when some files could not be opened, even if it scanned the rest and found nothing. That is not a
# failure: with "Infected files: 0" in its summary the scan is a success and the unreadable files are only reported.
SCAN_SCRIPT = r'''
log=$1; nopts=$2; shift 2
opts=("${@:1:nopts}"); shift "$nopts"
tmp=$(mktemp)
{
echo "clamdscan: scanning $# path(s) via clamd ($(date '+%F %T'))"
echo
clamdscan "${opts[@]}" -- "$@" 2>&1
} | tee "$log" "$tmp"
rc=${PIPESTATUS[0]}
skipped=""
if [ "$rc" = 2 ] && grep -q '^Infected files: 0$' "$tmp"; then
  n=$(sed -n 's/^Total errors: *//p' "$tmp" | head -n1)
  rc=0
  skipped=" ($n file(s) could not be opened and were skipped; everything else was scanned)"
fi
rm -f "$tmp"
{
echo
case $rc in
  0) echo "Result: no threats found$skipped." ;;
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


_INFECTED = re.compile(r"^Infected files:\s*(\d+)\s*$", re.M)
_ERRORS = re.compile(r"^Total errors:\s*(\d+)\s*$", re.M)


def interpret(rc: int, out: str) -> tuple[str, int]:
    """Map a clamdscan run to ('clean' | 'threats' | 'error', number of files that could not be opened).

    Exit code 2 does not always mean failure: clamdscan uses it when some files could not be opened (permissions, files
    that vanished) even though it scanned everything else. If its summary says "Infected files: 0" that is a clean scan.
    No summary at all (clamd not running, bad configuration) stays an error.
    """
    m = _INFECTED.search(out)
    e = _ERRORS.search(out)
    skipped = int(e.group(1)) if e else 0
    if rc == 1 or (m and int(m.group(1)) > 0):
        return "threats", skipped
    if rc == 0 or (rc == 2 and m):
        return "clean", skipped
    return "error", skipped


def _skipped_note(skipped: int) -> str:
    return f" ({skipped} file(s) could not be opened and were skipped; everything else was scanned)" if skipped else ""


def _state_file(name: str = "binary-last-scan") -> Path:
    from .. import history

    return history.history_dir().parent / name


def _write_time(name: str) -> None:
    try:
        f = _state_file(name)
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(str(time.time()))
    except OSError:
        pass


def mark_scan() -> None:
    """Remember that a binary scan was attempted now (never raises)."""
    _write_time("binary-last-scan")


def mark_success() -> None:
    """Remember that a binary scan ran to a result (clean or threats). A failed attempt does not count."""
    _write_time("binary-last-success")


def _read_time(name: str) -> float | None:
    try:
        return float(_state_file(name).read_text().strip())
    except (OSError, ValueError):
        return None


def last_scan_time() -> float | None:
    return _read_time("binary-last-scan")


def seconds_since_last_scan() -> float | None:
    """Since the last attempt (successful or not)."""
    t = last_scan_time()
    return None if t is None else max(0.0, time.time() - t)


def seconds_since_last_success() -> float | None:
    t = _read_time("binary-last-success")
    return None if t is None else max(0.0, time.time() - t)


def existing_paths(paths: list[str]) -> list[str]:
    return [os.path.expanduser(p) for p in paths if os.path.exists(os.path.expanduser(p))]


def background_command(paths: list[str], low_priority: bool, options: list[str] | None = None) -> list[str]:
    from .base import priority_prefix

    opts = options if options is not None else ["--fdpass", "-i"]
    return (priority_prefix() if low_priority else []) + ["clamdscan", *opts, "--", *paths]


_lock = threading.Lock()
_proc: subprocess.Popen | None = None  # the running background scan, if any
_cancel_requested = False


def _execute(cmd: list[str]) -> tuple[int, str, bool]:
    """Run the scan; returns (exit code, output, cancelled). The process can be stopped with cancel_background()."""
    global _proc, _cancel_requested
    try:
        with _lock:
            _cancel_requested = False
            _proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, errors="replace")
            proc = _proc
        try:
            out, _ = proc.communicate(timeout=BACKGROUND_TIMEOUT)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            rc, out = 124, f"timed out after {BACKGROUND_TIMEOUT}s"
        with _lock:
            cancelled = _cancel_requested
        return rc, out or "", cancelled
    except OSError as e:
        return 127, str(e), False
    finally:
        with _lock:
            _proc = None


def background_running() -> bool:
    with _lock:
        return _proc is not None and _proc.poll() is None


def cancel_background() -> bool:
    """Stop the running background scan (SIGTERM to the clamdscan client; the daemon notices the closed connection).
    Returns False when none is running. run_background() then returns the state 'cancelled'."""
    global _cancel_requested
    with _lock:
        if _proc is None or _proc.poll() is not None:
            return False
        _cancel_requested = True
        _proc.terminate()
        return True


def run_background(paths: list[str], low_priority: bool = True, trigger: str = "scheduled",
                   settings: Settings | None = None) -> tuple[str, str]:
    """Scan without a terminal and write the log to the history. Returns (state, message) with state
    'clean', 'threats', 'error', 'cancelled' or 'unavailable'. Blocking: call it from a worker thread. Never raises."""
    from .. import history

    if not available():
        return "unavailable", "clamdscan not found (install the 'clamav' package)"
    existing = existing_paths(paths)
    if not existing:
        return "unavailable", "none of the configured paths exist"
    try:
        options = scanopts.clamd_args(settings or Settings())
    except ValueError as e:
        return "error", f"Invalid extra arguments in the ClamAV options: {e}"
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

    rc, out, cancelled = _execute(background_command(existing, low_priority, options))
    if cancelled:
        finish(out + "\nResult: cancelled, replaced by a newer scan.\n")
        return "cancelled", "Scan cancelled: a newer scan was started"
    state, skipped = interpret(rc, out)
    if state == "clean":
        finish(out + f"\nResult: no threats found{_skipped_note(skipped)}.\n")
        mark_success()
        return "clean", "No threats found" + (f" ({skipped} unreadable file(s) skipped)" if skipped else "")
    if state == "threats":
        finish(out + "\nResult: THREATS FOUND (listed above). Nothing was removed.\n")
        mark_success()
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


def build_command(paths: list[str], log_path: str = "/dev/null", options: list[str] | None = None) -> list[str] | None:
    """Full argv that opens a terminal running the scan, or None if no terminal emulator was found."""
    term = find_terminal()
    if term is None:
        return None
    existing = [os.path.expanduser(p) for p in paths if os.path.exists(os.path.expanduser(p))]
    if not existing:
        return None
    binary, pre = term
    opts = options if options is not None else ["--fdpass", "-i"]
    return [binary, *pre, "bash", "-c", SCAN_SCRIPT, "clamdscan", log_path, str(len(opts)), *opts, *existing]


def launch(paths: list[str], settings: Settings | None = None) -> tuple[bool, str]:
    if not available():
        return False, "clamdscan not found (install the 'clamav' package)"
    try:
        options = scanopts.clamd_args(settings or Settings())
    except ValueError as e:
        return False, f"Invalid extra arguments in the ClamAV options: {e}"
    from .. import history

    try:
        log = str(history.new_binary_log_path())
    except OSError:
        log = "/dev/null"
    cmd = build_command(paths, log, options)
    if cmd is None:
        return False, "no terminal emulator or none of the configured paths found"
    try:
        subprocess.Popen(cmd, start_new_session=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as e:
        return False, str(e)
    mark_scan()
    mark_success()  # the user watches this scan in a terminal and decides what it means
    return True, "started"
