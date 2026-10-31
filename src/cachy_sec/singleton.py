"""Only one instance of the tray app per user session.

Two instances each keep their own in-memory settings: a scanner switched off in one window would still run from the
other instance's timer, and every instance shows its own tray icon. The lock is an flock, released by the kernel when the
process ends, so a crash never leaves a stale lock behind.
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
from typing import IO

_held: IO | None = None  # keeps the lock for the lifetime of the process


def lock_path() -> Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime and Path(runtime).is_dir():
        return Path(runtime) / "cachy-security-scanner.lock"
    base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "cachy-security-scanner" / "instance.lock"


def acquire(path: Path | None = None) -> IO | None:
    """The lock file object, or None if another instance already holds it."""
    global _held
    p = path or lock_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    f = open(p, "a+")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        return None
    f.seek(0)
    f.truncate()
    f.write(str(os.getpid()))
    f.flush()
    if path is None:
        _held = f
    return f
