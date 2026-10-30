"""Self-managing checkouts of upstream scanner repositories (no manual steps for the user).

ensure_repo() clones when missing, fast-forwards otherwise, and wipes + re-clones a broken
checkout. Deletion is restricted to directories directly below our own vendor root.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from .scanners.base import run, which


def vendor_root() -> Path:
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "cachy-security-scanner" / "vendor"


def _inside_root(d: Path) -> bool:
    return d.resolve().parent == vendor_root().resolve()


def _healthy(d: Path) -> bool:
    return (d / ".git").is_dir() and run(["git", "-C", str(d), "fsck", "--connectivity-only", "--no-dangling"], 120)[0] == 0 \
        and run(["git", "-C", str(d), "rev-parse", "--verify", "HEAD"], 30)[0] == 0


def _clone(url: str, d: Path) -> tuple[bool, str]:
    d.parent.mkdir(parents=True, exist_ok=True)
    code, out = run(["git", "clone", "--depth", "1", url, str(d)], 300)
    if code != 0:
        shutil.rmtree(d, ignore_errors=True)  # never leave a half-cloned directory behind
    return code == 0, out[-300:]


def ensure_repo(url: str, d: Path) -> tuple[bool, str]:
    """Return (ok, message). ok means a healthy, up-to-date checkout exists afterwards (or stale but usable)."""
    if not which("git"):
        return False, "git not found"
    if not _inside_root(d):
        return False, "refusing to manage a directory outside the vendor root"
    if not d.exists():
        return _clone(url, d)
    if not _healthy(d):
        shutil.rmtree(d, ignore_errors=True)
        return _clone(url, d)
    code, out = run(["git", "-C", str(d), "pull", "--ff-only", "--quiet"], 180)
    if code == 0:
        return True, "updated"
    # Diverged, shallow-history trouble, corrupt objects, force-pushed upstream: start over.
    shutil.rmtree(d, ignore_errors=True)
    ok, msg = _clone(url, d)
    return ok, msg if not ok else "re-cloned after failed update"


def head(d: Path) -> str:
    return run(["git", "-C", str(d), "rev-parse", "HEAD"], 30)[1].strip()
