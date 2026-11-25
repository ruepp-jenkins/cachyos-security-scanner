"""Self-managing checkouts of upstream scanner repositories (no manual steps for the user).

ensure_repo() clones when missing, fast-forwards otherwise, and wipes + re-clones a broken
checkout. ensure_release() does the same but stays on the newest stable release tag (vX.Y.Z).
Deletion is restricted to directories directly below our own vendor root.
"""
from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

from .scanners.base import run, which


def vendor_root() -> Path:
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "cachy-security-scanner" / "vendor"


def _inside_root(d: Path) -> bool:
    return d.resolve().parent == vendor_root().resolve()


def _healthy(d: Path) -> bool:
    return (d / ".git").is_dir() and run(["git", "-C", str(d), "fsck", "--connectivity-only", "--no-dangling"], 120, low_priority=True)[0] == 0 \
        and run(["git", "-C", str(d), "rev-parse", "--verify", "HEAD"], 30)[0] == 0


def _clone(url: str, d: Path) -> tuple[bool, str]:
    d.parent.mkdir(parents=True, exist_ok=True)
    code, out = run(["git", "clone", "--depth", "1", url, str(d)], 300, low_priority=True)
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
    code, out = run(["git", "-C", str(d), "pull", "--ff-only", "--quiet"], 180, low_priority=True)
    if code == 0:
        return True, "updated"
    # Diverged, shallow-history trouble, corrupt objects, force-pushed upstream: start over.
    shutil.rmtree(d, ignore_errors=True)
    ok, msg = _clone(url, d)
    return ok, msg if not ok else "re-cloned after failed update"


_RELEASE_TAG = re.compile(r"refs/tags/(v(\d+)\.(\d+)\.(\d+))$")  # no suffix: pre-releases (-rc.1) never match


def latest_release(url: str) -> str | None:
    """Newest stable release tag of a remote repository; None if it cannot be asked or has none."""
    code, out = run(["git", "ls-remote", "--tags", "--refs", url], 120)
    if code != 0:
        return None
    tags = [(tuple(map(int, m.groups()[1:])), m.group(1)) for m in map(_RELEASE_TAG.search, out.splitlines()) if m]
    return max(tags)[1] if tags else None


def ensure_release(url: str, d: Path) -> tuple[bool, str]:
    """Like ensure_repo(), but the checkout is the newest stable release instead of the default branch.

    If the releases cannot be listed (offline), an existing healthy checkout is kept as it is.
    """
    if not which("git"):
        return False, "git not found"
    if not _inside_root(d):
        return False, "refusing to manage a directory outside the vendor root"
    if d.exists() and not _healthy(d):
        shutil.rmtree(d, ignore_errors=True)
    tag = latest_release(url)
    if tag is None:
        return (True, "stale: release list not available") if d.exists() else (False, "no release found")
    if d.exists():
        code, commit = run(["git", "-C", str(d), "rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{commit}}"], 30)
        if code == 0 and commit.strip() == head(d):
            return True, tag
        if run(["git", "-C", str(d), "fetch", "--depth", "1", "--quiet", "origin", f"+refs/tags/{tag}:refs/tags/{tag}"],
               300, low_priority=True)[0] == 0 \
                and run(["git", "-C", str(d), "checkout", "--quiet", "--force", "--detach", f"refs/tags/{tag}"], 120)[0] == 0:
            return True, tag
        shutil.rmtree(d, ignore_errors=True)  # start over
    d.parent.mkdir(parents=True, exist_ok=True)
    code, out = run(["git", "clone", "--depth", "1", "--branch", tag, url, str(d)], 300, low_priority=True)
    if code != 0:
        shutil.rmtree(d, ignore_errors=True)
    return code == 0, tag if code == 0 else out[-300:]


def head(d: Path) -> str:
    return run(["git", "-C", str(d), "rev-parse", "HEAD"], 30)[1].strip()
