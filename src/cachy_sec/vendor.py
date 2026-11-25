"""Self-managing checkouts of upstream scanner repositories (no manual steps for the user).

ensure_repo() clones when missing, fast-forwards otherwise, and wipes + re-clones a broken
checkout. A working checkout is only replaced after its successor was downloaded, so being offline never removes a
scanner. ensure_release() does the same but stays on the newest stable release tag (vX.Y.Z).
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


def _clone(url: str, d: Path, tag: str | None = None) -> tuple[bool, str]:
    d.parent.mkdir(parents=True, exist_ok=True)
    branch = ["--branch", tag] if tag else []
    code, out = run(["git", "clone", "--depth", "1", *branch, url, str(d)], 300, low_priority=True)
    if code != 0:
        shutil.rmtree(d, ignore_errors=True)  # never leave a half-cloned directory behind
    return code == 0, (tag or "cloned") if code == 0 else _last_line(out)


def _last_line(out: str) -> str:
    return (out.strip().splitlines() or ["unknown git error"])[-1][-300:]


def reclone(url: str, d: Path, tag: str | None = None) -> tuple[bool, str]:
    """Replace an existing checkout with a fresh one; the old one stays if the download fails."""
    if not _inside_root(d):
        return False, "refusing to manage a directory outside the vendor root"
    new = d.with_name(f".{d.name}.new")
    shutil.rmtree(new, ignore_errors=True)
    ok, msg = _clone(url, new, tag)
    if ok:
        shutil.rmtree(d, ignore_errors=True)
        new.rename(d)
    return ok, msg


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
    before = head(d)
    code, out = run(["git", "-C", str(d), "pull", "--ff-only", "--quiet"], 180, low_priority=True)
    if code == 0:
        return True, "already up to date" if head(d) == before else "updated"
    # Diverged, shallow-history trouble, corrupt objects, force-pushed upstream (or simply offline): start over if we can.
    ok, msg = reclone(url, d)
    return True, "re-cloned after failed update" if ok else f"stale: update failed ({_last_line(out)})"


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
    if not d.exists():
        return _clone(url, d, tag)
    code, commit = run(["git", "-C", str(d), "rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{commit}}"], 30)
    if code == 0 and commit.strip() == head(d):
        return True, tag
    if run(["git", "-C", str(d), "fetch", "--depth", "1", "--quiet", "origin", f"+refs/tags/{tag}:refs/tags/{tag}"],
           300, low_priority=True)[0] == 0 \
            and run(["git", "-C", str(d), "checkout", "--quiet", "--force", "--detach", f"refs/tags/{tag}"], 120)[0] == 0:
        return True, tag
    ok, msg = reclone(url, d, tag)
    return True, tag if ok else f"stale: could not switch to {tag} ({msg})"


def head(d: Path) -> str:
    return run(["git", "-C", str(d), "rev-parse", "HEAD"], 30)[1].strip()


def version(d: Path) -> str:
    """"abc1234 of 2026-07-07" for the checked-out commit."""
    code, out = run(["git", "-C", str(d), "log", "-1", "--format=%h of %cs"], 30)
    return out.strip() if code == 0 else "unknown"
