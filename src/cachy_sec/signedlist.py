"""Signed community lists published by this project's GitHub Actions on the rolling release `lists`.

Used by the false-positive list and the blocklist. Both are fetched only from this project's GitHub, verified against
the release signing key (one signature namespace per list) and cached; a list that fails verification or validation
is never used. The workflow stamps a `published` timestamp into each file before signing, so the UI can say how
current a list is.

    python -m cachy_sec.signedlist validate lists/*.json
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from . import updater

RELEASE_TAG = "lists"  # rolling release that carries the lists
STALE_AFTER_S = 55 * 60  # periodic check: hourly (a little less, so an hourly tick never just misses it)
SCAN_MAX_AGE_S = 5 * 60  # a scan only uses a list that was downloaded this recently, if it can get a new one
RETRY_AFTER_FAILURE_S = 5 * 60  # do not hammer GitHub while a list cannot be fetched
_LOCK = threading.Lock()  # a scan and the periodic check must not write the same list at once
_PUBLISHED = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
_COMMIT = re.compile(r"^[0-9a-f]{7,40}$")


@dataclass(frozen=True)
class Spec:
    name: str  # file name in lists/ and in the release
    namespace: str  # ssh signature namespace (domain separation between lists and from app releases)
    validate: Callable[[object], list]
    max_bytes: int = 500_000


@dataclass
class Loaded:
    entries: list
    published: str  # "" when the file carries no stamp
    fetched: float  # when the cached copy was downloaded
    commit: str = ""  # git commit the list was published from; "" when the file carries none


def url(name: str) -> str:
    return f"https://github.com/{updater.GITHUB_REPO}/releases/download/{RELEASE_TAG}/{name}"


def _dir() -> Path:
    base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "cachy-security-scanner"


def paths(spec: Spec) -> tuple[Path, Path]:
    return _dir() / spec.name, _dir() / (spec.name + ".sig")


def last_error(spec: Spec) -> str:
    """Why the last download failed ("" if it did not, or a later one succeeded)."""
    try:
        return _failed_marker(spec).read_text().strip()
    except OSError:
        return ""


def _failed_marker(spec: Spec) -> Path:
    return _dir() / (spec.name + ".failed")


def _age(p: Path) -> float | None:
    try:
        return time.time() - p.stat().st_mtime
    except OSError:
        return None


def is_fresh(spec: Spec, max_age: float = STALE_AFTER_S) -> bool:
    age = _age(paths(spec)[0])
    return age is not None and 0 <= age < max_age


def refresh(spec: Spec, force: bool = False, pubkey: str | None = None,
            max_age: float | None = None) -> tuple[bool, str]:
    """Download list + signature, verify, validate, store. The cache is only ever replaced by a verified list.

    `force` always downloads. `max_age` (scans) downloads when the copy is older, even right after a failed attempt.
    Otherwise (periodic check) the copy may be STALE_AFTER_S old and a failure is not retried immediately.
    """
    with _LOCK:
        return _refresh(spec, force, pubkey, max_age)


def _refresh(spec: Spec, force: bool, pubkey: str | None, max_age: float | None) -> tuple[bool, str]:
    if not force:
        if is_fresh(spec, STALE_AFTER_S if max_age is None else max_age):
            return True, "cache is fresh"
        failed = _age(_failed_marker(spec))
        if max_age is None and failed is not None and failed < RETRY_AFTER_FAILURE_S:
            return False, "the last download failed a moment ago; trying again later"
    try:
        data = updater._get(url(spec.name), spec.max_bytes)
        sig = updater._get(url(spec.name + ".sig"), 100_000)
        updater.verify_signature(data, sig, pubkey, namespace=spec.namespace)
        spec.validate(json.loads(data))
    except (updater.UpdateError, ValueError) as e:
        try:
            _dir().mkdir(parents=True, exist_ok=True)
            _failed_marker(spec).write_text(str(e)[:300])
        except OSError:
            pass
        return False, str(e)
    f, fs = paths(spec)
    try:
        f.parent.mkdir(parents=True, exist_ok=True)
        for p, blob in ((fs, sig), (f, data)):  # data last: its mtime marks a complete pair
            tmp = p.with_suffix(p.suffix + ".tmp")
            tmp.write_bytes(blob)
            tmp.replace(p)
        _failed_marker(spec).unlink(missing_ok=True)
    except OSError as e:
        return False, str(e)
    return True, "updated"


def load(spec: Spec, pubkey: str | None = None) -> Loaded | None:
    """The cached list, re-verified on every load. Any problem means None (nothing is hidden / flagged)."""
    f, fs = paths(spec)
    try:
        data, sig = f.read_bytes(), fs.read_bytes()
        updater.verify_signature(data, sig, pubkey, namespace=spec.namespace)
        obj = json.loads(data)
        entries = spec.validate(obj)
        published = obj.get("published", "") if isinstance(obj, dict) else ""
        commit = str(obj.get("commit", "")) if isinstance(obj, dict) else ""
        return Loaded(entries, published if _PUBLISHED.match(str(published)) else "", f.stat().st_mtime,
                      commit if _COMMIT.match(commit) else "")
    except (OSError, updater.UpdateError, ValueError):
        return None


def describe(loaded: Loaded | None, noun: str = "entry", plural: str = "entries", error: str = "") -> str:
    """One line for the settings dialog: availability and how current the list is."""
    if loaded is None:
        if error:
            return f"not available: the last download failed ({error})"
        return "not downloaded yet (fetched at start, hourly and before scans)"
    n = len(loaded.entries)
    if loaded.published:
        when = loaded.published[:10] + " " + loaded.published[11:16] + " UTC"
        stamp = f"from {when}"
    else:
        stamp = "downloaded " + time.strftime("%Y-%m-%d %H:%M", time.localtime(loaded.fetched))
    return f"available, {stamp}, {n} {noun if n == 1 else plural}"


def state_line(spec: Spec, loaded: Loaded | None) -> str:
    """describe() plus when the cached copy was downloaded and whether the last download failed; for scan logs."""
    error = last_error(spec)
    line = describe(loaded, "entry", "entries", error)
    if loaded is not None:
        line += "; downloaded " + time.strftime("%Y-%m-%d %H:%M", time.localtime(loaded.fetched))
        if error:
            line += f"; the last download failed ({error})"
    return line


def main(argv: list[str]) -> int:
    from . import blocklist, fplist  # registry; imported here to avoid import cycles

    specs = {s.name: s for s in (fplist.SPEC, blocklist.SPEC)}
    if len(argv) < 3 or argv[1] != "validate":
        print("usage: python -m cachy_sec.signedlist validate FILE...", file=sys.stderr)
        return 2
    status = 0
    for name in argv[2:]:
        spec = specs.get(Path(name).name)
        if spec is None:
            print(f"{name}: UNKNOWN list (expected one of: {', '.join(specs)})", file=sys.stderr)
            status = 1
            continue
        try:
            n = len(spec.validate(json.loads(Path(name).read_text())))
        except (OSError, ValueError) as e:
            print(f"{name}: INVALID: {e}", file=sys.stderr)
            status = 1
            continue
        print(f"{name}: OK ({n} entries)")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv))
