"""Community false-positive list for aur-scan, maintained in the project's GitHub repository.

The list says "package P at version V (glob allowed) is known to trigger rule C without being malicious".
It is opt-in (the user decides whether to trust it), fetched only from this project's GitHub release
`false-positives`, signed with the release key (separate signature namespace) and only ever *hides* the listed
combinations; it cannot add findings or run anything.

    python -m cachy_sec.fplist validate lists/false-positives_aur-scan.json
"""
from __future__ import annotations

import datetime
import fnmatch
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from . import updater

SCHEMA = 1
LIST_NAME = "false-positives_aur-scan.json"  # lists/<topic>_<scanner>.json; more lists can follow
SIG_NAMESPACE = "cachy-security-scanner-fplist"  # domain separation from release signatures
MAX_BYTES = 500_000
MAX_ENTRIES = 5000
STALE_AFTER_S = 6 * 3600

_PKG = re.compile(r"^[a-z0-9@._+-]{1,100}$")
_VER = re.compile(r"^[0-9A-Za-z:.+_~*?\[\]-]{1,100}$")
_CODE = re.compile(r"^[A-Z][A-Z0-9]*-\d+$")


@dataclass
class Entry:
    package: str
    versions: list[str]
    codes: list[str]
    reason: str
    author: str = ""
    reported: str = ""  # ISO date the false positive was reported
    description: str = ""  # optional longer explanation
    reference: str = ""


def validate(data: object) -> list[Entry]:
    """Strict schema check; raises ValueError naming the first problem."""
    if not isinstance(data, dict) or data.get("schema") != SCHEMA or not isinstance(data.get("entries"), list):
        raise ValueError(f"expected an object with schema={SCHEMA} and an entries list")
    if len(data["entries"]) > MAX_ENTRIES:
        raise ValueError("too many entries")
    out: list[Entry] = []
    for i, e in enumerate(data["entries"], 1):
        where = f"entry {i}"
        if not isinstance(e, dict):
            raise ValueError(f"{where}: not an object")
        pkg, vers, codes, reason = e.get("package"), e.get("versions"), e.get("codes"), e.get("reason")
        ref, author, reported, desc = e.get("reference", ""), e.get("author"), e.get("reported"), e.get("description", "")
        if not isinstance(pkg, str) or not _PKG.match(pkg):
            raise ValueError(f"{where}: invalid package")
        where = f"entry {i} ({pkg})"
        if not isinstance(vers, list) or not vers or not all(isinstance(v, str) and _VER.match(v) for v in vers):
            raise ValueError(f"{where}: versions must be a non-empty list of version strings or globs")
        if not all(re.search(r"\d", v) for v in vers):
            raise ValueError(f"{where}: a version pattern must contain a digit (no catch-all)")
        if not isinstance(codes, list) or not codes or not all(isinstance(c, str) and _CODE.match(c) for c in codes):
            raise ValueError(f"{where}: codes must be a non-empty list of rule codes like DEEP-001")
        if not isinstance(reason, str) or not 10 <= len(reason) <= 500:
            raise ValueError(f"{where}: reason (10-500 characters) is required")
        if not isinstance(author, str) or not 1 <= len(author.strip()) <= 100:
            raise ValueError(f"{where}: author (who reported it) is required")
        try:
            if not isinstance(reported, str) or datetime.date.fromisoformat(reported).isoformat() != reported:
                raise ValueError
        except ValueError:
            raise ValueError(f"{where}: reported must be an ISO date like 2026-10-31") from None
        if not isinstance(desc, str) or len(desc) > 2000:
            raise ValueError(f"{where}: description must be text of at most 2000 characters")
        if not isinstance(ref, str) or (ref and not ref.startswith("https://")):
            raise ValueError(f"{where}: reference must be an https URL")
        out.append(Entry(pkg, list(vers), list(codes), reason, author.strip(), reported, desc, ref))
    return out


def match(entries: list[Entry], package: str, version: str, code: str) -> Entry | None:
    if not version:
        return None
    for e in entries:
        if e.package == package and code in e.codes and any(fnmatch.fnmatchcase(version, v) for v in e.versions):
            return e
    return None


def _dir() -> Path:
    base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "cachy-security-scanner"


def _paths() -> tuple[Path, Path]:
    return _dir() / LIST_NAME, _dir() / (LIST_NAME + ".sig")


def _url(name: str) -> str:
    return f"https://github.com/{updater.GITHUB_REPO}/releases/download/false-positives/{name}"


def is_fresh() -> bool:
    try:
        return time.time() - _paths()[0].stat().st_mtime < STALE_AFTER_S
    except OSError:
        return False


def refresh(force: bool = False, pubkey: str | None = None) -> tuple[bool, str]:
    """Download list + signature from GitHub, verify, store. The cache is only replaced by a verified list."""
    if not force and is_fresh():
        return True, "cache is fresh"
    try:
        data = updater._get(_url(LIST_NAME), MAX_BYTES)
        sig = updater._get(_url(LIST_NAME + ".sig"), 100_000)
        updater.verify_signature(data, sig, pubkey, namespace=SIG_NAMESPACE)
        validate(json.loads(data))
    except (updater.UpdateError, ValueError) as e:
        return False, str(e)
    f, fs = _paths()
    try:
        f.parent.mkdir(parents=True, exist_ok=True)
        for p, blob in ((fs, sig), (f, data)):  # data last: its mtime marks a complete pair
            tmp = p.with_suffix(p.suffix + ".tmp")
            tmp.write_bytes(blob)
            tmp.replace(p)
    except OSError as e:
        return False, str(e)
    return True, "updated"


def load(pubkey: str | None = None) -> list[Entry]:
    """Cached list, re-verified on every load; any problem means "no entries" (nothing gets hidden)."""
    f, fs = _paths()
    try:
        data, sig = f.read_bytes(), fs.read_bytes()
        updater.verify_signature(data, sig, pubkey, namespace=SIG_NAMESPACE)
        return validate(json.loads(data))
    except (OSError, updater.UpdateError, ValueError):
        return []


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[1] == "validate":
        try:
            entries = validate(json.loads(Path(argv[2]).read_text()))
        except (OSError, ValueError) as e:
            print(f"INVALID: {e}", file=sys.stderr)
            return 1
        print(f"OK: {len(entries)} entries")
        return 0
    print("usage: python -m cachy_sec.fplist validate FILE", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
