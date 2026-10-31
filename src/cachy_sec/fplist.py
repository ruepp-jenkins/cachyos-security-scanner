"""Community false-positive list for aur-scan, maintained in the project's GitHub repository.

The list says "package P at version V (glob allowed) is known to trigger rule C without being malicious".
It is opt-in (the user decides whether to trust it), fetched only from this project's GitHub release
`lists`, signed with the release key (separate signature namespace) and only ever *hides* the listed
combinations; it cannot add findings or run anything.

    python -m cachy_sec.signedlist validate lists/*.json
"""
from __future__ import annotations

import datetime
import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path

from . import signedlist

SCHEMA = 1
LIST_NAME = "false-positives_aur-scan.json"  # lists/<topic>_<scanner>.json; more lists can follow
SIG_NAMESPACE = "cachy-security-scanner-fplist"  # domain separation from release signatures
MAX_BYTES = 500_000
MAX_ENTRIES = 5000

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
        author, reported, desc = e.get("author"), e.get("reported"), e.get("description", "")
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
        out.append(Entry(pkg, list(vers), list(codes), reason, author.strip(), reported, desc))
    return out


def match(entries: list[Entry], package: str, version: str, code: str) -> Entry | None:
    if not version:
        return None
    for e in entries:
        if e.package == package and code in e.codes and any(fnmatch.fnmatchcase(version, v) for v in e.versions):
            return e
    return None


SPEC = signedlist.Spec(LIST_NAME, SIG_NAMESPACE, lambda data: validate(data), MAX_BYTES)


def _paths() -> tuple[Path, Path]:
    return signedlist.paths(SPEC)


def _url(name: str) -> str:
    return signedlist.url(name)


def is_fresh() -> bool:
    return signedlist.is_fresh(SPEC)


def refresh(force: bool = False, pubkey: str | None = None) -> tuple[bool, str]:
    return signedlist.refresh(SPEC, force, pubkey)


def load(pubkey: str | None = None) -> list[Entry]:
    """Cached list, re-verified on every load; any problem means "no entries" (nothing gets hidden)."""
    loaded = signedlist.load(SPEC, pubkey)
    return loaded.entries if loaded else []


def status() -> str:
    return signedlist.describe(signedlist.load(SPEC))
