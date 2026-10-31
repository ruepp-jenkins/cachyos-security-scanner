"""Community blocklist of known malicious / compromised AUR packages, maintained in lists/blocklist_aur.json.

Signed and published like the false-positive list (see signedlist). An entry flags a package name, optionally only
specific versions (glob allowed; no versions = every version). Only reports findings; removal always needs the
user's confirmation.
"""
from __future__ import annotations

import datetime
import fnmatch
import re
from dataclasses import dataclass

from . import signedlist

SCHEMA = 1
LIST_NAME = "blocklist_aur.json"
SIG_NAMESPACE = "cachy-security-scanner-blocklist"
MAX_BYTES = 2_000_000
MAX_ENTRIES = 20000

_PKG = re.compile(r"^[a-z0-9@._+-]{1,100}$")
_VER = re.compile(r"^[0-9A-Za-z:.+_~*?\[\]-]{1,100}$")


@dataclass
class Entry:
    package: str
    versions: list[str]  # ["*"] = every version
    reason: str
    author: str
    reported: str
    description: str = ""
    reference: str = ""


def validate(data: object) -> list[Entry]:
    """Strict schema check; raises ValueError naming the first problem."""
    if not isinstance(data, dict) or data.get("schema") != SCHEMA or not isinstance(data.get("entries"), list):
        raise ValueError(f"expected an object with schema={SCHEMA} and an entries list")
    if len(data["entries"]) > MAX_ENTRIES:
        raise ValueError("too many entries")
    out: list[Entry] = []
    for i, e in enumerate(data["entries"], 1):
        if not isinstance(e, dict):
            raise ValueError(f"entry {i}: not an object")
        pkg = e.get("package")
        if not isinstance(pkg, str) or not _PKG.match(pkg):
            raise ValueError(f"entry {i}: invalid package")
        where = f"entry {i} ({pkg})"
        vers = e.get("versions", ["*"])
        if not isinstance(vers, list) or not vers or not all(isinstance(v, str) and _VER.match(v) for v in vers):
            raise ValueError(f"{where}: versions must be a non-empty list of version strings or globs (omit for all)")
        reason, author, reported = e.get("reason"), e.get("author"), e.get("reported")
        desc, ref = e.get("description", ""), e.get("reference", "")
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
        out.append(Entry(pkg, list(vers), reason, author.strip(), reported, desc, ref))
    return out


def match(entries: list[Entry], package: str, version: str) -> Entry | None:
    for e in entries:
        if e.package == package and any(fnmatch.fnmatchcase(version, v) for v in e.versions):
            return e
    return None


SPEC = signedlist.Spec(LIST_NAME, SIG_NAMESPACE, lambda data: validate(data), MAX_BYTES)


def refresh(force: bool = False, pubkey: str | None = None) -> tuple[bool, str]:
    return signedlist.refresh(SPEC, force, pubkey)


def load(pubkey: str | None = None) -> signedlist.Loaded | None:
    return signedlist.load(SPEC, pubkey)


def status() -> str:
    return signedlist.describe(load(), "entry", "entries", signedlist.last_error(SPEC))
