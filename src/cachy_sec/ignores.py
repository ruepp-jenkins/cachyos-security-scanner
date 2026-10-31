"""Per-software, per-version ignores for findings.

An entry says: "for package X at exactly version V, the rule codes C are accepted". As soon as the package
is updated (version changes) the entry no longer matches and the findings are reported again. A rule code
that is not in C (a new kind of finding for the same version) is reported too.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .scanners.base import run
from .settings import config_path


def store_path() -> Path:
    return config_path().parent / "ignored_findings.json"


@dataclass
class Ignore:
    package: str
    version: str
    codes: list[str] = field(default_factory=list)
    added: str = ""

    def label(self) -> str:
        return f"{self.package} {self.version}: {', '.join(self.codes)}"


def load(path: Path | None = None) -> list[Ignore]:
    try:
        data = json.loads((path or store_path()).read_text())
    except (OSError, ValueError):
        return []
    out = []
    for d in data if isinstance(data, list) else []:
        if isinstance(d, dict) and isinstance(d.get("package"), str) and isinstance(d.get("version"), str) \
                and isinstance(d.get("codes"), list):
            out.append(Ignore(d["package"], d["version"], [str(c) for c in d["codes"]], str(d.get("added", ""))))
    return out


def _save(entries: list[Ignore], path: Path | None = None) -> None:
    p = path or store_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps([asdict(e) for e in entries], indent=1))
    tmp.replace(p)


def add(package: str, version: str, codes: list[str], path: Path | None = None) -> None:
    if not package or not version or not codes:
        raise ValueError("package, version and codes are required")  # without a version it could never expire
    entries = load(path)
    for e in entries:
        if e.package == package and e.version == version:
            e.codes = sorted(set(e.codes) | set(codes))
            break
    else:
        entries.append(Ignore(package, version, sorted(set(codes)), time.strftime("%Y-%m-%d %H:%M")))
    _save(entries, path)


def remove(package: str, version: str, path: Path | None = None) -> None:
    _save([e for e in load(path) if not (e.package == package and e.version == version)], path)


def matcher(versions: dict[str, str], entries: list[Ignore] | None = None):
    """Return suppress(package, code): True if (package, installed version, code) was accepted."""
    accepted = {(e.package, e.version): set(e.codes) for e in (load() if entries is None else entries)}

    def suppress(package: str, code: str) -> bool:
        v = versions.get(package)
        return v is not None and code in accepted.get((package, v), ())

    return suppress


@dataclass
class Row:
    """One ignorable entry in the findings window: a rule that fired for a package at its installed version."""
    package: str
    version: str
    code: str
    title: str
    count: int
    files: list[str] = field(default_factory=list)  # files that triggered this rule, for "Open files"


def rows(findings) -> list[Row]:
    out = []
    for f in findings:
        if f.package:  # version may be unknown: such a row can be inspected but not ignored
            out += [Row(f.package, f.version, code, title, n, f.rule_files.get(code, f.files)) for code, title, n in f.rules]
    return out


def srcinfo_version(directory: Path) -> str:
    """Version of the package files that were scanned: epoch:pkgver-pkgrel from the .SRCINFO next to the PKGBUILD.

    aur-scan analyses the PKGBUILD in the helper's cache (e.g. ~/.cache/yay/<pkg>), which can be newer or older than
    what is installed. Ignores and the false-positive list therefore bind to this version. Empty if unreadable.
    """
    try:
        text = (directory / ".SRCINFO").read_text(errors="replace")
    except OSError:
        return ""
    base: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.strip().partition(" = ")
        if key == "pkgname":
            break  # the pkgbase block comes first; per-package blocks follow
        if sep and key in ("pkgver", "pkgrel", "epoch"):
            base.setdefault(key, value.strip())
    if not base.get("pkgver") or not base.get("pkgrel"):
        return ""
    epoch = base.get("epoch", "")
    return (f"{epoch}:" if epoch and epoch != "0" else "") + f"{base['pkgver']}-{base['pkgrel']}"


def installed_versions() -> dict[str, str]:
    """Foreign (AUR) packages and their full installed version (epoch:pkgver-pkgrel). Empty if pacman fails."""
    code, out = run(["pacman", "-Qm"], 30)
    if code != 0:
        return {}
    return dict(ln.split(None, 1) for ln in out.splitlines() if len(ln.split(None, 1)) == 2)
