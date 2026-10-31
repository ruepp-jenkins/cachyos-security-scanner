"""Adapter for KiefStudioMA/ks-aur-scanner (`aur-scan`, AUR package `aur-scanner`).

`aur-scan system --fail-on <level>` audits installed AUR packages and exits non-zero when findings
reach that level. The exact non-zero codes are not documented, so any non-zero code with
recognisable scan output is treated as "findings"; 126/127/124 are treated as errors.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

from .. import vendor
from .base import CLEAN, ERROR, WARNING, Finding, Scanner, ScanResult, run, which

_ERROR_CODES = {124, 126, 127}
LOG_TAIL = 100_000


_HEADER = re.compile(r"^Scanning:\s+(\S+)\s+ISSUES:\s*(.*?)\s*$")
_ISSUE = re.compile(r"^\s{2,}([A-Z][A-Z0-9]*-\d+)\s+(.+?)\s*$")


def is_ignored(pkg: str, code: str, ignore: set[str]) -> bool:
    return code in ignore or pkg in ignore or f"{pkg}:{code}" in ignore


def recognized(out: str) -> bool:
    return any(ln.startswith("Scanning:") for ln in out.splitlines())


def parse_output(out: str, label: str, ignore: frozenset[str] | set[str] = frozenset()) -> list[Finding]:
    """One finding per package that `aur-scan system` reports issues for.

    Output format (seen in practice):
        Scanning: <pkg> ISSUES: 10 critical
            CODE-001 Title - /path/to/file
    The trailing summary block ("Severity: 11 critical ...") is deliberately not a finding.
    Issues matching `ignore` (code, package or package:CODE) are dropped; a package without remaining issues
    produces no finding.
    """
    findings: list[Finding] = []
    pkg = counts = None
    issues: list[tuple[str, str, str]] = []

    def flush() -> None:
        kept = [i for i in issues if not is_ignored(pkg or "", i[0], set(ignore))]
        if pkg and kept:
            groups: dict[tuple[str, str], int] = {}
            for code, title, _ in kept:
                key = (code, title.split(": ")[0])
                groups[key] = groups.get(key, 0) + 1
            what = ", ".join(f"{c} {t}" + (f" ×{n}" if n > 1 else "") for (c, t), n in groups.items())
            detail = "\n".join(f"{c} {t}" + (f"  [{p}]" if p else "") for c, t, p in kept)
            n = len(kept)
            findings.append(Finding(WARNING, f"{pkg}: {n} issue{'s' if n != 1 else ''} – {what}", label, package=pkg, detail=detail))

    for line in out.splitlines():
        m = _HEADER.match(line)
        if m:
            flush()
            pkg, counts, issues = m.group(1), m.group(2), []
            continue
        if line.startswith("Scanning:"):  # "Scanning: pkg OK": a clean package ends the previous block
            flush()
            pkg, issues = None, []
            continue
        m = _ISSUE.match(line)
        if m and pkg:
            title, _, path = m.group(2).rpartition(" - /")
            issues.append((m.group(1), title or m.group(2), ("/" + path) if title else ""))
        elif pkg and line.strip() and not line.startswith(" "):
            flush()
            pkg, issues = None, []  # summary block reached
    flush()
    return findings


REPO_URL = "https://github.com/KiefStudioMA/ks-aur-scanner.git"


def _dir() -> Path:
    return vendor.vendor_root() / "ks-aur-scanner"


def _built() -> Path:
    return _dir() / "target" / "release" / "aur-scan"


BUILD_CMD = ["cargo", "build", "--release", "--locked", "-p", "aur-scanner-cli"]


class AurScan(Scanner):
    """Uses `aur-scan` from PATH (AUR package) or, if absent, clones the repo and builds it with cargo.

    Upstream publishes no prebuilt binaries, so building needs git, cargo and clang (pacman: rust clang).
    The pacman package of this app depends on them, so normally this just works.
    """

    name = "aur_scan"
    label = "aur-scan (ks-aur-scanner)"

    def __init__(self, ignore: list[str] | None = None) -> None:
        self._ignore = frozenset(ignore or [])
        self._prepared = False
        self._build_log = ""

    def _binary(self) -> str | None:
        return which("aur-scan") or (str(_built()) if _built().exists() else None)

    def available(self) -> bool:
        return self._binary() is not None or (which("git") is not None and which("cargo") is not None)

    def unavailable_reason(self) -> str:
        missing = [t for t in ("git", "cargo") if not which(t)]
        return (f"aur-scan is not installed and cannot be built because {' and '.join(missing)} "
                f"{'is' if len(missing) == 1 else 'are'} missing (sudo pacman -S rust git clang, "
                "or install the 'aur-scanner' package from the AUR)")

    def _build(self) -> tuple[bool, str]:
        code, out = run(BUILD_CMD + ["--manifest-path", str(_dir() / "Cargo.toml")], 3600)
        return code == 0, out

    def update(self) -> None:
        self._prepared = True
        if which("aur-scan"):
            return  # package-managed
        before = vendor.head(_dir()) if _dir().exists() else ""
        ok, msg = vendor.ensure_repo(REPO_URL, _dir())
        if not ok:
            self._build_log = f"git: {msg}"
            return
        if (vendor.head(_dir()) != before or not _built().exists()) and which("cargo"):
            built, out = self._build()
            if not built:  # broken tree or toolchain trouble: start from a clean checkout once
                shutil.rmtree(_dir(), ignore_errors=True)
                if vendor.ensure_repo(REPO_URL, _dir())[0]:
                    built, out = self._build()
            self._build_log = "" if built else out

    def scan(self) -> ScanResult:
        if self._binary() is None and not self._prepared:
            self.update()
        binary = self._binary()
        if binary is None:
            return ScanResult(self.name, ERROR, [], "aur-scan could not be set up: "
                              + (self._build_log.strip().splitlines() or ["build failed"])[-1][:200],
                              log=self._build_log[-LOG_TAIL:])
        code, out = run([binary, "--no-color", "system", "--fail-on", "high"], 1800)
        if code == 0:
            return ScanResult(self.name, CLEAN, log=out)
        if code in _ERROR_CODES:
            return ScanResult(self.name, ERROR, [], f"exit {code}: {out[-500:]}", log=out)
        findings = parse_output(out, self.label, self._ignore)
        if not findings and recognized(out):
            return ScanResult(self.name, CLEAN, log=out)  # everything it reported is on the ignore list
        if not findings:
            findings = [Finding(WARNING, "aur-scan reported findings at or above 'high'", self.label)]
        return ScanResult(self.name, WARNING, findings, out[-2000:], log=out)
