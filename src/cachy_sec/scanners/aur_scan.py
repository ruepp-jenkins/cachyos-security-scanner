"""Adapter for KiefStudioMA/ks-aur-scanner (`aur-scan`, AUR package `aur-scanner`).

`aur-scan system --fail-on <level>` audits installed AUR packages and exits non-zero when findings
reach that level. The exact non-zero codes are not documented, so any non-zero code with
recognisable scan output is treated as "findings"; 126/127/124 are treated as errors.
"""
from __future__ import annotations

from pathlib import Path

from .. import vendor
from .base import CLEAN, ERROR, WARNING, Finding, Scanner, ScanResult, run, which

_ERROR_CODES = {124, 126, 127}


REPO_URL = "https://github.com/KiefStudioMA/ks-aur-scanner.git"


def _dir() -> Path:
    return vendor.vendor_root() / "ks-aur-scanner"


def _built() -> Path:
    return _dir() / "target" / "release" / "aur-scan"


class AurScan(Scanner):
    """Uses `aur-scan` from PATH (AUR package) or, if absent, clones and builds the repo with cargo."""

    name = "aur_scan"
    label = "aur-scan (ks-aur-scanner)"

    def _binary(self) -> str | None:
        return which("aur-scan") or (str(_built()) if _built().exists() else None)

    def available(self) -> bool:
        return self._binary() is not None or (which("git") is not None and which("cargo") is not None)

    def update(self) -> None:
        if which("aur-scan"):
            return  # package-managed
        before = vendor.head(_dir()) if _dir().exists() else ""
        ok, _ = vendor.ensure_repo(REPO_URL, _dir())
        if ok and (vendor.head(_dir()) != before or not _built().exists()) and which("cargo"):
            code, _ = run(["cargo", "build", "--release", "--locked", "--manifest-path", str(_dir() / "Cargo.toml")], 1800)
            if code != 0:  # broken tree or toolchain trouble: start from a clean checkout once
                import shutil
                shutil.rmtree(_dir(), ignore_errors=True)
                if vendor.ensure_repo(REPO_URL, _dir())[0]:
                    run(["cargo", "build", "--release", "--locked", "--manifest-path", str(_dir() / "Cargo.toml")], 1800)

    def scan(self) -> ScanResult:
        if self._binary() is None:
            self.update()
        binary = self._binary()
        if binary is None:
            return ScanResult(self.name, ERROR, [], "aur-scan not available (needs git + cargo to build it)")
        code, out = run([binary, "--no-color", "system", "--fail-on", "high"], 1800)
        if code == 0:
            return ScanResult(self.name, CLEAN)
        if code in _ERROR_CODES:
            return ScanResult(self.name, ERROR, [], f"exit {code}: {out[-500:]}")
        findings = [Finding(WARNING, ln.strip()[:200], self.label)
                    for ln in out.splitlines() if "high" in ln.lower() or "critical" in ln.lower()][:50]
        if not findings:
            findings = [Finding(WARNING, "aur-scan reported findings at or above 'high'", self.label)]
        return ScanResult(self.name, WARNING, findings, out[-2000:])
