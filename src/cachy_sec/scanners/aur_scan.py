"""Adapter for KiefStudioMA/ks-aur-scanner (`aur-scan`, AUR package `aur-scanner`).

`aur-scan system --fail-on <level>` audits installed AUR packages and exits non-zero when findings
reach that level. The exact non-zero codes are not documented, so any non-zero code with
recognisable scan output is treated as "findings"; 126/127/124 are treated as errors.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from .. import vendor
from .base import CLEAN, ERROR, WARNING, Finding, Scanner, ScanResult, run, which

_ERROR_CODES = {124, 126, 127}
LOG_TAIL = 100_000


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

    def __init__(self) -> None:
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
        findings = [Finding(WARNING, ln.strip()[:200], self.label)
                    for ln in out.splitlines() if "high" in ln.lower() or "critical" in ln.lower()][:50]
        if not findings:
            findings = [Finding(WARNING, "aur-scan reported findings at or above 'high'", self.label)]
        return ScanResult(self.name, WARNING, findings, out[-2000:], log=out)
