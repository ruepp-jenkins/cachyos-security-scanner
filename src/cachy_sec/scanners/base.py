"""Common types for scanner backends."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field

CLEAN, WARNING, CRITICAL, ERROR = "clean", "warning", "critical", "error"
USABLE = (CLEAN, WARNING, CRITICAL)  # statuses that mean "the scanner actually ran"
_RANK = {CLEAN: 0, WARNING: 1, ERROR: 2, CRITICAL: 3}


@dataclass
class Finding:
    severity: str
    title: str
    source: str
    package: str | None = None  # set when the finding maps to an installed pacman package
    detail: str = ""  # optional multi-line explanation shown in details views and the history
    files: list[str] = field(default_factory=list)  # files the finding refers to (absolute paths), for "open files"
    version: str = ""  # installed version of `package` when found; ignores are bound to it
    codes: list[str] = field(default_factory=list)  # rule codes behind the finding (scanner specific)
    rules: list[tuple[str, str, int]] = field(default_factory=list)  # (code, short title, occurrences) per rule

@dataclass
class ScanResult:
    backend: str
    status: str = CLEAN
    findings: list[Finding] = field(default_factory=list)
    message: str = ""
    log: str = ""  # raw tool output, kept for the scan history
    duration_s: float = 0.0
    notes: list[str] = field(default_factory=list)  # short hints shown with the findings (why something was/was not hidden)

    @property
    def ok(self) -> bool:
        return self.status in (CLEAN, WARNING, CRITICAL)


def worst(results: list[ScanResult]) -> str:
    return max((r.status for r in results), key=_RANK.get, default=CLEAN)


_low_priority = True  # set per scan from the settings (see engine.run_scan)


def set_low_priority(enabled: bool) -> None:
    global _low_priority
    _low_priority = enabled


def priority_prefix() -> list[str]:
    """`nice -n 19` plus the lowest best-effort I/O class, for whichever of the two tools exist."""
    prefix: list[str] = []
    if shutil.which("nice"):
        prefix += ["nice", "-n", "19"]
    if shutil.which("ionice"):
        prefix += ["ionice", "-c", "2", "-n", "7"]  # best-effort, lowest level: slow but never starved like "idle"
    return prefix


def run(cmd: list[str], timeout: int = 600, low_priority: bool = False) -> tuple[int, str]:
    """Run a command without a shell; returns (exit code, combined output).

    low_priority: run it niced (CPU) and with the lowest I/O priority, if the user's setting allows it. Meant for the
    heavy work (scanners, builds); never for things like package removal.
    """
    if low_priority and _low_priority:
        cmd = priority_prefix() + cmd
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    except OSError as e:
        return 127, str(e)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


class Scanner:
    name = "base"
    label = "base"

    def available(self) -> bool:
        raise NotImplementedError

    def unavailable_reason(self) -> str:
        return "not installed"

    def update(self) -> None:  # refresh blocklists etc.; failures must not abort the scan
        pass

    def scan(self) -> ScanResult:
        raise NotImplementedError


def which(binary: str) -> str | None:
    return shutil.which(binary)
