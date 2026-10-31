"""Common types for scanner backends."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field

CLEAN, WARNING, CRITICAL, ERROR = "clean", "warning", "critical", "error"
_RANK = {CLEAN: 0, WARNING: 1, ERROR: 2, CRITICAL: 3}


@dataclass
class Finding:
    severity: str
    title: str
    source: str
    package: str | None = None  # set when the finding maps to an installed pacman package


@dataclass
class ScanResult:
    backend: str
    status: str = CLEAN
    findings: list[Finding] = field(default_factory=list)
    message: str = ""
    log: str = ""  # raw tool output, kept for the scan history

    @property
    def ok(self) -> bool:
        return self.status in (CLEAN, WARNING, CRITICAL)


def worst(results: list[ScanResult]) -> str:
    return max((r.status for r in results), key=_RANK.get, default=CLEAN)


def run(cmd: list[str], timeout: int = 600) -> tuple[int, str]:
    """Run a command without a shell; returns (exit code, combined output)."""
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

    def update(self) -> None:  # refresh blocklists etc.; failures must not abort the scan
        pass

    def scan(self) -> ScanResult:
        raise NotImplementedError


def which(binary: str) -> str | None:
    return shutil.which(binary)
