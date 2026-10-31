"""Orchestration: pick backends, honour skip rules, run scans, summarise. No Qt in here."""
from __future__ import annotations

import time
from dataclasses import dataclass

from . import gaming
from .scanners.aur_malware_check import AurMalwareCheck
from .scanners.aur_scan import AurScan
from .scanners.base import CLEAN, CRITICAL, ERROR, UNAVAILABLE, USABLE, Finding, ScanResult, Scanner, worst
from .scanners.builtin_list import BuiltinList
from .settings import Settings


def enabled_scanners(s: Settings) -> list[Scanner]:
    pairs = [(s.use_aur_malware_check, AurMalwareCheck), (s.use_aur_scan, AurScan), (s.use_builtin_list, BuiltinList)]
    return [cls() for on, cls in pairs if on]


def skip_reason(s: Settings, *, manual: bool) -> str | None:
    """Why an automatic scan must not run now; manual scans are never skipped."""
    if manual:
        return None
    if s.skip_in_gaming_mode and gaming.gaming_active():
        return "gaming mode active"
    if s.skip_on_battery and gaming.on_battery():
        return "running on battery"
    return None


@dataclass
class Report:
    results: list[ScanResult]
    skipped: str | None = None

    @property
    def status(self) -> str:
        return worst(self.results)

    @property
    def findings(self) -> list[Finding]:
        return [f for r in self.results for f in r.findings]

    @property
    def kind(self) -> str:
        """Notification/icon class: "bad" (findings, or no scanner could run), "info" (skipped), else "good"."""
        if self.skipped:
            return "info"
        if self.findings or not any(r.status in USABLE for r in self.results):
            return "bad"
        return "good"

    def summary(self) -> str:
        if self.skipped:
            return f"Scan skipped: {self.skipped}"
        if not self.results:
            return "No AUR scanner enabled. Enable one in Settings."
        if self.findings:
            n = len(self.findings)
            return f"{n} finding{'s' if n != 1 else ''} – review before using the affected software"
        ran = [r for r in self.results if r.status in USABLE]
        problems = [r for r in self.results if r.status not in USABLE]
        if not ran:
            return "Scan failed: " + "; ".join(f"{r.backend}: {r.message}" for r in problems)[:300]
        text = "No threats found (" + ", ".join(r.backend for r in ran) + ")"
        if problems:
            text += "; not run: " + ", ".join(f"{r.backend} ({r.status})" for r in problems)
        return text


def run_scan(s: Settings, *, manual: bool = False) -> Report:
    reason = skip_reason(s, manual=manual)
    if reason:
        return Report([], skipped=reason)
    results: list[ScanResult] = []
    for sc in enabled_scanners(s):  # every enabled scanner gets its own result, even when it cannot run
        t0 = time.monotonic()
        if not sc.available():
            reason = sc.unavailable_reason()
            results.append(ScanResult(sc.name, UNAVAILABLE, [], reason, log=f"Not run: {reason}"))
            continue
        if s.update_sources_before_scan:
            try:
                sc.update()
            except Exception:  # noqa: BLE001 - a failed update must never block the scan
                pass
        try:
            r = sc.scan()
        except Exception as e:  # noqa: BLE001
            r = ScanResult(sc.name, ERROR, [], str(e), log=f"Scanner crashed: {e}")
        r.duration_s = time.monotonic() - t0
        results.append(r)
    return Report(results)


def infected_packages(report: Report) -> list[str]:
    return sorted({f.package for f in report.findings if f.package and f.severity == CRITICAL})
