"""Orchestration: pick backends, honour skip rules, run scans, summarise. No Qt in here."""
from __future__ import annotations

from dataclasses import dataclass

from . import gaming
from .scanners.aur_malware_check import AurMalwareCheck
from .scanners.aur_scan import AurScan
from .scanners.base import CLEAN, CRITICAL, ERROR, Finding, ScanResult, Scanner, worst
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
        """Notification/icon class: "bad" (findings or every scanner failed), "info" (skipped), else "good"."""
        if self.skipped:
            return "info"
        if self.findings or not self.results or all(r.status == ERROR for r in self.results):
            return "bad"
        return "good"

    def summary(self) -> str:
        if self.skipped:
            return f"Scan skipped: {self.skipped}"
        if not self.results:
            return "No scanner available. Install one in Settings."
        if self.findings:
            n = len(self.findings)
            return f"{n} finding{'s' if n != 1 else ''} – review before using the affected software"
        errs = [r for r in self.results if r.status == ERROR]
        if errs and len(errs) == len(self.results):
            return "Scan failed: " + "; ".join(f"{r.backend}: {r.message}" for r in errs)[:300]
        ok = ", ".join(r.backend for r in self.results if r.status == CLEAN)
        return f"No threats found ({ok})" + (f"; {len(errs)} scanner(s) had errors" if errs else "")


def run_scan(s: Settings, *, manual: bool = False) -> Report:
    reason = skip_reason(s, manual=manual)
    if reason:
        return Report([], skipped=reason)
    results: list[ScanResult] = []
    for sc in enabled_scanners(s):
        if not sc.available():
            continue
        if s.update_sources_before_scan:
            try:
                sc.update()
            except Exception:  # noqa: BLE001 - a failed update must never block the scan
                pass
        try:
            results.append(sc.scan())
        except Exception as e:  # noqa: BLE001
            results.append(ScanResult(sc.name, ERROR, [], str(e)))
    return Report(results)


def infected_packages(report: Report) -> list[str]:
    return sorted({f.package for f in report.findings if f.package and f.severity == CRITICAL})
