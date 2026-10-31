"""Orchestration: pick backends, honour skip rules, run scans, summarise. No Qt in here."""
from __future__ import annotations

import time
from dataclasses import dataclass

from . import gaming
from .scanners.aur_malware_check import AurMalwareCheck
from .scanners.aur_scan import AurScan
from .scanners.base import CLEAN, CRITICAL, ERROR, USABLE, Finding, ScanResult, Scanner, set_low_priority, worst
from .scanners.blocklist import CommunityBlocklist
from .settings import Settings


def enabled_scanners(s: Settings) -> list[Scanner]:
    pairs = [(s.use_aur_malware_check, AurMalwareCheck),
             (s.use_aur_scan, lambda: AurScan(s.ignored_findings, s.use_false_positive_list)),
             (s.use_community_blocklist, CommunityBlocklist)]
    return [make() for on, make in pairs if on]


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
    def notes(self) -> list[str]:
        return [n for r in self.results for n in r.notes]

    @property
    def kind(self) -> str:
        """Notification/icon class: "bad" (findings, or any enabled scanner failed to run), "info" (skipped), else "good"."""
        if self.skipped:
            return "info"
        if self.findings or not self.results or any(r.status not in USABLE for r in self.results):
            return "bad"
        return "good"

    def summary(self) -> str:
        if self.skipped:
            return f"Scan skipped: {self.skipped}"
        if not self.results:
            return "No AUR scanner enabled. Enable one in Settings."
        if self.findings:
            n = len(self.findings)
            who = ", ".join(r.backend for r in self.results if r.findings)  # which scanner(s) reported it
            return f"{n} finding{'s' if n != 1 else ''} from {who} – review before using the affected software"
        ran = [r for r in self.results if r.status in USABLE]
        problems = [r for r in self.results if r.status not in USABLE]
        if not problems:
            return "No threats found (" + ", ".join(r.backend for r in ran) + ")"
        # an enabled scanner that could not run means incomplete protection: report it as an error
        head = "Scan incomplete" if ran else "Scan failed"
        return f"{head}: " + "; ".join(f"{r.backend}: {r.message}" for r in problems)[:300]


def refresh_lists(s: Settings, force: bool = False) -> dict[str, str]:
    """Download the community lists the settings use (skipped while the cached copy is fresh). Never raises."""
    from . import blocklist, fplist  # local: keeps engine importable without the list modules during tests

    out: dict[str, str] = {}
    try:
        if s.use_community_blocklist:
            out["blocklist"] = blocklist.refresh(force)[1]
        if s.use_aur_scan and s.use_false_positive_list:
            out["false-positives"] = fplist.refresh(force)[1]
    except Exception as e:  # noqa: BLE001 - a failed download must never break the app
        out["error"] = str(e)
    return out


def run_scan(s: Settings, *, manual: bool = False) -> Report:
    reason = skip_reason(s, manual=manual)
    if reason:
        return Report([], skipped=reason)
    set_low_priority(s.low_priority_scans)
    results: list[ScanResult] = []
    for sc in enabled_scanners(s):  # every enabled scanner gets its own result, even when it cannot run
        t0 = time.monotonic()
        if not sc.available():
            reason = sc.unavailable_reason()
            results.append(ScanResult(sc.name, ERROR, [], f"not available: {reason}", log=f"Not run: {reason}"))
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
