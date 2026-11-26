"""What the "About" window shows: versions of the app, the scanners and their data. No Qt in here.

Read-only: nothing is downloaded, updated or built. A part that cannot be determined says so instead of failing.
"""
from __future__ import annotations

import platform
import time
from collections.abc import Callable
from pathlib import Path

from . import __version__, blocklist, fplist, signedlist, updater, vendor
from .scanners import aur_malware_check as amc
from .scanners import aur_scan, clamd
from .scanners.base import run, which
from .settings import Settings

Section = tuple[str, list[tuple[str, str]]]

PROJECT_URL = f"https://github.com/{updater.GITHUB_REPO}"


def links() -> list[tuple[str, str]]:
    return [("Help (documentation)", updater.docs_url()),
            ("Project page", PROJECT_URL),
            ("Releases and changes", f"{PROJECT_URL}/releases"),
            ("Issues", f"{PROJECT_URL}/issues"),
            ("License (MIT)", f"{PROJECT_URL}/blob/master/LICENSE")]


UPSTREAM = [("aur-malware-check", "https://github.com/lenucksi/aur-malware-check"),
            ("ks-aur-scanner", "https://github.com/KiefStudioMA/ks-aur-scanner"),
            ("ClamAV", "https://www.clamav.net/")]


def app_version() -> str:
    text = "development build (from source)" if __version__ == "0.0.0" else __version__
    installed = updater.effective_version()
    if installed != __version__:
        text += f" – version {installed} is installed, restart to use it"
    return text


def _safe(rows: Callable[[], list[tuple[str, str]]]) -> list[tuple[str, str]]:
    try:
        return rows()
    except Exception as e:  # noqa: BLE001 - information only
        return [("Status", f"could not be determined ({e})")]


def _checkout(directory: Path) -> str:
    if not directory.exists():
        return "not downloaded yet (happens with the first scan)"
    return f"commit {vendor.version(directory)}"


def _aur_malware_check() -> list[tuple[str, str]]:
    wrapper = which("aur-malware-check")
    if wrapper:
        return [("Program", f"installed command {wrapper} (updated by your package manager)")]
    d = amc.vendor_dir()
    rows = [("Program", _checkout(d))]
    counts = amc.package_counts()
    if counts:
        rows.append(("Package lists", f"{sum(counts.values())} names in {len(counts)} campaigns"))
    definitions = d / "data" / "campaigns.json"
    if definitions.is_file():
        rows.append(("Campaign definitions", "file of " + time.strftime("%Y-%m-%d %H:%M",
                                                                        time.localtime(definitions.stat().st_mtime))))
    return rows


def _aur_scan() -> list[tuple[str, str]]:
    system = which("aur-scan")
    binary = system or aur_scan.built_binary()
    if not binary:
        return [("Program", "not built yet (happens with the first scan while aur-scan is enabled)")]
    code, out = run([binary, "--version"], 30)
    version = out.strip() if code == 0 and out.strip() else "unknown"
    source = f"installed command {system}" if system else f"built by this app, {_checkout(aur_scan.source_dir())}"
    return [("Version", version), ("Source", source),
            ("Threat indicators", aur_scan.indicator_info(binary) or "unknown")]


def parse_clamav_version(line: str) -> list[tuple[str, str]]:
    """"ClamAV 1.5.1/27800/Wed Nov 25 09:00:00 2026" -> engine and signature database."""
    engine, _, rest = line.partition("/")
    signatures, _, date = rest.partition("/")
    rows = [("Engine", engine.strip() or "unknown")]
    rows.append(("Signatures", f"version {signatures}" + (f" of {date}" if date else "") if signatures
                 else "unknown (is clamd running?)"))
    return rows


def _clamav() -> list[tuple[str, str]]:
    if not which("clamdscan"):
        return [("Status", "not installed (optional, package 'clamav')")]
    line = clamd.database_info()
    if line == "unknown":
        return [("Status", "installed, but the version could not be read (is clamd running?)")]
    return parse_clamav_version(line)


def _lists() -> list[tuple[str, str]]:
    return [(name, signedlist.state_line(spec, signedlist.load(spec)))
            for name, spec in (("Blocklist", blocklist.SPEC), ("False positives", fplist.SPEC))]


def collect(s: Settings) -> list[Section]:
    def title(name: str, enabled: bool) -> str:
        return name if enabled else f"{name} (switched off)"

    return [(title("aur-malware-check", s.use_aur_malware_check), _safe(_aur_malware_check)),
            (title("aur-scan (ks-aur-scanner)", s.use_aur_scan), _safe(_aur_scan)),
            ("ClamAV", _safe(_clamav)),
            ("Community lists", _safe(_lists)),
            ("System", [("Python", platform.python_version())])]
