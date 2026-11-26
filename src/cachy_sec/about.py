"""What the "About" window shows: versions of the app, the scanners and their data. No Qt in here.

Read-only: nothing is downloaded, updated or built. A part that cannot be determined says so instead of failing.
"""
from __future__ import annotations

import platform
import time
from collections.abc import Callable
from pathlib import Path

from . import __commit__, __version__, blocklist, fplist, signedlist, updater, vendor
from .scanners import aur_malware_check as amc
from .scanners import aur_scan, clamd
from .scanners.base import run, which
from .settings import Settings

Section = tuple[str, list[tuple[str, str]]]

PROJECT_URL = f"https://github.com/{updater.GITHUB_REPO}"
COPYRIGHT = "Copyright © ruepp-jenkins (Stefan Ruepp)"
PROGRAM = "This program"


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


def package_dir() -> Path:
    return Path(__file__).resolve().parent


def commit() -> str:
    """Commit of the running code: stamped into releases; read from git when run from a source checkout."""
    if __commit__:
        return __commit__[:7]
    root = package_dir().parents[1]  # <checkout>/src/cachy_sec
    if (root / ".git").exists() and which("git"):
        found = vendor.version(root)
        if found != "unknown":
            return found
    return "unknown (not recorded in this build)"


def installation() -> str:
    if updater.updates_dir().resolve() in package_dir().parents:
        return "downloaded app update"
    return "source checkout" if __version__ == "0.0.0" else "installed package"


def _program() -> list[tuple[str, str]]:
    return [("Version", app_version()), ("Commit", commit()), ("Installation", installation()),
            ("Location", str(package_dir())), ("Python", platform.python_version())]


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


def _list(spec: signedlist.Spec) -> list[tuple[str, str]]:
    loaded = signedlist.load(spec)
    error = signedlist.last_error(spec)
    if loaded is None:
        rows = [("Status", "no verified copy yet" if not error else "not available")]
    else:
        n = len(loaded.entries)
        published = loaded.published.replace("T", " ").replace("Z", " UTC") or "unknown"
        rows = [("Status", f"active, signature verified, {n} {'entry' if n == 1 else 'entries'}"),
                ("Published", published),
                ("Commit", loaded.commit[:7] or "not recorded in this copy"),
                ("Downloaded", time.strftime("%Y-%m-%d %H:%M", time.localtime(loaded.fetched)))]
    if error:
        rows.append(("Last download", f"failed: {error}"))
    return rows


def collect(s: Settings) -> list[Section]:
    def title(name: str, enabled: bool) -> str:
        return name if enabled else f"{name} (switched off)"

    def community_list(name: str, enabled: bool, spec: signedlist.Spec) -> Section:
        if not enabled:
            return title(name, False), [("Status", "not used")]
        return name, _safe(lambda: _list(spec))

    return [(PROGRAM, _safe(_program)),
            community_list("Community blocklist", s.use_community_blocklist, blocklist.SPEC),
            community_list("False-positive list", s.use_aur_scan and s.use_false_positive_list, fplist.SPEC),
            (title("aur-malware-check", s.use_aur_malware_check), _safe(_aur_malware_check)),
            (title("aur-scan (ks-aur-scanner)", s.use_aur_scan), _safe(_aur_scan)),
            ("ClamAV", _safe(_clamav))]
