"""Adapter for KiefStudioMA/ks-aur-scanner (`aur-scan`, AUR package `aur-scanner`).

`aur-scan system --fail-on <level>` audits installed AUR packages and exits non-zero when findings
reach that level. The exact non-zero codes are not documented, so any non-zero code with
recognisable scan output is treated as "findings"; 126/127/124 are treated as errors.
"""
from __future__ import annotations

import re
import shutil
from collections.abc import Callable
from pathlib import Path

from .. import fplist, ignores, vendor
from .base import CLEAN, ERROR, WARNING, Finding, Scanner, ScanResult, run, which

_ERROR_CODES = {124, 126, 127}
LOG_TAIL = 100_000


_HEADER = re.compile(r"^Scanning:\s+(\S+)\s+ISSUES:\s*(.*?)\s*$")
_ISSUE = re.compile(r"^\s{2,}([A-Z][A-Z0-9]*-\d+)\s+(.+?)\s*$")


def is_ignored(pkg: str, code: str, ignore: set[str]) -> bool:
    return code in ignore or pkg in ignore or f"{pkg}:{code}" in ignore


def scanned_dirs(out: str) -> dict[str, Path]:
    """package -> directory of the files aur-scan reported for it (from the " - /path" part of the issue lines)."""
    dirs: dict[str, Path] = {}
    pkg = None
    for line in out.splitlines():
        m = _HEADER.match(line)
        if m:
            pkg = m.group(1)
        elif line.startswith("Scanning:"):
            pkg = None
        elif pkg and pkg not in dirs and _ISSUE.match(line) and " - /" in line:
            dirs[pkg] = Path("/" + line.rpartition(" - /")[2]).parent
    return dirs


def recognized(out: str) -> bool:
    return any(ln.startswith("Scanning:") for ln in out.splitlines())


def parse_output(out: str, label: str, ignore: frozenset[str] | set[str] = frozenset(),
                 suppress: Callable[[str, str], bool] | None = None,
                 versions: dict[str, str] | None = None) -> list[Finding]:
    """One finding per package that `aur-scan system` reports issues for.

    Output format (seen in practice):
        Scanning: <pkg> ISSUES: 10 critical
            CODE-001 Title - /path/to/file
    The trailing summary block ("Severity: 11 critical ...") is deliberately not a finding.
    Issues matching `ignore` (code, package or package:CODE) or `suppress(package, code)` (per-version ignores)
    are dropped; a package without remaining issues produces no finding.
    """
    findings: list[Finding] = []
    pkg = counts = None
    issues: list[tuple[str, str, str]] = []

    def flush() -> None:
        kept = [i for i in issues if not is_ignored(pkg or "", i[0], set(ignore))
                and not (suppress and suppress(pkg or "", i[0]))]
        if pkg and kept:
            groups: dict[tuple[str, str], int] = {}
            for code, title, _ in kept:
                key = (code, title.split(": ")[0])
                groups[key] = groups.get(key, 0) + 1
            what = ", ".join(f"{c} {t}" + (f" ×{n}" if n > 1 else "") for (c, t), n in groups.items())
            detail = "\n".join(f"{c} {t}" + (f"  [{p}]" if p else "") for c, t, p in kept)
            n = len(kept)
            files = list(dict.fromkeys(p for _, _, p in kept if p))
            per_code: dict[str, list] = {}
            for (c, t), cnt in groups.items():
                per_code.setdefault(c, [t, 0])[1] += cnt
            rules = [(c, t, cnt) for c, (t, cnt) in per_code.items()]
            ver = (versions or {}).get(pkg, "")
            findings.append(Finding(WARNING, f"{pkg}{' ' + ver if ver else ''}: {n} issue{'s' if n != 1 else ''} – {what}",
                                    label, package=pkg,
                                    detail=detail, files=files, version=(versions or {}).get(pkg, ""),
                                    codes=list(dict.fromkeys(c for c, _, _ in kept)), rules=rules))

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

    def __init__(self, ignore: list[str] | None = None, use_fp_list: bool = False) -> None:
        self._ignore = frozenset(ignore or [])
        self._use_fp = use_fp_list  # signed community false-positive list from the project's GitHub (switchable in the settings)
        self._fp_checked = False
        self._fp_status = ""
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
        code, out = run(BUILD_CMD + ["--manifest-path", str(_dir() / "Cargo.toml")], 3600, low_priority=True)
        return code == 0, out

    def _refresh_fp(self) -> None:
        """Fetch the list only if there is no verified copy yet; regular refreshes happen at start and periodically."""
        self._fp_checked = True
        if self._use_fp and not fplist.load():
            ok, msg = fplist.refresh()
            self._fp_status = msg if ok else f"download/verification failed ({msg})"

    def update(self) -> None:
        self._prepared = True
        self._refresh_fp()
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
        code, out = run([binary, "--no-color", "system", "--fail-on", "high"], 1800, low_priority=True)
        if code == 0:
            return ScanResult(self.name, CLEAN, log=out)
        if code in _ERROR_CODES:
            return ScanResult(self.name, ERROR, [], f"exit {code}: {out[-500:]}", log=out)
        if self._use_fp and not self._fp_checked:
            self._refresh_fp()
        installed = ignores.installed_versions()
        versions = dict(installed)
        for pkg, d in scanned_dirs(out).items():  # the scanned PKGBUILD's version wins over the installed one
            v = ignores.srcinfo_version(d)
            if v:
                versions[pkg] = v
        user = ignores.matcher(versions)
        entries = fplist.load() if self._use_fp else []
        hits: dict[str, str] = {}

        def suppress(pkg: str, rule: str) -> bool:
            if user(pkg, rule):
                return True
            e = fplist.match(entries, pkg, versions.get(pkg, ""), rule)
            if e:
                hits[f"{pkg} {versions.get(pkg)} {rule}"] = f"{e.reason} (reported by {e.author}, {e.reported})"
            return e is not None

        findings = parse_output(out, self.label, self._ignore, suppress, versions)
        if recognized(out):  # make the "why was it (not) hidden" question answerable from the history
            reported = sorted({m.group(1) for m in map(_HEADER.match, out.splitlines()) if m})
            out += ("\n\n--- context ---\n"
                    + ("community false-positive list: " + (f"on, {len(entries)} entries ({self._fp_status or 'cache'})"
                                                            if self._use_fp else "off (Settings > aur-scan to enable)") + "\n")
                    + "scanned PKGBUILD version / installed version: "
                    + (", ".join(f"{p} {versions.get(p, '?')} / {installed.get(p, 'not installed')}" for p in reported) or "-")
                    + "\n")
        if hits:  # transparency: show what the community list hid
            out += "\n\n--- hidden by the community false-positive list ---\n" + "\n".join(
                f"{k}: {v}" for k, v in hits.items()) + "\n"
        notes: list[str] = []
        if hits:
            notes.append(f"{len(hits)} finding(s) were hidden by the community false-positive list.")
        if findings and recognized(out):
            if not self._use_fp:
                notes.append("The community false-positive list is switched off (Settings > aur-scan).")
            elif not entries:
                notes.append("The community false-positive list is on but not available "
                             f"({self._fp_status or 'no verified copy in the cache'}); nothing could be hidden.")
        if not findings and recognized(out):
            return ScanResult(self.name, CLEAN, log=out, notes=notes)  # everything it reported is on an ignore list
        if not findings:
            findings = [Finding(WARNING, "aur-scan reported findings at or above 'high'", self.label)]
        return ScanResult(self.name, WARNING, findings, out[-2000:], log=out, notes=notes)
