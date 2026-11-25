"""Adapter for KiefStudioMA/ks-aur-scanner (`aur-scan`, AUR package `aur-scanner`).

`aur-scan system --fail-on <level>` audits installed AUR packages and exits non-zero when findings
reach that level. The exact non-zero codes are not documented, so any non-zero code with
recognisable scan output is treated as "findings"; 126/127/124 are treated as errors.
"""
from __future__ import annotations

import re
import shlex
import shutil
from collections.abc import Callable
from pathlib import Path

from .. import fplist, ignores, scanopts, vendor
from ..settings import Settings
from .base import CLEAN, CRITICAL, ERROR, WARNING, Finding, Scanner, ScanResult, run, which

_ERROR_CODES = {124, 126, 127}
LOG_TAIL = 100_000


_PREFIXES = ("Scanning:", "Fetching:")  # "Fetching:" replaces "Scanning:" with --rescan
_HEADER = re.compile(r"^(?:Scanning|Fetching):\s+(\S+)\s+ISSUES:\s*(.*?)\s*$")
# `aur-scan system` prints detail lines for critical findings only; everything else exists just as a count (or not at all)
_HIGH_COUNT = re.compile(r"(\d+) high")
UNLISTED_HIGH = "UNLISTED-HIGH"
UNLISTED_LOWER = "UNLISTED-LOWER"
_BELOW_HIGH = ("medium", "low", "info")
# rule ids are not all "ABC-001": there are e.g. EXEC-REMOTE and TI-UNCHECKED-001
_ISSUE = re.compile(r"^\s{2,}([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)\s+(.+?)\s*$")


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
        elif line.startswith(_PREFIXES):
            pkg = None
        elif pkg and pkg not in dirs and _ISSUE.match(line) and " - /" in line:
            dirs[pkg] = Path("/" + line.rpartition(" - /")[2]).parent
    return dirs


def recognized(out: str) -> bool:
    return any(ln.startswith(_PREFIXES) for ln in out.splitlines())


def ioc_hits(out: str) -> list[tuple[str, str]]:
    """(package, campaign) of the "IOC ALERT" block: installed names that are known to be malicious."""
    hits: list[tuple[str, str]] = []
    inside = False
    for line in out.splitlines():
        if line.startswith("IOC ALERT:"):
            inside = True
        elif inside:
            m = re.match(r"^\s+(\S+) -> (.+?)\s*$", line)
            if m:
                hits.append((m.group(1), m.group(2)))
            elif not line.strip() or not line.startswith(" "):
                inside = False
    return hits


def _summary_list(out: str, heading: str) -> list[str]:
    """The "    - item" lines below a heading of the summary block ("Errors:", "Skipped:")."""
    items: list[str] = []
    inside = False
    for line in out.splitlines():
        if line.strip().startswith(heading):
            inside = True
        elif inside:
            if line.startswith("    - "):
                items.append(line[6:].strip())
            else:
                inside = False
    return items


def not_reviewed(out: str) -> list[str]:
    """"package: reason" for packages aur-scan could not fetch or scan."""
    return _summary_list(out, "Errors:")


def skipped(out: str) -> list[str]:
    """Packages aur-scan did not check because no helper cache has their PKGBUILD."""
    return _summary_list(out, "Skipped:")


def _short(items: list[str], n: int = 10) -> str:
    return ", ".join(items[:n]) + (f" and {len(items) - n} more" if len(items) > n else "")


def parse_output(out: str, label: str, ignore: frozenset[str] | set[str] = frozenset(),
                 suppress: Callable[[str, str], bool] | None = None,
                 versions: dict[str, str] | None = None, fail_on: str = "high") -> list[Finding]:
    """One finding per package that `aur-scan system` reports issues for.

    Output format (seen in practice):
        Scanning: <pkg> ISSUES: 10 critical
            CODE-001 Title - /path/to/file
    The trailing summary block ("Severity: 11 critical ...") is deliberately not a finding.
    aur-scan lists only critical findings. High ones (and, if `fail_on` is lower than "high", a package whose
    header counts neither) become UNLISTED-* issues so that they are never taken for "clean".

    Issues matching `ignore` (code, package or package:CODE) or `suppress(package, code)` (per-version ignores)
    are dropped; a package without remaining issues produces no finding.
    """
    findings: list[Finding] = []
    pkg = None
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
            rule_files: dict[str, list[str]] = {}
            for c, _, p in kept:
                if p and p not in rule_files.setdefault(c, []):
                    rule_files[c].append(p)
            ver = (versions or {}).get(pkg, "")
            findings.append(Finding(WARNING, f"{pkg}{' ' + ver if ver else ''}: {n} issue{'s' if n != 1 else ''} – {what}",
                                    label, package=pkg,
                                    detail=detail, files=files, version=(versions or {}).get(pkg, ""),
                                    codes=list(dict.fromkeys(c for c, _, _ in kept)), rules=rules,
                                    rule_files=rule_files))

    for line in out.splitlines():
        m = _HEADER.match(line)
        if m:
            flush()
            pkg, counts, issues = m.group(1), m.group(2), []
            high = _HIGH_COUNT.search(counts)
            if high and fail_on != "critical":
                title = "high-severity finding, not listed by aur-scan system (see: aur-scan check)"
                issues = [(UNLISTED_HIGH, title, "")] * int(high.group(1))
            elif fail_on in _BELOW_HIGH and "critical" not in counts and not high:
                issues = [(UNLISTED_LOWER, "findings below high, not listed by aur-scan system (see: aur-scan check)", "")]
            continue
        if line.startswith(_PREFIXES):  # "Scanning: pkg OK": a clean package ends the previous block
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
    """Uses `aur-scan` from PATH (AUR package) or, if absent, clones the newest release tag and builds it with cargo.

    Upstream publishes no prebuilt binaries, so building needs git, cargo and clang (pacman: rust clang).
    The pacman package of this app depends on them, so normally this just works.
    """

    name = "aur_scan"
    label = "aur-scan (ks-aur-scanner)"

    def __init__(self, ignore: list[str] | None = None, use_fp_list: bool = False, settings: Settings | None = None) -> None:
        self._settings = settings or Settings()
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
        ok, msg = vendor.ensure_release(REPO_URL, _dir())
        if not ok:
            self._build_log = f"git: {msg}"
            return
        if (vendor.head(_dir()) != before or not _built().exists()) and which("cargo"):
            built, out = self._build()
            if not built:  # broken tree or toolchain trouble: start from a clean checkout once
                shutil.rmtree(_dir(), ignore_errors=True)
                if vendor.ensure_release(REPO_URL, _dir())[0]:
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
        try:
            options = scanopts.aur_scan_args(self._settings)
        except ValueError as e:
            return ScanResult(self.name, ERROR, [], f"invalid extra arguments in the options of aur-scan: {e}")
        code, out = run([binary, "--no-color", "system", *options], 1800, low_priority=True)
        if options != ["--fail-on", "high"]:
            out = f"[options: {shlex.join(options)}]\n{out}"
        missing = skipped(out)
        skip_notes = [f"aur-scan did not check {len(missing)} package(s), no PKGBUILD in an AUR helper cache: "
                      f"{_short(missing)}"] if missing else []
        if code == 0:
            return ScanResult(self.name, CLEAN, log=out, notes=skip_notes)
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

        fail_on = self._settings.aur_scan_fail_on
        findings = parse_output(out, self.label, self._ignore, suppress, versions, fail_on)
        listed = bool(parse_output(out, self.label, fail_on=fail_on))  # anything reported at all, before ignoring
        # known-malicious names are never hidden by an ignore list
        iocs = ioc_hits(out)
        findings = [Finding(CRITICAL, f"{p}: installed package matches a known-malicious name ({c})", self.label,
                            package=p, version=versions.get(p, ""), detail=f"aur-scan IOC alert: {c}")
                    for p, c in iocs] + findings
        failed = not_reviewed(out)
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
        notes: list[str] = list(skip_notes)
        if failed:
            notes.append(f"aur-scan could NOT check {len(failed)} package(s): {_short(failed, 5)}")
        if listed and fail_on in _BELOW_HIGH:
            notes.append(f"aur-scan system does not list every finding below 'high'; check single packages with "
                         "'aur-scan check <package>'.")
        if hits:
            notes.append(f"{len(hits)} finding(s) were hidden by the community false-positive list.")
        if findings and recognized(out):
            if not self._use_fp:
                notes.append("The community false-positive list is switched off (Settings > aur-scan).")
            elif not entries:
                notes.append("The community false-positive list is on but not available "
                             f"({self._fp_status or 'no verified copy in the cache'}); nothing could be hidden.")
        if not findings and failed:
            return ScanResult(self.name, ERROR, [], f"{len(failed)} package(s) could not be checked: {_short(failed, 3)}",
                              log=out, notes=notes)
        if not findings and recognized(out) and listed:
            return ScanResult(self.name, CLEAN, log=out, notes=notes)  # everything it reported is on an ignore list
        if not findings:
            findings = [Finding(WARNING, f"aur-scan reported findings at or above '{fail_on}' (see the log)", self.label)]
        status = CRITICAL if iocs else WARNING
        return ScanResult(self.name, status, findings, out[-2000:], log=out, notes=notes)
