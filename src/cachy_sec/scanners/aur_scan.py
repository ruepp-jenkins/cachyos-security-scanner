"""Adapter for KiefStudioMA/ks-aur-scanner (`aur-scan`, AUR package `aur-scanner`).

`aur-scan system --fail-on <level>` audits installed AUR packages and exits non-zero when findings
reach that level. It names only the critical findings; the others are read with `aur-scan scan <dir>
--format json` from the same helper cache directory. The exact non-zero codes are not documented, so any non-zero code with
recognisable scan output is treated as "findings"; 126/127/124 are treated as errors.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
from collections.abc import Callable
from pathlib import Path

from .. import fetch_missing, fplist, ignores, scanopts, signedlist, vendor
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
_CODE = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+")
_PKGNAME = re.compile(r"[a-z0-9@_+][a-z0-9@._+-]*")
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
# the same places in the same order as get_aur_cache_dirs() of `aur-scan system`
_HELPER_DIRS = (("XDG_CACHE_HOME", ".cache", ("yay", "paru/clone", "aura/packages", "pakku", "trizen/sources",
                                             "aurutils/sync", "pat-aur/pkgbuild/aur")),
                ("XDG_DATA_HOME", ".local/share", ("pikaur/aur_repos",)),
                ("XDG_CONFIG_HOME", ".config", ("rua/pkg",)))


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


def _option_values(options: list[str], *names: str) -> list[str]:
    values = []
    for i, token in enumerate(options):
        if token in names and i + 1 < len(options):
            values.append(options[i + 1])
        else:
            values += [token.split("=", 1)[1] for n in names if n.startswith("--") and token.startswith(n + "=")]
    return values


def find_pkg_dir(pkg: str, options: list[str]) -> Path | None:
    """The directory `aur-scan system` scanned for `pkg`: the first helper cache that has its PKGBUILD."""
    if not _PKGNAME.fullmatch(pkg):
        return None
    roots = [Path(v) for v in _option_values(options, "--cache-dir")]
    for variable, default, subdirs in _HELPER_DIRS:
        value = os.environ.get(variable, "")
        base = Path(value) if value.startswith("/") else Path.home() / default
        roots += [base / sub for sub in subdirs]
    return next((r / pkg for r in roots if (r / pkg / "PKGBUILD").exists()), None)


def parse_json_findings(text: str) -> list[dict] | None:
    """Findings of `aur-scan scan --format json` as {severity, code, title, path, line}; None if unreadable."""
    start = 0 if text.startswith("{") else text.find("\n{") + 1
    try:
        data, _ = json.JSONDecoder().raw_decode(text, start)
        result = []
        for f in data["findings"]:
            code = str(f["id"])
            location = f.get("location") or {}
            path = str(location.get("file") or "")
            title = "".join(c for c in " ".join(str(f.get("title", "")).split()) if c.isprintable())[:200]
            if _CODE.fullmatch(code):
                result.append({"severity": str(f["severity"]).lower(), "code": code, "title": title,
                               "path": path if path.startswith("/") and path.isprintable() else "",
                               "line": location.get("line")})
    except (ValueError, KeyError, TypeError, AttributeError):
        return None
    return result


def unlisted_packages(out: str, fail_on: str) -> list[str]:
    """Cached packages with findings that count for `fail_on` but have no detail line in the `system` output."""
    wanted = []
    for line in out.splitlines():
        m = _HEADER.match(line)
        if not m or not line.startswith("Scanning:") or fail_on == "critical":  # "Fetching:": not from the cache
            continue
        counts = m.group(2)
        if _HIGH_COUNT.search(counts) or (fail_on in _BELOW_HIGH and "critical" not in counts):
            wanted.append(m.group(1))
    return wanted


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
                 versions: dict[str, str] | None = None, fail_on: str = "high",
                 details: dict[str, list[dict]] | None = None) -> list[Finding]:
    """One finding per package that `aur-scan system` reports issues for.

    Output format (seen in practice):
        Scanning: <pkg> ISSUES: 10 critical
            CODE-001 Title - /path/to/file
    The trailing summary block ("Severity: 11 critical ...") is deliberately not a finding.
    aur-scan lists only critical findings. High ones (and, if `fail_on` is lower than "high", a package whose
    header counts neither) are taken from `details` (package -> parse_json_findings()). Whatever the header
    counts beyond that becomes an UNLISTED-* issue so that it is never taken for "clean".

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
            known = (details or {}).get(pkg, [])
            if high and fail_on != "critical":
                found = [d for d in known if d["severity"] == "high"]
                missing = int(high.group(1)) - len(found)
                issues = [(d["code"], d["title"], d["path"]) for d in found]
                title = "high-severity finding without details (known only to aur-scan system, e.g. its history check)"
                issues += [(UNLISTED_HIGH, title, "")] * max(missing, 0)
            elif fail_on in _BELOW_HIGH and "critical" not in counts and not high:
                levels = _SEVERITY_ORDER[2:_SEVERITY_ORDER.index(fail_on) + 1]
                issues = [(d["code"], d["title"], d["path"]) for d in known if d["severity"] in levels]
                if not issues:
                    issues = [(UNLISTED_LOWER, "findings below high, not listed by aur-scan system", "")]
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


def _marker() -> Path:
    return _dir() / "target" / "built-commit"  # which commit the binary was built from


def _built_commit() -> str:
    try:
        return _marker().read_text().strip()
    except OSError:
        return ""


def _dir() -> Path:
    return vendor.vendor_root() / "ks-aur-scanner"


def _built() -> Path:
    return _dir() / "target" / "release" / "aur-scan"


BUILD_CMD = ["cargo", "build", "--release", "--locked", "-p", "aur-scanner-cli"]


def source_dir() -> Path:
    return _dir()


def built_binary() -> str | None:
    return str(_built()) if _built().exists() else None


def indicator_info(binary: str) -> str:
    """Date and number of the threat indicators built into aur-scan; "" if it cannot say."""
    code, out = run([binary, "--no-color", "ioc"], 60)
    if code != 0:
        return ""
    return "; ".join(" ".join(ln.split()) for ln in out.splitlines()
                     if ln.strip().startswith(("Last updated", "Indicators", "Override file")))


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
        self._outdated = False  # the newest release could not be built; an older build is used

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
        """Make sure the list is current before it is used; if it cannot be downloaded, the verified copy stays."""
        self._fp_checked = True
        if self._use_fp:
            ok, msg = fplist.refresh(max_age=signedlist.SCAN_MAX_AGE_S)
            self._fp_status = msg if ok else f"download/verification failed ({msg})"

    def update(self) -> None:
        self._prepared = True
        self._refresh_fp()
        self._update_program()
        self._log_databases()

    def _update_program(self) -> None:
        system = which("aur-scan")
        if system:  # package-managed
            self.log_update(f"program: installed command {system} (updated by your package manager)")
            return
        before = vendor.version(_dir()) if _dir().exists() else ""
        ok, msg = vendor.ensure_release(REPO_URL, _dir())
        if not ok:
            self._build_log = f"git: {msg}"
            self.log_update(f"program: download FAILED: {msg}")
            return
        after = vendor.version(_dir())
        changed = f" (was {before})" if before and before != after else ""
        self.log_update(f"program (git release): {msg}; commit {after}{changed}")
        if _built().exists() and _built_commit() == vendor.head(_dir()):
            self.log_update("build: up to date, nothing to compile")
            return
        if not which("cargo"):
            self.log_update("build: skipped, cargo is not installed")
            return
        built, out = self._build()
        if not built and not _built().exists():  # nothing usable: start from a clean checkout once
            if vendor.reclone(REPO_URL, _dir(), vendor.latest_release(REPO_URL))[0]:
                built, out = self._build()
        self._build_log = "" if built else out
        if built:
            try:
                _marker().parent.mkdir(parents=True, exist_ok=True)
                _marker().write_text(vendor.head(_dir()))
            except OSError:
                pass
            self.log_update("build: compiled with cargo")
            return
        self._outdated = _built().exists()
        self.log_update("build: FAILED" + (", the previous build is still used" if self._outdated else ""))
        self.log_update("\n".join(out.strip().splitlines()[-15:]))

    def _log_databases(self) -> None:
        """Version and built-in threat indicators of aur-scan (part of the program, so they change with releases)."""
        binary = self._binary()
        if binary:
            code, out = run([binary, "--version"], 30)
            if code == 0:
                self.log_update(f"version: {out.strip()}")
            info = indicator_info(binary)
            if info:
                self.log_update(f"built-in threat indicators: {info}")
        if self._use_fp:
            result = f" (check before this scan: {self._fp_status})" if self._fp_status else ""
            self.log_update("community false-positive list: "
                            + signedlist.state_line(fplist.SPEC, signedlist.load(fplist.SPEC)) + result)

    def _read_details(self, binary: str, dirs: dict[str, Path], options: list[str]) -> dict[str, list[dict]]:
        """Run `aur-scan scan` on the given package directories to learn which findings are behind the counts."""
        extra = [a for v in _option_values(options, "-c", "--config") for a in ("--config", v)]
        details = {}
        for pkg, d in dirs.items():
            _, out = run([binary, "--no-color", *extra, "scan", str(d), "--format", "json"], 600, low_priority=True)
            found = parse_json_findings(out)
            if found is not None:
                details[pkg] = found
        return details

    def _fetch_missing(self, binary: str, names: list[str], installed: dict[str, str], options: list[str],
                       blocked: Callable[[str, str, str], bool]) -> list[fetch_missing.Prepared]:
        """Prepare and scan the packages that no helper cache holds. `blocked(package, version, code)`: this critical
        finding is not on any ignore list, so makepkg must not run the PKGBUILD."""
        extra = [a for v in _option_values(options, "-c", "--config") for a in ("--config", v)]

        def scan(directory: Path) -> list[dict] | None:
            _, out = run([binary, "--no-color", *extra, "scan", str(directory), "--format", "json"], 600,
                         low_priority=True)
            return parse_json_findings(out)

        prepared = []
        for name in names:
            def blocks(findings: list[dict], version: str, name: str = name) -> bool:
                return any(f["severity"] == "critical" and blocked(name, version, f["code"]) for f in findings)

            try:
                p = fetch_missing.prepare(name, installed.get(name, ""), scan, blocks)
            except Exception as e:  # noqa: BLE001 - one package must not stop the others
                p = fetch_missing.Prepared(name, problem=f"{type(e).__name__}: {e}"[:200])
            for line in p.log + ([f"result: {p.problem}"] if p.problem and p.problem not in p.log else []):
                self.log_update(f"missing package {name}: {line}")
            prepared.append(p)
        return prepared

    def _clean_up_fetched(self, keep: set[str]) -> None:
        for name in fetch_missing.clean_up(keep):
            self.log_update(f"fetched copy of {name} deleted (no longer needed)")

    def _coverage_notes(self, missing: list[str], prepared: list[fetch_missing.Prepared]) -> list[str]:
        """What was and was not looked at."""
        notes: list[str] = []
        done = {p.package for p in prepared if p.directory}
        left = [m for m in missing if m not in done]
        full = [p for p in prepared if p.unpacked]
        if full:
            notes.append(f"{len(full)} package(s) without a helper cache were fetched and unpacked by the app: "
                         + _short([p.package + ("" if p.installed_match else f" (AUR {p.version}, not the installed one)")
                                   for p in full], 5))
        for p in prepared:
            if p.problem:
                what = "only partly checked" if p.directory else "NOT checked"
                notes.append(f"{p.package} was {what}: {p.problem}")
        if left and not prepared:
            notes.append(f"aur-scan did not check {len(left)} package(s), no PKGBUILD in an AUR helper cache: "
                         f"{_short(left)}")
        if self._outdated:
            notes.append("The newest aur-scan release could not be built; the previous build was used (see the log).")
        return notes

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
        if code in _ERROR_CODES:
            return ScanResult(self.name, ERROR, [], f"exit {code}: {out[-500:]}", log=out)
        missing = skipped(out)
        fetch = self._settings.aur_scan_fetch_missing
        if fetch_missing.root().is_dir() and not (fetch and missing):
            self._clean_up_fetched(set())  # switched off, or every package is in a helper cache now
        if code == 0 and not (fetch and missing):
            return ScanResult(self.name, CLEAN, log=out, notes=self._coverage_notes(missing, []))
        if self._use_fp and not self._fp_checked:
            self._refresh_fp()
        installed = ignores.installed_versions()
        fail_on = self._settings.aur_scan_fail_on
        entries = fplist.load() if self._use_fp else []
        prepared: list[fetch_missing.Prepared] = []
        if fetch:
            def blocked(pkg: str, version: str, rule: str) -> bool:
                return not (is_ignored(pkg, rule, set(self._ignore)) or ignores.matcher({pkg: version})(pkg, rule)
                            or fplist.match(entries, pkg, version, rule))

            prepared = self._fetch_missing(binary, missing, installed, options, blocked)
        if fetch and missing:  # drop copies of removed packages or ones a helper now caches
            self._clean_up_fetched({fetch_missing.package_base(n, installed.get(n, "")) for n in missing})
        checked = [p for p in prepared if p.directory]
        if checked:
            out += "\n\n--- packages without a helper cache, fetched by the app ---\n" + "\n".join(
                fetch_missing.synthetic_block(p, fail_on, _SEVERITY_ORDER) for p in checked) + "\n"
        coverage = self._coverage_notes(missing, prepared)
        if code == 0 and not any(f["severity"] in _SEVERITY_ORDER[: _SEVERITY_ORDER.index(fail_on) + 1]
                                 for p in checked for f in p.findings):
            return ScanResult(self.name, CLEAN, log=out, notes=coverage)
        versions = dict(installed)
        for pkg, d in scanned_dirs(out).items():  # the scanned PKGBUILD's version wins over the installed one
            v = ignores.srcinfo_version(d)
            if v:
                versions[pkg] = v
        with_issues = sorted({m.group(1) for m in map(_HEADER.match, out.splitlines()) if m})
        pkg_dirs = {p: d for p in with_issues if (d := find_pkg_dir(p, options))}
        for pkg, d in pkg_dirs.items():
            v = ignores.srcinfo_version(d)
            if v:
                versions[pkg] = v
        details = self._read_details(binary, {p: pkg_dirs[p] for p in unlisted_packages(out, fail_on) if p in pkg_dirs},
                                     options)
        for p in checked:  # from the app's own copy: its version comes from git, not from the files in the sandbox
            details[p.package] = p.findings
            versions[p.package] = p.version
        for line in out.splitlines():
            # --rescan: aur-scan looked at the current AUR version, which is unknown here. Nothing bound to a version
            # may hide a finding then.
            if line.startswith("Fetching:") and (m := _HEADER.match(line)):
                versions.pop(m.group(1), None)
        user = ignores.matcher(versions)
        hits: dict[str, str] = {}

        def suppress(pkg: str, rule: str) -> bool:
            if user(pkg, rule):
                return True
            e = fplist.match(entries, pkg, versions.get(pkg, ""), rule)
            if e:
                hits[f"{pkg} {versions.get(pkg)} {rule}"] = f"{e.reason} (reported by {e.author}, {e.reported})"
            return e is not None

        findings = parse_output(out, self.label, self._ignore, suppress, versions, fail_on, details)
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
        if details:
            shown = _SEVERITY_ORDER[1:_SEVERITY_ORDER.index(fail_on) + 1]
            out += "\n\n--- findings not listed by aur-scan system (from aur-scan scan --format json) ---\n" + "\n".join(
                f"{p}: [{d['severity']}] {d['code']} {d['title']}"
                + (f" - {d['path']}" + (f":{d['line']}" if d['line'] else "") if d['path'] else "")
                for p, found in details.items() for d in found if d["severity"] in shown) + "\n"
        if hits:  # transparency: show what the community list hid
            out += "\n\n--- hidden by the community false-positive list ---\n" + "\n".join(
                f"{k}: {v}" for k, v in hits.items()) + "\n"
        notes: list[str] = list(coverage)
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
