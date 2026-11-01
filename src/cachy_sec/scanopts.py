"""Per-scanner options: the typed choices of the options dialogs plus validated "extra arguments".

The app never starts a shell: every scanner is run from an argument list. Extra arguments are still checked
strictly, so they can only ever be *options of that scanner*:

- split like a shell would (quotes allowed), then every token is checked on its own;
- shell operators and substitutions (``&&  ||  ;  |  <  >  `  $``, newlines) are rejected, although they could
  not do anything without a shell;
- the first token must be an option (``-x`` / ``--name`` / ``--name=value``), so no sub-command and no program name
  can be smuggled in; a plain word is accepted only as the value of the option before it;
- a bare ``--`` is rejected, and so are options that would delete or move files, write files, only print help, or
  that this app sets itself (the denylists below; abbreviations of long options are caught as well).
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from .settings import Settings

MAX_TOKENS = 40
MAX_LENGTH = 1000
_META = set(";&|<>`$\n\r\0")
_OPTION = re.compile(r"^(--[A-Za-z][A-Za-z0-9-]*(=.*)?|-[A-Za-z]+)$", re.S)

SEVERITIES = ("critical", "high", "medium", "low", "info")

_COMMON_DENY = {"--help", "-h", "--version", "-V"}  # would "scan" nothing and still exit 0
# aur-malware-check: output/refresh options are set by the app or write files
DENY_AMC = _COMMON_DENY | {"--json", "--refresh", "--refresh-campaigns", "--dry-run", "--list-campaigns",
                           "--output", "-o", "--log-file", "--scan-all-homes"}
# aur-scan: the app parses the text output and sets the failure level and colours itself
DENY_AUR_SCAN = _COMMON_DENY | {"--no-color", "--quiet", "-q", "--fail-on", "--severity", "-s", "--rescan"}
# clamdscan: nothing may delete, move or copy files; --infected/--fdpass are required by the app
DENY_CLAMD = _COMMON_DENY | {"--remove", "--move", "--copy", "--file-list", "-f", "--fdpass", "--infected", "-i",
                             "--multiscan", "-m", "--allmatch", "-z", "--stream", "--quiet", "--no-summary"}


def parse_extra(text: str, deny: set[str]) -> list[str]:
    """The tokens of `text` or ValueError saying what is wrong. See the module docstring for the rules."""
    text = (text or "").strip()
    if not text:
        return []
    if len(text) > MAX_LENGTH:
        raise ValueError(f"too long (more than {MAX_LENGTH} characters)")
    if bad := sorted(set(text) & _META - {"\n", "\r", "\0"}):
        raise ValueError("characters that start other programs are not allowed: " + " ".join(bad))
    if set(text) & {"\n", "\r", "\0"}:
        raise ValueError("line breaks are not allowed")
    try:
        tokens = shlex.split(text)
    except ValueError as e:
        raise ValueError(f"cannot read the quotes: {e}") from None
    if len(tokens) > MAX_TOKENS:
        raise ValueError(f"too many arguments (more than {MAX_TOKENS})")
    if tokens and not tokens[0].startswith("-"):
        raise ValueError(f"must start with an option such as --name, not '{tokens[0]}'")
    longs = [d for d in deny if d.startswith("--")]
    shorts = {d[1] for d in deny if len(d) == 2 and not d.startswith("--")}
    prev_option = False
    for t in tokens:
        if set(t) & _META:
            raise ValueError(f"'{t}': characters that start other programs are not allowed")
        if t == "--":
            raise ValueError("'--' is not allowed")
        if t.startswith("-"):
            if not _OPTION.match(t):
                raise ValueError(f"'{t}' is not a valid option")
            if t.startswith("--"):
                name = t.split("=", 1)[0]
                if name in deny or (len(name) > 2 and any(d.startswith(name) for d in longs)):
                    raise ValueError(f"'{name}' is not allowed here (set by the app, or it could change or remove files)")
            elif set(t[1:]) & shorts:
                raise ValueError(f"'{t}' contains an option that is not allowed here")
            prev_option = "=" not in t
        else:
            if not prev_option:
                raise ValueError(f"'{t}': a value must directly follow its option")
            prev_option = False
    return tokens


@dataclass(frozen=True)
class Opt:
    key: str  # attribute of Settings
    kind: str  # "bool" | "choice" | "text"
    label: str
    tip: str
    choices: tuple[str, ...] = ()


@dataclass(frozen=True)
class Spec:
    title: str
    intro: str
    opts: tuple[Opt, ...]
    extra_key: str
    deny: set[str]


AMC = Spec(
    "aur-malware-check options",
    "Checks installed AUR packages against lists of packages from known attack campaigns. The extra checks below are\n"
    "off by default; they look at more places on your system and take a little longer.",
    (
        Opt("amc_all_time", "bool", "Report infected packages regardless of install date",
            "Without this, only packages installed inside the campaign's time window are flagged.\n"
            "(upstream: --all-time)"),
        Opt("amc_check_systemd", "bool", "Check for unknown systemd services (Restart=always)", "upstream: --check-systemd"),
        Opt("amc_check_ebpf", "bool", "Check for eBPF rootkit traces", "upstream: --check-ebpf"),
        Opt("amc_check_ioc_files", "bool", "Check for known malware files on disk (path + SHA-256)",
            "upstream: --check-ioc-files"),
        Opt("amc_check_caches", "bool", "Check the npm, bun, yarn and pnpm caches for malicious packages",
            "upstream: --check-npm-cache --check-bun-cache --check-yarn-cache --check-pnpm-cache"),
    ),
    "amc_extra_args",
    DENY_AMC,
)

AUR_SCAN = Spec(
    "aur-scan options",
    "Heuristic analysis of the PKGBUILDs and install scripts of your installed AUR packages (aur-scan system).",
    (
        Opt("aur_scan_fail_on", "choice", "Treat findings from this severity up as a detection",
            "aur-scan reports a non-zero result at or above this level. Lower = more sensitive, more false positives.\n"
            "(upstream: --fail-on)", SEVERITIES),
        Opt("aur_scan_min_severity", "choice", "Only report findings from this severity up",
            "Findings below this level are not reported at all. 'all' = no limit. (upstream: --severity)",
            ("all",) + SEVERITIES),
        Opt("aur_scan_rescan", "bool", "Fetch the PKGBUILDs from the AUR again instead of using the helper's cache",
            "Needs network access and takes longer. (upstream: system --rescan)"),
    ),
    "aur_scan_extra_args",
    DENY_AUR_SCAN,
)

CLAMD = Spec(
    "ClamAV (clamdscan) options",
    "Options of the clamdscan client. --fdpass and --infected are always set by the app; nothing is ever removed, moved\n"
    "or copied.",
    (
        Opt("binary_multiscan", "bool", "Scan with several threads (--multiscan)",
            "Faster on multi-core machines, but uses more CPU while it runs."),
        Opt("binary_allmatch", "bool", "Report every match in a file, not only the first (--allmatch)",
            "Continues scanning a file after the first match. Slower, gives more complete reports."),
    ),
    "binary_extra_args",
    DENY_CLAMD,
)

SPECS = {"amc": AMC, "aur_scan": AUR_SCAN, "clamd": CLAMD}


def extra(spec: Spec, s: Settings) -> list[str]:
    return parse_extra(getattr(s, spec.extra_key), spec.deny)


def amc_args(s: Settings) -> list[str]:
    """Extra arguments for `aur_check --json`. Raises ValueError if the user's extra arguments are not acceptable."""
    args: list[str] = []
    if s.amc_all_time:
        args.append("--all-time")
    if s.amc_check_systemd:
        args.append("--check-systemd")
    if s.amc_check_ebpf:
        args.append("--check-ebpf")
    if s.amc_check_ioc_files:
        args.append("--check-ioc-files")
    if s.amc_check_caches:
        args += ["--check-npm-cache", "--check-bun-cache", "--check-yarn-cache", "--check-pnpm-cache"]
    return args + extra(AMC, s)


def aur_scan_args(s: Settings) -> list[str]:
    """Arguments after `aur-scan --no-color system`."""
    args = ["--fail-on", s.aur_scan_fail_on]
    if s.aur_scan_min_severity != "all":
        args += ["--severity", s.aur_scan_min_severity]
    if s.aur_scan_rescan:
        args.append("--rescan")
    return args + extra(AUR_SCAN, s)


def clamd_args(s: Settings) -> list[str]:
    """Options for clamdscan, placed before the `--` and the paths."""
    args = ["--fdpass", "-i"]
    if s.binary_multiscan:
        args.append("--multiscan")
    if s.binary_allmatch:
        args.append("--allmatch")
    return args + extra(CLAMD, s)


def preview(which: str, s: Settings) -> str:
    """The command line as it will be run (for the options dialog); an error text if the extra arguments are bad."""
    try:
        if which == "amc":
            return "aur-malware-check --json " + shlex.join(amc_args(s))
        if which == "aur_scan":
            return "aur-scan --no-color system " + shlex.join(aur_scan_args(s))
        return "clamdscan " + shlex.join(clamd_args(s)) + " -- <paths>"
    except ValueError as e:
        return f"Invalid extra arguments: {e}"
