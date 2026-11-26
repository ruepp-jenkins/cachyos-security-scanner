"""Fetch installed AUR packages that no helper cache holds, so that aur-scan can look at them (opt-in).

Layout below ~/.cache/cachy-security-scanner/aur/:
  repo/<base>        git clone of the AUR repository; only this app writes here
  work/<base>        copy of the chosen commit; `makepkg` unpacks the sources here, inside a sandbox
  state/<base>.json  which commit is in work/ and what was found in the repository files

Two rules keep a hostile package from doing harm:
  * `makepkg` runs the PKGBUILD as a shell script, so it only ever runs inside bubblewrap: no home directory,
    nothing writable but work/<base>. Without bubblewrap the sources are not unpacked at all. Nothing is built or
    installed (`--nobuild --holdver`: download, extract, prepare()), and a package with a critical finding is not
    unpacked.
  * the sandbox can write anything into work/, so git is never run there and nothing in it is trusted; the version
    and the repository findings come from repo/ and state/.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import tarfile
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import ignores
from .scanners.base import run, which

AUR_URL = "https://aur.archlinux.org/{}.git"
LOCAL_DB = Path("/var/lib/pacman/local")
HISTORY = 300  # commits searched for the installed version
_NAME = re.compile(r"[a-z0-9@_+][a-z0-9@._+-]*")
UNPACK_TIMEOUT = 1800
MAKEPKG = ["makepkg", "--nobuild", "--nodeps", "--holdver", "--skippgpcheck", "--noconfirm", "--nocolor"]
# what makepkg needs from /etc; nothing else of the system's configuration is visible
ETC = ("makepkg.conf", "makepkg.conf.d", "pacman.conf", "ssl", "ca-certificates", "resolv.conf", "hosts",
       "nsswitch.conf", "passwd", "group", "gitconfig")
PROXY_VARIABLES = ("http_proxy", "https_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY")


@dataclass
class Prepared:
    package: str
    directory: Path | None = None
    version: str = ""  # of the fetched PKGBUILD
    installed_match: bool = False  # the fetched commit has exactly the installed version
    unpacked: bool = False
    findings: list[dict] = field(default_factory=list)
    problem: str = ""  # why the package was not checked (no directory) or only partly (directory set)
    log: list[str] = field(default_factory=list)  # what was downloaded, reused or unpacked, for the scan history


def root() -> Path:
    base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "cachy-security-scanner" / "aur"


def package_base(package: str, version: str) -> str:
    """The AUR repository of a package (split packages share one), from pacman's local database."""
    try:
        lines = (LOCAL_DB / f"{package}-{version}" / "desc").read_text(errors="replace").splitlines()
        return lines[lines.index("%BASE%") + 1].strip() or package
    except (OSError, ValueError, IndexError):
        return package


def _git(repo: Path, *args: str, timeout: int = 120) -> tuple[int, str]:
    return run(["git", "-C", str(repo), *args], timeout)


def _update_repo(base: str, repo: Path) -> str:
    """Clone or fetch; returns "" or why the copy could not be brought up to date."""
    if (repo / ".git").is_dir():
        code, out = _git(repo, "fetch", "--quiet", "origin", timeout=300)
    else:
        shutil.rmtree(repo, ignore_errors=True)
        repo.parent.mkdir(parents=True, exist_ok=True)
        code, out = run(["git", "clone", "--quiet", "--no-checkout", AUR_URL.format(base), str(repo)], 300)
    return "" if code == 0 else (out.strip().splitlines() or ["git failed"])[-1][:200]


def pick_commit(repo: Path, installed: str) -> tuple[str, str, bool]:
    """(commit, its version, whether that is the installed version). The newest commit if none matches, which is
    the usual case for -git packages. ("", "", False) if the repository has no PKGBUILD (not an AUR package)."""
    code, out = _git(repo, "log", f"-n{HISTORY}", "--format=%H", "origin/HEAD", "--", ".SRCINFO")
    commits = out.split() if code == 0 else []
    newest = ("", "", False)
    for commit in commits:
        code, text = _git(repo, "show", f"{commit}:.SRCINFO")
        version = ignores.version_from_srcinfo(text) if code == 0 else ""
        if not newest[0]:
            newest = (commit, version, False)
        if version and version == installed:
            return commit, version, True
    return newest


def _export(repo: Path, commit: str, work: Path) -> str:
    """Put the files of `commit` into an empty `work` directory (without any git metadata)."""
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "files.tar"
        code, out = _git(repo, "archive", "--format=tar", "-o", str(archive), commit)
        if code != 0:
            return out.strip()[-200:]
        try:
            with tarfile.open(archive) as tar:
                tar.extractall(work, filter="data")  # refuses paths and links that leave the directory
        except (tarfile.TarError, OSError) as e:
            return str(e)[:200]
    return "" if (work / "PKGBUILD").is_file() else "the repository has no PKGBUILD"


def sandbox_command(work: Path, prepare_sources: bool = True) -> list[str]:
    """bubblewrap + makepkg: the system read-only, an empty home, only `work` writable, network for downloads."""
    cmd = ["bwrap", "--unshare-all", "--share-net", "--die-with-parent", "--new-session", "--clearenv",
           "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/bin", "/sbin",
           "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64", "--proc", "/proc", "--dev", "/dev",
           "--tmpfs", "/tmp", "--dir", "/tmp/home"]
    for name in ETC:
        cmd += ["--ro-bind-try", f"/etc/{name}", f"/etc/{name}"]
    cmd += ["--bind", str(work), str(work), "--chdir", str(work)]
    environment = {"HOME": "/tmp/home", "PATH": "/usr/bin", "LANG": "C.UTF-8", "BUILDDIR": str(work),
                   "SRCDEST": str(work), "PKGDEST": str(work), "SRCPKGDEST": str(work), "LOGDEST": str(work)}
    environment.update({k: os.environ[k] for k in PROXY_VARIABLES if k in os.environ})
    for key, value in environment.items():
        cmd += ["--setenv", key, value]
    return cmd + MAKEPKG + ([] if prepare_sources else ["--noprepare"])


def _unpack(work: Path) -> tuple[bool, str]:
    """Download, extract and prepare the sources: (unpacked, what did not work). Never runs without the sandbox.

    prepare() is what unpacks e.g. the contents of a .deb. It may need build tools that are not installed, so on
    failure the sources are only extracted.
    """
    missing = [tool for tool in ("bwrap", "makepkg") if not which(tool)]
    if missing:
        return False, f"sources not unpacked, {' and '.join(missing)} not found (package 'bubblewrap' / 'pacman')"
    problem = ""
    for prepare_sources in (True, False):
        code, out = run(sandbox_command(work, prepare_sources), UNPACK_TIMEOUT, low_priority=True)
        if code == 0:
            return True, problem if not prepare_sources else ""
        errors = [ln.strip() for ln in out.splitlines() if "ERROR" in ln] or out.strip().splitlines() or [f"exit {code}"]
        problem = f"{'prepare() failed, sources only extracted' if prepare_sources else 'sources not unpacked'}: " \
                  f"{errors[-1][:200]}"
    return False, problem


def _size(directory: Path) -> str:
    total = 0
    for folder, _, files in os.walk(directory):
        for name in files:
            try:
                total += os.lstat(os.path.join(folder, name)).st_size
            except OSError:
                pass
    return f"{total / 1_000_000:.1f} MB"


def _unique(findings: list[dict]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for f in findings:
        seen.setdefault((f["code"], f["path"], f["line"], f["severity"]), f)
    return list(seen.values())


def prepare(package: str, installed: str, scan: Callable[[Path], list[dict] | None],
            blocks: Callable[[list[dict], str], bool]) -> Prepared:
    """Fetch (or reuse) the files of one package and scan them.

    `scan(directory)` returns the findings or None if it failed; `blocks(findings, version)` says whether they forbid
    to let makepkg run the PKGBUILD.
    """
    result = Prepared(package)
    base = package_base(package, installed)
    if not _NAME.fullmatch(base):
        result.problem = "unusual package name"
        return result
    repo, work, state_file = root() / "repo" / base, root() / "work" / base, root() / "state" / f"{base}.json"
    known = (repo / ".git").is_dir()
    offline = _update_repo(base, repo)
    if offline:
        result.log.append(f"AUR repository {base}: " + (f"could not be updated, the stored copy is used ({offline})" if known
                                                         else f"download FAILED ({offline})"))
    else:
        result.log.append(f"AUR repository {base}: " + ("checked for changes" if known
                                                         else f"downloaded from {AUR_URL.format(base)}"))
    commit, version, matches = pick_commit(repo, installed) if (repo / ".git").is_dir() else ("", "", False)
    if not commit:
        result.problem = offline or "not found in the AUR"
        return result
    result.version, result.installed_match = version, matches
    result.log.append(f"commit {commit[:7]}, version {version or 'unknown'}"
                      + (" (the installed one)" if matches else f" (installed {installed or 'unknown'} not in the history)"))
    try:
        state = json.loads(state_file.read_text())
    except (OSError, ValueError):
        state = {}
    if state.get("commit") != commit or not work.is_dir():
        state = {}
        error = _export(repo, commit, work)
        if error:
            result.problem = error
            result.log.append(f"files could not be copied: {error}")
            return result
    else:
        result.log.append("files unchanged, the stored copy is reused")
    first = state.get("repository_findings")
    if first is None:  # never unpacked yet: look at the repository files before makepkg runs anything
        first = scan(work)
        if first is None:
            result.problem = "aur-scan could not read the fetched files"
            return result
    result.directory, result.findings = work, _unique(first)
    if not state.get("unpacked"):
        if blocks(first, version):
            result.problem = "sources not unpacked because of a critical finding in the repository files"
            return result
        started = time.monotonic()
        unpacked, result.problem = _unpack(work)
        if not unpacked:
            result.log.append(f"{result.problem}")
            return result
        result.log.append(f"sources downloaded and unpacked in {time.monotonic() - started:.0f} s (sandboxed makepkg), "
                          f"{_size(work)} in {work}")
        state = {"commit": commit, "unpacked": True, "repository_findings": first, "note": result.problem}
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(json.dumps(state))
    else:
        result.log.append("sources already unpacked, nothing downloaded again")
    result.unpacked = True
    result.problem = state.get("note", "")
    after = scan(work)
    if after is None:
        result.problem = "aur-scan could not read the unpacked sources"
    else:
        result.findings = _unique(first + after)  # union: nothing run in the sandbox can take a finding away
    return result


def clean_up(keep: set[str]) -> list[str]:
    """Remove copies that are no longer needed (package removed, or now in a helper cache). `keep`: base names.
    Returns the names whose copies were deleted."""
    removed: set[str] = set()
    for kind in ("repo", "work", "state"):
        folder = root() / kind
        if not folder.is_dir():
            continue
        for entry in folder.iterdir():
            name = entry.stem if kind == "state" else entry.name
            if name in keep:
                continue
            removed.add(name)
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry, ignore_errors=True)
            else:
                entry.unlink(missing_ok=True)
    return sorted(removed)


def synthetic_block(p: Prepared, fail_on: str, order: tuple[str, ...]) -> str:
    """The package in the format of `aur-scan system`, so it goes through the same parsing and ignore rules."""
    counted = order[: order.index(fail_on) + 1]
    relevant = [f for f in p.findings if f["severity"] in counted]
    if not relevant:
        return f"Scanning: {p.package} OK"
    critical = [f for f in relevant if f["severity"] == "critical"]
    high = sum(f["severity"] == "high" for f in relevant)
    counts = (f"{len(critical)} critical " if critical else "") + (f"{high} high " if high else "")
    lines = [f"Scanning: {p.package} ISSUES: {counts}"]
    lines += [f"    {f['code']} {f['title']} - {f['path'] or p.directory}" for f in critical]
    return "\n".join(lines)
