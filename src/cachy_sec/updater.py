"""Self-update from GitHub Releases (the only update source).

The app is pure Python, so a release is a tarball of the `cachy_sec` package built by GitHub
Actions together with SHA256SUMS and an SSH signature over it. Updates are verified against the
maintainer public key embedded below (fail closed when no key is set), unpacked into the user's
data directory and picked up by bootstrap.py on the next start. The packaged install is never
modified; it only acts as the baseline.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import __version__

GITHUB_REPO = "ruepp-jenkins/cachyos-security-scanner"
# Public half of the release signing key (`ssh-keygen -t ed25519`), e.g. "ssh-ed25519 AAAA...".
SIGNER_PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBFjDF4EBdmz4aD/d6wwcqsdw7oXU2KDGaVbDT4iFVjg cachy-sec release"
SIG_NAMESPACE = "cachy-security-scanner"
ALLOWED_HOST_SUFFIXES = ("github.com", "githubusercontent.com")
MAX_DOWNLOAD = 20 * 1024 * 1024
RESTART_EXIT_CODE = 75
SUPERVISED_ENV = "CACHY_SEC_SUPERVISED"


class UpdateError(Exception):
    pass


@dataclass
class Release:
    version: str
    assets: dict[str, str]  # asset name -> download URL


def parse_version(v: str) -> tuple[int, ...] | None:
    m = re.fullmatch(r"v?(\d+(?:\.\d+){0,3})", v.strip())
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def updates_dir() -> Path:
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "cachy-security-scanner" / "updates"


def _host_ok(url: str) -> bool:
    u = urllib.parse.urlparse(url)
    h = (u.hostname or "").lower()
    return u.scheme == "https" and any(h == s or h.endswith("." + s) for s in ALLOWED_HOST_SUFFIXES)


class _Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        if not _host_ok(newurl):
            raise UpdateError(f"redirect to non-GitHub host refused: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _get(url: str, limit: int = MAX_DOWNLOAD) -> bytes:
    if not _host_ok(url):
        raise UpdateError(f"refusing non-GitHub URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "cachy-security-scanner", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.build_opener(_Redirects).open(req, timeout=30) as r:
            data = r.read(limit + 1)
    except (urllib.error.URLError, OSError) as e:
        raise UpdateError(f"download failed: {e}") from e
    if len(data) > limit:
        raise UpdateError("download too large")
    return data


def _complete(version: str, assets: dict[str, str]) -> bool:
    return all(n in assets for n in (f"cachy-security-scanner-{version}.tar.gz", "SHA256SUMS", "SHA256SUMS.sig"))


def latest_release() -> Release | None:
    """Newest non-draft release that carries all update files.

    Uses the release list instead of /releases/latest, which returns 404 when every release is
    marked as pre-release and ignores releases whose build failed and has no assets.
    """
    data = json.loads(_get(f"https://api.github.com/repos/{GITHUB_REPO}/releases?per_page=20", 2_000_000))
    best: Release | None = None
    for r in data if isinstance(data, list) else []:
        if r.get("draft"):
            continue
        v = str(r.get("tag_name", "")).lstrip("v")
        pv = parse_version(v)
        if pv is None:
            continue
        assets = {a["name"]: a["browser_download_url"] for a in r.get("assets", []) if "browser_download_url" in a}
        if _complete(v, assets) and (best is None or pv > (parse_version(best.version) or ())):
            best = Release(v, assets)
    return best


def installed_overlay() -> tuple[str, Path] | None:
    """The version recorded in updates/current, if its directory is intact."""
    try:
        v = (updates_dir() / "current").read_text().strip()
    except OSError:
        return None
    p = updates_dir() / v
    return (v, p) if parse_version(v) and (p / "cachy_sec" / "__init__.py").is_file() else None


def effective_version() -> str:
    o = installed_overlay()
    if o and (parse_version(o[0]) or ()) > (parse_version(__version__) or ()):
        return o[0]
    return __version__


def supervised() -> bool:
    """True when started through bootstrap, i.e. exiting with RESTART_EXIT_CODE restarts the app."""
    return os.environ.get(SUPERVISED_ENV) == "1"


def describe_version() -> str:
    """Human readable version of the running code, plus a pending (installed but not yet running) update."""
    text = "development build" if __version__ == "0.0.0" else __version__
    o = installed_overlay()
    if o and (parse_version(o[0]) or ()) > (parse_version(__version__) or ()):
        text += f" – update {o[0]} installed, applied on restart"
    return text


def is_newer(candidate: str) -> bool:
    return (parse_version(candidate) or ()) > (parse_version(effective_version()) or ())


def verify_signature(signed: bytes, signature: bytes, pubkey: str | None = None) -> None:
    pubkey = SIGNER_PUBKEY if pubkey is None else pubkey
    if not pubkey.strip():
        raise UpdateError("no release signing key configured; refusing to update")
    if not shutil.which("ssh-keygen"):
        raise UpdateError("ssh-keygen (openssh) not found; cannot verify the update")
    with tempfile.TemporaryDirectory() as d:
        sig, signers = Path(d, "sums.sig"), Path(d, "allowed")
        sig.write_bytes(signature)
        signers.write_text(f'release namespaces="{SIG_NAMESPACE}" {pubkey.strip()}\n')
        p = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(signers), "-I", "release", "-n", SIG_NAMESPACE,
                            "-s", str(sig)], input=signed, capture_output=True, timeout=30)
    if p.returncode != 0:
        raise UpdateError("signature verification failed")


def checksum_for(sums: bytes, name: str) -> str:
    for line in sums.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == name and re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            return parts[0]
    raise UpdateError(f"no checksum for {name}")


def safe_extract(tarball: Path, dest: Path) -> None:
    with tarfile.open(tarball, "r:gz") as t:
        for m in t.getmembers():
            n = Path(m.name)
            if n.is_absolute() or ".." in n.parts or not (m.isfile() or m.isdir()):
                raise UpdateError(f"unsafe tar member: {m.name}")
            if n.parts[0] != "cachy_sec":
                raise UpdateError(f"unexpected tar member: {m.name}")
        t.extractall(dest, filter="data")


def install(rel: Release, pubkey: str | None = None) -> Path:
    tar_name = f"cachy-security-scanner-{rel.version}.tar.gz"
    for need in (tar_name, "SHA256SUMS", "SHA256SUMS.sig"):
        if need not in rel.assets:
            raise UpdateError(f"release is missing {need}")
    sums = _get(rel.assets["SHA256SUMS"], 1_000_000)
    verify_signature(sums, _get(rel.assets["SHA256SUMS.sig"], 100_000), pubkey)
    blob = _get(rel.assets[tar_name])
    if hashlib.sha256(blob).hexdigest() != checksum_for(sums, tar_name):
        raise UpdateError("checksum mismatch")
    root = updates_dir()
    root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=root))
    try:
        tarf = staging / "pkg.tar.gz"
        tarf.write_bytes(blob)
        out = staging / "tree"
        out.mkdir()
        safe_extract(tarf, out)
        init = (out / "cachy_sec" / "__init__.py").read_text()
        m = re.search(r'__version__\s*=\s*"([^"]+)"', init)
        if not m or m.group(1) != rel.version:
            raise UpdateError("package version does not match the release tag")
        final = root / rel.version
        shutil.rmtree(final, ignore_errors=True)
        out.replace(final)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    cur = root / "current.tmp"
    cur.write_text(rel.version)
    cur.replace(root / "current")
    for d in root.iterdir():  # keep only the active version
        if d.is_dir() and d.name != rel.version and not d.name.startswith("."):
            shutil.rmtree(d, ignore_errors=True)
    return final


def discard_overlay() -> None:
    shutil.rmtree(updates_dir(), ignore_errors=True)


def check_and_install() -> tuple[str, str]:
    """Returns (state, message); state is 'current', 'installed' or 'error'. Never raises."""
    try:
        rel = latest_release()
        if rel is None or not is_newer(rel.version):
            return "current", f"Up to date ({effective_version()})"
        install(rel)
        return "installed", rel.version
    except (UpdateError, ValueError, KeyError, OSError, tarfile.TarError, subprocess.SubprocessError) as e:
        return "error", str(e)
