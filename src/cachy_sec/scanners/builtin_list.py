"""Built-in fallback: compare installed foreign packages with a user-supplied/fetched blocklist.

Independent of third-party scanner upkeep. The list URL is configurable via the
CACHY_SEC_BLOCKLIST_URL environment variable and must return one package name per line
(plain text; lines starting with '#' are ignored). Without a URL this backend reports
"not available" rather than guessing a source.
"""
from __future__ import annotations

import os
import urllib.request
from pathlib import Path

from .base import CLEAN, CRITICAL, ERROR, Finding, Scanner, ScanResult, run


def parse_list(text: str) -> set[str]:
    return {ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")}


def cache_file() -> Path:
    base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "cachy-security-scanner" / "blocklist.txt"


class BuiltinList(Scanner):
    name = "builtin_list"
    label = "Built-in blocklist"

    def _url(self) -> str | None:
        return os.environ.get("CACHY_SEC_BLOCKLIST_URL") or None

    def available(self) -> bool:
        return cache_file().exists() or self._url() is not None

    def unavailable_reason(self) -> str:
        return "no blocklist configured (set CACHY_SEC_BLOCKLIST_URL)"

    def update(self) -> None:
        url = self._url()
        if not url or not url.startswith("https://"):
            return
        try:
            with urllib.request.urlopen(url, timeout=30) as r:  # noqa: S310 (https only, checked above)
                data = r.read(5_000_000).decode("utf-8", "replace")
        except OSError:
            return
        if parse_list(data):
            f = cache_file()
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(data)

    def scan(self) -> ScanResult:
        try:
            blocked = parse_list(cache_file().read_text())
        except OSError:
            return ScanResult(self.name, ERROR, [], "no blocklist cached")
        code, out = run(["pacman", "-Qmq"], 60)
        if code != 0:
            return ScanResult(self.name, ERROR, [], f"pacman -Qmq failed: {out[-300:]}")
        hits = sorted(blocked & set(out.split()))
        findings = [Finding(CRITICAL, f"{p} matches the known-compromised list", self.label, p) for p in hits]
        return ScanResult(self.name, CRITICAL if hits else CLEAN, findings)
