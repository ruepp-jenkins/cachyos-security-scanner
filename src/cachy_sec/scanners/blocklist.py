"""Scanner for the community blocklist: matches installed AUR packages against lists/blocklist_aur.json."""
from __future__ import annotations

from .. import blocklist
from ..signedlist import describe
from ..ignores import installed_versions
from .base import CLEAN, CRITICAL, ERROR, Finding, Scanner, ScanResult


class CommunityBlocklist(Scanner):
    name = "blocklist"
    label = "Community blocklist"

    def __init__(self) -> None:
        self._status = ""
        self._refreshed = False

    def available(self) -> bool:
        return True  # needs only network access (or a cached copy); a missing list is reported as an error in scan()

    def update(self) -> None:
        self._refreshed = True
        ok, msg = blocklist.refresh()
        self._status = msg if ok else f"download/verification failed ({msg}); using the cached list if any"

    def scan(self) -> ScanResult:
        if not self._refreshed:
            self.update()
        loaded = blocklist.load()
        if loaded is None:
            return ScanResult(self.name, ERROR, [], f"community blocklist not available yet: {self._status}",
                              log=f"No verified blocklist in the cache.\n{self._status}")
        installed = installed_versions()
        findings = []
        for pkg, version in sorted(installed.items()):
            e = blocklist.match(loaded.entries, pkg, version)
            if e:
                detail = f"reported by {e.author} on {e.reported}"
                if e.description:
                    detail += f"\n{e.description}"
                if e.reference:
                    detail += f"\n{e.reference}"
                findings.append(Finding(CRITICAL, f"{pkg} {version} is on the community blocklist: {e.reason}",
                                        self.label, package=pkg, detail=detail, version=version))
        log = (f"blocklist: {describe(loaded, 'entry', 'entries')}; list refresh: {self._status or 'cache'}\n"
               f"checked {len(installed)} installed AUR/foreign packages\n"
               + "".join(f"HIT {f.title}\n" for f in findings))
        return ScanResult(self.name, CRITICAL if findings else CLEAN, findings, log=log)
