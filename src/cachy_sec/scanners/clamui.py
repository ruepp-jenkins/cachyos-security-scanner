"""Adapter for ClamUI (https://github.com/linx-systems/clamui). Run only on user request.

ClamUI is a hard prerequisite; there is intentionally no plain clamscan fallback.
Uses `clamui scan <paths...> --json`.
"""
from __future__ import annotations

import json
import os

from .base import CLEAN, CRITICAL, ERROR, Finding, ScanResult, run, which


def available() -> bool:
    return which("clamui") is not None


def scan(paths: list[str]) -> ScanResult:
    existing = [os.path.expanduser(p) for p in paths if os.path.exists(os.path.expanduser(p))]
    if not existing:
        return ScanResult("clamui", ERROR, [], "none of the configured paths exist")
    code, out = run(["clamui", "scan", *existing, "--json"], 6 * 3600)
    try:
        data = json.loads(out)
    except ValueError:
        data = None
    infected = _threats(data)
    if infected:
        return ScanResult("clamui", CRITICAL, [Finding(CRITICAL, t, "ClamUI") for t in infected])
    if code == 0:
        return ScanResult("clamui", CLEAN)
    return ScanResult("clamui", ERROR, [], f"exit {code}: {out[-500:]}")


def _threats(data: object) -> list[str]:
    """Collect '<file>: <signature>' strings from dicts that look like infections."""
    found: list[str] = []
    if isinstance(data, dict):
        for k, v in data.items():
            if "threat" in str(k).lower() or "infected" in str(k).lower():
                if isinstance(v, list):
                    found += [json.dumps(i)[:200] if not isinstance(i, str) else i for i in v]
        for v in data.values():
            found += _threats(v)
    elif isinstance(data, list):
        for i in data:
            found += _threats(i)
    return found
