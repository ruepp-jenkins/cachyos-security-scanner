"""Scan history: one JSON file per package scan, one text log per binary (clamd) scan.

Plain files in the user's data directory so they can be read, copied or deleted without the app.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from .scanners.base import CLEAN, CRITICAL, ERROR, WARNING, Finding, ScanResult

LOG_CAP = 200_000
SKIPPED = "skipped"
UNKNOWN = "unknown"


def history_dir() -> Path:
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "cachy-security-scanner" / "history"


@dataclass
class Entry:
    path: Path
    started: str
    kind: str  # "packages" | "binaries"
    trigger: str
    status: str
    summary: str
    duration_s: float = 0.0

    def log_text(self) -> str:
        """Everything worth showing in the viewer for this entry."""
        if self.path.suffix == ".log":
            return _read(self.path)
        try:
            data = json.loads(_read(self.path))
        except ValueError:
            return "(unreadable history file)"
        out = [f"Started:  {data.get('started')}", f"Trigger:  {data.get('trigger')}",
               f"Duration: {data.get('duration_s')}s", f"Status:   {data.get('status')}", f"Summary:  {data.get('summary')}", ""]
        for r in data.get("results", []):
            out.append(f"===== {r.get('backend')} – {r.get('status')} =====")
            for f in r.get("findings", []):
                out.append(f"[{f.get('severity')}] {f.get('title')}")
            if r.get("message"):
                out.append(r["message"])
            if r.get("log"):
                out += ["", "--- output ---", r["log"]]
            out.append("")
        return "\n".join(out)


def _read(p: Path) -> str:
    try:
        return p.read_text(errors="replace")
    except OSError as e:
        return f"(cannot read {p}: {e})"


def _stamp() -> str:
    return time.strftime("%Y%m%dT%H%M%S")


def _result_dict(r: ScanResult) -> dict:
    return {"backend": r.backend, "status": r.status, "message": r.message[-LOG_CAP:], "log": r.log[-LOG_CAP:],
            "findings": [{"severity": f.severity, "title": f.title, "source": f.source, "package": f.package}
                         for f in r.findings]}


def record(report, trigger: str, started: float, duration_s: float, keep: int = 200) -> Path | None:
    """Persist a package-scan report. Never raises: history must not break scanning."""
    status = SKIPPED if report.skipped else report.status
    data = {"started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started)), "kind": "packages",
            "trigger": trigger, "status": status, "summary": report.summary(), "duration_s": round(duration_s, 1),
            "results": [_result_dict(r) for r in report.results]}
    try:
        d = history_dir()
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"{time.strftime('%Y%m%dT%H%M%S', time.localtime(started))}-packages.json"
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1))
        tmp.replace(p)
        prune(keep)
        return p
    except OSError:
        return None


def new_binary_log_path() -> Path:
    d = history_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{_stamp()}-binaries.log"


def _binary_status(text: str) -> tuple[str, str]:
    if "Result: no threats found" in text:
        return CLEAN, "No threats found"
    if "Result: THREATS FOUND" in text:
        return CRITICAL, "Threats found – see log"
    if "Result: scan failed" in text:
        return ERROR, "Scan failed – see log"
    return UNKNOWN, "No result recorded (window closed early?)"


def _stamp_to_display(name: str) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.strptime(name[:15], "%Y%m%dT%H%M%S"))
    except ValueError:
        return name


_cache: dict[tuple[str, int, int], Entry] = {}  # (path, mtime_ns, size) -> parsed entry; keeps polling cheap


def list_entries() -> list[Entry]:
    """Newest first. Unchanged files are served from a cache so the viewer can poll often."""
    d = history_dir()
    entries: list[Entry] = []
    try:
        files = sorted(d.iterdir(), reverse=True)
    except OSError:
        return []
    live: set[tuple[str, int, int]] = set()
    for p in files:
        if p.suffix not in (".json", ".log"):
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        key = (str(p), st.st_mtime_ns, st.st_size)
        live.add(key)
        if key not in _cache:
            _cache[key] = _parse(p)
        entries.append(_cache[key])
    for k in [k for k in _cache if k not in live]:
        del _cache[k]
    return entries


def _parse(p: Path) -> Entry:
    if p.suffix == ".json":
        try:
            data = json.loads(_read(p))
            return Entry(p, data.get("started", _stamp_to_display(p.name)), data.get("kind", "packages"),
                         data.get("trigger", ""), data.get("status", UNKNOWN), data.get("summary", ""),
                         float(data.get("duration_s", 0)))
        except (ValueError, TypeError):
            return Entry(p, _stamp_to_display(p.name), "packages", "", UNKNOWN, "(unreadable)")
    status, summary = _binary_status(_read(p))
    return Entry(p, _stamp_to_display(p.name), "binaries", "manual", status, summary)


def prune(keep: int) -> None:
    keep = max(10, keep)
    files = sorted((p for p in history_dir().iterdir() if p.suffix in (".json", ".log")), reverse=True)
    for p in files[keep:]:
        p.unlink(missing_ok=True)


def clear() -> int:
    n = 0
    try:
        for p in history_dir().iterdir():
            if p.suffix in (".json", ".log", ".tmp"):
                p.unlink(missing_ok=True)
                n += 1
    except OSError:
        pass
    return n
