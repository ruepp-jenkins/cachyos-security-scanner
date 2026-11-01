"""User settings, stored as JSON in the XDG config directory."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

DEFAULT_IGNORED = ["SCAN-001"]  # aur-scan: "package file could not be analyzed" is an analysis note, not a finding

WEEK_MINUTES = 7 * 24 * 60

DEFAULT_BINARY_PATHS = [
    "/usr/bin",
    "/usr/local/bin",
    "/opt",
    "~/.local/bin",
    "/var/lib/flatpak/exports/bin",
]


def config_path() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "cachy-security-scanner" / "settings.json"


@dataclass
class Settings:
    schema: int = 5  # bump when a default changes meaning; see load()
    # --- when the AUR package scans run (manual scans are always possible) ---
    scan_on_start: bool = True
    startup_delay_minutes: int = 1  # wait this long after the app started (lets the desktop finish starting)
    scan_after_pkg_changes: bool = True
    pkg_change_delay_seconds: int = 10  # merges multi-step upgrades into one scan; short, so a bad package is caught fast
    scan_periodic: bool = True
    interval_minutes: int = 360
    update_sources_before_scan: bool = True
    skip_in_gaming_mode: bool = True
    skip_on_battery: bool = False
    low_priority_scans: bool = True  # run scanners and builds niced, with the lowest I/O priority
    # AUR scanner backends, all enabled by default.
    use_aur_malware_check: bool = True
    use_aur_scan: bool = False  # heuristic analysis, produces false positives: opt-in
    use_community_blocklist: bool = True  # signed list of known malicious AUR packages (lists/blocklist_aur.json)
    # Hide aur-scan findings that the project's signed community list marks as known false positives
    # (only effective while aur-scan itself is enabled).
    use_false_positive_list: bool = True
    # aur-scan results to hide: a rule code (SCAN-001), a package (heidisql) or package:CODE
    ignored_findings: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORED))
    # Binary scan with clamdscan runs only on request from the tray menu.
    binary_scan_paths: list[str] = field(default_factory=lambda: list(DEFAULT_BINARY_PATHS))
    # Optional automatic binary scans (background, no terminal window; result in the history). All off by default.
    binary_on_start: bool = False
    binary_after_pkg_changes: bool = False
    binary_with_aur_scans: bool = False  # run together with every package scan
    binary_periodic: bool = False
    binary_interval_minutes: int = WEEK_MINUTES
    binary_min_gap_hours: int = 24  # start / package change / package scan triggers: not more often than this
    binary_low_priority: bool = True  # nice / ionice for the clamdscan client
    notify_when_clean: bool = False
    confirm_before_remove: bool = True
    history_keep: int = 200  # number of scan records to keep
    editor_command: str = ""  # e.g. "codium"; empty = auto-detect, falls back to the file manager
    autostart: bool = True  # start at login (XDG autostart entry)
    auto_update: bool = True  # app updates from GitHub Releases only

    def validate(self) -> None:
        self.history_keep = max(10, min(int(self.history_keep), 5000))
        self.interval_minutes = max(15, min(int(self.interval_minutes), 52 * WEEK_MINUTES))
        self.startup_delay_minutes = max(0, min(int(self.startup_delay_minutes), 120))
        self.pkg_change_delay_seconds = max(5, min(int(self.pkg_change_delay_seconds), 3600))
        self.binary_interval_minutes = max(60, min(int(self.binary_interval_minutes), 52 * WEEK_MINUTES))
        self.binary_min_gap_hours = max(0, min(int(self.binary_min_gap_hours), 24 * 90))

    @classmethod
    def load(cls, path: Path | None = None) -> "Settings":
        path = path or config_path()
        s = cls()
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            return s
        if isinstance(data, dict):
            for f in fields(cls):
                if f.name in data and isinstance(data[f.name], type(getattr(s, f.name))):
                    setattr(s, f.name, data[f.name])
        old = data.get("schema", 1) if isinstance(data, dict) else 4
        if old < 3:
            s.use_aur_scan = False  # became opt-in: heuristic scanner with false positives
        if old < 4 and isinstance(data, dict):  # the "mode" setting became independent switches
            mode = data.get("mode", "interval")
            s.scan_periodic = mode == "interval"
            if mode == "manual":
                s.scan_on_start = s.scan_after_pkg_changes = False
        if old < 5 and s.pkg_change_delay_seconds == 30:
            s.pkg_change_delay_seconds = 10  # the old default; the minimum gap between package scans was removed
        s.schema = 5
        s.validate()
        return s

    @classmethod
    def load_existing(cls, path: Path | None = None) -> "Settings | None":
        """The saved settings, or None if there is no readable settings file (callers then keep what they have)."""
        return cls.load(path) if (path or config_path()).is_file() else None

    def save(self, path: Path | None = None) -> None:
        path = path or config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2))
        tmp.replace(path)
