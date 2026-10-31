"""User settings, stored as JSON in the XDG config directory."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

DEFAULT_IGNORED = ["SCAN-001"]  # aur-scan: "package file could not be analyzed" is an analysis note, not a finding

MODES = ("startup", "interval", "manual")

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
    schema: int = 3  # bump when a default changes meaning; see load()
    mode: str = "interval"  # startup | interval | manual
    interval_minutes: int = 360
    scan_on_start: bool = True
    scan_after_pkg_changes: bool = True
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
    notify_when_clean: bool = False
    confirm_before_remove: bool = True
    history_keep: int = 200  # number of scan records to keep
    editor_command: str = ""  # e.g. "codium"; empty = auto-detect, falls back to the file manager
    autostart: bool = True  # start at login (XDG autostart entry)
    auto_update: bool = True  # app updates from GitHub Releases only

    def validate(self) -> None:
        if self.mode not in MODES:
            self.mode = "interval"
        self.history_keep = max(10, min(int(self.history_keep), 5000))
        self.interval_minutes = max(15, min(int(self.interval_minutes), 7 * 24 * 60))

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
        old = data.get("schema", 1) if isinstance(data, dict) else 3
        if old < 3:
            s.use_aur_scan = False  # became opt-in: heuristic scanner with false positives
        s.schema = 3
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
