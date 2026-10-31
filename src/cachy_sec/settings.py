"""User settings, stored as JSON in the XDG config directory."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

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
    mode: str = "interval"  # startup | interval | manual
    interval_minutes: int = 360
    scan_on_start: bool = True
    scan_after_pkg_changes: bool = True
    update_sources_before_scan: bool = True
    skip_in_gaming_mode: bool = True
    skip_on_battery: bool = False
    # AUR scanner backends, all enabled by default.
    use_aur_malware_check: bool = True
    use_aur_scan: bool = True
    use_builtin_list: bool = True
    # Binary scan with clamdscan runs only on request from the tray menu.
    binary_scan_paths: list[str] = field(default_factory=lambda: list(DEFAULT_BINARY_PATHS))
    notify_when_clean: bool = False
    confirm_before_remove: bool = True
    auto_update: bool = True  # app updates from GitHub Releases only

    def validate(self) -> None:
        if self.mode not in MODES:
            self.mode = "interval"
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
        s.validate()
        return s

    def save(self, path: Path | None = None) -> None:
        path = path or config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2))
        tmp.replace(path)
