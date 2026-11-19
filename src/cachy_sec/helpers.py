"""Which AUR helpers are installed, and the (experimental) yay setting that keeps build folders.

The package scanner (aur-scan) reads what the AUR helper leaves in its cache. paru keeps the extracted sources (`src/`),
yay deletes them unless its `keepSrc` option is on, so a scan can see much less with yay. The app only *reads* this
information; it changes yay's configuration only when the user clicks the button, by running `yay --keepsrc --save`.
"""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field

from .scanners.base import run

SUPPORTED = "paru"
OTHERS = ("yay", "pikaur", "trizen", "aura", "pakku", "rua", "aurman", "pacaur")  # other AUR helpers worth a warning


@dataclass
class Info:
    found: list[str] = field(default_factory=list)  # installed AUR helpers, supported one first
    yay_keepsrc: bool | None = None  # None = yay not installed, or its setting could not be read

    @property
    def paru(self) -> bool:
        return SUPPORTED in self.found

    @property
    def others(self) -> list[str]:
        return [h for h in self.found if h != SUPPORTED]

    @property
    def yay_needs_setting(self) -> bool:
        """yay is installed and its keepSrc option is not (known to be) on."""
        return "yay" in self.found and self.yay_keepsrc is not True


def parse_keepsrc(output: str) -> bool | None:
    """The `keepSrc` value from `yay -P -g` (a JSON document, possibly with other text around it)."""
    start, end = output.find("{"), output.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(output[start:end + 1])
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    for key, value in data.items():
        if key.lower() == "keepsrc" and isinstance(value, bool):
            return value
    return None


def yay_keepsrc() -> bool | None:
    code, out = run(["yay", "-P", "-g"], 30)
    return parse_keepsrc(out) if code == 0 else None


def inspect() -> Info:
    found = [h for h in (SUPPORTED, *OTHERS) if shutil.which(h)]
    return Info(found, yay_keepsrc() if "yay" in found else None)


def enable_yay_keepsrc() -> tuple[bool, str]:
    """Run `yay --keepsrc --save` and read the setting back. Only called when the user asks for it."""
    code, out = run(["yay", "--keepsrc", "--save"], 60)
    if code != 0:
        return False, (out.strip().splitlines() or [f"yay exited with code {code}"])[-1]
    value = yay_keepsrc()
    if value is True:
        return True, "keepSrc is now on. It applies to packages built from now on; rebuild a package to get its sources back."
    return False, "yay ran, but keepSrc is still not reported as on. Check `yay -P -g`."
