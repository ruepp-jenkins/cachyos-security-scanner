"""Heuristics for "the user is gaming right now" and "running on battery"."""
from __future__ import annotations

from pathlib import Path

# Process names (comm, max 15 chars) that indicate an active gaming session.
GAMING_PROCS = {"gamemoded", "gamescope", "gamescope-wl", "gamescopereaper", "reaper", "SteamLaunch", "lutris-wrapper"}


def _comms(proc: Path = Path("/proc")) -> set[str]:
    names: set[str] = set()
    for d in proc.iterdir():
        if d.name.isdigit():
            try:
                names.add((d / "comm").read_text().strip())
            except OSError:
                continue
    return names


def gaming_active(proc: Path = Path("/proc")) -> bool:
    try:
        return bool(_comms(proc) & GAMING_PROCS)
    except OSError:
        return False


def on_battery(supply: Path = Path("/sys/class/power_supply")) -> bool:
    try:
        mains = [p for p in supply.iterdir() if (p / "type").read_text().strip() == "Mains"]
        if not mains:
            return False
        return all((p / "online").read_text().strip() == "0" for p in mains)
    except OSError:
        return False
