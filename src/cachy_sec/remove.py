"""Optional removal of flagged packages. Only called after explicit user confirmation."""
from __future__ import annotations

import re

from .scanners.base import run

_PKG = re.compile(r"^[a-z0-9@._+-]+$")


def remove_packages(pkgs: list[str]) -> tuple[bool, str]:
    safe = [p for p in pkgs if _PKG.match(p)]
    if not safe or len(safe) != len(pkgs):
        return False, "refusing: invalid package name"
    code, out = run(["pkexec", "pacman", "-Rns", "--noconfirm", "--", *safe], 600)
    return code == 0, out[-500:]
