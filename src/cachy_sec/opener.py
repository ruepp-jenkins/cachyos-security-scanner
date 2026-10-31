"""Open the files behind a finding in an editor (or the file manager). No Qt, no shell."""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path

# Editors that open a whole folder; the first one installed wins when the setting is empty.
AUTO_EDITORS = ["codium", "vscodium", "code", "code-oss", "cursor", "zed", "subl"]


def finding_dirs(findings) -> dict[str, Path]:
    """package -> directory holding the files the scanner looked at (only existing, absolute ones)."""
    out: dict[str, Path] = {}
    for f in findings:
        for file in getattr(f, "files", []):
            p = Path(file)
            d = p if p.is_dir() else p.parent
            if p.is_absolute() and d.is_dir():
                out.setdefault(f.package or d.name, d)
                break
    return out


def directory_of(files: list[str]) -> Path | None:
    """The existing directory that holds the first of these (absolute) files, or None."""
    for file in files:
        p = Path(file)
        d = p if p.is_dir() else p.parent
        if p.is_absolute() and d.is_dir():
            return d
    return None


def build_command(directory: Path, editor: str = "") -> list[str] | None:
    """Argv to show `directory`: configured editor, else the first known folder editor, else the file manager."""
    if not directory.is_dir():
        return None
    if editor.strip():
        try:
            parts = shlex.split(editor)
        except ValueError:
            return None
        return parts + [str(directory)] if parts and shutil.which(parts[0]) else None
    for name in AUTO_EDITORS:
        exe = shutil.which(name)
        if exe:
            return [exe, str(directory)]
    xdg = shutil.which("xdg-open")
    return [xdg, str(directory)] if xdg else None


def open_directory(directory: Path, editor: str = "") -> tuple[bool, str]:
    cmd = build_command(directory, editor)
    if cmd is None:
        return False, f"cannot open {directory}: no editor / file manager found, or the folder no longer exists"
    try:
        subprocess.Popen(cmd, start_new_session=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=os.path.expanduser("~"))
    except OSError as e:
        return False, str(e)
    return True, cmd[0]
