"""Dialog shown when a scan finds something: entries (each with its own Ignore button), details, removal."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import (QDialog, QFrame, QHBoxLayout, QLabel, QMenu, QPlainTextEdit, QPushButton,
                               QScrollArea, QVBoxLayout, QWidget)

from . import icons, ignores, opener

COLLAPSED_WIDTH = 700
EXPANDED_SIZE = (900, 620)  # roomy enough that file paths and issue lines do not wrap
MAX_VISIBLE_ROWS = 6
ROW_HEIGHT = 36


def details_text(findings) -> str:
    blocks = []
    for f in findings:
        lines = [f"[{f.severity}] {f.source}: {f.title}"] + [f"    {ln}" for ln in f.detail.splitlines()]
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


class FindingsDialog(QDialog):
    def __init__(self, summary: str, findings, pkgs: list[str], on_remove: Callable[[list[str]], None],
                 editor: str = "", on_ignore: Callable[[str, str, list[str]], None] | None = None,
                 on_changed: Callable[[], None] | None = None, scan_info: str = "",
                 notes: list[str] | None = None) -> None:
        super().__init__()
        self._base_title = "Possible compromise" + (f" – {scan_info}" if scan_info else "")
        self.editor = editor
        self.on_ignore = on_ignore
        self.on_changed = on_changed  # called once when the window closes after at least one ignore
        self._ignored_any = False
        self.setWindowTitle(self._base_title)
        self.setWindowIcon(QIcon(icons.path(icons.BAD)))
        root = QVBoxLayout(self)
        self.banner = QLabel("A newer scan has finished since this window opened; these findings may no longer apply.")
        self.banner.setWordWrap(True)
        self.banner.setStyleSheet("background: #8a6d00; color: white; padding: 4px;")
        self.banner.setVisible(False)
        root.addWidget(self.banner)

        top = QHBoxLayout()
        pic = QLabel()
        pic.setPixmap(QIcon(icons.path(icons.BAD)).pixmap(64, 64))
        pic.setAlignment(pic.alignment() | 0x20)  # top
        top.addWidget(pic)
        text = QLabel(summary)
        text.setWordWrap(True)
        top.addWidget(text, 1)
        root.addLayout(top)
        if notes:
            hint = QLabel("\n".join(notes))
            hint.setWordWrap(True)
            hint.setEnabled(False)  # greyed secondary text
            root.addWidget(hint)

        entries = ignores.rows(findings) if on_ignore else []
        self._entries_height = 0
        if entries:
            root.addWidget(QLabel("Each entry can be accepted on its own, for exactly the installed version "
                                  "(reported again after an update):"))
            area = QScrollArea()
            area.setWidgetResizable(True)
            area.setFrameShape(QFrame.StyledPanel)
            inner = QWidget()
            lay = QVBoxLayout(inner)
            lay.setContentsMargins(6, 4, 6, 4)
            for r in entries:
                lay.addLayout(self._entry_row(r))
            lay.addStretch()
            area.setWidget(inner)
            self._entries_height = min(len(entries), MAX_VISIBLE_ROWS) * ROW_HEIGHT + 16
            area.setMinimumHeight(self._entries_height)
            root.addWidget(area)

        self.details = QPlainTextEdit(details_text(findings), readOnly=True)
        mono = QFont("monospace")
        mono.setStyleHint(QFont.Monospace)
        self.details.setFont(mono)
        self.details.setLineWrapMode(QPlainTextEdit.NoWrap)  # long paths scroll instead of breaking every line
        self.details.setVisible(False)
        root.addWidget(self.details, 1)

        row = QHBoxLayout()
        self.toggle = QPushButton("Show details")
        self.toggle.setCheckable(True)
        self.toggle.toggled.connect(self._toggled)
        row.addWidget(self.toggle)
        row.addStretch()
        dirs = opener.finding_dirs(findings)
        if dirs:
            op = QPushButton("Open files…")
            op.setToolTip("Open the folder with the scanned files (PKGBUILD, install script, …) in your editor.\n"
                          "Editors with a restricted mode (VSCodium/VS Code): do not trust the folder.")
            if len(dirs) == 1:
                d = next(iter(dirs.values()))
                op.clicked.connect(lambda: self._open(d))
            else:
                menu = QMenu(op)
                for pkg, d in dirs.items():
                    menu.addAction(f"{pkg}  ({d})", lambda d=d: self._open(d))
                op.setMenu(menu)
            row.addWidget(op)
        if pkgs:
            rm = QPushButton("Remove packages…")
            rm.clicked.connect(lambda: on_remove(pkgs))
            row.addWidget(rm)
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        row.addWidget(close)
        root.addLayout(row)
        self.resize(COLLAPSED_WIDTH, 200 + self._entries_height)

    def mark_outdated(self) -> None:
        """Called when a newer scan has produced a result, so an old window is not mistaken for the current state."""
        self.setWindowTitle(self._base_title + " (outdated)")
        self.banner.setVisible(True)

    def _entry_row(self, r: ignores.Row) -> QHBoxLayout:
        line = QHBoxLayout()
        times = f"  ×{r.count}" if r.count > 1 else ""
        label = QLabel(f"{r.package} {r.version} – {r.code} {r.title}{times}")  # plain text: scanner output is untrusted
        label.setWordWrap(True)
        line.addWidget(label, 1)
        btn = QPushButton("Ignore")
        btn.setToolTip(f"Accept {r.code} for {r.package} {r.version} only.\n"
                       "After an update of the package it is reported again if it still applies.\n"
                       "Revoke it any time in the settings.")
        btn.clicked.connect(lambda _=False, r=r, b=btn, lb=label: self._ignore(r, b, lb))
        line.addWidget(btn)
        return line

    def _ignore(self, r: ignores.Row, button: QPushButton, label: QLabel) -> None:
        self.on_ignore(r.package, r.version, [r.code])
        self._ignored_any = True
        button.setEnabled(False)
        button.setText("Ignored")
        label.setEnabled(False)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().closeEvent(event)
        if self._ignored_any and self.on_changed:
            self._ignored_any = False
            self.on_changed()  # re-scan once, after the user is done ticking entries off

    def _open(self, directory: Path) -> None:
        ok, msg = opener.open_directory(directory, self.editor)
        if not ok:
            self.details.setVisible(True)
            self.details.appendPlainText("\n" + msg)

    def _toggled(self, on: bool) -> None:
        self.details.setVisible(on)
        self.toggle.setText("Hide details" if on else "Show details")
        if on:
            self.resize(max(self.width(), EXPANDED_SIZE[0]), max(self.height(), EXPANDED_SIZE[1] + self._entries_height // 2))
        else:
            self.resize(COLLAPSED_WIDTH, 200 + self._entries_height)
