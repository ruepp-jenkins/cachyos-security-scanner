"""Dialog shown when a scan finds something: summary, collapsible details, optional removal."""
from __future__ import annotations

from collections.abc import Callable

from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import (QDialog, QHBoxLayout, QLabel, QMenu, QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout)

from . import icons, opener
from pathlib import Path

COLLAPSED_SIZE = (640, 200)
EXPANDED_SIZE = (900, 560)  # roomy enough that file paths and issue lines do not wrap


def details_text(findings) -> str:
    blocks = []
    for f in findings:
        lines = [f"[{f.severity}] {f.source}: {f.title}"] + [f"    {ln}" for ln in f.detail.splitlines()]
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


class FindingsDialog(QDialog):
    def __init__(self, summary: str, findings, pkgs: list[str], on_remove: Callable[[list[str]], None],
                 editor: str = "", on_ignore: Callable[[str, str, list[str]], None] | None = None) -> None:
        super().__init__()
        self.editor = editor
        self.on_ignore = on_ignore
        self.setWindowTitle("Possible compromise")
        self.setWindowIcon(QIcon(icons.path(icons.BAD)))
        root = QVBoxLayout(self)

        top = QHBoxLayout()
        pic = QLabel()
        pic.setPixmap(QIcon(icons.path(icons.BAD)).pixmap(64, 64))
        pic.setAlignment(pic.alignment() | 0x20)  # top
        top.addWidget(pic)
        text = QLabel(summary)
        text.setWordWrap(True)
        top.addWidget(text, 1)
        root.addLayout(top)

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
        ignorable = [f for f in findings if f.package and f.version and f.codes]
        if ignorable and on_ignore:
            ig = QPushButton("Ignore for this version…")
            ig.setToolTip("Accept these findings for exactly the installed version of the software.\n"
                          "After an update of the package they are reported again if they still apply.")
            menu = QMenu(ig)
            for f in ignorable:
                act = menu.addAction(f"{f.package} {f.version}  –  {', '.join(f.codes)}")
                act.triggered.connect(lambda _=False, f=f, act=act: self._ignore(f, act))
            ig.setMenu(menu)
            row.addWidget(ig)
        if pkgs:
            rm = QPushButton("Remove packages…")
            rm.clicked.connect(lambda: on_remove(pkgs))
            row.addWidget(rm)
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        row.addWidget(close)
        root.addLayout(row)
        self.resize(*COLLAPSED_SIZE)

    def _ignore(self, f, action) -> None:
        q = QMessageBox.question(
            self, "Ignore findings",
            f"Ignore {', '.join(f.codes)} for {f.package} {f.version}?\n\n"
            "This only applies to exactly this version. When the package is updated and the problem is still "
            "there, you will be notified again. You can revoke it in the settings.")
        if q != QMessageBox.Yes:
            return
        self.on_ignore(f.package, f.version, list(f.codes))
        action.setEnabled(False)
        self.details.setVisible(True)
        self.details.appendPlainText(f"\nIgnored for {f.package} {f.version}: {', '.join(f.codes)}")

    def _open(self, directory: Path) -> None:
        ok, msg = opener.open_directory(directory, self.editor)
        if not ok:
            self.details.setVisible(True)
            self.details.appendPlainText("\n" + msg)

    def _toggled(self, on: bool) -> None:
        self.details.setVisible(on)
        self.toggle.setText("Hide details" if on else "Show details")
        self.resize(*(EXPANDED_SIZE if on else COLLAPSED_SIZE))
