"""Window shown when a scan finds something: entries (each with its own Ignore button), details, removal.

There is only one such window; later scans update it in place (`update_findings`).
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices, QFont, QIcon
from PySide6.QtWidgets import (QDialog, QFrame, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton,
                               QScrollArea, QVBoxLayout, QWidget)

from . import engine, icons, ignores, opener, report

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
        self.editor = editor
        self.on_ignore = on_ignore
        self.on_changed = on_changed  # called once when the window closes after at least one ignore
        self._ignored_any = False
        self._ignored: set[tuple[str, str, str]] = set()  # (package, version, code) accepted in this window
        self._keys: set[tuple] = set()
        self._rows: set[tuple[str, str, str]] = set()
        self._new_rows: set[tuple[str, str, str]] = set()
        self._notes: list[str] = []
        self._pkgs: list[str] = []
        self._entries_height = 0
        root = QVBoxLayout(self)
        self.banner = QLabel()
        self.banner.setWordWrap(True)
        self.banner.setStyleSheet("background: #8a6d00; color: white; padding: 4px;")
        self.banner.setVisible(False)
        root.addWidget(self.banner)

        top = QHBoxLayout()
        self.pic = QLabel()
        self.pic.setAlignment(self.pic.alignment() | 0x20)  # top
        top.addWidget(self.pic)
        self.summary_label = QLabel()
        self.summary_label.setWordWrap(True)
        top.addWidget(self.summary_label, 1)
        root.addLayout(top)
        self.hint = QLabel()
        self.hint.setWordWrap(True)
        self.hint.setEnabled(False)  # greyed secondary text
        root.addWidget(self.hint)

        self.intro = QLabel("Each entry can be inspected (Open files) and, for a known version, accepted on its own "
                            "(Ignore; reported again after an update), or reported as a false positive to the project:")
        self.intro.setWordWrap(True)
        root.addWidget(self.intro)
        self.area = QScrollArea()
        self.area.setWidgetResizable(True)
        self.area.setFrameShape(QFrame.StyledPanel)
        root.addWidget(self.area)

        self.details = QPlainTextEdit(readOnly=True)
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
        self.remove_button = QPushButton("Remove packages…")
        self.remove_button.clicked.connect(lambda _=False: on_remove(list(self._pkgs)))
        row.addWidget(self.remove_button)
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        row.addWidget(close)
        root.addLayout(row)
        self._show(summary, findings, pkgs, scan_info, notes or [])
        self.resize(COLLAPSED_WIDTH, 200 + self._entries_height)

    def update_findings(self, summary: str, findings, pkgs: list[str], scan_info: str = "",
                        notes: list[str] | None = None, carried: list[str] | None = None) -> None:
        """Show the result of a newer scan. Without a change in the findings the list is left untouched, so the
        scroll position and the selected text survive."""
        keys = {engine.finding_key(f) for f in findings}
        new, gone = len(keys - self._keys), len(self._keys - keys)
        text = "Updated by a newer scan" + (f" ({scan_info})" if scan_info else "") + ": "
        text += ", ".join(t for t in (f"{new} new" if new else "", f"{gone} gone" if gone else "") if t) or "no change"
        text += "."
        if carried:
            text += (f" {', '.join(carried)} did not finish, so its findings are still the ones of an earlier scan.")
        self._show(summary, findings, pkgs, scan_info, notes or [])
        self.banner.setText(text)
        self.banner.setVisible(True)
        self._grow()

    def _grow(self) -> None:
        """Make room for the banner and for added entries; never shrinks a window the user has sized."""
        needed = 200 + self._entries_height + self.banner.sizeHint().height()
        if self.details.isVisible():
            needed += self.details.minimumSizeHint().height()
        if not self.isMaximized() and self.height() < needed:
            self.resize(self.width(), needed)

    def _show(self, summary: str, findings, pkgs: list[str], scan_info: str, notes: list[str]) -> None:
        state = "Possible compromise" if findings else "No findings any more"
        self.setWindowTitle(state + (f" – {scan_info}" if scan_info else ""))
        icon = QIcon(icons.path(icons.BAD if findings else icons.GOOD))
        self.setWindowIcon(icon)
        self.pic.setPixmap(icon.pixmap(64, 64))
        self.summary_label.setText(summary)
        self.hint.setText("\n".join(notes))
        self.hint.setVisible(bool(notes))
        self._pkgs = list(pkgs)
        self.remove_button.setVisible(bool(pkgs))

        keys = {engine.finding_key(f) for f in findings}
        if keys == self._keys and self.area.widget() is not None:
            return
        entries = ignores.rows(findings)
        rows = {(r.package, r.version, r.code) for r in entries}
        self._new_rows = rows - self._rows if self.area.widget() is not None else set()
        self._keys, self._rows = keys, rows

        position = self.area.verticalScrollBar().value()
        inner = QWidget()
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(6, 4, 6, 4)
        for r in entries:
            lay.addLayout(self._entry_row(r))
        lay.addStretch()
        self.area.setWidget(inner)  # deletes the previous one
        self._entries_height = min(len(entries), MAX_VISIBLE_ROWS) * ROW_HEIGHT + 16 if entries else 0
        self.area.setMinimumHeight(self._entries_height)
        self.area.setVisible(bool(entries))
        self.intro.setVisible(bool(entries))
        self.area.verticalScrollBar().setValue(position)

        position = self.details.verticalScrollBar().value()
        self.details.setPlainText(details_text(findings))
        self.details.verticalScrollBar().setValue(position)

    def _entry_row(self, r: ignores.Row) -> QHBoxLayout:
        line = QHBoxLayout()
        times = f"  ×{r.count}" if r.count > 1 else ""
        key = (r.package, r.version, r.code)
        mark = "NEW  " if key in self._new_rows else ""
        label = QLabel(f"{mark}{r.package} {r.version} – {r.code} {r.title}{times}")  # plain text: scanner output is untrusted
        label.setWordWrap(True)
        line.addWidget(label, 1)
        directory = opener.directory_of(r.files)
        op = QPushButton("Open files")
        if directory is not None:
            op.setToolTip(f"Open {directory} in your editor.\nEditors with a restricted mode (VSCodium/VS Code): "
                          "do not trust the folder.")
            op.clicked.connect(lambda _=False, d=directory: self._open(d))
        else:
            op.setEnabled(False)
            op.setToolTip("The folder with the scanned files no longer exists.")
        line.addWidget(op)
        btn = QPushButton("Ignore")
        if self.on_ignore and r.version:
            btn.setToolTip(f"Accept {r.code} for {r.package} {r.version} only.\n"
                           "After an update of the package it is reported again if it still applies.\n"
                           "Revoke it any time in the settings.")
            btn.clicked.connect(lambda _=False, r=r, b=btn, lb=label: self._ignore(r, b, lb))
        else:
            btn.setEnabled(False)
            btn.setToolTip("The version of this package is unknown, so the finding cannot be accepted for one version.")
        if key in self._ignored:  # accepted here while the scan that updated the list was already running
            btn.setEnabled(False)
            btn.setText("Ignored")
            label.setEnabled(False)
        line.addWidget(btn)
        rep = QPushButton("Report false positive")
        rep.setToolTip("Open a prefilled form on GitHub to tell the project that this finding is wrong for this version.\n"
                       "Only package, version and rule code are filled in; nothing is sent by the app.\n"
                       "Please check the package yourself first.")
        rep.setStyleSheet(report.STYLE_FALSE_POSITIVE)
        rep.clicked.connect(lambda _=False, r=r: QDesktopServices.openUrl(
            QUrl(report.false_positive_url(r.package, r.version, [r.code]))))
        line.addWidget(rep)
        bad = QPushButton("Report malicious")
        bad.setToolTip("Open a prefilled form on GitHub to propose this package for the community blocklist.\n"
                       "Only report packages you have checked yourself. Nothing is sent by the app.")
        bad.setStyleSheet(report.STYLE_MALICIOUS)
        bad.clicked.connect(lambda _=False, r=r: QDesktopServices.openUrl(
            QUrl(report.blocklist_url(r.package, r.version))))
        line.addWidget(bad)
        return line

    def _ignore(self, r: ignores.Row, button: QPushButton, label: QLabel) -> None:
        self.on_ignore(r.package, r.version, [r.code])
        self._ignored_any = True
        self._ignored.add((r.package, r.version, r.code))
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
