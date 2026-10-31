"""Scan history viewer."""
from __future__ import annotations

import subprocess

from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import (QDialog, QHBoxLayout, QMessageBox, QPlainTextEdit, QPushButton, QSplitter,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QAbstractItemView, QHeaderView)
from pathlib import Path

from PySide6.QtCore import Qt, QTimer

from . import history, icons


class HistoryDialog(QDialog):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Scan history")
        self.setWindowIcon(QIcon(icons.path(icons.APP)))
        self.resize(900, 600)
        self.entries: list[history.Entry] = []
        self.selected: Path | None = None  # selection is tracked by file, not by row, so new entries don't move it
        self._last_text: str | None = None
        self._last_sig: list | None = None
        root = QVBoxLayout(self)
        split = QSplitter(Qt.Vertical)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Started", "Type", "Trigger", "Status", "Summary"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.log = QPlainTextEdit(readOnly=True)
        mono = QFont("monospace")
        mono.setStyleHint(QFont.Monospace)
        self.log.setFont(mono)
        split.addWidget(self.table)
        split.addWidget(self.log)
        split.setSizes([250, 350])
        root.addWidget(split)
        row = QHBoxLayout()
        for text, fn in (("Refresh", self.reload), ("Open folder", self._open_folder), ("Clear history…", self._clear)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addStretch()
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        row.addWidget(close)
        root.addLayout(row)
        self.reload()
        self.timer = QTimer(self)  # live view: new scans appear and a running scan's log keeps growing
        self.timer.timeout.connect(self.reload)
        self.timer.start(3000)

    def reload(self) -> None:
        """Pick up new/changed scans without touching the current selection."""
        self.entries = history.list_entries()
        sig = [(e.path, e.status, e.summary) for e in self.entries]
        if sig != self._last_sig:
            self._last_sig = sig
            self.table.blockSignals(True)
            self.table.setRowCount(len(self.entries))
            for i, e in enumerate(self.entries):
                for c, v in enumerate((e.started, e.kind, e.trigger, e.status, e.summary)):
                    self.table.setItem(i, c, QTableWidgetItem(v))
            row = next((i for i, e in enumerate(self.entries) if e.path == self.selected), -1)
            if row >= 0:
                self.table.selectRow(row)
            self.table.blockSignals(False)
            if row < 0 and self.selected is not None:  # selected scan was pruned/cleared
                self.selected = None
                self._set_log("")
        if not self.entries:
            self._set_log("No scans recorded yet.")
        elif self.selected is None:
            self.table.selectRow(0)  # nothing selected yet (first start, or the old selection was removed)
        else:
            self._update_log()

    def _selection_changed(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if rows:
            self.selected = self.entries[rows[0].row()].path
            self._last_text = None  # new entry: show from the top
            self._update_log(reset_scroll=True)

    def _update_log(self, reset_scroll: bool = False) -> None:
        e = next((e for e in self.entries if e.path == self.selected), None)
        if e is None:
            return
        text = e.log_text()
        if text == self._last_text:
            return
        self._set_log(text, keep_position=not reset_scroll)

    def _set_log(self, text: str, keep_position: bool = False) -> None:
        bar = self.log.verticalScrollBar()
        at_bottom = bar.value() >= bar.maximum() - 2
        pos = bar.value()
        self._last_text = text
        self.log.setPlainText(text)
        if keep_position:
            bar.setValue(bar.maximum() if at_bottom else pos)  # follow a growing log only if already at the end

    def _open_folder(self) -> None:
        d = history.history_dir()
        d.mkdir(parents=True, exist_ok=True)
        subprocess.Popen(["xdg-open", str(d)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _clear(self) -> None:
        if QMessageBox.question(self, "Clear history", "Delete all recorded scans and logs?") == QMessageBox.Yes:
            history.clear()
            self.reload()
