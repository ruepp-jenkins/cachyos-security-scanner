"""Scan history viewer."""
from __future__ import annotations

import subprocess

from PySide6.QtGui import QFont
from PySide6.QtWidgets import (QDialog, QHBoxLayout, QMessageBox, QPlainTextEdit, QPushButton, QSplitter,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QAbstractItemView, QHeaderView)
from PySide6.QtCore import Qt

from . import history


class HistoryDialog(QDialog):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Scan history")
        self.resize(900, 600)
        self.entries: list[history.Entry] = []
        root = QVBoxLayout(self)
        split = QSplitter(Qt.Vertical)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Started", "Type", "Trigger", "Status", "Summary"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self._show)
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

    def reload(self) -> None:
        self.entries = history.list_entries()
        self.table.setRowCount(len(self.entries))
        for i, e in enumerate(self.entries):
            for c, v in enumerate((e.started, e.kind, e.trigger, e.status, e.summary)):
                self.table.setItem(i, c, QTableWidgetItem(v))
        self.log.setPlainText("" if self.entries else "No scans recorded yet.")
        if self.entries:
            self.table.selectRow(0)

    def _show(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if rows:
            self.log.setPlainText(self.entries[rows[0].row()].log_text())

    def _open_folder(self) -> None:
        d = history.history_dir()
        d.mkdir(parents=True, exist_ok=True)
        subprocess.Popen(["xdg-open", str(d)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _clear(self) -> None:
        if QMessageBox.question(self, "Clear history", "Delete all recorded scans and logs?") == QMessageBox.Yes:
            history.clear()
            self.reload()
