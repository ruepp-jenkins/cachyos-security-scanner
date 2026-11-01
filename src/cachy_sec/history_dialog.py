"""Scan history viewer."""
from __future__ import annotations

import subprocess

from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import (QCheckBox, QDialog, QHBoxLayout, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton,
                               QSplitter, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
                               QAbstractItemView, QHeaderView)
from pathlib import Path

from PySide6.QtCore import Qt, QTimer

from . import history, icons


THREAT_STATUSES = ("warning", "critical")
_PATH_ROLE = Qt.UserRole


class _SortItem(QTableWidgetItem):
    """Item that sorts by an explicit key (used for the status icon column)."""

    def __init__(self, key: int) -> None:
        super().__init__("")
        self.key = key

    def __lt__(self, other: QTableWidgetItem) -> bool:  # type: ignore[override]
        return self.key < getattr(other, "key", 0)


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
        top = QWidget()
        top_l = QVBoxLayout(top)
        top_l.setContentsMargins(0, 0, 0, 0)
        bar = QHBoxLayout()
        self.filter_edit = QLineEdit(placeholderText="Filter: search all columns and the scan details…", clearButtonEnabled=True)
        self.filter_edit.textChanged.connect(self._refilter)
        self.only_threats = QCheckBox("Only scans with detected threats")
        self.only_threats.toggled.connect(self._refilter)
        bar.addWidget(self.filter_edit, 1)
        bar.addWidget(self.only_threats)
        top_l.addLayout(bar)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["", "Started", "Type", "Trigger", "Summary"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        hdr = self.table.horizontalHeader()
        for c in range(4):
            hdr.setSectionResizeMode(c, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(1, Qt.DescendingOrder)
        self._icons: dict[str, QIcon] = {}
        top_l.addWidget(self.table)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.log = QPlainTextEdit(readOnly=True)
        mono = QFont("monospace")
        mono.setStyleHint(QFont.Monospace)
        self.log.setFont(mono)
        split.addWidget(top)
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
            self._fill()
            if self.selected is not None and not any(e.path == self.selected for e in self.entries):
                self.selected = None  # selected scan was pruned/cleared
                self._set_log("")
        if not self.entries:
            self._set_log("No scans recorded yet.")
        elif self.selected is None:
            if self.table.rowCount():
                self.table.selectRow(0)  # nothing selected yet (first start, or the old selection was removed)
        else:
            self._update_log()

    def _matches(self, e: history.Entry) -> bool:
        if self.only_threats.isChecked() and e.status not in THREAT_STATUSES:
            return False
        needle = self.filter_edit.text().strip().lower()
        if not needle:
            return True
        hay = " ".join((e.started, e.kind, e.trigger, e.status, e.summary)).lower()
        return needle in hay or needle in e.log_text().lower()  # full text over the details; speed is not critical

    def _fill(self) -> None:
        shown = [e for e in self.entries if self._matches(e)]
        hdr = self.table.horizontalHeader()
        col, order = hdr.sortIndicatorSection(), hdr.sortIndicatorOrder()
        self.table.blockSignals(True)
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(shown))
        for i, e in enumerate(shown):
            icon = _SortItem(icons.STATUS_RANK.get(e.status, 1))
            icon.setIcon(self._status_icon(e.status))
            icon.setToolTip(e.status)
            icon.setData(_PATH_ROLE, str(e.path))
            self.table.setItem(i, 0, icon)
            for c, v in enumerate((e.started, e.kind, e.trigger, e.summary), start=1):
                self.table.setItem(i, c, QTableWidgetItem(v))
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(col, order)
        for i in range(self.table.rowCount()):
            if self.table.item(i, 0).data(_PATH_ROLE) == (str(self.selected) if self.selected else None):
                self.table.selectRow(i)
                break
        self.table.blockSignals(False)

    def _status_icon(self, status: str) -> QIcon:
        if status not in self._icons:
            self._icons[status] = QIcon(icons.for_status(status))
        return self._icons[status]

    def select_latest(self, kind: str | None, statuses: tuple[str, ...]) -> None:
        """Select the newest entry of this kind (None = any) with one of these statuses, making sure it is visible."""
        self.reload()
        e = next((e for e in self.entries if (kind is None or e.kind == kind) and e.status in statuses), None)
        if e is None:
            return
        self.filter_edit.blockSignals(True)
        self.only_threats.blockSignals(True)
        self.filter_edit.clear()
        self.only_threats.setChecked(False)  # a filter must not hide the entry the user was sent to
        self.filter_edit.blockSignals(False)
        self.only_threats.blockSignals(False)
        self.selected = e.path
        self._fill()
        self._last_text = None
        self._update_log(reset_scroll=True)
        item = next((self.table.item(i, 0) for i in range(self.table.rowCount())
                     if self.table.item(i, 0).data(_PATH_ROLE) == str(e.path)), None)
        if item is not None:
            self.table.scrollToItem(item)

    def _refilter(self, *_: object) -> None:
        self._fill()

    def _selection_changed(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if rows:
            self.selected = Path(self.table.item(rows[0].row(), 0).data(_PATH_ROLE))
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
