"""Settings dialog."""
from __future__ import annotations

import copy

from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QGroupBox,
                               QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit, QPushButton, QSpinBox,
                               QVBoxLayout)

from . import clamd_schedule
from .scanners import clamd
from .scanners.aur_malware_check import AurMalwareCheck
from .scanners.aur_scan import AurScan
from .scanners.builtin_list import BuiltinList
from .settings import Settings


class SettingsDialog(QDialog):
    def __init__(self, s: Settings) -> None:
        super().__init__()
        self.setWindowTitle("CachyOS Security Scanner – Settings")
        self.s = copy.deepcopy(s)
        root = QVBoxLayout(self)

        when = QGroupBox("When to scan")
        f = QFormLayout(when)
        self.mode = QComboBox()
        self.mode.addItem("Only right after start", "startup")
        self.mode.addItem("At regular intervals", "interval")
        self.mode.addItem("Manual only", "manual")
        self.mode.setCurrentIndex(self.mode.findData(s.mode))
        self.interval = QSpinBox()
        self.interval.setRange(15, 7 * 24 * 60)
        self.interval.setSuffix(" min")
        self.interval.setValue(s.interval_minutes)
        f.addRow("Mode", self.mode)
        f.addRow("Interval", self.interval)
        self.on_start = self._cb("Scan at start", s.scan_on_start, f)
        self.after_pkg = self._cb("Scan after package installs/updates (needs pacman hook)", s.scan_after_pkg_changes, f)
        self.update_src = self._cb("Update scanner sources before each scan", s.update_sources_before_scan, f)
        self.gaming = self._cb("Skip automatic scans in gaming mode (gamemode, gamescope, Steam)", s.skip_in_gaming_mode, f)
        self.battery = self._cb("Skip automatic scans on battery", s.skip_on_battery, f)
        self.clean_note = self._cb("Also notify when nothing was found", s.notify_when_clean, f)
        root.addWidget(when)

        back = QGroupBox("AUR scanners")
        bl = QVBoxLayout(back)
        self.b_amc = self._backend(bl, "aur-malware-check (lenucksi)", s.use_aur_malware_check, AurMalwareCheck())
        self.b_scan = self._backend(bl, "aur-scan (ks-aur-scanner)", s.use_aur_scan, AurScan())
        self.b_list = self._backend(bl, "Built-in blocklist (needs CACHY_SEC_BLOCKLIST_URL)", s.use_builtin_list, BuiltinList())
        bl.addWidget(QLabel("Scanner repositories are cloned and updated automatically before scans."))
        root.addWidget(back)

        clam = QGroupBox("Binary scan with ClamAV (clamdscan, on request from the tray menu)")
        cl = QVBoxLayout(clam)
        if not clamd.available():
            cl.addWidget(QLabel("clamdscan not found (package clamav) – the tray entry stays disabled."))
        cl.addWidget(QLabel("Paths to scan, one per line:"))
        self.paths = QPlainTextEdit("\n".join(s.binary_scan_paths))
        cl.addWidget(self.paths)
        row = QHBoxLayout()
        en = QPushButton("Set up regular clamd scan (weekly)")
        dis = QPushButton("Remove regular scan")
        en.clicked.connect(self._sched_on)
        dis.clicked.connect(self._sched_off)
        en.setEnabled(clamd.available())
        row.addWidget(en)
        row.addWidget(dis)
        cl.addLayout(row)
        root.addWidget(clam)

        self.autostart = QCheckBox("Start automatically at login")
        self.autostart.setChecked(s.autostart)
        root.addWidget(self.autostart)

        self.auto_update = QCheckBox("Check GitHub Releases for app updates and install them (signed releases only)")
        self.auto_update.setChecked(s.auto_update)
        root.addWidget(self.auto_update)

        self.keep = QSpinBox()
        self.keep.setRange(10, 5000)
        self.keep.setValue(s.history_keep)
        self.keep.setPrefix("Keep the last ")
        self.keep.setSuffix(" scans in the history")
        root.addWidget(self.keep)

        self.confirm_rm = QCheckBox("Ask before removing packages (recommended)")
        self.confirm_rm.setChecked(s.confirm_before_remove)
        root.addWidget(self.confirm_rm)

        bb = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        root.addWidget(bb)

    @staticmethod
    def _cb(text: str, val: bool, form: QFormLayout) -> QCheckBox:
        c = QCheckBox(text)
        c.setChecked(val)
        form.addRow(c)
        return c

    @staticmethod
    def _backend(layout: QVBoxLayout, text: str, val: bool, scanner) -> QCheckBox:
        ok = scanner.available()
        c = QCheckBox(text if ok else f"{text} – will be fetched on first scan if possible")
        c.setChecked(val)
        layout.addWidget(c)
        return c

    def _paths(self) -> list[str]:
        return [p.strip() for p in self.paths.toPlainText().splitlines() if p.strip()]

    def _sched_on(self) -> None:
        ok, out = clamd_schedule.enable(self._paths())
        QMessageBox.information(self, "Regular clamd scan", "Enabled (systemd user timer)." if ok else out)

    def _sched_off(self) -> None:
        ok, out = clamd_schedule.disable()
        QMessageBox.information(self, "Regular clamd scan", "Removed." if ok else out)

    def result_settings(self) -> Settings:
        s = self.s
        s.mode = self.mode.currentData()
        s.interval_minutes = self.interval.value()
        s.scan_on_start = self.on_start.isChecked()
        s.scan_after_pkg_changes = self.after_pkg.isChecked()
        s.update_sources_before_scan = self.update_src.isChecked()
        s.skip_in_gaming_mode = self.gaming.isChecked()
        s.skip_on_battery = self.battery.isChecked()
        s.notify_when_clean = self.clean_note.isChecked()
        s.use_aur_malware_check = self.b_amc.isChecked()
        s.use_aur_scan = self.b_scan.isChecked()
        s.use_builtin_list = self.b_list.isChecked()
        s.binary_scan_paths = self._paths()
        s.autostart = self.autostart.isChecked()
        s.history_keep = self.keep.value()
        s.auto_update = self.auto_update.isChecked()
        s.confirm_before_remove = self.confirm_rm.isChecked()
        s.validate()
        return s
