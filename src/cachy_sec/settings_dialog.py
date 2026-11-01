"""Settings dialog."""
from __future__ import annotations

import copy
import time

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication, QIcon
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QGroupBox, QLineEdit, QListWidget,
                               QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit, QPushButton, QSpinBox,
                               QScrollArea, QVBoxLayout, QWidget)

from . import blocklist, clamd_schedule, fplist, icons, ignores, updater
from .scanners import clamd
from .scanners.aur_malware_check import AurMalwareCheck
from .scanners.aur_scan import AurScan
from .scanners.blocklist import CommunityBlocklist
from .settings import Settings, config_path




UNITS = (("minutes", 1), ("hours", 60), ("days", 24 * 60), ("weeks", 7 * 24 * 60))


class IntervalEdit(QWidget):
    """A number plus a unit (minutes / hours / days / weeks); the value is exposed in minutes."""

    def __init__(self, minutes: int, min_minutes: int, max_minutes: int) -> None:
        super().__init__()
        self.min_minutes, self.max_minutes = min_minutes, max_minutes
        self.amount = QSpinBox()
        self.amount.setRange(1, 100_000)
        self.unit = QComboBox()
        for name, mult in UNITS:
            self.unit.addItem(name, mult)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.amount)
        lay.addWidget(self.unit)
        lay.addStretch()
        self.set_minutes(minutes)

    def set_minutes(self, minutes: int) -> None:
        minutes = max(self.min_minutes, minutes)
        idx = max((i for i, (_, m) in enumerate(UNITS) if minutes % m == 0), default=0)  # largest unit that fits exactly
        self.unit.setCurrentIndex(idx)
        self.amount.setValue(minutes // UNITS[idx][1])

    def minutes(self) -> int:
        return max(self.min_minutes, min(self.max_minutes, self.amount.value() * self.unit.currentData()))


class SettingsDialog(QDialog):
    def __init__(self, s: Settings) -> None:
        super().__init__()
        self.setWindowTitle("CachyOS Security Scanner – Settings")
        self.setWindowIcon(QIcon(icons.path(icons.APP)))
        self.s = copy.deepcopy(s)
        # The options are long: they live in a scroll area, while Save/Cancel/Help stay visible at the bottom.
        outer = QVBoxLayout(self)
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QScrollArea.NoFrame)
        content = QWidget()
        self.scroll_area.setWidget(content)
        outer.addWidget(self.scroll_area, 1)
        root = QVBoxLayout(content)

        when = QGroupBox("When to scan AUR packages (manual scans always work)")
        f = QFormLayout(when)
        self.on_start = self._cb("Scan at start", s.scan_on_start, f)
        self.start_delay = QSpinBox()
        self.start_delay.setRange(0, 120)
        self.start_delay.setSuffix(" min")
        self.start_delay.setValue(s.startup_delay_minutes)
        self.start_delay.setToolTip("Wait this long after the app started, so the desktop can finish starting first.")
        f.addRow("    Delay after start", self.start_delay)
        self.after_pkg = self._cb("Scan after package installs/updates (needs pacman hook)", s.scan_after_pkg_changes, f)
        self.pkg_delay = QSpinBox()
        self.pkg_delay.setRange(5, 3600)
        self.pkg_delay.setSuffix(" s")
        self.pkg_delay.setValue(s.pkg_change_delay_seconds)
        self.pkg_delay.setToolTip("Wait this long after the last package change, so a multi-step upgrade gives one scan.")
        f.addRow("    Wait after the last change", self.pkg_delay)
        self.pkg_gap = QSpinBox()
        self.pkg_gap.setRange(0, 24 * 60)
        self.pkg_gap.setSuffix(" min")
        self.pkg_gap.setValue(s.pkg_scan_min_gap_minutes)
        self.pkg_gap.setToolTip("At most one package-change scan per this time, however often you install packages. 0 = no limit.")
        f.addRow("    At most one scan per", self.pkg_gap)
        self.periodic = self._cb("Scan at regular intervals", s.scan_periodic, f)
        self.interval = IntervalEdit(s.interval_minutes, 15, 52 * 7 * 24 * 60)
        f.addRow("    Every", self.interval)
        self.periodic.toggled.connect(self.interval.setEnabled)
        self.interval.setEnabled(s.scan_periodic)
        self.update_src = self._cb("Update scanner sources before each scan", s.update_sources_before_scan, f)
        self.gaming = self._cb("Skip automatic scans in gaming mode (gamemode, gamescope, Steam)", s.skip_in_gaming_mode, f)
        self.battery = self._cb("Skip automatic scans on battery", s.skip_on_battery, f)
        self.low_prio = self._cb("Run scans with low priority (nice / ionice)", s.low_priority_scans, f)
        self.low_prio.setToolTip("Scanners, their updates and builds run with the lowest CPU and I/O priority, so they do not\n"
                                 "slow down your work or games. Scans may take a bit longer.")
        self.clean_note = self._cb("Also notify when nothing was found", s.notify_when_clean, f)
        root.addWidget(when)

        back = QGroupBox("AUR scanners")
        bl = QVBoxLayout(back)
        self.b_amc = self._backend(bl, "aur-malware-check (lenucksi)", s.use_aur_malware_check, AurMalwareCheck())
        self.b_scan = self._backend(bl, "aur-scan (ks-aur-scanner) – heuristic, can produce false positives; only enable if you know what it does", s.use_aur_scan, AurScan())
        # belongs to aur-scan: indented below it and only usable while aur-scan is enabled
        self.b_fp = QCheckBox("Community false-positive list")
        self.b_fp.setChecked(s.use_false_positive_list)
        self.b_fp.setToolTip("Signed list of known false positives for specific software versions, maintained in the project's\n"
                             "GitHub repository. It only hides the listed findings for the listed versions. On by default;\n"
                             "untick it if you do not trust the list. Every hidden finding is noted in the scan log.")
        self.fp_status = QLabel(fplist.status())
        self.fp_status.setEnabled(False)  # greyed hint text
        fp_col = QVBoxLayout()
        fp_col.setContentsMargins(24, 0, 0, 0)
        fp_col.setSpacing(0)
        fp_col.addWidget(self.b_fp)
        fp_col.addWidget(self.fp_status)
        bl.addLayout(fp_col)
        self.b_scan.toggled.connect(self.b_fp.setEnabled)
        self.b_scan.toggled.connect(lambda on: self.fp_status.setVisible(on))
        self.b_fp.setEnabled(self.b_scan.isChecked())
        self.fp_status.setVisible(self.b_scan.isChecked())
        self.b_list = self._backend(bl, "Community blocklist (known malicious AUR packages)", s.use_community_blocklist, CommunityBlocklist())
        self.b_list.setToolTip("Signed list of known malicious or compromised AUR packages, maintained in the project's GitHub\n"
                               "repository. Installed packages are matched by name and version.")
        self.bl_status = QLabel(blocklist.status())
        self.bl_status.setEnabled(False)
        bl_col = QHBoxLayout()
        bl_col.setContentsMargins(24, 0, 0, 0)
        bl_col.addWidget(self.bl_status)
        bl.addLayout(bl_col)
        bl.addWidget(QLabel("aur-scan: findings to ignore, one per line (rule code like SCAN-001, a package name, or package:CODE):"))
        self.ignored = QPlainTextEdit("\n".join(s.ignored_findings))
        self.ignored.setMaximumHeight(70)
        bl.addWidget(self.ignored)
        bl.addWidget(QLabel("Accepted findings (bound to the software version; reported again after an update):"))
        self.accepted_list = QListWidget()
        self.accepted_list.setMaximumHeight(80)
        bl.addWidget(self.accepted_list)
        rev = QPushButton("Revoke selected")
        rev.clicked.connect(self._revoke)
        bl.addWidget(rev)
        self._load_accepted()
        bl.addWidget(QLabel("Scanner repositories are cloned and updated automatically before scans."))
        root.addWidget(back)

        clam = QGroupBox("Binary scan with ClamAV (clamdscan)")
        cl = QVBoxLayout(clam)
        if not clamd.available():
            hint = QLabel("clamdscan not found. Install the package clamav (sudo pacman -S clamav) and start the daemon "
                          "(sudo systemctl enable --now clamav-daemon) to use binary scans. The options below are disabled until then.")
            hint.setWordWrap(True)
            cl.addWidget(hint)
        cl.addWidget(QLabel("Paths to scan, one per line:"))
        self.paths = QPlainTextEdit("\n".join(s.binary_scan_paths))
        self.paths.setMaximumHeight(110)
        cl.addWidget(self.paths)
        cl.addWidget(QLabel("The tray menu starts a scan on request in a terminal window. Optionally it also runs by itself,\n"
                            "in the background (the result goes to the scan history):"))
        cf = QFormLayout()
        cl.addLayout(cf)
        self.b_start = self._cb("Scan binaries at start", s.binary_on_start, cf)
        self.b_pkg = self._cb("Scan binaries after package installs/updates", s.binary_after_pkg_changes, cf)
        self.b_with = self._cb("Scan binaries together with every AUR package scan", s.binary_with_aur_scans, cf)
        self.b_periodic = self._cb("Scan binaries at regular intervals", s.binary_periodic, cf)
        self.b_interval = IntervalEdit(s.binary_interval_minutes, 60, 52 * 7 * 24 * 60)
        cf.addRow("    Every", self.b_interval)
        self.b_periodic.toggled.connect(self.b_interval.setEnabled)
        self.b_interval.setEnabled(s.binary_periodic)
        self.b_gap = QSpinBox()
        self.b_gap.setRange(0, 24 * 90)
        self.b_gap.setSuffix(" h")
        self.b_gap.setValue(s.binary_min_gap_hours)
        self.b_gap.setToolTip("Applies to the start, package change and package scan triggers, so a binary scan does not run\n"
                              "after every pacman update. The interval above is not limited by it. 0 = no limit.")
        cf.addRow("    At most one scan per (except interval)", self.b_gap)
        self.b_low = self._cb("Run binary scans with low priority (nice / ionice)", s.binary_low_priority, cf)
        self.b_low.setToolTip("Lowers the priority of the clamdscan client. The scanning itself is done by the clamd daemon,\n"
                              "whose priority is set by its own service (systemctl edit clamav-daemon: Nice=, IOSchedulingClass=).")
        if not clamd.available():  # keep the saved values, just make them unreachable
            for w in (self.paths, self.b_start, self.b_pkg, self.b_with, self.b_periodic, self.b_interval, self.b_gap, self.b_low):
                w.setEnabled(False)
        else:
            self.b_interval.setEnabled(s.binary_periodic)
        last = clamd.last_scan_time()
        when_txt = time.strftime("%Y-%m-%d %H:%M", time.localtime(last)) if last else "never"
        self.b_last = QLabel(f"Last binary scan started: {when_txt}. Automatic binary scans skip gaming mode / battery like the others.")
        self.b_last.setEnabled(False)
        cl.addWidget(self.b_last)
        if clamd_schedule.is_enabled():  # leftover of an earlier version: a systemd timer outside this app
            old = QPushButton("Remove the old systemd timer (cachy-sec-clamd)")
            old.clicked.connect(lambda: (self._sched_off(), old.hide()))
            cl.addWidget(old)
        root.addWidget(clam)

        ed = QHBoxLayout()
        ed.addWidget(QLabel("Editor for \"Open files\" (empty = auto: codium, code, … or file manager):"))
        self.editor = QLineEdit(s.editor_command)
        self.editor.setPlaceholderText("e.g. codium")
        ed.addWidget(self.editor, 1)
        root.addLayout(ed)

        self.autostart = QCheckBox("Start automatically at login")
        self.autostart.setChecked(s.autostart)
        root.addWidget(self.autostart)

        self.auto_update = QCheckBox("Check for app updates automatically and install them (signed GitHub releases only)")
        self.auto_update.setToolTip("Off: no automatic check. The tray entry \"Check for app updates\" still works and asks before it installs.")
        self.auto_update.setChecked(s.auto_update)
        root.addWidget(self.auto_update)

        self.keep = QSpinBox()
        self.keep.setRange(10, 5000)
        self.keep.setValue(s.history_keep)
        self.keep.setPrefix("Keep the last ")
        self.keep.setSuffix(" history entries (one per scanner and scan)")
        root.addWidget(self.keep)

        self.confirm_rm = QCheckBox("Ask before removing packages (recommended)")
        self.confirm_rm.setChecked(s.confirm_before_remove)
        root.addWidget(self.confirm_rm)

        v = updater.describe_version()
        ver = QLabel(f"CachyOS Security Scanner – {v if v.startswith('development') else 'version ' + v}\nSettings file: {config_path()}")
        ver.setTextInteractionFlags(Qt.TextSelectableByMouse)
        root.addWidget(ver)

        bb = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel | QDialogButtonBox.Help)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        bb.helpRequested.connect(self.open_help)
        outer.addWidget(bb)
        self._fit_to_screen()

    def _fit_to_screen(self) -> None:
        """Open at the natural size, but never taller or wider than the screen (the rest is reachable by scrolling)."""
        screen = QGuiApplication.primaryScreen()
        content = self.scroll_area.widget().sizeHint()
        bar = self.scroll_area.verticalScrollBar().sizeHint().width()
        want_w, want_h = content.width() + bar + 24, content.height() + 70  # 70: button row and margins
        if screen is None:
            self.resize(want_w, want_h)
            return
        avail = screen.availableGeometry()
        self.resize(min(want_w, int(avail.width() * 0.9)), min(want_h, int(avail.height() * 0.85)))

    def open_help(self) -> None:
        """Open the settings reference of the running version (tag) in the browser."""
        QDesktopServices.openUrl(QUrl(updater.docs_url("settings.md")))  # the page of this version's tag

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

    def _load_accepted(self) -> None:
        self.accepted_list.clear()
        self._entries = ignores.load()
        for e in self._entries:
            self.accepted_list.addItem(e.label())

    def _revoke(self) -> None:
        row = self.accepted_list.currentRow()
        if row >= 0:
            e = self._entries[row]
            ignores.remove(e.package, e.version)  # applied immediately, independent of "Save"
            self._load_accepted()

    def _paths(self) -> list[str]:
        return [p.strip() for p in self.paths.toPlainText().splitlines() if p.strip()]

    def _sched_off(self) -> None:
        ok, out = clamd_schedule.disable()
        QMessageBox.information(self, "Regular clamd scan", "Removed." if ok else out)

    def result_settings(self) -> Settings:
        s = self.s
        s.scan_on_start = self.on_start.isChecked()
        s.startup_delay_minutes = self.start_delay.value()
        s.scan_after_pkg_changes = self.after_pkg.isChecked()
        s.pkg_change_delay_seconds = self.pkg_delay.value()
        s.pkg_scan_min_gap_minutes = self.pkg_gap.value()
        s.scan_periodic = self.periodic.isChecked()
        s.interval_minutes = self.interval.minutes()
        s.binary_on_start = self.b_start.isChecked()
        s.binary_after_pkg_changes = self.b_pkg.isChecked()
        s.binary_with_aur_scans = self.b_with.isChecked()
        s.binary_periodic = self.b_periodic.isChecked()
        s.binary_interval_minutes = self.b_interval.minutes()
        s.binary_min_gap_hours = self.b_gap.value()
        s.binary_low_priority = self.b_low.isChecked()
        s.update_sources_before_scan = self.update_src.isChecked()
        s.skip_in_gaming_mode = self.gaming.isChecked()
        s.skip_on_battery = self.battery.isChecked()
        s.low_priority_scans = self.low_prio.isChecked()
        s.notify_when_clean = self.clean_note.isChecked()
        s.use_aur_malware_check = self.b_amc.isChecked()
        s.use_aur_scan = self.b_scan.isChecked()
        s.use_community_blocklist = self.b_list.isChecked()
        s.use_false_positive_list = self.b_fp.isChecked()
        s.ignored_findings = [x.strip() for x in self.ignored.toPlainText().splitlines() if x.strip()]
        s.binary_scan_paths = self._paths()
        s.editor_command = self.editor.text().strip()
        s.autostart = self.autostart.isChecked()
        s.history_keep = self.keep.value()
        s.auto_update = self.auto_update.isChecked()
        s.confirm_before_remove = self.confirm_rm.isChecked()
        s.validate()
        return s
