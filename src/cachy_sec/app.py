"""Qt tray application."""
from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QFileSystemWatcher, QObject, QRunnable, QThreadPool, QTimer, Signal
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QApplication, QMenu, QMessageBox, QSystemTrayIcon

from . import engine, notify, remove, scheduler, updater
from .scanners import clamui
from .settings import Settings
from .settings_dialog import SettingsDialog

TRIGGER = Path("/var/lib/cachy-security-scanner/trigger")  # touched by the pacman hook
DEBOUNCE_MS = 30_000


class _Job(QRunnable):
    def __init__(self, fn, done) -> None:
        super().__init__()
        self.fn, self.done = fn, done

    def run(self) -> None:
        self.done.emit(self.fn())


class _Done(QObject):
    emit_report = Signal(object, bool)

    def emit(self, payload) -> None:  # noqa: A003
        self.emit_report.emit(*payload)


class _UpdateJob(QRunnable):
    def __init__(self, sig) -> None:
        super().__init__()
        self.sig = sig

    def run(self) -> None:
        self.sig.emit(*updater.check_and_install())


class _UpdateSignal(QObject):
    result = Signal(str, str)

    def emit(self, state: str, msg: str) -> None:  # noqa: A003
        self.result.emit(state, msg)


class Tray(QObject):
    def __init__(self, app: QApplication) -> None:
        super().__init__()
        self.settings = Settings.load()
        self.busy = False
        self.last_report: engine.Report | None = None
        self.pool = QThreadPool.globalInstance()
        self.done = _Done()
        self.done.emit_report.connect(self._finished)

        icon = QIcon.fromTheme("security-high", QIcon.fromTheme("dialog-information"))
        self.tray = QSystemTrayIcon(icon, app)
        self.tray.setToolTip("CachyOS Security Scanner")
        self.menu = QMenu()
        self.act_scan = self.menu.addAction("Check for compromised packages now", lambda: self.scan(manual=True))
        self.act_clam = self.menu.addAction("Scan binaries with ClamUI", self.scan_clamui)
        self.act_last = self.menu.addAction("No scan yet")
        self.act_last.setEnabled(False)
        self.menu.addSeparator()
        self.act_update = self.menu.addAction("Check for app updates", lambda: self.check_update(manual=True))
        self.act_restart = self.menu.addAction("Restart to apply update", lambda: QApplication.exit(updater.RESTART_EXIT_CODE))
        self.act_restart.setVisible(False)
        self.menu.addAction("Settings…", self.open_settings)
        self.menu.addAction("Quit", app.quit)
        self.menu.aboutToShow.connect(self._refresh_menu)
        self.tray.setContextMenu(self.menu)
        self.tray.show()

        self.timer = QTimer(self)
        self.timer.timeout.connect(lambda: self.scan(manual=False))
        self.debounce = QTimer(self)
        self.debounce.setSingleShot(True)
        self.debounce.timeout.connect(lambda: self.scan(manual=False))
        self.watcher = QFileSystemWatcher(self)
        self.watcher.fileChanged.connect(self._pkg_changed)
        self.watcher.directoryChanged.connect(self._pkg_changed)
        self.upd_sig = _UpdateSignal()
        self.upd_sig.result.connect(self._update_done)
        self.upd_manual = False
        self.upd_timer = QTimer(self)
        self.upd_timer.timeout.connect(lambda: self.check_update(manual=False))
        self.upd_timer.start(24 * 3600 * 1000)
        QTimer.singleShot(30_000, lambda: self.check_update(manual=False))
        self._apply_settings()
        if scheduler.scan_at_startup(self.settings):
            QTimer.singleShot(5000, lambda: self.scan(manual=False))

    def _apply_settings(self) -> None:
        ms = scheduler.interval_ms(self.settings)
        self.timer.stop()
        if ms:
            self.timer.start(ms)
        for p in (TRIGGER, TRIGGER.parent):
            if p.exists() and str(p) not in self.watcher.files() + self.watcher.directories():
                self.watcher.addPath(str(p))

    def check_update(self, manual: bool) -> None:
        if not (manual or self.settings.auto_update):
            return
        self.upd_manual = manual
        self.pool.start(_UpdateJob(self.upd_sig))

    def _update_done(self, state: str, msg: str) -> None:
        if state == "installed":
            self.act_restart.setText(f"Restart to apply update {msg}")
            self.act_restart.setVisible(True)
            notify.notify("Security scanner updated", f"Version {msg} was installed. Restart from the tray menu to use it.")
        elif self.upd_manual:
            notify.notify("Update check", msg if state == "current" else f"Update failed: {msg}")

    def _refresh_menu(self) -> None:
        ok = clamui.available()
        self.act_clam.setEnabled(ok and not self.busy)
        self.act_clam.setText("Scan binaries with ClamUI" if ok else "Scan binaries with ClamUI (ClamUI not installed)")
        self.act_scan.setEnabled(not self.busy)

    def _pkg_changed(self, _path: str) -> None:
        if scheduler.scan_after_pkg_change(self.settings):
            self.debounce.start(DEBOUNCE_MS)  # coalesce multi-step upgrades
        if TRIGGER.exists() and str(TRIGGER) not in self.watcher.files():
            self.watcher.addPath(str(TRIGGER))

    def scan(self, manual: bool) -> None:
        if self.busy:
            return
        self.busy = True
        self.tray.setToolTip("Scanning…")
        s = self.settings
        self.pool.start(_Job(lambda: (engine.run_scan(s, manual=manual), manual), self.done))

    def scan_clamui(self) -> None:
        if self.busy:
            return
        self.busy = True
        self.tray.setToolTip("ClamUI scan running…")
        s = self.settings
        self.pool.start(_Job(lambda: (engine.run_clamui_scan(s), True), self.done))

    def _finished(self, report: engine.Report, manual: bool) -> None:
        self.busy = False
        self.last_report = report
        text = report.summary()
        self.tray.setToolTip(f"CachyOS Security Scanner – {text}")
        self.act_last.setText(text[:80])
        if report.findings:
            notify.notify("Security scanner: possible compromise", text, urgent=True)
            self.tray.setIcon(QIcon.fromTheme("dialog-warning"))
            self._offer_removal(report)
        else:
            self.tray.setIcon(QIcon.fromTheme("security-high", QIcon.fromTheme("dialog-information")))
            if manual or self.settings.notify_when_clean:
                notify.notify("Security scan finished", text)

    def _offer_removal(self, report: engine.Report) -> None:
        pkgs = engine.infected_packages(report)
        box = QMessageBox(QMessageBox.Warning, "Possible compromise", report.summary())
        box.setDetailedText("\n".join(f"[{f.severity}] {f.source}: {f.title}" for f in report.findings))
        rm = box.addButton("Remove packages…", QMessageBox.DestructiveRole) if pkgs else None
        box.addButton("Close", QMessageBox.RejectRole)
        box.exec()
        if rm is not None and box.clickedButton() is rm:
            ok = QMessageBox.Yes if not self.settings.confirm_before_remove else QMessageBox.question(
                None, "Remove packages", "Remove with pacman -Rns?\n\n" + "\n".join(pkgs))
            if ok == QMessageBox.Yes:
                done, out = remove.remove_packages(pkgs)
                QMessageBox.information(None, "Removal", "Done." if done else f"Failed:\n{out}")

    def open_settings(self) -> None:
        dlg = SettingsDialog(self.settings)
        if dlg.exec():
            self.settings = dlg.result_settings()
            self.settings.save()
            self._apply_settings()


def main() -> int:
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setApplicationName("cachy-security-scanner")
    if not QSystemTrayIcon.isSystemTrayAvailable():
        print("No system tray available", file=sys.stderr)
        return 1
    tray = Tray(app)  # noqa: F841 - keep reference
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
