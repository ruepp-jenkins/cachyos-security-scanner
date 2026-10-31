"""Qt tray application."""
from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import Qt, QFileSystemWatcher, QObject, QRunnable, QThreadPool, QTimer, Signal
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QApplication, QMenu, QMessageBox, QSystemTrayIcon

import time

from . import autostart, engine, history, notify, remove, scheduler, updater
from .scanners import clamd
from .settings import Settings
from .history_dialog import HistoryDialog
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
        self.rm_done = _Done()
        self.rm_done.emit_report.connect(self._removed)
        self._dialogs: list = []
        self.dialog_open = False  # modal settings dialog

        icon = QIcon.fromTheme("security-high", QIcon.fromTheme("dialog-information"))
        self.tray = QSystemTrayIcon(icon, app)
        self.tray.setToolTip("CachyOS Security Scanner")
        self.menu = QMenu()
        self.act_scan = self.menu.addAction("Check for compromised packages now", lambda: self.scan(manual=True))
        self.act_clam = self.menu.addAction("Scan binaries with ClamAV (clamd)", self.scan_binaries)
        self.act_last = self.menu.addAction("No scan yet")
        self.act_last.setEnabled(False)
        self.menu.addAction("Scan history…", self.open_history)
        self.menu.addSeparator()
        self.act_update = self.menu.addAction("Check for app updates", lambda: self.check_update(manual=True))
        self.act_restart = self.menu.addAction("Restart to apply update", self._restart)
        self.act_restart.setVisible(False)
        self.menu.addAction("Settings…", self.open_settings)
        self.act_version = self.menu.addAction(f"Version {updater.describe_version()}")
        self.act_version.setEnabled(False)
        self.menu.addAction("Quit", app.quit)
        self.menu.aboutToShow.connect(self._refresh_menu)
        self.tray.setContextMenu(self.menu)
        self.tray.show()

        self.timer = QTimer(self)
        self.timer.timeout.connect(lambda: self.scan(manual=False, trigger="interval"))
        self.debounce = QTimer(self)
        self.debounce.setSingleShot(True)
        self.debounce.timeout.connect(lambda: self.scan(manual=False, trigger="package change"))
        self.watcher = QFileSystemWatcher(self)
        self.watcher.fileChanged.connect(self._pkg_changed)
        self.watcher.directoryChanged.connect(self._pkg_changed)
        self.upd_sig = _UpdateSignal()
        self.upd_sig.result.connect(self._update_done)
        self.upd_manual = False
        self.restart_timer = QTimer(self)
        self.restart_timer.timeout.connect(self._restart_if_idle)
        self.upd_timer = QTimer(self)
        self.upd_timer.timeout.connect(lambda: self.check_update(manual=False))
        self.upd_timer.start(24 * 3600 * 1000)
        QTimer.singleShot(30_000, lambda: self.check_update(manual=False))
        self._apply_settings()
        autostart.apply(self.settings.autostart)
        if scheduler.scan_at_startup(self.settings):
            QTimer.singleShot(5000, lambda: self.scan(manual=False, trigger="startup"))

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
            if updater.supervised():
                notify.notify("Security scanner updated", f"Version {msg} was installed and is applied automatically as soon as nothing is running.")
                self.restart_timer.start(5000)
            else:  # started directly (e.g. from source): no supervisor that could relaunch us
                notify.notify("Security scanner updated", f"Version {msg} was installed. Restart the app to use it.")
        elif self.upd_manual:
            notify.notify("Update check", msg if state == "current" else f"Update failed: {msg}")

    def _restart_if_idle(self) -> None:
        """Apply a pending update once no package scan, dialog or removal would be interrupted."""
        if self.busy or self._dialogs or self.dialog_open:
            return
        self.restart_timer.stop()
        self._restart()

    def _restart(self) -> None:
        if updater.supervised():
            QApplication.exit(updater.RESTART_EXIT_CODE)
        else:
            notify.notify("Restart needed", "Please start the app again to use the new version.")

    def _refresh_menu(self) -> None:
        ok = clamd.available()
        self.act_clam.setEnabled(ok)
        self.act_clam.setText("Scan binaries with ClamAV (clamd)" if ok else "Scan binaries with ClamAV (clamdscan not installed)")

    def _pkg_changed(self, _path: str) -> None:
        if scheduler.scan_after_pkg_change(self.settings):
            self.debounce.start(DEBOUNCE_MS)  # coalesce multi-step upgrades
        if TRIGGER.exists() and str(TRIGGER) not in self.watcher.files():
            self.watcher.addPath(str(TRIGGER))

    def scan(self, manual: bool, trigger: str = "manual") -> None:
        if self.busy:  # only the package scan itself is serialised; binary scans and updates run independently
            if manual:
                notify.notify("Security scan", "A package scan is already running; the result will follow.")
            return
        self.busy = True
        self.tray.setToolTip("Scanning…")
        s = self.settings

        def job():
            started = time.time()
            report = engine.run_scan(s, manual=manual)
            history.record(report, trigger, started, time.time() - started, s.history_keep)
            return report, manual

        self.pool.start(_Job(job, self.done))

    def scan_binaries(self) -> None:
        """Open a terminal showing the live clamdscan output; everything else is up to the user."""
        ok, msg = clamd.launch(self.settings.binary_scan_paths)
        if not ok:
            notify.notify("Binary scan not started", msg)

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
        """Non-modal: the dialog never blocks the tray, other scans or update checks."""
        pkgs = engine.infected_packages(report)
        box = QMessageBox(QMessageBox.Warning, "Possible compromise", report.summary())
        box.setAttribute(Qt.WA_DeleteOnClose)
        box.setDetailedText("\n".join(f"[{f.severity}] {f.source}: {f.title}" for f in report.findings))
        rm = box.addButton("Remove packages…", QMessageBox.DestructiveRole) if pkgs else None
        box.addButton("Close", QMessageBox.RejectRole)
        box.buttonClicked.connect(lambda b: self._remove_clicked(b is rm, pkgs))
        self._dialogs.append(box)  # keep a reference while open
        box.destroyed.connect(lambda *_: self._dialogs.remove(box) if box in self._dialogs else None)
        box.open()

    def _remove_clicked(self, clicked: bool, pkgs: list[str]) -> None:
        if not clicked:
            return
        if self.settings.confirm_before_remove:
            q = QMessageBox(QMessageBox.Question, "Remove packages", "Remove with pacman -Rns?\n\n" + "\n".join(pkgs),
                            QMessageBox.Yes | QMessageBox.No)
            q.setAttribute(Qt.WA_DeleteOnClose)
            q.finished.connect(lambda r: self._do_remove(pkgs) if r == QMessageBox.Yes else None)
            self._dialogs.append(q)
            q.open()
        else:
            self._do_remove(pkgs)

    def _do_remove(self, pkgs: list[str]) -> None:
        self.pool.start(_Job(lambda: (remove.remove_packages(pkgs), False), self.rm_done))

    def _removed(self, result, _manual) -> None:
        done, out = result
        notify.notify("Package removal", "Done." if done else f"Failed: {out}", urgent=not done)

    def open_history(self) -> None:
        dlg = HistoryDialog()
        dlg.setAttribute(Qt.WA_DeleteOnClose)
        self._dialogs.append(dlg)
        dlg.destroyed.connect(lambda *_: self._dialogs.remove(dlg) if dlg in self._dialogs else None)
        dlg.show()

    def open_settings(self) -> None:
        dlg = SettingsDialog(self.settings)
        self.dialog_open = True
        accepted = dlg.exec()
        self.dialog_open = False
        if accepted:
            self.settings = dlg.result_settings()
            self.settings.save()
            self._apply_settings()
            autostart.apply(self.settings.autostart)


def main() -> int:
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setApplicationName("cachy-security-scanner")
    for _ in range(60):  # right after login the panel may not be up yet: wait up to ~60 s
        if QSystemTrayIcon.isSystemTrayAvailable():
            break
        time.sleep(1)
        app.processEvents()
    else:
        print("No system tray available", file=sys.stderr)
        return 1
    tray = Tray(app)  # noqa: F841 - keep reference
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
