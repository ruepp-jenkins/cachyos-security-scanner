"""Qt tray application."""
from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import Qt, QFileSystemWatcher, QObject, QRunnable, QThreadPool, QTimer, Signal
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import QApplication, QMenu, QMessageBox, QSystemTrayIcon

import time

from . import autostart, engine, history, icons, ignores, notify, remove, scheduler, singleton, updater
from .scanners import clamd
from .scanners.base import ERROR, ScanResult
from .settings import Settings
from .findings_dialog import FindingsDialog
from .history_dialog import HistoryDialog
from .settings_dialog import SettingsDialog

TRIGGER = Path("/var/lib/cachy-security-scanner/trigger")  # touched by the pacman hook
RESTART_POLL_MS = 5_000


class _Job(QRunnable):
    def __init__(self, fn, done, on_error=None) -> None:
        super().__init__()
        self.fn, self.done, self.on_error = fn, done, on_error

    def run(self) -> None:
        try:
            payload = self.fn()
        except Exception as e:  # noqa: BLE001 - without a result the app would stay "busy" and never restart
            if self.on_error is None:
                raise
            payload = self.on_error(e)
        self.done.emit(payload)


class _Done(QObject):
    emit_report = Signal(object, bool)

    def emit(self, payload) -> None:  # noqa: A003
        self.emit_report.emit(*payload)


class _UpdateJob(QRunnable):
    def __init__(self, sig, check_only: bool = False) -> None:
        super().__init__()
        self.sig, self.check_only = sig, check_only

    def run(self) -> None:
        self.sig.emit(*(updater.check_available() if self.check_only else updater.check_and_install()))


class _ClickSignal(QObject):
    clicked = Signal(str)  # which history entry to select; emitted from the notification helper thread


# What a click on a notification selects in the scan history: (entry kind or None for any, accepted statuses)
SELECTORS = {"threat": (None, ("warning", "critical")), "error": (None, ("error",)),
             "binary-threat": ("binaries", ("critical",)), "binary-error": ("binaries", ("error",))}


class _BinaryDone(QObject):
    finished = Signal(str, str)

    def emit(self, payload) -> None:  # noqa: A003
        self.finished.emit(*payload)


class _ListsJob(QRunnable):
    def __init__(self, settings, then_scan: bool, sig) -> None:
        super().__init__()
        self.settings, self.then_scan, self.sig = settings, then_scan, sig

    def run(self) -> None:
        engine.refresh_lists(self.settings)
        self.sig.done.emit(self.then_scan)


class _ListsSignal(QObject):
    done = Signal(bool)


class _UpdateSignal(QObject):
    result = Signal(str, str)

    def emit(self, state: str, msg: str) -> None:  # noqa: A003
        self.result.emit(state, msg)


class Tray(QObject):
    def __init__(self, app: QApplication) -> None:
        super().__init__()
        self.settings = Settings.load()
        self.busy = False
        self.binary_busy = False
        self._last_binary_error = ""
        self._last_scan_end: float | None = None  # time.monotonic() of the last finished package scan
        self.rescan_pending = False
        self._unsaved = False  # True while the last settings save failed
        self.pending_version, self._restart_waited, self._restart_hinted = "", 0, False
        self.last_report: engine.Report | None = None
        self.pool = QThreadPool.globalInstance()
        self.done = _Done()
        self.done.emit_report.connect(self._finished)
        self.rm_done = _Done()
        self.rm_done.emit_report.connect(self._removed)
        self._dialogs: list = []
        self._findings_dialogs: list = []  # open findings windows, to mark them outdated by a newer scan
        self.history_dlg = None  # single-instance windows; findings dialogs may be many
        self.settings_dlg = None

        app.setWindowIcon(QIcon(icons.path(icons.APP)))
        self.tray = QSystemTrayIcon(QIcon(icons.path(icons.APP)), app)
        self.tray.setToolTip("CachyOS Security Scanner")
        self.menu = QMenu()
        self.act_scan = self.menu.addAction("Check for compromised packages now", lambda: self.scan(manual=True))
        self.act_clam = self.menu.addAction("Scan binaries with ClamAV (clamd)", self.scan_binaries)
        self.menu.addAction("Scan history…", self.open_history)
        self.menu.addSeparator()
        self.act_update = self.menu.addAction("Check for app updates", lambda: self.check_update(manual=True))
        self.act_restart = self.menu.addAction("Restart to apply update", self._restart)
        self.act_restart.setVisible(False)
        self.menu.addAction("Settings…", self.open_settings)
        self.menu.addAction("Quit", app.quit)
        self.menu.aboutToShow.connect(self._refresh_menu)
        self.tray.setContextMenu(self.menu)
        self.tray.activated.connect(self._tray_activated)
        self.tray.show()

        self.timer = QTimer(self)
        self.timer.timeout.connect(lambda: self.scan(manual=False, trigger="interval"))
        self.debounce = QTimer(self)
        self.debounce.setSingleShot(True)
        self.debounce.timeout.connect(self._pkg_scan_due)
        self.watcher = QFileSystemWatcher(self)
        self.watcher.fileChanged.connect(self._pkg_changed)
        self.watcher.directoryChanged.connect(self._pkg_changed)
        self.upd_sig = _UpdateSignal()
        self.upd_sig.result.connect(self._update_done)
        self.upd_manual = False
        self._update_running = False  # one update job at a time: two installs would write the same folder
        self.restart_timer = QTimer(self)
        self.restart_timer.timeout.connect(self._restart_if_idle)
        self.upd_timer = QTimer(self)
        self.upd_timer.timeout.connect(lambda: self.check_update(manual=False))
        self.upd_timer.start(24 * 3600 * 1000)
        QTimer.singleShot(30_000, lambda: self.check_update(manual=False))
        self.click_sig = _ClickSignal()
        self.click_sig.clicked.connect(lambda target: self.open_history(select=target))
        self.bin_done = _BinaryDone()
        self.bin_done.finished.connect(self._binary_finished)
        self.bin_timer = QTimer(self)  # periodic binary scans: polled, so a weekly interval survives restarts
        self.bin_timer.timeout.connect(self._binary_poll)
        self.bin_timer.start(10 * 60_000)
        QTimer.singleShot((self.settings.startup_delay_minutes + 5) * 60_000, self._binary_poll)  # not before the start scans
        self._apply_settings()
        autostart.apply(self.settings.autostart)
        # Community lists: downloaded at start (the startup scan waits for them), then re-checked hourly and
        # re-downloaded when older than signedlist.STALE_AFTER_S. Scans themselves never trigger a download.
        self.lists_sig = _ListsSignal()
        self.lists_sig.done.connect(self._lists_done)
        self.lists_timer = QTimer(self)
        self.lists_timer.timeout.connect(lambda: self.refresh_lists(False))
        self.lists_timer.start(3600 * 1000)
        QTimer.singleShot(3000, lambda: self.refresh_lists(scheduler.scan_at_startup(self.settings)
                                                           or scheduler.binary_at_startup(self.settings)))

    def _reload_settings(self) -> None:
        """The saved file is the source of truth (another instance or an earlier run may have changed it),
        unless the last save failed: then the in-memory settings are what the user chose."""
        if not self._unsaved:
            fresh = Settings.load_existing()
            if fresh is not None:
                self.settings = fresh

    def refresh_lists(self, then_scan: bool = False) -> None:
        self.pool.start(_ListsJob(self.settings, then_scan, self.lists_sig))

    def _lists_done(self, then_scan: bool) -> None:
        if then_scan:  # the lists are fresh now; give the desktop a moment to finish starting before the load begins
            QTimer.singleShot(self.settings.startup_delay_minutes * 60_000, self._startup_scans)

    def _startup_scans(self) -> None:
        self._reload_settings()
        if scheduler.scan_at_startup(self.settings):
            self.scan(manual=False, trigger="startup")
        if scheduler.binary_at_startup(self.settings):
            self.auto_binary_scan("startup")

    def _pkg_scan_due(self) -> None:
        self._reload_settings()
        if scheduler.scan_after_pkg_change(self.settings):
            self.scan(manual=False, trigger="package change")
        if self.settings.binary_after_pkg_changes:
            self.auto_binary_scan("package change")

    def _binary_poll(self) -> None:
        self._reload_settings()
        if scheduler.binary_due(self.settings, clamd.seconds_since_last_success(), clamd.seconds_since_last_scan()):
            self.auto_binary_scan("interval", periodic=True)

    def auto_binary_scan(self, trigger: str, periodic: bool = False) -> None:
        """Scheduled binary scan in the background; the log goes to the history. Respects gaming/battery skips and,
        for event-driven triggers, the minimum gap between binary scans."""
        s = self.settings
        if self.binary_busy or not clamd.available():
            return
        if engine.skip_reason(s, manual=False):
            return
        if not periodic and not scheduler.binary_gap_ok(s, clamd.seconds_since_last_scan()):
            return
        self.binary_busy = True
        paths, low = list(s.binary_scan_paths), s.binary_low_priority
        self.pool.start(_Job(lambda: clamd.run_background(paths, low, trigger), self.bin_done,
                             lambda e: ("error", f"internal error: {e}")))

    def _binary_finished(self, state: str, msg: str) -> None:
        self.binary_busy = False
        if state in ("clean", "threats"):
            self._last_binary_error = ""
        if state == "threats":
            self.tray.setIcon(QIcon(icons.for_status("critical")))
            self.tray.setToolTip(f"CachyOS Security Scanner – {msg}")
            notify.notify("Binary scan: threats found", msg, kind="bad", urgent=True, on_click=self._click_to("binary-threat"))
        elif state in ("error", "unavailable"):
            if msg != self._last_binary_error:  # the same failure is reported once, not at every retry
                notify.notify("Binary scan did not run", msg, kind="bad", on_click=self._click_to("binary-error"))
            self._last_binary_error = msg
        elif self.settings.notify_when_clean:
            notify.notify("Binary scan finished", msg, kind="good")

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
        if self._update_running:
            return
        self._update_running = True
        self.upd_manual = manual
        # With automatic updates off, a manual check only looks and asks before installing anything.
        self.pool.start(_UpdateJob(self.upd_sig, check_only=not self.settings.auto_update))

    def _offer_update(self, version: str) -> None:
        box = QMessageBox(QMessageBox.Question, "Update available",
                          f"Version {version} is available (installed: {updater.effective_version()}).\n\nInstall it now?",
                          QMessageBox.Yes | QMessageBox.No)
        box.setWindowIcon(QIcon(icons.path(icons.APP)))
        box.setAttribute(Qt.WA_DeleteOnClose)
        box.setDefaultButton(QMessageBox.Yes)
        self._track_dialog(box)

        def answered(result: int) -> None:
            if result == QMessageBox.Yes.value:
                if self._update_running:
                    return
                self._update_running = True
                self.upd_manual = True
                self.pool.start(_UpdateJob(self.upd_sig))

        box.finished.connect(answered)
        box.show()

    def _update_done(self, state: str, msg: str) -> None:
        self._update_running = False
        if state == "available":
            self._offer_update(msg)
        elif state == "installed":
            self.act_restart.setText(f"Restart to apply update {msg}")
            self.act_restart.setVisible(True)
            if updater.supervised():
                notify.notify("Security scanner updated", f"Version {msg} was installed and is applied automatically as soon as nothing is running.", kind="good")
                self.pending_version, self._restart_waited, self._restart_hinted = msg, 0, False
                self.restart_timer.start(RESTART_POLL_MS)
            else:  # started directly (e.g. from source): no supervisor that could relaunch us
                notify.notify("Security scanner updated", f"Version {msg} was installed. Restart the app to use it.", kind="good")
        elif self.upd_manual:
            notify.notify("Update check", msg if state == "current" else f"Update failed: {msg}",
                          kind="good" if state == "current" else "bad")

    def _track_dialog(self, dlg) -> None:
        """Remember an open window (it delays an automatic restart) and forget it when it is gone."""
        self._dialogs.append(dlg)
        dlg.destroyed.connect(lambda *_: dlg in self._dialogs and self._dialogs.remove(dlg))

    def _restart_blocker(self) -> str | None:
        """Why an automatic restart must wait right now, or None if nothing would be interrupted."""
        if self.busy or self.binary_busy:
            return "a scan is running"
        for d in [self.settings_dlg, *self._dialogs]:
            try:
                if d is not None and d.isVisible():
                    return f"the window \"{d.windowTitle()}\" is open"
            except RuntimeError:  # the C++ window is already gone
                continue
        return None

    def _restart_if_idle(self) -> None:
        """Apply a pending update once no package scan or open window would be interrupted."""
        reason = self._restart_blocker()
        label = f"Restart to apply update {self.pending_version}"
        if reason:
            self.act_restart.setText(f"{label} (waiting: {reason})")
            self._restart_waited += RESTART_POLL_MS
            if not self._restart_hinted and self._restart_waited >= 60_000:
                self._restart_hinted = True  # say once why nothing happens
                notify.notify("Update waiting", f"The update is installed but the restart waits because {reason}. "
                              "Close it, or use \"Restart to apply update\" in the tray menu.", kind="info")
            return
        self.restart_timer.stop()
        self._restart()

    def _restart(self) -> None:
        if updater.supervised():
            QApplication.exit(updater.RESTART_EXIT_CODE)
        else:
            notify.notify("Restart needed", "Please start the app again to use the new version.", kind="info")

    def _tray_activated(self, reason) -> None:
        if reason == QSystemTrayIcon.Trigger:  # plain left click
            self.open_history()

    def _refresh_menu(self) -> None:
        ok = clamd.available()
        self.act_clam.setEnabled(ok)
        self.act_clam.setText("Scan binaries with ClamAV (clamd)" if ok else "Scan binaries with ClamAV (clamdscan not installed)")

    def _pkg_changed(self, _path: str) -> None:
        if scheduler.anything_after_pkg_change(self.settings):
            since = None  # the package-scan gap applies only to package scans, not to binary-after-package-change
            if scheduler.scan_after_pkg_change(self.settings) and self._last_scan_end is not None:
                since = time.monotonic() - self._last_scan_end
            self.debounce.start(scheduler.pkg_delay_ms(self.settings, since))  # coalesce multi-step upgrades
        if TRIGGER.exists() and str(TRIGGER) not in self.watcher.files():
            self.watcher.addPath(str(TRIGGER))

    def scan(self, manual: bool, trigger: str = "manual") -> None:
        if self.busy:  # only the package scan itself is serialised; binary scans and updates run independently
            if manual:
                notify.notify("Security scan", "A package scan is already running; the result will follow.")
            elif trigger == "package change":
                self.rescan_pending = True  # packages changed mid-scan: scan again afterwards instead of dropping it
            return
        self.busy = True
        self.tray.setToolTip("Scanning…")
        self._reload_settings()
        s = self.settings

        def job():
            started = time.time()
            report = engine.run_scan(s, manual=manual)
            history.record(report, trigger, started, time.time() - started, s.history_keep)
            return report, manual

        def failed(e: Exception):
            import traceback
            r = ScanResult("internal", ERROR, [], f"internal error: {e}", log=traceback.format_exc())
            return engine.Report([r]), manual

        self.pool.start(_Job(job, self.done, failed))

    def scan_binaries(self) -> None:
        """Open a terminal showing the live clamdscan output; everything else is up to the user."""
        ok, msg = clamd.launch(self.settings.binary_scan_paths)
        if not ok:
            notify.notify("Binary scan not started", msg, kind="bad")

    def _finished(self, report: engine.Report, manual: bool) -> None:
        self.busy = False
        self.last_report = report
        if not report.skipped:
            self._last_scan_end = time.monotonic()
            if self.settings.binary_with_aur_scans:
                self.auto_binary_scan("with package scan")
        if self.rescan_pending:
            self.rescan_pending = False
            if scheduler.anything_after_pkg_change(self.settings):  # same wait and gap as any package-change scan
                self.debounce.start(scheduler.pkg_delay_ms(self.settings, 0.0))
        for old in list(self._findings_dialogs):
            old.mark_outdated()
        text = report.summary()
        self.tray.setToolTip(f"CachyOS Security Scanner – {text}")
        st = report.icon_status
        if st:  # a skipped scan leaves the previous icon, so an earlier finding stays visible
            self.tray.setIcon(QIcon(icons.for_status(st)))
        if report.findings:
            notify.notify("Security scanner: possible compromise", text, kind="bad", urgent=True, on_click=self._click_to("threat"))
            self._offer_removal(report, f"{time.strftime('%H:%M')}, {'manual' if manual else 'automatic'} scan")
        else:
            if manual or self.settings.notify_when_clean or report.kind == "bad":
                notify.notify("Security scan finished", text, kind=report.kind, urgent=report.kind == "bad",
                              on_click=self._click_to("error") if report.kind == "bad" else None)

    def _offer_removal(self, report: engine.Report, scan_info: str = "") -> None:
        """Non-modal: the dialog never blocks the tray, other scans or update checks."""
        box = FindingsDialog(report.summary(), report.findings, engine.infected_packages(report), self._remove_clicked,
                             self.settings.editor_command, self._ignore_finding,
                             lambda: self.scan(manual=True, trigger="after ignore"), scan_info, report.notes)
        box.setAttribute(Qt.WA_DeleteOnClose)
        self._track_dialog(box)  # keeps a reference while open and delays an automatic restart
        self._findings_dialogs.append(box)
        box.destroyed.connect(lambda *_: box in self._findings_dialogs and self._findings_dialogs.remove(box))
        box.show()

    def _ignore_finding(self, package: str, version: str, codes: list[str]) -> None:
        try:
            ignores.add(package, version, codes)
        except (ValueError, OSError) as e:
            notify.notify("Ignore failed", str(e), kind="bad")
            return
        notify.notify("Finding ignored", f"{package} {version}: {', '.join(codes)} – reported again after an update.", kind="info")
        # the re-scan (tray state, history) runs once when the findings window is closed

    def _remove_clicked(self, pkgs: list[str]) -> None:
        if self.settings.confirm_before_remove:
            q = QMessageBox(QMessageBox.Question, "Remove packages", "Remove with pacman -Rns?\n\n" + "\n".join(pkgs),
                            QMessageBox.Yes | QMessageBox.No)
            q.setAttribute(Qt.WA_DeleteOnClose)
            q.finished.connect(lambda r: self._do_remove(pkgs) if r == QMessageBox.Yes else None)
            self._track_dialog(q)
            q.open()
        else:
            self._do_remove(pkgs)

    def _do_remove(self, pkgs: list[str]) -> None:
        self.pool.start(_Job(lambda: (remove.remove_packages(pkgs), False), self.rm_done,
                             lambda e: ((False, f"internal error: {e}"), False)))

    def _removed(self, result, _manual) -> None:
        done, out = result
        notify.notify("Package removal", "Done." if done else f"Failed: {out}", kind="good" if done else "bad", urgent=not done)
        if done:  # re-check right away so the tray reflects the fix instead of staying red
            self.scan(manual=True, trigger="after removal")

    @staticmethod
    def _focus(dlg) -> None:
        dlg.showNormal()  # un-minimise
        dlg.raise_()
        dlg.activateWindow()

    def _click_to(self, target: str):
        """Callback for notify(): a click opens the scan history with the newest matching entry selected."""
        return lambda: self.click_sig.clicked.emit(target)

    def open_history(self, select: str | None = None) -> None:
        """At most one history window: a second request just brings the existing one to the front.

        select: a key of SELECTORS; the newest matching entry is selected so the cause is visible at once."""
        if self.history_dlg is not None:
            self._focus(self.history_dlg)
        else:
            dlg = self.history_dlg = HistoryDialog()
            dlg.setAttribute(Qt.WA_DeleteOnClose)
            self._track_dialog(dlg)
            dlg.destroyed.connect(lambda *_: setattr(self, "history_dlg", None))
            dlg.show()
        if select in SELECTORS:
            self.history_dlg.select_latest(*SELECTORS[select])

    def open_settings(self) -> None:
        """At most one settings window (non-modal, so the tray stays usable)."""
        if self.settings_dlg is not None:
            self._focus(self.settings_dlg)
            return
        self._reload_settings()  # never show (and then re-save) a stale in-memory state
        dlg = SettingsDialog(self.settings)
        dlg.accepted.connect(lambda: self._settings_saved(dlg))  # read the values before the dialog is deleted
        dlg.finished.connect(lambda _: (setattr(self, "settings_dlg", None), dlg.deleteLater()))
        self.settings_dlg = dlg  # only after the wiring worked: a half-built window must never be "the" settings window
        dlg.show()

    def _settings_saved(self, dlg) -> None:
        self.settings = dlg.result_settings()
        try:
            self.settings.save()
            self._unsaved = False
        except OSError as e:  # e.g. read-only or foreign-owned config dir: say so instead of failing silently
            self._unsaved = True
            notify.notify("Settings could not be saved", f"{e}\nThe changes only apply until the app is restarted.",
                          kind="bad", urgent=True)
        self._apply_settings()
        autostart.apply(self.settings.autostart)
        self.refresh_lists(False)  # e.g. a list was just switched on: fetch it now (no-op while the cache is fresh)


def main() -> int:
    if singleton.acquire() is None:
        print("CachyOS Security Scanner is already running.", file=sys.stderr)
        notify.notify("Security scanner", "Already running – look for its icon in the system tray.", kind="info")
        return 0
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
