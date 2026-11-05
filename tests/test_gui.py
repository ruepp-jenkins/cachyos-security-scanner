"""Qt smoke tests, run headless (QT_QPA_PLATFORM=offscreen). Skipped when PySide6 or its system libraries are missing.

They exist because pure-logic tests cannot see wiring bugs, e.g. a widget attribute that shadows a Qt signal.
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QCoreApplication, QEvent, QThreadPool, Qt
    from PySide6.QtWidgets import QAbstractItemView, QApplication, QDialog, QDialogButtonBox, QPushButton
    HAVE_QT = True
except ImportError:
    HAVE_QT = False

if HAVE_QT:
    from cachy_sec import app as appmod, engine, history, ignores, notify, settings as st
    from cachy_sec.findings_dialog import FindingsDialog
    from cachy_sec.history_dialog import HistoryDialog
    from cachy_sec.options_dialog import OptionsDialog
    from cachy_sec.settings_dialog import SettingsDialog
    from cachy_sec.scanners import aur_malware_check, aur_scan, blocklist
    from cachy_sec.scanners.base import CLEAN, WARNING, Finding, ScanResult


def pump(until, limit=10.0):
    end = time.time() + limit
    while not until() and time.time() < end:
        QCoreApplication.processEvents()
        time.sleep(0.01)


@unittest.skipUnless(HAVE_QT, "PySide6 (and its system libraries) not available")
class GuiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qapp = QApplication.instance() or QApplication([])

    @classmethod
    def tearDownClass(cls):
        cls.qapp.processEvents()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": t + "/cfg", "XDG_DATA_HOME": t + "/data",
                                           "XDG_CACHE_HOME": t + "/cache", "XDG_RUNTIME_DIR": t, "HOME": t})
        env.start()
        self._trays = []
        self._loose = []
        self.addCleanup(self._cleanup_qt)
        self.ran = []
        ran = self.ran

        class FakeAur(aur_scan.AurScan):
            def available(self): return True
            def update(self): pass
            def scan(self): ran.append("aur_scan"); return ScanResult("aur_scan", CLEAN)

        class FakeAmc(aur_malware_check.AurMalwareCheck):
            def available(self): return True
            def update(self): pass
            def scan(self): ran.append("aur_malware_check"); return ScanResult("aur_malware_check", CLEAN)

        class FakeBl(blocklist.CommunityBlocklist):
            def scan(self): ran.append("blocklist"); return ScanResult("blocklist", CLEAN)

        for p in (env,
                  mock.patch.object(engine, "AurScan", FakeAur), mock.patch.object(engine, "AurMalwareCheck", FakeAmc),
                  mock.patch.object(engine, "CommunityBlocklist", FakeBl),
                  mock.patch.object(notify, "notify"), mock.patch.object(appmod.Tray, "refresh_lists")):
            if p is not env:
                p.start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(self.tmp.cleanup)

    def _tray(self):
        tray = appmod.Tray(self.qapp)
        self._trays.append(tray)
        return tray

    def _track(self, dlg):
        """Register a dialog the test created itself, so it is torn down in order."""
        self._loose.append(dlg)
        return dlg

    def _cleanup_qt(self):
        """Tear Qt objects down in order; leaving them to interpreter shutdown can crash the process at exit."""
        QThreadPool.globalInstance().waitForDone(3000)
        for dlg in self._loose:
            if getattr(dlg, "timer", None) is not None:  # HistoryDialog polls
                dlg.timer.stop()
            dlg.close()
            dlg.deleteLater()
        self._loose.clear()
        for tray in self._trays:
            for name in ("timer", "debounce", "upd_timer", "restart_timer", "lists_timer"):
                getattr(tray, name).stop()
            for dlg in (tray.settings_dlg, tray.history_dlg, *tray._dialogs):
                if dlg is not None:
                    dlg.close()
                    dlg.deleteLater()
            tray.tray.hide()
            tray.tray.deleteLater()
            tray.menu.deleteLater()
            tray.deleteLater()
        self._trays.clear()
        for _ in range(3):
            QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
            QCoreApplication.processEvents()

    def test_unticking_a_scanner_is_saved_applied_and_survives_a_restart(self):
        st.Settings(scan_periodic=False, scan_on_start=False, scan_after_pkg_changes=False, use_aur_scan=True).save()
        tray = self._tray()
        tray.open_settings()
        dlg = tray.settings_dlg
        self.assertTrue(dlg.b_scan.isChecked())
        dlg.b_scan.setChecked(False)
        dlg.findChild(QDialogButtonBox).button(QDialogButtonBox.Save).click()
        pump(lambda: tray.settings_dlg is None, 3)
        self.assertFalse(tray.settings.use_aur_scan)  # applied in memory
        self.assertFalse(json.loads(Path(st.config_path()).read_text())["use_aur_scan"])  # and on disk
        tray.scan(manual=True)
        pump(lambda: not tray.busy and tray.last_report is not None)
        self.assertNotIn("aur_scan", self.ran)  # the disabled scanner does not run
        tray2 = self._tray()  # "restart"
        self.assertFalse(tray2.settings.use_aur_scan)
        tray2.open_settings()
        self.assertFalse(tray2.settings_dlg.b_scan.isChecked())
        tray2.settings_dlg.reject()

    def test_settings_window_opens_once_and_cancel_saves_nothing(self):
        st.Settings(scan_periodic=False, scan_on_start=False, scan_after_pkg_changes=False, use_aur_scan=True).save()
        tray = self._tray()
        tray.open_settings()
        first = tray.settings_dlg
        tray.open_settings()  # second request: same window
        self.assertIs(tray.settings_dlg, first)
        first.b_scan.setChecked(False)
        first.reject()
        pump(lambda: tray.settings_dlg is None, 3)
        self.assertTrue(tray.settings.use_aur_scan)
        self.assertTrue(json.loads(Path(st.config_path()).read_text())["use_aur_scan"])

    def test_pending_restart_waits_only_for_visible_windows_and_scans(self):
        tray = self._tray()
        exits = []
        with mock.patch.object(appmod.QApplication, "exit", side_effect=exits.append), \
             mock.patch.object(appmod.updater, "supervised", return_value=True):
            tray.pending_version = "9.9.9"
            # a settings window that was created but never shown (or already closed) must not block the restart
            tray.settings_dlg = self._track(SettingsDialog(st.Settings()))
            self.assertIsNone(tray._restart_blocker())
            # a visible window does
            tray.settings_dlg.show()
            self.assertIn("window", tray._restart_blocker())
            tray._restart_if_idle()
            self.assertEqual(exits, [])
            self.assertIn("waiting", tray.act_restart.text())  # the tray entry says why
            tray.settings_dlg.hide()
            # a running scan does too
            tray.busy = True
            self.assertEqual(tray._restart_blocker(), "a scan is running")
            tray._restart_if_idle()
            self.assertEqual(exits, [])
            tray.busy = False
            tray._restart_if_idle()
            self.assertEqual(exits, [75])  # idle: restart requested
            tray.settings_dlg = None

    def test_a_failing_scan_does_not_leave_the_app_busy(self):
        tray = self._tray()
        with mock.patch.object(engine, "run_scan", side_effect=RuntimeError("boom")):
            tray.scan(manual=True)
            pump(lambda: not tray.busy, 5)
        self.assertFalse(tray.busy)  # otherwise no scan could ever run again and no restart could happen
        self.assertIn("internal error", tray.last_report.summary())

    def test_closed_windows_are_forgotten(self):
        from PySide6.QtWidgets import QMessageBox
        tray = self._tray()
        box = QMessageBox()
        box.setAttribute(appmod.Qt.WA_DeleteOnClose)
        tray._track_dialog(box)
        box.show()  # windows the user can see are the ones that matter
        self.assertEqual(len(tray._dialogs), 1)
        box.close()
        pump(lambda: not tray._dialogs, 3)
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        pump(lambda: not tray._dialogs, 3)
        self.assertEqual(tray._dialogs, [])

    def test_settings_window_fits_the_screen_and_scrolls(self):
        from PySide6.QtGui import QGuiApplication
        from PySide6.QtWidgets import QScrollArea
        d = self._track(SettingsDialog(st.Settings()))
        d.show()
        QCoreApplication.processEvents()
        avail = QGuiApplication.primaryScreen().availableGeometry()
        self.assertLessEqual(d.height(), avail.height())  # not taller than the screen (e.g. a Full-HD laptop)
        self.assertLessEqual(d.width(), avail.width())
        scroll = d.findChild(QScrollArea)
        self.assertIsNotNone(scroll)
        self.assertGreater(scroll.verticalScrollBar().maximum(), 0)  # the options really are reachable by scrolling
        buttons = d.findChild(QDialogButtonBox)
        self.assertFalse(scroll.isAncestorOf(buttons))  # Save/Cancel/Help stay visible outside the scroll area
        self.assertTrue(buttons.isVisible())

    def test_help_button_opens_the_settings_reference(self):
        d = self._track(SettingsDialog(st.Settings()))
        help_btn = d.findChild(QDialogButtonBox).button(QDialogButtonBox.Help)
        self.assertIsNotNone(help_btn)
        with mock.patch("cachy_sec.settings_dialog.QDesktopServices.openUrl") as open_url:
            help_btn.click()
        url = open_url.call_args[0][0].toString()
        self.assertTrue(url.startswith("https://github.com/ruepp-jenkins/cachyos-security-scanner/"))
        self.assertTrue(url.endswith("/docs/settings.md"))

    def test_scanner_options_dialog_validates_and_returns_the_values(self):
        for which in ("amc", "aur_scan", "clamd"):
            d = OptionsDialog(which, st.Settings())
            self.assertEqual(d.error.text(), "")
            self.assertTrue(d.preview.text())
        d = OptionsDialog("clamd", st.Settings())
        d.extra.setText("--remove")
        self.assertNotEqual(d.error.text(), "")
        d._ok()
        self.assertEqual(d.result(), 0)  # stays open, nothing accepted
        d.paths_edit.setPlainText("/usr/bin\n\n  ~/bin  \n")
        d.extra.setText("--config-file=/etc/clamav/clamd.conf")
        d.widgets["binary_multiscan"].setChecked(True)
        self.assertEqual(d.error.text(), "")
        d._ok()
        r = d.result_settings()
        self.assertTrue(r.binary_multiscan)
        self.assertEqual(r.binary_extra_args, "--config-file=/etc/clamav/clamd.conf")
        self.assertEqual(r.binary_scan_paths, ["/usr/bin", "~/bin"])  # blank lines and spaces dropped
        d._reset()
        self.assertEqual(d.paths_edit.toPlainText().splitlines(), st.DEFAULT_BINARY_PATHS)
        a = OptionsDialog("aur_scan", st.Settings())
        a.widgets["aur_scan_fail_on"].setCurrentText("low")
        a._ok()
        self.assertEqual(a.result_settings().aur_scan_fail_on, "low")
        a._reset()
        self.assertEqual(a.widgets["aur_scan_fail_on"].currentText(), "high")

    def test_a_newer_trigger_cancels_the_running_binary_scan_and_restarts_it(self):
        from cachy_sec.scanners import clamd
        tray = self._tray()
        started = []
        with mock.patch.object(clamd, "available", return_value=True), \
                mock.patch.object(clamd, "cancel_background", return_value=True) as cancel, \
                mock.patch.object(clamd, "run_background", side_effect=lambda *a: started.append(a[2]) or ("clean", "ok")):
            tray.binary_busy = True  # a scan is running
            tray.auto_binary_scan("interval", periodic=True)  # the interval trigger just waits
            cancel.assert_not_called()
            tray.auto_binary_scan("package change")  # an event trigger cancels it
            cancel.assert_called_once()
            self.assertEqual(tray._binary_next, ("package change", False))
            tray._binary_finished("cancelled", "cancelled")  # the cancelled scan ends -> the new one starts
            self.assertTrue(tray.binary_busy)
            pump(lambda: bool(started))
            self.assertEqual(started, ["package change"])
            QThreadPool.globalInstance().waitForDone(3000)

    def test_tray_shows_the_scanning_icon_while_any_scan_runs(self):
        tray = self._tray()
        tray._idle_tip = "CachyOS Security Scanner – all clear"
        tray._refresh_tray()
        self.assertEqual(tray.tray.toolTip(), "CachyOS Security Scanner – all clear")
        tray.busy = True
        tray._refresh_tray()
        self.assertIn("scanning", tray.tray.toolTip())
        tray.busy = False
        tray.binary_busy = True
        tray._refresh_tray()
        self.assertIn("binary scan running", tray.tray.toolTip())
        tray.binary_busy = False
        tray._refresh_tray()
        self.assertEqual(tray.tray.toolTip(), "CachyOS Security Scanner – all clear")

    def test_dialogs_do_not_shadow_qt_attributes(self):
        finding = Finding(WARNING, "t", "s", package="p", version="1-1", rules=[("X-1", "title", 1)])
        dialogs = [self._track(SettingsDialog(st.Settings())), self._track(HistoryDialog()), self._track(OptionsDialog("clamd", st.Settings())),
                   self._track(FindingsDialog("sum", [finding], [], lambda p: None, "", lambda *a: None))]
        for d in dialogs:
            # PySide caches accessed signals in the instance dict; only our own attributes count
            shadowed = [k for k, v in vars(d).items() if hasattr(QDialog, k) and type(v).__name__ != "SignalInstance"]
            self.assertEqual(shadowed, [], f"{type(d).__name__} overrides Qt attributes {shadowed}")

    def test_findings_dialog_has_an_ignore_button_per_entry(self):
        f = Finding(WARNING, "p 1-1: 2 issues", "aur-scan", package="p", version="1-1",
                    rules=[("DEEP-001", "Decode", 1), ("DEEP-003", "Bidi", 1)], codes=["DEEP-001", "DEEP-003"])
        calls, changed = [], []
        d = self._track(FindingsDialog("2 findings", [f], [], lambda p: None, "", lambda *a: calls.append(a),
                                       lambda: changed.append(1)))
        buttons = [b for b in d.findChildren(QPushButton) if b.text() == "Ignore"]
        self.assertEqual(len(buttons), 2)
        buttons[0].click()
        self.assertEqual(calls, [("p", "1-1", ["DEEP-001"])])  # only that entry
        self.assertFalse(buttons[0].isEnabled())
        self.assertTrue(buttons[1].isEnabled())
        d.close()
        self.assertEqual(changed, [1])  # one re-scan, after closing

    def test_every_entry_has_its_own_open_files_button_and_there_is_no_global_one(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            (Path(a) / "PKGBUILD").write_text("x")
            (Path(b) / "PKGBUILD").write_text("x")
            f1 = Finding(WARNING, "one 1-1: 1 issue", "aur-scan", package="one", version="1-1", codes=["DEEP-001"],
                         rules=[("DEEP-001", "Decode", 1)], files=[f"{a}/PKGBUILD"], rule_files={"DEEP-001": [f"{a}/PKGBUILD"]})
            f2 = Finding(WARNING, "two 2-2: 1 issue", "aur-scan", package="two", version="", codes=["DEEP-003"],
                         rules=[("DEEP-003", "Bidi", 1)], files=[f"{b}/PKGBUILD"], rule_files={"DEEP-003": [f"{b}/PKGBUILD"]})
            f3 = Finding(WARNING, "gone 1-1: 1 issue", "aur-scan", package="gone", version="1-1", codes=["X-1"],
                         rules=[("X-1", "T", 1)], files=["/does/not/exist/PKGBUILD"], rule_files={"X-1": ["/does/not/exist/PKGBUILD"]})
            d = self._track(FindingsDialog("3 findings", [f1, f2, f3], [], lambda p: None, "codium", lambda *x: None))
            opens = [x for x in d.findChildren(QPushButton) if x.text() in ("Open files", "Open files…")]
            self.assertEqual([x.text() for x in opens], ["Open files"] * 3)  # one per entry, no global "Open files…"
            self.assertEqual([x.isEnabled() for x in opens], [True, True, False])  # a vanished folder disables its button
            ignores_ = [x for x in d.findChildren(QPushButton) if x.text() == "Ignore"]
            self.assertEqual([x.isEnabled() for x in ignores_], [True, False, True])  # unknown version: cannot be ignored
            with mock.patch("cachy_sec.findings_dialog.opener.open_directory", return_value=(True, "codium")) as op:
                opens[1].click()
                opens[0].click()
            self.assertEqual([c.args for c in op.call_args_list], [(Path(b), "codium"), (Path(a), "codium")])

    def test_history_viewer_keeps_the_selection_when_new_entries_arrive(self):
        for i, name in enumerate(("a", "b")):
            history.record(engine.Report([ScanResult(name, CLEAN)]), "manual", time.time() - 100 + i * 10, 1)
        d = self._track(HistoryDialog())
        d.table.selectRow(1)
        QCoreApplication.processEvents()
        chosen = d.selected
        history.record(engine.Report([ScanResult("c", CLEAN)]), "manual", time.time(), 1)
        d.reload()
        self.assertEqual(d.selected, chosen)
        row = d.table.selectionModel().selectedRows()[0].row()
        self.assertEqual(Path(d.table.item(row, 0).data(Qt.UserRole)), chosen)

    def test_history_viewer_filter_threat_checkbox_and_single_selection(self):
        from cachy_sec.scanners.base import CRITICAL, Finding
        history.record(engine.Report([ScanResult("alpha", CLEAN)]), "manual", time.time() - 50, 1)
        bad = ScanResult("beta", CRITICAL, findings=[Finding(CRITICAL, "evil", "beta", package="superpkg", detail="superpkg")])
        history.record(engine.Report([bad]), "manual", time.time(), 1)
        d = self._track(HistoryDialog())
        self.assertEqual(d.table.rowCount(), 2)
        self.assertEqual(d.table.selectionMode(), QAbstractItemView.SingleSelection)
        d.filter_edit.setText("superpkg")  # only present in the scan details
        self.assertEqual(d.table.rowCount(), 1)
        d.filter_edit.setText("")
        d.only_threats.setChecked(True)
        self.assertEqual(d.table.rowCount(), 1)
        self.assertEqual(d.table.item(0, 0).toolTip(), "critical")


    def test_interval_edit_round_trips_and_picks_the_largest_exact_unit(self):
        from cachy_sec.settings_dialog import IntervalEdit
        for minutes, shown in ((360, (6, "hours")), (7 * 24 * 60, (1, "weeks")), (90, (90, "minutes")), (2 * 1440, (2, "days"))):
            w = IntervalEdit(minutes, 15, 52 * 7 * 24 * 60)
            self.assertEqual((w.amount.value(), w.unit.currentText()), shown)
            self.assertEqual(w.minutes(), minutes)
            w.deleteLater()

    def test_refresh_lists_button_updates_the_status_lines(self):
        d = self._track(SettingsDialog(st.Settings()))
        d._lists_refreshed({"community blocklist": (True, "updated"), "false-positive list": (False, "HTTP Error 404")})
        self.assertTrue(d.refresh_btn.isEnabled())
        self.assertIn("community blocklist: updated", d.refresh_result.text())
        self.assertIn("false-positive list: FAILED – HTTP Error 404", d.refresh_result.text())

    def test_report_buttons_are_tinted(self):
        from cachy_sec.report_dialog import ReportDialog
        d = self._track(ReportDialog())
        self.assertIn("46, 160, 67", d.buttons[0].styleSheet())
        self.assertIn("218, 54, 51", d.buttons[1].styleSheet())
        self.assertEqual(d.buttons[2].styleSheet(), "")

    def test_report_dialog_offers_three_reports(self):
        from cachy_sec.report_dialog import ReportDialog
        d = self._track(ReportDialog())
        self.assertEqual([b.text() for b in d.buttons], ["False positive", "Malicious package", "Program error"])
        d.show()
        with mock.patch("cachy_sec.report_dialog.QDesktopServices.openUrl", return_value=True) as op:
            d.buttons[2].click()
        self.assertIn("template=bug.yml", op.call_args[0][0].toString())
        self.assertTrue(d.isVisible(), "the window stays open after opening the form")
        with mock.patch("cachy_sec.report_dialog.QDesktopServices.openUrl", return_value=False):
            d.buttons[0].click()
        self.assertIn("template=false-positive.yml", d.status.text())  # no browser: the link is shown instead
        self.assertGreaterEqual(d.width(), 600)

    def test_settings_dialog_saves_the_schedule_options(self):
        d = self._track(SettingsDialog(st.Settings()))
        d.periodic.setChecked(True)
        d.interval.amount.setValue(2)
        d.interval.unit.setCurrentIndex(d.interval.unit.findText("days"))
        d.b_with.setChecked(True)
        d.b_periodic.setChecked(True)
        d.b_interval.amount.setValue(3)
        d.b_interval.unit.setCurrentIndex(d.b_interval.unit.findText("days"))
        d.start_delay.setValue(5)
        d.b_low.setChecked(False)
        r = d.result_settings()
        self.assertEqual((r.interval_minutes, r.binary_interval_minutes), (2880, 4320))
        self.assertTrue(r.binary_with_aur_scans and r.binary_periodic and not r.binary_low_priority)
        self.assertEqual(r.startup_delay_minutes, 5)

    def test_binary_options_are_disabled_without_clamdscan(self):
        from unittest import mock as m
        with m.patch("cachy_sec.settings_dialog.clamd.available", return_value=False):
            d = self._track(SettingsDialog(st.Settings(binary_on_start=True)))
        for w in (d.b_options, d.b_start, d.b_pkg, d.b_with, d.b_periodic, d.b_interval, d.b_low):
            self.assertFalse(w.isEnabled())
        self.assertTrue(d.result_settings().binary_on_start)  # the saved value survives

    def test_select_latest_jumps_to_the_matching_entry_and_clears_filters(self):
        from cachy_sec.scanners.base import CRITICAL, Finding
        bad = ScanResult("beta", CRITICAL, findings=[Finding(CRITICAL, "evil", "beta", package="p")])
        history.record(engine.Report([bad]), "manual", time.time() - 100, 1)
        history.record(engine.Report([ScanResult("alpha", CLEAN)]), "manual", time.time(), 1)  # newer, clean
        d = self._track(HistoryDialog())
        d.filter_edit.setText("zzz-nothing")
        self.assertEqual(d.table.rowCount(), 0)
        d.select_latest(None, ("warning", "critical"))
        self.assertEqual(d.filter_edit.text(), "")
        sel = d.table.selectionModel().selectedRows()
        self.assertEqual(len(sel), 1)
        self.assertEqual(d.table.item(sel[0].row(), 0).toolTip(), "critical")
        self.assertIn("evil", d.log.toPlainText())

if __name__ == "__main__":
    unittest.main()
