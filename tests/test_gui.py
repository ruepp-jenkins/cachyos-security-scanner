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
    from PySide6.QtCore import QCoreApplication, QEvent, QThreadPool
    from PySide6.QtWidgets import QApplication, QDialog, QDialogButtonBox, QPushButton
    HAVE_QT = True
except ImportError:
    HAVE_QT = False

if HAVE_QT:
    from cachy_sec import app as appmod, engine, history, ignores, notify, settings as st
    from cachy_sec.findings_dialog import FindingsDialog
    from cachy_sec.history_dialog import HistoryDialog
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
        st.Settings(mode="manual", scan_on_start=False, use_aur_scan=True).save()
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
        st.Settings(mode="manual", scan_on_start=False, use_aur_scan=True).save()
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

    def test_dialogs_do_not_shadow_qt_attributes(self):
        finding = Finding(WARNING, "t", "s", package="p", version="1-1", rules=[("X-1", "title", 1)])
        dialogs = [self._track(SettingsDialog(st.Settings())), self._track(HistoryDialog()),
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
        self.assertEqual(d.entries[row].path, chosen)


if __name__ == "__main__":
    unittest.main()
