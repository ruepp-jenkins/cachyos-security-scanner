import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cachy_sec import engine, scheduler, updater  # noqa: E402
from cachy_sec.scanners import aur_malware_check as amc  # noqa: E402
from cachy_sec import blocklist, signedlist  # noqa: E402
from cachy_sec.scanners.aur_scan import AurScan  # noqa: E402
from cachy_sec.scanners.base import CLEAN, CRITICAL, WARNING, ScanResult  # noqa: E402
from cachy_sec.settings import Settings  # noqa: E402


class SettingsTest(unittest.TestCase):
    def test_defaults_enable_both_aur_scanners(self):
        s = Settings()
        self.assertTrue(s.use_aur_malware_check)
        self.assertFalse(s.use_aur_scan)  # heuristic, opt-in
        self.assertTrue(s.use_false_positive_list)  # on by default (only effective while aur-scan is on)
        self.assertTrue(s.use_community_blocklist)  # on by default
        self.assertEqual(s.ignored_findings, ["SCAN-001"])

    def test_old_settings_file_migrates(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.json"
            p.write_text(json.dumps({"use_builtin_list": True, "use_aur_scan": True, "use_aur_malware_check": False}))
            s = Settings.load(p)
            self.assertFalse(s.use_aur_scan)  # became opt-in
            self.assertFalse(s.use_aur_malware_check)  # other choices are kept
            self.assertTrue(s.use_community_blocklist)  # the old built-in list setting is gone; the new list is on
            self.assertEqual(s.ignored_findings, ["SCAN-001"])
            s.use_aur_scan = True
            s.save(p)
            self.assertTrue(Settings.load(p).use_aur_scan)  # a deliberate opt-in after migration sticks

    def test_bad_types_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.json"
            p.write_text(json.dumps({"use_aur_malware_check": "no"}))
            self.assertTrue(Settings.load(p).use_aur_malware_check)


class SchedulerTest(unittest.TestCase):
    def test_triggers_are_independent(self):
        self.assertIsNone(scheduler.interval_ms(Settings(scan_periodic=False)))
        self.assertEqual(scheduler.interval_ms(Settings(scan_periodic=True, interval_minutes=30)), 1_800_000)
        self.assertFalse(scheduler.scan_at_startup(Settings(scan_on_start=False)))
        self.assertFalse(scheduler.binary_at_startup(Settings()))  # binary scans are opt-in
        self.assertTrue(scheduler.anything_after_pkg_change(Settings(scan_after_pkg_changes=False, binary_after_pkg_changes=True)))
        self.assertFalse(scheduler.anything_after_pkg_change(Settings(scan_after_pkg_changes=False)))

    def test_package_scans_have_a_short_wait_and_no_minimum_gap(self):
        self.assertEqual(Settings().pkg_change_delay_seconds, 10)
        self.assertEqual(scheduler.pkg_delay_ms(Settings(pkg_change_delay_seconds=20)), 20_000)
        self.assertFalse(hasattr(Settings(), "pkg_scan_min_gap_minutes"))

    def test_old_package_wait_default_is_migrated(self):
        import json, tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.json"
            p.write_text(json.dumps({"schema": 4, "pkg_change_delay_seconds": 30, "pkg_scan_min_gap_minutes": 10}))
            self.assertEqual(Settings.load(p).pkg_change_delay_seconds, 10)
            p.write_text(json.dumps({"schema": 4, "pkg_change_delay_seconds": 45}))
            self.assertEqual(Settings.load(p).pkg_change_delay_seconds, 45)  # a value the user chose stays

    def test_binary_schedule_decisions(self):
        s = Settings(binary_periodic=True, binary_interval_minutes=7 * 1440, binary_min_gap_hours=24)
        self.assertTrue(scheduler.binary_due(s, None))
        self.assertFalse(scheduler.binary_due(s, 3 * 86400))
        self.assertTrue(scheduler.binary_due(s, 8 * 86400))
        self.assertFalse(scheduler.binary_due(Settings(binary_periodic=False), None))
        self.assertFalse(scheduler.binary_due(s, 8 * 86400, 600))  # failed 10 min ago: retry only after an hour
        self.assertTrue(scheduler.binary_due(s, None, 7200))
        self.assertTrue(scheduler.binary_due(s, 8 * 86400, 7200))
        self.assertTrue(scheduler.binary_gap_ok(s, None))
        self.assertFalse(scheduler.binary_gap_ok(s, 3600))
        self.assertTrue(scheduler.binary_gap_ok(s, 25 * 3600))

    def test_old_mode_setting_is_migrated(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.json"
            p.write_text(json.dumps({"schema": 3, "mode": "manual"}))
            s = Settings.load(p)
            self.assertFalse(s.scan_periodic or s.scan_on_start or s.scan_after_pkg_changes)
            p.write_text(json.dumps({"schema": 3, "mode": "startup"}))
            s = Settings.load(p)
            self.assertTrue(s.scan_on_start and s.scan_after_pkg_changes and not s.scan_periodic)
            p.write_text(json.dumps({"schema": 3, "mode": "interval"}))
            self.assertTrue(Settings.load(p).scan_periodic)

    def test_gaming_skip_only_for_automatic(self):
        with mock.patch("cachy_sec.gaming.gaming_active", return_value=True):
            self.assertEqual(engine.skip_reason(Settings(), manual=False), "gaming mode active")
            self.assertIsNone(engine.skip_reason(Settings(), manual=True))
            self.assertIsNone(engine.skip_reason(Settings(skip_in_gaming_mode=False), manual=False))


class AdapterTest(unittest.TestCase):
    def test_extract_findings(self):
        data = {"infected_packages": ["evil-bin", {"name": "x"}], "warnings": ["odd"], "ok": ["fine"]}
        f = amc.extract_findings(data, "t")
        self.assertEqual({(x.severity, x.package) for x in f},
                         {(CRITICAL, "evil-bin"), (CRITICAL, "x"), (WARNING, "odd")})

    def test_exit_codes(self):
        sc = amc.AurMalwareCheck()
        mock.patch.object(sc, "_command", return_value=["x"]).start()
        self.addCleanup(mock.patch.stopall)
        with mock.patch.object(sc, "_cwd_cmd", return_value=(2, '{"compromised": ["bad"]}')):
            r = sc.scan()
            self.assertEqual((r.status, r.findings[0].package), (CRITICAL, "bad"))
        with mock.patch.object(sc, "_cwd_cmd", return_value=(0, "{}")):
            self.assertEqual(sc.scan().status, CLEAN)
        with mock.patch.object(sc, "_cwd_cmd", return_value=(3, "boom")):
            self.assertFalse(sc.scan().ok)

    def test_aur_scan_parses_one_finding_per_package_without_summary_noise(self):
        from cachy_sec.scanners.aur_scan import parse_output
        f = parse_output('AUR Security Scanner | System Audit\n============================================================\n\nGetting installed AUR packages...\nFound 10 AUR packages installed\n\nIOC name check: no installed package matches a known-malicious name indicator.\n\nScanning: chkrootkit OK\nScanning: heidisql ISSUES: 1 critical \n    DEEP-001 Decode-and-execute flow - /home/u/.cache/yay/heidisql/PKGBUILD\nScanning: multitail OK\nScanning: remote-desktop-manager ISSUES: 10 critical \n    SCAN-001 Package file could not be analyzed: rdm-1.pkg.tar.zst - /home/u/.cache/yay/rdm/rdm-1.pkg.tar.zst\n    SCAN-001 Package file could not be analyzed: rdm-2.pkg.tar.zst - /home/u/.cache/yay/rdm/rdm-2.pkg.tar.zst\n    CRYPTO-003 Monero/Bitcoin wallet address (source sidecar) - /home/u/.cache/yay/rdm/rdm-1.pkg.tar.zst\n    DEEP-001 Decode-and-execute flow - /home/u/.cache/yay/rdm/PKGBUILD\n\n============================================================\nSystem Scan Summary\n\n  Total: 5 packages scanned\n  Issues: 2 packages with issues\n  Severity: 11 critical, 0 high severity findings\n\n  Skipped: 5 packages not found in cache (use --rescan to fetch from AUR):\n    - synergy\n', "aur-scan")
        self.assertEqual([x.package for x in f], ["heidisql", "remote-desktop-manager"])
        self.assertNotIn("Severity", " ".join(x.title for x in f))
        self.assertIn("SCAN-001 Package file could not be analyzed ×2", f[1].title)  # no ignore list here
        self.assertEqual(len(f[1].detail.splitlines()), 4)
        self.assertIn("[/home/u/.cache/yay/heidisql/PKGBUILD]", f[0].detail)
        self.assertEqual(parse_output("Scanning: a OK\nScanning: b OK\n", "x"), [])

    def test_findings_carry_files_and_opener_finds_dirs(self):
        from cachy_sec import opener
        from cachy_sec.scanners.aur_scan import parse_output
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "PKGBUILD").write_text("x")
            out = f"Scanning: demo ISSUES: 1 critical\n    DEEP-001 Decode-and-execute flow - {d}/PKGBUILD\n"
            [f] = parse_output(out, "x")
            self.assertEqual(f.files, [f"{d}/PKGBUILD"])
            self.assertEqual(opener.finding_dirs([f]), {"demo": Path(d)})
            f.files = ["/does/not/exist/PKGBUILD", "relative/path"]
            self.assertEqual(opener.finding_dirs([f]), {})
            with mock.patch("shutil.which", side_effect=lambda n: "/usr/bin/codium" if n == "codium" else None):
                self.assertEqual(opener.build_command(Path(d)), ["/usr/bin/codium", d])
                self.assertIsNone(opener.build_command(Path(d), "nonexistent-editor"))
            with mock.patch("shutil.which", side_effect=lambda n: f"/usr/bin/{n}" if n in ("kate", "xdg-open") else None):
                self.assertEqual(opener.build_command(Path(d), "kate --new"), ["kate", "--new", d])
                self.assertEqual(opener.build_command(Path(d)), ["/usr/bin/xdg-open", d])  # no folder editor: file manager
            self.assertIsNone(opener.build_command(Path(d) / "missing"))

    def test_directory_of_finds_the_folder_of_the_first_existing_file(self):
        from cachy_sec import opener
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "PKGBUILD").write_text("x")
            self.assertEqual(opener.directory_of(["/nope/PKGBUILD", f"{d}/PKGBUILD"]), Path(d))
            self.assertIsNone(opener.directory_of(["/nope/PKGBUILD", "relative/x"]))
            self.assertIsNone(opener.directory_of([]))

    def test_aur_scan_ignore_list(self):
        from cachy_sec.scanners.aur_scan import parse_output
        sample = "Scanning: heidisql ISSUES: 1 critical\n    DEEP-001 Decode - /p/PKGBUILD\nScanning: rdm ISSUES: 2 critical\n    SCAN-001 Package file could not be analyzed: a.zst - /p/a.zst\n    CRYPTO-003 Wallet - /p/a.zst\n"
        self.assertEqual([f.package for f in parse_output(sample, "x", {"SCAN-001"})], ["heidisql", "rdm"])
        rdm = parse_output(sample, "x", {"SCAN-001"})[1]
        self.assertIn("1 issue –", rdm.title)
        self.assertNotIn("SCAN-001", rdm.title)
        self.assertEqual([f.package for f in parse_output(sample, "x", {"heidisql"})], ["rdm"])
        self.assertEqual([f.package for f in parse_output(sample, "x", {"rdm:CRYPTO-003", "SCAN-001"})], ["heidisql"])
        only_ignored = "Scanning: rdm ISSUES: 1 critical\n    SCAN-001 Package file could not be analyzed: a.zst - /p/a.zst\n"
        with mock.patch("cachy_sec.scanners.aur_scan.run", return_value=(1, only_ignored)), \
             mock.patch.object(AurScan, "_binary", return_value="/x/aur-scan"):
            self.assertEqual(AurScan(["SCAN-001"]).scan().status, CLEAN)  # nothing left to report
            self.assertEqual(AurScan([]).scan().status, WARNING)

    def test_aur_scan(self):
        p = mock.patch.object(AurScan, "_binary", return_value="/x/aur-scan")
        p.start()
        self.addCleanup(p.stop)
        with mock.patch("cachy_sec.scanners.aur_scan.run", return_value=(1, "unexpected output format")):
            r = AurScan().scan()
            self.assertEqual(r.status, WARNING)
            self.assertEqual(len(r.findings), 1)  # unparseable output still must not be lost
        with mock.patch("cachy_sec.scanners.aur_scan.run", return_value=(1, 'AUR Security Scanner | System Audit\n============================================================\n\nGetting installed AUR packages...\nFound 10 AUR packages installed\n\nIOC name check: no installed package matches a known-malicious name indicator.\n\nScanning: chkrootkit OK\nScanning: heidisql ISSUES: 1 critical \n    DEEP-001 Decode-and-execute flow - /home/u/.cache/yay/heidisql/PKGBUILD\nScanning: multitail OK\nScanning: remote-desktop-manager ISSUES: 10 critical \n    SCAN-001 Package file could not be analyzed: rdm-1.pkg.tar.zst - /home/u/.cache/yay/rdm/rdm-1.pkg.tar.zst\n    SCAN-001 Package file could not be analyzed: rdm-2.pkg.tar.zst - /home/u/.cache/yay/rdm/rdm-2.pkg.tar.zst\n    CRYPTO-003 Monero/Bitcoin wallet address (source sidecar) - /home/u/.cache/yay/rdm/rdm-1.pkg.tar.zst\n    DEEP-001 Decode-and-execute flow - /home/u/.cache/yay/rdm/PKGBUILD\n\n============================================================\nSystem Scan Summary\n\n  Total: 5 packages scanned\n  Issues: 2 packages with issues\n  Severity: 11 critical, 0 high severity findings\n\n  Skipped: 5 packages not found in cache (use --rescan to fetch from AUR):\n    - synergy\n')):
            r = AurScan().scan()
            self.assertEqual(len(r.findings), 2)
        with mock.patch("cachy_sec.scanners.aur_scan.run", return_value=(127, "nope")):
            self.assertFalse(AurScan().scan().ok)

    def test_aur_scan_build_failure_is_reported_with_log(self):
        sc = AurScan()
        with mock.patch.object(AurScan, "_binary", return_value=None), \
             mock.patch.object(AurScan, "update", autospec=True, side_effect=lambda self: (setattr(self, "_build_log", "error: linker `cc` not found"), setattr(self, "_prepared", True))) as up:
            r = sc.scan()
            sc.scan()
        self.assertEqual(r.status, "error")
        self.assertIn("linker `cc` not found", r.message)
        self.assertIn("linker", r.log)
        self.assertEqual(up.call_count, 1)  # a failed build is not retried within the same scan

    def test_amc_python_version_check(self):
        sc = amc.AurMalwareCheck()
        with mock.patch("cachy_sec.scanners.aur_malware_check.which", side_effect=lambda n: "/usr/bin/python3" if n == "python3" else None), \
             mock.patch("cachy_sec.scanners.aur_malware_check.run", return_value=(0, "3 12\n")):
            self.assertIsNone(amc._python())
            self.assertFalse(sc.available())
            self.assertIn("Python 3.14+", sc.unavailable_reason())
        with mock.patch("cachy_sec.scanners.aur_malware_check.which", side_effect=lambda n: "/usr/bin/python3" if n in ("python3", "git") else None), \
             mock.patch("cachy_sec.scanners.aur_malware_check.run", return_value=(0, "3 14\n")):
            self.assertEqual(amc._python(), "/usr/bin/python3")
            self.assertTrue(sc.available())


class ReportTest(unittest.TestCase):
    def test_clean_feedback(self):
        self.assertIn("No threats found", engine.Report([ScanResult("a", CLEAN)]).summary())
        self.assertIn("skipped", engine.Report([], skipped="gaming mode active").summary())

    def test_every_enabled_scanner_gets_a_result(self):
        class Gone:
            name = "gone"
            def available(self): return False
            def unavailable_reason(self): return "not installed"
        class Fine:
            name = "fine"
            def available(self): return True
            def update(self): pass
            def scan(self): return ScanResult("fine", CLEAN)
        with mock.patch.object(engine, "enabled_scanners", return_value=[Gone(), Fine()]), \
             mock.patch("cachy_sec.gaming.gaming_active", return_value=False):
            r = engine.run_scan(Settings(update_sources_before_scan=False), manual=True)
        self.assertEqual([x.backend for x in r.results], ["gone", "fine"])
        self.assertEqual(r.results[0].status, "error")
        self.assertIn("not available: not installed", r.results[0].message)

    def test_run_scan_skips_missing_and_survives_errors(self):
        class Boom:
            name = "boom"
            def available(self): return True
            def update(self): raise RuntimeError
            def scan(self): raise RuntimeError("x")
        with mock.patch.object(engine, "enabled_scanners", return_value=[Boom()]), \
             mock.patch("cachy_sec.gaming.gaming_active", return_value=False):
            r = engine.run_scan(Settings(), manual=True)
        self.assertEqual(r.results[0].status, "error")


class IconsTest(unittest.TestCase):
    def test_bundled_icons_exist_and_map_to_kinds(self):
        import xml.dom.minidom
        from cachy_sec import icons
        for name in (icons.APP, icons.GOOD, icons.BAD):
            xml.dom.minidom.parse(icons.path(name))  # exists and is well-formed
        self.assertTrue(icons.for_kind("good").endswith("status-good.svg"))
        self.assertTrue(icons.for_kind("bad").endswith("status-bad.svg"))
        self.assertTrue(icons.for_kind("info").endswith("cachy-security-scanner.svg"))

    def test_notify_passes_icon(self):
        from cachy_sec import notify
        with mock.patch("subprocess.run") as r:
            notify.notify("t", "b", kind="bad", urgent=True)
        cmd = r.call_args[0][0]
        self.assertEqual(cmd[cmd.index("-i") + 1].rsplit("/", 1)[1], "status-bad.svg")

    def test_click_on_the_notification_calls_back(self):
        from cachy_sec import notify
        hits = []
        done = mock.Mock(returncode=0, stdout="default\n", stderr="")
        with mock.patch("subprocess.run", return_value=done) as r:
            t = notify.notify("t", "b", kind="bad", on_click=lambda: hits.append(1))
            t.join(5)
        cmd = r.call_args[0][0]
        self.assertIn("--wait", cmd)
        self.assertTrue(any(c.startswith("--action=default=") for c in cmd))
        self.assertEqual(cmd[-2:], ["t", "b"])  # options come before title and body
        self.assertEqual(hits, [1])

    def test_dismissed_notification_does_not_call_back(self):
        from cachy_sec import notify
        hits = []
        done = mock.Mock(returncode=0, stdout="\n", stderr="")
        with mock.patch("subprocess.run", return_value=done):
            notify.notify("t", "b", on_click=lambda: hits.append(1)).join(5)
        self.assertEqual(hits, [])

    def test_old_notify_send_falls_back_to_a_plain_notification(self):
        from cachy_sec import notify
        calls = []

        def fake(cmd, **kw):
            calls.append(cmd)
            if "--wait" in cmd:
                return mock.Mock(returncode=1, stdout="", stderr="Unknown option --action")
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("subprocess.run", side_effect=fake):
            notify.notify("t", "b", on_click=lambda: None).join(5)
        self.assertEqual(len(calls), 2)
        self.assertNotIn("--wait", calls[1])

    def test_report_kind(self):
        from cachy_sec.scanners.base import Finding
        self.assertEqual(engine.Report([ScanResult("a", CLEAN)]).kind, "good")
        from cachy_sec.scanners.base import Finding as F
        rep = engine.Report([ScanResult("aur_scan", WARNING, [F(WARNING, "x", "s")]), ScanResult("blocklist", CLEAN)])
        self.assertIn("1 finding from aur_scan", rep.summary())  # says which scanner reported it
        self.assertEqual(engine.Report([ScanResult("a", CRITICAL, [Finding(CRITICAL, "x", "s")])]).kind, "bad")
        self.assertEqual(engine.Report([ScanResult("a", "error")]).kind, "bad")
        mixed = engine.Report([ScanResult("a", CLEAN), ScanResult("b", "error", [], "x")])
        self.assertEqual(mixed.kind, "bad")  # an enabled scanner that cannot run is an error, not silence
        self.assertIn("Scan incomplete: b: x", mixed.summary())
        self.assertEqual(engine.Report([], skipped="gaming mode active").kind, "info")


def _fp_entry(**kw):
    e = {"package": "heidisql", "versions": ["1:12.*"], "codes": ["DEEP-001"], "reason": "unzip + bash -c in different files",
         "author": "someone", "reported": "2026-10-31"}
    e.update(kw)
    return {"schema": 1, "entries": [e]}


class FalsePositiveListTest(unittest.TestCase):
    def test_repo_list_is_valid(self):
        from cachy_sec import fplist
        data = json.loads((Path(__file__).resolve().parents[1] / "lists" / fplist.LIST_NAME).read_text())
        self.assertTrue(fplist.validate(data))

    def test_validation_rules(self):
        from cachy_sec import fplist
        e = fplist.validate(_fp_entry(description="more text"))[0]
        self.assertEqual((e.author, e.reported, e.description), ("someone", "2026-10-31", "more text"))
        self.assertEqual(fplist.validate(_fp_entry())[0].description, "")  # description is optional
        for bad in (_fp_entry(author=""), _fp_entry(reported="31.10.2026"), _fp_entry(reported="2026-13-01"),
                    _fp_entry(versions=["*"]), _fp_entry(versions=[]), _fp_entry(codes=["deep-001"]),
                    _fp_entry(codes=["*"]), _fp_entry(reason="short"),
                    _fp_entry(package="Bad Name"), {"schema": 2, "entries": []}, []):
            with self.assertRaises(ValueError, msg=str(bad)):
                fplist.validate(bad)
        missing = _fp_entry()
        del missing["entries"][0]["author"]
        with self.assertRaises(ValueError):
            fplist.validate(missing)

    def test_match_with_globs_and_versions(self):
        from cachy_sec import fplist
        entries = fplist.validate(_fp_entry())
        self.assertIsNotNone(fplist.match(entries, "heidisql", "1:12.22-1", "DEEP-001"))
        self.assertIsNone(fplist.match(entries, "heidisql", "2:1.0-1", "DEEP-001"))   # other version
        self.assertIsNone(fplist.match(entries, "heidisql", "1:12.22-1", "DEEP-003"))  # other rule
        self.assertIsNone(fplist.match(entries, "other", "1:12.22-1", "DEEP-001"))
        self.assertIsNone(fplist.match(entries, "heidisql", "", "DEEP-001"))  # unknown version: hide nothing

    def test_refresh_requires_valid_signature_and_load_reverifies(self):
        import os, subprocess
        from cachy_sec import fplist, updater
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"XDG_CACHE_HOME": d}):
            key = Path(d) / "k"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            pub = (Path(d) / "k.pub").read_text().strip()
            payload = Path(d) / fplist.LIST_NAME
            payload.write_text(json.dumps(_fp_entry()))
            subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", str(key), "-n", fplist.SIG_NAMESPACE, str(payload)], check=True)
            files = {fplist._url(fplist.LIST_NAME): payload.read_bytes(), fplist._url(fplist.LIST_NAME + ".sig"): (Path(d) / (fplist.LIST_NAME + ".sig")).read_bytes()}
            with mock.patch.object(updater, "_get", side_effect=lambda u, limit=0: files[u]):
                self.assertEqual(fplist.refresh(force=True, pubkey=pub), (True, "updated"))
                self.assertEqual(len(fplist.load(pub)), 1)
                self.assertTrue(fplist.refresh(pubkey=pub)[1].startswith("cache is fresh"))
                self.assertEqual(fplist.load(""), [])  # no signing key configured: nothing is trusted
                other = Path(d) / "o"
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(other)], check=True)
                self.assertEqual(fplist.load((Path(d) / "o.pub").read_text().strip()), [])  # wrong signer
            # tampered cache file is rejected on load
            fplist._paths()[0].write_text(json.dumps(_fp_entry(codes=["DEEP-003"])))
            self.assertEqual(fplist.load(pub), [])
            # a bad download never replaces the cache
            files[fplist._url(fplist.LIST_NAME)] = b'{"schema":1,"entries":[]}'
            with mock.patch.object(updater, "_get", side_effect=lambda u, limit=0: files[u]):
                ok, msg = fplist.refresh(force=True, pubkey=pub)
            self.assertFalse(ok)

    def test_aur_scan_uses_list_only_when_enabled_and_notes_it_in_the_log(self):
        from cachy_sec import fplist
        out = "Scanning: heidisql ISSUES: 1 critical\n    DEEP-001 Decode - /p/PKGBUILD\n"
        entries = fplist.validate(_fp_entry())
        common = [mock.patch("cachy_sec.scanners.aur_scan.run", return_value=(1, out)),
                  mock.patch.object(AurScan, "_binary", return_value="/x/aur-scan"),
                  mock.patch("cachy_sec.ignores.installed_versions", return_value={"heidisql": "1:12.22-1"}),
                  mock.patch("cachy_sec.ignores.load", return_value=[]),
                  mock.patch("cachy_sec.fplist.load", return_value=entries),
                  mock.patch("cachy_sec.fplist.refresh", return_value=(True, "ok"))]
        for p in common:
            p.start()
        self.addCleanup(mock.patch.stopall)
        off = AurScan(use_fp_list=False).scan()
        self.assertEqual(off.status, WARNING)  # not used when the checkbox is off
        self.assertIn("community false-positive list: off", off.log)  # the log says why nothing was hidden
        self.assertTrue(any("switched off" in n for n in off.notes))  # and so does the findings window
        self.assertIn("scanned PKGBUILD version / installed version: heidisql 1:12.22-1 / 1:12.22-1", off.log)
        self.assertIn("heidisql 1:12.22-1:", off.findings[0].title)
        on = AurScan(use_fp_list=True).scan()
        self.assertEqual(on.status, CLEAN)
        self.assertIn("hidden by the community false-positive list", on.log)
        self.assertIn("community false-positive list: on, 1 entries", on.log)
        self.assertTrue(any("1 finding(s) were hidden" in n for n in on.notes))
        with mock.patch("cachy_sec.fplist.load", return_value=[]):  # enabled, but no verified list in the cache
            missing = AurScan(use_fp_list=True).scan()
        self.assertEqual(missing.status, WARNING)
        self.assertTrue(any("on but not available" in n for n in missing.notes))
        self.assertIn("reported by someone, 2026-10-31", on.log)


def _bl_entry(**kw):
    e = {"package": "evil-bin", "reason": "installs a reverse shell from the install script", "author": "someone",
         "reported": "2026-10-31"}
    e.update(kw)
    return {"schema": 1, "entries": [e]}


class BlocklistTest(unittest.TestCase):
    def test_repo_lists_are_valid(self):
        root = Path(__file__).resolve().parents[1] / "lists"
        from cachy_sec import fplist
        blocklist.validate(json.loads((root / blocklist.LIST_NAME).read_text()))
        fplist.validate(json.loads((root / fplist.LIST_NAME).read_text()))
        self.assertEqual(signedlist.main(["x", "validate", str(root / blocklist.LIST_NAME), str(root / fplist_name())]), 0)

    def test_validation_and_match(self):
        e = blocklist.validate(_bl_entry())[0]
        self.assertEqual(e.versions, ["*"])  # no versions = all
        for bad in (_bl_entry(package="Bad Name"), _bl_entry(author=""), _bl_entry(reported="yesterday"),
                    _bl_entry(reason="bad"), _bl_entry(versions=[]), _bl_entry(reference="http://x"),
                    {"schema": 9, "entries": []}):
            with self.assertRaises(ValueError, msg=str(bad)):
                blocklist.validate(bad)
        entries = blocklist.validate(_bl_entry(versions=["1.2.*"], reference="https://example.org/advisory"))
        self.assertIsNotNone(blocklist.match(entries, "evil-bin", "1.2.7-1"))
        self.assertIsNone(blocklist.match(entries, "evil-bin", "1.3.0-1"))
        self.assertIsNone(blocklist.match(entries, "other", "1.2.7-1"))
        self.assertIsNotNone(blocklist.match(blocklist.validate(_bl_entry()), "evil-bin", "9:9-9"))

    def test_scanner_flags_installed_match_and_errors_without_a_list(self):
        from cachy_sec.scanners.blocklist import CommunityBlocklist
        entries = blocklist.validate(_bl_entry(versions=["1.*"], reference="https://example.org/a"))
        loaded = signedlist.Loaded(entries, "2026-10-31T18:45:01Z", 0.0)
        with mock.patch("cachy_sec.blocklist.refresh", return_value=(True, "updated")), \
             mock.patch("cachy_sec.blocklist.load", return_value=loaded), \
             mock.patch("cachy_sec.scanners.blocklist.installed_versions",
                        return_value={"evil-bin": "1.0-1", "fine": "2-1"}):
            r = CommunityBlocklist().scan()
        self.assertEqual((r.status, r.findings[0].package, r.findings[0].version), (CRITICAL, "evil-bin", "1.0-1"))
        self.assertIn("reported by someone on 2026-10-31", r.findings[0].detail)
        self.assertIn("from 2026-10-31 18:45 UTC", r.log)
        with mock.patch("cachy_sec.blocklist.refresh", return_value=(False, "HTTP Error 404")), \
             mock.patch("cachy_sec.blocklist.load", return_value=None):
            r = CommunityBlocklist().scan()
        self.assertEqual(r.status, "error")  # protection incomplete: not silent
        self.assertIn("HTTP Error 404", r.message)
        with mock.patch("cachy_sec.blocklist.refresh", return_value=(True, "cache is fresh")), \
             mock.patch("cachy_sec.blocklist.load", return_value=signedlist.Loaded([], "", 0.0)), \
             mock.patch("cachy_sec.scanners.blocklist.installed_versions", return_value={"fine": "2-1"}):
            self.assertEqual(CommunityBlocklist().scan().status, CLEAN)


def fplist_name():
    from cachy_sec import fplist
    return fplist.LIST_NAME


class LowPriorityTest(unittest.TestCase):
    NICE = "import os; print(os.nice(0))"

    def tearDown(self):
        from cachy_sec.scanners import base
        base.set_low_priority(True)

    def test_scanner_processes_really_run_niced(self):
        import shutil
        from cachy_sec.scanners import base
        if not shutil.which("nice"):
            self.skipTest("nice not available")
        base.set_low_priority(True)
        code, out = base.run([sys.executable, "-c", self.NICE], 30, low_priority=True)
        self.assertEqual((code, out.strip()), (0, "19"))
        code, out = base.run([sys.executable, "-c", self.NICE], 30)  # heavy work only: plain calls stay normal
        self.assertNotEqual(out.strip(), "19")
        base.set_low_priority(False)  # the user switched it off
        code, out = base.run([sys.executable, "-c", self.NICE], 30, low_priority=True)
        self.assertNotEqual(out.strip(), "19")

    def test_prefix_uses_only_tools_that_exist(self):
        from cachy_sec.scanners import base
        with mock.patch("shutil.which", side_effect=lambda n: f"/usr/bin/{n}"):
            self.assertEqual(base.priority_prefix(), ["nice", "-n", "19", "ionice", "-c", "2", "-n", "7"])
        with mock.patch("shutil.which", side_effect=lambda n: "/usr/bin/nice" if n == "nice" else None):
            self.assertEqual(base.priority_prefix(), ["nice", "-n", "19"])
        with mock.patch("shutil.which", return_value=None):
            self.assertEqual(base.priority_prefix(), [])  # nothing to prepend: the command just runs normally

    def test_engine_applies_the_setting_and_scanners_use_it(self):
        from cachy_sec.scanners import base
        self.assertTrue(Settings().low_priority_scans)
        seen = []
        with mock.patch("cachy_sec.scanners.aur_scan.run", side_effect=lambda cmd, timeout=0, low_priority=False: seen.append(low_priority) or (0, "")), \
             mock.patch.object(AurScan, "_binary", return_value="/x/aur-scan"), \
             mock.patch("cachy_sec.gaming.gaming_active", return_value=False):
            engine.run_scan(Settings(use_aur_scan=True, use_aur_malware_check=False, use_community_blocklist=False,
                                     low_priority_scans=False, update_sources_before_scan=False), manual=True)
            self.assertIs(base._low_priority, False)
        self.assertEqual(seen, [True])  # the scan call asks for low priority; the setting decides whether it applies


class SingleInstanceTest(unittest.TestCase):
    def test_second_instance_is_refused_and_lock_is_released(self):
        from cachy_sec import singleton
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.lock"
            first = singleton.acquire(p)
            self.assertIsNotNone(first)
            self.assertIsNone(singleton.acquire(p))  # a second instance must not start
            self.assertEqual(p.read_text(), str(os.getpid()))
            first.close()  # process exit does the same: no stale lock after a crash
            again = singleton.acquire(p)
            self.assertIsNotNone(again)
            again.close()

    def test_save_failure_is_an_error_not_silent(self):
        with tempfile.TemporaryDirectory() as d:
            blocker = Path(d) / "cfg"
            blocker.write_text("a file where the config directory should be")
            with self.assertRaises(OSError):
                Settings(use_aur_scan=False).save(blocker / "settings.json")  # the app catches this and notifies

    def test_disabled_scanner_stays_disabled_across_save_and_load(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "cfg" / "settings.json"
            s = Settings.load(p)  # first start: defaults
            s.use_aur_scan = True
            s.save(p)
            s = Settings.load(p)
            self.assertTrue(s.use_aur_scan)
            s.use_aur_scan = False  # the user unticks it and saves
            s.save(p)
            self.assertFalse(Settings.load(p).use_aur_scan)  # ... and a restart must not bring it back
            self.assertFalse(json.loads(p.read_text())["use_aur_scan"])

    def test_scan_always_uses_the_saved_settings_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.json"
            self.assertIsNone(Settings.load_existing(p))  # no file: callers keep what they have
            Settings(use_aur_scan=False, use_aur_malware_check=True).save(p)
            s = Settings.load_existing(p)
            self.assertFalse(s.use_aur_scan)
            self.assertEqual([type(x).__name__ for x in engine.enabled_scanners(s)], ["AurMalwareCheck", "CommunityBlocklist"])


class ListRefreshPolicyTest(unittest.TestCase):
    def test_scans_do_not_download_when_a_list_is_cached(self):
        from cachy_sec.scanners.blocklist import CommunityBlocklist
        loaded = signedlist.Loaded([], "", 0.0)
        with mock.patch("cachy_sec.blocklist.load", return_value=loaded), \
             mock.patch("cachy_sec.blocklist.refresh") as refresh, \
             mock.patch("cachy_sec.scanners.blocklist.installed_versions", return_value={}):
            self.assertEqual(CommunityBlocklist().scan().status, CLEAN)
        refresh.assert_not_called()
        # nothing cached yet: one fetch attempt, and a clear error if it fails
        with mock.patch("cachy_sec.blocklist.load", return_value=None), \
             mock.patch("cachy_sec.blocklist.refresh", return_value=(False, "HTTP Error 404")) as refresh:
            r = CommunityBlocklist().scan()
        refresh.assert_called_once()
        self.assertEqual(r.status, "error")

    def test_aur_scan_does_not_download_when_cached_but_fetches_when_missing(self):
        entries = []
        with mock.patch("cachy_sec.fplist.load", return_value=[object()]), mock.patch("cachy_sec.fplist.refresh") as refresh:
            AurScan(use_fp_list=True)._refresh_fp()
        refresh.assert_not_called()
        with mock.patch("cachy_sec.fplist.load", return_value=entries), \
             mock.patch("cachy_sec.fplist.refresh", return_value=(True, "updated")) as refresh:
            AurScan(use_fp_list=True)._refresh_fp()
        refresh.assert_called_once()

    def test_engine_refresh_lists_follows_the_settings(self):
        with mock.patch("cachy_sec.blocklist.refresh", return_value=(True, "updated")) as bl, \
             mock.patch("cachy_sec.fplist.refresh", return_value=(True, "cache is fresh")) as fp:
            out = engine.refresh_lists(Settings(use_community_blocklist=True, use_aur_scan=True, use_false_positive_list=True))
            self.assertEqual(out, {"blocklist": "updated", "false-positives": "cache is fresh"})
            bl.reset_mock(); fp.reset_mock()
            out = engine.refresh_lists(Settings(use_community_blocklist=False, use_aur_scan=False, use_false_positive_list=True))
            self.assertEqual(out, {})  # false-positive list is pointless without aur-scan
            bl.assert_not_called(); fp.assert_not_called()
        with mock.patch("cachy_sec.blocklist.refresh", side_effect=RuntimeError("boom")):
            self.assertIn("boom", engine.refresh_lists(Settings())["error"])  # never raises

    def test_failed_download_reason_is_shown_in_the_status(self):
        import os
        from cachy_sec import fplist
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"XDG_CACHE_HOME": d}):
            self.assertIn("not downloaded yet", fplist.status())
            with mock.patch.object(updater, "_get", side_effect=updater.UpdateError("download failed: HTTP Error 404: Not Found")):
                self.assertFalse(fplist.refresh(force=True)[0])
            self.assertIn("last download failed (download failed: HTTP Error 404", fplist.status())


class ScannerOptionsTest(unittest.TestCase):
    def setUp(self):
        from cachy_sec import scanopts
        self.o = scanopts

    def test_empty_and_plain_options(self):
        self.assertEqual(self.o.parse_extra("", self.o.DENY_CLAMD), [])
        self.assertEqual(self.o.parse_extra("--verbose --name=a --limit 5", set()), ["--verbose", "--name=a", "--limit", "5"])
        self.assertEqual(self.o.parse_extra("-l 'chaos rat=./list.txt'", self.o.DENY_AMC), ["-l", "chaos rat=./list.txt"])

    def test_shell_tricks_are_rejected(self):
        for bad in ("--verbose && touch /tmp/x", "--verbose; id", "--verbose | cat", "--a `id`", "--a $(id)", "--a $HOME",
                    "--a > /tmp/x", "--a < /etc/passwd", "--a\nid", "--a=b&c"):
            with self.assertRaises(ValueError, msg=bad):
                self.o.parse_extra(bad, set())

    def test_must_be_options(self):
        for bad in ("rm -rf x", "scan --verbose", "--a b c", "--", "--verbose -- /etc", "-", "--1x", "--a 'unterminated"):
            with self.assertRaises(ValueError, msg=bad):
                self.o.parse_extra(bad, set())
        with self.assertRaises(ValueError):
            self.o.parse_extra("--" + "a" * 1100, set())
        with self.assertRaises(ValueError):
            self.o.parse_extra(" ".join(["--a"] * 41), set())

    def test_denied_options_incl_abbreviations_and_groups(self):
        d = self.o.DENY_CLAMD
        for bad in ("--remove", "--remove=yes", "--move=/tmp", "--move /tmp", "--rem", "--copy /x", "-f list", "-vf", "--help",
                    "--fdpass", "-i", "--file-list=x"):
            with self.assertRaises(ValueError, msg=bad):
                self.o.parse_extra(bad, d)
        self.assertEqual(self.o.parse_extra("--config-file=/etc/clamav/clamd.conf", d), ["--config-file=/etc/clamav/clamd.conf"])
        for bad in ("--log-file x", "--out f", "--json", "-o f"):
            with self.assertRaises(ValueError, msg=bad):
                self.o.parse_extra(bad, self.o.DENY_AMC)
        for bad in ("--fail-on low", "--no-color", "-q", "--sev low", "--rescan"):
            with self.assertRaises(ValueError, msg=bad):
                self.o.parse_extra(bad, self.o.DENY_AUR_SCAN)

    def test_built_arguments(self):
        s = Settings()
        self.assertEqual(self.o.amc_args(s), [])
        self.assertEqual(self.o.aur_scan_args(s), ["--fail-on", "high"])
        self.assertEqual(self.o.clamd_args(s), ["--fdpass", "-i", "--multiscan"])
        s = Settings(amc_check_systemd=True, amc_check_caches=True, amc_all_time=True, amc_extra_args="--verbose",
                     aur_scan_fail_on="low", aur_scan_min_severity="medium", aur_scan_rescan=True, aur_scan_extra_args="-v",
                     binary_multiscan=False, binary_allmatch=True, binary_extra_args="--config-file=/x")
        self.assertEqual(self.o.amc_args(s), ["--all-time", "--check-systemd", "--check-npm-cache", "--check-bun-cache",
                                              "--check-yarn-cache", "--check-pnpm-cache", "--verbose"])
        self.assertEqual(self.o.aur_scan_args(s), ["--fail-on", "low", "--severity", "medium", "--rescan", "-v"])
        self.assertEqual(self.o.clamd_args(s), ["--fdpass", "-i", "--allmatch", "--config-file=/x"])
        self.assertIn("Invalid extra arguments", self.o.preview("clamd", Settings(binary_extra_args="--remove")))
        self.assertTrue(self.o.preview("aur_scan", Settings()).startswith("aur-scan --no-color system"))

    def test_invalid_saved_value_is_an_error_not_a_scan(self):
        from cachy_sec.scanners import clamd
        s = Settings(binary_extra_args="--remove")
        with tempfile.TemporaryDirectory() as d, mock.patch("cachy_sec.scanners.clamd.available", return_value=True), \
                mock.patch("subprocess.run") as run:
            state, msg = clamd.run_background([d], True, "manual", s)
            self.assertEqual(state, "error")
            self.assertIn("--remove", msg)
            run.assert_not_called()
            ok, msg = clamd.launch([d], s)
            self.assertFalse(ok)

    def test_choices_are_validated_on_load(self):
        s = Settings(aur_scan_fail_on="bogus", aur_scan_min_severity="x")
        s.validate()
        self.assertEqual((s.aur_scan_fail_on, s.aur_scan_min_severity), ("high", "all"))

    def test_options_reach_the_commands(self):
        from cachy_sec.scanners import clamd
        self.assertEqual(clamd.background_command(["/a"], False, ["--fdpass", "-i"]), ["clamdscan", "--fdpass", "-i", "--", "/a"])
        s = Settings(aur_scan_fail_on="medium")
        scanner = AurScan([], False, s)
        with mock.patch.object(AurScan, "_binary", return_value="/bin/aur-scan"), \
                mock.patch("cachy_sec.scanners.aur_scan.run", return_value=(0, "ok")) as run:
            scanner._prepared = True
            scanner.scan()
        self.assertEqual(run.call_args[0][0], ["/bin/aur-scan", "--no-color", "system", "--fail-on", "medium"])


class DocsTest(unittest.TestCase):
    def test_every_setting_is_documented(self):
        """docs/settings.md must mention each settings key, so a new option cannot be forgotten."""
        from dataclasses import fields
        text = (Path(__file__).resolve().parents[1] / "docs" / "settings.md").read_text()
        missing = [f.name for f in fields(Settings) if f.name != "schema" and f"`{f.name}`" not in text]
        self.assertEqual(missing, [], f"undocumented settings: {missing}")

    def test_license_is_consistent(self):
        root = Path(__file__).resolve().parents[1]
        self.assertTrue((root / "LICENSE").read_text().startswith("MIT License"))
        self.assertIn("license=('MIT')", (root / "PKGBUILD").read_text())
        self.assertIn('license = { text = "MIT" }', (root / "pyproject.toml").read_text())
        self.assertIn("/usr/share/licenses/$pkgname/LICENSE", (root / "PKGBUILD").read_text())  # installed with the package

    def test_relative_links_in_the_docs_exist(self):
        import re
        root = Path(__file__).resolve().parents[1]
        for doc in (root / "docs" / "settings.md", root / "README.md"):
            for target in re.findall(r"\]\((?!https?:|#|mailto:)([^)#]+)", doc.read_text()):
                self.assertTrue((doc.parent / target).exists(), f"{doc.name}: broken link {target}")


class SignedListTest(unittest.TestCase):
    def test_describe_for_the_settings_dialog(self):
        self.assertIn("not downloaded yet", signedlist.describe(None))
        self.assertIn("last download failed (boom)", signedlist.describe(None, error="boom"))
        l = signedlist.Loaded([1, 2, 3], "2026-10-31T18:45:01Z", 0.0)
        self.assertEqual(signedlist.describe(l), "available, from 2026-10-31 18:45 UTC, 3 entries")
        self.assertEqual(signedlist.describe(signedlist.Loaded([1], "2026-10-31T18:45:01Z", 0.0)),
                         "available, from 2026-10-31 18:45 UTC, 1 entry")
        self.assertIn("downloaded ", signedlist.describe(signedlist.Loaded([], "", 0.0)))  # no stamp: local download time

    def test_published_stamp_is_read_and_failures_back_off(self):
        import os, subprocess
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"XDG_CACHE_HOME": d}):
            key = Path(d) / "k"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            pub = (Path(d) / "k.pub").read_text().strip()
            payload = Path(d) / blocklist.LIST_NAME
            payload.write_text(json.dumps({**_bl_entry(), "published": "2026-10-31T18:45:01Z"}))
            subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", str(key), "-n", blocklist.SIG_NAMESPACE, str(payload)], check=True)
            files = {signedlist.url(blocklist.LIST_NAME): payload.read_bytes(),
                     signedlist.url(blocklist.LIST_NAME + ".sig"): (Path(d) / (blocklist.LIST_NAME + ".sig")).read_bytes()}
            with mock.patch.object(updater, "_get", side_effect=lambda u, limit=0: files[u]):
                self.assertEqual(blocklist.refresh(force=True, pubkey=pub), (True, "updated"))
            loaded = signedlist.load(blocklist.SPEC, pub)
            self.assertEqual((loaded.published, len(loaded.entries)), ("2026-10-31T18:45:01Z", 1))
            self.assertIsNone(signedlist.load(blocklist.SPEC, ""))  # no trusted key: unusable
            # a failed download leaves a marker; no new attempt for a while
            for p in signedlist.paths(blocklist.SPEC):
                p.unlink()
            calls = []
            def boom(u, limit=0):
                calls.append(u)
                raise updater.UpdateError("HTTP Error 404")
            with mock.patch.object(updater, "_get", side_effect=boom):
                self.assertFalse(blocklist.refresh(pubkey=pub)[0])
                self.assertFalse(blocklist.refresh(pubkey=pub)[0])
                self.assertEqual(len(calls), 1)  # second call did not hit the network
                blocklist.refresh(force=True, pubkey=pub)
                self.assertEqual(len(calls), 2)  # force ignores the back-off


class IgnoreTest(unittest.TestCase):
    SAMPLE = "Scanning: heidisql ISSUES: 1 critical\n    DEEP-001 Decode - /p/PKGBUILD\n    DEEP-003 Bidi - /p/PKGBUILD\n"

    def test_ignore_is_bound_to_package_version_and_codes(self):
        from cachy_sec import ignores
        from cachy_sec.scanners.aur_scan import parse_output
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "i.json"
            ignores.add("heidisql", "1:12.22-1", ["DEEP-001"], p)
            entries = ignores.load(p)
            v1 = {"heidisql": "1:12.22-1"}
            f = parse_output(self.SAMPLE, "x", suppress=ignores.matcher(v1, entries), versions=v1)
            self.assertEqual([x.codes for x in f], [["DEEP-003"]])  # a not-accepted code still shows
            self.assertEqual(f[0].version, "1:12.22-1")
            v2 = {"heidisql": "1:12.23-1"}  # the package was updated
            f = parse_output(self.SAMPLE, "x", suppress=ignores.matcher(v2, entries), versions=v2)
            self.assertEqual(f[0].codes, ["DEEP-001", "DEEP-003"])  # reported again
            f = parse_output(self.SAMPLE, "x", suppress=ignores.matcher({}, entries), versions={})
            self.assertEqual(f[0].codes, ["DEEP-001", "DEEP-003"])  # version unknown: fail open, show it

    def test_srcinfo_version_and_scanned_version_wins_over_installed(self):
        from cachy_sec import fplist, ignores
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / ".SRCINFO").write_text("pkgbase = heidisql\n\tpkgdesc = x\n\tpkgver = 12.22\n\tpkgrel = 1\n\tepoch = 1\n\n"
                                              "pkgname = heidisql\n\tpkgver = 99\n")
            self.assertEqual(ignores.srcinfo_version(Path(d)), "1:12.22-1")
            (Path(d) / ".SRCINFO").write_text("pkgbase = a\n\tpkgver = 2.0\n\tpkgrel = 3\n\tepoch = 0\n")
            self.assertEqual(ignores.srcinfo_version(Path(d)), "2.0-3")  # epoch 0 / missing: no prefix
            (Path(d) / ".SRCINFO").write_text("pkgbase = a\n\tpkgver = 2.0\n")
            self.assertEqual(ignores.srcinfo_version(Path(d)), "")  # incomplete: fall back to the installed version
            self.assertEqual(ignores.srcinfo_version(Path(d) / "missing"), "")
            (Path(d) / ".SRCINFO").write_text("pkgbase = heidisql\n\tpkgver = 12.22\n\tpkgrel = 1\n\tepoch = 1\n")
            out = f"Scanning: heidisql ISSUES: 1 critical\n    DEEP-001 Decode - {d}/PKGBUILD\n"
            entries = fplist.validate(_fp_entry())
            for p in [mock.patch("cachy_sec.scanners.aur_scan.run", return_value=(1, out)),
                      mock.patch.object(AurScan, "_binary", return_value="/x/aur-scan"),
                      # the installed version is older than the PKGBUILD in the helper cache
                      mock.patch("cachy_sec.ignores.installed_versions", return_value={"heidisql": "1:12.21-1"}),
                      mock.patch("cachy_sec.ignores.load", return_value=[]),
                      mock.patch("cachy_sec.fplist.load", return_value=entries),
                      mock.patch("cachy_sec.fplist.refresh", return_value=(True, "ok"))]:
                p.start()
            self.addCleanup(mock.patch.stopall)
            r = AurScan(use_fp_list=True).scan()
            self.assertEqual(r.status, CLEAN)  # matched on the scanned 1:12.22-1, not the installed 1:12.21-1
            self.assertIn("heidisql 1:12.22-1 / 1:12.21-1", r.log)

    def test_one_row_per_rule_for_the_findings_window(self):
        from cachy_sec import ignores
        from cachy_sec.scanners.aur_scan import parse_output
        sample = ("Scanning: rdm ISSUES: 4 critical\n    SCAN-001 Package file could not be analyzed: a.zst - /p/a.zst\n"
                  "    SCAN-001 Package file could not be analyzed: b.zst - /p/b.zst\n    DEEP-001 Decode - /p/PKGBUILD\n"
                  "    DEEP-003 Bidi - /p/PKGBUILD\n")
        v = {"rdm": "1-1"}
        f = parse_output(sample, "x", versions=v)
        rows = ignores.rows(f)
        self.assertEqual([(r.package, r.version, r.code, r.count) for r in rows],
                         [("rdm", "1-1", "SCAN-001", 2), ("rdm", "1-1", "DEEP-001", 1), ("rdm", "1-1", "DEEP-003", 1)])
        self.assertEqual(rows[0].title, "Package file could not be analyzed")
        self.assertEqual(rows[0].files, ["/p/a.zst", "/p/b.zst"])  # the files behind exactly this rule
        self.assertEqual(rows[1].files, ["/p/PKGBUILD"])
        unknown = ignores.rows(parse_output(sample, "x", versions={}))
        self.assertEqual({r.version for r in unknown}, {""})  # still listed (can be inspected), but not ignorable
        # ticking entries off one at a time: each ignore only hides its own rule
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "i.json"
            ignores.add("rdm", "1-1", ["SCAN-001"], p)
            f = parse_output(sample, "x", suppress=ignores.matcher(v, ignores.load(p)), versions=v)
            self.assertEqual([r.code for r in ignores.rows(f)], ["DEEP-001", "DEEP-003"])

    def test_add_merges_validates_and_revokes(self):
        from cachy_sec import ignores
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "i.json"
            ignores.add("a", "1-1", ["X-1"], p)
            ignores.add("a", "1-1", ["X-2"], p)
            ignores.add("a", "2-1", ["X-1"], p)
            self.assertEqual([(e.version, e.codes) for e in ignores.load(p)], [("1-1", ["X-1", "X-2"]), ("2-1", ["X-1"])])
            with self.assertRaises(ValueError):
                ignores.add("a", "", ["X-1"], p)  # an ignore without a version could never expire
            ignores.remove("a", "1-1", p)
            self.assertEqual([e.version for e in ignores.load(p)], ["2-1"])
            p.write_text("garbage")
            self.assertEqual(ignores.load(p), [])

    def test_aur_scan_end_to_end_with_versions(self):
        from cachy_sec import ignores
        out = "Scanning: heidisql ISSUES: 1 critical\n    DEEP-001 Decode - /p/PKGBUILD\n"
        ent = [ignores.Ignore("heidisql", "1:12.22-1", ["DEEP-001"])]
        with mock.patch("cachy_sec.scanners.aur_scan.run", return_value=(1, out)), \
             mock.patch.object(AurScan, "_binary", return_value="/x/aur-scan"), \
             mock.patch("cachy_sec.ignores.installed_versions", return_value={"heidisql": "1:12.22-1"}), \
             mock.patch("cachy_sec.ignores.load", return_value=ent):
            self.assertEqual(AurScan().scan().status, CLEAN)
        with mock.patch("cachy_sec.scanners.aur_scan.run", return_value=(1, out)), \
             mock.patch.object(AurScan, "_binary", return_value="/x/aur-scan"), \
             mock.patch("cachy_sec.ignores.installed_versions", return_value={"heidisql": "1:12.23-1"}), \
             mock.patch("cachy_sec.ignores.load", return_value=ent):
            r = AurScan().scan()
            self.assertEqual((r.status, r.findings[0].version), (WARNING, "1:12.23-1"))


class ClamdTest(unittest.TestCase):
    def test_build_command_per_terminal(self):
        from cachy_sec.scanners import clamd
        with tempfile.TemporaryDirectory() as d:
            with mock.patch("shutil.which", side_effect=lambda n: f"/usr/bin/{n}" if n == "konsole" else None):
                cmd = clamd.build_command([d, "/does/not/exist"])
            self.assertEqual(cmd[:3], ["/usr/bin/konsole", "-e", "bash"])
            self.assertEqual(cmd[-1], d)  # missing paths are dropped
            self.assertIn('clamdscan "${opts[@]}" -- "$@"', cmd[4])
            self.assertEqual(cmd[5:9], ["clamdscan", "/dev/null", "3", "--fdpass"])  # script args: log, option count, options
            with mock.patch("shutil.which", side_effect=lambda n: "/usr/bin/foot" if n == "foot" else None):
                self.assertEqual(clamd.build_command([d])[:2], ["/usr/bin/foot", "bash"])

    def test_no_terminal_or_no_paths(self):
        from cachy_sec.scanners import clamd
        with mock.patch("shutil.which", return_value=None):
            self.assertIsNone(clamd.build_command(["/tmp"]))
        with mock.patch("shutil.which", return_value="/usr/bin/xterm"):
            self.assertIsNone(clamd.build_command(["/does/not/exist"]))

    def test_script_is_valid_bash(self):
        import subprocess
        from cachy_sec.scanners import clamd
        self.assertEqual(subprocess.run(["bash", "-n", "-c", clamd.SCAN_SCRIPT]).returncode, 0)


class HistoryTest(unittest.TestCase):
    def setUp(self):
        import os
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"XDG_DATA_HOME": self.tmp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_record_list_and_view(self):
        import time
        from cachy_sec import history
        from cachy_sec.scanners.base import Finding
        rep = engine.Report([ScanResult("aur_scan", CRITICAL, [Finding(CRITICAL, "bad-pkg matches", "x", "bad-pkg")],
                                        "msg", log="raw tool output")])
        [p] = history.record(rep, "manual", time.time(), 1.234)
        self.assertTrue(p.exists())
        [e] = history.list_entries()
        self.assertEqual((e.kind, e.trigger, e.status), ("aur_scan", "manual", CRITICAL))
        txt = e.log_text()
        self.assertIn("raw tool output", txt)
        self.assertIn("bad-pkg matches", txt)

    def test_one_entry_per_scanner_including_unavailable(self):
        import time
        from cachy_sec import history
        rep = engine.Report([ScanResult("aur_malware_check", CLEAN, log="ok output"),
                             ScanResult("aur_scan", "error", [], "needs cargo", log="Not run: needs cargo")])
        paths = history.record(rep, "interval", time.time(), 2)
        self.assertEqual(len(paths), 2)
        by = {e.kind: e for e in history.list_entries()}
        self.assertEqual(by["aur_malware_check"].status, CLEAN)
        self.assertEqual(by["aur_scan"].status, "error")
        self.assertIn("Not run: needs cargo", by["aur_scan"].log_text())
        self.assertNotIn("ok output", by["aur_scan"].log_text())

    def test_history_records_the_process_id(self):
        import time
        from cachy_sec import history
        [p] = history.record(engine.Report([ScanResult("a", CLEAN)]), "manual", time.time(), 1)
        self.assertEqual(json.loads(p.read_text())["pid"], os.getpid())
        self.assertIn(f"Process:  {os.getpid()}", history.list_entries()[0].log_text())

    def test_skipped_scan_is_recorded(self):
        import time
        from cachy_sec import history
        history.record(engine.Report([], skipped="gaming mode active"), "interval", time.time(), 0)
        self.assertEqual(history.list_entries()[0].status, "skipped")

    def test_prune_and_clear(self):
        from cachy_sec import history
        d = history.history_dir()
        d.mkdir(parents=True)
        for i in range(15):
            (d / f"20260101T0000{i:02d}-packages.json").write_text("{}")
        history.prune(10)
        self.assertEqual(len(list(d.iterdir())), 10)
        self.assertEqual(history.clear(), 10)

    def test_binary_log_status(self):
        from cachy_sec import history
        d = history.history_dir()
        d.mkdir(parents=True)
        (d / "20260101T000001-binaries.log").write_text("x\nResult: THREATS FOUND (listed above).")
        (d / "20260101T000002-binaries.log").write_text("Result: no threats found.")
        st = {e.path.name: e.status for e in history.list_entries()}
        self.assertEqual(st["20260101T000001-binaries.log"], CRITICAL)
        self.assertEqual(st["20260101T000002-binaries.log"], CLEAN)

    def test_listing_sees_growing_log_and_new_files(self):
        from cachy_sec import history
        d = history.history_dir()
        d.mkdir(parents=True)
        f = d / "20260101T000001-binaries.log"
        f.write_text("scanning...\n")
        self.assertEqual(history.list_entries()[0].status, "unknown")  # still running
        f.write_text("scanning...\nResult: no threats found.\n")
        self.assertEqual(history.list_entries()[0].status, CLEAN)  # cache must not hide the change
        (d / "20260102T000001-binaries.log").write_text("x")
        self.assertEqual([e.path.name for e in history.list_entries()][0], "20260102T000001-binaries.log")
        f.unlink()
        self.assertEqual(len(history.list_entries()), 1)

    def test_corrupt_file_does_not_break_listing(self):
        from cachy_sec import history
        d = history.history_dir()
        d.mkdir(parents=True)
        (d / "20260101T000003-packages.json").write_text("not json")
        self.assertEqual(history.list_entries()[0].status, "unknown")


class ClamdScriptTest(unittest.TestCase):
    def test_script_logs_and_reports_exit(self):
        import os, subprocess, stat
        from cachy_sec.scanners import clamd
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "clamdscan"
            fake.write_text("#!/bin/sh\necho 'Eicar-Test: FOUND'\nexit 1\n")
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            log = Path(d) / "scan.log"
            env = dict(os.environ, PATH=f"{d}:{os.environ['PATH']}")
            subprocess.run(["bash", "-c", clamd.SCAN_SCRIPT, "clamdscan", str(log), d], env=env,
                           input=b"\n", capture_output=True, timeout=20)
            text = log.read_text()
            self.assertIn("Eicar-Test: FOUND", text)
            self.assertIn("Result: THREATS FOUND", text)


    def _script_result(self, body: str) -> str:
        import os, subprocess, stat
        from cachy_sec.scanners import clamd
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "clamdscan"
            fake.write_text("#!/bin/sh\n" + body)
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            log = Path(d) / "scan.log"
            env = dict(os.environ, PATH=f"{d}:{os.environ['PATH']}")
            subprocess.run(["bash", "-c", clamd.SCAN_SCRIPT, "clamdscan", str(log), d], env=env,
                           input=b"\n", capture_output=True, timeout=20)
            return log.read_text()

    def test_unreadable_files_without_detection_are_not_a_failure(self):
        text = self._script_result("echo '/usr/bin/x: Failed to open file'\necho 'Infected files: 0'\n"
                                   "echo 'Total errors: 2'\nexit 2\n")
        self.assertIn("Result: no threats found (2 file(s) could not be opened", text)
        self.assertNotIn("scan failed", text)

    def test_exit_2_without_summary_is_still_a_failure(self):
        text = self._script_result("echo 'ERROR: Could not connect to clamd'\nexit 2\n")
        self.assertIn("Result: scan failed (exit 2)", text)


class ClamdInterpretTest(unittest.TestCase):
    OUT = "/usr/bin/cupsd: Failed to open file\n\n----------- SCAN SUMMARY -----------\nInfected files: 0\nTotal errors: 16\n"

    def test_exit_codes(self):
        from cachy_sec.scanners.clamd import interpret
        self.assertEqual(interpret(2, self.OUT), ("clean", 16))  # the case from the bug report
        self.assertEqual(interpret(0, "Infected files: 0\n"), ("clean", 0))
        self.assertEqual(interpret(1, "x: Eicar FOUND\nInfected files: 1\n"), ("threats", 0))
        self.assertEqual(interpret(2, "x: Eicar FOUND\nInfected files: 1\nTotal errors: 3\n"), ("threats", 3))
        self.assertEqual(interpret(2, "ERROR: Could not connect to clamd\n")[0], "error")
        self.assertEqual(interpret(124, "timed out")[0], "error")

    def test_history_summary_mentions_skipped_files(self):
        from cachy_sec import history
        st, summary = history._binary_status("Result: no threats found (16 file(s) could not be opened and were skipped).")
        self.assertEqual(st, CLEAN)
        self.assertIn("16 unreadable", summary)


class AutostartTest(unittest.TestCase):
    def setUp(self):
        import os
        self.tmp = tempfile.TemporaryDirectory()
        self.sysdir = Path(self.tmp.name) / "sys"
        self.env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(Path(self.tmp.name) / "cfg"),
                                                "XDG_CONFIG_DIRS": str(self.sysdir)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_enable_disable_without_system_entry(self):
        from cachy_sec import autostart
        self.assertFalse(autostart.is_enabled())
        autostart.apply(True)
        self.assertTrue(autostart.is_enabled())
        self.assertIn("Exec=", autostart.user_file().read_text())
        autostart.apply(False)
        self.assertFalse(autostart.user_file().exists())

    def test_disable_overrides_system_entry_with_hidden(self):
        from cachy_sec import autostart
        (self.sysdir / "autostart").mkdir(parents=True)
        (self.sysdir / "autostart" / autostart.NAME).write_text("[Desktop Entry]\n")
        self.assertTrue(autostart.is_enabled())  # package-provided entry counts
        autostart.apply(False)
        self.assertFalse(autostart.is_enabled())
        self.assertIn("Hidden=true", autostart.user_file().read_text())
        autostart.apply(True)
        self.assertTrue(autostart.is_enabled())

    def test_exec_with_spaces_is_quoted(self):
        from cachy_sec import autostart
        with mock.patch("shutil.which", return_value="/opt/my app/bin/x"):
            self.assertEqual(autostart.exec_line(), '"/opt/my app/bin/x"')


class VendorTest(unittest.TestCase):
    def setUp(self):
        import os, subprocess
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"XDG_DATA_HOME": self.tmp.name})
        self.env.start()
        self.up = Path(self.tmp.name) / "upstream"
        g = lambda *a, cwd=self.up: subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True)
        self.up.mkdir()
        g("init", "-q", "-b", "main")
        g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "--allow-empty", "-qm", "one")
        self.g = g

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_clone_update_and_repair(self):
        import shutil
        from cachy_sec import vendor
        d = vendor.vendor_root() / "repo"
        url = self.up.as_uri()
        self.assertTrue(vendor.ensure_repo(url, d)[0])
        self.g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "--allow-empty", "-qm", "two")
        self.assertTrue(vendor.ensure_repo(url, d)[0])
        self.assertEqual(vendor.head(d), vendor.run(["git", "-C", str(self.up), "rev-parse", "HEAD"])[1].strip())
        # corrupt the checkout: HEAD points nowhere
        shutil.rmtree(d / ".git" / "objects")
        ok, _ = vendor.ensure_repo(url, d)
        self.assertTrue(ok)
        self.assertTrue(vendor._healthy(d))

    def test_refuses_outside_root(self):
        from cachy_sec import vendor
        ok, msg = vendor.ensure_repo(self.up.as_uri(), Path(self.tmp.name) / "elsewhere")
        self.assertFalse(ok)


class UpdaterTest(unittest.TestCase):
    def setUp(self):
        import os
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"XDG_DATA_HOME": self.tmp.name})
        self.env.start()
        d = Path(self.tmp.name)
        import subprocess
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(d / "k")], check=True)
        self.pub = (d / "k.pub").read_text().strip()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def _release(self, version="9.9.9", files=None):
        import io, subprocess, tarfile, hashlib
        d = Path(self.tmp.name)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as t:
            for name, content in (files or {"cachy_sec/__init__.py": f'__version__ = "{version}"\n'}).items():
                b = content.encode()
                ti = tarfile.TarInfo(name)
                ti.size = len(b)
                t.addfile(ti, io.BytesIO(b))
        blob = buf.getvalue()
        name = f"cachy-security-scanner-{version}.tar.gz"
        sums = f"{hashlib.sha256(blob).hexdigest()}  {name}\n".encode()
        (d / "SHA256SUMS").write_bytes(sums)
        subprocess.run(["ssh-keygen", "-Y", "sign", "-q", "-f", str(d / "k"), "-n", "cachy-security-scanner",
                        str(d / "SHA256SUMS")], check=True)
        sig = (d / "SHA256SUMS.sig").read_bytes()
        urls = {name: "https://github.com/x/t", "SHA256SUMS": "https://github.com/x/s", "SHA256SUMS.sig": "https://github.com/x/g"}
        blobs = {urls[name]: blob, urls["SHA256SUMS"]: sums, urls["SHA256SUMS.sig"]: sig}
        return updater.Release(version, urls), blobs

    def test_versions(self):
        self.assertEqual(updater.parse_version("v1.2.3"), (1, 2, 3))
        self.assertIsNone(updater.parse_version("1.2-evil"))
        self.assertTrue(updater.is_newer("99.0.0"))
        self.assertFalse(updater.is_newer("0.0.0"))

    def test_latest_release_picks_newest_complete_incl_prerelease(self):
        def rel(tag, names, **kw):
            return {"tag_name": tag, "draft": False, "prerelease": True, **kw,
                    "assets": [{"name": n, "browser_download_url": f"https://github.com/x/{n}"} for n in names]}
        full = lambda v: [f"cachy-security-scanner-{v}.tar.gz", "SHA256SUMS", "SHA256SUMS.sig"]
        data = [rel("v0.0.4", []),                       # failed build: no assets
                rel("v0.0.3", full("0.0.3")),
                rel("v0.0.9", full("0.0.9"), draft=True),  # drafts are ignored
                rel("v0.0.2", full("0.0.2"))]
        with mock.patch.object(updater, "_get", return_value=json.dumps(data).encode()):
            self.assertEqual(updater.latest_release().version, "0.0.3")
        with mock.patch.object(updater, "_get", return_value=b"[]"):
            self.assertIsNone(updater.latest_release())

    def test_describe_version_and_pending_update(self):
        with mock.patch.object(updater, "__version__", "0.0.0"):  # the release workflow stamps a real version first
            self.assertIn("development build", updater.describe_version())
        with mock.patch.object(updater, "__version__", "1.0.0"):
            self.assertEqual(updater.describe_version(), "1.0.0")
            rel, blobs = self._release(version="1.1.0")
            with mock.patch.object(updater, "_get", side_effect=lambda u, limit=0: blobs[u]):
                updater.install(rel, self.pub)
            self.assertIn("update 1.1.0 installed", updater.describe_version())

    def test_supervised_flag_or_parent_process(self):
        import os
        with mock.patch.dict(os.environ, {updater.SUPERVISED_ENV: "1"}):
            self.assertTrue(updater.supervised())
        os.environ.pop(updater.SUPERVISED_ENV, None)
        for parent, expected in (("/usr/bin/python /usr/bin/cachy-security-scanner ", True),   # older supervisor, no env flag
                                 ("/usr/bin/python -m cachy_sec.bootstrap ", True),
                                 ("-bash ", False), ("", False)):
            with mock.patch.object(updater, "_parent_cmdline", return_value=parent):
                self.assertEqual(updater.supervised(), expected, parent)

    def test_hosts(self):
        self.assertTrue(updater._host_ok("https://objects.githubusercontent.com/x"))
        self.assertFalse(updater._host_ok("https://evilgithub.com/x"))
        self.assertFalse(updater._host_ok("http://github.com/x"))

    def test_install_happy_path(self):
        rel, blobs = self._release()
        with mock.patch.object(updater, "_get", side_effect=lambda u, limit=0: blobs[u]):
            updater.install(rel, self.pub)
        v, p = updater.installed_overlay()
        self.assertEqual(v, "9.9.9")
        self.assertTrue((p / "cachy_sec" / "__init__.py").is_file())

    def test_fail_closed_without_key(self):
        rel, blobs = self._release()
        with mock.patch.object(updater, "_get", side_effect=lambda u, limit=0: blobs[u]):
            with self.assertRaises(updater.UpdateError):
                updater.install(rel, "")
        self.assertIsNone(updater.installed_overlay())

    def test_tampered_bundle_rejected(self):
        rel, blobs = self._release()
        tar_url = rel.assets["cachy-security-scanner-9.9.9.tar.gz"]
        blobs[tar_url] = blobs[tar_url] + b"x"
        with mock.patch.object(updater, "_get", side_effect=lambda u, limit=0: blobs[u]):
            with self.assertRaises(updater.UpdateError):
                updater.install(rel, self.pub)

    def test_wrong_signer_rejected(self):
        import subprocess
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(Path(self.tmp.name) / "o")], check=True)
        other = (Path(self.tmp.name) / "o.pub").read_text().strip()
        rel, blobs = self._release()
        with mock.patch.object(updater, "_get", side_effect=lambda u, limit=0: blobs[u]):
            with self.assertRaises(updater.UpdateError):
                updater.install(rel, other)

    def test_path_traversal_rejected(self):
        rel, blobs = self._release(files={"cachy_sec/__init__.py": '__version__ = "9.9.9"\n', "../evil": "x"})
        with mock.patch.object(updater, "_get", side_effect=lambda u, limit=0: blobs[u]):
            with self.assertRaises(updater.UpdateError):
                updater.install(rel, self.pub)
        self.assertFalse((Path(self.tmp.name) / "cachy-security-scanner" / "evil").exists())

    def test_tag_version_mismatch_rejected(self):
        rel, blobs = self._release(files={"cachy_sec/__init__.py": '__version__ = "1.0.0"\n'})
        with mock.patch.object(updater, "_get", side_effect=lambda u, limit=0: blobs[u]):
            with self.assertRaises(updater.UpdateError):
                updater.install(rel, self.pub)


class StatusIconTests(unittest.TestCase):
    def test_every_history_status_has_its_own_icon_file(self):
        from pathlib import Path
        from cachy_sec import icons
        self.assertEqual(len(set(icons.FOR_STATUS.values())), len(icons.FOR_STATUS))
        for status in icons.FOR_STATUS:
            self.assertTrue(Path(icons.for_status(status)).is_file(), status)
        self.assertTrue(Path(icons.for_status("something-new")).is_file())  # unknown values fall back


class ReportIconStatusTests(unittest.TestCase):
    def test_tray_status_distinguishes_warning_critical_error_clean_skipped(self):
        from cachy_sec import engine
        from cachy_sec.scanners.base import CLEAN, CRITICAL, ERROR, WARNING, Finding, ScanResult
        f = lambda sev: [Finding(sev, "t", "s")]
        R = engine.Report
        self.assertEqual(R([ScanResult("a", CLEAN)]).icon_status, "clean")
        self.assertEqual(R([ScanResult("a", WARNING, f(WARNING))]).icon_status, "warning")
        self.assertEqual(R([ScanResult("a", WARNING, f(WARNING)), ScanResult("b", CRITICAL, f(CRITICAL))]).icon_status, "critical")
        self.assertEqual(R([ScanResult("a", WARNING, f(WARNING)), ScanResult("b", ERROR)]).icon_status, "warning")
        self.assertEqual(R([ScanResult("a", CLEAN), ScanResult("b", ERROR)]).icon_status, "error")
        self.assertEqual(R([]).icon_status, "error")
        self.assertIsNone(R([], skipped="gaming").icon_status)


class BinaryBackgroundTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"XDG_DATA_HOME": self.tmp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def _run(self, rc, out="found: x\n"):
        from cachy_sec.scanners import clamd
        cp = mock.Mock(returncode=rc, stdout=out, stderr="")
        with mock.patch("cachy_sec.scanners.clamd.available", return_value=True), \
                mock.patch("subprocess.run", return_value=cp) as run:
            return clamd.run_background([self.tmp.name], True), run

    def test_results_map_to_states_and_history_status(self):
        from cachy_sec import history
        for rc, state, status in ((0, "clean", "clean"), (1, "threats", "critical"), (2, "error", "error")):
            (got, _), _run = self._run(rc)
            self.assertEqual(got, state)
            self.assertEqual(history.list_entries()[0].status, status)
            for p in history.history_dir().iterdir():
                p.unlink()

    def test_background_scan_with_unreadable_files_is_clean(self):
        from cachy_sec import history
        (state, msg), _ = self._run(2, "/usr/bin/cupsd: Failed to open file\nInfected files: 0\nTotal errors: 16\n")
        self.assertEqual(state, "clean")
        self.assertIn("16", msg)
        e = history.list_entries()[0]
        self.assertEqual(e.status, "clean")
        self.assertIn("unreadable", e.summary)

    def test_history_shows_the_trigger_of_a_scheduled_binary_scan(self):
        from cachy_sec import history
        from cachy_sec.scanners import clamd
        cp = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch("cachy_sec.scanners.clamd.available", return_value=True), mock.patch("subprocess.run", return_value=cp):
            clamd.run_background([self.tmp.name], True, "package change")
        self.assertEqual(history.list_entries()[0].trigger, "package change")

    def test_low_priority_prefix_and_last_scan_marker(self):
        from cachy_sec.scanners import clamd
        self.assertIsNone(clamd.seconds_since_last_scan())
        _, run = self._run(0)
        cmd = run.call_args.args[0]
        self.assertIn("clamdscan", cmd)
        self.assertIsNotNone(clamd.seconds_since_last_scan())
        self.assertLess(clamd.seconds_since_last_scan(), 5)

    def test_a_failed_scan_does_not_count_as_success(self):
        from cachy_sec.scanners import clamd
        self._run(2)
        self.assertIsNotNone(clamd.seconds_since_last_scan())
        self.assertIsNone(clamd.seconds_since_last_success())
        self._run(0)
        self.assertIsNotNone(clamd.seconds_since_last_success())

    def test_without_existing_paths_nothing_runs(self):
        from cachy_sec.scanners import clamd
        with mock.patch("cachy_sec.scanners.clamd.available", return_value=True), mock.patch("subprocess.run") as run:
            self.assertEqual(clamd.run_background(["/nonexistent/x"], True)[0], "unavailable")
            run.assert_not_called()


class UpdateCheckOnlyTests(unittest.TestCase):
    def test_check_available_does_not_install(self):
        from cachy_sec import updater
        rel = updater.Release("99.0.0", {})
        with mock.patch.object(updater, "latest_release", return_value=rel), mock.patch.object(updater, "install") as inst:
            self.assertEqual(updater.check_available(), ("available", "99.0.0"))
            inst.assert_not_called()
        with mock.patch.object(updater, "latest_release", return_value=None):
            self.assertEqual(updater.check_available()[0], "current")
        with mock.patch.object(updater, "latest_release", side_effect=updater.UpdateError("offline")):
            self.assertEqual(updater.check_available(), ("error", "offline"))


class DocsUrlTests(unittest.TestCase):
    def test_help_links_point_at_the_tag_of_the_running_version(self):
        from cachy_sec import updater
        with mock.patch.object(updater, "__version__", "1.2.3"):
            self.assertEqual(updater.docs_url("settings.md"),
                             "https://github.com/ruepp-jenkins/cachyos-security-scanner/blob/v1.2.3/docs/settings.md")
        with mock.patch.object(updater, "__version__", "0.0.0"):
            self.assertIn("/blob/master/docs/README.md", updater.docs_url())


if __name__ == "__main__":
    unittest.main()
