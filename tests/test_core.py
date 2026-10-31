import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cachy_sec import engine, scheduler, updater  # noqa: E402
from cachy_sec.scanners import aur_malware_check as amc  # noqa: E402
from cachy_sec.scanners import builtin_list  # noqa: E402
from cachy_sec.scanners.aur_scan import AurScan  # noqa: E402
from cachy_sec.scanners.base import CLEAN, CRITICAL, WARNING, ScanResult  # noqa: E402
from cachy_sec.settings import Settings  # noqa: E402


class SettingsTest(unittest.TestCase):
    def test_defaults_enable_both_aur_scanners(self):
        s = Settings()
        self.assertTrue(s.use_aur_malware_check)
        self.assertFalse(s.use_aur_scan)  # heuristic, opt-in
        self.assertFalse(s.use_builtin_list)
        self.assertEqual(s.ignored_findings, ["SCAN-001"])

    def test_old_settings_file_migrates_builtin_list_off(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.json"
            p.write_text(json.dumps({"use_builtin_list": True, "use_aur_scan": True, "use_aur_malware_check": False}))
            s = Settings.load(p)
            self.assertFalse(s.use_builtin_list)
            self.assertFalse(s.use_aur_scan)  # became opt-in
            self.assertFalse(s.use_aur_malware_check)  # other choices are kept
            self.assertEqual(s.ignored_findings, ["SCAN-001"])
            s.use_builtin_list = True
            s.use_aur_scan = True
            s.save(p)
            again = Settings.load(p)
            self.assertTrue(again.use_builtin_list and again.use_aur_scan)  # a deliberate opt-in after migration sticks

    def test_roundtrip_and_clamping(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.json"
            s = Settings(mode="bogus", interval_minutes=1)
            s.save(p)
            loaded = Settings.load(p)
            self.assertEqual(loaded.mode, "interval")
            self.assertEqual(loaded.interval_minutes, 15)

    def test_bad_types_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.json"
            p.write_text(json.dumps({"use_aur_malware_check": "no"}))
            self.assertTrue(Settings.load(p).use_aur_malware_check)


class SchedulerTest(unittest.TestCase):
    def test_modes(self):
        self.assertIsNone(scheduler.interval_ms(Settings(mode="startup")))
        self.assertEqual(scheduler.interval_ms(Settings(mode="interval", interval_minutes=30)), 1_800_000)
        self.assertFalse(scheduler.scan_at_startup(Settings(mode="manual")))
        self.assertTrue(scheduler.scan_at_startup(Settings(mode="startup")))

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

    def test_builtin_list(self):
        self.assertEqual(builtin_list.parse_list("# c\nfoo\n\n bar \n"), {"foo", "bar"})
        with tempfile.TemporaryDirectory() as d, mock.patch.object(builtin_list, "cache_file", return_value=Path(d) / "l"):
            (Path(d) / "l").write_text("evil\n")
            with mock.patch("cachy_sec.scanners.builtin_list.run", return_value=(0, "evil\ngood\n")):
                r = builtin_list.BuiltinList().scan()
            self.assertEqual((r.status, r.findings[0].package), (CRITICAL, "evil"))


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

    def test_report_kind(self):
        from cachy_sec.scanners.base import Finding
        self.assertEqual(engine.Report([ScanResult("a", CLEAN)]).kind, "good")
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
                    _fp_entry(codes=["*"]), _fp_entry(reason="short"), _fp_entry(reference="http://x"),
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
        self.assertEqual(off.status, WARNING)  # opt-in: not used unless the checkbox is on
        on = AurScan(use_fp_list=True).scan()
        self.assertEqual(on.status, CLEAN)
        self.assertIn("hidden by the community false-positive list", on.log)
        self.assertIn("reported by someone, 2026-10-31", on.log)


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
            self.assertIn("clamdscan --fdpass", cmd[4])
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


if __name__ == "__main__":
    unittest.main()
