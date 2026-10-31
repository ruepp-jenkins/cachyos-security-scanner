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
        self.assertTrue(s.use_aur_malware_check and s.use_aur_scan)
        self.assertFalse(s.use_builtin_list)

    def test_old_settings_file_migrates_builtin_list_off(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.json"
            p.write_text(json.dumps({"use_builtin_list": True, "use_aur_scan": False}))
            s = Settings.load(p)
            self.assertFalse(s.use_builtin_list)
            self.assertFalse(s.use_aur_scan)  # other choices are kept
            s.use_builtin_list = True
            s.save(p)
            self.assertTrue(Settings.load(p).use_builtin_list)  # a deliberate opt-in after migration sticks

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
            p.write_text(json.dumps({"use_aur_scan": "no"}))
            self.assertTrue(Settings.load(p).use_aur_scan)


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
        with mock.patch.object(sc, "_cwd_cmd", return_value=(2, '{"compromised": ["bad"]}')):
            r = sc.scan()
            self.assertEqual((r.status, r.findings[0].package), (CRITICAL, "bad"))
        with mock.patch.object(sc, "_cwd_cmd", return_value=(0, "{}")):
            self.assertEqual(sc.scan().status, CLEAN)
        with mock.patch.object(sc, "_cwd_cmd", return_value=(3, "boom")):
            self.assertFalse(sc.scan().ok)

    def test_aur_scan(self):
        p = mock.patch.object(AurScan, "_binary", return_value="/x/aur-scan")
        p.start()
        self.addCleanup(p.stop)
        with mock.patch("cachy_sec.scanners.aur_scan.run", return_value=(1, "pkg foo: HIGH curl|bash")):
            r = AurScan().scan()
            self.assertEqual(r.status, WARNING)
            self.assertEqual(len(r.findings), 1)
        with mock.patch("cachy_sec.scanners.aur_scan.run", return_value=(127, "nope")):
            self.assertFalse(AurScan().scan().ok)

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
        self.assertEqual(r.results[0].status, "unavailable")

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
        self.assertEqual(engine.Report([ScanResult("a", "unavailable")]).kind, "bad")
        mixed = engine.Report([ScanResult("a", CLEAN), ScanResult("b", "unavailable", [], "x")])
        self.assertEqual(mixed.kind, "good")  # one scanner not runnable must not turn the tray red
        self.assertIn("not run: b", mixed.summary())
        self.assertEqual(engine.Report([], skipped="gaming mode active").kind, "info")


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
                             ScanResult("aur_scan", "unavailable", [], "needs cargo", log="Not run: needs cargo")])
        paths = history.record(rep, "interval", time.time(), 2)
        self.assertEqual(len(paths), 2)
        by = {e.kind: e for e in history.list_entries()}
        self.assertEqual(by["aur_malware_check"].status, CLEAN)
        self.assertEqual(by["aur_scan"].status, "unavailable")
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
        self.assertIn("development build", updater.describe_version())  # repo version is 0.0.0
        with mock.patch.object(updater, "__version__", "1.0.0"):
            self.assertEqual(updater.describe_version(), "1.0.0")
            rel, blobs = self._release(version="1.1.0")
            with mock.patch.object(updater, "_get", side_effect=lambda u, limit=0: blobs[u]):
                updater.install(rel, self.pub)
            self.assertIn("update 1.1.0 installed", updater.describe_version())

    def test_supervised_flag(self):
        import os
        with mock.patch.dict(os.environ, {updater.SUPERVISED_ENV: "1"}):
            self.assertTrue(updater.supervised())
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(updater.SUPERVISED_ENV, None)
            self.assertFalse(updater.supervised())

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
