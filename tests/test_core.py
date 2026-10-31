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
        p = history.record(rep, "manual", time.time(), 1.234)
        self.assertTrue(p.exists())
        [e] = history.list_entries()
        self.assertEqual((e.kind, e.trigger, e.status), ("packages", "manual", CRITICAL))
        txt = e.log_text()
        self.assertIn("raw tool output", txt)
        self.assertIn("bad-pkg matches", txt)

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
        self.assertFalse(updater.is_newer("0.0.1"))

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
