import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import restore_support as rs
from vps3xui import coordination as coord
from vps3xui.errors import ToolError
from vps3xui.restore import job as rj
from vps3xui.restore import runtime

BOOT_A = "1" * 32
BOOT_B = "2" * 32


class RuntimeTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.manifest, _dir, self.backup, self.plan, _request = rs.scenario(self.tmp)
        self.store = rj.RestoreJobStore(os.path.join(self.tmp, "state"))
        self.store.register(self.plan, rs.RELEASE_DIGEST, now=rs.NOW)
        self.job_id = self.plan["job_id"]
        self.unit = runtime.unit_name(self.job_id, "prepare", 1)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def assertCode(self, code, func, *args, **kwargs):
        with self.assertRaises(ToolError) as caught:
            func(*args, **kwargs)
        self.assertEqual(caught.exception.code, code, caught.exception.message)
        return caught.exception

    def launch(self, phase="launched", boot=BOOT_A, begin=True):
        with self.store.session(self.job_id) as job:
            if begin:
                job.begin_stage("prepare", self.plan, now=rs.NOW)
            runtime.record_launch(job, self.unit, phase, boot, now=rs.NOW)
        return self.store.open(self.job_id)


class LaunchTest(RuntimeTestCase):
    def test_argv_is_bounded_and_has_no_source_finalizer(self):
        job = self.store.open(self.job_id)
        argv = runtime.systemd_run_argv(job, "prepare", 1, "/opt/vps3xui/releases/r1", 3600, 120)
        self.assertEqual(argv[0], "systemd-run")
        self.assertIn("--unit=" + self.unit, argv)
        for prop in ("Type=exec", "RuntimeMaxSec=3600", "TimeoutStopSec=120", "KillMode=control-group"):
            self.assertIn("--property=" + prop, argv)
        self.assertFalse(any("ExecStopPost" in part or "finalizer" in part for part in argv))
        self.assertEqual(argv[-1], job.path)

    def test_argv_rejects_unbounded_or_unsafe_values(self):
        job = self.store.open(self.job_id)
        for runtime_max, stop in ((0, 120), (10 ** 6, 120), (3600, 5), (3600, True), ("3600", 120)):
            self.assertCode("E_CONTRACT", runtime.systemd_run_argv, job, "prepare", 1,
                            "/opt/r", runtime_max, stop)
        for release in ("relative", "/opt/../etc", "/opt/r;rm", "/opt/r x"):
            self.assertCode("E_CONTRACT", runtime.systemd_run_argv, job, "prepare", 1, release, 3600, 120)
        self.assertCode("E_CONTRACT", runtime.systemd_run_argv, job, "deploy", 1, "/opt/r", 3600, 120)

    def test_unit_name_is_derived_from_the_job(self):
        self.assertEqual(self.unit, "vps3xui-restore-prepare-%s-1" % self.job_id)
        self.assertTrue(runtime.UNIT_RE.match(runtime.unit_name(self.job_id, "certbot_activate", 2)))
        self.assertCode("E_CONTRACT", runtime.unit_name, "../x", "prepare", 1)

    def test_record_launch_needs_lock_and_own_unit(self):
        job = self.store.open(self.job_id)
        self.assertCode("E_CONTRACT", runtime.record_launch, job, self.unit, "pending", BOOT_A)
        foreign = runtime.unit_name("rst-" + "0" * 24, "prepare", 1)
        with self.store.session(self.job_id) as locked:
            self.assertCode("E_NOT_OWNED", runtime.record_launch, locked, foreign, "pending", BOOT_A)
            self.assertCode("E_NOT_OWNED", runtime.record_launch, locked, "ssh.service", "pending", BOOT_A)
            self.assertCode("E_CONTRACT", runtime.record_launch, locked, self.unit, "done", BOOT_A)
            marker = runtime.record_launch(locked, self.unit, "pending", BOOT_A, now=rs.NOW)
        self.assertEqual(runtime.read_launch(job), marker)
        mode = os.stat(os.path.join(job.path, runtime.LAUNCHED_FILE)).st_mode & 0o777
        self.assertEqual(mode, 0o600)


class ObserveTest(RuntimeTestCase):
    def test_not_launched(self):
        job = self.store.open(self.job_id)
        view = runtime.observe(job, BOOT_A, unit_active=lambda unit: self.fail("no query"))
        self.assertEqual((view["interrupted"], view["live"], view["reason"]), (False, False, "not_launched"))

    def test_live_unit_blocks_a_retry(self):
        job = self.launch()
        view = runtime.observe(job, BOOT_A, unit_active=lambda unit: True)
        self.assertEqual((view["live"], view["reason"]), (True, "unit_active"))
        self.assertCode("E_UNIT_BUSY", runtime.assert_not_live, job, BOOT_A, lambda unit: True)

    def test_unknown_liveness_is_not_stopped(self):
        job = self.launch()
        view = runtime.observe(job, BOOT_A, unit_active=lambda unit: None)
        self.assertEqual((view["interrupted"], view["live"]), (False, None))
        self.assertCode("E_PRECONDITION", runtime.assert_not_live, job, BOOT_A, lambda unit: None)

    def test_reboot_interrupts_without_restart(self):
        job = self.launch()
        view = runtime.observe(job, BOOT_B, unit_active=lambda unit: self.fail("no query"))
        self.assertEqual((view["interrupted"], view["reason"]), (True, "boot_changed"))
        with self.store.session(self.job_id) as locked:
            status = locked.reconcile(view, now=rs.NOW)
        self.assertEqual(status["state"], "preparing")
        self.assertEqual(status["interruption"]["reason"], "boot_changed")
        self.assertEqual(job.attempts()[-1]["result"], "interrupted")
        self.assertEqual(job.primary_failure()["code"], "E_INTERRUPTED")

    def test_pending_launch_is_unconfirmed(self):
        job = self.launch(phase="pending")
        view = runtime.observe(job, BOOT_A, unit_active=lambda unit: False)
        self.assertEqual((view["interrupted"], view["reason"]), (True, "unconfirmed_launch"))

    def test_inactive_unit_of_running_stage_is_interrupted(self):
        job = self.launch()
        view = runtime.observe(job, BOOT_A, unit_active=lambda unit: False)
        self.assertEqual((view["interrupted"], view["reason"]), (True, "unit_not_active"))
        self.assertEqual(runtime.assert_not_live(job, BOOT_A, lambda unit: False)["live"], False)

    def test_finished_stage_is_not_interrupted(self):
        self.launch(begin=False)
        job = self.store.open(self.job_id)
        view = runtime.observe(job, BOOT_A, unit_active=lambda unit: False)
        self.assertEqual((view["interrupted"], view["reason"]), (False, "unit_finished"))

    def test_foreign_or_corrupt_marker(self):
        job = self.launch()
        path = os.path.join(job.path, runtime.LAUNCHED_FILE)
        coord.replace_json(path, {"job_id": "rst-" + "0" * 24, "unit_name": self.unit})
        view = runtime.observe(job, BOOT_A, unit_active=lambda unit: False)
        self.assertEqual((view["interrupted"], view["live"], view["reason"]),
                         (True, None, "launch_marker_invalid"))
        coord.atomic_write_bytes(path, b"{")
        self.assertCode("E_PRECONDITION", runtime.assert_not_live, job, BOOT_A, lambda unit: False)


class RunBoundedTest(unittest.TestCase):
    def test_exit_code_is_reported(self):
        self.assertEqual(runtime.run_bounded([sys.executable, "-c", "raise SystemExit(3)"], 30),
                         ("exited", 3))

    def test_timeout_is_unknown(self):
        self.assertEqual(runtime.run_bounded([sys.executable, "-c", "import time; time.sleep(30)"], 1),
                         ("unknown", None))

    def test_missing_program_did_not_start(self):
        self.assertEqual(runtime.run_bounded(["/nonexistent/vps3xui-tool"], 5), ("not_started", None))

    def test_unobservable_end_is_unknown(self):
        def broken(*_args, **_kwargs):
            raise PermissionError("denied")

        self.assertEqual(runtime.run_bounded(["x"], 5, runner=broken), ("unknown", None))

    def test_output_is_discarded_and_bounds_are_checked(self):
        seen = {}

        def runner(argv, **kwargs):
            seen.update(kwargs)
            return subprocess.CompletedProcess(argv, 0)

        self.assertEqual(runtime.run_bounded(["true"], 5, runner=runner), ("exited", 0))
        self.assertEqual(seen["stdout"], subprocess.DEVNULL)
        self.assertEqual(seen["stderr"], subprocess.DEVNULL)
        for bad in (0, 10 ** 6, True):
            with self.assertRaises(ToolError):
                runtime.run_bounded(["true"], bad)
        with self.assertRaises(ToolError):
            runtime.run_bounded([], 5)


if __name__ == "__main__":
    unittest.main()
