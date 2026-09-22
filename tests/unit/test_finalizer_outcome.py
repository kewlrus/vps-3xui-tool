"""The finalizer must not turn a failed unit into a proven success (item 4).

An automatic (``ExecStopPost``) finalization may publish ``COMPLETE`` only when
the unit reported the *complete* triple ``SERVICE_RESULT=success``,
``EXIT_CODE=exited``, ``EXIT_STATUS=0``. Absent (``None``/``{}``), missing,
blank, unexpected or failed evidence is a refusal, never a success. The tests
below exercise both the direct ``finalizer.recover`` call and the shipped
``bin/vps3xui-finalizer`` entrypoint that systemd actually runs.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import support
from vps3xui import coordination as coord
from vps3xui.inventory import Inventory
from vps3xui.plan import build_plan
from vps3xui.verify import verify_directory
from vps3xui.worker import finalizer
from vps3xui.worker.backup_worker import BackupWorker
from vps3xui.worker.jobctx import REPORT_FILE, JobContext

SUCCESS_RESULT = {"SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": "0"}

# Every entry is an unacceptable unit outcome: none may publish COMPLETE.
FAIL_CASES = [
    ("absent_none", None),
    ("absent_empty", {}),
    ("missing_service_result", {"EXIT_CODE": "exited", "EXIT_STATUS": "0"}),
    ("missing_exit_code", {"SERVICE_RESULT": "success", "EXIT_STATUS": "0"}),
    ("missing_exit_status", {"SERVICE_RESULT": "success", "EXIT_CODE": "exited"}),
    ("blank_service_result", {"SERVICE_RESULT": "", "EXIT_CODE": "exited", "EXIT_STATUS": "0"}),
    ("blank_exit_code", {"SERVICE_RESULT": "success", "EXIT_CODE": "", "EXIT_STATUS": "0"}),
    ("blank_exit_status", {"SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": ""}),
    ("timeout", {"SERVICE_RESULT": "timeout", "EXIT_CODE": "killed", "EXIT_STATUS": "9"}),
    ("signal", {"SERVICE_RESULT": "signal", "EXIT_CODE": "killed", "EXIT_STATUS": "9"}),
    ("exit_code_failed", {"SERVICE_RESULT": "exit-code", "EXIT_CODE": "exited", "EXIT_STATUS": "1"}),
    ("oom_kill", {"SERVICE_RESULT": "oom-kill", "EXIT_CODE": "killed", "EXIT_STATUS": "137"}),
    ("invalid_service_result", {"SERVICE_RESULT": "bogus", "EXIT_CODE": "exited", "EXIT_STATUS": "0"}),
    ("invalid_exit_code", {"SERVICE_RESULT": "success", "EXIT_CODE": "killed", "EXIT_STATUS": "0"}),
    ("blank_nonzero_status", {"SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": "1"}),
]


def copied_job(tmp, faults=None, job_id="req-final-1"):
    manifest = support.approved_manifest(tmp)
    inventory = Inventory.from_probe(support.synthetic_probe())
    plan = build_plan(manifest, inventory, support.HOST_KEY)
    job_dir = os.path.join(tmp, "jobs", job_id)
    backup_dir = os.path.join(tmp, "backups", job_id)
    support.seed_job(job_dir, {
        "schema_version": 1,
        "request_id": job_id,
        "job_id": job_id,
        "manifest_id": manifest.manifest_id,
        "plan_digest": plan["identity"],
        "machine_id": support.MACHINE_ID,
        "host_key_fingerprint": support.HOST_KEY,
        "backup_dir": backup_dir,
        "stop_containers": plan["stop_containers"],
        "leave_stopped": plan["leave_stopped"],
        "required_bytes_estimate": 5_000_000_000,
    }, plan, manifest)
    system = support.SyntheticSystem(manifest, os.path.join(tmp, "system"), faults=faults)
    worker = BackupWorker(system, job_dir, manifest)
    worker.run()
    return manifest, system, job_dir, backup_dir


class FinalizerOutcomeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="finalizer-")

    def _fresh_job(self, name):
        tmp = tempfile.mkdtemp(prefix="finalizer-%s-" % name)
        return copied_job(tmp)

    def test_timeout_unit_never_succeeds(self):
        manifest, system, job_dir, backup_dir = copied_job(self.tmp)
        result = finalizer.recover(job_dir, system, manifest,
                                   service_result={"SERVICE_RESULT": "timeout"})
        self.assertNotEqual(result["state"], "succeeded")
        self.assertEqual(result["state"], "failed")
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        self.assertFalse(verify_directory(backup_dir, manifest, require_complete=True).ok)

    def test_killed_unit_never_succeeds(self):
        manifest, system, job_dir, backup_dir = copied_job(self.tmp)
        result = finalizer.recover(job_dir, system, manifest,
                                   service_result={"SERVICE_RESULT": "signal",
                                                   "EXIT_CODE": "killed", "EXIT_STATUS": "9"})
        self.assertNotEqual(result["state"], "succeeded")
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))

    def test_nonzero_exit_never_succeeds(self):
        manifest, system, job_dir, backup_dir = copied_job(self.tmp)
        result = finalizer.recover(job_dir, system, manifest,
                                   service_result={"SERVICE_RESULT": "exit-code",
                                                   "EXIT_CODE": "exited", "EXIT_STATUS": "1"})
        self.assertNotEqual(result["state"], "succeeded")
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))

    def test_absent_and_partial_unit_evidence_never_succeeds(self):
        for name, service_result in FAIL_CASES:
            with self.subTest(case=name):
                manifest, system, job_dir, backup_dir = self._fresh_job(name)
                result = finalizer.recover(job_dir, system, manifest,
                                           service_result=service_result)
                self.assertEqual(result["state"], "failed", (name, result))
                self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")), name)
                self.assertFalse(
                    verify_directory(backup_dir, manifest, require_complete=True).ok, name)
                report = JobContext(job_dir).read_json(REPORT_FILE)
                failure = report["original_failure"]
                self.assertEqual(failure["code"], "E_UNIT_FAILED", name)
                reason = failure["detail"]["reason"]
                if service_result is None:
                    self.assertEqual(reason, "unit_evidence_missing", name)
                    self.assertNotIn("unit_result", report, name)
                    continue
                # The actual unit metadata is retained next to the error.
                self.assertEqual(report["unit_result"], service_result, name)
                expected = "unit_evidence_missing" if service_result == {} else "unit_evidence_incomplete"
                self.assertEqual(reason, expected, name)

    def test_confirmed_success_publishes_complete(self):
        manifest, system, job_dir, backup_dir = copied_job(self.tmp)
        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        self.assertEqual(result["state"], "succeeded")
        self.assertTrue(os.path.isfile(os.path.join(backup_dir, "COMPLETE")))
        report = JobContext(job_dir).read_json(REPORT_FILE)
        self.assertEqual(report["unit_result"], SUCCESS_RESULT)
        self.assertIsNone(report["original_failure"])

    def test_explicit_recover_does_not_upgrade_a_partial_copy(self):
        manifest, system, job_dir, backup_dir = copied_job(self.tmp)
        result = finalizer.recover(job_dir, system, manifest, explicit=True)
        self.assertNotEqual(result["state"], "succeeded")
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))

    def test_explicit_recover_refuses_success_evidence_too(self):
        manifest, system, job_dir, backup_dir = copied_job(self.tmp)
        result = finalizer.recover(job_dir, system, manifest, explicit=True,
                                   service_result=dict(SUCCESS_RESULT))
        self.assertNotEqual(result["state"], "succeeded")
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))

    def test_marker_is_the_final_write_and_failure_leaves_no_success(self):
        manifest, system, job_dir, backup_dir = copied_job(self.tmp)
        with mock.patch.object(finalizer, "_publish_complete",
                               side_effect=finalizer.ToolError("E_STATE_WRITE_FAILED", "boom")):
            with self.assertRaises(finalizer.ToolError):
                finalizer.recover(job_dir, system, manifest,
                                  service_result=dict(SUCCESS_RESULT))
        # The report/state were written first, but with no marker the job is not
        # a valid portable success.
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        self.assertFalse(verify_directory(backup_dir, manifest, require_complete=True).ok)
        complete, state = coord.is_complete(job_dir)
        self.assertFalse(complete)

    def test_report_is_persisted_before_the_marker(self):
        manifest, system, job_dir, backup_dir = copied_job(self.tmp)
        seen = {}
        real_publish = finalizer._publish_complete

        def spy_publish(ctx, target):
            with open(os.path.join(job_dir, REPORT_FILE), "r", encoding="utf-8") as handle:
                seen["report"] = json.load(handle)
            real_publish(ctx, target)

        with mock.patch.object(finalizer, "_publish_complete", spy_publish):
            finalizer.recover(job_dir, system, manifest,
                              service_result=dict(SUCCESS_RESULT))
        self.assertEqual(seen["report"]["state"], "succeeded")
        self.assertTrue(os.path.isfile(os.path.join(backup_dir, "COMPLETE")))


FINALIZER_ENTRYPOINT = "bin/vps3xui-finalizer"

# Injected as ``<release_dir>/sitecustomize.py``. The shipped entrypoint sets
# ``PYTHONPATH`` to its own release directory, so Python imports this before the
# finalizer module runs and the real ``RealSystem`` never touches the host.
FAKE_SITECUSTOMIZE = '''"""Test-only host adapter for the finalizer entrypoint tests."""
import json
import os
import sys

sys.path.insert(0, os.environ["VPS3XUI_FAKE_REPO"])

with open(os.path.join(os.environ["VPS3XUI_FAKE_JOB_DIR"], "initial-state.json"),
          "r", encoding="utf-8") as _handle:
    _INITIAL = json.load(_handle)


class FakeSystem(object):
    def __init__(self, backup_root="/var/backups/vps3xui", release_dir=None):
        self.backup_root = backup_root
        self.release_dir = release_dir

    def machine_id(self):
        return _INITIAL["machine_id"]

    def start_containers(self, ids):
        pass

    def container_states(self, names):
        recorded = {item["name"]: item for item in _INITIAL.get("stop_containers") or []}
        return {name: {"name": name, "id": recorded[name]["id"], "running": True}
                for name in names if name in recorded}

    def restore_certbot_triggers(self, state, manifest):
        pass


from vps3xui.worker import system as _system_module

_system_module.RealSystem = FakeSystem
'''


class FinalizerEntrypointTest(unittest.TestCase):
    """The shipped entrypoint (what systemd runs) with real ExecStopPost env."""

    def setUp(self):
        self.tmp = support.temp_state_dir("finalizer-entry-")
        self.release_dir = os.path.join(self.tmp, "release")
        bindir = os.path.join(self.release_dir, "bin")
        os.makedirs(bindir, mode=0o700)
        self.entrypoint = os.path.join(self.release_dir, FINALIZER_ENTRYPOINT)
        shutil.copyfile(os.path.join(support.REPO_ROOT, FINALIZER_ENTRYPOINT), self.entrypoint)
        os.chmod(self.entrypoint, 0o755)
        with open(os.path.join(self.release_dir, "sitecustomize.py"), "w",
                  encoding="utf-8") as handle:
            handle.write(FAKE_SITECUSTOMIZE)

    def _run_entrypoint(self, job_dir, env_overrides):
        env = dict(os.environ)
        for key in ("SERVICE_RESULT", "EXIT_CODE", "EXIT_STATUS"):
            env.pop(key, None)
        env.update(env_overrides)
        env["VPS3XUI_FAKE_REPO"] = support.REPO_ROOT
        env["VPS3XUI_FAKE_JOB_DIR"] = job_dir
        env["VPS3XUI_RELEASE_DIR"] = self.release_dir
        proc = subprocess.run([self.entrypoint, job_dir, "--release-dir", self.release_dir],
                              cwd=support.REPO_ROOT, env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
        stdout = proc.stdout.decode("utf-8", "replace").strip().splitlines()
        self.assertTrue(stdout, proc.stderr.decode("utf-8", "replace"))
        return proc.returncode, json.loads(stdout[-1])

    def _fresh_job(self, name):
        tmp = tempfile.mkdtemp(prefix="finalizer-entry-%s-" % name)
        return copied_job(tmp)

    def test_entrypoint_report_table(self):
        for name, service_result in FAIL_CASES:
            with self.subTest(case=name):
                manifest, _system, job_dir, backup_dir = self._fresh_job(name)
                code, result = self._run_entrypoint(job_dir, service_result or {})
                self.assertNotEqual(code, 0, name)
                self.assertEqual(result["state"], "failed", (name, result))
                self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")), name)
                self.assertFalse(
                    verify_directory(backup_dir, manifest, require_complete=True).ok, name)
                report = JobContext(job_dir).read_json(REPORT_FILE)
                self.assertEqual(report["original_failure"]["code"], "E_UNIT_FAILED", name)

    def test_entrypoint_complete_success_env_publishes_complete(self):
        manifest, _system, job_dir, backup_dir = self._fresh_job("complete")
        code, result = self._run_entrypoint(job_dir, dict(SUCCESS_RESULT))
        self.assertEqual(code, 0, result)
        self.assertEqual(result["state"], "succeeded", result)
        self.assertTrue(os.path.isfile(os.path.join(backup_dir, "COMPLETE")))
        self.assertTrue(verify_directory(backup_dir, manifest, require_complete=True).ok)
        report = JobContext(job_dir).read_json(REPORT_FILE)
        self.assertEqual(report["unit_result"], SUCCESS_RESULT)
        self.assertIsNone(report["original_failure"])


if __name__ == "__main__":
    unittest.main()
