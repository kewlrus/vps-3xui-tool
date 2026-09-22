"""F5: a proven preflight-only failure must end terminal ``failed``.

A worker that fails before any host effect (before ``changes_started``) records
an explicit, job/request-bound no-effects proof in ``report.json``. The
independent finalizer turns that into a terminal ``failed`` without starting a
container, restoring a Certbot trigger or writing a marker, so the job no longer
blocks new work. The same decision must refuse anything ambiguous -- a missing,
corrupt, foreign or fabricated proof, a state that advanced past preflight, an
unreadable recorded original state, or an injected ``COMPLETE`` -- and leave the
job ``unknown``/``recovery_required``.

These tests run the real worker and the real finalizer (including the shipped
``bin/vps3xui-finalizer`` entrypoint) with the real coordination module.
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import support
from vps3xui import coordination as coord
from vps3xui.inventory import Inventory
from vps3xui.plan import build_plan
from vps3xui.worker import finalizer
from vps3xui.worker.backup_worker import (
    PREFLIGHT_EVIDENCE_KEY,
    BackupWorker,
)
from vps3xui.worker.jobctx import (
    COMPLETE_MARKER,
    INITIAL_STATE_FILE,
    PLAN_FILE,
    REPORT_FILE,
    STATE_FILE,
    JobContext,
)

REMOTE_OPS = os.path.join(support.REPO_ROOT, "vps3xui", "remote_ops.py")
FINALIZER_ENTRYPOINT = "bin/vps3xui-finalizer"


def run_ops(root, command, *args):
    argv = [sys.executable, REMOTE_OPS, root, command] + list(args)
    result = subprocess.run(argv, capture_output=True, timeout=60)
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
    except ValueError:
        payload = None
    return result.returncode, payload


def reserve_only(root, job_id, plan_digest="d", manifest_id="m"):
    payload = {
        "job_id": job_id,
        "request": {"job_id": job_id, "plan_digest": plan_digest, "manifest_id": manifest_id},
        "plan": {"identity": plan_digest},
        "launch": {},
    }
    token = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    return run_ops(root, "reserve-and-launch", token)


def preflight_job(tmp, job_id="req-worker-1", faults=None, mutate=None):
    """Seed a real job and return the real worker/system around it."""
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
    if mutate is not None:
        mutate(job_dir)
    # A unique host root per job so repeated subtests never collide on the
    # population symlinks the synthetic host writes.
    system_root = tempfile.mkdtemp(prefix="host-%s-" % job_id, dir=tmp)
    system = support.SyntheticSystem(manifest, system_root, faults=faults)
    worker = BackupWorker(system, job_dir, manifest)
    return manifest, system, worker, job_dir, backup_dir


def drop_plan(job_dir):
    os.unlink(os.path.join(job_dir, PLAN_FILE))


class PreflightNoEffectsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="f5-preflight-")

    def _run_worker(self, job_id="req-worker-1", faults=None, mutate=None):
        manifest, system, worker, job_dir, backup_dir = preflight_job(
            self.tmp, job_id=job_id, faults=faults, mutate=mutate)
        report = worker.run()
        return manifest, system, worker, job_dir, backup_dir, report

    def test_each_preflight_fault_proves_no_effects_and_keeps_first_cause(self):
        cases = [
            ("container_drift", dict(faults=None),
             lambda system: system.containers.__setitem__(
                 "litellm", {"id": "id-changed", "running": True}), "E_PLAN_STALE"),
            ("plan_missing", dict(mutate=drop_plan), None, "E_PLAN_STALE"),
            ("insufficient_space", dict(faults={"low_space": True}), None, "E_PRECONDITION"),
            ("lease", dict(faults=None),
             lambda system: setattr(system, "lease_active", True), "E_PRECONDITION"),
            ("initial_state_write_failure", dict(patch_write=True), None, "E_EXECUTION"),
        ]
        for name, kwargs, tweak, expected_code in cases:
            with self.subTest(case=name):
                manifest, system, worker, job_dir, backup_dir = preflight_job(
                    self.tmp, job_id="req-%s" % name,
                    faults=kwargs.get("faults"), mutate=kwargs.get("mutate"))
                if kwargs.get("patch_write"):
                    real_write = JobContext.write_json

                    def failing_write(self, fname, obj, mode=0o600):
                        if fname == INITIAL_STATE_FILE:
                            raise OSError("injected initial-state write failure")
                        return real_write(self, fname, obj, mode)

                    with mock.patch.object(JobContext, "write_json", failing_write):
                        report = worker.run()
                else:
                    if tweak is not None:
                        tweak(system)
                    report = worker.run()

                self.assertEqual(report["state"], "failed", report)
                self.assertEqual(report["original_failure"]["code"], expected_code, report)
                evidence = report.get(PREFLIGHT_EVIDENCE_KEY)
                self.assertIsInstance(evidence, dict, report)
                self.assertIs(evidence["effects_started"], False, report)
                self.assertEqual(evidence["phase"], "preflight", report)
                self.assertEqual(evidence["job_id"], os.path.basename(job_dir), report)
                self.assertEqual(evidence["request_id"], os.path.basename(job_dir), report)

                result = finalizer.recover(job_dir, system, manifest)
                self.assertEqual(result["state"], "failed", result)
                self.assertEqual(result["reason"], "no_effects_preflight_failure", result)
                self.assertTrue(result["no_effects"], result)
                self.assertIs(result["effects_started"], False, result)
                # No host effect was attempted or claimed.
                self.assertEqual(system.started_ids, [], result)
                self.assertEqual(system.stopped_ids, [], result)
                self.assertEqual(system.start_batches, [], result)
                self.assertEqual(system.stop_batches, [], result)
                self.assertFalse(system.masked_runtime, result)
                self.assertFalse(os.path.exists(backup_dir), result)
                terminal = JobContext(job_dir).read_json(REPORT_FILE)
                self.assertEqual(terminal["state"], "failed", terminal)
                self.assertEqual(terminal["original_failure"]["code"], expected_code, terminal)
                self.assertEqual(terminal["source_runtime_recovery"], "not_run", terminal)
                self.assertTrue(terminal["recovery"]["no_effects"], terminal)
                self.assertEqual(coord.is_complete(job_dir), (True, "failed"))

    def test_finalizer_report_preserves_the_job_and_request_binding(self):
        manifest, system, worker, job_dir, backup_dir, report = self._run_worker(
            job_id="req-bind", faults={"low_space": True})
        evidence = report[PREFLIGHT_EVIDENCE_KEY]
        request = JobContext(job_dir).read_json("request.json")
        self.assertEqual(evidence["plan_digest"], request["plan_digest"])
        self.assertEqual(evidence["request_id"], request["request_id"])

        finalizer.recover(job_dir, system, manifest)
        terminal = JobContext(job_dir).read_json(REPORT_FILE)
        # The proof is retained for audit even in the terminal report.
        self.assertEqual(terminal[PREFLIGHT_EVIDENCE_KEY], evidence)

    def test_present_preflight_initial_state_still_fastpaths(self):
        # A failure after the preflight snapshot was durably written but still
        # before ``changes_started`` (here: the write-confirmation check) must
        # also terminalize without the identity-gated recovery mutations.
        manifest, system, worker, job_dir, backup_dir = preflight_job(
            self.tmp, job_id="req-present-initial")
        real_exists = JobContext.exists

        def missing_initial(self, name):
            if name == INITIAL_STATE_FILE:
                return False
            return real_exists(self, name)

        with mock.patch.object(JobContext, "exists", missing_initial):
            report = worker.run()
        self.assertEqual(report["state"], "failed", report)
        self.assertEqual(report["original_failure"]["code"], "E_STATE_WRITE_FAILED", report)
        self.assertIs(report[PREFLIGHT_EVIDENCE_KEY]["effects_started"], False, report)
        self.assertTrue(os.path.isfile(os.path.join(job_dir, INITIAL_STATE_FILE)))

        result = finalizer.recover(job_dir, system, manifest)
        self.assertEqual(result["state"], "failed", result)
        self.assertTrue(result["no_effects"], result)
        self.assertEqual(system.started_ids, [], result)
        self.assertEqual(system.stopped_ids, [], result)
        self.assertFalse(system.masked_runtime, result)
        self.assertFalse(os.path.exists(backup_dir), result)

    def test_explicit_recover_is_idempotent_and_local_remote_status_terminal(self):
        manifest, system, worker, job_dir, backup_dir, report = self._run_worker(
            job_id="req-idem", faults={"low_space": True})
        root = os.path.dirname(os.path.dirname(job_dir))

        first = finalizer.recover(job_dir, system, manifest)
        second = finalizer.recover(job_dir, system, manifest, explicit=True)
        third = finalizer.recover(job_dir, system, manifest, explicit=True)
        for result in (first, second, third):
            self.assertEqual(result["state"], "failed", result)
            self.assertTrue(result["no_effects"], result)
        self.assertEqual(system.started_ids, [])
        self.assertEqual(system.stopped_ids, [])
        self.assertFalse(os.path.exists(backup_dir))

        # Local terminal status and no blocking job.
        self.assertEqual(coord.is_complete(job_dir), (True, "failed"))
        self.assertEqual(coord.scan_blocking(root), [])
        code, payload = run_ops(root, "blocking")
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["blocking"], [])
        code, payload = run_ops(root, "status", "req-idem")
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["state"], "failed", payload)
        self.assertTrue(payload["operation_complete"], payload)

        # A real new reservation is accepted after the terminal failure.
        code, payload = reserve_only(root, "req-after-idem")
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload["reserved"], payload)

    def test_worker_rerun_never_overrides_the_recorded_failure(self):
        manifest, system, worker, job_dir, backup_dir, report = self._run_worker(
            job_id="req-rerun", faults={"low_space": True})
        evidence = report[PREFLIGHT_EVIDENCE_KEY]
        finalizer.recover(job_dir, system, manifest)

        rerun = BackupWorker(system, job_dir, manifest).run()
        self.assertEqual(rerun["state"], "failed", rerun)
        self.assertEqual(rerun[PREFLIGHT_EVIDENCE_KEY], evidence)
        self.assertEqual(system.stopped_ids, [])
        self.assertEqual(system.copy_calls, [])

    def test_shipped_entrypoint_finalizes_preflight_failure_without_host_calls(self):
        manifest, system, worker, job_dir, backup_dir, report = self._run_worker(
            job_id="req-entry", faults={"low_space": True})

        release = os.path.join(self.tmp, "release")
        os.makedirs(os.path.join(release, "bin"), mode=0o700)
        entrypoint = os.path.join(release, FINALIZER_ENTRYPOINT)
        shutil.copyfile(os.path.join(support.REPO_ROOT, FINALIZER_ENTRYPOINT), entrypoint)
        os.chmod(entrypoint, 0o755)
        host_log = os.path.join(self.tmp, "host-calls.log")
        with open(os.path.join(release, "sitecustomize.py"), "w", encoding="utf-8") as handle:
            handle.write(FAKE_SITECUSTOMIZE)

        env = dict(os.environ)
        env["VPS3XUI_FAKE_REPO"] = support.REPO_ROOT
        env["VPS3XUI_FAKE_HOST_LOG"] = host_log
        env["VPS3XUI_RELEASE_DIR"] = release
        proc = subprocess.run([entrypoint, job_dir, "--release-dir", release],
                              cwd=support.REPO_ROOT, env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
        stdout = proc.stdout.decode("utf-8", "replace").strip().splitlines()
        self.assertTrue(stdout, proc.stderr.decode("utf-8", "replace"))
        result = json.loads(stdout[-1])
        self.assertEqual(proc.returncode, 1, result)
        self.assertEqual(result["state"], "failed", result)
        self.assertTrue(result["no_effects"], result)
        # The fake host records any Docker/systemd call; the fastpath makes none.
        self.assertFalse(os.path.exists(host_log), "the finalizer touched the host")
        self.assertFalse(os.path.exists(backup_dir))
        self.assertEqual(JobContext(job_dir).read_json(REPORT_FILE)["state"], "failed")


class PreflightNegativeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="f5-negative-")

    def _failed_job(self, job_id="req-neg", tmp=None):
        manifest, system, worker, job_dir, backup_dir = preflight_job(
            tmp or self.tmp, job_id=job_id, faults={"low_space": True})
        report = worker.run()
        assert report["state"] == "failed", report
        return manifest, system, job_dir, backup_dir

    def _assert_unresolved(self, manifest, system, job_dir, backup_dir):
        result = finalizer.recover(job_dir, system, manifest)
        self.assertNotEqual(result["state"], "failed", result)
        self.assertFalse(result.get("no_effects"), result)
        self.assertEqual(system.started_ids, [], result)
        self.assertEqual(system.stopped_ids, [], result)
        self.assertFalse(system.masked_runtime, result)
        self.assertFalse(os.path.exists(backup_dir), result)
        self.assertFalse(coord.is_complete(job_dir)[0])
        return result

    def test_ambiguous_report_without_evidence_stays_unknown(self):
        manifest, system, job_dir, backup_dir = self._failed_job("req-noevidence")
        ctx = JobContext(job_dir)
        report = ctx.read_json(REPORT_FILE)
        report.pop(PREFLIGHT_EVIDENCE_KEY)
        ctx.write_json(REPORT_FILE, report)
        result = self._assert_unresolved(manifest, system, job_dir, backup_dir)
        self.assertEqual(result["state"], "unknown", result)

    def test_abrupt_crash_without_evidence_stays_unknown(self):
        manifest, system, worker, job_dir, backup_dir = preflight_job(
            self.tmp, job_id="req-crash")
        # A worker killed mid-preflight leaves no report and no proof.
        ctx = JobContext(job_dir)
        ctx.write_json(STATE_FILE, {"state": "preflight"})
        result = self._assert_unresolved(manifest, system, job_dir, backup_dir)
        self.assertEqual(result["state"], "unknown", result)

    def test_fabricated_or_foreign_evidence_is_refused(self):
        for name in ("not_an_object", "missing_flag", "flag_true",
                     "phase_past_preflight", "wrong_job", "wrong_request",
                     "wrong_plan"):
            with self.subTest(case=name):
                job_id = "req-neg-%s" % name
                # A fresh root per case: an unresolved job legitimately blocks
                # the next worker run in the same root.
                tmp = tempfile.mkdtemp(prefix="f5-neg-%s-" % name)
                manifest, system, job_dir, backup_dir = self._failed_job(job_id, tmp)
                ctx = JobContext(job_dir)
                request = ctx.read_json("request.json")
                if name == "not_an_object":
                    value = "garbage"
                else:
                    evidence = {
                        "effects_started": False,
                        "phase": "preflight",
                        "job_id": job_id,
                        "request_id": request["request_id"],
                        "plan_digest": request["plan_digest"],
                    }
                    value = evidence
                if name == "missing_flag":
                    value.pop("effects_started")
                elif name == "flag_true":
                    value["effects_started"] = True
                elif name == "phase_past_preflight":
                    value["phase"] = "quiescing"
                elif name == "wrong_job":
                    value["job_id"] = "req-other"
                elif name == "wrong_request":
                    value["request_id"] = "req-other"
                if name == "wrong_plan":
                    value["plan_digest"] = "not-the-plan"
                report = ctx.read_json(REPORT_FILE)
                report[PREFLIGHT_EVIDENCE_KEY] = value
                ctx.write_json(REPORT_FILE, report)
                self._assert_unresolved(manifest, system, job_dir, backup_dir)

    def test_state_past_preflight_is_refused_even_with_proof(self):
        manifest, system, job_dir, backup_dir = self._failed_job("req-copying")
        ctx = JobContext(job_dir)
        ctx.write_json(STATE_FILE, {"state": "copying"})
        result = self._assert_unresolved(manifest, system, job_dir, backup_dir)
        self.assertEqual(result["state"], "unknown", result)

    def test_present_corrupt_initial_state_is_refused(self):
        manifest, system, job_dir, backup_dir = self._failed_job("req-corruptinit")
        with open(os.path.join(job_dir, INITIAL_STATE_FILE), "w", encoding="utf-8") as handle:
            handle.write("{not json")
        result = self._assert_unresolved(manifest, system, job_dir, backup_dir)
        self.assertEqual(result["state"], "unknown", result)
        self.assertEqual(result["reason"], "initial_state_unreadable", result)

    def test_recorded_original_state_past_preflight_forces_recovery_path(self):
        manifest, system, job_dir, backup_dir = self._failed_job("req-begun")
        ctx = JobContext(job_dir)
        ctx.write_json(INITIAL_STATE_FILE, {
            "schema_version": 1,
            "machine_id": support.MACHINE_ID,
            "stop_containers": [],
            "leave_stopped": [],
            "certbot": {"units": {}},
            "lease_active": False,
        })
        result = finalizer.recover(job_dir, system, manifest)
        # A recorded Certbot/lease phase is durable evidence that quiesce was
        # reached, so the safe fastpath is refused.
        self.assertNotIn("no_effects", result)
        self.assertFalse(os.path.exists(backup_dir))

    def test_injected_complete_refuses_the_fastpath(self):
        manifest, system, job_dir, backup_dir = self._failed_job("req-complete")
        os.makedirs(backup_dir, mode=0o700)
        marker = os.path.join(backup_dir, COMPLETE_MARKER)
        with open(marker, "wb") as handle:
            handle.write(b"complete\n")
        result = finalizer.recover(job_dir, system, manifest)
        self.assertNotEqual(result["state"], "failed", result)
        self.assertEqual(result["state"], "recovery_required", result)
        self.assertTrue(os.path.isfile(marker), result)
        self.assertEqual(system.started_ids, [], result)
        self.assertEqual(system.stopped_ids, [], result)
        self.assertFalse(coord.is_complete(job_dir)[0])


# Injected as ``<release_dir>/sitecustomize.py``. Replaces the host adapter so
# any Docker/systemd call is recorded instead of executed; the preflight-only
# fastpath must make none.
FAKE_SITECUSTOMIZE = '''"""Test-only host adapter: record any host call."""
import os
import sys


def _record(name):
    path = os.environ.get("VPS3XUI_FAKE_HOST_LOG")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(name + "\\n")


sys.path.insert(0, os.environ["VPS3XUI_FAKE_REPO"])


class FakeSystem(object):
    def __init__(self, backup_root="/var/backups/vps3xui", release_dir=None):
        self.backup_root = backup_root
        self.release_dir = release_dir

    def machine_id(self):
        _record("machine_id")
        raise AssertionError("the preflight fastpath must not read the host")

    def start_containers(self, ids):
        _record("start_containers")
        raise AssertionError("the preflight fastpath must not start containers")

    def container_states(self, names):
        _record("container_states")
        raise AssertionError("the preflight fastpath must not inspect containers")

    def restore_certbot_triggers(self, state, manifest):
        _record("restore_certbot_triggers")
        raise AssertionError("the preflight fastpath must not restore triggers")


from vps3xui.worker import system as _system_module

_system_module.RealSystem = FakeSystem
'''


if __name__ == "__main__":
    unittest.main()
