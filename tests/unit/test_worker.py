import json
import os
import tempfile
import unittest

import support
from vps3xui.inventory import Inventory
from vps3xui.plan import build_plan
from vps3xui.verify import verify_directory
from vps3xui.worker import finalizer
from vps3xui.worker.backup_worker import BackupWorker
from vps3xui.worker.jobctx import REQUEST_FILE, INITIAL_STATE_FILE, REPORT_FILE, STATE_FILE, JobContext


def build_job(tmp, faults=None):
    manifest = support.approved_manifest(tmp)
    inventory = Inventory.from_probe(support.synthetic_probe())
    plan = build_plan(manifest, inventory, support.HOST_KEY)
    job_dir = os.path.join(tmp, "jobs", "req-worker-1")
    backup_dir = os.path.join(tmp, "backups", "req-worker-1")
    support.seed_job(job_dir, {
        "schema_version": 1,
        "request_id": "req-worker-1",
        "job_id": "req-worker-1",
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
    return manifest, system, worker, job_dir, backup_dir


def run_with_finalizer(manifest, system, worker, job_dir):
    """Run the worker, then the independent finalizer (ExecStopPost).

    A clean worker exit supplies the unit metadata a real systemd unit reports;
    the finalizer needs that complete evidence to publish success.
    """
    worker.run()
    finalizer.recover(job_dir, system, manifest,
                      service_result=dict(support.UNIT_SUCCESS_RESULT))
    return JobContext(job_dir).read_json(REPORT_FILE)


class WorkerHappyPathTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="worker-")

    def test_worker_stops_and_starts_one_id_at_a_time_in_order(self):
        manifest, backup_dir, report, system = support.complete_backup(
            tempfile.mkdtemp(prefix="worker-order-")
        )
        self.assertEqual(report["state"], "succeeded")
        recorded = [item["id"] for item in
                    support.read_json_file(os.path.join(os.path.dirname(backup_dir), "..", "jobs",
                                                        "req-verify-1", "initial-state.json"))["stop_containers"]]
        self.assertEqual(system.stop_batches, [[cid] for cid in recorded])
        self.assertEqual(system.start_batches[:len(recorded)], [[cid] for cid in recorded])

    def test_worker_alone_never_publishes_complete(self):
        manifest, system, worker, job_dir, backup_dir = build_job(self.tmp)
        report = worker.run()
        self.assertEqual(report["state"], "copied")
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        self.assertEqual(report["data_integrity"], "verified")

    def test_happy_path_publishes_complete_and_restores_state(self):
        manifest, system, worker, job_dir, backup_dir = build_job(self.tmp)
        report = run_with_finalizer(manifest, system, worker, job_dir)
        self.assertEqual(report["state"], "succeeded")
        self.assertEqual(report["data_integrity"], "verified")
        self.assertEqual(report["source_runtime_recovery"], "verified")
        self.assertEqual(report["model_generation"], "not_run")
        self.assertEqual(report["telegram_client_test"], "not_run")
        self.assertEqual(report["restore_drill"], "not_run")
        self.assertTrue(os.path.isfile(os.path.join(backup_dir, "COMPLETE")))
        result = verify_directory(backup_dir, manifest, require_complete=True)
        self.assertTrue(result.ok, result.error)

    def test_only_recorded_running_containers_are_stopped_and_restarted(self):
        manifest, system, worker, job_dir, backup_dir = build_job(self.tmp)
        worker.run()
        self.assertNotIn("id-telemt-0004", system.stopped_ids + system.started_ids)
        self.assertEqual(sorted(system.stopped_ids), sorted(system.started_ids))
        self.assertTrue(system.containers["litellm"]["running"])
        self.assertFalse(system.containers["telemt"]["running"])

    def test_certbot_timer_restored_to_original_state(self):
        manifest, system, worker, job_dir, backup_dir = build_job(self.tmp)
        worker.run()
        self.assertEqual(system.units["certbot.timer"]["active_state"], "active")
        self.assertEqual(system.units["certbot.timer"]["unit_file_state"], "enabled")

    def test_no_secret_canary_in_job_state_or_events(self):
        manifest, system, worker, job_dir, backup_dir = build_job(self.tmp)
        worker.run()
        for name in (STATE_FILE, REPORT_FILE, "events.log", INITIAL_STATE_FILE):
            with open(os.path.join(job_dir, name), "rb") as handle:
                blob = handle.read()
            for canary in (support.SECRET_CANARY, support.ENV_CANARY, support.DB_CANARY):
                self.assertNotIn(canary.encode(), blob, "%s leaked %s" % (name, canary))

    def test_worker_is_idempotent_on_rerun(self):
        manifest, system, worker, job_dir, backup_dir = build_job(self.tmp)
        first = worker.run()
        finalizer.recover(job_dir, system, manifest,
                          service_result=dict(support.UNIT_SUCCESS_RESULT))
        second_worker = BackupWorker(support.SyntheticSystem(manifest, os.path.join(self.tmp, "system2")),
                                     job_dir, manifest)
        second = second_worker.run()
        self.assertEqual(first["state"], "copied")
        self.assertEqual(second.get("state"), "succeeded")


class WorkerFailureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="worker-fail-")

    def test_copy_failure_preserves_cause_and_recovers(self):
        manifest, system, worker, job_dir, backup_dir = build_job(self.tmp, faults={"copy_fail": True})
        report = worker.run()
        self.assertEqual(report["state"], "failed")
        self.assertEqual(report["original_failure"]["code"], "E_EXECUTION")
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        self.assertTrue(system.containers["litellm"]["running"])
        self.assertTrue(report["recovery"]["recovery_complete"])

    def test_container_start_failure_requires_recovery(self):
        manifest, system, worker, job_dir, backup_dir = build_job(self.tmp, faults={"start_fail": True})
        report = worker.run()
        self.assertEqual(report["state"], "recovery_required")
        self.assertEqual(report["source_runtime_recovery"], "failed")
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        self.assertEqual(report["original_failure"]["code"], "E_EXECUTION")

    def test_certbot_restore_failure_requires_recovery(self):
        manifest, system, worker, job_dir, backup_dir = build_job(
            self.tmp, faults={"certbot_restore_fail": True}
        )
        report = worker.run()
        self.assertEqual(report["state"], "recovery_required")
        self.assertFalse(report["recovery"]["certbot_restored"])

    def test_active_lease_aborts_before_any_change(self):
        manifest, system, worker, job_dir, backup_dir = build_job(self.tmp)
        system.lease_active = True
        report = worker.run()
        self.assertEqual(report["state"], "failed")
        self.assertEqual(report["original_failure"]["code"], "E_PRECONDITION")
        self.assertEqual(system.stopped_ids, [])
        self.assertEqual(system.units["certbot.timer"]["active_state"], "active")
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))

    def test_renewal_race_aborts_and_restores_triggers(self):
        manifest, system, worker, job_dir, backup_dir = build_job(self.tmp, faults={"renewal_race": True})
        report = worker.run()
        self.assertEqual(report["state"], "failed")
        self.assertEqual(report["original_failure"]["code"], "E_CONFLICT")
        self.assertEqual(system.stopped_ids, [])
        self.assertEqual(system.units["certbot.timer"]["active_state"], "active")

    def test_low_space_aborts_before_change(self):
        manifest, system, worker, job_dir, backup_dir = build_job(self.tmp, faults={"low_space": True})
        report = worker.run()
        self.assertEqual(report["state"], "failed")
        self.assertEqual(report["original_failure"]["code"], "E_PRECONDITION")
        self.assertEqual(system.stopped_ids, [])

    def test_preflight_failure_records_no_effects_proof_for_the_finalizer(self):
        # F5: a failure before ``changes_started`` must carry a durable,
        # job/request-bound no-effects proof so the independent ExecStopPost
        # finalizer can end the job terminal ``failed`` instead of the blocking
        # ``unknown``. This is the counterpart to the copying guard below.
        manifest, system, worker, job_dir, backup_dir = build_job(
            self.tmp, faults={"low_space": True})
        report = worker.run()
        self.assertEqual(report["state"], "failed")
        evidence = report.get("preflight_evidence")
        self.assertIs(evidence["effects_started"], False)
        self.assertEqual(evidence["phase"], "preflight")
        self.assertEqual(evidence["job_id"], "req-worker-1")
        result = finalizer.recover(job_dir, system, manifest)
        self.assertEqual(result["state"], "failed")
        self.assertEqual(system.stopped_ids, [])
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))

    def test_drift_after_plan_aborts(self):
        manifest, system, worker, job_dir, backup_dir = build_job(self.tmp)
        system.containers["litellm"]["id"] = "id-changed"
        report = worker.run()
        self.assertEqual(report["state"], "failed")
        self.assertEqual(report["original_failure"]["code"], "E_PLAN_STALE")
        self.assertEqual(system.stopped_ids, [])

    def test_unplanned_running_container_aborts(self):
        manifest, system, worker, job_dir, backup_dir = build_job(self.tmp)
        system.containers["agent-relay"] = {"id": "id-relay", "running": True}
        report = worker.run()
        self.assertEqual(report["state"], "failed")
        self.assertEqual(report["original_failure"]["code"], "E_PLAN_STALE")

    def test_missing_required_artifact_fails_without_complete(self):
        manifest, system, worker, job_dir, backup_dir = build_job(self.tmp, faults={"drop_metadata": True})
        report = worker.run()
        self.assertEqual(report["state"], "failed")
        self.assertEqual(report["original_failure"]["code"], "E_MISSING_ARTIFACT")
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))


class WorkerKillTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="worker-kill-")

    def test_sigkill_during_copy_is_recovered_by_finalizer_not_marked_success(self):
        manifest, system, worker, job_dir, backup_dir = build_job(
            self.tmp, faults={"kill_during_copy": True}
        )
        with self.assertRaises(support.KillWorker):
            worker.run()
        state = support.read_json_file(os.path.join(job_dir, STATE_FILE))
        self.assertEqual(state["state"], "copying")
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        # ExecStopPost finalizer restores the recorded runtime.
        system.faults = {}
        result = finalizer.recover(job_dir, system, manifest)
        self.assertTrue(result["recovered"])
        self.assertEqual(result["state"], "failed")
        self.assertTrue(system.containers["litellm"]["running"])
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))

    def test_finalizer_without_initial_state_reports_unknown(self):
        manifest, system, worker, job_dir, backup_dir = build_job(self.tmp)
        ctx = JobContext(job_dir)
        ctx.write_json(STATE_FILE, {"state": "copying"})
        result = finalizer.recover(job_dir, system, manifest)
        self.assertEqual(result["state"], "unknown")
        self.assertFalse(result["recovered"])
        report = support.read_json_file(os.path.join(job_dir, REPORT_FILE))
        self.assertEqual(report["state"], "unknown")


if __name__ == "__main__":
    unittest.main()
