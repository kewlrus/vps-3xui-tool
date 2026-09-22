"""R7: the finalizer preserves the persisted primary failure journal.

The worker persists its first cause to ``failure.json`` before it can write
``report.json``. An independent finalizer invocation must surface that durable
cause unchanged, even when the report is missing or carries a later error, the
unit outcome is a signal, or the finalizer's own recovery attempt fails. A
missing journal still falls back to the report; a present but untrusted journal
must fail closed without leaking or erasing its contents.

The crash fixtures use the real ``BackupWorker`` journal writer and the real
``finalizer.recover`` entry point against the synthetic system only.
"""

import json
import os
import unittest
from unittest import mock

import support
from vps3xui.inventory import Inventory
from vps3xui.plan import build_plan
from vps3xui.worker import finalizer
from vps3xui.worker.backup_worker import BackupWorker
from vps3xui.worker.jobctx import FAILURE_FILE, JobContext, REPORT_FILE, STATE_FILE

SUCCESS_RESULT = {"SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": "0"}
SIGNAL_RESULT = {"SERVICE_RESULT": "signal", "EXIT_CODE": "killed", "EXIT_STATUS": "9"}
CRASH_MESSAGE = "Container restart failed during recovery."


class SimulatedCrash(BaseException):
    """The process dies after journaling the failure and before the report."""


def seeded_job(tmp, job_id):
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
    system = support.SyntheticSystem(manifest, os.path.join(tmp, "system", job_id))
    return manifest, system, job_dir, backup_dir


def copied_job(tmp, job_id):
    """A normal copied job: no failure journal, report says ``copied``."""
    manifest, system, job_dir, backup_dir = seeded_job(tmp, job_id)
    BackupWorker(system, job_dir, manifest).run()
    return manifest, system, job_dir, backup_dir


def crash_after_recording_failure(tmp, job_id):
    """Stop the real worker exactly between ``failure.json`` and the report.

    ``start_fail`` makes the worker's own recovery record the primary
    ``E_EXECUTION`` cause in the journal; ``_write_report`` then raises
    ``BaseException`` where a SIGKILL between the two writes would strike. The
    job is left with ``state=recovery_required`` and no ``report.json``.
    """
    manifest, system, job_dir, backup_dir = seeded_job(tmp, job_id)
    system.faults["start_fail"] = True
    worker = BackupWorker(system, job_dir, manifest)
    with mock.patch.object(BackupWorker, "_write_report",
                           side_effect=SimulatedCrash("crash before report")):
        try:
            worker.run()
        except SimulatedCrash:
            pass
        else:
            raise AssertionError("worker did not crash before writing report.json")
    return manifest, system, job_dir, backup_dir


def primary_failure(record):
    return {key: record.get(key) for key in ("code", "message", "resource")}


class FinalizerFailureJournalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = support.temp_state_dir("finalizer-journal-")

    def test_crash_boundary_primary_cause_survives_a_new_finalizer(self):
        manifest, system, job_dir, backup_dir = crash_after_recording_failure(
            self.tmp, "req-r7-crash")
        ctx = JobContext(job_dir)
        journal = support.read_json_file(ctx.path(FAILURE_FILE))
        self.assertEqual(journal["code"], "E_EXECUTION")
        self.assertEqual(journal["message"], CRASH_MESSAGE)
        self.assertFalse(os.path.exists(ctx.path(REPORT_FILE)))
        self.assertEqual((ctx.read_json(STATE_FILE) or {}).get("state"), "recovery_required")

        # The finalizer must now be able to recover, so only the worker's crash
        # boundary remains; the signal metadata must not replace the cause.
        system.faults = {}
        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SIGNAL_RESULT))
        report = ctx.read_json(REPORT_FILE)
        self.assertEqual(result["state"], "failed")
        self.assertEqual(report["original_failure"], primary_failure(journal))
        self.assertEqual(report["unit_result"], SIGNAL_RESULT)
        self.assertEqual(support.read_json_file(ctx.path(FAILURE_FILE)), journal)
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))

    def test_recovery_failure_and_later_report_cause_keep_the_primary(self):
        manifest, system, job_dir, backup_dir = crash_after_recording_failure(
            self.tmp, "req-r7-conflict")
        ctx = JobContext(job_dir)
        journal = support.read_json_file(ctx.path(FAILURE_FILE))
        # A report written by a later step must not replace the first cause.
        ctx.write_json(REPORT_FILE, {
            "schema_version": 1,
            "job_id": os.path.basename(job_dir),
            "backup_dir": backup_dir,
            "state": "recovery_required",
            "original_failure": {
                "code": "E_RECOVERY_REQUIRED",
                "message": "later error that must not win",
                "resource": "certbot",
            },
        })

        # ``start_fail`` is still active, so the finalizer's own recovery fails.
        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SIGNAL_RESULT))
        report = ctx.read_json(REPORT_FILE)
        self.assertEqual(result["state"], "recovery_required")
        self.assertFalse(report["recovery"]["recovery_complete"])
        self.assertEqual(report["original_failure"], primary_failure(journal))
        self.assertEqual(report["unit_result"], SIGNAL_RESULT)
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))

    def test_missing_journal_falls_back_to_the_report(self):
        manifest, system, job_dir, backup_dir = copied_job(self.tmp, "req-r7-fallback")
        ctx = JobContext(job_dir)
        self.assertFalse(os.path.exists(ctx.path(FAILURE_FILE)))
        fallback = {
            "code": "E_RECOVERY_REQUIRED",
            "message": "later report cause",
            "resource": "certbot",
        }
        report = ctx.read_json(REPORT_FILE)
        report["original_failure"] = dict(fallback)
        ctx.write_json(REPORT_FILE, report)

        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        final = ctx.read_json(REPORT_FILE)
        self.assertEqual(result["state"], "failed")
        self.assertEqual(final["original_failure"], fallback)
        self.assertFalse(os.path.exists(ctx.path(FAILURE_FILE)))
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))

    def test_corrupt_journal_fails_closed_and_is_never_erased(self):
        manifest, system, job_dir, backup_dir = copied_job(self.tmp, "req-r7-corrupt")
        ctx = JobContext(job_dir)
        canary = "JOURNAL_CANARY_CONTENTS"
        blob = ('{"code": "E_EXECUTION", "message": "%s"' % canary).encode("utf-8")
        with open(ctx.path(FAILURE_FILE), "wb") as handle:
            handle.write(blob)
        os.chmod(ctx.path(FAILURE_FILE), 0o600)

        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        report = ctx.read_json(REPORT_FILE)
        failure = report["original_failure"]
        self.assertEqual(result["state"], "failed")
        self.assertEqual(failure["code"], "E_EXECUTION")
        self.assertEqual(failure["resource"], FAILURE_FILE)
        self.assertEqual(failure["detail"]["reason"], "failure_journal_malformed")
        self.assertNotIn(canary, json.dumps(report, sort_keys=True))
        self.assertNotIn(canary, json.dumps(result, sort_keys=True))
        # The R5-gated recovery attempt still ran for the recorded resources.
        self.assertTrue(result["containers_started"])
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        with open(ctx.path(FAILURE_FILE), "rb") as handle:
            self.assertEqual(handle.read(), blob)

    def test_unreadable_journal_fails_closed(self):
        manifest, system, job_dir, backup_dir = copied_job(self.tmp, "req-r7-unreadable")
        ctx = JobContext(job_dir)
        os.symlink(os.path.join(self.tmp, "does-not-exist"), ctx.path(FAILURE_FILE))

        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        failure = ctx.read_json(REPORT_FILE)["original_failure"]
        self.assertEqual(result["state"], "failed")
        self.assertEqual(failure["detail"]["reason"], "failure_journal_unreadable")
        self.assertTrue(os.path.islink(ctx.path(FAILURE_FILE)))
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))

    def test_missing_journal_on_a_normal_success_stays_valid(self):
        manifest, system, job_dir, backup_dir = copied_job(self.tmp, "req-r7-success")
        ctx = JobContext(job_dir)
        self.assertFalse(os.path.exists(ctx.path(FAILURE_FILE)))

        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        report = ctx.read_json(REPORT_FILE)
        self.assertEqual(result["state"], "succeeded")
        self.assertTrue(os.path.isfile(os.path.join(backup_dir, "COMPLETE")))
        self.assertIsNone(report["original_failure"])
        self.assertFalse(os.path.exists(ctx.path(FAILURE_FILE)))


if __name__ == "__main__":
    unittest.main()
