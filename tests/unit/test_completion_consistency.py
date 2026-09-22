"""F3: reconcile contradictory terminal state / COMPLETE / failure evidence.

The completion evidence of a job is checked as a whole, with real files and the
shipped worker/finalizer/remote-status code paths:

* a valid or corrupt ``failure.json``, a report that retains a first failure, a
  non-success report/state or a stale/unsafe ``COMPLETE`` marker means the job
  must not be reported as complete -- not by the worker's rerun guard, not by
  ``remote_ops status``/``blocking``, and not by the source verify/fetch gate;
* the finalizer revokes the stale marker only inside this job's validated,
  request-authoritative backup directory, under the machine identity gate; an
  unprovable revocation (wrong host, unsafe path, unlink/fsync failure) keeps the
  first cause and reports ``recovery_required`` instead of success;
* a genuinely completed job stays idempotent and its evidence is untouched.
"""

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import support
from vps3xui import backup as backup_ops
from vps3xui import coordination as coord
from vps3xui.errors import ToolError
from vps3xui.inventory import Inventory
from vps3xui.plan import build_plan
from vps3xui.verify import verify_directory
from vps3xui.worker import finalizer
from vps3xui.worker.backup_worker import BackupWorker
from vps3xui.worker.jobctx import (
    FAILURE_FILE,
    INITIAL_STATE_FILE,
    REPORT_FILE,
    REQUEST_FILE,
    STATE_FILE,
    JobContext,
)

SUCCESS_RESULT = {"SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": "0"}
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REMOTE_OPS = os.path.join(REPO_ROOT, "vps3xui", "remote_ops.py")


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


def seeded_job(tmp, job_id, backup_dir=None, machine_id=None):
    manifest = support.approved_manifest(tmp)
    inventory = Inventory.from_probe(support.synthetic_probe())
    plan = build_plan(manifest, inventory, support.HOST_KEY)
    job_dir = os.path.join(tmp, "jobs", job_id)
    if backup_dir is None:
        backup_dir = os.path.join(tmp, "backups", job_id)
    support.seed_job(job_dir, {
        "schema_version": 1,
        "request_id": job_id,
        "job_id": job_id,
        "manifest_id": manifest.manifest_id,
        "plan_digest": plan["identity"],
        "machine_id": machine_id or support.MACHINE_ID,
        "host_key_fingerprint": support.HOST_KEY,
        "backup_dir": backup_dir,
        "stop_containers": plan["stop_containers"],
        "leave_stopped": plan["leave_stopped"],
        "required_bytes_estimate": 5_000_000_000,
    }, plan, manifest)
    system = support.SyntheticSystem(manifest, os.path.join(tmp, "system", job_id))
    return manifest, system, job_dir, backup_dir


def completed_job(tmp, job_id):
    """Run the real worker and finalizer; the job is a genuine ``COMPLETE``."""
    manifest, system, job_dir, backup_dir = seeded_job(tmp, job_id)
    BackupWorker(system, job_dir, manifest).run()
    result = finalizer.recover(job_dir, system, manifest,
                               service_result=dict(SUCCESS_RESULT))
    assert result["state"] == "succeeded", result
    assert os.path.isfile(os.path.join(backup_dir, "COMPLETE"))
    return manifest, system, job_dir, backup_dir


def write_bytes(path, data, mode=0o600):
    with open(path, "wb") as handle:
        handle.write(data)
    os.chmod(path, mode)


def write_json_file(path, obj, mode=0o600):
    write_bytes(path, (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8"), mode)


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def read_json_file(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def valid_journal(job_id, message="original failure"):
    return {
        "schema_version": 1,
        "job_id": job_id,
        "code": "E_EXECUTION",
        "message": message,
        "resource": "backup",
        "recorded_at": "2026-09-22T00:00:00Z",
    }


def writer_report(job_id, backup_dir, manifest_id="m", **overrides):
    """The terminal success report shape the real finalizer writes.

    Handcrafted success fixtures use this so the completion rules are exercised
    against the writer-produced evidence, not against a weakened subset.
    """
    report = {
        "schema_version": 1,
        "job_id": job_id,
        "tool_version": "test",
        "backup_dir": backup_dir,
        "manifest_id": manifest_id,
        "manifest_digest": "digest",
        "state": "succeeded",
        "data_integrity": "verified",
        "source_runtime_recovery": "verified",
        "original_failure": None,
        "recovery": {
            "containers_started": [],
            "container_failures": [],
            "certbot_restored": True,
            "recovery_complete": True,
        },
        "unit_result": dict(SUCCESS_RESULT),
        "completed_at": "2026-09-22T00:00:00Z",
    }
    report.update(overrides)
    return report


class CompletionConsistencyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = support.temp_state_dir("f3-completion-")

    # -- genuine success ---------------------------------------------------
    def test_genuine_success_stays_idempotent_and_preserves_evidence(self):
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, "req-f3-ok")
        ctx = JobContext(job_dir)
        report_before = read_bytes(ctx.path(REPORT_FILE))
        state_before = read_bytes(ctx.path(STATE_FILE))
        starts_before = list(system.started_ids)

        self.assertEqual(coord.completion_conflict(job_dir), None)
        self.assertEqual(coord.is_complete(job_dir), (True, "succeeded"))

        default = finalizer.recover(job_dir, system, manifest,
                                    service_result=dict(SUCCESS_RESULT))
        explicit = finalizer.recover(job_dir, system, manifest, explicit=True)
        missing_env = finalizer.recover(job_dir, system, manifest)
        for result in (default, explicit, missing_env):
            self.assertEqual(result["state"], "succeeded", result)
            self.assertTrue(result.get("already_complete"), result)
            self.assertNotIn("revocation", result)
        self.assertEqual(coord.completion_conflict(job_dir), None)
        # No resource was started or restarted and no evidence byte changed.
        self.assertEqual(system.started_ids, starts_before)
        self.assertEqual(read_bytes(ctx.path(REPORT_FILE)), report_before)
        self.assertEqual(read_bytes(ctx.path(STATE_FILE)), state_before)
        self.assertTrue(os.path.isfile(os.path.join(backup_dir, "COMPLETE")))
        self.assertTrue(verify_directory(backup_dir, manifest, require_complete=True).ok)

    # -- failure journal present ------------------------------------------
    def test_succeeded_with_valid_journal_is_refused_then_revoked(self):
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, "req-f3-valid")
        ctx = JobContext(job_dir)
        journal_path = ctx.path(FAILURE_FILE)
        write_bytes(journal_path, (json.dumps(valid_journal("req-f3-valid")) + "\n").encode())
        journal_before = read_bytes(journal_path)

        # Source status fails closed BEFORE any reconciliation.
        self.assertFalse(coord.is_complete(job_dir)[0])
        payload = self._remote_payload(job_dir, "req-f3-valid")
        self.assertEqual(payload["state"], "recovery_required", payload)
        self.assertEqual(payload["evidence"], "failure_journal_present", payload)
        self.assertFalse(payload["operation_complete"])

        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        self.assertEqual(result["state"], "failed", result)
        self.assertEqual(result["revocation"], {"ok": True, "revoked": True})
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        self.assertEqual(read_bytes(journal_path), journal_before)
        report = ctx.read_json(REPORT_FILE)
        self.assertEqual(report["original_failure"]["code"], "E_EXECUTION")
        self.assertEqual(report["original_failure"]["message"], "original failure")
        self.assertEqual(report["recovery"]["revocation"], {"ok": True, "revoked": True})
        # Portable verification now refuses the affected directory.
        portable = backup_ops.run_verify_directory(manifest, backup_dir)
        self.assertFalse(portable["operation_complete"], portable)

        # A repeated recovery preserves the first-cause bytes and stays failed.
        second = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        self.assertEqual(second["state"], "failed", second)
        self.assertEqual(read_bytes(journal_path), journal_before)
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))

    def test_repaired_failure_stays_terminal_and_unblocks_new_work(self):
        job_id = "req-f3-terminal"
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, job_id)
        ctx = JobContext(job_dir)
        journal_path = ctx.path(FAILURE_FILE)
        write_bytes(journal_path, (json.dumps(valid_journal(job_id)) + "\n").encode())

        first = finalizer.recover(job_dir, system, manifest,
                                  service_result=dict(SUCCESS_RESULT))
        self.assertEqual(first["state"], "failed", first)
        self.assertEqual(first["revocation"], {"ok": True, "revoked": True})
        # The first cause may legally remain on a terminal failed job.
        self.assertTrue(os.path.isfile(journal_path))

        # The repaired job is terminal, so it neither blocks new work nor is
        # re-promoted to an unresolved state by a repeated recovery.
        self.assertEqual(coord.is_complete(job_dir), (True, "failed"))
        root = os.path.dirname(os.path.dirname(job_dir))
        code, payload = run_ops(root, "blocking")
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["blocking"], [])
        code, payload = run_ops(root, "status", job_id)
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["state"], "failed", payload)
        self.assertTrue(payload["operation_complete"], payload)

        second = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        self.assertEqual(second["state"], "failed", second)
        self.assertNotEqual(second["state"], "recovery_required")
        report = ctx.read_json(REPORT_FILE)
        self.assertEqual(report["recovery"]["revocation"], {"ok": True, "revoked": True})

        code, payload = reserve_only(root, "req-f3-after-repair")
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload["reserved"], payload)

    def test_succeeded_with_corrupt_journal_fails_closed_content_free(self):
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, "req-f3-corrupt")
        ctx = JobContext(job_dir)
        canary = "F3_JOURNAL_CANARY_CONTENTS"
        blob = ('{"code": "E_EXECUTION", "message": "%s"' % canary).encode("utf-8")
        write_bytes(ctx.path(FAILURE_FILE), blob)

        self.assertFalse(coord.is_complete(job_dir)[0])
        payload = self._remote_payload(job_dir, "req-f3-corrupt")
        self.assertEqual(payload["state"], "recovery_required", payload)
        self.assertFalse(payload["operation_complete"])

        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        report = ctx.read_json(REPORT_FILE)
        self.assertEqual(result["state"], "failed", result)
        self.assertEqual(report["original_failure"]["resource"], FAILURE_FILE)
        self.assertEqual(report["original_failure"]["detail"]["reason"],
                         "failure_journal_malformed")
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        self.assertEqual(read_bytes(ctx.path(FAILURE_FILE)), blob)
        self.assertNotIn(canary, json.dumps(report, sort_keys=True))
        self.assertNotIn(canary, json.dumps(result, sort_keys=True))

    # -- report failure ----------------------------------------------------
    def test_report_failure_contradicts_a_success_marker(self):
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, "req-f3-report")
        ctx = JobContext(job_dir)
        report = ctx.read_json(REPORT_FILE)
        report["original_failure"] = {"code": "E_EXECUTION",
                                      "message": "late report cause", "resource": None}
        ctx.write_json(REPORT_FILE, report)

        self.assertFalse(coord.is_complete(job_dir)[0])
        payload = self._remote_payload(job_dir, "req-f3-report")
        self.assertEqual(payload["evidence"], "report_original_failure", payload)
        self.assertFalse(payload["operation_complete"])

        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        final = ctx.read_json(REPORT_FILE)
        self.assertEqual(result["state"], "failed", result)
        self.assertEqual(final["original_failure"]["code"], "E_EXECUTION")
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        self.assertFalse(verify_directory(backup_dir, manifest, require_complete=True).ok)

    # -- failed / missing / corrupt state with a marker --------------------
    def test_stale_marker_under_failed_state_is_revoked(self):
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, "req-f3-failed")
        ctx = JobContext(job_dir)
        ctx.write_json(STATE_FILE, {"state": "failed"})

        self.assertFalse(coord.is_complete(job_dir)[0])
        payload = self._remote_payload(job_dir, "req-f3-failed")
        self.assertEqual(payload["evidence"], "stale_complete", payload)
        self.assertFalse(payload["operation_complete"])

        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        self.assertNotEqual(result["state"], "succeeded", result)
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        self.assertFalse(verify_directory(backup_dir, manifest, require_complete=True).ok)

    def test_corrupt_state_with_marker_is_revoked(self):
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, "req-f3-corruptstate")
        ctx = JobContext(job_dir)
        write_bytes(ctx.path(STATE_FILE), b"{ not json")

        self.assertFalse(coord.is_complete(job_dir)[0])
        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        self.assertNotEqual(result["state"], "succeeded", result)
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        self.assertFalse(verify_directory(backup_dir, manifest, require_complete=True).ok)

    def test_missing_state_and_report_with_marker_is_revoked(self):
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, "req-f3-missing")
        ctx = JobContext(job_dir)
        os.unlink(ctx.path(STATE_FILE))
        os.unlink(ctx.path(REPORT_FILE))

        self.assertFalse(coord.is_complete(job_dir)[0])
        result = finalizer.recover(job_dir, system, manifest)
        self.assertNotEqual(result["state"], "succeeded", result)
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        self.assertFalse(verify_directory(backup_dir, manifest, require_complete=True).ok)

    # -- unsafe marker / path ----------------------------------------------
    def test_marker_symlink_is_never_success_and_never_followed(self):
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, "req-f3-symlink")
        marker = os.path.join(backup_dir, "COMPLETE")
        target = os.path.join(self.tmp, "elsewhere-marker")
        write_bytes(target, b"complete\n")
        os.unlink(marker)
        os.symlink(target, marker)

        self.assertFalse(coord.is_complete(job_dir)[0])
        payload = self._remote_payload(job_dir, "req-f3-symlink")
        self.assertEqual(payload["evidence"], "marker_unsafe", payload)
        self.assertFalse(payload["operation_complete"])

        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        self.assertNotEqual(result["state"], "succeeded", result)
        self.assertEqual(result["revocation"], {"ok": False, "reason": "marker_not_regular"})
        self.assertTrue(os.path.islink(marker))
        self.assertEqual(read_bytes(target), b"complete\n")
        self.assertFalse(verify_directory(backup_dir, manifest, require_complete=True).ok)

    def test_unsafe_backup_path_refuses_any_backup_mutation(self):
        job_id = "req-f3-unsafe"
        real_backups = os.path.join(self.tmp, "real-backups")
        os.makedirs(os.path.join(real_backups, job_id), mode=0o700)
        link = os.path.join(self.tmp, "link-backups")
        os.symlink(real_backups, link)
        linked_backup = os.path.join(link, job_id)
        manifest, system, job_dir, backup_dir = seeded_job(
            self.tmp, job_id, backup_dir=linked_backup)
        ctx = JobContext(job_dir)
        marker = os.path.join(real_backups, job_id, "COMPLETE")
        write_bytes(marker, b"complete\n")
        write_bytes(ctx.path(FAILURE_FILE),
                    (json.dumps(valid_journal(job_id)) + "\n").encode())
        write_json_file(ctx.path(REPORT_FILE), {
            "schema_version": 1, "job_id": job_id, "backup_dir": linked_backup,
            "manifest_id": manifest.manifest_id, "state": "succeeded",
        })
        write_json_file(ctx.path(INITIAL_STATE_FILE), {
            "machine_id": support.MACHINE_ID, "stop_containers": [], "leave_stopped": [],
        })

        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        self.assertNotEqual(result["state"], "succeeded", result)
        self.assertEqual(result["revocation"], {"ok": False, "reason": "unsafe_backup_path"})
        self.assertTrue(os.path.isfile(marker))

    # -- request/report/metadata binding disagreements ---------------------
    def test_request_report_backup_dir_disagreement_never_publishes(self):
        job_id = "req-f3-bind-dir"
        manifest, system, job_dir, backup_dir = seeded_job(self.tmp, job_id)
        BackupWorker(system, job_dir, manifest).run()
        ctx = JobContext(job_dir)
        root = os.path.dirname(os.path.dirname(job_dir))
        other = os.path.join(self.tmp, "other-backups", job_id)
        os.makedirs(other, mode=0o700)
        request = ctx.read_json(REQUEST_FILE)
        request["backup_dir"] = other
        ctx.write_json(REQUEST_FILE, request)

        # The report still names the real copy; the immutable request names
        # another directory. Success must not be proven for either path, and a
        # repeated recovery must keep returning the unresolved binding instead
        # of downgrading it into a terminal failure that unblocks new work.
        for attempt in (1, 2):
            result = finalizer.recover(job_dir, system, manifest,
                                       service_result=dict(SUCCESS_RESULT))
            self.assertEqual(result["state"], "recovery_required", (attempt, result))
            self.assertEqual(result["binding_problem"], "backup_dir_conflict", result)
            self.assertFalse(coord.is_complete(job_dir)[0])
            report = ctx.read_json(REPORT_FILE)
            self.assertEqual(report["state"], "recovery_required")
            self.assertEqual(report["recovery"]["binding_problem"], "backup_dir_conflict")
            self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
            self.assertFalse(os.path.exists(os.path.join(other, "COMPLETE")))
            payload = self._remote_payload(job_dir, job_id)
            self.assertEqual(payload["state"], "recovery_required", payload)
            self.assertEqual(payload["evidence"], "binding_unresolved", payload)
            self.assertFalse(payload["operation_complete"])
            code, payload = run_ops(root, "blocking")
            self.assertEqual(code, 0, payload)
            self.assertEqual([item["job_id"] for item in payload["blocking"]], [job_id])
            code, payload = reserve_only(root, "req-f3-bind-new-%d" % attempt)
            self.assertEqual(code, 3, payload)
            self.assertEqual(payload["error"]["code"], "E_JOB_INCOMPLETE")

        # Repairing the authoritative binding never fabricates success: the job
        # already left its copy-only window, so it ends as a terminal failure.
        request["backup_dir"] = backup_dir
        ctx.write_json(REQUEST_FILE, request)
        repaired = finalizer.recover(job_dir, system, manifest,
                                     service_result=dict(SUCCESS_RESULT))
        self.assertEqual(repaired["state"], "failed", repaired)
        self.assertNotIn("binding_problem", repaired)
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        self.assertEqual(coord.is_complete(job_dir), (True, "failed"))
        self.assertNotIn("binding_problem", ctx.read_json(REPORT_FILE)["recovery"])
        code, payload = run_ops(root, "blocking")
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["blocking"], [])
        code, payload = reserve_only(root, "req-f3-bind-after-repair")
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload["reserved"], payload)

    def test_failed_state_with_pending_cleanup_stays_blocked(self):
        job_id = "req-f3-pending"
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, job_id)
        ctx = JobContext(job_dir)
        root = os.path.dirname(os.path.dirname(job_dir))
        write_bytes(ctx.path(FAILURE_FILE),
                    (json.dumps(valid_journal(job_id)) + "\n").encode())
        with mock.patch.object(finalizer, "_fsync_dir_fd", side_effect=OSError("boom")):
            first = finalizer.recover(job_dir, system, manifest,
                                      service_result=dict(SUCCESS_RESULT))
        self.assertEqual(first["state"], "recovery_required", first)
        self.assertEqual(first["revocation"], {"ok": False, "reason": "marker_fsync_failed"})

        # Even if the state file had been written as terminal ``failed`` while
        # the revocation is unfinished, the job must not count as complete and
        # must not unblock a new reservation.
        ctx.write_json(STATE_FILE, {"state": "failed"})
        self.assertEqual(coord.completion_conflict(job_dir), "revocation_pending")
        self.assertFalse(coord.is_complete(job_dir)[0])
        payload = self._remote_payload(job_dir, job_id)
        self.assertEqual(payload["state"], "recovery_required", payload)
        self.assertEqual(payload["evidence"], "revocation_pending", payload)
        self.assertFalse(payload["operation_complete"])
        code, payload = run_ops(root, "blocking")
        self.assertEqual([item["job_id"] for item in payload["blocking"]], [job_id])
        code, payload = reserve_only(root, "req-f3-pending-blocked")
        self.assertEqual(code, 3, payload)
        self.assertEqual(payload["error"]["code"], "E_JOB_INCOMPLETE")

        # Only the completed retry makes the job terminal.
        second = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        self.assertEqual(second["state"], "failed", second)
        self.assertEqual(coord.is_complete(job_dir), (True, "failed"))
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))

    def test_failed_state_with_recorded_binding_error_stays_blocked(self):
        job_id = "req-f3-stale-failed"
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, job_id)
        ctx = JobContext(job_dir)
        other = os.path.join(self.tmp, "other-backups", job_id)
        os.makedirs(other, mode=0o700)
        request = ctx.read_json(REQUEST_FILE)
        request["backup_dir"] = other
        ctx.write_json(REQUEST_FILE, request)
        # The curated error a recovery persisted, on a state file that was
        # (wrongly) written as terminal ``failed``.
        report = ctx.read_json(REPORT_FILE)
        report["recovery"] = dict(report["recovery"], binding_problem="backup_dir_conflict")
        ctx.write_json(REPORT_FILE, report)
        ctx.write_json(STATE_FILE, {"state": "failed"})

        self.assertEqual(coord.completion_conflict(job_dir), "binding_unresolved")
        self.assertFalse(coord.is_complete(job_dir)[0])
        # ...and the same holds when only the request/report comparison shows
        # the disagreement, as in jobs already written ``failed`` before this
        # fix persisted the reason.
        report["recovery"].pop("binding_problem")
        ctx.write_json(REPORT_FILE, report)
        self.assertEqual(coord.completion_conflict(job_dir), "binding_unresolved")
        self.assertFalse(coord.is_complete(job_dir)[0])
        report["recovery"]["binding_problem"] = "backup_dir_conflict"
        ctx.write_json(REPORT_FILE, report)

        payload = self._remote_payload(job_dir, job_id)
        self.assertEqual(payload["state"], "recovery_required", payload)
        self.assertEqual(payload["evidence"], "binding_unresolved", payload)
        self.assertFalse(payload["operation_complete"])

        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        self.assertEqual(result["state"], "recovery_required", result)
        self.assertEqual(result["binding_problem"], "backup_dir_conflict")
        # The real marker is preserved: it is the unvalidated report path, so
        # nothing there may be removed while the binding is unresolved.
        self.assertTrue(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        self.assertFalse(os.path.exists(os.path.join(other, "COMPLETE")))

    def test_failed_before_copy_without_backup_path_stays_terminal(self):
        job_id = "req-f3-precopy"
        manifest = support.approved_manifest(self.tmp)
        inventory = Inventory.from_probe(support.synthetic_probe())
        plan = build_plan(manifest, inventory, support.HOST_KEY)
        job_dir = os.path.join(self.tmp, "jobs", job_id)
        # A legitimately failed-before-copy job whose request recorded no
        # backup path: nothing was copied, so no path must be demanded of it.
        support.seed_job(job_dir, {
            "schema_version": 1,
            "request_id": job_id,
            "job_id": job_id,
            "manifest_id": manifest.manifest_id,
            "plan_digest": plan["identity"],
            "machine_id": support.MACHINE_ID,
            "host_key_fingerprint": support.HOST_KEY,
            "stop_containers": plan["stop_containers"],
            "leave_stopped": plan["leave_stopped"],
            "required_bytes_estimate": 5_000_000_000,
        }, plan, manifest)
        system = support.SyntheticSystem(manifest, os.path.join(self.tmp, "system"),
                                         faults={"renewal_race": True})
        report = BackupWorker(system, job_dir, manifest).run()
        self.assertEqual(report["state"], "failed", report)
        self.assertEqual(report["original_failure"]["code"], "E_CONFLICT")
        self.assertFalse(os.path.exists(os.path.join(job_dir, "backup")))

        system.faults = {}
        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        self.assertEqual(result["state"], "failed", result)
        self.assertNotIn("binding_problem", result)
        self.assertNotIn("binding_problem",
                         JobContext(job_dir).read_json(REPORT_FILE)["recovery"])
        self.assertEqual(coord.is_complete(job_dir), (True, "failed"))
        root = os.path.dirname(os.path.dirname(job_dir))
        code, payload = run_ops(root, "blocking")
        self.assertEqual(payload["blocking"], [])
        code, payload = run_ops(root, "status", job_id)
        self.assertEqual(payload["state"], "failed", payload)
        self.assertTrue(payload["operation_complete"], payload)
        code, payload = reserve_only(root, "req-f3-precopy-next")
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload["reserved"], payload)

    def test_succeeded_marker_at_report_path_after_request_change_is_refused(self):
        job_id = "req-f3-bind-marker"
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, job_id)
        ctx = JobContext(job_dir)
        other = os.path.join(self.tmp, "other-backups", job_id)
        os.makedirs(other, mode=0o700)
        request = ctx.read_json(REQUEST_FILE)
        request["backup_dir"] = other
        ctx.write_json(REQUEST_FILE, request)

        # The marker still exists at the report-selected path; the immutable
        # request disagrees, so the job is not complete and the marker is never
        # touched (it is only valid inside the request-authoritative target).
        self.assertEqual(coord.completion_conflict(job_dir), "backup_dir_conflict")
        self.assertFalse(coord.is_complete(job_dir)[0])
        payload = self._remote_payload(job_dir, job_id)
        self.assertEqual(payload["state"], "recovery_required", payload)
        self.assertEqual(payload["evidence"], "backup_dir_conflict", payload)
        self.assertFalse(payload["operation_complete"])

        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        self.assertNotEqual(result["state"], "succeeded", result)
        self.assertEqual(result["revocation"],
                         {"ok": False, "reason": "backup_dir_conflict"})
        self.assertTrue(os.path.isfile(os.path.join(backup_dir, "COMPLETE")))
        self.assertFalse(os.path.exists(os.path.join(other, "COMPLETE")))

    def test_backup_metadata_mismatch_blocks_success(self):
        for field, value in (("manifest_id", "other-manifest"),
                             ("backup_id", "other-job")):
            with self.subTest(field=field):
                tmp = support.temp_state_dir("f3-meta-%s-" % field)
                job_id = "req-f3-meta-%s" % field.replace("_", "-")
                manifest, system, job_dir, backup_dir = completed_job(tmp, job_id)
                metadata_path = os.path.join(backup_dir, "backup.json")
                metadata = read_json_file(metadata_path)
                metadata[field] = value
                write_json_file(metadata_path, metadata)

                self.assertEqual(coord.completion_conflict(job_dir),
                                 "backup_metadata_mismatch")
                self.assertFalse(coord.is_complete(job_dir)[0])
                payload = self._remote_payload(job_dir, job_id)
                self.assertEqual(payload["state"], "recovery_required", payload)
                self.assertFalse(payload["operation_complete"])

                result = finalizer.recover(job_dir, system, manifest,
                                           service_result=dict(SUCCESS_RESULT))
                self.assertNotEqual(result["state"], "succeeded", result)
                self.assertEqual(result["revocation"],
                                 {"ok": False, "reason": "backup_metadata_mismatch"})
                self.assertTrue(os.path.isfile(os.path.join(backup_dir, "COMPLETE")))

    def test_missing_report_with_journal_retains_the_authoritative_path(self):
        job_id = "req-f3-noreport"
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, job_id)
        ctx = JobContext(job_dir)
        os.unlink(ctx.path(REPORT_FILE))
        write_bytes(ctx.path(FAILURE_FILE),
                    (json.dumps(valid_journal(job_id)) + "\n").encode())

        payload = self._remote_payload(job_dir, job_id)
        self.assertEqual(payload["evidence"], "failure_journal_present", payload)
        self.assertFalse(payload["operation_complete"])

        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        self.assertEqual(result["state"], "failed", result)
        report = ctx.read_json(REPORT_FILE)
        self.assertEqual(report["state"], "failed")
        # The validated request path is retained; the job-directory default is
        # never substituted for it and no marker survives.
        self.assertEqual(report["backup_dir"], backup_dir)
        self.assertFalse(os.path.exists(os.path.join(job_dir, "backup")))
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))

    def test_missing_report_without_journal_is_never_success(self):
        job_id = "req-f3-noreport2"
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, job_id)
        ctx = JobContext(job_dir)
        os.unlink(ctx.path(REPORT_FILE))

        self.assertEqual(coord.completion_conflict(job_dir), "report_missing")
        payload = self._remote_payload(job_dir, job_id)
        self.assertEqual(payload["evidence"], "report_missing", payload)
        self.assertFalse(payload["operation_complete"])

        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        self.assertNotEqual(result["state"], "succeeded", result)
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        self.assertEqual(ctx.read_json(REPORT_FILE)["backup_dir"], backup_dir)

    def test_contradictory_success_report_variants_are_refused(self):
        cases = [
            ("recovery-unverified", {"source_runtime_recovery": "failed"},
             "report_recovery_unverified"),
            ("recovery-incomplete",
             {"recovery": {"containers_started": [], "container_failures": [],
                           "certbot_restored": True, "recovery_complete": False}},
             "report_recovery_incomplete"),
            ("unit-unproven",
             {"unit_result": {"SERVICE_RESULT": "timeout", "EXIT_CODE": "exited",
                              "EXIT_STATUS": "0"}},
             "report_unit_unproven"),
            ("state-copied", {"state": "copied"}, "report_state_conflict"),
        ]
        for name, overrides, expected in cases:
            with self.subTest(case=name):
                job_id = "req-f3-contra-%s" % name
                manifest, system, job_dir, backup_dir = completed_job(self.tmp, job_id)
                ctx = JobContext(job_dir)
                report = ctx.read_json(REPORT_FILE)
                report.update(overrides)
                write_json_file(ctx.path(REPORT_FILE), report)

                self.assertEqual(coord.completion_conflict(job_dir), expected)
                self.assertFalse(coord.is_complete(job_dir)[0])
                payload = self._remote_payload(job_dir, job_id)
                self.assertEqual(payload["state"], "recovery_required", payload)
                self.assertEqual(payload["evidence"], expected, payload)
                self.assertFalse(payload["operation_complete"])

                result = finalizer.recover(job_dir, system, manifest,
                                           service_result=dict(SUCCESS_RESULT))
                self.assertNotEqual(result["state"], "succeeded", result)
                self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))

    def test_zero_byte_marker_is_never_idempotent_success(self):
        job_id = "req-f3-empty"
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, job_id)
        marker = os.path.join(backup_dir, "COMPLETE")
        write_bytes(marker, b"")

        self.assertFalse(coord.has_complete(backup_dir))
        self.assertEqual(coord.completion_conflict(job_dir), "marker_unsafe")
        self.assertFalse(coord.is_complete(job_dir)[0])
        payload = self._remote_payload(job_dir, job_id)
        self.assertEqual(payload["evidence"], "marker_unsafe", payload)
        self.assertFalse(payload["operation_complete"])

        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        self.assertNotEqual(result["state"], "succeeded", result)
        self.assertEqual(result["revocation"], {"ok": False, "reason": "marker_not_regular"})
        self.assertTrue(os.path.isfile(marker))

    # -- wrong host --------------------------------------------------------
    def test_wrong_host_performs_zero_host_mutations(self):
        job_id = "req-f3-wronghost"
        manifest, system, job_dir, backup_dir = seeded_job(self.tmp, job_id)
        ctx = JobContext(job_dir)
        os.makedirs(backup_dir, mode=0o700)
        write_bytes(os.path.join(backup_dir, "COMPLETE"), b"complete\n")
        write_bytes(ctx.path(FAILURE_FILE),
                    (json.dumps(valid_journal(job_id)) + "\n").encode())
        write_json_file(ctx.path(REPORT_FILE), {
            "schema_version": 1, "job_id": job_id, "backup_dir": backup_dir,
            "manifest_id": manifest.manifest_id, "state": "succeeded",
        })
        write_json_file(ctx.path(INITIAL_STATE_FILE), {
            "machine_id": "b" * 32,
            "stop_containers": [{"name": "litellm", "id": "id-litellm-0001"}],
            "leave_stopped": [],
        })

        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        self.assertNotEqual(result["state"], "succeeded", result)
        self.assertEqual(result["revocation"], {"ok": False, "reason": "identity_unverified"})
        self.assertEqual(system.started_ids, [])
        self.assertEqual(system.start_batches, [])
        self.assertEqual(system.stop_batches, [])
        self.assertTrue(os.path.isfile(os.path.join(backup_dir, "COMPLETE")))

    def test_marker_without_initial_state_is_unresolved(self):
        job_id = "req-f3-noinitial"
        manifest, system, job_dir, backup_dir = seeded_job(self.tmp, job_id)
        ctx = JobContext(job_dir)
        os.makedirs(backup_dir, mode=0o700)
        write_bytes(os.path.join(backup_dir, "COMPLETE"), b"complete\n")
        write_bytes(ctx.path(FAILURE_FILE),
                    (json.dumps(valid_journal(job_id)) + "\n").encode())
        write_json_file(ctx.path(REPORT_FILE), {
            "schema_version": 1, "job_id": job_id, "backup_dir": backup_dir,
            "manifest_id": manifest.manifest_id, "state": "succeeded",
        })

        result = finalizer.recover(job_dir, system, manifest)
        self.assertEqual(result["state"], "recovery_required", result)
        self.assertEqual(result["revocation"], {"ok": False, "reason": "identity_unverified"})
        self.assertTrue(os.path.isfile(os.path.join(backup_dir, "COMPLETE")))
        report = ctx.read_json(REPORT_FILE)
        self.assertEqual(report["state"], "recovery_required")
        self.assertEqual(report["recovery"]["revocation"],
                         {"ok": False, "reason": "identity_unverified"})

    # -- revocation syscall failures ---------------------------------------
    def test_unlink_failure_keeps_the_marker_and_no_success(self):
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, "req-f3-unlink")
        ctx = JobContext(job_dir)
        write_bytes(ctx.path(FAILURE_FILE),
                    (json.dumps(valid_journal("req-f3-unlink")) + "\n").encode())
        with mock.patch.object(finalizer.os, "unlink", side_effect=OSError("boom")):
            result = finalizer.recover(job_dir, system, manifest,
                                       service_result=dict(SUCCESS_RESULT))
        self.assertEqual(result["revocation"], {"ok": False, "reason": "marker_unlink_failed"})
        self.assertEqual(result["state"], "recovery_required", result)
        self.assertTrue(os.path.isfile(os.path.join(backup_dir, "COMPLETE")))
        self.assertFalse(coord.is_complete(job_dir)[0])
        payload = self._remote_payload(job_dir, "req-f3-unlink")
        self.assertFalse(payload["operation_complete"])

    def test_fsync_failure_is_unresolved_and_never_success(self):
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, "req-f3-fsync")
        ctx = JobContext(job_dir)
        write_bytes(ctx.path(FAILURE_FILE),
                    (json.dumps(valid_journal("req-f3-fsync")) + "\n").encode())
        with mock.patch.object(finalizer, "_fsync_dir_fd", side_effect=OSError("boom")):
            result = finalizer.recover(job_dir, system, manifest,
                                       service_result=dict(SUCCESS_RESULT))
        self.assertEqual(result["revocation"], {"ok": False, "reason": "marker_fsync_failed"})
        self.assertEqual(result["state"], "recovery_required", result)
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        self.assertFalse(coord.is_complete(job_dir)[0])
        payload = self._remote_payload(job_dir, "req-f3-fsync")
        self.assertFalse(payload["operation_complete"])

    def test_pending_revocation_retry_fsyncs_before_clearing(self):
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, "req-f3-fsync-retry")
        ctx = JobContext(job_dir)
        write_bytes(ctx.path(FAILURE_FILE),
                    (json.dumps(valid_journal("req-f3-fsync-retry")) + "\n").encode())
        with mock.patch.object(finalizer, "_fsync_dir_fd", side_effect=OSError("boom")):
            first = finalizer.recover(job_dir, system, manifest,
                                      service_result=dict(SUCCESS_RESULT))
        self.assertEqual(first["revocation"], {"ok": False, "reason": "marker_fsync_failed"})
        self.assertEqual(first["state"], "recovery_required", first)
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        report = ctx.read_json(REPORT_FILE)
        self.assertEqual(report["recovery"]["revocation"],
                         {"ok": False, "reason": "marker_fsync_failed"})

        # The marker is already gone, so the retry can only prove durable
        # absence by fsyncing the directory again; it must not read the missing
        # entry as a finished revocation.
        calls = []
        real = finalizer._fsync_dir_fd

        def recording(fd):
            calls.append(fd)
            return real(fd)

        with mock.patch.object(finalizer, "_fsync_dir_fd", side_effect=recording):
            second = finalizer.recover(job_dir, system, manifest,
                                       service_result=dict(SUCCESS_RESULT))
        self.assertTrue(calls, "the retry must fsync the directory")
        self.assertEqual(second["state"], "failed", second)
        report = ctx.read_json(REPORT_FILE)
        self.assertEqual(report["recovery"]["revocation"], {"ok": True, "revoked": True})

    # -- worker rerun -------------------------------------------------------
    def test_worker_rerun_refuses_a_terminal_contradiction(self):
        manifest, system, job_dir, backup_dir = completed_job(self.tmp, "req-f3-rerun")
        ctx = JobContext(job_dir)
        write_bytes(ctx.path(FAILURE_FILE),
                    (json.dumps(valid_journal("req-f3-rerun")) + "\n").encode())
        journal_before = read_bytes(ctx.path(FAILURE_FILE))

        fresh = support.SyntheticSystem(manifest, os.path.join(self.tmp, "system-rerun"))
        rerun = BackupWorker(fresh, job_dir, manifest).run()
        self.assertEqual(rerun["state"], "recovery_required", rerun)
        self.assertEqual(rerun["reason"], "failure_journal_present")
        self.assertNotEqual(rerun["state"], "succeeded")
        self.assertEqual(fresh.copy_calls, [])
        self.assertEqual(fresh.stop_batches, [])
        self.assertEqual(fresh.start_batches, [])
        self.assertEqual(read_bytes(ctx.path(FAILURE_FILE)), journal_before)
        self.assertTrue(os.path.isfile(os.path.join(backup_dir, "COMPLETE")))

    # -- real remote_ops subprocess ---------------------------------------
    def _remote_payload(self, job_dir, job_id):
        root = os.path.dirname(os.path.dirname(job_dir))
        code, payload = run_ops(root, "status", job_id)
        self.assertEqual(code, 0, payload)
        return payload

    def test_remote_ops_status_and_blocking_fail_closed_subprocess(self):
        root = tempfile.mkdtemp(prefix="f3-remote-")
        job_id = "req-f3-remote"
        job_dir = os.path.join(root, "jobs", job_id)
        os.makedirs(job_dir, mode=0o700)
        backup_dir = os.path.join(root, "backups", job_id)
        os.makedirs(backup_dir, mode=0o700)
        write_json_file(os.path.join(job_dir, REQUEST_FILE),
                        {"job_id": job_id, "backup_dir": backup_dir, "manifest_id": "m"})
        write_json_file(os.path.join(job_dir, STATE_FILE), {"state": "succeeded"})
        write_json_file(os.path.join(job_dir, REPORT_FILE),
                        writer_report(job_id, backup_dir, "m"))
        write_bytes(os.path.join(backup_dir, "COMPLETE"), b"complete\n")

        # An agreeing job is a complete success and does not block new work.
        code, payload = run_ops(root, "status", job_id)
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload["operation_complete"], payload)
        code, payload = run_ops(root, "blocking")
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["blocking"], [])

        # Add the durable first cause while the marker still exists.
        write_bytes(os.path.join(job_dir, FAILURE_FILE),
                    (json.dumps(valid_journal(job_id)) + "\n").encode())
        code, payload = run_ops(root, "status", job_id)
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload["state"], "recovery_required", payload)
        self.assertEqual(payload["evidence"], "failure_journal_present", payload)
        self.assertFalse(payload["operation_complete"])
        code, payload = run_ops(root, "blocking")
        self.assertEqual(code, 0, payload)
        self.assertEqual([item["job_id"] for item in payload["blocking"]], [job_id])
        # ...and the stale marker blocks a genuinely new reservation.
        code, payload = reserve_only(root, "req-f3-blocked")
        self.assertEqual(code, 3, payload)
        self.assertEqual(payload["error"]["code"], "E_JOB_INCOMPLETE")
        self.assertEqual(payload["error"]["resource"], job_id)


    def test_shipped_standalone_coordination_reports_the_conflict(self):
        from vps3xui.adapters.ssh import _remote_ops_bytes

        root = tempfile.mkdtemp(prefix="f3-standalone-")
        job_id = "req-f3-stand"
        job_dir = os.path.join(root, "jobs", job_id)
        os.makedirs(job_dir, mode=0o700)
        backup_dir = os.path.join(root, "backups", job_id)
        os.makedirs(backup_dir, mode=0o700)
        write_json_file(os.path.join(job_dir, REQUEST_FILE),
                        {"job_id": job_id, "backup_dir": backup_dir})
        write_json_file(os.path.join(job_dir, STATE_FILE), {"state": "succeeded"})
        write_json_file(os.path.join(job_dir, REPORT_FILE),
                        {"job_id": job_id, "state": "succeeded", "backup_dir": backup_dir})
        write_bytes(os.path.join(backup_dir, "COMPLETE"), b"complete\n")
        write_bytes(os.path.join(job_dir, FAILURE_FILE),
                    (json.dumps(valid_journal(job_id)) + "\n").encode())

        # The shipped program is the reviewed coordination module concatenated
        # ahead of remote_ops and executed with ``python3 -``; it must resolve
        # the conflict without importing any helper the release did not ship.
        proc = subprocess.run([sys.executable, "-", root, "status", job_id],
                              input=_remote_ops_bytes(), capture_output=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        payload = json.loads(proc.stdout.decode())
        self.assertEqual(payload["state"], "recovery_required", payload)
        self.assertEqual(payload["evidence"], "failure_journal_present", payload)
        self.assertFalse(payload["operation_complete"])


class SourceGateTest(unittest.TestCase):
    """The source verify/fetch gate and the portable gate agree end to end."""

    def setUp(self):
        self.tmp = support.temp_state_dir("f3-gate-")

    def _completed_host_job(self, request_id):
        manifest = support.approved_manifest(self.tmp)
        host = support.SyntheticHost(manifest, root=os.path.join(self.tmp, "host"))
        plan, _drift, _inventory, _fingerprint = backup_ops.run_plan(host, manifest, 3600)
        plan_path = os.path.join(self.tmp, "plan.json")
        backup_ops.write_plan(plan, plan_path)
        state_dir = os.path.join(self.tmp, "state")
        backup_ops.run_start(host, manifest, plan_path, request_id, state_dir, apply=True)
        return manifest, host, state_dir, request_id

    def test_source_verify_and_fetch_refuse_before_and_after_reconciliation(self):
        request_id = "req-f3-gate"
        manifest, host, state_dir, _request_id = self._completed_host_job(request_id)
        local_job = host._local(backup_ops.job_dir(request_id))
        local_backup = host._local(backup_ops.backup_dir(request_id))
        self.assertTrue(verify_directory(local_backup, manifest, require_complete=True).ok)

        # A durable first cause attached to a marker-bearing success.
        write_bytes(os.path.join(local_job, FAILURE_FILE),
                    (json.dumps(valid_journal(request_id)) + "\n").encode())

        verify = backup_ops.run_verify_job(host, manifest, request_id, state_dir)
        self.assertEqual(verify["state"], "failed", verify)
        self.assertFalse(verify["operation_complete"])
        with self.assertRaises(ToolError) as caught:
            backup_ops.run_fetch(host, manifest, request_id,
                                 os.path.join(self.tmp, "fetched"), state_dir, apply=True)
        self.assertEqual(caught.exception.code, "E_PRECONDITION")

        # Reconciliation revokes the marker; both gates still refuse.
        result = finalizer.recover(local_job, host._system(request_id), manifest, explicit=True)
        self.assertNotEqual(result["state"], "succeeded", result)
        self.assertFalse(os.path.exists(os.path.join(local_backup, "COMPLETE")))
        portable = backup_ops.run_verify_directory(manifest, local_backup)
        self.assertFalse(portable["operation_complete"], portable)
        verify = backup_ops.run_verify_job(host, manifest, request_id, state_dir)
        self.assertFalse(verify["operation_complete"], verify)


if __name__ == "__main__":
    unittest.main()
