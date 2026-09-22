import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import restore_support as rs
from vps3xui import coordination as coord
from vps3xui.errors import ToolError
from vps3xui.restore import contracts
from vps3xui.restore import job as rj

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
STEP_KIND = {
    "prepared_target": ("package", "docker-ce"),
    "verified_payload": ("payload", "/var/lib/vps3xui-restore/payload"),
    "data_restored": ("file_tree", "/opt/litellm"),
    "containers_created": ("container", "litellm"),
    "guard_prepared": ("certbot_automation", "certbot-guard"),
    "activation": ("container", "litellm:start"),
    "verification_report": ("payload", "verification-report"),
    "certbot_activated": ("certbot_automation", "certbot.timer"),
}


class RestoreJobTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.manifest, self.backup_dir, self.backup, self.plan, self.request = rs.scenario(self.tmp)
        self.root = os.path.join(self.tmp, "state")
        self.store = rj.RestoreJobStore(self.root)
        self.job_id = self.plan["job_id"]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def assertCode(self, code, func, *args, **kwargs):
        with self.assertRaises(ToolError) as caught:
            func(*args, **kwargs)
        self.assertEqual(caught.exception.code, code, caught.exception.message)
        return caught.exception

    def register(self):
        request, created = self.store.register(self.plan, rs.RELEASE_DIGEST, now=rs.NOW)
        return request

    def run_stage(self, job, stage, cutover=None):
        job.begin_stage(stage, self.plan, now=rs.NOW, cutover=cutover)
        receipts = {}
        for kind in contracts.STAGE_PRODUCES[stage]:
            step_id = "step:" + kind
            resource_kind, resource = STEP_KIND[kind]
            intent = job.intent(step_id, resource_kind, resource, "created_by_job",
                                {"state": "present"}, preexisting=False, now=rs.NOW)
            job.outcome(intent, "applied", {"state": "present"}, now=rs.NOW)
            receipts[kind] = contracts.build_receipt(kind, self.plan, job.steps(), [step_id],
                                                     {"state": "present"}, now=rs.NOW)
        return job.complete_stage(receipts, now=rs.NOW)

    def to_state(self, final_stage):
        self.register()
        with self.store.session(self.job_id) as job:
            for stage in contracts.STAGES:
                self.run_stage(job, stage, cutover=cutover() if stage == "activate" else None)
                if stage == final_stage:
                    return


def cutover():
    return {"observation_digest": "a" * 64, "attestation_digest": "b" * 64,
            "fencing_method": "docker_units_masked", "observed_at": "2026-09-23T12:00:00Z",
            "attested_at": "2026-09-23T12:00:00Z", "evaluated_at": "2026-09-23T12:00:00Z"}


def entry_names(path):
    return sorted(name for name in os.listdir(path) if not name.startswith(".tmp-"))


class RegistrationTest(RestoreJobTestCase):
    def test_register_is_durable_private_and_idempotent(self):
        request, created = self.store.register(self.plan, rs.RELEASE_DIGEST, now=rs.NOW)
        self.assertTrue(created)
        self.assertEqual(request, self.request)
        path = self.store.job_path(self.job_id)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o700)
        for name in (rj.REQUEST_FILE, rj.STATE_FILE):
            self.assertEqual(os.stat(os.path.join(path, name)).st_mode & 0o777, 0o600)
        # Lost response: the same plan resolves the existing job, nothing is recreated.
        again, created = self.store.register(self.plan, rs.RELEASE_DIGEST, now=rs.NOW)
        self.assertFalse(created)
        self.assertEqual(again, request)
        self.assertEqual(self.store.open(self.job_id).state_record()["state"], "planned")

    def test_later_stage_plan_resumes_same_job(self):
        self.register()
        later = rs.restore_plan(self.manifest, self.backup, now=rs.NOW + contracts.datetime.timedelta(minutes=5))
        self.assertNotEqual(later["identity"], self.plan["identity"])
        _request, created = self.store.register(later, rs.RELEASE_DIGEST, now=rs.NOW)
        self.assertFalse(created)

    def test_different_bindings_under_same_job_conflict(self):
        self.register()
        other = rs.restore_plan(self.manifest, self.backup,
                                target=rs.target_facts(machine_id="d" * 32))
        forged = rs.mutated(other, "job_id", self.job_id)
        with mock.patch.object(contracts, "validate_restore_plan", return_value=forged):
            self.assertCode("E_REQUEST_ID_CONFLICT", self.store.register, forged, rs.RELEASE_DIGEST)

    def test_other_tool_version_does_not_resume(self):
        self.register()
        stale = rs.mutated(self.plan, "tool_version", "0.0.1")
        with mock.patch.object(contracts, "validate_restore_plan", return_value=stale):
            self.assertCode("E_PLAN_STALE", self.store.register, stale, rs.RELEASE_DIGEST)

    def test_concurrent_registration_creates_one_job(self):
        results, errors = [], []

        def worker():
            try:
                results.append(self.store.register(self.plan, rs.RELEASE_DIGEST, now=rs.NOW,
                                                   wait_seconds=10)[1])
            except ToolError as error:
                errors.append(error.code)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(sorted(results), [False] * 5 + [True])
        self.assertEqual(entry_names(coord.restore_jobs_root(self.root)), [self.job_id])

    def test_held_lock_refuses_without_waiting(self):
        with coord.stack_lock(self.root):
            self.assertCode("E_LOCKED", self.store.register, self.plan, rs.RELEASE_DIGEST)
        self.assertFalse(os.path.exists(coord.restore_jobs_root(self.root)))

    def test_failed_registration_leaves_no_job(self):
        with mock.patch("os.fsync", side_effect=OSError("disk")):
            self.assertRaises(ToolError, self.store.register, self.plan, rs.RELEASE_DIGEST)
        self.assertFalse(self.store.exists(self.job_id))
        self.assertEqual(coord.scan_blocking(self.root), [])
        self.register()


class SharedLockTest(RestoreJobTestCase):
    def backup_job(self, state):
        path = coord.job_dir(self.root, "job-1")
        coord.ensure_dir(path)
        coord.replace_json(os.path.join(path, coord.STATE_FILE), {"state": state})

    def test_unfinished_backup_blocks_restore(self):
        self.backup_job("copying")
        self.assertCode("E_JOB_INCOMPLETE", self.store.register, self.plan, rs.RELEASE_DIGEST)

    def test_unfinished_restore_blocks_backup_and_other_restore(self):
        self.to_state("stage")
        self.assertCode("E_JOB_INCOMPLETE", coord.assert_no_blocking, self.root)
        self.assertCode("E_JOB_INCOMPLETE", coord.assert_no_blocking, self.root, ignoring=self.job_id)
        coord.assert_no_blocking(self.root, ignoring_restore=self.job_id)
        other = rs.restore_plan(self.manifest, self.backup, target=rs.target_facts(machine_id="d" * 32))
        self.assertCode("E_JOB_INCOMPLETE", self.store.register, other, rs.RELEASE_DIGEST)

    def test_verified_restore_is_settled(self):
        self.to_state("verify")
        self.assertEqual(coord.scan_blocking(self.root), [])
        coord.assert_no_blocking(self.root)

    def test_unreadable_restore_entry_blocks(self):
        parent = coord.restore_jobs_root(self.root)
        coord.ensure_dir(parent)
        with open(os.path.join(parent, "stray"), "w") as handle:
            handle.write("x")
        self.assertEqual(coord.scan_blocking(self.root)[0]["state"], "unknown")

    def test_p0_scan_without_restore_jobs_is_unchanged(self):
        self.assertEqual(coord.scan_blocking(self.root), [])
        self.backup_job("copying")
        self.assertEqual(coord.scan_blocking(self.root), [{"job_id": "job-1", "state": "copying"}])


class StageMachineTest(RestoreJobTestCase):
    def test_full_happy_path_and_receipts(self):
        self.to_state("certbot_activate")
        job = self.store.open(self.job_id)
        status = job.status()
        self.assertEqual(status["state"], "certbot_active")
        self.assertTrue(status["settled"])
        self.assertEqual(sorted(status["receipts"]), sorted(contracts.RECEIPT_STAGE))
        self.assertIsNone(status["primary_failure"])

    def test_staged_does_not_permit_start(self):
        self.to_state("stage")
        with self.store.session(self.job_id) as job:
            status = job.status()
            self.assertEqual(status["state"], "staged")
            self.assertFalse(status["start_permitted"])
            self.assertCode("E_PRECONDITION", job.begin_stage, "activate", self.plan, now=rs.NOW)
            self.assertCode("E_PRECONDITION", job.begin_stage, "activate", self.plan, now=rs.NOW,
                            cutover={"observation_digest": "a" * 64})
            self.assertEqual(job.state_record()["state"], "staged")

    def test_stage_order_is_enforced(self):
        self.register()
        with self.store.session(self.job_id) as job:
            self.assertCode("E_PRECONDITION", job.begin_stage, "stage", self.plan, now=rs.NOW)

    def test_changes_need_the_lock(self):
        self.register()
        job = self.store.open(self.job_id)
        self.assertCode("E_CONTRACT", job.begin_stage, "prepare", self.plan, now=rs.NOW)

    def test_expired_plan_refused(self):
        self.register()
        late = rs.NOW + contracts.datetime.timedelta(hours=2)
        with self.store.session(self.job_id) as job:
            self.assertCode("E_PLAN_EXPIRED", job.begin_stage, "prepare", self.plan, now=late)

    def test_changed_target_plan_refused_at_stage(self):
        self.register()
        other = rs.restore_plan(self.manifest, self.backup, target=rs.target_facts(machine_id="d" * 32))
        with self.store.session(self.job_id) as job:
            self.assertCode("E_REQUEST_ID_CONFLICT", job.begin_stage, "prepare", other, now=rs.NOW)
            self.assertEqual(job.state_record()["state"], "planned")

    def test_verify_may_repeat(self):
        self.to_state("verify")
        with self.store.session(self.job_id) as job:
            job.begin_stage("verify", self.plan, now=rs.NOW)
            self.assertEqual(job.state_record()["state"], "verifying")


class JournalTest(RestoreJobTestCase):
    def setUp(self):
        super(JournalTest, self).setUp()
        self.register()

    def journal_dir(self):
        return os.path.join(self.store.job_path(self.job_id), rj.JOURNAL_DIR)

    def test_intent_is_durable_before_effect(self):
        with self.store.session(self.job_id) as job:
            job.begin_stage("prepare", self.plan, now=rs.NOW)
            job.intent("pkg", "package", "docker-ce", "created_by_job", {"state": "installed"},
                       preexisting=False, now=rs.NOW)
            names = entry_names(self.journal_dir())
            self.assertEqual(names, ["000001.json"])
            mode = os.stat(os.path.join(self.journal_dir(), names[0])).st_mode & 0o777
            self.assertEqual(mode, 0o600)
            self.assertEqual(job.status()["state"], "unknown")
            self.assertEqual(job.status()["unknown_steps"], ["pkg"])

    def test_intent_write_failure_blocks_the_effect(self):
        with self.store.session(self.job_id) as job:
            job.begin_stage("prepare", self.plan, now=rs.NOW)
            with mock.patch("os.fsync", side_effect=OSError("io")):
                self.assertCode("E_STATE_WRITE_FAILED", job.intent, "pkg", "package", "docker-ce",
                                "created_by_job", {"state": "installed"}, preexisting=False)
            self.assertEqual(entry_names(self.journal_dir()), [])
            self.assertEqual(job.status()["state"], "preparing")

    def test_outcome_write_failure_leaves_step_unknown(self):
        with self.store.session(self.job_id) as job:
            job.begin_stage("prepare", self.plan, now=rs.NOW)
            intent = job.intent("pkg", "package", "docker-ce", "created_by_job",
                                {"state": "installed"}, preexisting=False, now=rs.NOW)
            with mock.patch("os.fsync", side_effect=OSError("io")):
                self.assertCode("E_STATE_WRITE_FAILED", job.outcome, intent, "applied",
                                {"state": "installed"})
            status = job.status()
            self.assertEqual(status["state"], "unknown")
            self.assertEqual(status["owned_resources"][0]["outcome"], "unknown")
            self.assertCode("E_JOB_INCOMPLETE", job.intent, "other", "package", "curl",
                            "created_by_job", {}, preexisting=False)

    def test_state_write_failure_is_not_success(self):
        with self.store.session(self.job_id) as job:
            job.begin_stage("prepare", self.plan, now=rs.NOW)
            intent = job.intent("pkg", "package", "docker-ce", "created_by_job",
                                {"state": "installed"}, preexisting=False, now=rs.NOW)
            job.outcome(intent, "applied", {"state": "installed"}, now=rs.NOW)
            receipt = contracts.build_receipt("prepared_target", self.plan, job.steps(), ["pkg"],
                                              {"ok": True}, now=rs.NOW)
            real_replace = coord.replace_json

            def failing(path, obj):
                if os.path.basename(path) == rj.STATE_FILE:
                    raise ToolError("E_STATE_WRITE_FAILED", "no space")
                return real_replace(path, obj)

            with mock.patch.object(coord, "replace_json", side_effect=failing):
                self.assertCode("E_STATE_WRITE_FAILED", job.complete_stage,
                                {"prepared_target": receipt}, now=rs.NOW)
            self.assertEqual(job.status()["state"], "preparing")
            self.assertCode("E_PRECONDITION", job.begin_stage, "stage", self.plan, now=rs.NOW)

    def test_unknown_command_result_stops_the_job(self):
        with self.store.session(self.job_id) as job:
            job.begin_stage("prepare", self.plan, now=rs.NOW)
            intent = job.intent("pkg", "package", "docker-ce", "created_by_job",
                                {"state": "installed"}, preexisting=False, now=rs.NOW)
            job.outcome(intent, "unknown", None, error={"code": "E_EXECUTION"}, now=rs.NOW)
            self.assertEqual(job.state_record()["state"], "unknown")
            self.assertEqual(job.primary_failure()["step_id"], "pkg")
            self.assertCode("E_JOB_INCOMPLETE", job.begin_stage, "prepare", self.plan, now=rs.NOW)

    def test_foreign_resource_is_never_claimed(self):
        with self.store.session(self.job_id) as job:
            job.begin_stage("prepare", self.plan, now=rs.NOW)
            self.assertCode("E_NOT_OWNED", job.intent, "vol", "volume", "litellm_data",
                            "created_by_job", {}, preexisting=True)
            self.assertCode("E_PRECONDITION", job.intent, "vol", "volume", "litellm_data",
                            "created_by_job", {}, preexisting=None)
            self.assertCode("E_PRECONDITION", job.intent, "vol", "volume", "litellm_data",
                            "preexisting_accepted", {}, preexisting=False)
            job.intent("vol", "volume", "litellm_data", "preexisting_accepted", {},
                       preexisting=True, now=rs.NOW)
            self.assertEqual(job.status()["owned_resources"], [])

    def test_retry_of_own_resource_after_failure(self):
        with self.store.session(self.job_id) as job:
            job.begin_stage("prepare", self.plan, now=rs.NOW)
            intent = job.intent("dir", "directory", "/opt/litellm", "created_by_job", {},
                                preexisting=False, now=rs.NOW)
            job.outcome(intent, "failed", {"present": True}, error={"code": "E_EXECUTION"}, now=rs.NOW)
            # The partially created directory now exists but is not owned by an applied step.
            self.assertCode("E_NOT_OWNED", job.intent, "dir", "directory", "/opt/litellm",
                            "created_by_job", {}, preexisting=True)
            self.assertCode("E_CONFLICT", job.intent, "dir", "directory", "/opt/other",
                            "created_by_job", {}, preexisting=False)

    def test_applied_step_is_not_repeated(self):
        with self.store.session(self.job_id) as job:
            job.begin_stage("prepare", self.plan, now=rs.NOW)
            intent = job.intent("pkg", "package", "docker-ce", "created_by_job", {},
                                preexisting=False, now=rs.NOW)
            job.outcome(intent, "applied", {"state": "installed"}, now=rs.NOW)
            self.assertCode("E_CONFLICT", job.intent, "pkg", "package", "docker-ce",
                            "created_by_job", {}, preexisting=True)
            self.assertCode("E_CONFLICT", job.outcome, intent, "applied", {"state": "installed"})

    def test_foreign_journal_entry_requires_recovery(self):
        with self.store.session(self.job_id) as job:
            job.begin_stage("prepare", self.plan, now=rs.NOW)
            foreign, _ = rs.applied_step("rst-" + "0" * 24, 1, "pkg")
            rj.publish_exclusive(os.path.join(self.journal_dir(), "000001.json"), foreign)
            status = job.status()
            self.assertEqual(status["state"], "recovery_required")
            self.assertEqual(status["record_problem"], "E_NOT_OWNED")
            self.assertCode("E_NOT_OWNED", job.intent, "x", "package", "curl",
                            "created_by_job", {}, preexisting=False)

    def test_broken_sequence_and_stray_files_require_recovery(self):
        with self.store.session(self.job_id) as job:
            job.begin_stage("prepare", self.plan, now=rs.NOW)
            intent, _ = rs.applied_step(self.job_id, 1, "pkg")
            rj.publish_exclusive(os.path.join(self.journal_dir(), "000002.json"), intent)
            self.assertEqual(job.status()["state"], "recovery_required")
            os.unlink(os.path.join(self.journal_dir(), "000002.json"))
            with open(os.path.join(self.journal_dir(), "notes.txt"), "w") as handle:
                handle.write("x")
            self.assertEqual(job.status()["state"], "recovery_required")

    def test_unpublished_temp_entry_is_ignored(self):
        with self.store.session(self.job_id) as job:
            job.begin_stage("prepare", self.plan, now=rs.NOW)
            coord.ensure_dir(self.journal_dir())
            with open(os.path.join(self.journal_dir(), ".tmp-abc"), "w") as handle:
                handle.write("{")
            self.assertEqual(job.status()["state"], "preparing")

    def test_existing_entry_is_never_replaced(self):
        with self.store.session(self.job_id) as job:
            job.begin_stage("prepare", self.plan, now=rs.NOW)
            intent = job.intent("pkg", "package", "docker-ce", "created_by_job", {},
                                preexisting=False, now=rs.NOW)
            path = os.path.join(self.journal_dir(), "000001.json")
            self.assertCode("E_CONFLICT", rj.publish_exclusive, path, {"other": True})
            with open(path) as handle:
                self.assertEqual(json.load(handle), intent)

    def test_context_exposes_the_durable_journal(self):
        with self.store.session(self.job_id) as job:
            context = job.context(self.plan)
            self.assertIs(context.journal, job)
            self.assertEqual(context.request, self.request)
            self.assertEqual(context.receipts, {})


class FailureTest(RestoreJobTestCase):
    def setUp(self):
        super(FailureTest, self).setUp()
        self.register()

    def test_first_cause_is_kept_across_retries(self):
        with self.store.session(self.job_id) as job:
            job.begin_stage("prepare", self.plan, now=rs.NOW)
            intent = job.intent("pkg", "package", "docker-ce", "created_by_job", {},
                                preexisting=False, now=rs.NOW)
            job.outcome(intent, "failed", {"state": "absent"}, error={"code": "E_EXECUTION"}, now=rs.NOW)
            state = job.fail_stage(ToolError("E_EXECUTION", "apt failed", resource="docker-ce"),
                                   retryable=True, now=rs.NOW, step_id="pkg")
            self.assertEqual(state, "preparing")
            job.begin_stage("prepare", self.plan, now=rs.NOW)
            intent = job.intent("pkg", "package", "docker-ce", "created_by_job", {},
                                preexisting=False, now=rs.NOW)
            job.outcome(intent, "failed", {"state": "absent"}, now=rs.NOW)
            state = job.fail_stage(ToolError("E_PRECONDITION", "later"), retryable=False, now=rs.NOW)
            self.assertEqual(state, "failed")
            failure = job.primary_failure()
            self.assertEqual((failure["code"], failure["attempt"], failure["step_id"]),
                             ("E_EXECUTION", 1, "pkg"))
            attempts = job.attempts()
            self.assertEqual([item["result"] for item in attempts], ["failed", "failed"])
            self.assertEqual(attempts[1]["error"]["code"], "E_PRECONDITION")
            self.assertCode("E_JOB_INCOMPLETE", job.begin_stage, "prepare", self.plan, now=rs.NOW)
            self.assertTrue(job.status()["blocking"])

    def test_receipt_of_another_target_requires_recovery(self):
        other = rs.restore_plan(self.manifest, self.backup, target=rs.target_facts(machine_id="d" * 32))
        with self.store.session(self.job_id) as job:
            job.begin_stage("prepare", self.plan, now=rs.NOW)
            intent = job.intent("pkg", "package", "docker-ce", "created_by_job", {},
                                preexisting=False, now=rs.NOW)
            job.outcome(intent, "applied", {"state": "installed"}, now=rs.NOW)
            foreign = contracts.build_receipt("prepared_target", other, job.steps(), ["pkg"],
                                              {"ok": True}, now=rs.NOW)
            self.assertCode("E_NOT_OWNED", job.complete_stage, {"prepared_target": foreign}, now=rs.NOW)
            self.assertEqual(job.state_record()["state"], "recovery_required")
            self.assertEqual(job.primary_failure()["code"], "E_NOT_OWNED")
            self.assertEqual(job.receipts(), {})

    def test_receipt_without_journaled_step_is_refused(self):
        with self.store.session(self.job_id) as job:
            job.begin_stage("prepare", self.plan, now=rs.NOW)
            fake_steps = {"ghost": {"stage": "prepare", "outcome": "applied"}}
            receipt = contracts.build_receipt("prepared_target", self.plan, fake_steps, ["ghost"],
                                              {"ok": True}, now=rs.NOW)
            self.assertCode("E_VERIFY_FAILED", job.complete_stage, {"prepared_target": receipt}, now=rs.NOW)
            self.assertEqual(job.state_record()["state"], "failed")

    def test_tampered_stored_receipt_is_refused(self):
        self.to_state_prepared()
        path = os.path.join(self.store.job_path(self.job_id), rj.RECEIPTS_DIR, "prepared_target.json")
        with open(path) as handle:
            receipt = json.load(handle)
        coord.replace_json(path, rs.mutated(receipt, "steps", ["other"]))
        with self.store.session(self.job_id) as job:
            self.assertEqual(job.status()["state"], "recovery_required")
            self.assertCode("E_VERIFY_FAILED", job.begin_stage, "stage", self.plan, now=rs.NOW)

    def to_state_prepared(self):
        with self.store.session(self.job_id) as job:
            self.run_stage(job, "prepare")


KILL_SCRIPT = r"""
import os, signal, sys
sys.path[:0] = [sys.argv[1], os.path.join(sys.argv[1], "tests")]
import json
import restore_support as rs
from vps3xui.restore import job as rj
with open(sys.argv[2]) as handle:
    plan = json.load(handle)
store = rj.RestoreJobStore(sys.argv[3])
with store.session(plan["job_id"]) as job:
    job.begin_stage("prepare", plan, now=rs.NOW)
    job.intent("dir", "directory", sys.argv[4], "created_by_job", {"present": True},
               preexisting=False, now=rs.NOW)
    os.mkdir(sys.argv[4])  # the effect happens
    os.kill(os.getpid(), signal.SIGKILL)  # ... and the receipt is never written
"""


class SigkillTest(RestoreJobTestCase):
    def test_sigkill_between_effect_and_outcome(self):
        plan = self.plan
        self.store.register(plan, rs.RELEASE_DIGEST, now=rs.NOW)
        plan_file = os.path.join(self.tmp, "plan.json")
        with open(plan_file, "w") as handle:
            json.dump(plan, handle)
        resource = os.path.join(self.tmp, "created-by-effect")
        proc = subprocess.run([sys.executable, "-c", KILL_SCRIPT, REPO, plan_file, self.root, resource],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60,
                              env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        self.assertEqual(proc.returncode, -signal.SIGKILL)
        self.assertTrue(os.path.isdir(resource))
        job_id = plan["job_id"]
        # The kernel released the lock with the process; nothing reports success.
        job = self.store.open(job_id)
        status = job.status()
        self.assertEqual(status["state"], "unknown")
        self.assertEqual(status["recorded_state"], "preparing")
        self.assertEqual(status["owned_resources"],
                         [{"step_id": "dir", "kind": "directory", "resource": resource, "outcome": "unknown"}])
        self.assertIn(job_id, [item["job_id"] for item in coord.scan_blocking(self.root)])
        with self.store.session(job_id) as locked:
            view = locked.reconcile({"interrupted": True, "reason": "unit_not_active"}, now=rs.NOW)
            self.assertEqual(view["state"], "unknown")
            self.assertEqual(locked.state_record()["state"], "unknown")
            self.assertEqual(locked.primary_failure()["code"], "E_INTERRUPTED")
            self.assertEqual(locked.attempts()[-1]["result"], "interrupted")
            self.assertCode("E_JOB_INCOMPLETE", locked.begin_stage, "prepare", plan, now=rs.NOW)
        # Undetermined data is never deleted automatically.
        self.assertTrue(os.path.isdir(resource))
        self.assertCode("E_JOB_INCOMPLETE", coord.assert_no_blocking, self.root)


class ScanTest(RestoreJobTestCase):
    def test_scan_reports_every_job(self):
        self.to_state("prepare")
        parent = coord.restore_jobs_root(self.root)
        os.mkdir(os.path.join(parent, "broken"), 0o700)
        views = {item["job_id"]: item for item in rj.scan_restore_jobs(self.root)}
        self.assertEqual(views[self.job_id]["state"], "prepared")
        self.assertEqual(views["broken"]["state"], "recovery_required")
        self.assertTrue(views["broken"]["blocking"])

    def test_corrupt_state_requires_recovery(self):
        self.register()
        path = os.path.join(self.store.job_path(self.job_id), rj.STATE_FILE)
        coord.atomic_write_bytes(path, b"{not json")
        self.assertEqual(self.store.open(self.job_id).status()["state"], "recovery_required")
        self.assertEqual(coord.scan_blocking(self.root)[0]["state"], "unknown")


if __name__ == "__main__":
    unittest.main()
