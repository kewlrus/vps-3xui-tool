"""R5: identity must gate every finalizer host mutation.

A wrong, missing, malformed or unreadable machine-id, and any recorded
container identity that cannot be matched to the *current* host exactly, must
leave the finalizer with zero Docker/Certbot mutations and state
``recovery_required``. Only a host whose recorded identities were all proven may
run the existing best-effort recovery.
"""

import os
import unittest

import support
from vps3xui.errors import ToolError
from vps3xui.inventory import Inventory
from vps3xui.plan import build_plan
from vps3xui.worker import finalizer
from vps3xui.worker.backup_worker import BackupWorker
from vps3xui.worker.jobctx import INITIAL_STATE_FILE, JobContext, REPORT_FILE

MUTATING_CALLS = ("start_containers", "stop_containers",
                  "restore_certbot_triggers", "disable_certbot_triggers")
SUCCESS_RESULT = {"SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": "0"}


class RecordingSystem(object):
    """Wrap a ``SyntheticSystem`` and record every host call in order.

    ``mutations`` contains only the calls that could change the host, so a test
    can assert that an identity failure performed none of them.
    """

    def __init__(self, inner):
        self.inner = inner
        self.calls = []
        self.started_ids = []

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def machine_id(self):
        self.calls.append("machine_id")
        return self.inner.machine_id()

    def container_states(self, names):
        self.calls.append("container_states")
        return self.inner.container_states(names)

    def start_containers(self, ids):
        self.calls.append("start_containers")
        self.started_ids.extend(ids)
        return self.inner.start_containers(ids)

    def stop_containers(self, ids):
        self.calls.append("stop_containers")
        return self.inner.stop_containers(ids)

    def restore_certbot_triggers(self, state, manifest):
        self.calls.append("restore_certbot_triggers")
        return self.inner.restore_certbot_triggers(state, manifest)

    def disable_certbot_triggers(self, manifest):
        self.calls.append("disable_certbot_triggers")
        return self.inner.disable_certbot_triggers(manifest)

    @property
    def mutations(self):
        return [name for name in self.calls if name in MUTATING_CALLS]


class UnreadableMachineSystem(RecordingSystem):
    def machine_id(self):
        self.calls.append("machine_id")
        raise ToolError("E_RUNTIME_MISSING", "synthetic unreadable machine-id")


class UnreadableContainerSystem(RecordingSystem):
    def container_states(self, names):
        self.calls.append("container_states")
        raise ToolError("E_EXECUTION", "synthetic docker inspect failure")


def copied_job(tmp, job_id, faults=None):
    """Run the real worker so the job holds ``copied`` state and initial evidence."""
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
    system = support.SyntheticSystem(manifest, os.path.join(tmp, "system", job_id), faults=faults)
    BackupWorker(system, job_dir, manifest).run()
    return manifest, system, job_dir, backup_dir, plan


def rewrite_initial(job_dir, mutate):
    ctx = JobContext(job_dir)
    initial = ctx.read_json(INITIAL_STATE_FILE)
    mutate(initial)
    ctx.write_json(INITIAL_STATE_FILE, initial)


class FinalizerIdentityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = support.temp_state_dir("finalizer-identity-")

    def recover(self, manifest, system, job_dir, service_result=None):
        recorder = RecordingSystem(system)
        result = finalizer.recover(job_dir, recorder, manifest,
                                   service_result=service_result)
        return recorder, result

    # -- machine identity -------------------------------------------------
    def test_changed_machine_id_performs_no_host_mutation(self):
        manifest, system, job_dir, backup_dir, _plan = copied_job(self.tmp, "req-r5-machine")
        system.machine = "ffffffffffffffffffffffffffffffff"
        recorder, result = self.recover(manifest, system, job_dir, SUCCESS_RESULT)
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(recorder.mutations, [])
        self.assertFalse(os.path.isfile(os.path.join(backup_dir, "COMPLETE")))
        report = support.read_json_file(os.path.join(job_dir, REPORT_FILE))
        self.assertEqual(report["recovery"]["identity_error"], "machine_id_changed")
        self.assertFalse(report["recovery"]["recovery_complete"])
        self.assertFalse(report["recovery"]["certbot_restored"])

    def test_missing_machine_id_performs_no_host_mutation(self):
        manifest, system, job_dir, _backup, _plan = copied_job(self.tmp, "req-r5-missing")
        rewrite_initial(job_dir, lambda initial: initial.pop("machine_id"))
        recorder, result = self.recover(manifest, system, job_dir, SUCCESS_RESULT)
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(recorder.mutations, [])
        report = support.read_json_file(os.path.join(job_dir, REPORT_FILE))
        self.assertEqual(report["recovery"]["identity_error"], "machine_id_unrecorded")

    def test_malformed_machine_id_performs_no_host_mutation(self):
        manifest, system, job_dir, _backup, _plan = copied_job(self.tmp, "req-r5-malformed")
        rewrite_initial(job_dir, lambda initial: initial.__setitem__("machine_id", {"nope": 1}))
        recorder, result = self.recover(manifest, system, job_dir, SUCCESS_RESULT)
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(recorder.mutations, [])
        report = support.read_json_file(os.path.join(job_dir, REPORT_FILE))
        self.assertEqual(report["recovery"]["identity_error"], "machine_id_malformed")

    def test_unreadable_machine_id_performs_no_host_mutation(self):
        manifest, system, job_dir, _backup, _plan = copied_job(self.tmp, "req-r5-unreadable")
        recorder = UnreadableMachineSystem(system)
        result = finalizer.recover(job_dir, recorder, manifest, service_result=SUCCESS_RESULT)
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(recorder.mutations, [])
        self.assertEqual(recorder.calls, ["machine_id"])
        report = support.read_json_file(os.path.join(job_dir, REPORT_FILE))
        self.assertEqual(report["recovery"]["identity_error"], "machine_id_unreadable")

    # -- container identity ----------------------------------------------
    def test_container_id_mismatch_performs_no_host_mutation(self):
        manifest, system, job_dir, _backup, _plan = copied_job(self.tmp, "req-r5-mismatch")

        def tamper(initial):
            initial["stop_containers"][0]["id"] = "id-litellm-badbad"

        rewrite_initial(job_dir, tamper)
        recorder, result = self.recover(manifest, system, job_dir, SUCCESS_RESULT)
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(recorder.mutations, [])
        report = support.read_json_file(os.path.join(job_dir, REPORT_FILE))
        self.assertEqual(report["recovery"]["container_error"], "container_id_mismatch")

    def test_container_prefix_id_is_never_accepted(self):
        manifest, system, job_dir, _backup, _plan = copied_job(self.tmp, "req-r5-prefix")

        def tamper(initial):
            full = initial["stop_containers"][0]["id"]
            initial["stop_containers"][0]["id"] = full[:6]

        rewrite_initial(job_dir, tamper)
        recorder, result = self.recover(manifest, system, job_dir, SUCCESS_RESULT)
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(recorder.mutations, [])
        report = support.read_json_file(os.path.join(job_dir, REPORT_FILE))
        self.assertEqual(report["recovery"]["container_error"], "container_id_mismatch")

    def test_missing_container_performs_no_host_mutation(self):
        manifest, system, job_dir, _backup, _plan = copied_job(self.tmp, "req-r5-container-missing")
        del system.containers["caddy"]
        recorder, result = self.recover(manifest, system, job_dir, SUCCESS_RESULT)
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(recorder.mutations, [])
        report = support.read_json_file(os.path.join(job_dir, REPORT_FILE))
        self.assertEqual(report["recovery"]["container_error"], "container_missing")

    def test_container_inspect_exception_performs_no_host_mutation(self):
        manifest, system, job_dir, _backup, _plan = copied_job(self.tmp, "req-r5-inspect")
        recorder = UnreadableContainerSystem(system)
        result = finalizer.recover(job_dir, recorder, manifest, service_result=SUCCESS_RESULT)
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(recorder.mutations, [])
        report = support.read_json_file(os.path.join(job_dir, REPORT_FILE))
        self.assertEqual(report["recovery"]["container_error"], "container_inspect_failed")

    def test_record_without_container_id_is_not_started(self):
        manifest, system, job_dir, _backup, _plan = copied_job(self.tmp, "req-r5-noid")

        def tamper(initial):
            initial["stop_containers"][0]["id"] = None

        rewrite_initial(job_dir, tamper)
        recorder, result = self.recover(manifest, system, job_dir, SUCCESS_RESULT)
        self.assertEqual(result["state"], "recovery_required")
        self.assertEqual(recorder.mutations, [])
        report = support.read_json_file(os.path.join(job_dir, REPORT_FILE))
        self.assertEqual(report["recovery"]["container_error"], "container_id_unrecorded")

    # -- valid recovery and best-effort semantics -------------------------
    def test_valid_recovery_starts_recorded_only_and_restores_certbot(self):
        manifest, system, job_dir, backup_dir, _plan = copied_job(self.tmp, "req-r5-valid")
        recorded = support.read_json_file(os.path.join(job_dir, INITIAL_STATE_FILE))["stop_containers"]
        recorder, result = self.recover(manifest, system, job_dir, SUCCESS_RESULT)
        self.assertEqual(result["state"], "succeeded", result)
        self.assertTrue(os.path.isfile(os.path.join(backup_dir, "COMPLETE")))
        # The validation inspect runs before the first mutation.
        self.assertEqual(recorder.calls[0], "machine_id")
        self.assertEqual(recorder.calls[1], "container_states")
        self.assertLess(recorder.calls.index("container_states"),
                        recorder.calls.index("start_containers"))
        self.assertEqual(recorder.started_ids, [item["id"] for item in recorded])
        # Originally stopped containers are never started.
        self.assertNotIn("id-telemt-0004", recorder.started_ids)
        self.assertIn("restore_certbot_triggers", recorder.calls)
        for name in (item["name"] for item in recorded):
            self.assertEqual(system.containers[name]["running"], True)

    def test_start_failure_still_attempts_every_container_and_restores_certbot(self):
        manifest, system, job_dir, _backup, _plan = copied_job(
            self.tmp, "req-r5-start-fail", faults={"start_fail": True}
        )
        recorded = support.read_json_file(os.path.join(job_dir, INITIAL_STATE_FILE))["stop_containers"]
        recorder, result = self.recover(manifest, system, job_dir, SUCCESS_RESULT)
        self.assertEqual(result["state"], "recovery_required", result)
        self.assertFalse(result["recovered"])
        # Every recorded container was attempted, one id at a time, in order.
        self.assertEqual(recorder.started_ids, [item["id"] for item in recorded])
        self.assertEqual(sorted(result["container_failures"]),
                         sorted(item["name"] for item in recorded))
        # Certbot is still restored on the verified host; post-start verify ran.
        self.assertIn("restore_certbot_triggers", recorder.calls)
        self.assertEqual(recorder.calls.count("container_states"), 1 + len(recorded))
        report = support.read_json_file(os.path.join(job_dir, REPORT_FILE))
        self.assertFalse(report["recovery"]["recovery_complete"])
        self.assertIsNone(report["recovery"].get("identity_error"))
        self.assertIsNone(report["recovery"].get("container_error"))


if __name__ == "__main__":
    unittest.main()
