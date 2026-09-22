import datetime
import json
import os
import shutil
import tempfile
import unittest

import restore_support as rs
import support
from vps3xui.errors import ToolError
from vps3xui.restore import contracts
from vps3xui.verify import verify_directory

MINUTE = datetime.timedelta(minutes=1)


class RestoreContractTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.manifest, self.backup_dir, self.backup, self.plan, self.request = rs.scenario(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def assertCode(self, code, func, *args, **kwargs):
        with self.assertRaises(ToolError) as caught:
            func(*args, **kwargs)
        self.assertEqual(caught.exception.code, code, caught.exception.message)
        return caught.exception


class SchemaFilesTest(unittest.TestCase):
    def test_every_schema_loads_and_is_closed(self):
        for kind, name in contracts.SCHEMA_FILES.items():
            schema = contracts.load_schema(kind)
            self.assertFalse(schema["additionalProperties"], name)
            self.assertTrue(schema["schema"].startswith("vps3xui/restore-"), name)
            self.assertEqual(schema["properties"]["schema_version"]["enum"], [1], name)

    def test_stage_graph_is_closed(self):
        produced = set()
        for stage in contracts.STAGES:
            for kind in contracts.STAGE_REQUIRES[stage]:
                self.assertIn(kind, produced, "%s needs %s before it is produced" % (stage, kind))
            produced.update(contracts.STAGE_PRODUCES[stage])
        self.assertEqual(produced, set(contracts.RECEIPT_STAGE))


class BackupIdentityTest(RestoreContractTestCase):
    def test_identity_binds_sums_and_manifest(self):
        self.assertEqual(self.backup["backup_digest"], rs.sums_digest(self.backup_dir))
        self.assertEqual(self.backup["manifest_digest"], self.manifest.digest)
        self.assertEqual(self.backup["format_version"], 1)
        # P0 metadata carries no source identity: none leaks into the backup record.
        self.assertNotIn("machine_id", json.dumps(self.backup))

    def test_unverified_backup_is_refused(self):
        os.remove(os.path.join(self.backup_dir, "COMPLETE"))
        result = verify_directory(self.backup_dir, self.manifest)
        self.assertFalse(result.ok)
        self.assertCode("E_VERIFY_FAILED", contracts.backup_identity,
                        self.backup_dir, self.manifest, result)

    def test_other_manifest_is_refused(self):
        verified = verify_directory(self.backup_dir, self.manifest)
        other = support.approved_manifest(os.path.join(self.tmp, "other"), manifest_id="other-stack")
        self.assertCode("E_TRUST_MISMATCH", contracts.backup_identity, self.backup_dir, other, verified)

    def test_unsupported_format_is_refused(self):
        verified = verify_directory(self.backup_dir, self.manifest)
        path = os.path.join(self.backup_dir, "backup.json")
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        data["schema_version"] = 2
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        self.assertCode("E_UNSUPPORTED", contracts.backup_identity, self.backup_dir, self.manifest, verified)


class SourceIdentityTest(RestoreContractTestCase):
    def unpinned(self, **source):
        data = dict(self.manifest.data)
        pins = {"expected_machine_id": None, "expected_host_key_fingerprint": None}
        pins.update(source)
        data["source"] = dict(data["source"], **pins)
        from vps3xui.manifest import Manifest
        return Manifest(None, data)

    def test_complete_manifest_pins(self):
        source = contracts.resolve_source_identity(self.backup, self.manifest)
        self.assertEqual(source["provenance"], "manifest_pins")
        self.assertEqual(source["machine_id"], support.MACHINE_ID)

    def test_bound_source_record_accepted(self):
        source = contracts.resolve_source_identity(self.backup, self.manifest, rs.source_record(self.backup))
        self.assertEqual(source["provenance"], "source_record")

    def test_unpinned_without_record_is_refused(self):
        manifest = self.unpinned()
        backup = dict(self.backup, manifest_digest=manifest.digest)
        self.assertCode("E_PRECONDITION", contracts.resolve_source_identity, backup, manifest)

    def test_single_pin_is_not_enough(self):
        manifest = self.unpinned(expected_machine_id=support.MACHINE_ID)
        backup = dict(self.backup, manifest_digest=manifest.digest)
        self.assertCode("E_PRECONDITION", contracts.resolve_source_identity, backup, manifest)

    def test_unpinned_with_bound_record(self):
        manifest = self.unpinned()
        backup = dict(self.backup, manifest_digest=manifest.digest)
        source = contracts.resolve_source_identity(backup, manifest, rs.source_record(backup))
        self.assertEqual(source["host_key_fingerprint"], support.HOST_KEY)

    def test_record_for_other_backup_is_refused(self):
        record = rs.mutated(rs.source_record(self.backup), "backup_digest", "0" * 64)
        self.assertCode("E_TRUST_MISMATCH", contracts.resolve_source_identity,
                        self.backup, self.manifest, record)
        record = rs.mutated(rs.source_record(self.backup), "obtained.source_job_id", "other-job")
        self.assertCode("E_TRUST_MISMATCH", contracts.resolve_source_identity,
                        self.backup, self.manifest, record)

    def test_record_contradicting_pins_is_refused(self):
        record = rs.source_record(self.backup, machine_id="c" * 32)
        self.assertCode("E_TRUST_MISMATCH", contracts.resolve_source_identity,
                        self.backup, self.manifest, record)

    def test_incomplete_record_is_refused(self):
        record = rs.source_record(self.backup)
        del record["source"]["machine_id"]
        self.assertCode("E_TRUST_MISMATCH", contracts.resolve_source_identity,
                        self.backup, self.manifest, record)

    def test_manifest_of_other_backup_is_refused(self):
        backup = dict(self.backup, manifest_digest="0" * 64)
        self.assertCode("E_TRUST_MISMATCH", contracts.resolve_source_identity, backup, self.manifest)


class TargetAndPlanTest(RestoreContractTestCase):
    def test_plan_is_valid_and_bound(self):
        plan = contracts.validate_restore_plan(self.plan)
        self.assertTrue(plan["job_id"].startswith(contracts.JOB_ID_PREFIX))
        self.assertEqual(plan["activation_boundary"]["automatic_source_actions"], [])
        self.assertEqual(plan["target"]["platform_id"], "ubuntu-24.04-amd64")
        contracts.verify_restore_plan(plan, self.manifest, self.backup, rs.target_facts(), now=rs.NOW)

    def test_source_machine_via_other_alias_is_refused(self):
        self.assertCode("E_HOST_IDENTITY_MISMATCH", rs.restore_plan, self.manifest, self.backup,
                        target=rs.same_machine_target_facts())
        self.assertCode("E_HOST_IDENTITY_MISMATCH", rs.restore_plan, self.manifest, self.backup,
                        target=rs.target_facts(host_key_fingerprint=support.HOST_KEY))

    def test_unsupported_platform_and_missing_facts(self):
        self.assertCode("E_UNSUPPORTED", rs.target_facts, os_version="22.04")
        self.assertCode("E_UNSUPPORTED", rs.target_facts, arch="aarch64")
        self.assertCode("E_UNSUPPORTED", rs.target_facts, os_id="centos")
        self.assertCode("E_UNSUPPORTED", rs.target_facts, os_id="debian", os_version="12")
        self.assertCode("E_HOST_KEY_UNKNOWN", rs.target_facts, host_key_fingerprint=None)
        self.assertCode("E_PROBE_INCOMPLETE", rs.target_facts, machine_id=None)

    def test_installer_not_confirmed_yet(self):
        for item in contracts.SUPPORTED_PLATFORMS:
            self.assertCode("E_PRECONDITION", contracts.require_install_confirmed, item["platform_id"])

    def test_conflicts_and_space_block_plan(self):
        self.assertCode("E_CONFLICT", rs.restore_plan, self.manifest, self.backup,
                        conflicts=[{"resource": "volume:llmproxy_chatgpt_auth"}])
        self.assertCode("E_PRECONDITION", rs.restore_plan, self.manifest, self.backup,
                        space={"required_bytes": 10, "free_bytes": 1})

    def test_expired_and_changed_target(self):
        later = rs.NOW + datetime.timedelta(seconds=contracts.DEFAULT_PLAN_TTL_SECONDS) + MINUTE
        self.assertCode("E_PLAN_EXPIRED", contracts.verify_restore_plan, self.plan,
                        self.manifest, self.backup, rs.target_facts(), now=later)
        self.assertCode("E_HOST_IDENTITY_MISMATCH", contracts.verify_restore_plan, self.plan,
                        self.manifest, self.backup, rs.target_facts(machine_id="d" * 32), now=rs.NOW)
        self.assertCode("E_HOST_IDENTITY_MISMATCH", contracts.verify_restore_plan, self.plan,
                        self.manifest, self.backup,
                        rs.target_facts(host_key_fingerprint="SHA256:OtherTargetKeyValue"), now=rs.NOW)
        self.assertCode("E_HOST_IDENTITY_MISMATCH", contracts.verify_restore_plan, self.plan,
                        self.manifest, self.backup,
                        rs.target_facts(resolved={"hostname": "198.51.100.9", "port": 22, "user": "root"}),
                        now=rs.NOW)
        self.assertCode("E_PLAN_STALE", contracts.verify_restore_plan, self.plan,
                        self.manifest, self.backup, rs.target_facts(ssh_alias="renamed"), now=rs.NOW)
        self.assertCode("E_PLAN_STALE", contracts.verify_restore_plan, self.plan,
                        self.manifest, dict(self.backup, backup_id="other"), rs.target_facts(), now=rs.NOW)

    def test_tampered_plan_is_rejected(self):
        tampered = rs.mutated(self.plan, "activation_boundary.max_evidence_age_seconds", 900)
        self.assertCode("E_PLAN_STALE", contracts.validate_restore_plan, tampered)
        tampered = rs.mutated(self.plan, "activation_boundary.automatic_source_actions", ["stop_source"])
        self.assertCode("E_PLAN_INVALID", contracts.validate_restore_plan, tampered)
        tampered = rs.mutated(self.plan, "conflicts", [{"resource": "x"}])
        self.assertCode("E_PLAN_INVALID", contracts.validate_restore_plan, tampered)
        tampered = dict(self.plan, extra_field=True)
        self.assertCode("E_PLAN_INVALID", contracts.validate_restore_plan, tampered)
        # A consistently re-hashed plan whose job ID was swapped is still refused.
        tampered = dict(self.plan, job_id="rst-" + "0" * 24)
        tampered["identity"] = contracts.restore_plan_identity(tampered)
        self.assertCode("E_PLAN_INVALID", contracts.validate_restore_plan, tampered)

    def test_schema_errors_do_not_echo_values(self):
        tampered = rs.mutated(self.plan, "target.machine_id", support.SECRET_CANARY)
        error = self.assertCode("E_PLAN_INVALID", contracts.validate_restore_plan, tampered)
        self.assertNotIn(support.SECRET_CANARY, json.dumps(error.to_error_object()))


class JobAndRetryTest(RestoreContractTestCase):
    def test_job_id_is_stable_across_stage_plans(self):
        later = rs.restore_plan(self.manifest, self.backup, now=rs.NOW + datetime.timedelta(hours=2))
        self.assertEqual(later["job_id"], self.plan["job_id"])
        self.assertNotEqual(later["identity"], self.plan["identity"])
        self.assertEqual(contracts.request_matches_plan(self.request, later), "resume")

    def test_other_target_is_other_job(self):
        other = rs.restore_plan(self.manifest, self.backup, target=rs.target_facts(machine_id="e" * 32))
        self.assertNotEqual(other["job_id"], self.plan["job_id"])
        self.assertCode("E_REQUEST_ID_CONFLICT", contracts.request_matches_plan, self.request, other)

    def test_changed_bindings_conflict(self):
        record_source = contracts.resolve_source_identity(
            self.backup, self.manifest, rs.source_record(self.backup, ssh_alias="vps-3xui-renamed"))
        other = rs.restore_plan(self.manifest, self.backup, source=record_source)
        self.assertEqual(other["job_id"], self.plan["job_id"])
        self.assertCode("E_REQUEST_ID_CONFLICT", contracts.request_matches_plan, self.request, other)

    def test_other_tool_version_does_not_resume(self):
        request = dict(self.request, tool_version="0.0.1-old")
        self.assertCode("E_PLAN_STALE", contracts.request_matches_plan, request, self.plan)

    def test_stage_boundaries(self):
        contracts.check_stage_entry("planned", "prepare")
        contracts.check_stage_entry("preparing", "prepare")
        self.assertCode("E_PRECONDITION", contracts.check_stage_entry, "planned", "activate")
        self.assertCode("E_PRECONDITION", contracts.check_stage_entry, "staged", "certbot_activate")
        for state in contracts.TERMINAL_BLOCKING_STATES:
            self.assertCode("E_JOB_INCOMPLETE", contracts.check_stage_entry, state, "prepare")
        self.assertCode("E_CONTRACT", contracts.check_stage_entry, "planned", "deploy")


class JournalTest(RestoreContractTestCase):
    def test_applied_steps_and_ownership(self):
        job = self.plan["job_id"]
        entries = list(rs.applied_step(job, 1, "prepare:docker"))
        entries += list(rs.applied_step(job, 3, "prepare:dir", kind="directory",
                                        resource="/opt/llmproxy", ownership="preexisting_accepted"))
        steps = contracts.replay_journal(entries, job)
        self.assertEqual(steps["prepare:docker"]["outcome"], "applied")
        owned = contracts.owned_resources(steps)
        self.assertEqual([item["resource"] for item in owned], ["docker-ce"])

    def test_intent_without_outcome_is_unknown_and_owned(self):
        job = self.plan["job_id"]
        intent, _ = rs.applied_step(job, 1, "stage:volume", stage="stage", kind="volume",
                                    resource="llmproxy_chatgpt_auth")
        steps = contracts.replay_journal([intent], job)
        self.assertEqual(steps["stage:volume"]["outcome"], "unknown")
        self.assertEqual(contracts.owned_resources(steps)[0]["outcome"], "unknown")

    def test_applied_needs_observation(self):
        intent, _ = rs.applied_step(self.plan["job_id"], 1, "prepare:docker")
        self.assertCode("E_CONTRACT", contracts.journal_outcome, intent, 2, "applied", None)

    def test_contradictory_journals(self):
        job = self.plan["job_id"]
        intent, outcome = rs.applied_step(job, 1, "prepare:docker")
        self.assertCode("E_NOT_OWNED", contracts.replay_journal, [intent, outcome], "rst-other")
        self.assertCode("E_RECOVERY_REQUIRED", contracts.replay_journal, [outcome], job)
        self.assertCode("E_RECOVERY_REQUIRED", contracts.replay_journal, [intent, outcome, outcome], job)
        gap = dict(outcome, seq=5)
        self.assertCode("E_RECOVERY_REQUIRED", contracts.replay_journal, [intent, gap], job)
        swapped = dict(outcome, resource="other-package")
        self.assertCode("E_RECOVERY_REQUIRED", contracts.replay_journal, [intent, swapped], job)
        second = dict(intent, seq=2)
        self.assertCode("E_RECOVERY_REQUIRED", contracts.replay_journal, [intent, second], job)

    def test_failed_step_may_be_retried(self):
        job = self.plan["job_id"]
        intent, _ = rs.applied_step(job, 1, "prepare:docker")
        failed = contracts.journal_outcome(intent, 2, "failed", {"state": "absent"},
                                           error={"code": "E_EXECUTION"}, now=rs.NOW)
        retry, done = rs.applied_step(job, 3, "prepare:docker")
        steps = contracts.replay_journal([intent, failed, retry, done], job)
        self.assertEqual(steps["prepare:docker"]["outcome"], "applied")


class ReceiptTest(RestoreContractTestCase):
    def prepared(self, steps=None):
        job = self.plan["job_id"]
        steps = steps or contracts.replay_journal(list(rs.applied_step(job, 1, "prepare:docker")), job)
        return contracts.build_receipt("prepared_target", self.plan, steps, ["prepare:docker"],
                                       {"docker_version": "27.3.1", "certbot_timer": "inactive"}, now=rs.NOW)

    def test_receipt_accepted_by_consumer(self):
        receipt = self.prepared()
        contracts.check_stage_inputs("stage", {"prepared_target": receipt}, self.request)

    def test_receipt_needs_applied_steps(self):
        job = self.plan["job_id"]
        intent, _ = rs.applied_step(job, 1, "prepare:docker")
        steps = contracts.replay_journal([intent], job)
        self.assertCode("E_VERIFY_FAILED", self.prepared, steps)
        self.assertCode("E_CONTRACT", contracts.build_receipt, "prepared_target", self.plan,
                        {}, [], {}, now=rs.NOW)

    def test_missing_foreign_or_tampered_receipt(self):
        self.assertCode("E_VERIFY_FAILED", contracts.check_stage_inputs, "stage", {}, self.request)
        receipt = self.prepared()
        tampered = rs.mutated(receipt, "observed.certbot_timer", "active")
        self.assertCode("E_VERIFY_FAILED", contracts.validate_receipt, tampered, self.request,
                        "prepared_target")
        foreign = rs.mutated(receipt, "target.machine_id", "f" * 32)
        foreign["receipt_digest"] = contracts.record_digest(foreign, exclude=("receipt_digest",))
        self.assertCode("E_NOT_OWNED", contracts.validate_receipt, foreign, self.request, "prepared_target")
        self.assertCode("E_VERIFY_FAILED", contracts.validate_receipt, receipt, self.request, "activation")


class CutoverTest(RestoreContractTestCase):
    def evaluate(self, observation="default", attestation="default", now=None):
        if observation == "default":
            observation = rs.source_observation(self.plan)
        if attestation == "default":
            attestation = rs.cutover_attestation(self.plan)
        return contracts.evaluate_cutover(observation, attestation, self.request, self.plan,
                                          now=now or rs.NOW + MINUTE)

    def test_fresh_fenced_source_with_attestation(self):
        result = self.evaluate()
        self.assertEqual(result["fencing_method"], "docker_units_masked")
        observation = rs.source_observation(self.plan, fencing="containers_restart_disabled")
        observation["docker"]["service"] = {"load_state": "loaded", "active_state": "active"}
        self.evaluate(observation=observation)

    def test_unreachable_source_is_not_evidence(self):
        self.assertCode("E_PRECONDITION", self.evaluate, observation=None)

    def test_operator_decision_is_separate(self):
        self.assertCode("E_PRECONDITION", self.evaluate, attestation=None)
        self.assertCode("E_PRECONDITION", self.evaluate,
                        attestation=rs.cutover_attestation(self.plan, permitted=False))
        self.assertCode("E_PRECONDITION", self.evaluate,
                        attestation=rs.cutover_attestation(self.plan, channel=False))
        other = rs.mutated(rs.cutover_attestation(self.plan), "plan_identity", "0" * 64)
        self.assertCode("E_PRECONDITION", self.evaluate, attestation=other)

    def test_stale_or_future_evidence(self):
        late = rs.NOW + datetime.timedelta(seconds=contracts.DEFAULT_CUTOVER_MAX_AGE_SECONDS) + MINUTE
        self.assertCode("E_PRECONDITION", self.evaluate, now=late)
        future = rs.source_observation(self.plan, observed_at=rs.NOW + datetime.timedelta(minutes=10))
        self.assertCode("E_PRECONDITION", self.evaluate, observation=future)

    def test_source_not_stopped_or_not_fenced(self):
        observation = rs.source_observation(self.plan)
        observation["containers"][0]["running"] = True
        self.assertCode("E_PRECONDITION", self.evaluate, observation=observation)
        observation = rs.source_observation(self.plan)
        observation["containers"][0]["running"] = None
        self.assertCode("E_PRECONDITION", self.evaluate, observation=observation)
        observation = rs.source_observation(self.plan)
        observation["containers"].pop()
        self.assertCode("E_PRECONDITION", self.evaluate, observation=observation)
        observation = rs.source_observation(self.plan)
        observation["docker"]["socket"] = {"load_state": "loaded", "active_state": "inactive"}
        self.assertCode("E_PRECONDITION", self.evaluate, observation=observation)
        observation = rs.source_observation(self.plan, fencing="containers_restart_disabled")
        observation["containers"][0]["restart_policy"] = "unless-stopped"
        self.assertCode("E_PRECONDITION", self.evaluate, observation=observation)

    def test_observation_from_wrong_machine_or_incomplete(self):
        target_source = {"ssh_alias": "vps-3xui", "host_key_fingerprint": rs.TARGET_HOST_KEY,
                         "machine_id": rs.TARGET_MACHINE_ID}
        self.assertCode("E_HOST_IDENTITY_MISMATCH", self.evaluate,
                        observation=rs.source_observation(self.plan, source=target_source))
        self.assertCode("E_PROBE_INCOMPLETE", self.evaluate,
                        observation=rs.source_observation(self.plan, probe_complete=False))
        self.assertCode("E_PRECONDITION", self.evaluate,
                        observation=rs.source_observation(self.plan, channel="unauthenticated"))


class DiagnosticsTest(unittest.TestCase):
    def test_overall_and_manual_separation(self):
        machine = {name: "passed" for name, spec in contracts.DIAGNOSTIC_CHECKS.items()
                   if spec["source"] == "machine"}
        report = contracts.build_verification_report("rst-x", machine)
        self.assertEqual(report["overall"], "passed")
        self.assertEqual(set(report["manual_checks"].values()), {"not_run"})
        partial = dict(machine)
        del partial["response_from_target"]
        self.assertEqual(contracts.build_verification_report("rst-x", partial)["overall"], "unknown")
        failed = dict(machine, response_from_target="failed")
        self.assertEqual(contracts.build_verification_report("rst-x", failed)["overall"], "failed")

    def test_manual_pass_and_unknown_checks_are_refused(self):
        with self.assertRaises(ToolError):
            contracts.build_verification_report("rst-x", {"model_generation": "passed"})
        with self.assertRaises(ToolError):
            contracts.build_verification_report("rst-x", {"health_endpoint": "passed"})
        with self.assertRaises(ToolError):
            contracts.build_verification_report("rst-x", {"target_identity": "ok"})


if __name__ == "__main__":
    unittest.main()
