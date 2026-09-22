import contextlib
import io
import copy
import json
import os
import shutil
import tempfile
import unittest

import support
from vps3xui import cli
from vps3xui import manifest as manifest_module
from vps3xui.jobs import JobStore


class Harness(object):
    def __init__(self, tmp, manifest, probe=None, host_faults=None):
        self.tmp = tmp
        self.manifest = manifest
        self.probe = probe
        self.host_faults = host_faults or {}
        self.hosts = {}
        self.state_dir = os.path.join(tmp, "state")

    def factory(self, alias):
        if alias not in self.hosts:
            root = os.path.join(self.tmp, "host-%d" % len(self.hosts))
            self.hosts[alias] = support.SyntheticHost(
                self.manifest, root=root, probe=self.probe, faults=self.host_faults
            )
        return self.hosts[alias]

    @property
    def host(self):
        return self.factory(self.manifest.ssh_alias)

    def run(self, argv):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            code = cli.main(argv, host_factory=self.factory)
        text = buffer.getvalue()
        payload = None
        try:
            payload = json.loads(text.strip().splitlines()[-1])
        except (ValueError, IndexError):
            payload = None
        return code, payload, text

    def plan_path(self, name="plan.json"):
        return os.path.join(self.tmp, name)

    def base_argv(self, command):
        return command + ["--host", self.manifest.ssh_alias, "--manifest", self.manifest.path]


def make_harness(host_faults=None, probe=None, approved=True):
    tmp = tempfile.mkdtemp(prefix="cli-")
    manifest = support.approved_manifest(tmp)
    if not approved:
        # A plan must still be buildable; only the apply gate is unapproved.
        data = copy.deepcopy(manifest.data)
        data["approved"] = False
        path = os.path.join(tmp, "unapproved.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        manifest = manifest_module.load(path)
    return Harness(tmp, manifest, probe=probe, host_faults=host_faults)


class CliFlowTest(unittest.TestCase):
    def test_plan_output_preserves_an_existing_output_parent_mode(self):
        harness = make_harness()
        parent = os.path.join(harness.tmp, "cwd")
        os.makedirs(parent)
        os.chmod(parent, 0o755)
        plan_path = os.path.join(parent, "plan.json")
        code, payload, _ = harness.run(
            harness.base_argv(["backup", "plan"]) + ["--out", plan_path, "--json"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(payload["state"], "planned")
        self.assertEqual(oct(os.stat(parent).st_mode & 0o777), "0o755")
        self.assertEqual(oct(os.stat(plan_path).st_mode & 0o777), "0o600")

    def test_happy_path_plan_start_status_verify_fetch(self):
        harness = make_harness()
        plan_path = harness.plan_path()
        code, payload, _ = harness.run(
            harness.base_argv(["backup", "plan"]) + ["--out", plan_path, "--json"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(payload["state"], "planned")
        self.assertEqual(payload["stop_containers"], ["litellm", "caddy", "3xui_app"])

        request_id = "req-flow-0001"
        code, payload, _ = harness.run(
            harness.base_argv(["backup", "start"])
            + ["--plan", plan_path, "--request-id", request_id,
               "--state-dir", harness.state_dir, "--apply", "--json"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(payload["state"], "accepted")

        code, payload, _ = harness.run(
            ["job", "status", request_id, "--host", harness.manifest.ssh_alias,
             "--state-dir", harness.state_dir, "--json"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(payload["state"], "succeeded")
        self.assertEqual(payload["report"]["restore_drill"], "not_run")

        code, payload, _ = harness.run(
            harness.base_argv(["backup", "verify"])
            + ["--job", request_id, "--state-dir", harness.state_dir, "--json"]
        )
        self.assertEqual(code, 0)
        self.assertTrue(payload["verification"]["ok"])

        destination = os.path.join(harness.tmp, "fetched")
        code, payload, _ = harness.run(
            harness.base_argv(["backup", "fetch"])
            + ["--job", request_id, "--destination", destination,
               "--state-dir", harness.state_dir, "--apply", "--json"]
        )
        self.assertEqual(code, 0)
        self.assertEqual(payload["state"], "verified")

        code, payload, _ = harness.run(
            ["backup", "verify", "--manifest", harness.manifest.path,
             "--directory", destination, "--json"]
        )
        self.assertEqual(code, 0)
        self.assertTrue(payload["verification"]["ok"])

    def test_retry_same_request_id_does_not_start_second_backup(self):
        harness = make_harness()
        plan_path = harness.plan_path()
        harness.run(harness.base_argv(["backup", "plan"]) + ["--out", plan_path, "--json"])
        request_id = "req-retry-0001"
        argv = harness.base_argv(["backup", "start"]) + [
            "--plan", plan_path, "--request-id", request_id,
            "--state-dir", harness.state_dir, "--apply", "--json",
        ]
        harness.run(argv)
        code, payload, _ = harness.run(argv)
        self.assertEqual(code, 0)
        self.assertTrue(payload.get("resolved_existing"))
        self.assertEqual(len(harness.host.launches), 1)

    def test_same_request_id_different_manifest_conflicts(self):
        harness = make_harness()
        plan_path = harness.plan_path()
        harness.run(harness.base_argv(["backup", "plan"]) + ["--out", plan_path, "--json"])
        request_id = "req-conflict-0001"
        harness.run(harness.base_argv(["backup", "start"]) + [
            "--plan", plan_path, "--request-id", request_id,
            "--state-dir", harness.state_dir, "--apply", "--json",
        ])
        other = support.approved_manifest(harness.tmp, approval_note="changed plan")
        other_plan = harness.plan_path("plan2.json")
        code, _, _ = harness.run([
            "backup", "plan", "--host", other.ssh_alias, "--manifest", other.path,
            "--out", other_plan, "--json",
        ])
        self.assertEqual(code, 0)
        code, payload, _ = harness.run([
            "backup", "start", "--host", harness.manifest.ssh_alias,
            "--manifest", harness.manifest.path, "--plan", other_plan,
            "--request-id", request_id, "--state-dir", harness.state_dir,
            "--apply", "--json",
        ])
        self.assertEqual(code, 3)
        self.assertEqual(payload["error"]["code"], "E_REQUEST_ID_CONFLICT")

    def test_incomplete_job_blocks_new_work(self):
        harness = make_harness()
        plan_path = harness.plan_path()
        harness.run(harness.base_argv(["backup", "plan"]) + ["--out", plan_path, "--json"])
        store = JobStore(harness.state_dir)
        store.register_request("req-old-0001", "digest", harness.manifest.manifest_id,
                               harness.manifest.ssh_alias)
        store.update_request("req-old-0001", state="copying")
        code, payload, _ = harness.run(harness.base_argv(["backup", "start"]) + [
            "--plan", plan_path, "--request-id", "req-new-0001",
            "--state-dir", harness.state_dir, "--apply", "--json",
        ])
        self.assertEqual(code, 3)
        self.assertEqual(payload["error"]["code"], "E_JOB_INCOMPLETE")

    def test_start_without_apply_is_contract_error(self):
        harness = make_harness()
        plan_path = harness.plan_path()
        harness.run(harness.base_argv(["backup", "plan"]) + ["--out", plan_path, "--json"])
        code, payload, _ = harness.run(harness.base_argv(["backup", "start"]) + [
            "--plan", plan_path, "--request-id", "req-noapply", "--json",
        ])
        self.assertEqual(code, 2)
        self.assertEqual(payload["error"]["code"], "E_CONTRACT")

    def test_unapproved_manifest_blocks_start(self):
        harness = make_harness(approved=False)
        plan_path = harness.plan_path()
        code, payload, _ = harness.run(harness.base_argv(["backup", "plan"]) + ["--out", plan_path, "--json"])
        self.assertEqual(code, 0)
        self.assertFalse(payload["approved"])
        code, payload, _ = harness.run(harness.base_argv(["backup", "start"]) + [
            "--plan", plan_path, "--request-id", "req-unapproved",
            "--state-dir", harness.state_dir, "--apply", "--json",
        ])
        self.assertEqual(code, 2)
        self.assertEqual(payload["error"]["code"], "E_MANIFEST_NOT_APPROVED")

    def test_pending_approval_running_blocks_plan(self):
        probe = support.synthetic_probe()
        probe["containers"].append({
            "id": "id-relay", "name": "agent-relay", "image": "relay:local", "image_id": "sha256:r",
            "repo_digests": [], "running": True, "status": "running",
            "restart_policy": "unless-stopped", "network_mode": "llmproxy_backend",
            "compose_project": "llmproxy", "compose_service": "agent-relay", "mounts": [],
        })
        tmp = tempfile.mkdtemp(prefix="cli-pending-")
        manifest = manifest_module.load(manifest_module.EXAMPLE_MANIFEST_PATH)
        harness = Harness(tmp, manifest, probe=probe)
        code, payload, _ = harness.run(
            harness.base_argv(["backup", "plan"]) + ["--out", harness.plan_path(), "--json"]
        )
        self.assertEqual(code, 3)
        self.assertEqual(payload["error"]["code"], "E_MANIFEST_PENDING_APPROVAL")

    def test_argument_error_is_one_json_object(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            code = cli.main(["backup", "plan", "--json", "--host", "x"])
        self.assertEqual(code, 2)
        lines = [line for line in buffer.getvalue().strip().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1, lines)
        payload = json.loads(lines[0])
        self.assertEqual(payload["error"]["code"], "E_CONTRACT")

    def test_os_error_is_one_safe_json_object_with_command_name(self):
        harness = make_harness()
        buffer = io.StringIO()

        def broken_factory(_alias):
            raise OSError("boom with secret CANARY-do-not-reflect")

        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            code = cli.main(
                ["inspect", "--host", harness.manifest.ssh_alias,
                 "--manifest", harness.manifest.path, "--json"],
                host_factory=broken_factory,
            )
        self.assertEqual(code, 4)
        lines = [line for line in buffer.getvalue().strip().splitlines() if line.strip()]
        self.assertEqual(len(lines), 1, lines)
        payload = json.loads(lines[0])
        self.assertEqual(payload["error"]["code"], "E_EXECUTION")
        self.assertNotIn("CANARY-do-not-reflect", buffer.getvalue())

    def test_unsafe_job_id_is_rejected_before_path_construction(self):
        harness = make_harness()
        code, payload, _ = harness.run(
            ["job", "status", "../../etc/passwd", "--host", harness.manifest.ssh_alias, "--json"]
        )
        self.assertEqual(code, 2)
        self.assertEqual(payload["error"]["code"], "E_UNSAFE_ID")
        code, payload, _ = harness.run([
            "backup", "fetch", "--host", harness.manifest.ssh_alias,
            "--manifest", harness.manifest.path, "--job", "../evil",
            "--destination", harness.tmp, "--json", "--apply",
        ])
        self.assertEqual(code, 2)
        self.assertEqual(payload["error"]["code"], "E_UNSAFE_ID")

    def test_secret_canaries_absent_from_all_cli_output(self):
        harness = make_harness()
        plan_path = harness.plan_path()
        outputs = []
        for argv in [
            harness.base_argv(["inspect"]) + ["--json"],
            harness.base_argv(["backup", "plan"]) + ["--out", plan_path, "--json"],
        ]:
            _, _, text = harness.run(argv)
            outputs.append(text)
        request_id = "req-canary-0001"
        argv = harness.base_argv(["backup", "start"]) + [
            "--plan", plan_path, "--request-id", request_id,
            "--state-dir", harness.state_dir, "--apply", "--json",
        ]
        for follow in [
            argv,
            ["job", "status", request_id, "--host", harness.manifest.ssh_alias,
             "--state-dir", harness.state_dir, "--json"],
            harness.base_argv(["backup", "verify"]) + ["--job", request_id,
                                                       "--state-dir", harness.state_dir, "--json"],
            harness.base_argv(["backup", "fetch"]) + [
                "--job", request_id, "--destination", os.path.join(harness.tmp, "out"),
                "--state-dir", harness.state_dir, "--apply", "--json"],
        ]:
            _, _, text = harness.run(follow)
            outputs.append(text)
        blob = "\n".join(outputs)
        for canary in (support.SECRET_CANARY, support.ENV_CANARY, support.DB_CANARY):
            self.assertNotIn(canary, blob)

    def test_fetch_refuses_non_empty_destination(self):
        harness = make_harness()
        plan_path = harness.plan_path()
        harness.run(harness.base_argv(["backup", "plan"]) + ["--out", plan_path, "--json"])
        request_id = "req-fetch-0001"
        harness.run(harness.base_argv(["backup", "start"]) + [
            "--plan", plan_path, "--request-id", request_id,
            "--state-dir", harness.state_dir, "--apply", "--json",
        ])
        destination = os.path.join(harness.tmp, "busy")
        os.makedirs(destination)
        with open(os.path.join(destination, "keep"), "w") as handle:
            handle.write("x")
        code, payload, _ = harness.run(harness.base_argv(["backup", "fetch"]) + [
            "--job", request_id, "--destination", destination,
            "--state-dir", harness.state_dir, "--apply", "--json",
        ])
        self.assertEqual(code, 3)
        self.assertEqual(payload["error"]["code"], "E_PRECONDITION")

    def test_fetch_refuses_symlink_destinations_before_writing(self):
        harness = make_harness()
        self.addCleanup(shutil.rmtree, harness.tmp)
        plan_path = harness.plan_path()
        code, _, _ = harness.run(harness.base_argv(["backup", "plan"]) + [
            "--out", plan_path, "--json",
        ])
        self.assertEqual(code, 0)
        request_id = "req-fetch-symlink"
        code, _, _ = harness.run(harness.base_argv(["backup", "start"]) + [
            "--plan", plan_path, "--request-id", request_id,
            "--state-dir", harness.state_dir, "--apply", "--json",
        ])
        self.assertEqual(code, 0)
        for kind in ("existing", "dangling", "trailing-slash", "ancestor"):
            with self.subTest(kind=kind):
                target = os.path.join(harness.tmp, "target-" + kind)
                link = os.path.join(harness.tmp, "link-" + kind)
                if kind != "dangling":
                    os.mkdir(target, 0o755)
                    os.chmod(target, 0o755)
                os.symlink(target, link)
                destination = link
                if kind == "trailing-slash":
                    destination += "/"
                elif kind == "ancestor":
                    destination = os.path.join(link, "copy")
                code, payload, _ = harness.run(harness.base_argv(["backup", "fetch"]) + [
                    "--job", request_id, "--destination", destination,
                    "--state-dir", harness.state_dir, "--apply", "--json",
                ])
                self.assertNotEqual(code, 0)
                self.assertEqual(payload["error"]["code"], "E_UNSAFE_PATH")
                self.assertTrue(os.path.islink(link))
                if kind == "dangling":
                    self.assertFalse(os.path.lexists(target))
                else:
                    self.assertEqual(os.listdir(target), [])
                    self.assertEqual(os.stat(target).st_mode & 0o777, 0o755)
                self.assertFalse(os.path.lexists(target + ".partial"))

    def test_status_unknown_for_missing_job(self):
        harness = make_harness()
        code, payload, _ = harness.run([
            "job", "status", "req-missing-0001", "--host", harness.manifest.ssh_alias,
            "--state-dir", harness.state_dir, "--json",
        ])
        self.assertEqual(code, 0)
        self.assertEqual(payload["state"], "unknown")
        self.assertEqual(payload["evidence"], "missing_state_and_report")

    def test_verify_before_success_is_refused(self):
        harness = make_harness()
        code, payload, _ = harness.run(
            harness.base_argv(["backup", "verify"])
            + ["--job", "req-none", "--state-dir", harness.state_dir, "--json"]
        )
        self.assertEqual(code, 5)
        self.assertEqual(payload["error"]["code"], "E_VERIFY_FAILED")

    def test_recovery_required_then_recover_completes_recovery(self):
        harness = make_harness(host_faults={"start_fail": True})
        plan_path = harness.plan_path()
        harness.run(harness.base_argv(["backup", "plan"]) + ["--out", plan_path, "--json"])
        request_id = "req-recover-0001"
        harness.run(harness.base_argv(["backup", "start"]) + [
            "--plan", plan_path, "--request-id", request_id,
            "--state-dir", harness.state_dir, "--apply", "--json",
        ])
        _, status, _ = harness.run([
            "job", "status", request_id, "--host", harness.manifest.ssh_alias,
            "--state-dir", harness.state_dir, "--json",
        ])
        self.assertEqual(status["state"], "recovery_required")
        code, payload, _ = harness.run([
            "job", "recover", "--host", harness.manifest.ssh_alias, "--job", request_id,
            "--state-dir", harness.state_dir, "--apply", "--wait-seconds", "0", "--json",
        ])
        self.assertEqual(code, 0)
        self.assertEqual(payload["state"], "failed")
        self.assertTrue(harness.host.systems[request_id].containers["litellm"]["running"])
        # A failed job is terminal and no longer blocks new work.
        store = JobStore(harness.state_dir)
        records = {r["request_id"]: r for r in store.list_requests()}
        self.assertEqual(records[request_id]["state"], "failed")
        self.assertEqual(store.blocking_requests(), [])


if __name__ == "__main__":
    unittest.main()
