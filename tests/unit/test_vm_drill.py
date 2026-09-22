"""Local behavior tests for the R9 VM drill harness.

These tests use fake commands and a fake driver. They verify the assembled argv
and scenario choreography, but they are not Linux/Docker/systemd evidence: the
real VM drill remains NOT RUN until an approved disposable host executes it.
"""

import hashlib
import importlib.util
import io
import json
import os
import tarfile
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VmDrillPath = os.path.join(REPO_ROOT, "scripts", "vm_drill.py")

_spec = importlib.util.spec_from_file_location("vm_drill_under_test", VmDrillPath)
vm_drill = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vm_drill)


def _write_executable(path, body):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
    os.chmod(path, 0o755)


class LaunchArgvTest(unittest.TestCase):
    def test_shipped_entrypoint_argv_is_executable_and_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            release = os.path.join(tmp, "release")
            record = os.path.join(tmp, "argv.json")
            body = ("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %s\n" % record)
            _write_executable(os.path.join(release, "bin", "vps3xui-finalizer"), body)
            _write_executable(os.path.join(release, "bin", "vps3xui-worker"), body)
            job = os.path.join(tmp, "job dir")
            finalizer = vm_drill.finalizer_argv(release, job)
            worker = vm_drill.worker_argv(release, job)
            for argv in (finalizer, worker):
                self.assertTrue(os.access(argv[0], os.X_OK))
                subprocess.run(argv, check=True)
                with open(record, "r", encoding="utf-8") as handle:
                    observed = handle.read().splitlines()
                self.assertEqual(observed, argv[1:])
            self.assertEqual(finalizer[0].rsplit("/", 1)[-1], "vps3xui-finalizer")
            self.assertEqual(worker[0].rsplit("/", 1)[-1], "vps3xui-worker")

    def test_exec_stop_post_is_systemd_escaped_and_round_trips(self):
        release = "/release with spaces/and$dollar%percent"
        job = "/job dir/with'quote"
        finalizer = vm_drill.finalizer_argv(release, job)
        escaped = vm_drill.systemd_escape_argv(finalizer)
        self.assertNotEqual(escaped, " ".join(finalizer))
        self.assertEqual(vm_drill.systemd_split_argv(escaped), finalizer)
        argv = vm_drill.systemd_run_argv("drill-unit", ["/bin/true"], finalizer,
                                         "token", 30, 90)
        property_value = next(item for item in argv
                              if item.startswith("--property=ExecStopPost="))
        parsed = vm_drill.systemd_split_argv(property_value.split("=", 2)[2])
        self.assertEqual(parsed, finalizer)
        self.assertIn("--property=RuntimeMaxSec=30", argv)
        self.assertEqual(argv[-1], "/bin/true")
        self.assertNotIn("--property=ExecStopPost=%s" % " ".join(finalizer), argv)

    def test_repo_ships_executable_worker_and_finalizer_entrypoints(self):
        for name in ("vps3xui-worker", "vps3xui-finalizer"):
            script = os.path.join(REPO_ROOT, "bin", name)
            self.assertTrue(os.path.isfile(script), script)
            self.assertTrue(os.access(script, os.X_OK),
                            "entrypoint not executable: " + script)
            result = subprocess.run([script, "--help"], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertIn(b"job_dir", result.stdout)

    def test_worker_and_finalizer_argv_point_at_the_shipped_scripts(self):
        job = "/var/lib/vps3xui/jobs/drill"
        self.assertEqual(vm_drill.worker_argv(REPO_ROOT, job),
                         [os.path.join(REPO_ROOT, "bin", "vps3xui-worker"),
                          "--release-dir", REPO_ROOT, job])
        self.assertEqual(vm_drill.finalizer_argv(REPO_ROOT, job),
                         [os.path.join(REPO_ROOT, "bin", "vps3xui-finalizer"),
                          "--release-dir", REPO_ROOT, job])

    def test_exec_stop_post_finalizer_never_carries_recover(self):
        finalizer = vm_drill.finalizer_argv("/release", "/job")
        self.assertNotIn("--recover", finalizer)
        self.assertIn("--recover", vm_drill.finalizer_argv("/release", "/job", recover=True))

    def test_systemd_exec_token_is_the_executable_path_not_one_string(self):
        with tempfile.TemporaryDirectory() as tmp:
            release = os.path.join(tmp, "release with spaces")
            job = os.path.join(tmp, "job dir")
            for name in ("vps3xui-worker", "vps3xui-finalizer"):
                _write_executable(os.path.join(release, "bin", name),
                                  "#!/bin/sh\nexit 0\n")
            worker = vm_drill.worker_argv(release, job)
            argv = vm_drill.systemd_run_argv("u", worker,
                                             vm_drill.finalizer_argv(release, job),
                                             "token", 30, 90)
            tail = argv[argv.index("--property=StandardError=journal") + 1:]
            self.assertEqual(tail, worker)
            self.assertTrue(os.access(tail[0], os.X_OK))
            self.assertEqual(tail[0], os.path.join(release, "bin", "vps3xui-worker"))
            self.assertFalse(any("--release-dir" in item and " " in item for item in tail))

    def test_worker_argv_is_not_one_command_plus_arguments_string(self):
        argv = vm_drill.worker_argv("/release", "/job")
        self.assertEqual(argv[1], "--release-dir")
        self.assertEqual(argv[2], "/release")
        self.assertEqual(argv[3], "/job")
        self.assertFalse(any("--release-dir /release" in item for item in argv))


class FakeSubmitter(object):
    def __init__(self):
        self.signals = []
        self.returncode = None

    def poll(self):
        return self.returncode

    def send_signal(self, sig):
        self.signals.append(sig)

    def wait(self, timeout=None):
        self.returncode = -9
        return self.returncode


class FakeDriver(object):
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.states = {}
        self.complete = {}
        self.unit_active_value = True
        self.submitter = FakeSubmitter()
        self.primary_job = os.path.join(root, "primary")
        self.running = {}
        self.ids = {}
        self.jobs = [("success", self.primary_job)]
        os.makedirs(self.primary_job)

    def unit_name(self, label):
        return "unit-" + label

    def ledger_token(self):
        self.calls.append("ledger-token")
        return "fixture-token"

    def job_state(self, job):
        return self.states.get(job, "unknown")

    def container_running(self, name):
        return self.running.get(name, False)

    def container_id(self, name):
        return self.ids.get(name, "")

    def assert_copying(self, job):
        self.calls.append(("assert-copying", job))
        return {"stop_containers": [{"name": "src-app", "id": "a" * 64}]}

    def reap_submitter(self, submitter):
        self.calls.append("reap-submitter")
        if submitter.poll() is None:
            submitter.returncode = -9

    def write_copy_shim(self):
        self.calls.append("write-copy-shim")

    def new_job(self, label):
        job = os.path.join(self.root, "job-" + label)
        os.makedirs(job, exist_ok=True)
        self.jobs.append((label, job))
        self.calls.append(("new-job", label))
        return job

    def preserve_all_evidence(self):
        self.calls.append("preserve-evidence")

    def new_barrier(self, label):
        barrier = os.path.join(self.root, "barrier-" + label)
        os.makedirs(barrier, exist_ok=True)
        self.calls.append(("new-barrier", label))
        return barrier

    def launch(self, job, unit, runtime, stop, barrier=None):
        self.calls.append(("launch", unit, runtime, stop, barrier))
        self.states[job] = "copying" if barrier else "succeeded"
        self.complete[job] = not barrier
        if not barrier:
            with open(self.complete_path(job), "w", encoding="utf-8") as handle:
                handle.write("complete\n")

    def launch_via_submitter(self, job, unit, runtime, stop, barrier):
        self.calls.append(("submit", unit, runtime, stop, barrier))
        self.states[job] = "copying"
        self.complete[job] = False
        return self.submitter

    def wait_barrier(self, barrier, timeout):
        self.calls.append(("wait-barrier", barrier))

    def kill_unit(self, unit):
        self.calls.append(("kill-unit", unit))
        for job in self.states:
            self.states[job] = "failed"
        self.complete = {job: False for job in self.complete}

    def wait_terminal(self, job, timeout):
        self.calls.append(("wait-terminal", job))
        return self.states.get(job, "failed")

    def wait_finalized(self, job, unit, timeout):
        self.calls.append(("wait-finalized", job, unit))
        return self.states.get(job, "failed")

    def wait_unit_inactive(self, unit, timeout):
        self.calls.append(("wait-unit-inactive", unit))

    def job_report(self, job):
        if "timeout" in job:
            return {"unit_result": {"SERVICE_RESULT": "timeout",
                                    "EXIT_CODE": "killed", "EXIT_STATUS": "15"}}
        return {}

    def complete_path(self, job):
        return os.path.join(job, "COMPLETE")

    def unit_active(self, unit):
        self.calls.append(("unit-active", unit))
        return self.unit_active_value

    def kill_submitter(self, submitter):
        self.calls.append("kill-submitter")
        submitter.send_signal(9)
        submitter.wait()

    def preserve_job_evidence(self, label, job):
        self.calls.append(("preserve-job", label))

    def release_barrier(self, barrier):
        self.calls.append(("release-barrier", barrier))
        for job, state in list(self.states.items()):
            if state == "copying":
                self.states[job] = "succeeded"
                self.complete[job] = True
                with open(self.complete_path(job), "w", encoding="utf-8") as handle:
                    handle.write("complete\n")

    def assert_source_restored(self, job):
        self.calls.append(("assert-source", job))

    def restore_success(self, job):
        self.calls.append(("restore-success", job))
        return {"restored": True}

    def snapshot_firewall(self):
        self.calls.append("snapshot-firewall")
        return {"ufw": "hash"}

    def assert_firewall_unchanged(self, before):
        self.calls.append(("assert-firewall", before))


class ScenarioChoreographyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.driver = FakeDriver(self.tmp.name)

    def test_success_builds_and_restores_actual_backup(self):
        result = vm_drill.scenario_success(self.driver, self.driver.primary_job)
        self.assertEqual(result["state"], "succeeded")
        self.assertIn(("restore-success", self.driver.primary_job), self.driver.calls)
        launch = [call for call in self.driver.calls if call[0] == "launch"][0]
        self.assertIsNone(launch[4], "the success path must not use the copy barrier")

    def test_sigkill_targets_the_worker_unit_during_copying(self):
        job = self.driver.new_job("kill")
        result = vm_drill.scenario_sigkill(self.driver, job)
        self.assertEqual(result["state"], "failed")
        order = [call for call in self.driver.calls
                 if call in (("wait-barrier", os.path.join(self.tmp.name, "barrier-kill")),
                             ("kill-unit", "unit-kill"))]
        self.assertEqual(order, [("wait-barrier", os.path.join(self.tmp.name, "barrier-kill")),
                                 ("kill-unit", "unit-kill")])
        self.assertFalse(os.path.exists(self.driver.complete_path(job)))

    def test_timeout_uses_real_runtime_property_not_fake_env(self):
        job = self.driver.new_job("timeout")
        result = vm_drill.scenario_timeout(self.driver, job)
        self.assertEqual(result["unit_result"]["SERVICE_RESULT"], "timeout")
        launch = [call for call in self.driver.calls if call[0] == "launch"][0]
        self.assertEqual(launch[2], 30)
        self.assertFalse(result["complete"])

    def test_transport_kills_only_the_submitter_and_worker_finishes(self):
        job = self.driver.new_job("transport")
        result = vm_drill.scenario_transport(self.driver, job)
        self.assertEqual(result["state"], "succeeded")
        kill_index = self.driver.calls.index("kill-submitter")
        release_index = self.driver.calls.index(
            ("release-barrier", os.path.join(self.tmp.name, "barrier-transport")))
        self.assertLess(kill_index, release_index)
        self.assertFalse(any(call[0] == "kill-unit" for call in self.driver.calls
                             if isinstance(call, tuple)))
        self.assertTrue(os.path.exists(self.driver.complete_path(job)))

    def test_run_all_orders_success_before_kill_timeout_and_transport(self):
        results = vm_drill.run_all(self.driver)
        self.assertTrue(results["success"]["restored"]["restored"])
        self.assertEqual(results["sigkill"]["state"], "failed")
        self.assertEqual(results["timeout"]["unit_result"]["SERVICE_RESULT"], "timeout")
        self.assertEqual(results["transport"]["state"], "succeeded")
        labels = [call[1] for call in self.driver.calls
                  if isinstance(call, tuple) and call[0] == "new-job"]
        self.assertEqual(labels, ["kill", "timeout", "transport"])


class DriverProcessHelpersTest(unittest.TestCase):
    """Exercise the real Driver process helpers with a fake subprocess.

    These cover the Linux code paths the FakeDriver skips (docker inspect parsing,
    tar-stream parsing, firewall hashing and bounded command failure) without
    touching Docker, systemd or the host firewall.
    """

    def _driver(self):
        driver = object.__new__(vm_drill.Driver)
        driver.log_lines = []
        driver.commands = []
        driver.log = lambda message: None
        return driver

    def test_driver_run_raises_bounded_failure_and_records_command(self):
        driver = self._driver()
        original = vm_drill.subprocess.run
        tail = b"x" * 500
        vm_drill.subprocess.run = lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, 1, b"", b"boom\n" + tail)
        try:
            with self.assertRaises(vm_drill.DrillFailure) as ctx:
                driver.run(["/bin/false"])
        finally:
            vm_drill.subprocess.run = original
        self.assertEqual(driver.commands, [["/bin/false"]])
        message = str(ctx.exception)
        self.assertIn("command failed (1)", message)
        self.assertIn("boom", message)
        # stderr detail is bounded so a huge/secret log never lands in evidence.
        self.assertLessEqual(len(message), len("command failed (1): ") + 300)
        self.assertNotIn("x" * 301, message)

    def test_container_running_reads_docker_inspect(self):
        driver = self._driver()
        original = vm_drill.subprocess.run
        answers = [(0, b"true\n"), (0, b"false\n"), (1, b"")]

        def fake_run(argv, **kwargs):
            code, out = answers.pop(0)
            return subprocess.CompletedProcess(argv, code, out, b"")

        vm_drill.subprocess.run = fake_run
        try:
            self.assertTrue(driver.container_running("drill"))
            self.assertFalse(driver.container_running("drill"))
            self.assertFalse(driver.container_running("drill"))
        finally:
            vm_drill.subprocess.run = original

    def test_read_container_file_parses_docker_cp_tar_stream(self):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w") as archive:
            info = tarfile.TarInfo("jail.local")
            info.mode = 0o640
            data = b"synthetic drill jail; never production\n"
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        stream = payload.getvalue()
        seen = {}
        driver = self._driver()
        original = vm_drill.subprocess.run

        def fake_run(argv, **kwargs):
            seen["argv"] = list(argv)
            return subprocess.CompletedProcess(argv, 0, stream, b"")

        vm_drill.subprocess.run = fake_run
        try:
            data, facts = driver._read_container_file("drill", "/etc/fail2ban/jail.local")
        finally:
            vm_drill.subprocess.run = original
        self.assertEqual(seen["argv"], ["docker", "cp",
                                        "drill:/etc/fail2ban/jail.local", "-"])
        self.assertIn(b"synthetic drill jail", data)
        self.assertEqual(facts["mode"], "0640")
        self.assertEqual(facts["uid"], 0)
        self.assertEqual(facts["gid"], 0)

    def test_read_container_file_fails_bounded_on_docker_error(self):
        driver = self._driver()
        original = vm_drill.subprocess.run
        vm_drill.subprocess.run = lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, 1, b"", b"")
        try:
            with self.assertRaises(vm_drill.DrillFailure):
                driver._read_container_file("drill", "/etc/fail2ban/jail.local")
        finally:
            vm_drill.subprocess.run = original

    def _source_state_driver(self, tmp, idle_id="i" * 64, include_idle_fact=True):
        initial = {"stop_containers": [{"name": "3xui_app", "id": "a" * 64}],
                   "containers": {}, "certbot": {"units": {}}}
        if include_idle_fact:
            initial["containers"]["drill-idle"] = {"name": "drill-idle",
                                                   "id": idle_id, "running": False}
        with open(os.path.join(tmp, "initial-state.json"), "w", encoding="utf-8") as handle:
            json.dump(initial, handle)
        driver = self._driver()
        driver.job_report = lambda job: {"source_runtime_recovery": "verified"}
        driver.names = {"idle_container": "drill-idle"}
        driver.fixture_info = {"idle_container": {"id": idle_id}}
        driver.container_state = lambda name: "running" if name == "3xui_app" else "stopped"
        driver.container_identity = lambda name: {"3xui_app": "a" * 64,
                                                  "drill-idle": idle_id}.get(name, "")
        return driver

    def test_assert_source_restored_requires_running_recorded_containers(self):
        with tempfile.TemporaryDirectory() as tmp:
            driver = self._source_state_driver(tmp)
            driver.assert_source_restored(tmp)
            # A replaced source container id must fail.
            driver.container_identity = lambda name: "b" * 64
            with self.assertRaises(vm_drill.DrillFailure):
                driver.assert_source_restored(tmp)
            # A source container that is not provably running must fail.
            driver.container_identity = lambda name: {"3xui_app": "a" * 64,
                                                      "drill-idle": "i" * 64}.get(name, "")
            driver.container_state = lambda name: "unknown"
            with self.assertRaises(vm_drill.DrillFailure):
                driver.assert_source_restored(tmp)

    def test_assert_source_restored_checks_the_idle_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            # The idle container must be provably stopped, not merely "not running".
            driver = self._source_state_driver(tmp)
            driver.container_state = lambda name: "unknown"
            with self.assertRaises(vm_drill.DrillFailure):
                driver.assert_source_restored(tmp)
            # A replaced idle container id must fail.
            driver = self._source_state_driver(tmp)
            driver.container_identity = lambda name: ("a" * 64 if name == "3xui_app"
                                                      else "z" * 64)
            with self.assertRaises(vm_drill.DrillFailure):
                driver.assert_source_restored(tmp)
            # A missing idle identity is a hard failure, never a skip.
            driver = self._source_state_driver(tmp, include_idle_fact=False)
            driver.fixture_info = {}
            with self.assertRaises(vm_drill.DrillFailure):
                driver.assert_source_restored(tmp)

    def test_assert_source_restored_rejects_unverified_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "initial-state.json"), "w", encoding="utf-8") as handle:
                json.dump({"stop_containers": [], "certbot": {"units": {}}}, handle)
            driver = self._driver()
            driver.job_report = lambda job: {"source_runtime_recovery": "failed"}
            with self.assertRaises(vm_drill.DrillFailure):
                driver.assert_source_restored(tmp)

    def test_firewall_snapshot_is_stable_and_change_is_refused(self):
        driver = self._driver()
        before = driver.snapshot_firewall()
        driver.assert_firewall_unchanged(before)
        with self.assertRaises(vm_drill.DrillFailure):
            driver.assert_firewall_unchanged({"fabricated": "hash"})

    def test_copy_shim_is_valid_posix_and_blocks_only_tar_create(self):
        driver = self._driver()
        driver.drill_root = tempfile.mkdtemp()
        driver.copy_shim_dir = os.path.join(driver.drill_root, "drill-bin")
        driver.ledger_path = "/ledger"
        driver.host = object()
        captured = {}
        original_dir = vm_drill.fixture.create_owned_dir
        original_file = vm_drill.fixture.write_owned_file

        def fake_dir(ledger, path, host):
            os.makedirs(path, exist_ok=True)

        def fake_file(ledger, path, content, mode, host):
            captured["content"] = content
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(content)
            os.chmod(path, mode)

        vm_drill.fixture.create_owned_dir = fake_dir
        vm_drill.fixture.write_owned_file = fake_file
        try:
            shim_dir = driver.write_copy_shim()
        finally:
            vm_drill.fixture.create_owned_dir = original_dir
            vm_drill.fixture.write_owned_file = original_file
        shim = os.path.join(shim_dir, "tar")
        result = subprocess.run(["sh", "-n", shim], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue(os.access(shim, os.X_OK))
        content = captured["content"]
        self.assertIn('*" -cpf "*', content)
        self.assertIn('exec "$real_tar" "$@"', content)
        self.assertIn("VPS3XUI_DRILL_COPY_BARRIER/reached", content)


class LifecycleObservationTest(unittest.TestCase):
    """R9-E: finalizer-aware observation, never a false success or false stop."""

    def _driver(self):
        driver = object.__new__(vm_drill.Driver)
        driver.log = lambda message: None
        return driver

    def test_wait_finalized_waits_for_the_complete_marker(self):
        driver = self._driver()
        state = {"value": "succeeded"}
        marker = {"exists": False}
        polls = {"count": 0}
        driver.job_state = lambda job: state["value"]
        driver.job_report = lambda job: {"state": state["value"], "completed_at": "t"}
        driver.unit_runtime_state = lambda unit: "stopped"
        driver.complete_path = lambda job: "/COMPLETE"
        original_exists = os.path.exists

        def fake_exists(path):
            if path == "/COMPLETE":
                polls["count"] += 1
                if polls["count"] >= 3:
                    marker["exists"] = True
                return marker["exists"]
            return original_exists(path)

        driver._original_exists = original_exists
        os.path.exists = fake_exists
        try:
            result = driver.wait_finalized("/job", "/unit", timeout_sec=5)
        finally:
            os.path.exists = original_exists
        self.assertEqual(result, "succeeded")
        self.assertGreaterEqual(polls["count"], 3,
                                "the marker must exist before the wait returns")

    def test_wait_finalized_does_not_accept_a_deactivating_unit(self):
        driver = self._driver()
        states = ["deactivating", "stopped"]
        driver.job_state = lambda job: "succeeded"
        driver.job_report = lambda job: {"state": "succeeded", "completed_at": "t"}
        driver.unit_runtime_state = lambda unit: states.pop(0) if states else "stopped"
        driver.complete_path = lambda job: __file__  # an always-present marker
        result = driver.wait_finalized("/job", "/unit", timeout_sec=5)
        self.assertEqual(result, "succeeded")

    def test_wait_unit_inactive_never_reads_an_error_as_inactive(self):
        driver = self._driver()
        states = ["unknown", "unknown", "stopped"]
        driver.unit_runtime_state = lambda unit: states.pop(0)
        self.assertEqual(driver.wait_unit_inactive("/unit", 5), "stopped")
        driver.unit_runtime_state = lambda unit: "unknown"
        with self.assertRaises(vm_drill.DrillFailure):
            driver.wait_unit_inactive("/unit", 1)

    def _copying_driver(self, tmp, stop_records=None, idle_id="i" * 64,
                        include_idle_fact=True):
        initial = {"stop_containers": stop_records or [{"name": "src", "id": "a" * 64}]}
        if include_idle_fact:
            initial["containers"] = {"drill-idle": {"name": "drill-idle",
                                                    "id": idle_id, "running": False}}
        with open(os.path.join(tmp, "initial-state.json"), "w", encoding="utf-8") as handle:
            json.dump(initial, handle)
        driver = self._driver()
        driver.names = {"idle_container": "drill-idle"}
        driver.job_state = lambda job: "copying"
        driver.container_state = lambda name: "stopped"
        driver.container_identity = lambda name: {"src": "a" * 64,
                                                  "drill-idle": idle_id}.get(name, "")
        return driver

    def test_assert_copying_proves_the_source_is_quiesced(self):
        with tempfile.TemporaryDirectory() as tmp:
            driver = self._copying_driver(tmp)
            result = driver.assert_copying(tmp)
            self.assertEqual(result["stop_containers"][0]["name"], "src")
            self.assertEqual(result["idle_container"]["id"], "i" * 64)
            driver.container_state = lambda name: "running" if name == "src" else "stopped"
            with self.assertRaises(vm_drill.DrillFailure):
                driver.assert_copying(tmp)
            driver.container_state = lambda name: "running" if name == "drill-idle" else "stopped"
            with self.assertRaises(vm_drill.DrillFailure):
                driver.assert_copying(tmp)
            driver.job_state = lambda job: "quiescing"
            driver.container_state = lambda name: "stopped"
            with self.assertRaises(vm_drill.DrillFailure):
                driver.assert_copying(tmp)

    def test_assert_copying_never_reads_an_inspect_error_as_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            driver = self._copying_driver(tmp)
            # A Docker/bus error or a missing container is not "stopped".
            for observed in ("unknown", "absent", "running"):
                driver.container_state = (lambda value: (lambda name: value))(observed)
                with self.assertRaises(vm_drill.DrillFailure):
                    driver.assert_copying(tmp)

    def test_assert_copying_requires_and_checks_container_identities(self):
        with tempfile.TemporaryDirectory() as tmp:
            # A recorded source container without an id is a hard failure.
            driver = self._copying_driver(tmp, stop_records=[{"name": "src", "id": ""}])
            with self.assertRaises(vm_drill.DrillFailure):
                driver.assert_copying(tmp)
            # A missing idle identity is a hard failure, never a skipped check.
            driver = self._copying_driver(tmp, include_idle_fact=False)
            with self.assertRaises(vm_drill.DrillFailure):
                driver.assert_copying(tmp)
            # A replaced idle container id must fail.
            driver = self._copying_driver(tmp)
            driver.container_identity = lambda name: ("a" * 64 if name == "src"
                                                      else "z" * 64)
            with self.assertRaises(vm_drill.DrillFailure):
                driver.assert_copying(tmp)


class EvidenceRetentionTest(unittest.TestCase):
    """R9-F: evidence is validated, preserved before cleanup and always written."""
    IMAGE = "fixture.local/app@sha256:" + "0" * 64

    def test_validate_evidence_dir_requires_this_runs_owner_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "root")
            os.makedirs(root)
            with self.assertRaises(vm_drill.DrillFailure):
                vm_drill.validate_evidence_dir(root, root, "nonce")
            with self.assertRaises(vm_drill.DrillFailure):
                vm_drill.validate_evidence_dir("relative/evidence", root, "nonce")
            evidence = os.path.join(tmp, "evidence")
            os.makedirs(evidence)
            # no marker yet -> refused
            with self.assertRaises(vm_drill.DrillFailure):
                vm_drill.validate_evidence_dir(evidence, root, "nonce")
            # another run's marker is refused, as is a missing nonce
            with open(os.path.join(evidence, vm_drill.EVIDENCE_MARKER_NAME), "w",
                      encoding="utf-8") as handle:
                handle.write("someone-elses-nonce\n")
            with self.assertRaises(vm_drill.DrillFailure):
                vm_drill.validate_evidence_dir(evidence, root, "nonce")
            with self.assertRaises(vm_drill.DrillFailure):
                vm_drill.validate_evidence_dir(evidence, root, None)
            vm_drill.validate_evidence_dir(evidence, root, "someone-elses-nonce")
            with open(os.path.join(evidence, "evidence.json"), "w",
                      encoding="utf-8") as handle:
                handle.write("{}\n")
            with self.assertRaises(vm_drill.DrillFailure):
                vm_drill.validate_evidence_dir(evidence, root, "someone-elses-nonce")

    def test_prepare_evidence_dir_creates_exclusively_and_stamps_the_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            root = os.path.join(tmp, "root")
            os.makedirs(root)
            evidence = os.path.join(tmp, "evidence")
            ledger = os.path.join(root, "ledger.json")
            nonce = vm_drill.prepare_evidence_dir(evidence, root, "t1", self.IMAGE, ledger)
            self.assertTrue(os.path.isdir(evidence))
            self.assertFalse(os.path.islink(evidence))
            marker = os.path.join(evidence, vm_drill.EVIDENCE_MARKER_NAME)
            with open(marker, "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read().strip(), nonce)
            # A second call must refuse to touch the existing directory.
            with self.assertRaises(vm_drill.DrillFailure):
                vm_drill.prepare_evidence_dir(evidence, root, "t1", self.IMAGE, ledger)
            with open(marker, "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read().strip(), nonce)
            self.assertEqual(sorted(os.listdir(evidence)), [vm_drill.EVIDENCE_MARKER_NAME])

    def test_prepare_evidence_dir_refuses_a_symlinked_ancestor(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            real = os.path.join(tmp, "real")
            os.makedirs(real)
            link = os.path.join(tmp, "link")
            os.symlink(real, link)
            root = os.path.join(tmp, "root")
            os.makedirs(root)
            with self.assertRaises(vm_drill.DrillFailure):
                vm_drill.prepare_evidence_dir(os.path.join(link, "evidence"), root,
                                              "t1", self.IMAGE,
                                              os.path.join(root, "ledger.json"))
            self.assertFalse(os.path.exists(os.path.join(real, "evidence")))

    def test_prepare_evidence_dir_refuses_a_fixture_owned_overlap(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            root = os.path.join(tmp, "root")
            os.makedirs(root)
            owned = os.path.join(tmp, "owned")
            os.makedirs(owned)
            original = vm_drill.prospective_owned_paths
            vm_drill.prospective_owned_paths = lambda identifier, image, ledger: [owned]
            try:
                with self.assertRaises(vm_drill.DrillFailure):
                    vm_drill.prepare_evidence_dir(os.path.join(owned, "evidence"), root,
                                                  "t1", self.IMAGE,
                                                  os.path.join(root, "ledger.json"))
            finally:
                vm_drill.prospective_owned_paths = original
            self.assertFalse(os.path.exists(os.path.join(owned, "evidence")))

    def test_prospective_owned_paths_cover_the_fixture_trees(self):
        paths = vm_drill.prospective_owned_paths("t1", self.IMAGE, "/scratch/ledger.json")
        names = vm_drill.fixture.fixture_identity("t1")
        self.assertIn(names["job_dir"], paths)
        self.assertIn("/scratch/ledger.json", paths)
        for path in vm_drill.fixture.fixture_dirs(names):
            self.assertIn(path, paths)

    def test_evidence_conflicts_flags_a_fixture_owned_path(self):
        names = vm_drill.fixture.fixture_identity("t1")
        overlap = os.path.join(names["job_dir"], "evidence")
        self.assertTrue(vm_drill._evidence_conflicts(overlap, "t1", self.IMAGE,
                                                     "/scratch/ledger.json", "/scratch"))
        self.assertEqual(
            vm_drill._evidence_conflicts("/srv/evidence", "t1", self.IMAGE,
                                         "/scratch/ledger.json", "/scratch"), [])

    def test_assert_evidence_separate_refuses_a_ledger_owned_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = vm_drill.fixture.Host(root=tmp, platform="linux", euid=0)
            ledger_path = "/var/lib/%s.ledger.json" % "vps3xui-drill-t1"
            ledger = vm_drill.fixture.Ledger(ledger_path, host, "t1", "vps3xui-drill-t1")
            ledger.begin()
            tree = "/var/lib/vps3xui-drill-t1/restore"
            os.makedirs(host.local(tree), 0o700)
            ledger.add_tree(tree, host.lstat(tree))
            driver = object.__new__(vm_drill.Driver)
            driver.host = host
            driver.ledger_path = ledger_path
            vm_drill.assert_evidence_separate(driver, "/tmp/evidence-outside")
            with self.assertRaises(vm_drill.DrillFailure):
                vm_drill.assert_evidence_separate(driver, tree + "/evidence")

    def test_preserve_job_evidence_copies_the_durable_job_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            job = os.path.join(tmp, "job")
            evidence = os.path.join(tmp, "evidence")
            os.makedirs(job)
            os.makedirs(evidence)
            for name in ("report.json", "state.json", "initial-state.json"):
                with open(os.path.join(job, name), "w", encoding="utf-8") as handle:
                    handle.write('{"unit_result": {"SERVICE_RESULT": "timeout"}}\n')
            driver = object.__new__(vm_drill.Driver)
            driver.evidence_dir = evidence
            driver.jobs = []
            driver.preserve_job_evidence("timeout", job)
            for name in ("report.json", "state.json", "initial-state.json"):
                self.assertTrue(os.path.isfile(
                    os.path.join(evidence, "jobs", "timeout", name)), name)

    def test_main_turns_a_fixture_systemexit_into_failed_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = os.path.join(tmp, "evidence")
            nonce = "n" * 32
            os.makedirs(evidence)
            with open(os.path.join(evidence, vm_drill.EVIDENCE_MARKER_NAME), "w",
                      encoding="utf-8") as handle:
                handle.write(nonce + "\n")
            original_problem = vm_drill._tooling_problem
            original_create = vm_drill.Driver.create_fixture
            original_marker = os.environ.get("VPS3XUI_DRILL_EVIDENCE_MARKER")
            vm_drill._tooling_problem = lambda: None
            os.environ["VPS3XUI_DRILL_EVIDENCE_MARKER"] = nonce

            def explode(self):
                raise SystemExit("refusing to reuse existing fixture resources")

            vm_drill.Driver.create_fixture = explode
            try:
                status = vm_drill.main(["--release-dir", "/release",
                                        "--drill-root", tmp, "--image", self.IMAGE,
                                        "--identifier", "t1", "--ledger",
                                        os.path.join(tmp, "ledger.json"),
                                        "--evidence-dir", evidence])
            finally:
                vm_drill._tooling_problem = original_problem
                vm_drill.Driver.create_fixture = original_create
                if original_marker is None:
                    os.environ.pop("VPS3XUI_DRILL_EVIDENCE_MARKER", None)
                else:
                    os.environ["VPS3XUI_DRILL_EVIDENCE_MARKER"] = original_marker
            self.assertEqual(status, vm_drill.EXIT_FAILED)
            with open(os.path.join(evidence, "evidence.json"), "r", encoding="utf-8") as handle:
                document = json.load(handle)
            self.assertFalse(document["ok"])
            self.assertEqual(document["error_type"], "SystemExit")


class RestoreChoreographyTest(unittest.TestCase):
    """Real restore comparison: files, metadata, links, volume and docker cp."""

    IMAGE = "fixture.local/app@sha256:" + "0" * 64
    COMPOSE = b"services:\n  app:\n    image: fixture\n"
    APP_ENV = b"FIXTURE_ONLY=1\n"
    JAIL = b"synthetic drill jail; never production\n"
    FILTER = b"[Definition]\nfailregex = ^drill\n"
    DB = b"synthetic drill fail2ban database\n"

    def _expectations(self, names):
        stat_info = os.stat
        uid, gid = os.getuid(), os.getgid()
        return {
            "bind_files": [
                {"path": names["compose_dir"] + "/docker-compose.yaml",
                 "sha256": hashlib.sha256(self.COMPOSE).hexdigest(), "mode": "0644",
                 "uid": uid, "gid": gid},
                {"path": names["compose_dir"] + "/app.env",
                 "sha256": hashlib.sha256(self.APP_ENV).hexdigest(), "mode": "0600",
                 "uid": uid, "gid": gid},
            ],
            "links": [{"path": "/etc/letsencrypt/live/%s/cert.pem" % names["lineage"],
                       "target": "../../archive/%s/cert.pem" % names["lineage"]}],
            "volume": {"name": names["volume"], "path": "fixture.txt",
                       "content": "fixture-data\n"},
            "fail2ban": {
                "config_path": "/etc/fail2ban", "data_path": "/var/lib/fail2ban",
                "files": [
                    {"path": "/etc/fail2ban/jail.local",
                     "sha256": hashlib.sha256(self.JAIL).hexdigest(),
                     "mode": "0640", "uid": 0, "gid": 0},
                    {"path": "/etc/fail2ban/filter.d/drill.conf",
                     "sha256": hashlib.sha256(self.FILTER).hexdigest(),
                     "mode": "0640", "uid": 0, "gid": 0},
                    {"path": "/var/lib/fail2ban/db.sqlite",
                     "sha256": hashlib.sha256(self.DB).hexdigest(),
                     "mode": "0600", "uid": 0, "gid": 0},
                ],
            },
        }

    def _seed_bind_destination(self, destination, names, mode=0o600, link_target=None):
        for path, blob, file_mode in (
            (names["compose_dir"] + "/docker-compose.yaml", self.COMPOSE, 0o644),
            (names["compose_dir"] + "/app.env", self.APP_ENV, mode),
        ):
            target = os.path.join(destination, path.lstrip("/"))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as handle:
                handle.write(blob)
            os.chmod(target, file_mode)
        live = os.path.join(destination,
                            ("/etc/letsencrypt/live/%s" % names["lineage"]).lstrip("/"))
        os.makedirs(live, exist_ok=True)
        os.symlink(link_target or ("../../archive/%s/cert.pem" % names["lineage"]),
                   os.path.join(live, "cert.pem"))

    def _run_restore(self, tmp, mutate=None, container_facts_mutation=None,
                     expect_failure=False):
        names = vm_drill.fixture.fixture_identity("t1")
        expectations = self._expectations(names)
        bind_root = os.path.join(tmp, "restore-bind")
        volume_root = os.path.join(tmp, "restore-volume")
        backup = os.path.join(tmp, "backup")
        os.makedirs(backup, exist_ok=True)
        for name in ("config.tar", "data.tar", "volume.tar", "binds.tar"):
            with open(os.path.join(backup, name), "wb") as handle:
                handle.write(b"validation is patched\n")
        manifest = SimpleNamespace(
            bind_trees=[{"artifact": "binds.tar", "root": "/",
                         "includes": [names["compose_dir"].lstrip("/") + "/docker-compose.yaml",
                                      names["compose_dir"].lstrip("/") + "/app.env",
                                      "etc/letsencrypt"]}],
            volumes=[{"name": names["volume"], "artifact": "volume.tar"}],
            writable_layers=[
                {"container": "3xui_app", "path": "/etc/fail2ban", "artifact": "config.tar"},
                {"container": "3xui_app", "path": "/var/lib/fail2ban", "artifact": "data.tar"},
            ],
        )
        driver = object.__new__(vm_drill.Driver)
        driver.manifest = manifest
        driver.names = {"restored_container": "drill-restored"}
        driver.image = self.IMAGE
        driver.ledger_path = "/ledger"
        driver.drill_root = tmp
        driver.host = object()
        driver.fixture_info = {"restore_expectations": expectations,
                               "idle_container": {"id": "i" * 64}}
        driver.job_report = lambda job: {"backup_dir": backup}
        driver.container_running = lambda name: False
        driver.container_state = lambda name: "stopped"
        driver._read_container_file = lambda container, path: (
            self.JAIL if path.endswith("jail.local")
            else self.FILTER if path.endswith("drill.conf")
            else self.DB,
            {"mode": "0640" if path.endswith("jail.local") or path.endswith("drill.conf") else "0600",
             "uid": 0, "gid": 0})

        def extract(artifact, destination):
            if os.path.basename(destination).startswith("volume-"):
                with open(os.path.join(destination, "fixture.txt"), "w",
                          encoding="utf-8") as handle:
                    handle.write("fixture-data\n")
                return
            self._seed_bind_destination(destination, names)
            if mutate == "bind_mode":
                os.chmod(os.path.join(destination,
                                      (names["compose_dir"] + "/app.env").lstrip("/")), 0o644)
            if mutate == "link":
                live = os.path.join(destination,
                                    ("/etc/letsencrypt/live/%s" % names["lineage"]).lstrip("/"))
                os.unlink(os.path.join(live, "cert.pem"))
                os.symlink("../../archive/other/cert.pem", os.path.join(live, "cert.pem"))

        calls = []
        original_run = vm_drill.subprocess.run

        def fake_run(argv, **kwargs):
            calls.append((list(argv), getattr(kwargs.get("stdin"), "name", None)))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        import vps3xui.verify as verify_module
        import vps3xui.adapters.archive as archive_module
        originals = (verify_module.verify_directory, archive_module.validate_tar,
                     archive_module.safe_extract, vm_drill.fixture.create_owned_tree,
                     vm_drill.fixture.create_owned_container, vm_drill.subprocess.run,
                     driver._read_container_file)
        try:
            verify_module.verify_directory = lambda *a, **k: SimpleNamespace(ok=True)
            archive_module.validate_tar = lambda *a, **k: SimpleNamespace()
            archive_module.safe_extract = extract
            vm_drill.fixture.create_owned_tree = lambda ledger, path, host: os.makedirs(path, exist_ok=True)
            vm_drill.fixture.create_owned_container = lambda *a, **k: {"name": a[1], "id": "c" * 64}
            vm_drill.subprocess.run = fake_run
            if container_facts_mutation:
                driver._read_container_file = container_facts_mutation(driver._read_container_file)
            if expect_failure:
                with self.assertRaises(vm_drill.DrillFailure):
                    driver.restore_success(os.path.join(tmp, "job"))
                return calls
            restored = driver.restore_success(os.path.join(tmp, "job"))
        finally:
            (verify_module.verify_directory, archive_module.validate_tar,
             archive_module.safe_extract, vm_drill.fixture.create_owned_tree,
             vm_drill.fixture.create_owned_container, vm_drill.subprocess.run,
             driver._read_container_file) = originals
        self.assertEqual(len(restored["bind_files"]), 2)
        self.assertEqual(restored["links"][0]["target"],
                         "../../archive/%s/cert.pem" % names["lineage"])
        self.assertEqual(restored["volume"]["content"], "fixture-data\n")
        self.assertEqual(len(restored["fail2ban_files"]), 3)
        copies = [call for call in calls if call[0][:2] == ["docker", "cp"]]
        self.assertTrue(copies)
        for argv, _name in copies:
            self.assertEqual(argv[:3], ["docker", "cp", "-a"])
        return restored

    def test_restore_compares_seeded_files_metadata_links_and_volume(self):
        names = vm_drill.fixture.fixture_identity("t1")
        with tempfile.TemporaryDirectory() as tmp:
            restored = self._run_restore(tmp)
        self.assertEqual(restored["bind_files"][0]["sha256"],
                         hashlib.sha256(self.COMPOSE).hexdigest())
        self.assertEqual(restored["bind_files"][1]["mode"], "0600")
        self.assertTrue(restored["fail2ban_stopped"])
        self.assertEqual(restored["fail2ban_container"], "drill-restored")

    def test_restore_fails_when_restored_metadata_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._run_restore(tmp, mutate="bind_mode", expect_failure=True)

    def test_restore_fails_when_link_target_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._run_restore(tmp, mutate="link", expect_failure=True)

    def test_restore_fails_when_fail2ban_owner_changes(self):
        def mutate(original):
            def patched(container, path):
                content, facts = original(container, path)
                facts = dict(facts)
                facts["uid"] = 1000
                return content, facts
            return patched

        with tempfile.TemporaryDirectory() as tmp:
            self._run_restore(tmp, container_facts_mutation=mutate, expect_failure=True)

    def _write_tar(self, path, entries, symlink=None):
        # Numeric ownership is set to this process's ids so the real
        # ``safe_extract`` python fallback never needs a privileged chown.
        uid, gid = os.getuid(), os.getgid()
        with tarfile.open(path, "w") as archive:
            for name, content, mode in entries:
                info = tarfile.TarInfo(name)
                info.size = len(content)
                info.mode = mode
                info.uid = uid
                info.gid = gid
                archive.addfile(info, io.BytesIO(content))
            if symlink is not None:
                name, target = symlink
                link = tarfile.TarInfo(name)
                link.type = tarfile.SYMTYPE
                link.linkname = target
                link.mode = 0o777
                link.uid = uid
                link.gid = gid
                archive.addfile(link)

    def test_restore_success_uses_real_archives_and_real_safe_extract(self):
        """The archive boundary is real: real tar files, real safe_extract.

        Only the Docker boundary (``docker cp``/container create/inspect) and the
        product pre-check are faked; ``validate_tar``/``safe_extract`` and the
        real bind/volume/link comparison run unpatched.
        """
        names = vm_drill.fixture.fixture_identity("t1")
        lineage = names["lineage"]
        with tempfile.TemporaryDirectory() as tmp:
            backup = os.path.join(tmp, "backup")
            os.makedirs(backup)
            compose_name = names["compose_dir"].lstrip("/") + "/docker-compose.yaml"
            env_name = names["compose_dir"].lstrip("/") + "/app.env"
            live_name = "etc/letsencrypt/live/%s/cert.pem" % lineage
            archive_name = "etc/letsencrypt/archive/%s/cert.pem" % lineage
            self._write_tar(os.path.join(backup, "volume.tar"),
                            [("fixture.txt", b"fixture-data\n", 0o644)])
            self._write_tar(
                os.path.join(backup, "binds.tar"),
                [(compose_name, self.COMPOSE, 0o644),
                 (env_name, self.APP_ENV, 0o600),
                 (archive_name, b"certificate\n", 0o644)],
                symlink=(live_name, "../../archive/%s/cert.pem" % lineage))
            self._write_tar(os.path.join(backup, "config.tar"),
                            [("jail.local", self.JAIL, 0o640),
                             ("filter.d/drill.conf", self.FILTER, 0o640)])
            self._write_tar(os.path.join(backup, "data.tar"),
                            [("db.sqlite", self.DB, 0o600)])
            manifest = SimpleNamespace(
                bind_trees=[{"artifact": "binds.tar", "root": "/"}],
                volumes=[{"name": names["volume"], "artifact": "volume.tar"}],
                writable_layers=[
                    {"container": "3xui_app", "path": "/etc/fail2ban",
                     "artifact": "config.tar"},
                    {"container": "3xui_app", "path": "/var/lib/fail2ban",
                     "artifact": "data.tar"},
                ],
            )
            driver = object.__new__(vm_drill.Driver)
            driver.manifest = manifest
            driver.names = {"restored_container": "drill-restored"}
            driver.image = self.IMAGE
            driver.ledger_path = "/ledger"
            driver.drill_root = tmp
            driver.host = object()
            driver.fixture_info = {"restore_expectations": self._expectations(names)}
            driver.job_report = lambda job: {"backup_dir": backup}
            driver.container_state = lambda name: "stopped"
            driver._read_container_file = lambda container, path: (
                self.JAIL if path.endswith("jail.local")
                else self.FILTER if path.endswith("drill.conf") else self.DB,
                {"mode": ("0640" if path.endswith("jail.local")
                          or path.endswith("drill.conf") else "0600"),
                 "uid": 0, "gid": 0})

            import vps3xui.verify as verify_module
            originals = (verify_module.verify_directory,
                         vm_drill.fixture.create_owned_tree,
                         vm_drill.fixture.create_owned_container,
                         vm_drill.subprocess.run)

            def fake_run(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 0, b"", b"")

            try:
                verify_module.verify_directory = lambda *a, **k: SimpleNamespace(ok=True)
                vm_drill.fixture.create_owned_tree = (
                    lambda ledger, path, host: os.makedirs(path, exist_ok=True))
                vm_drill.fixture.create_owned_container = (
                    lambda *a, **k: {"name": a[1], "id": "c" * 64})
                vm_drill.subprocess.run = fake_run
                restored = driver.restore_success(os.path.join(tmp, "job"))
            finally:
                (verify_module.verify_directory,
                 vm_drill.fixture.create_owned_tree,
                 vm_drill.fixture.create_owned_container,
                 vm_drill.subprocess.run) = originals
            self.assertEqual(restored["bind_files"][0]["sha256"],
                             hashlib.sha256(self.COMPOSE).hexdigest())
            self.assertEqual(restored["bind_files"][1]["sha256"],
                             hashlib.sha256(self.APP_ENV).hexdigest())
            self.assertEqual(restored["bind_files"][1]["mode"], "0600")
            self.assertEqual(restored["links"][0]["path"],
                             "/etc/letsencrypt/live/%s/cert.pem" % lineage)
            self.assertEqual(restored["links"][0]["target"],
                             "../../archive/%s/cert.pem" % lineage)
            self.assertEqual(restored["volume"]["content"], "fixture-data\n")
            self.assertEqual(len(restored["fail2ban_files"]), 3)
            self.assertTrue(restored["fail2ban_stopped"])
            # The real safe_extract produced real files on disk.
            bind_root = restored["destinations"]["binds.tar"]
            self.assertTrue(os.path.isfile(os.path.join(bind_root, compose_name)))
            self.assertTrue(os.path.islink(os.path.join(bind_root, live_name)))

    def test_restore_requires_fixture_expectations(self):
        driver = object.__new__(vm_drill.Driver)
        driver.fixture_info = {}
        with self.assertRaises(vm_drill.DrillFailure):
            driver.restore_success("/job")


class RestoredMetadataTest(unittest.TestCase):
    """R9 item 4: the real metadata matcher with only the command boundary faked."""

    def _driver(self):
        return object.__new__(vm_drill.Driver)

    def _prepare(self, tmp, name="opt/app/app.env", content=b"FIXTURE_ONLY=1\n",
                 mode=0o600):
        destination = os.path.join(tmp, "dest")
        path = os.path.join(destination, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(content)
        os.chmod(path, mode)
        info = os.stat(path)
        expected = {"path": "/" + name, "sha256": hashlib.sha256(content).hexdigest(),
                    "mode": "%04o" % (mode & 0o777),
                    "uid": info.st_uid, "gid": info.st_gid}
        return destination, expected

    def _with_metadata(self, answer, func):
        original = vm_drill._bounded_metadata_tool
        seen = []

        def fake(argv, tool, path):
            seen.append((list(argv), tool, path))
            return answer(argv, tool, path)

        vm_drill._bounded_metadata_tool = fake
        try:
            return func(), seen
        finally:
            vm_drill._bounded_metadata_tool = original

    def test_read_acl_requests_numeric_entries(self):
        def answer(argv, tool, path):
            return "user::rw-\nuser:4242:rwx\n"

        text, seen = self._with_metadata(answer, lambda: vm_drill._read_acl("/tmp/x"))
        self.assertIn("user:4242:rwx", text)
        self.assertEqual(seen[0][0][0], "getfacl")
        self.assertIn("-n", seen[0][0])

    def test_assert_restored_file_accepts_the_required_acl_and_xattr(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination, expected = self._prepare(tmp)
            expected["acl"] = "user:4242:rwx"
            expected["xattr_name"] = "user.vps3xui"
            expected["xattr_value"] = "drill"

            def answer(argv, tool, path):
                if tool == "getfacl":
                    return "user::rw-\nuser:4242:rwx\n"
                return "drill"

            record, _seen = self._with_metadata(
                answer, lambda: self._driver()._assert_restored_file(expected, destination))
            self.assertEqual(record["acl"], "user:4242:rwx")
            self.assertEqual(record["xattr_value"], "drill")

    def test_assert_restored_file_fails_when_the_required_acl_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination, expected = self._prepare(tmp)
            expected["acl"] = "user:4242:rwx"

            def answer(argv, tool, path):
                return "user::rw-\ngroup::r--\n"  # 4242 entry absent

            with self.assertRaises(vm_drill.DrillFailure):
                self._with_metadata(
                    answer,
                    lambda: self._driver()._assert_restored_file(expected, destination))

    def test_assert_restored_file_fails_on_missing_or_wrong_xattr(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination, expected = self._prepare(tmp)
            expected["xattr_name"] = "user.vps3xui"
            expected["xattr_value"] = "drill"
            with self.assertRaises(vm_drill.DrillFailure):
                self._with_metadata(lambda argv, tool, path: "",
                                    lambda: self._driver()._assert_restored_file(
                                        expected, destination))
            with self.assertRaises(vm_drill.DrillFailure):
                self._with_metadata(lambda argv, tool, path: "other",
                                    lambda: self._driver()._assert_restored_file(
                                        expected, destination))


class BoundedCommandTest(unittest.TestCase):
    """R9 item 5: every drill command is bounded and a timeout is not a pass."""

    def _driver(self):
        driver = object.__new__(vm_drill.Driver)
        driver.commands = []
        driver.log_lines = []
        return driver

    def test_driver_run_sets_a_default_timeout_and_reports_a_timeout(self):
        driver = self._driver()
        original = vm_drill.subprocess.run
        seen = {}

        def fake_run(argv, **kwargs):
            seen["timeout"] = kwargs.get("timeout")
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        vm_drill.subprocess.run = fake_run
        try:
            driver.run(["/bin/true"])
        finally:
            vm_drill.subprocess.run = original
        self.assertEqual(seen["timeout"], vm_drill.DEFAULT_COMMAND_TIMEOUT)

        def time_out(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 1))

        vm_drill.subprocess.run = time_out
        try:
            with self.assertRaises(vm_drill.DrillFailure) as ctx:
                driver.run(["/bin/sleep"], timeout=3)
        finally:
            vm_drill.subprocess.run = original
        self.assertIn("timed out", str(ctx.exception))

    def test_run_bounded_returns_none_and_container_running_is_false_on_timeout(self):
        original = vm_drill.subprocess.run

        def time_out(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout", 1))

        vm_drill.subprocess.run = time_out
        try:
            self.assertIsNone(vm_drill._run_bounded(["docker", "inspect", "x"]))
            self.assertFalse(self._driver().container_running("x"))
            self.assertEqual(self._driver().container_id("x"), "")
            self.assertTrue(self._driver()._systemd_unit_state("u")["active_state"] == "unknown")
        finally:
            vm_drill.subprocess.run = original

    def test_container_state_is_unknown_on_a_docker_timeout(self):
        def runner(argv, timeout=None):
            raise subprocess.TimeoutExpired(argv, timeout or 1)

        host = vm_drill.fixture.Host(root="/", platform="linux", euid=0, runner=runner)
        self.assertEqual(vm_drill.fixture.container_runtime_state("drill", host), "unknown")
        self.assertEqual(vm_drill.fixture.container_identity("drill", host), "")
        # A proven absence is distinct from a failure.
        def absent(argv, timeout=None):
            return subprocess.CompletedProcess(
                argv, 1, b"", b"Error: No such object: drill\n")

        host_absent = vm_drill.fixture.Host(root="/", platform="linux", euid=0,
                                            runner=absent)
        self.assertEqual(vm_drill.fixture.container_runtime_state("drill", host_absent),
                         "absent")


class FixtureJobResultTest(unittest.TestCase):
    """R9 item 3: create_job must carry the idle container identity forward."""

    def test_create_job_returns_the_idle_container_record(self):
        fixture = vm_drill.fixture
        names = fixture.fixture_identity("t1")
        sentinel = {"name": names["idle_container"], "id": "i" * 64}
        resources = {"mountpoint": "/mnt", "container": {"id": "a" * 64},
                     "idle_container": sentinel, "restore_expectations": {"x": 1}}
        original = fixture.seed_job
        fixture.seed_job = lambda *a, **k: {"names": names}
        try:
            result = fixture.create_job(object(), names, "fixture.local/app@sha256:" + "0" * 64,
                                        "/release", object(), resources)
        finally:
            fixture.seed_job = original
        self.assertEqual(result["idle_container"], sentinel)
        self.assertEqual(result["container_id"], "a" * 64)
        self.assertEqual(result["restore_expectations"], {"x": 1})


if __name__ == "__main__":
    unittest.main()
