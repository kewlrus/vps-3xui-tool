"""R2: automatic ``ExecStopPost`` versus explicit ``job recover``.

The generated ``systemd-run`` argv is the only thing systemd executes, so these
tests take the real ``remote_ops._systemd_run_argv`` output, parse the
``ExecStopPost`` property (and the explicit recover command) and then run the
shipped ``bin/vps3xui-finalizer`` entrypoint as a child process.

The host adapter is faked through a ``sitecustomize`` shim staged inside the
release directory the launch argv points at, and the ``docker``/``systemctl``
binaries on ``PATH`` are fakes that record every call. Nothing here can touch a
real host: an accidental real command lands on the recording fake and fails.
"""

import json
import os
import shutil
import stat
import subprocess
import unittest

import support
from vps3xui import remote_ops
from vps3xui.inventory import Inventory
from vps3xui.plan import build_plan
from vps3xui.verify import verify_directory
from vps3xui.worker.backup_worker import BackupWorker

FINALIZER_ENTRYPOINT = "bin/vps3xui-finalizer"

# Injected as ``<release_dir>/sitecustomize.py``. The shipped entrypoint sets
# ``PYTHONPATH`` to its own release directory, so Python imports this before the
# finalizer module runs and the real ``RealSystem`` never touches the host.
FAKE_SITECUSTOMIZE = '''"""Test-only host adapter used by the launch-mode tests."""
import json
import os
import sys

sys.path.insert(0, os.environ["VPS3XUI_FAKE_REPO"])

with open(os.path.join(os.environ["VPS3XUI_FAKE_JOB_DIR"], "initial-state.json"),
          "r", encoding="utf-8") as _handle:
    _INITIAL = json.load(_handle)

_LOG_PATH = os.environ["VPS3XUI_FAKE_HOST_LOG"]


def _log(entry):
    with open(_LOG_PATH, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\\n")


class FakeSystem(object):
    """Records recovery calls instead of running Docker or systemd."""

    def __init__(self, backup_root="/var/backups/vps3xui", release_dir=None):
        self.backup_root = backup_root
        self.release_dir = release_dir

    def machine_id(self):
        _log({"call": "machine_id"})
        return _INITIAL["machine_id"]

    def start_containers(self, ids):
        _log({"call": "start_containers", "ids": list(ids)})

    def container_states(self, names):
        _log({"call": "container_states", "names": list(names)})
        recorded = {item["name"]: item for item in _INITIAL.get("stop_containers") or []}
        return {
            name: {"name": name, "id": recorded[name]["id"], "running": True}
            for name in names if name in recorded
        }

    def restore_certbot_triggers(self, state, manifest):
        _log({"call": "restore_certbot_triggers",
              "units": sorted(((state or {}).get("units") or {}).keys())})


from vps3xui.worker import system as _system_module

_system_module.RealSystem = FakeSystem
'''

# A stand-in for the host binaries. It records argv and fails loudly, so any
# path that bypasses the fake adapter is detected instead of mutating a host.
FAKE_HOST_BINARY = '''#!/bin/sh
printf '%s\\n' "$0" "$@" >> "$VPS3XUI_FAKE_BINARY_LOG"
exit "${VPS3XUI_FAKE_BINARY_RC:-1}"
'''


def copied_job(tmp, job_id):
    """Run the real worker against a synthetic system, leaving state ``copied``."""
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
    system = support.SyntheticSystem(manifest, os.path.join(tmp, "system"))
    BackupWorker(system, job_dir, manifest).run()
    return manifest, job_dir, backup_dir


def launch_metadata(release_dir, job_dir, unit_name):
    return {
        "unit_name": unit_name,
        "release_dir": release_dir,
        "job_dir": job_dir,
        "runtime_max_seconds": 900,
        "timeout_stop_seconds": 90,
    }


def exec_stop_post_tokens(argv):
    prefix = "--property=ExecStopPost="
    prop = next(token for token in argv if token.startswith(prefix))
    return prop[len(prefix):].split()


class FinalizerLaunchModeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = support.temp_state_dir("finalizer-launch-")
        self.release_dir = os.path.join(self.tmp, "release")
        self.fake_bin = os.path.join(self.tmp, "fakebin")
        self.host_log = os.path.join(self.tmp, "host-calls.jsonl")
        self.binary_log = os.path.join(self.tmp, "binary-calls.log")
        self.entrypoint = self._stage_release()
        self._install_host_binaries()

    def _stage_release(self):
        """Install the shipped entrypoint and the fake adapter exactly as a release would."""
        bindir = os.path.join(self.release_dir, "bin")
        os.makedirs(bindir, mode=0o700)
        entrypoint = os.path.join(self.release_dir, FINALIZER_ENTRYPOINT)
        shipped = os.path.join(support.REPO_ROOT, FINALIZER_ENTRYPOINT)
        shutil.copyfile(shipped, entrypoint)
        os.chmod(entrypoint, 0o755)
        with open(os.path.join(self.release_dir, "sitecustomize.py"), "w",
                  encoding="utf-8") as handle:
            handle.write(FAKE_SITECUSTOMIZE)
        # The staged entrypoint must be the shipped launcher, not a test rewrite.
        with open(shipped, "rb") as handle:
            shipped_bytes = handle.read()
        with open(entrypoint, "rb") as handle:
            self.assertEqual(handle.read(), shipped_bytes)
        return entrypoint

    def _install_host_binaries(self):
        os.makedirs(self.fake_bin, mode=0o700)
        for name in ("docker", "systemctl"):
            path = os.path.join(self.fake_bin, name)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(FAKE_HOST_BINARY)
            os.chmod(path, 0o755)

    def _env(self, job_dir):
        env = dict(os.environ)
        env["PATH"] = self.fake_bin + os.pathsep + env.get("PATH", "")
        # systemd supplies these to ExecStopPost; the automatic path must read
        # them and still finish the backup.
        env["SERVICE_RESULT"] = "success"
        env["EXIT_CODE"] = "exited"
        env["EXIT_STATUS"] = "0"
        env["VPS3XUI_FAKE_REPO"] = support.REPO_ROOT
        env["VPS3XUI_FAKE_JOB_DIR"] = job_dir
        env["VPS3XUI_FAKE_HOST_LOG"] = self.host_log
        env["VPS3XUI_FAKE_BINARY_LOG"] = self.binary_log
        # The shipped entrypoint sets PYTHONPATH to its own release directory.
        env.pop("PYTHONPATH", None)
        return env

    def _run_entrypoint(self, argv, job_dir):
        proc = subprocess.run(argv, cwd=support.REPO_ROOT, env=self._env(job_dir),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
        stdout = proc.stdout.decode("utf-8", "replace").strip().splitlines()
        self.assertTrue(stdout, proc.stderr.decode("utf-8", "replace"))
        return proc.returncode, json.loads(stdout[-1]), proc.stderr.decode("utf-8", "replace")

    def _host_calls(self):
        if not os.path.isfile(self.host_log):
            return []
        with open(self.host_log, "r", encoding="utf-8") as handle:
            return [json.loads(line) for line in handle.read().splitlines() if line]

    def _generated_backup_argv(self, job_dir):
        argv, problem = remote_ops._systemd_run_argv(
            "backup", launch_metadata(self.release_dir, job_dir, "vps3xui-backup-r2"))
        self.assertIsNone(problem, argv)
        return argv

    def _generated_recover_argv(self, job_dir):
        argv, problem = remote_ops._systemd_run_argv(
            "recover", launch_metadata(self.release_dir, job_dir, "vps3xui-recover-r2"))
        self.assertIsNone(problem, argv)
        return argv

    def test_generated_exec_stop_post_is_not_explicit_recover(self):
        manifest, job_dir, _backup = copied_job(self.tmp, "req-r2-mode")
        argv = self._generated_backup_argv(job_dir)
        tokens = exec_stop_post_tokens(argv)
        self.assertEqual(tokens[0], self.entrypoint, tokens)
        self.assertNotIn("--recover", tokens)
        self.assertEqual(tokens[-1], job_dir)
        self.assertIn(self.release_dir, tokens)

    def test_automatic_exec_stop_post_finishes_a_successful_copied_job(self):
        manifest, job_dir, backup_dir = copied_job(self.tmp, "req-r2-auto")
        argv = self._generated_backup_argv(job_dir)
        tokens = exec_stop_post_tokens(argv)

        code, result, stderr = self._run_entrypoint(tokens, job_dir)

        self.assertEqual(code, 0, stderr)
        self.assertEqual(result["state"], "succeeded", result)
        self.assertTrue(os.path.isfile(os.path.join(backup_dir, "COMPLETE")))
        self.assertTrue(verify_directory(backup_dir, manifest, require_complete=True).ok)
        # The real recovery path ran through the fake host adapter.
        calls = [entry["call"] for entry in self._host_calls()]
        self.assertIn("machine_id", calls)
        self.assertIn("start_containers", calls)
        self.assertIn("container_states", calls)
        # ...and no real host binary was executed.
        self.assertFalse(os.path.exists(self.binary_log), "a host binary was invoked")

    def test_generated_explicit_recover_cannot_upgrade_a_copied_job(self):
        manifest, job_dir, backup_dir = copied_job(self.tmp, "req-r2-explicit")
        argv = self._generated_recover_argv(job_dir)
        self.assertIn("--recover", argv)
        tokens = argv[argv.index(self.entrypoint):]
        self.assertIn("--recover", tokens)
        self.assertEqual(tokens[-1], job_dir)

        code, result, stderr = self._run_entrypoint(tokens, job_dir)

        self.assertNotEqual(code, 0, stderr)
        self.assertNotEqual(result["state"], "succeeded", result)
        self.assertEqual(result["state"], "recovery_required", result)
        self.assertTrue(result["recovered"], result)
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))
        self.assertFalse(verify_directory(backup_dir, manifest, require_complete=True).ok)
        self.assertFalse(os.path.exists(self.binary_log), "a host binary was invoked")


if __name__ == "__main__":
    unittest.main()
