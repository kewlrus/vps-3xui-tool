"""R3: bounded, ownership-aware launcher-to-worker lock handoff.

The submitter holds the host stack lock across the ``systemd-run
--property=Type=exec`` call and the launch-receipt write, so the worker is
exec'd while the lock is still held. Before the fix the worker acquired the
lock non-blocking and could exit ``E_LOCKED`` before persisting any state.

These tests use a *real* child process, a real ``flock`` on the real lock file
and the real ``BackupWorker.run`` / ``bin/vps3xui-worker`` entrypoint. All host
effects go through ``tests/support.py``'s synthetic system, so no Docker,
systemd, SSH or production data is touched.
"""

import base64
import fcntl
import json
import os
import shutil
import subprocess
import sys
import time
import unittest

import support
from vps3xui import coordination as coord
from vps3xui.inventory import Inventory
from vps3xui.plan import build_plan

TESTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(TESTS_DIR)
WORKER_ENTRYPOINT = "bin/vps3xui-worker"


# Real child process running the real ``BackupWorker.run`` against the synthetic
# system. It prints a ``STARTING`` line immediately before entering ``run`` so
# the parent can release the lock only after the worker is actually waiting.
CHILD_WORKER = '''\
import json
import os
import sys

repo = os.environ["VPS3XUI_REPO_ROOT"]
for path in (repo, os.path.join(repo, "tests")):
    if path not in sys.path:
        sys.path.insert(0, path)

import support
import vps3xui.worker.backup_worker as worker_module
from vps3xui import manifest as manifest_module
from vps3xui.errors import ToolError

job_dir, handoff, system_root = sys.argv[1], float(sys.argv[2]), sys.argv[3]
worker_module.LOCK_HANDOFF_SECONDS = handoff
manifest = manifest_module.load(os.path.join(job_dir, "manifest.json"))
system = support.SyntheticSystem(manifest, system_root)
worker = worker_module.BackupWorker(system, job_dir, manifest)
print("STARTING", flush=True)
try:
    report = worker.run()
except ToolError as error:
    print(json.dumps({"ok": False, "code": error.code}), flush=True)
    raise SystemExit(3)
print(json.dumps({"ok": True, "state": report.get("state"),
                  "code": (report.get("original_failure") or {}).get("code")}), flush=True)
raise SystemExit(0 if report.get("state") in ("copied", "succeeded") else 1)
'''


# A ``systemd-run`` stand-in that really starts the shipped worker (as a
# background child) *before* returning, exactly like ``Type=exec``. While the
# submitter still holds the stack lock it probes that lock and records whether
# it was contended, so the test can prove the handoff race was exercised.
FAKE_SYSTEMD_RUN = '''\
#!/usr/bin/env python3
import fcntl
import json
import os
import subprocess
import sys
import time

argv = sys.argv[1:]
index = next(i for i, token in enumerate(argv) if token.endswith("bin/vps3xui-worker"))
worker = argv[index]
rest = argv[index + 1:]
release_dir = rest[rest.index("--release-dir") + 1]
job_dir = rest[-1]

env = dict(os.environ)
child = subprocess.Popen([worker, "--release-dir", release_dir, job_dir], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Type=exec: the unit is "started" once the executable is exec'd, so return
# without waiting for completion. Give the worker a moment to reach the lock.
time.sleep(0.3)

root = os.path.dirname(os.path.dirname(job_dir))
try:
    fd = os.open(os.path.join(root, "lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        contended = False
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        contended = True
    os.close(fd)
except OSError:
    contended = None
with open(os.environ["VPS3XUI_FAKE_LAUNCH_LOG"], "a", encoding="utf-8") as handle:
    handle.write(json.dumps({"worker": worker, "release_dir": release_dir, "job_dir": job_dir,
                             "lock_contended_at_start": contended, "pid": child.pid},
                            sort_keys=True) + "\\n")
raise SystemExit(0)
'''


# ``sitecustomize`` staged in the release directory. The shipped entrypoint puts
# that directory on ``PYTHONPATH``, so this runs first and binds the worker's
# ``RealSystem`` to the synthetic harness instead of the host.
FAKE_SITECUSTOMIZE = '''\
import os
import sys

repo = os.environ["VPS3XUI_REPO_ROOT"]
for path in (repo, os.path.join(repo, "tests")):
    if path not in sys.path:
        sys.path.insert(0, path)

import support
import vps3xui.worker.backup_worker as worker_module
import vps3xui.worker.system as system_module
from vps3xui import manifest as manifest_module

handoff = os.environ.get("VPS3XUI_HANDOFF_SECONDS")
if handoff:
    worker_module.LOCK_HANDOFF_SECONDS = float(handoff)

_JOB_DIR = os.environ["VPS3XUI_FAKE_JOB_DIR"]
_SYSTEM_ROOT = os.environ["VPS3XUI_FAKE_SYSTEM_ROOT"]
_MANIFEST = manifest_module.load(os.path.join(_JOB_DIR, "manifest.json"))


class _SyntheticRealSystem(object):
    def __init__(self, backup_root="/var/backups/vps3xui", release_dir=None):
        self._inner = support.SyntheticSystem(_MANIFEST, _SYSTEM_ROOT)

    def __getattr__(self, name):
        return getattr(self._inner, name)


system_module.RealSystem = _SyntheticRealSystem
'''


def _request(tmp, job_id, manifest, plan):
    return {
        "schema_version": 1,
        "request_id": job_id,
        "job_id": job_id,
        "manifest_id": manifest.manifest_id,
        "manifest_digest": manifest.digest,
        "plan_digest": plan["identity"],
        "machine_id": support.MACHINE_ID,
        "host_key_fingerprint": support.HOST_KEY,
        "backup_dir": os.path.join(tmp, "backups", job_id),
        "release_dir": os.path.join(tmp, "release"),
        "unit_name": "vps3xui-backup-%s" % job_id,
        "stop_containers": plan["stop_containers"],
        "leave_stopped": plan["leave_stopped"],
        "runtime_max_seconds": 900,
        "timeout_stop_seconds": 90,
        "required_bytes_estimate": 5_000_000_000,
    }


class WorkerLockHandoffTest(unittest.TestCase):
    def setUp(self):
        self.tmp = support.temp_state_dir("worker-handoff-")
        self.manifest = support.approved_manifest(self.tmp)
        self.plan = build_plan(self.manifest, Inventory.from_probe(support.synthetic_probe()),
                               support.HOST_KEY)
        self.child_script = os.path.join(self.tmp, "child_worker.py")
        with open(self.child_script, "w", encoding="utf-8") as handle:
            handle.write(CHILD_WORKER)

    def _seed_job(self, job_id):
        job_dir = os.path.join(self.tmp, "jobs", job_id)
        request = _request(self.tmp, job_id, self.manifest, self.plan)
        support.seed_job(job_dir, request, self.plan, self.manifest)
        return job_dir, request

    def _child_env(self, job_id):
        env = dict(os.environ)
        env["VPS3XUI_REPO_ROOT"] = REPO_ROOT
        env["PYTHONPATH"] = os.pathsep.join([REPO_ROOT, TESTS_DIR])
        env["VPS3XUI_FAKE_JOB_DIR"] = os.path.join(self.tmp, "jobs", job_id)
        return env

    def _start_child(self, job_id, handoff, system_root=None):
        argv = [sys.executable, self.child_script, os.path.join(self.tmp, "jobs", job_id),
                str(handoff), system_root or os.path.join(self.tmp, "system")]
        return subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, env=self._child_env(job_id), cwd=REPO_ROOT)

    def _hold_lock(self, root):
        fd = os.open(coord.lock_path(root), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    def _effects_present(self, job_dir, request):
        return (os.path.exists(os.path.join(job_dir, "state.json"))
                or os.path.exists(os.path.join(job_dir, "initial-state.json"))
                or os.path.exists(request["backup_dir"]))

    def _wait_for_state(self, job_dir, states, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with open(os.path.join(job_dir, "state.json"), "r", encoding="utf-8") as handle:
                    state = json.load(handle).get("state")
            except (OSError, ValueError):
                state = None
            if state in states:
                return state
            time.sleep(0.1)
        return None

    # -- bounded wait, then progress -------------------------------------
    def test_worker_waits_for_held_launcher_lock_then_persists_original_state(self):
        job_id = "req-handoff-wait"
        job_dir, request = self._seed_job(job_id)
        root = os.path.dirname(os.path.dirname(job_dir))
        fd = self._hold_lock(root)
        proc = self._start_child(job_id, handoff=60)
        try:
            line = proc.stdout.readline()
            # NOTE: never pass ``proc.stderr.read()`` as an assert message here;
            # it would be evaluated eagerly and block until the child exits.
            self.assertEqual(line.strip(), "STARTING")
            # Give the child time to reach the flock and block on it.
            time.sleep(1.0)
            self.assertIsNone(proc.poll(), "worker exited before the launcher released the lock")
            self.assertFalse(self._effects_present(job_dir, request),
                             "the worker produced effects while the lock was still held")
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        stdout, stderr = proc.communicate(timeout=120)
        self.assertEqual(proc.returncode, 0, stdout + stderr)
        result = json.loads(stdout.splitlines()[-1])
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["state"], "copied", result)
        self.assertIsNone(result["code"], result)
        with open(os.path.join(job_dir, "initial-state.json"), "r", encoding="utf-8") as handle:
            initial = json.load(handle)
        self.assertEqual([item["id"] for item in initial["stop_containers"]],
                         [item["id"] for item in request["stop_containers"]])
        self.assertEqual(initial["machine_id"], support.MACHINE_ID)
        report = support.read_json_file(os.path.join(job_dir, "report.json"))
        self.assertEqual(report["state"], "copied")

    def test_bounded_handoff_times_out_cleanly_without_effects(self):
        job_id = "req-handoff-timeout"
        job_dir, request = self._seed_job(job_id)
        root = os.path.dirname(os.path.dirname(job_dir))
        fd = self._hold_lock(root)
        try:
            started = time.monotonic()
            proc = self._start_child(job_id, handoff=1.0)
            stdout, stderr = proc.communicate(timeout=60)
            elapsed = time.monotonic() - started
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        self.assertNotEqual(proc.returncode, 0, stdout + stderr)
        self.assertIn("E_LOCKED", stdout.splitlines()[-1], stdout + stderr)
        # The wait was exercised (bounded, not instant) but still finite.
        self.assertGreaterEqual(elapsed, 0.9, "the handoff bound was not honoured")
        self.assertLess(elapsed, 30, "the handoff wait was not bounded")
        self.assertFalse(self._effects_present(job_dir, request),
                         "a lock timeout must not leave any effects")

    # -- ownership-aware rejection ---------------------------------------
    def test_worker_without_reservation_is_rejected_without_waiting(self):
        job_id = "req-no-reservation"
        job_dir = os.path.join(self.tmp, "jobs", job_id)
        request = _request(self.tmp, job_id, self.manifest, self.plan)
        coord.require_private_dir(job_dir, 0o700)
        coord.replace_json(os.path.join(job_dir, coord.REQUEST_FILE), request)
        coord.replace_json(os.path.join(job_dir, coord.PLAN_FILE), self.plan)
        coord.replace_json(os.path.join(job_dir, coord.MANIFEST_FILE), self.manifest.data)
        started = time.monotonic()
        proc = self._start_child(job_id, handoff=30)
        stdout, stderr = proc.communicate(timeout=60)
        elapsed = time.monotonic() - started
        self.assertNotEqual(proc.returncode, 0, stdout + stderr)
        self.assertIn("E_NOT_OWNED", stdout.splitlines()[-1], stdout + stderr)
        self.assertLess(elapsed, 15, "an unowned worker must not wait for the lock")
        self.assertFalse(self._effects_present(job_dir, request))

    def test_worker_with_mismatched_reservation_is_rejected_without_waiting(self):
        job_id = "req-wrong-owner"
        job_dir, request = self._seed_job(job_id)
        coord.replace_json(os.path.join(job_dir, coord.RESERVATION_FILE), {
            "schema_version": coord.RESERVATION_SCHEMA_VERSION,
            "job_id": job_id,
            "plan_digest": "a-different-plan",
            "manifest_id": self.manifest.manifest_id,
        })
        started = time.monotonic()
        proc = self._start_child(job_id, handoff=30)
        stdout, stderr = proc.communicate(timeout=60)
        elapsed = time.monotonic() - started
        self.assertNotEqual(proc.returncode, 0, stdout + stderr)
        self.assertIn("E_NOT_OWNED", stdout.splitlines()[-1], stdout + stderr)
        self.assertLess(elapsed, 15, "a mismatched owner must not wait for the lock")
        self.assertFalse(self._effects_present(job_dir, request))

    def test_other_incomplete_job_blocks_owned_worker(self):
        job_id = "req-owned"
        job_dir, request = self._seed_job(job_id)
        other_dir = os.path.join(self.tmp, "jobs", "req-other")
        coord.require_private_dir(other_dir, 0o700)
        coord.replace_json(os.path.join(other_dir, coord.STATE_FILE), {"state": "copying"})
        proc = self._start_child(job_id, handoff=30)
        stdout, stderr = proc.communicate(timeout=60)
        self.assertNotEqual(proc.returncode, 0, stdout + stderr)
        self.assertIn("E_JOB_INCOMPLETE", stdout.splitlines()[-1], stdout + stderr)
        self.assertFalse(self._effects_present(job_dir, request))

    # -- assembled path: submitter holds the lock while the launcher starts --
    def test_generated_launcher_starts_worker_under_the_submitter_lock(self):
        job_id = "req-assembled"
        job_dir = os.path.join(self.tmp, "jobs", job_id)
        release_dir = os.path.join(self.tmp, "release")
        self._stage_release(release_dir)
        fake_bin = os.path.join(self.tmp, "fakebin")
        launch_log = os.path.join(self.tmp, "launch.jsonl")
        self._install_fake_systemd_run(fake_bin, launch_log)

        payload = {
            "job_id": job_id,
            "request": dict(_request(self.tmp, job_id, self.manifest, self.plan),
                            manifest=self.manifest.data),
            "plan": self.plan,
            "launch": {
                "unit_name": "vps3xui-backup-%s" % job_id,
                "release_dir": release_dir,
                "job_dir": job_dir,
                "runtime_max_seconds": 900,
                "timeout_stop_seconds": 90,
            },
        }
        token = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        env = dict(os.environ)
        env["PATH"] = fake_bin + os.pathsep + env.get("PATH", "")
        env["PYTHONPATH"] = os.pathsep.join([REPO_ROOT, TESTS_DIR])
        env["VPS3XUI_FAKE_LAUNCH_LOG"] = launch_log
        env["VPS3XUI_REPO_ROOT"] = REPO_ROOT
        env["VPS3XUI_FAKE_JOB_DIR"] = job_dir
        env["VPS3XUI_FAKE_SYSTEM_ROOT"] = os.path.join(self.tmp, "system")
        env["VPS3XUI_HANDOFF_SECONDS"] = "60"
        proc = subprocess.run([sys.executable, "-m", "vps3xui.remote_ops", self.tmp,
                               "reserve-and-launch", token],
                              cwd=REPO_ROOT, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=120)
        result = json.loads(proc.stdout.decode("utf-8"))
        self.assertTrue(result.get("ok"), proc.stdout.decode("utf-8") + proc.stderr.decode("utf-8"))
        self.assertTrue(result.get("reserved"), result)

        # The launcher observed the submitter still holding the lock as it started
        # the worker, i.e. the handoff race really happened.
        with open(launch_log, "r", encoding="utf-8") as handle:
            calls = [json.loads(line) for line in handle.read().splitlines() if line]
        self.assertEqual(len(calls), 1, calls)
        self.assertTrue(calls[0]["lock_contended_at_start"], calls)

        state = self._wait_for_state(job_dir, ("copied", "succeeded"), timeout=90)
        self.assertEqual(state, "copied", state)
        marker = support.read_json_file(os.path.join(job_dir, "launched.json"))
        self.assertEqual(marker["phase"], "launched")
        self.assertTrue(os.path.isfile(os.path.join(job_dir, "initial-state.json")))

    # -- fixtures ---------------------------------------------------------
    def _stage_release(self, release_dir):
        bindir = os.path.join(release_dir, "bin")
        os.makedirs(bindir, mode=0o700)
        entrypoint = os.path.join(release_dir, WORKER_ENTRYPOINT)
        shutil.copyfile(os.path.join(REPO_ROOT, WORKER_ENTRYPOINT), entrypoint)
        os.chmod(entrypoint, 0o755)
        with open(os.path.join(release_dir, "sitecustomize.py"), "w",
                  encoding="utf-8") as handle:
            handle.write(FAKE_SITECUSTOMIZE)

    def _install_fake_systemd_run(self, fake_bin, launch_log):
        os.makedirs(fake_bin, mode=0o700)
        binary = os.path.join(fake_bin, "systemd-run")
        with open(binary, "w", encoding="utf-8") as handle:
            handle.write(FAKE_SYSTEMD_RUN)
        os.chmod(binary, 0o755)


if __name__ == "__main__":
    unittest.main()
