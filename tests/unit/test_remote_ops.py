"""Subprocess-level tests for the host stack lock (``vps3xui.remote_ops``).

These do not mock anything: they run the shipped module as a real child
process against a temp root, so the flock, the durable reservation and the
crash-window behaviour are exercised at the actual boundary.
"""

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REMOTE_OPS = os.path.join(REPO_ROOT, "vps3xui", "remote_ops.py")


def run_ops(root, command, *args, stdin=None, env=None):
    argv = [sys.executable, REMOTE_OPS, root, command] + list(args)
    result = subprocess.run(argv, input=stdin, capture_output=True, timeout=60, env=env)
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
    except ValueError:
        payload = None
    return result.returncode, payload


def reserve(root, job_id, plan_digest="d1", manifest_id="m1"):
    payload = {
        "job_id": job_id,
        "request": {"job_id": job_id, "plan_digest": plan_digest,
                    "manifest_id": manifest_id,
                    "unit_name": "vps3xui-backup-%s" % job_id,
                    "release_dir": "/opt/vps3xui/releases/test"},
        "plan": {"identity": plan_digest},
        "launch": {},
    }
    token = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    return run_ops(root, "reserve-and-launch", token)


class RemoteOpsLockTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="remote-ops-")

    def test_incomplete_job_blocks_a_new_job(self):
        code, payload = reserve(self.root, "req-a")
        self.assertEqual(code, 0)
        self.assertTrue(payload["reserved"])
        code, payload = reserve(self.root, "req-b")
        self.assertEqual(code, 3)
        self.assertEqual(payload["error"]["code"], "E_JOB_INCOMPLETE")
        self.assertEqual(payload["error"]["resource"], "req-a")

    def test_same_request_id_and_plan_resolves(self):
        reserve(self.root, "req-a")
        code, payload = reserve(self.root, "req-a")
        self.assertEqual(code, 0)
        self.assertFalse(payload["reserved"])
        self.assertTrue(payload["existing"])

    def test_same_request_id_different_plan_conflicts(self):
        reserve(self.root, "req-a", plan_digest="d1")
        code, payload = reserve(self.root, "req-a", plan_digest="d2")
        self.assertEqual(code, 3)
        self.assertEqual(payload["error"]["code"], "E_REQUEST_ID_CONFLICT")

    def test_corrupt_state_is_unknown_not_absent(self):
        reserve(self.root, "req-a")
        job_dir = os.path.join(self.root, "jobs", "req-a")
        with open(os.path.join(job_dir, "state.json"), "w", encoding="utf-8") as handle:
            handle.write("{ not json")
        code, payload = run_ops(self.root, "status", "req-a")
        self.assertEqual(code, 0)
        self.assertEqual(payload["state"], "unknown")
        self.assertEqual(payload["evidence"], "corrupt_state")
        self.assertFalse(payload["operation_complete"])
        code, payload = run_ops(self.root, "blocking")
        self.assertEqual([item["job_id"] for item in payload["blocking"]], ["req-a"])

    def test_failed_job_without_complete_does_not_block(self):
        reserve(self.root, "req-a")
        job_dir = os.path.join(self.root, "jobs", "req-a")
        with open(os.path.join(job_dir, "state.json"), "w", encoding="utf-8") as handle:
            json.dump({"state": "failed"}, handle)
        code, payload = reserve(self.root, "req-b")
        self.assertEqual(code, 0)
        self.assertTrue(payload["reserved"])

    def test_parallel_reservations_serialize_to_one_winner(self):
        procs = []
        for index in range(8):
            payload = {
                "job_id": "req-%d" % index,
                "request": {"job_id": "req-%d" % index, "plan_digest": "d", "manifest_id": "m"},
                "plan": {"identity": "d"},
                "launch": {},
            }
            token = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
            procs.append(subprocess.Popen(
                [sys.executable, REMOTE_OPS, self.root, "reserve-and-launch", token],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ))
        results = []
        for proc in procs:
            out, _err = proc.communicate(timeout=60)
            results.append((proc.returncode, json.loads(out.decode("utf-8"))))
        winners = [payload for code, payload in results if code == 0 and payload.get("reserved")]
        # A loser either observes the winner's incomplete reservation or loses
        # the (non-blocking) host lock race; both mean it did NOT create a job.
        blocked = [payload for code, payload in results
                   if code == 3 and payload["error"]["code"] in
                   ("E_JOB_INCOMPLETE", "E_LOCKED")]
        self.assertEqual(len(winners), 1, results)
        self.assertEqual(len(blocked), 7, results)


FAKE_SYSTEMCTL = """#!/bin/sh
if [ "$1" = "is-active" ]; then
  echo "${VPS3XUI_FAKE_ACTIVE:-inactive}"
  exit "${VPS3XUI_FAKE_ACTIVE_RC:-0}"
fi
exit 0
"""

FAKE_SYSTEMD_RUN = """#!/bin/sh
{
  printf '%s\n' "$0"
  for a in "$@"; do printf '%s\n' "$a"; done
  printf '%s\n' '---END---'
} >> "$VPS3XUI_FAKE_LAUNCH_LOG"
exit 0
"""


def _fake_bin(directory, launch_log):
    os.makedirs(directory, exist_ok=True)
    for name, body in (("systemd-run", FAKE_SYSTEMD_RUN), ("systemctl", FAKE_SYSTEMCTL)):
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(body)
        os.chmod(path, 0o755)
    return launch_log


def _launch_env(fake_bin, launch_log, **extra):
    env = dict(os.environ)
    env["PATH"] = fake_bin + os.pathsep + env.get("PATH", "")
    env["VPS3XUI_FAKE_LAUNCH_LOG"] = launch_log
    env.update(extra)
    return env


class RemoteOpsLockHoldTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="remote-ops-hold-")
        self.fake_bin = os.path.join(self.root, "fakebin")
        self.launch_log = os.path.join(self.root, "launch.log")
        _fake_bin(self.fake_bin, self.launch_log)

    def test_held_stack_lock_blocks_new_job_and_recover(self):
        import fcntl
        reserve(self.root, "req-held")
        lock_path = os.path.join(self.root, "lock")
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            code, payload = reserve(self.root, "req-blocked")
            self.assertEqual(code, 3)
            self.assertEqual(payload["error"]["code"], "E_LOCKED")
            code, payload = run_ops(self.root, "recover", "req-held")
            self.assertEqual(code, 3)
            self.assertEqual(payload["error"]["code"], "E_LOCKED")
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def test_dead_worker_with_incomplete_reservation_blocks_new_job(self):
        reserve(self.root, "req-dead")
        job_dir = os.path.join(self.root, "jobs", "req-dead")
        with open(os.path.join(job_dir, "state.json"), "w", encoding="utf-8") as handle:
            json.dump({"state": "copying"}, handle)
        with open(os.path.join(job_dir, "launched.json"), "w", encoding="utf-8") as handle:
            json.dump({"job_id": "req-dead", "unit_name": "vps3xui-backup-req-dead",
                       "phase": "launched", "boot_id": None}, handle)
        code, payload = reserve(self.root, "req-new")
        self.assertEqual(code, 3)
        self.assertEqual(payload["error"]["code"], "E_JOB_INCOMPLETE")
        self.assertEqual(payload["error"]["resource"], "req-dead")

    def test_same_job_recover_launches_a_recover_unit(self):
        reserve(self.root, "req-rec")
        env = _launch_env(self.fake_bin, self.launch_log)
        code, payload = run_ops(self.root, "recover", "req-rec", env=env)
        self.assertEqual(code, 0, payload)
        self.assertTrue(payload["recovered"])
        with open(self.launch_log, "r", encoding="utf-8") as handle:
            log = handle.read()
        self.assertIn("vps3xui-recover-req-rec", log)
        self.assertIn("--no-block", log)
        self.assertIn("--recover", log)

    def test_recover_refuses_a_live_unit(self):
        reserve(self.root, "req-live")
        env = _launch_env(self.fake_bin, self.launch_log,
                          VPS3XUI_FAKE_ACTIVE="active", VPS3XUI_FAKE_ACTIVE_RC="0")
        code, payload = run_ops(self.root, "recover", "req-live", env=env)
        self.assertEqual(code, 3)
        self.assertEqual(payload["error"]["code"], "E_UNIT_BUSY")


if __name__ == "__main__":
    unittest.main()
