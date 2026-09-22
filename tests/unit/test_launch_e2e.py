"""End-to-end launch and release-install tests (REVIEW-2 items 1 and 6).

``RemoteHostOps`` ships the reviewed coordination module over the transport and
executes it as a *real* child process. Here the transport's ``run_raw`` is bound
to a local ``sh -c`` so the shipped ``vps3xui/remote_ops.py`` (with
``coordination.py`` concatenated, exactly as delivered) runs for real, and its
``systemd-run`` call lands on a fake executable on ``PATH`` that records argv.
Nothing here mocks the launch protocol or the install shell.
"""

import os
import subprocess
import sys
import tempfile
import unittest

import support
from vps3xui.adapters.ssh import CommandResult, RemoteHostOps
from vps3xui.errors import ToolError
from vps3xui.inventory import Inventory
from vps3xui.plan import build_plan


class LocalRemoteHostOps(RemoteHostOps):
    """A ``RemoteHostOps`` whose transport executes commands locally."""

    def __init__(self, alias, fake_bin, launch_log, systemd_rc=None):
        super(LocalRemoteHostOps, self).__init__(alias)
        self._fake_bin = fake_bin
        self._launch_log = launch_log
        self._systemd_rc = systemd_rc

    def run_raw(self, command, stdin_bytes=None, timeout=60, max_stdout=8 * 1024 * 1024):
        if command.startswith("command -v python3"):
            return CommandResult(0, b"/usr/bin/python3\n", b"")
        env = dict(os.environ)
        env["PATH"] = self._fake_bin + os.pathsep + env.get("PATH", "")
        env["VPS3XUI_FAKE_LAUNCH_LOG"] = self._launch_log
        if self._systemd_rc is not None:
            env["VPS3XUI_FAKE_SYSTEMD_RC"] = str(self._systemd_rc)
        proc = subprocess.run(["sh", "-c", command], input=stdin_bytes,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=env, timeout=timeout)
        return CommandResult(proc.returncode, proc.stdout[:max_stdout], proc.stderr[:4096])


def _launch_metadata(root, job_id, unit="vps3xui-backup-req-launch"):
    return {
        "unit_name": unit,
        "release_dir": os.path.join(root, "release"),
        "job_dir": os.path.join(root, "jobs", job_id),
        "runtime_max_seconds": 900,
        "timeout_stop_seconds": 90,
    }


class LaunchE2ETest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="launch-e2e-")
        self.manifest = support.approved_manifest(self.tmp)
        inventory = Inventory.from_probe(support.synthetic_probe())
        self.plan = build_plan(self.manifest, inventory, support.HOST_KEY)
        self.fake_bin = os.path.join(self.tmp, "fakebin")
        self.log = os.path.join(self.tmp, "launch.log")
        support.install_fake_systemd_run(self.fake_bin, self.log)

    def _host(self, root, systemd_rc=None):
        return LocalRemoteHostOps("vps-3xui", self.fake_bin, self.log, systemd_rc=systemd_rc)

    def _payload(self, root, job_id):
        request = {
            "schema_version": 1,
            "request_id": job_id,
            "job_id": job_id,
            "manifest_id": self.manifest.manifest_id,
            "manifest_digest": self.manifest.digest,
            "manifest": self.manifest.data,
            "plan_digest": self.plan["identity"],
            "machine_id": support.MACHINE_ID,
            "host_key_fingerprint": support.HOST_KEY,
            "backup_dir": os.path.join(root, "backups", job_id),
            "release_dir": os.path.join(root, "release"),
            "unit_name": "vps3xui-backup-%s" % job_id,
            "stop_containers": self.plan["stop_containers"],
            "leave_stopped": self.plan["leave_stopped"],
            "runtime_max_seconds": 900,
            "timeout_stop_seconds": 90,
            "required_bytes_estimate": 5_000_000_000,
        }
        return request

    def test_remote_launch_actually_invokes_systemd_run(self):
        root = os.path.join(self.tmp, "state")
        job_id = "req-launch-1"
        host = self._host(root)
        result = host.reserve_and_launch(
            root, os.path.join(root, "jobs", job_id), self._payload(root, job_id),
            self.plan, _launch_metadata(root, job_id),
        )
        self.assertTrue(result.get("ok"), result)
        self.assertTrue(result.get("reserved"))
        calls = support.read_launch_log(self.log)
        self.assertEqual(len(calls), 1, calls)
        argv = calls[0]
        self.assertTrue(argv[0].endswith("systemd-run"), argv[0])
        self.assertIn("--unit=vps3xui-backup-req-launch", argv)
        self.assertIn("--property=Type=exec", argv)
        self.assertIn("--property=RuntimeMaxSec=900", argv)
        self.assertIn("--property=TimeoutStopSec=90", argv)
        self.assertTrue(any(tok.endswith("bin/vps3xui-worker") for tok in argv), argv)
        self.assertEqual(argv[-1], os.path.join(root, "jobs", job_id))
        # The durable launch marker records a confirmed launch.
        marker = support.read_json_file(os.path.join(root, "jobs", job_id, "launched.json"))
        self.assertEqual(marker["phase"], "launched")

    def test_retry_after_launch_does_not_launch_a_second_unit(self):
        root = os.path.join(self.tmp, "state")
        job_id = "req-launch-2"
        host = self._host(root)
        payload = self._payload(root, job_id)
        host.reserve_and_launch(root, os.path.join(root, "jobs", job_id), payload,
                                self.plan, _launch_metadata(root, job_id))
        second = host.reserve_and_launch(root, os.path.join(root, "jobs", job_id), payload,
                                         self.plan, _launch_metadata(root, job_id))
        self.assertTrue(second.get("existing"))
        self.assertFalse(second.get("reserved"))
        self.assertEqual(len(support.read_launch_log(self.log)), 1)

    def test_failed_launch_error_surfaces_and_never_retries(self):
        root = os.path.join(self.tmp, "state")
        job_id = "req-launch-fail"
        host = self._host(root, systemd_rc=1)
        payload = self._payload(root, job_id)
        with self.assertRaises(ToolError) as ctx:
            host.reserve_and_launch(root, os.path.join(root, "jobs", job_id), payload,
                                    self.plan, _launch_metadata(root, job_id))
        self.assertEqual(ctx.exception.code, "E_EXECUTION")
        marker = support.read_json_file(os.path.join(root, "jobs", job_id, "launched.json"))
        self.assertEqual(marker["phase"], "pending")
        # A retry must not launch a second unit for an unconfirmed launch.
        result = self._host(root).reserve_and_launch(
            root, os.path.join(root, "jobs", job_id), payload, self.plan,
            _launch_metadata(root, job_id),
        )
        self.assertNotEqual(result.get("state"), "accepted")
        self.assertEqual(len(support.read_launch_log(self.log)), 1)

    def test_reserve_only_does_not_launch(self):
        root = os.path.join(self.tmp, "state")
        job_id = "req-reserve-only"
        host = self._host(root)
        result = host.reserve_and_launch(
            root, os.path.join(root, "jobs", job_id), self._payload(root, job_id),
            self.plan, {},
        )
        self.assertTrue(result.get("reserved"))
        self.assertEqual(support.read_launch_log(self.log), [])


class ReleaseInstallTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="release-install-")
        self.manifest = support.approved_manifest(self.tmp)
        self.fake_bin = os.path.join(self.tmp, "fakebin")
        self.log = os.path.join(self.tmp, "launch.log")
        support.install_fake_systemd_run(self.fake_bin, self.log)
        self.host = LocalRemoteHostOps("vps-3xui", self.fake_bin, self.log)

    def _archive(self):
        from vps3xui.release import build_release_archive, release_archive_digest

        archive = build_release_archive(self.manifest)
        return archive, release_archive_digest(archive)

    def test_install_helper_runs_for_real_and_is_idempotent(self):
        archive, digest = self._archive()
        release_dir = os.path.join(self.tmp, "opt", "vps3xui", "releases", "1.0.0-test")
        got = self.host.ensure_release(release_dir, archive)
        self.assertEqual(got, digest)
        for marker in (".digest", ".files", "RELEASE"):
            self.assertTrue(os.path.isfile(os.path.join(release_dir, marker)), marker)
        with open(os.path.join(release_dir, ".digest"), "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read().strip(), digest)
        # The received archive's contents are verified against the map on reuse.
        self.assertEqual(self.host.ensure_release(release_dir, archive), digest)

    def test_install_helper_rejects_a_corrupted_received_archive(self):
        archive, _digest = self._archive()
        release_dir = os.path.join(self.tmp, "opt", "vps3xui", "releases", "1.0.0-corrupt")

        def corrupt_write(remote_path, data, mode=0o600):
            os.makedirs(os.path.dirname(remote_path), exist_ok=True)
            with open(remote_path, "wb") as handle:
                handle.write(b"not the archive")

        self.host.write_file = corrupt_write  # type: ignore[assignment]
        with self.assertRaises(ToolError) as ctx:
            self.host.ensure_release(release_dir, archive)
        self.assertEqual(ctx.exception.code, "E_EXECUTION")
        self.assertFalse(os.path.exists(release_dir))

    def test_install_helper_refuses_a_different_archive_at_same_path(self):
        archive, digest = self._archive()
        release_dir = os.path.join(self.tmp, "opt", "vps3xui", "releases", "1.0.0-other")
        self.host.ensure_release(release_dir, archive)
        other = support.approved_manifest(tempfile.mkdtemp(prefix="release-other-"),
                                          approval_note="a different approved inventory")
        from vps3xui.release import build_release_archive

        with self.assertRaises(ToolError) as ctx:
            self.host.ensure_release(release_dir, build_release_archive(other))
        self.assertEqual(ctx.exception.code, "E_EXECUTION")


if __name__ == "__main__":
    unittest.main()
