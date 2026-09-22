"""File-safety primitives and no-follow behaviour (REVIEW-2 item 9)."""

import os
import tempfile
import unittest
from unittest import mock

from vps3xui import coordination as coord
from vps3xui.adapters import ssh as ssh_adapter
from vps3xui.errors import ToolError
from vps3xui.util import atomic_write_bytes, ensure_dir, require_private_dir, write_json
from vps3xui.worker.jobctx import JobContext


class DirectorySafetyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="file-safety-")

    def test_ensure_dir_refuses_a_symlink_ancestor(self):
        real = os.path.join(self.tmp, "real")
        os.makedirs(real)
        link = os.path.join(self.tmp, "link")
        os.symlink(real, link)
        with self.assertRaises(ToolError) as ctx:
            ensure_dir(os.path.join(link, "child"), 0o700)
        self.assertEqual(ctx.exception.code, "E_UNSAFE_PATH")
        self.assertFalse(os.path.exists(os.path.join(real, "child")))

    def test_ensure_dir_refuses_a_final_symlink(self):
        real = os.path.join(self.tmp, "real")
        os.makedirs(real)
        os.chmod(real, 0o755)
        link = os.path.join(self.tmp, "link")
        os.symlink(real, link)
        with self.assertRaises(ToolError) as ctx:
            ensure_dir(link, 0o700)
        self.assertEqual(ctx.exception.code, "E_UNSAFE_PATH")
        self.assertEqual(os.stat(real).st_mode & 0o777, 0o755)

    def test_ensure_dir_preserves_existing_directory_modes(self):
        for mode in (0o755, 0o751):
            parent = os.path.join(self.tmp, "existing-%03o" % mode)
            os.makedirs(parent)
            os.chmod(parent, mode)
            ensure_dir(parent, 0o700)
            self.assertEqual(os.stat(parent).st_mode & 0o777, mode)

    def test_ensure_dir_sets_only_newly_created_components_to_requested_mode(self):
        parent = os.path.join(self.tmp, "cwd")
        os.makedirs(parent)
        os.chmod(parent, 0o755)
        target = os.path.join(parent, "state")
        old_umask = os.umask(0o077)
        try:
            ensure_dir(target, 0o750)
        finally:
            os.umask(old_umask)
        self.assertEqual(os.stat(parent).st_mode & 0o777, 0o755)
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o750)

    def test_ensure_dir_does_not_chmod_a_raced_in_directory(self):
        target = os.path.join(self.tmp, "raced")
        real_mkdir = os.mkdir

        def racing_mkdir(path, mode=0o777):
            real_mkdir(path, mode)
            os.chmod(path, 0o755)
            raise FileExistsError(path)

        with mock.patch.object(coord.os, "mkdir", side_effect=racing_mkdir):
            ensure_dir(target, 0o700)
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o755)

    def test_require_private_dir_sets_mode_and_checks_owner(self):
        target = os.path.join(self.tmp, "private")
        require_private_dir(target, 0o700)
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o700)

    def test_require_private_dir_enforces_mode_on_an_existing_tool_directory(self):
        target = os.path.join(self.tmp, "existing-private")
        os.makedirs(target)
        os.chmod(target, 0o755)
        require_private_dir(target, 0o700)
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o700)

    def test_require_private_dir_refuses_a_symlink(self):
        real = os.path.join(self.tmp, "real-private")
        os.makedirs(real)
        link = os.path.join(self.tmp, "link-private")
        os.symlink(real, link)
        with self.assertRaises(ToolError) as ctx:
            require_private_dir(link, 0o700)
        self.assertEqual(ctx.exception.code, "E_UNSAFE_PATH")

    def test_require_private_dir_checks_ownership_before_chmod(self):
        target = os.path.join(self.tmp, "foreign")
        os.makedirs(target)
        os.chmod(target, 0o755)
        with mock.patch.object(coord.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(ToolError) as ctx:
                require_private_dir(target, 0o700)
        self.assertEqual(ctx.exception.code, "E_STATE_WRITE_FAILED")
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o755)

    def test_stack_lock_refuses_a_symlinked_lock_path(self):
        root = os.path.join(self.tmp, "state")
        require_private_dir(root, 0o700)
        victim = os.path.join(self.tmp, "victim")
        with open(victim, "w", encoding="utf-8") as handle:
            handle.write("x")
        os.symlink(victim, os.path.join(root, "lock"))
        with self.assertRaises(ToolError) as ctx:
            with coord.stack_lock(root):
                pass
        self.assertEqual(ctx.exception.code, "E_UNSAFE_PATH")

    def test_fsync_dir_fails_on_a_missing_directory(self):
        with self.assertRaises(ToolError) as ctx:
            coord.fsync_dir(os.path.join(self.tmp, "does-not-exist"))
        self.assertEqual(ctx.exception.code, "E_STATE_WRITE_FAILED")


class FileCreationSafetyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="file-create-")

    def test_atomic_write_bytes_creates_0600_and_refuses_symlink(self):
        target = os.path.join(self.tmp, "state.json")
        atomic_write_bytes(target, b"{}\n")
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)
        link = os.path.join(self.tmp, "link.json")
        os.symlink(target, link)
        with self.assertRaises(ToolError) as ctx:
            atomic_write_bytes(link, b"x")
        self.assertEqual(ctx.exception.code, "E_UNSAFE_PATH")

    def test_write_json_preserves_an_existing_general_parent_mode(self):
        parent = os.path.join(self.tmp, "cwd")
        os.makedirs(parent)
        os.chmod(parent, 0o755)
        target = os.path.join(parent, "output.json")
        write_json(target, {"ok": True})
        self.assertEqual(os.stat(parent).st_mode & 0o777, 0o755)
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)

    def test_write_exclusive_creates_0600_and_refuses_overwrite(self):
        target = os.path.join(self.tmp, "reserve.json")
        coord.write_exclusive(target, {"a": 1})
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)
        with self.assertRaises(ToolError) as ctx:
            coord.write_exclusive(target, {"a": 2})
        self.assertEqual(ctx.exception.code, "E_PRECONDITION")

    def test_read_json_nofollow_rejects_a_symlink(self):
        real = os.path.join(self.tmp, "real.json")
        with open(real, "w", encoding="utf-8") as handle:
            handle.write("{}")
        link = os.path.join(self.tmp, "link.json")
        os.symlink(real, link)
        with self.assertRaises(ValueError):
            coord.read_json_nofollow(link)

    def test_job_context_creates_a_private_directory(self):
        job_dir = os.path.join(self.tmp, "jobs", "req-x")
        JobContext(job_dir)
        self.assertEqual(os.stat(job_dir).st_mode & 0o777, 0o700)

    def test_fetch_to_refuses_existing_and_symlinked_destinations(self):
        transport = ssh_adapter.SshTransport("vps-3xui")
        pin = {"file": "/tmp/known_hosts", "known_hosts_source": "/tmp/kh",
               "keytype": "ssh-ed25519", "key": "AAA", "fingerprint": "SHA256:x",
               "hostname": "example.test", "port": "22", "user": "root"}
        existing = os.path.join(self.tmp, "existing.tar")
        with open(existing, "wb") as handle:
            handle.write(b"keep")
        with mock.patch.object(ssh_adapter.SshTransport, "host_key_pin", lambda self: pin):
            with self.assertRaises(ToolError) as ctx:
                transport.fetch_to("/remote/artifact.tar", existing)
            self.assertEqual(ctx.exception.code, "E_PRECONDITION")
            with open(existing, "rb") as handle:
                self.assertEqual(handle.read(), b"keep")
            victim = os.path.join(self.tmp, "victim")
            with open(victim, "wb") as handle:
                handle.write(b"victim")
            link = os.path.join(self.tmp, "link.tar")
            os.symlink(victim, link)
            with self.assertRaises(ToolError):
                transport.fetch_to("/remote/artifact.tar", link)
            with open(victim, "rb") as handle:
                self.assertEqual(handle.read(), b"victim")


if __name__ == "__main__":
    unittest.main()
