import base64
import hashlib
import os
import tempfile
import unittest
from unittest import mock

from vps3xui.adapters import ssh as ssh_adapter
from vps3xui.errors import ToolError


KEY_B64 = "AAAABBBB"
RESOLVED = "hostname example.test\nport 22\nuser root\nuserknownhostsfile %s\n"


def expected_fingerprint(key_b64):
    digest = hashlib.sha256(base64.b64decode(key_b64)).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def bound_run(known_hosts, inner):
    """Wrap an inner fake_run, answering the local binding calls first."""
    def fake_run(argv, **kwargs):
        if argv[:2] == ["ssh", "-G"]:
            return mock.Mock(returncode=0, stdout=(RESOLVED % known_hosts).encode(), stderr=b"")
        if argv and argv[0] == "ssh-keygen":
            return mock.Mock(returncode=0,
                             stdout=("example.test ssh-ed25519 %s\n" % KEY_B64).encode(),
                             stderr=b"")
        return inner(argv, **kwargs)
    return fake_run


class SshTransportTest(unittest.TestCase):
    def test_alias_validation(self):
        self.assertEqual(ssh_adapter.validate_alias("vps-3xui"), "vps-3xui")
        for bad in ["../evil", "a b", "-oProxyCommand=x", "", "x;y"]:
            with self.assertRaises(ToolError):
                ssh_adapter.validate_alias(bad)

    def test_required_ssh_hardening_options_are_always_present(self):
        joined = " ".join(ssh_adapter.SSH_OPTIONS)
        self.assertIn("StrictHostKeyChecking=yes", joined)
        self.assertIn("BatchMode=yes", joined)
        self.assertIn("ControlMaster=no", joined)
        self.assertIn("ControlPath=none", joined)
        self.assertIn("UpdateHostKeys=no", joined)

    def test_run_builds_hardened_command_and_keeps_stderr_bounded(self):
        transport = ssh_adapter.SshTransport("vps-3xui")
        captured = {}
        captured_calls = []

        def inner(argv, **kwargs):
            captured_calls.append(argv)
            captured["argv"] = argv
            captured["input"] = kwargs.get("input")
            return mock.Mock(returncode=0, stdout=b"ok\n", stderr=b"secret-stderr" * 100)

        with mock.patch("os.path.isfile", return_value=True), \
                mock.patch("subprocess.run", side_effect=bound_run("/etc/known_hosts", inner)):
            result = transport.run(["docker", "ps", "-a"])
        self.assertTrue(result.ok)
        self.assertIn("StrictHostKeyChecking=yes", captured["argv"])
        self.assertEqual(captured["argv"][-1], "'docker' 'ps' '-a'")
        self.assertNotIn("secret", result.text())
        self.assertNotIn("secret", result.safe_summary())
        self.assertGreater(result.stderr_len, 0)
        self.assertTrue(result.stderr_digest)

    def test_host_key_fingerprint_from_known_hosts(self):
        tmp = tempfile.mkdtemp(prefix="known-")
        known_hosts = os.path.join(tmp, "known_hosts")
        with open(known_hosts, "w", encoding="utf-8") as handle:
            handle.write("example ssh-ed25519 AAAABBBB\n")
        transport = ssh_adapter.SshTransport("vps-3xui")
        ssh_g = "hostname example.test\nport 22\nuserknownhostsfile %s\n" % known_hosts

        def fake_run(argv, **kwargs):
            if argv[:2] == ["ssh", "-G"]:
                return mock.Mock(returncode=0, stdout=ssh_g.encode(), stderr=b"")
            if argv and argv[0] == "ssh-keygen":
                return mock.Mock(
                    returncode=0,
                    stdout=("# Host example.test found\nexample.test ssh-ed25519 %s\n" % KEY_B64).encode(),
                    stderr=b"",
                )
            return mock.Mock(returncode=1, stdout=b"", stderr=b"")

        with mock.patch("subprocess.run", side_effect=fake_run):
            self.assertEqual(transport.host_key_fingerprint(), expected_fingerprint(KEY_B64))

    def test_unknown_host_key_is_reported(self):
        transport = ssh_adapter.SshTransport("vps-3xui")
        ssh_g = "hostname example.test\nport 22\nuserknownhostsfile /nonexistent\n"

        def fake_run(argv, **kwargs):
            if argv[:2] == ["ssh", "-G"]:
                return mock.Mock(returncode=0, stdout=ssh_g.encode(), stderr=b"")
            return mock.Mock(returncode=1, stdout=b"", stderr=b"")

        with mock.patch("subprocess.run", side_effect=fake_run):
            with self.assertRaises(ToolError) as caught:
                transport.host_key_fingerprint()
        self.assertEqual(caught.exception.code, "E_HOST_KEY_UNKNOWN")

    def test_fetch_to_writes_file_without_printing(self):
        transport = ssh_adapter.SshTransport("vps-3xui")
        content = b"binary\x00payload"

        def inner(argv, **kwargs):
            handle = kwargs.get("stdout")
            if handle is not None:
                handle.write(content)
            return mock.Mock(returncode=0, stderr=b"")

        tmp = tempfile.mkdtemp(prefix="fetch-")
        target = os.path.join(tmp, "artifact.tar")
        with mock.patch("os.path.isfile", return_value=True), \
                mock.patch("subprocess.run",
                           side_effect=bound_run("/etc/known_hosts", inner)):
            result = transport.fetch_to("/remote/artifact.tar", target)
        self.assertTrue(result.ok)
        with open(target, "rb") as handle:
            self.assertEqual(handle.read(), content)


if __name__ == "__main__":
    unittest.main()
