"""Real-adapter contract tests using a fake ``subprocess.run``.

These exercise ``vps3xui.adapters.ssh`` and ``vps3xui.worker.system`` directly
(not the SyntheticHost) so a missing method, wrong flag or ignored return code
fails the suite.
"""

import base64
import hashlib
import io
import os
import subprocess
import tempfile
import unittest
from unittest import mock

import fakeexec
import support
from vps3xui.adapters.ssh import RemoteHostOps, SshTransport
from vps3xui.errors import ToolError
from vps3xui.worker import system as system_module

KEY_B64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
KNOWN_HOSTS_LINE = b"vps.example.org ssh-ed25519 %s\n" % KEY_B64.encode("ascii")


def expected_fingerprint(key_b64):
    digest = hashlib.sha256(base64.b64decode(key_b64)).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


class SshAdapterTest(unittest.TestCase):
    def setUp(self):
        self.fake = fakeexec.FakeRun()
        self._patcher = mock.patch("subprocess.run", self.fake)
        self._patcher.start()
        self.addCleanup(self._patcher.stop)
        self.bind_host()

    def bind_host(self, known_hosts_line=KNOWN_HOSTS_LINE, resolved=None):
        """Script the local binding calls: ssh -G and ssh-keygen -F."""
        self.fake.rules = []
        self.fake.on(lambda argv: bool(argv) and argv[0] == "ssh-keygen",
                     stdout=known_hosts_line)
        self.fake.on(lambda argv: len(argv) > 1 and argv[0] == "ssh" and argv[1] == "-G",
                     stdout=self._resolved(**(resolved or {})))

    def _resolved(self, **extra):
        lines = ["hostname vps.example.org", "port 22", "user root",
                 "userknownhostsfile /tmp/known_hosts"]
        for key, value in extra.items():
            lines.append("%s %s" % (key, value))
        return ("\n".join(lines) + "\n").encode()

    def test_fingerprint_is_computed_from_pinned_key(self):
        with mock.patch("os.path.isfile", return_value=True):
            transport = SshTransport("vps-3xui")
            self.assertEqual(transport.fingerprint(), expected_fingerprint(KEY_B64))

    def test_operations_are_bound_to_the_pinned_key_and_context(self):
        self.fake.on_first("ssh", returncode=0, stdout=b"ok\n")
        with mock.patch("os.path.isfile", return_value=True):
            host = RemoteHostOps("vps-3xui")
            host.run(["true"])
        argv = self.fake.calls[-1][0]
        joined = " ".join(argv)
        self.assertIn("GlobalKnownHostsFile=/dev/null", joined)
        # The exact selected key is pinned into a private temporary known_hosts
        # file rather than reusing the ambient file.
        self.assertIn("UserKnownHostsFile=", joined)
        pin = [token.split("=", 1)[1] for token in argv
               if token.startswith("UserKnownHostsFile=")][0]
        self.assertIn("vps3xui-known-hosts-", pin)
        with open(pin, "rb") as handle:
            self.assertEqual(handle.read(), KNOWN_HOSTS_LINE)
        self.assertIn("HostKeyAlgorithms=ssh-ed25519", joined)
        self.assertIn("Hostname=vps.example.org", joined)
        self.assertIn("Port=22", joined)

    def test_unknown_host_key_fails_closed(self):
        self.bind_host(known_hosts_line=b"")
        with mock.patch("os.path.isfile", return_value=True):
            with self.assertRaises(ToolError) as ctx:
                SshTransport("vps-3xui").host_key_fingerprint()
            self.assertEqual(ctx.exception.code, "E_HOST_KEY_UNKNOWN")

    def test_complex_ssh_configuration_is_rejected(self):
        for key in ("proxycommand", "proxyjump", "hostkeyalias", "knownhostscommand"):
            self.bind_host(resolved={key: "something"})
            with mock.patch("os.path.isfile", return_value=True):
                with self.assertRaises(ToolError) as ctx:
                    SshTransport("vps-3xui").fingerprint()
                self.assertEqual(ctx.exception.code, "E_UNSUPPORTED")

    def test_run_rejects_nul_tokens(self):
        with self.assertRaises(ToolError) as ctx:
            SshTransport("vps-3xui").run(["echo", "a\x00b"])
        self.assertEqual(ctx.exception.code, "E_CONTRACT")

    def test_reserve_and_launch_ships_module_and_payload(self):
        # The reviewed module is shipped on stdin; the coordination command
        # travels as a single quoted argv token, so match the ssh call that
        # carries it rather than a bare "python3" token.
        module_calls = []

        def is_module_call(argv):
            hit = bool(argv) and argv[0] == "ssh" and any(
                "reserve-and-launch" in token for token in argv
            )
            if hit:
                module_calls.append((argv, self.fake.last_kwargs))
            return hit

        self.fake.on(is_module_call,
                     stdout=b'{"ok": true, "reserved": true, "job_id": "req-1"}\n')
        self.fake.on_first("ssh", returncode=0, stdout=b"ok\n")
        with mock.patch("os.path.isfile", return_value=True):
            host = RemoteHostOps("vps-3xui")
            payload = {
                "job_id": "req-1",
                "plan_digest": "d",
                "manifest_id": "m",
                "backup_dir": "/var/backups/vps3xui/req-1",
            }
            launch = {"unit_name": "u", "release_dir": "/opt/vps3xui/releases/x",
                      "job_dir": "/var/lib/vps3xui/jobs/req-1", "runtime_max_seconds": 900,
                      "timeout_stop_seconds": 90}
            result = host.reserve_and_launch("/var/lib/vps3xui", "/var/lib/vps3xui/jobs/req-1",
                                             payload, {"identity": "d"}, launch)
        self.assertTrue(result["reserved"])
        self.assertEqual(len(module_calls), 1)
        argv, kwargs = module_calls[0]
        self.assertIn("reserve-and-launch", argv[-1])
        stdin = kwargs.get("input") or b""
        self.assertIn(b"cmd_reserve_and_launch", stdin)  # the reviewed module, not generated code

    def test_remote_verify_passes_manifest(self):
        self.fake.on_first("ssh", returncode=0, stdout=b'{"ok": true}\n')
        with mock.patch("os.path.isfile", return_value=True):
            host = RemoteHostOps("vps-3xui")
            host.remote_verify("/opt/vps3xui/releases/x", "/var/backups/vps3xui/req-1",
                               "/var/lib/vps3xui/jobs/req-1/manifest.json")
        command = self.fake.calls[-1][0][-1]
        self.assertIn("--manifest", command)
        self.assertIn("remote_verify", command)


class RealSystemTest(unittest.TestCase):
    def setUp(self):
        self.fake = fakeexec.FakeRun()
        mock.patch("subprocess.run", self.fake).start()
        self.addCleanup(mock.patch.stopall)

    def test_tar_create_uses_double_dash(self):
        from vps3xui.worker.system import RealSystem
        target = os.path.join(tempfile.mkdtemp(prefix="tar-"), "x.tar")
        with open(target, "wb") as handle:
            handle.write(b"stub")
        self.fake.on_first("tar", stdout=b"")
        RealSystem()._tar_create(target, "/", ["opt/llmproxy"])
        call = self.fake.calls[-1][0]
        self.assertIn("--", call)
        self.assertEqual(call[call.index("--") + 1], "opt/llmproxy")
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)

    def test_tar_create_rejects_option_injection(self):
        from vps3xui.worker.system import RealSystem
        with self.assertRaises(ToolError) as ctx:
            RealSystem()._tar_create("/tmp/x.tar", "/", ["--checkpoint-action=exec=id"])
        self.assertEqual(ctx.exception.code, "E_UNSAFE_PATH")
        self.assertEqual(self.fake.calls, [])  # nothing was executed

    def test_certbot_mask_failure_is_not_ignored(self):
        from vps3xui.worker.system import RealSystem
        manifest = support.approved_manifest(tempfile.mkdtemp(prefix="cert-"))
        self.fake.on_subcommand("show",
                                stdout=b"LoadState=loaded\nActiveState=inactive\nUnitFileState=enabled\n",
                                returncode=0)
        self.fake.on_subcommand("is-active", stdout=b"inactive", returncode=3)
        self.fake.on_subcommand("pgrep", returncode=1)
        self.fake.on_subcommand("stop", stdout=b"", returncode=0)
        self.fake.on_subcommand("mask", stdout=b"", returncode=1)
        with mock.patch.object(system_module.os.path, "exists", return_value=False):
            with self.assertRaises(ToolError) as ctx:
                RealSystem().disable_certbot_triggers(manifest)
        self.assertEqual(ctx.exception.code, "E_EXECUTION")

    def test_restore_never_stops_active_service(self):
        from vps3xui.worker.system import RealSystem
        manifest = support.approved_manifest(tempfile.mkdtemp(prefix="cert2-"))
        state = {"units": {
            "certbot.service": {"active_state": "inactive", "unit_file_state": "enabled"},
            "certbot.timer": {"active_state": "active", "unit_file_state": "enabled"},
        }}
        self.fake.on_subcommand("unmask", returncode=0)
        self.fake.on_subcommand("is-active", stdout=b"active", returncode=0)
        with self.assertRaises(ToolError) as ctx:
            RealSystem().restore_certbot_triggers(state, manifest)
        self.assertEqual(ctx.exception.code, "E_CONFLICT")
        self.assertFalse(any("stop" in call[0] and "certbot.service" in call[0]
                             for call in self.fake.calls))


if __name__ == "__main__":
    unittest.main()
