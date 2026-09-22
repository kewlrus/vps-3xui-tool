"""The shipped probe must run read-only and degrade to bounded tokens."""

import base64
import json
import os
import subprocess
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROBE = os.path.join(REPO_ROOT, "vps3xui", "probe.py")


class ProbeTest(unittest.TestCase):
    def test_probe_emits_json_with_unavailable_sections_reported(self):
        env = dict(os.environ)
        env["PATH"] = ""  # no docker/systemctl/ufw available
        result = subprocess.run(
            [sys.executable, PROBE], capture_output=True, env=env, timeout=120
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        data = json.loads(result.stdout.decode("utf-8"))
        self.assertEqual(data["probe_version"], 3)
        self.assertFalse(data["docker"]["present"])
        self.assertIn("docker_missing", data["errors"])
        self.assertFalse(data["systemd"]["present"])
        self.assertFalse(data["ufw"]["present"])
        # The probe never emits environment or secret file contents.
        blob = result.stdout.decode("utf-8")
        self.assertNotIn("LITELLM_MASTER_KEY=", blob)
        self.assertNotIn("ANTHROPIC_API_KEY=", blob)

    def test_probe_output_is_bounded_json_shape(self):
        env = dict(os.environ)
        env["PATH"] = ""
        result = subprocess.run([sys.executable, PROBE], capture_output=True, env=env, timeout=120)
        data = json.loads(result.stdout.decode("utf-8"))
        for key in ("machine_id", "os", "arch", "python", "containers", "volumes",
                    "systemd", "certbot", "ufw", "paths", "space",
                    "config_fingerprints", "at_queue"):
            self.assertIn(key, data)
        self.assertIsInstance(data["containers"], list)
        self.assertIsInstance(data["paths"], dict)


    def test_probe_honors_base64_spec(self):
        spec = {
            "paths": ["/tmp"],
            "units": [],
            "compose_projects": [],
            "trusted_files": ["/etc/hosts"],
            "renewal_hook_dirs": ["/etc"],
        }
        token = base64.b64encode(json.dumps(spec).encode("utf-8")).decode("ascii")
        env = dict(os.environ)
        env["PATH"] = ""
        result = subprocess.run([sys.executable, PROBE, token], capture_output=True,
                                env=env, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        data = json.loads(result.stdout.decode("utf-8"))
        self.assertIn("/tmp", data["paths"])
        self.assertNotIn("/opt/llmproxy", data["paths"])
        self.assertIn("/etc/hosts", data["trusted_fingerprints"])
        self.assertIsInstance(data["trusted_fingerprints"]["/etc/hosts"], str)
        # Permission facts are numeric only, and never file contents.
        modes = data["trusted_modes"]["/etc/hosts"]
        self.assertRegex(modes["mode"], r"^0[0-7]{3}$")
        self.assertIsInstance(modes["uid"], int)
        self.assertIsInstance(modes["gid"], int)

    def test_probe_reports_bounded_tar_and_cron_facts(self):
        env = dict(os.environ)
        env["PATH"] = ""
        result = subprocess.run([sys.executable, PROBE], capture_output=True, env=env, timeout=120)
        data = json.loads(result.stdout.decode("utf-8"))
        self.assertIn("tar", data)
        for key in ("present", "gnu", "version"):
            self.assertIn(key, data["tar"])
        self.assertIsInstance(data["cron_certbot"], list)
        # The pending at-job queue degrades to bounded facts, not raw commands.
        self.assertIn(data["at_queue"]["state"], ("absent", "empty", "occupied", "unknown"))
        self.assertIn("directories", data["at_queue"])
        self.assertIn("atq", data["at_queue"])
        self.assertIn("trusted_modes", data)
        self.assertIsInstance(data["systemd"].get("version", None), (str, type(None)))


if __name__ == "__main__":
    unittest.main()
