"""The VM drill fixture must be synthetic, unique and contract-valid.

These tests exercise the fixture generator locally in ``--plan`` mode, which
never touches Docker, systemd or the real host, and validate that the manifest it
would install satisfies the reviewed manifest contract.
"""

import json
import os
import subprocess
import sys
import unittest

import support
from vps3xui import manifest as manifest_module

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURE = os.path.join(REPO_ROOT, "scripts", "vm_restore_fixture.py")

PRODUCTION_NAMES = {
    "llmproxy", "llmproxy_chatgpt_auth", "llmproxy_caddy_data", "llmproxy_caddy_config",
    "3xui_app", "caddy", "litellm", "telemt", "kewlsub.duckdns.org",
}


def plan(identifier="unit1", image="fixture.local/app@sha256:" + "0" * 64):
    result = subprocess.run(
        [sys.executable, FIXTURE, "--plan", "--identifier", identifier, "--image", image],
        capture_output=True, cwd=REPO_ROOT,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr.decode())
    return json.loads(result.stdout.decode("utf-8"))


class VmFixturePlanTest(unittest.TestCase):
    def setUp(self):
        self.plan = plan()
        self.names = self.plan["names"]

    def test_names_are_unique_and_prefixed(self):
        resources = [self.names["volume"], self.names["container"],
                     self.names["idle_container"], self.names["worker_unit"],
                     self.names["finalizer_unit"], self.names["job_dir"]]
        self.assertEqual(len(set(resources)), len(resources))
        for name in (self.names["volume"], self.names["container"],
                     self.names["worker_unit"], self.names["finalizer_unit"]):
            self.assertTrue(name.startswith("vps3xui-drill-"), name)
        self.assertEqual(self.names["fail2ban_container"], "3xui_app")
        self.assertTrue(self.names["restored_container"].startswith("vps3xui-drill-"))

    def test_names_never_collide_with_production(self):
        # The reviewed manifest contract permits writable layers only for the
        # literal production Fail2ban container name. The plan therefore carries
        # that one name, plus an explicit refusal list; every other production
        # name must stay absent.
        without_safety = {key: value for key, value in self.plan.items()
                          if key != "safety"}
        blob = json.dumps(without_safety)
        for name in PRODUCTION_NAMES - {"3xui_app"}:
            self.assertNotIn(name, blob)
        self.assertEqual(
            self.plan["safety"]["production_container_refusal"][0], "3xui_app")
        self.assertEqual(
            self.plan["safety"]["fail2ban_container_name"], "3xui_app")

    def test_fixture_paths_are_prefixed_or_system_fixture_files(self):
        for item in self.plan["files"]:
            path = item["path"]
            self.assertTrue(path.startswith("/"), path)
            self.assertNotIn("/root/panel", path)
            self.assertNotIn("/opt/llmproxy", path)
        guarded = {"path": "/usr/local/sbin/certbot-http01-guard", "mode": "0755"}
        guard = [item for item in self.plan["files"]
                 if item["path"] == "/usr/local/sbin/certbot-http01-guard"]
        self.assertEqual(len(guard), 1)
        self.assertEqual(guard[0]["mode"], guarded["mode"])

    def test_manifest_validates_and_pins_the_full_trust_set(self):
        manifest = manifest_module.from_object(self.plan["manifest"])
        self.assertTrue(manifest.approved)
        pinned = set(manifest.trusted_file_paths())
        for path in manifest.required_trust_paths():
            self.assertIn(path, pinned, path)
        # F6: the Certbot triggers are vendored so the worker's runtime mask is
        # not shadowed by an /etc file; their exact paths must be pinned.
        self.assertIn("/usr/lib/systemd/system/certbot.service", pinned)
        self.assertIn("/usr/lib/systemd/system/certbot.timer", pinned)
        self.assertNotIn("/etc/systemd/system/certbot.service", pinned)
        self.assertNotIn("/etc/systemd/system/certbot.timer", pinned)
        # The offline --plan baseline is canonical: the usrmerge /lib alias is
        # only ever added at runtime from the real host shape.
        self.assertNotIn("/lib/systemd/system/certbot.service", pinned)
        self.assertNotIn("/lib/systemd/system/certbot.timer", pinned)
        for key in manifest.required_hook_pins():
            self.assertIn(key, self.plan["manifest"]["certbot"]["hook_fingerprints"])

    def test_certbot_triggers_are_vendored_below_the_runtime_mask(self):
        paths = {item["path"] for item in self.plan["files"]}
        self.assertIn("/usr/lib/systemd/system/certbot.service", paths)
        self.assertIn("/usr/lib/systemd/system/certbot.timer", paths)
        self.assertNotIn("/etc/systemd/system/certbot.service", paths)
        self.assertNotIn("/etc/systemd/system/certbot.timer", paths)
        # The cleanup automation and the drop-in stay under /etc per manifest.
        self.assertIn("/etc/systemd/system/certbot-http01-cleanup.service", paths)
        self.assertIn("/etc/systemd/system/certbot-http01-cleanup.timer", paths)
        self.assertIn("/etc/systemd/system/certbot.service.d/http01-cleanup.conf", paths)

    def test_manifest_has_real_fail2ban_writable_layers_and_synthetic_container(self):
        data = self.plan["manifest"]
        self.assertEqual(
            [(layer["container"], layer["path"]) for layer in data["writable_layers"]],
            [("3xui_app", "/etc/fail2ban"), ("3xui_app", "/var/lib/fail2ban")])
        self.assertEqual(
            [c["name"] for c in data["containers"]],
            [self.names["container"], "3xui_app", self.names["idle_container"]])
        self.assertTrue(data["images"]["archive_images"] is False)
        self.assertTrue(data["ufw"]["never_apply"])

    def test_plan_declares_required_metadata_and_relative_links(self):
        self.assertEqual(
            self.plan["required_tools"],
            ["tar", "setfacl", "getfacl", "setfattr", "getfattr"])
        links = {item["path"]: item["target"] for item in self.plan["symlinks"]}
        lineage = self.names["lineage"]
        self.assertEqual(
            links["/etc/letsencrypt/live/%s/cert.pem" % lineage],
            "../../archive/%s/cert.pem" % lineage)
        self.assertTrue(self.plan["safety"]["reason"])

    def test_plan_mode_touches_no_declared_resource_names(self):
        # --plan must not shell out to docker/systemd at all.
        result = subprocess.run(
            [sys.executable, FIXTURE, "--plan", "--identifier", "unit2"],
            capture_output=True, cwd=REPO_ROOT,
        )
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(b"docker", result.stderr)
        self.assertNotIn(b"systemctl", result.stderr)


class VmFixtureGuardTest(unittest.TestCase):
    def test_identifier_is_sanitized_against_traversal(self):
        result = plan(identifier="../escape")
        for key in ("volume", "container", "worker_unit"):
            self.assertNotIn("/", result["names"][key])
            self.assertNotIn("..", result["names"][key])

    def test_empty_identifier_is_rejected(self):
        result = subprocess.run(
            [sys.executable, FIXTURE, "--plan", "--identifier", "...."],
            capture_output=True, cwd=REPO_ROOT,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_incomplete_image_reference_is_rejected(self):
        result = subprocess.run(
            [sys.executable, FIXTURE, "--plan", "--identifier", "unit3",
             "--image", "fixture.local/app:latest"],
            capture_output=True, cwd=REPO_ROOT,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_plan_and_create_are_mutually_exclusive(self):
        result = subprocess.run(
            [sys.executable, FIXTURE, "--plan", "--create", "--identifier", "unit4"],
            capture_output=True, cwd=REPO_ROOT,
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
