import datetime
import tempfile
import unittest

import support
from vps3xui import backup as backup_module
from vps3xui.errors import ToolError
from vps3xui.inventory import Inventory
from vps3xui.plan import (
    build_plan,
    inventory_structural_digest,
    parse_time,
    save_plan,
    load_plan,
    verify_plan,
)


class PlanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="plan-")
        self.manifest = support.approved_manifest(self.tmp)
        self.inventory = Inventory.from_probe(support.synthetic_probe())
        self.plan = build_plan(self.manifest, self.inventory, support.HOST_KEY, ttl_seconds=600)

    def test_plan_binds_host_and_records_originally_running_containers(self):
        self.assertEqual(self.plan["host"]["host_key_fingerprint"], support.HOST_KEY)
        self.assertEqual(self.plan["host"]["machine_id"], support.MACHINE_ID)
        self.assertEqual(self.plan["inventory_digest"], inventory_structural_digest(self.inventory))
        names = [item["name"] for item in self.plan["stop_containers"]]
        self.assertEqual(names, ["litellm", "caddy", "3xui_app"])
        self.assertIn("telemt", self.plan["leave_stopped"])

    def test_verify_plan_accepts_matching_inventory(self):
        verify_plan(self.plan, self.manifest, self.inventory, support.HOST_KEY)

    def test_expired_plan_is_rejected(self):
        later = parse_time(self.plan["expires_at"]) + datetime.timedelta(seconds=1)
        with self.assertRaises(ToolError) as caught:
            verify_plan(self.plan, self.manifest, self.inventory, support.HOST_KEY, now=later)
        self.assertEqual(caught.exception.code, "E_PLAN_EXPIRED")

    def test_stale_inventory_is_rejected(self):
        probe = support.synthetic_probe()
        probe["containers"][0]["id"] = "id-changed"
        changed = Inventory.from_probe(probe)
        with self.assertRaises(ToolError) as caught:
            verify_plan(self.plan, self.manifest, changed, support.HOST_KEY)
        self.assertEqual(caught.exception.code, "E_PLAN_STALE")

    def test_host_key_change_is_rejected(self):
        with self.assertRaises(ToolError) as caught:
            verify_plan(self.plan, self.manifest, self.inventory, "SHA256:different")
        self.assertEqual(caught.exception.code, "E_HOST_IDENTITY_MISMATCH")

    def test_missing_host_key_is_unknown(self):
        with self.assertRaises(ToolError) as caught:
            verify_plan(self.plan, self.manifest, self.inventory, None)
        self.assertEqual(caught.exception.code, "E_HOST_KEY_UNKNOWN")

    def test_machine_id_change_is_rejected(self):
        probe = support.synthetic_probe(machine_id="cccccccccccccccccccccccccccccccc")
        changed = Inventory.from_probe(probe)
        with self.assertRaises(ToolError) as caught:
            verify_plan(self.plan, self.manifest, changed, support.HOST_KEY)
        self.assertEqual(caught.exception.code, "E_HOST_IDENTITY_MISMATCH")

    def test_manifest_change_is_stale(self):
        other = support.approved_manifest(self.tmp, manifest_id="other-manifest")
        with self.assertRaises(ToolError) as caught:
            verify_plan(self.plan, other, self.inventory, support.HOST_KEY)
        self.assertEqual(caught.exception.code, "E_PLAN_STALE")

    def test_unknown_backup_root_free_space_is_precondition(self):
        probe = support.synthetic_probe(space={"/": {"total_bytes": 10 ** 12, "free_bytes": 10 ** 12}})
        inventory = Inventory.from_probe(probe)
        with self.assertRaises(ToolError) as caught:
            build_plan(self.manifest, inventory, support.HOST_KEY)
        self.assertEqual(caught.exception.code, "E_PRECONDITION")

    def test_zero_free_space_is_precondition(self):
        probe = support.synthetic_probe(space={
            "/": {"total_bytes": 10 ** 12, "free_bytes": 0},
            "/var/backups": {"total_bytes": 10 ** 12, "free_bytes": 10 ** 12},
        })
        inventory = Inventory.from_probe(probe)
        with self.assertRaises(ToolError) as caught:
            build_plan(self.manifest, inventory, support.HOST_KEY)
        self.assertEqual(caught.exception.code, "E_PRECONDITION")

    def test_manifest_expected_fingerprint_is_enforced(self):
        data = self.manifest.data
        data = dict(data)
        data["source"] = dict(data["source"])
        data["source"]["expected_host_key_fingerprint"] = "SHA256:expected"
        from vps3xui import manifest as manifest_module
        manifest = manifest_module.from_object(data)
        with self.assertRaises(ToolError) as caught:
            build_plan(manifest, self.inventory, support.HOST_KEY)
        self.assertEqual(caught.exception.code, "E_HOST_IDENTITY_MISMATCH")

    def test_config_fingerprint_change_stales_plan(self):
        probe = support.synthetic_probe()
        probe["config_fingerprints"] = {"/opt/llmproxy/docker-compose.yaml": "a" * 64}
        changed = Inventory.from_probe(probe)
        with self.assertRaises(ToolError) as caught:
            verify_plan(self.plan, self.manifest, changed, support.HOST_KEY)
        self.assertEqual(caught.exception.code, "E_PLAN_STALE")

    def test_cron_inventory_entries_are_canonicalized(self):
        probe = support.synthetic_probe()
        probe["cron_certbot"] = [
            {"path": "/etc/cron.d/certbot", "sha256": "a" * 64, "source": "cron"},
            {"path": "/etc/crontab", "sha256": "b" * 64, "source": "cron"},
        ]
        changed = Inventory.from_probe(probe)
        digest = inventory_structural_digest(changed)
        self.assertNotEqual(digest, inventory_structural_digest(self.inventory))
        self.assertEqual(digest, inventory_structural_digest(changed))

    def test_trusted_permission_change_stales_plan(self):
        probe = support.synthetic_probe()
        probe["trusted_modes"]["/usr/local/sbin/certbot-http01-guard"]["mode"] = "0777"
        changed = Inventory.from_probe(probe)
        with self.assertRaises(ToolError) as caught:
            verify_plan(self.plan, self.manifest, changed, support.HOST_KEY)
        self.assertEqual(caught.exception.code, "E_PLAN_STALE")

    def test_plan_round_trips_through_disk_with_0600(self):
        import os

        path = os.path.join(self.tmp, "plan.json")
        save_plan(self.plan, path)
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
        loaded = load_plan(path)
        self.assertEqual(loaded["input_digest"], self.plan["input_digest"])

    def test_backup_plan_output_preserves_an_existing_parent_mode(self):
        import os

        parent = os.path.join(self.tmp, "cwd")
        os.makedirs(parent)
        os.chmod(parent, 0o755)
        path = os.path.join(parent, "plan.json")
        backup_module.write_plan(self.plan, path)
        self.assertEqual(oct(os.stat(parent).st_mode & 0o777), "0o755")
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")


if __name__ == "__main__":
    unittest.main()
