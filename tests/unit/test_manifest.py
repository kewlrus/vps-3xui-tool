import copy
import json
import os
import tempfile
import unittest

import support
from vps3xui import jsonschema_lite
from vps3xui import manifest as manifest_module
from vps3xui.errors import ToolError


class ManifestSchemaTest(unittest.TestCase):
    def test_example_manifest_validates_and_is_unapproved(self):
        manifest = manifest_module.load(manifest_module.EXAMPLE_MANIFEST_PATH)
        self.assertFalse(manifest.approved)
        self.assertEqual(manifest.manifest_id, "vps3xui-snapshot-20260920")

    def test_required_artifacts_derived_from_manifest(self):
        manifest = manifest_module.load(manifest_module.EXAMPLE_MANIFEST_PATH)
        required = manifest.required_artifacts()
        for expected in [
            "binds.tar",
            "llmproxy_chatgpt_auth.tar",
            "certbot-automation.tar",
            "ufw-config.tar",
            "3xui-fail2ban-config.tar",
            "images.json",
            "backup.json",
        ]:
            self.assertIn(expected, required)
        self.assertNotIn("SHA256SUMS", required)
        self.assertNotIn("COMPLETE", required)

    def test_artifact_ownership_and_reference_only(self):
        manifest = manifest_module.load(manifest_module.EXAMPLE_MANIFEST_PATH)
        self.assertEqual(manifest.artifact_owner("llmproxy_chatgpt_auth.tar"),
                         "volume:llmproxy_chatgpt_auth")
        self.assertIn("ufw-config.tar", manifest.reference_only_artifacts())
        self.assertIn("binds.tar", manifest.sensitive_artifacts())

    def test_unknown_property_is_rejected(self):
        data = support.example_data()
        data["unexpected_key"] = True
        with self.assertRaises(ToolError) as caught:
            manifest_module.from_object(data)
        self.assertEqual(caught.exception.code, "E_MANIFEST_INVALID")

    def test_unsafe_manifest_id_is_rejected(self):
        data = support.example_data()
        data["manifest_id"] = "../escape"
        with self.assertRaises(ToolError) as caught:
            manifest_module.from_object(data)
        self.assertEqual(caught.exception.code, "E_MANIFEST_INVALID")

    def test_included_local_build_without_digest_is_not_restorable(self):
        data = support.example_data()
        data["containers"][0]["image"] = {
            "reference": "local/thing", "repo_digest": None,
            "source": "local_build", "restorable": False,
        }
        with self.assertRaises(ToolError) as caught:
            manifest_module.from_object(data)
        self.assertEqual(caught.exception.code, "E_IMAGE_NOT_RESTORABLE")

    def test_ufw_must_be_reference_only(self):
        data = support.example_data()
        data["ufw"]["never_apply"] = False
        with self.assertRaises(ToolError):
            manifest_module.from_object(data)

    def test_approved_manifest_requires_trusted_files(self):
        import tempfile
        data = support.approved_manifest(tempfile.mkdtemp(prefix="mf-")).data
        data["trusted_files"] = []
        with self.assertRaises(ToolError) as caught:
            manifest_module.from_object(data)
        self.assertEqual(caught.exception.code, "E_MANIFEST_INVALID")

    def test_example_manifest_has_empty_trust_and_is_unapproved(self):
        manifest = manifest_module.load(manifest_module.EXAMPLE_MANIFEST_PATH)
        self.assertFalse(manifest.approved)
        self.assertEqual(manifest.trusted_files, [])

    def test_container_mounts_are_validated(self):
        data = support.example_data()
        data["containers"][0]["mounts"] = [
            {"type": "bind", "name": None, "source": "/opt/x", "destination": "relative", "rw": False}
        ]
        with self.assertRaises(ToolError) as caught:
            manifest_module.from_object(data)
        self.assertEqual(caught.exception.code, "E_MANIFEST_INVALID")

    def test_pending_approval_names(self):
        manifest = manifest_module.load(manifest_module.EXAMPLE_MANIFEST_PATH)
        self.assertEqual(manifest.pending_approval_names(), ["agent-relay"])


class ManifestTrustContractTest(unittest.TestCase):
    """REVIEW-2 item 11: a subset trust contract must never approve a plan."""

    def setUp(self):
        self.data = copy.deepcopy(
            support.approved_manifest(tempfile.mkdtemp(prefix="mf-trust-")).data
        )

    def _reject(self, data):
        with self.assertRaises(ToolError) as caught:
            manifest_module.from_object(data)
        self.assertEqual(caught.exception.code, "E_MANIFEST_INVALID")
        return caught.exception

    def test_required_trust_paths_are_the_full_contract(self):
        manifest = manifest_module.from_object(self.data)
        required = manifest.required_trust_paths()
        self.assertIn("/usr/local/sbin/certbot-http01-guard", required)
        self.assertIn("/etc/certbot-http01-guard.enabled", required)
        self.assertIn("/etc/systemd/system/certbot-http01-cleanup.service", required)
        self.assertIn("/etc/systemd/system/certbot-http01-cleanup.timer", required)
        self.assertIn("/etc/systemd/system/certbot.service.d/http01-cleanup.conf", required)
        self.assertIn("/etc/letsencrypt/renewal/kewlsub.duckdns.org.conf", required)

    def test_subset_trust_set_is_rejected(self):
        self.data["trusted_files"] = [
            item for item in self.data["trusted_files"]
            if item["path"] != "/usr/local/sbin/certbot-http01-guard"
        ]
        error = self._reject(self.data)
        self.assertIn("certbot-http01-guard", error.resource or "")

    def test_missing_permitted_hook_pin_is_rejected(self):
        del self.data["certbot"]["hook_fingerprints"]["kewlsub.duckdns.org.conf:renew_hook"]
        error = self._reject(self.data)
        self.assertIn("renew_hook", error.resource or "")

    def test_guard_permissions_must_be_pinned(self):
        for item in self.data["trusted_files"]:
            if item["path"] == "/usr/local/sbin/certbot-http01-guard":
                del item["mode"]
        self._reject(self.data)

    def test_bad_permission_pin_is_rejected(self):
        for item in self.data["trusted_files"]:
            if item["path"] == "/usr/local/sbin/certbot-http01-guard":
                item["mode"] = "777"
        self._reject(self.data)

    def test_approved_manifest_requires_hook_directories(self):
        self.data["certbot"]["renewal_hook_dirs"] = []
        self._reject(self.data)

    def test_lease_inside_included_path_is_rejected(self):
        self.data["bind_trees"][0]["includes"].append("var/lib/certbot-http01-guard")
        error = self._reject(self.data)
        self.assertIn("lease", error.message.lower())

    def test_overlapping_included_paths_are_rejected(self):
        self.data["bind_trees"][0]["includes"].append("root/panel")
        error = self._reject(self.data)
        self.assertIn("overlap", error.message.lower())

    def test_duplicate_artifact_owner_is_rejected(self):
        self.data["volumes"][1]["artifact"] = self.data["volumes"][0]["artifact"]
        error = self._reject(self.data)
        self.assertIn("artifact", error.message.lower())


class ManifestUnapprovedTrustTest(unittest.TestCase):
    def test_unapproved_manifest_keeps_empty_trust(self):
        data = support.example_data()
        data["trusted_files"] = []
        manifest = manifest_module.from_object(data)
        self.assertFalse(manifest.approved)
        self.assertEqual(manifest.required_trust_paths()[0].startswith("/"), True)


class JsonSchemaLiteTest(unittest.TestCase):
    def test_type_and_required(self):
        schema = {"type": "object", "required": ["a"],
                  "properties": {"a": {"type": "integer"}}}
        jsonschema_lite.validate({"a": 1}, schema)
        with self.assertRaises(jsonschema_lite.SchemaError):
            jsonschema_lite.validate({}, schema)
        with self.assertRaises(jsonschema_lite.SchemaError):
            jsonschema_lite.validate({"a": "x"}, schema)

    def test_additional_properties_and_enum(self):
        schema = {"type": "object", "additionalProperties": False,
                  "properties": {"a": {"enum": [1, 2]}}}
        jsonschema_lite.validate({"a": 2}, schema)
        with self.assertRaises(jsonschema_lite.SchemaError):
            jsonschema_lite.validate({"a": 3}, schema)
        with self.assertRaises(jsonschema_lite.SchemaError):
            jsonschema_lite.validate({"b": 1}, schema)


if __name__ == "__main__":
    unittest.main()
