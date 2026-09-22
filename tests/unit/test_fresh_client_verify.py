"""F7: ``backup verify --host --job`` from a client with no local history.

The pinned release and backup paths come from the job's immutable remote
request, validated against the fixed job path, the live host key and the local
manifest. A local record is optional and must agree with the host when present.
"""

from __future__ import annotations

import json
import os
import unittest
from unittest import mock

import support
from vps3xui import backup as backup_ops
from vps3xui import coordination as coord
from vps3xui.errors import ToolError
from vps3xui.jobs import JobStore


class FreshClientVerifyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = support.temp_state_dir("f7-verify-")
        self.manifest = support.approved_manifest(self.tmp)
        self.host = support.SyntheticHost(self.manifest, root=os.path.join(self.tmp, "host"))
        plan, _drift, _inventory, _fingerprint = backup_ops.run_plan(self.host, self.manifest, 3600)
        plan_path = os.path.join(self.tmp, "plan.json")
        backup_ops.write_plan(plan, plan_path)
        self.job_id = "req-f7-verify"
        self.origin_state = os.path.join(self.tmp, "origin-state")
        backup_ops.run_start(self.host, self.manifest, plan_path, self.job_id,
                             self.origin_state, apply=True)
        self.fresh_state = os.path.join(self.tmp, "fresh-state")
        self.request_path = os.path.join(self.host._local(backup_ops.job_dir(self.job_id)),
                                         coord.REQUEST_FILE)
        self.succeeded = backup_ops._remote_status(self.host, self.job_id)
        self.assertEqual(self.succeeded["state"], "succeeded", self.succeeded)
        self.verify_calls = []
        original = self.host.remote_verify

        def recording_verify(release_dir, backup_dir, manifest_path):
            self.verify_calls.append((release_dir, backup_dir, manifest_path))
            return original(release_dir, backup_dir, manifest_path)

        self.host.remote_verify = recording_verify

    def _host_request(self):
        return self.host.read_json_file("%s/request.json" % backup_ops.job_dir(self.job_id))

    def _rewrite_request(self, **changes):
        with open(self.request_path, "r", encoding="utf-8") as handle:
            request = json.load(handle)
        for key, value in changes.items():
            if value is None:
                request.pop(key, None)
            else:
                request[key] = value
        with open(self.request_path, "w", encoding="utf-8") as handle:
            json.dump(request, handle)

    def _refused(self, code, state_dir=None):
        # Force the remote gate to report success so the client-side request
        # validation is exercised on its own; test_tampered_request_* below
        # covers the host gate refusing the same tampering independently.
        with mock.patch.object(self.host, "remote_job_status", return_value=self.succeeded), \
                self.assertRaises(ToolError) as caught:
            backup_ops.run_verify_job(self.host, self.manifest, self.job_id,
                                      state_dir or self.fresh_state)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(self.verify_calls, [])
        return caught.exception

    def test_empty_client_state_verifies_from_the_remote_request(self):
        result = backup_ops.run_verify_job(self.host, self.manifest, self.job_id, self.fresh_state)
        self.assertEqual(result["state"], "verified", result)
        self.assertTrue(result["operation_complete"])
        request = self._host_request()
        self.assertEqual(self.verify_calls, [(
            request["release_dir"],
            backup_ops.backup_dir(self.job_id),
            "%s/manifest.json" % backup_ops.job_dir(self.job_id),
        )])
        # Read-only: the fresh client registers nothing locally.
        self.assertEqual(JobStore(self.fresh_state).list_requests(), [])

    def test_existing_local_record_flow_still_verifies(self):
        result = backup_ops.run_verify_job(self.host, self.manifest, self.job_id, self.origin_state)
        self.assertEqual(result["state"], "verified", result)
        self.assertEqual(len(self.verify_calls), 1)

    def test_missing_request_is_refused(self):
        os.unlink(self.request_path)
        self._refused("E_PRECONDITION")

    def test_corrupt_request_is_refused(self):
        with open(self.request_path, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        self._refused("E_PRECONDITION")

    def test_unreadable_request_is_refused(self):
        with mock.patch.object(self.host, "read_json_file", side_effect=OSError("io")):
            self._refused("E_PRECONDITION")

    def test_non_object_request_is_refused(self):
        with mock.patch.object(self.host, "read_json_file", return_value=["x"]):
            self._refused("E_PRECONDITION")

    def test_foreign_job_request_is_refused(self):
        self._rewrite_request(job_id="req-other")
        self._refused("E_PRECONDITION")

    def test_foreign_request_id_is_refused(self):
        self._rewrite_request(request_id="req-other")
        self._refused("E_PRECONDITION")

    def test_host_key_mismatch_is_refused(self):
        self._rewrite_request(host_key_fingerprint="SHA256:someone-else")
        self._refused("E_HOST_IDENTITY_MISMATCH")

    def test_missing_host_key_binding_is_refused(self):
        self._rewrite_request(host_key_fingerprint=None)
        self._refused("E_HOST_IDENTITY_MISMATCH")

    def test_different_manifest_is_refused(self):
        other = support.approved_manifest(os.path.join(self.tmp, "other"), manifest_id="other-manifest")
        with self.assertRaises(ToolError) as caught:
            backup_ops.run_verify_job(self.host, other, self.job_id, self.fresh_state)
        self.assertEqual(caught.exception.code, "E_CONFLICT")
        self.assertEqual(self.verify_calls, [])

    def test_embedded_manifest_digest_mismatch_is_refused(self):
        request = self._host_request()
        embedded = dict(request["manifest"])
        embedded["note"] = "tampered"
        self._rewrite_request(manifest=embedded)
        self._refused("E_CONFLICT")

    def test_release_dir_not_derived_from_digest_is_refused(self):
        self._rewrite_request(release_dir="/tmp/attacker-release")
        self._refused("E_PRECONDITION")

    def test_release_digest_not_sha256_is_refused(self):
        self._rewrite_request(release_digest="abc")
        self._refused("E_PRECONDITION")

    def test_unsafe_tool_version_is_refused(self):
        request = self._host_request()
        self._rewrite_request(tool_version="../x",
                              release_dir="/opt/vps3xui/releases/../x-%s" % request["release_digest"][:16])
        self._refused("E_PRECONDITION")

    def test_unexpected_backup_dir_is_refused(self):
        self._rewrite_request(backup_dir="/var/backups/vps3xui/other")
        self._refused("E_PRECONDITION")

    def test_stale_local_record_cannot_redirect_the_target(self):
        store = JobStore(self.origin_state)
        store.update_request(self.job_id, release_dir="/opt/vps3xui/releases/stale-0000000000000000")
        exc = self._refused("E_CONFLICT", state_dir=self.origin_state)
        self.assertEqual(exc.resource, "release_dir")
        store.update_request(self.job_id, release_dir=self._host_request()["release_dir"],
                             backup_dir="/var/backups/vps3xui/elsewhere")
        exc = self._refused("E_CONFLICT", state_dir=self.origin_state)
        self.assertEqual(exc.resource, "backup_dir")

    def test_tampered_request_is_also_refused_by_the_host_gate(self):
        self._rewrite_request(job_id="req-other")
        result = backup_ops.run_verify_job(self.host, self.manifest, self.job_id, self.fresh_state)
        self.assertEqual(result["state"], "failed", result)
        self.assertFalse(result["operation_complete"])
        self.assertEqual(self.verify_calls, [])

    def test_source_success_gate_runs_before_request_resolution(self):
        with mock.patch.object(self.host, "remote_job_status",
                               return_value={"state": "recovery_required", "operation_complete": False}), \
                mock.patch.object(self.host, "read_json_file") as read:
            result = backup_ops.run_verify_job(self.host, self.manifest, self.job_id, self.fresh_state)
        self.assertEqual(result["state"], "failed")
        self.assertFalse(result["operation_complete"])
        read.assert_not_called()
        self.assertEqual(self.verify_calls, [])


if __name__ == "__main__":
    unittest.main()
