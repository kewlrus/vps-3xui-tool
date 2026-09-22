import copy
import json
import tempfile
import unittest

import support
from vps3xui import manifest as manifest_module
from vps3xui.inventory import Inventory, compare


def _findings(manifest, probe):
    return compare(manifest, Inventory.from_probe(probe))


def _codes(report):
    return sorted({item.code for item in report.findings})


class InventoryDriftTest(unittest.TestCase):
    def setUp(self):
        # An *approved* inventory: pending resources resolved and the trust
        # contract pinned, so the baseline is a clean drift report.
        self.manifest = support.approved_manifest(tempfile.mkdtemp(prefix="inv-"))

    def test_baseline_has_no_blocking_findings(self):
        report = _findings(self.manifest, support.synthetic_probe())
        self.assertTrue(report.ok, [item.to_object() for item in report.blocking])

    def test_unexpected_running_container_is_drift(self):
        probe = support.synthetic_probe()
        probe["containers"].append({
            "id": "id-rogue", "name": "rogue", "image": "rogue:1", "image_id": "sha256:r",
            "repo_digests": [], "running": True, "status": "running",
            "restart_policy": "no", "network_mode": "host",
            "compose_project": "llmproxy", "compose_service": "rogue", "mounts": [],
        })
        report = _findings(self.manifest, probe)
        self.assertIn("E_INVENTORY_DRIFT", _codes(report))
        self.assertFalse(report.ok)

    def test_excluded_running_container_is_drift(self):
        probe = support.synthetic_probe()
        for item in probe["containers"]:
            if item["name"] == "telemt":
                item["running"] = True
                item["status"] = "running"
        report = _findings(self.manifest, probe)
        self.assertIn("E_INVENTORY_DRIFT", _codes(report))

    def test_pending_approval_blocks_regardless_of_container_name(self):
        # Pending resources block completeness even when no container matches
        # the guessed name; approval is what resolves them.
        manifest = manifest_module.from_object(support.example_data())
        report = _findings(manifest, support.synthetic_probe())
        self.assertIn("E_MANIFEST_PENDING_APPROVAL", _codes(report))
        self.assertEqual(report.first_blocking_error().resource, "agent-relay")

    def test_approved_manifest_rejects_pending_resources(self):
        from vps3xui.errors import ToolError
        data = support.approved_manifest(tempfile.mkdtemp(prefix="inv-")).data
        data["pending_approval"] = [{"resource": "agent-relay", "kind": "container",
                                     "reason": "unverified"}]
        with self.assertRaises(ToolError) as caught:
            manifest_module.from_object(data)
        self.assertEqual(caught.exception.code, "E_MANIFEST_INVALID")

    def test_new_mount_is_drift(self):
        probe = support.synthetic_probe()
        for item in probe["containers"]:
            if item["name"] == "litellm":
                item["mounts"].append({
                    "type": "bind", "name": None, "source": "/opt/llmproxy/newthing",
                    "destination": "/app/new", "rw": False, "driver": None, "mode": "",
                })
        report = _findings(self.manifest, probe)
        self.assertIn("E_INVENTORY_DRIFT", _codes(report))

    def test_non_local_volume_driver_is_unsupported(self):
        probe = support.synthetic_probe()
        for item in probe["volumes"]:
            if item["name"] == "llmproxy_caddy_data":
                item["driver"] = "nfs"
        report = _findings(self.manifest, probe)
        self.assertIn("E_UNSUPPORTED", _codes(report))

    def test_missing_included_container_is_drift(self):
        probe = support.synthetic_probe()
        probe["containers"] = [c for c in probe["containers"] if c["name"] != "caddy"]
        report = _findings(self.manifest, probe)
        self.assertIn("E_INVENTORY_DRIFT", _codes(report))

    def test_image_digest_mismatch_is_drift(self):
        probe = support.synthetic_probe()
        for item in probe["containers"]:
            if item["name"] == "litellm":
                item["repo_digests"] = ["ghcr.io/berriai/litellm@sha256:" + "0" * 64]
        report = _findings(self.manifest, probe)
        self.assertIn("E_INVENTORY_DRIFT", _codes(report))

    def test_volume_options_mismatch_is_drift(self):
        probe = support.synthetic_probe()
        for item in probe["volumes"]:
            if item["name"] == "llmproxy_caddy_config":
                item["options"] = {"type": "none"}
        report = _findings(self.manifest, probe)
        self.assertIn("E_INVENTORY_DRIFT", _codes(report))

    def test_unknown_certbot_unit_is_conflict(self):
        probe = support.synthetic_probe()
        probe["systemd"]["unit_files"].append("certbot-renewal-extra.timer")
        report = _findings(self.manifest, probe)
        self.assertIn("E_CONFLICT", _codes(report))

    def test_cron_certbot_is_conflict(self):
        probe = support.synthetic_probe(cron_certbot=["/etc/cron.d/certbot"])
        report = _findings(self.manifest, probe)
        self.assertIn("E_CONFLICT", _codes(report))

    def test_unapproved_renewal_hook_is_conflict(self):
        data = support.example_data()
        data["certbot"]["permitted_hooks"] = ["renew_hook"]
        manifest = manifest_module.from_object(data)
        probe = support.synthetic_probe()
        probe["certbot"]["renewal_hooks"]["kewlsub.duckdns.org.conf"]["pre_hook"] = True
        report = _findings(manifest, probe)
        self.assertIn("E_CONFLICT", _codes(report))

    def test_unapproved_authenticator_is_conflict(self):
        probe = support.synthetic_probe()
        probe["certbot"]["renewal_hooks"]["kewlsub.duckdns.org.conf"]["authenticator"] = "dns-route53"
        report = _findings(self.manifest, probe)
        self.assertIn("E_CONFLICT", _codes(report))

    def test_guard_enabled_without_helper_is_conflict(self):
        probe = support.synthetic_probe()
        probe["certbot"]["guard_present"] = False
        report = _findings(self.manifest, probe)
        self.assertIn("E_CONFLICT", _codes(report))

    def test_active_lease_blocks_copy(self):
        probe = support.synthetic_probe()
        probe["certbot"]["lease_present"] = True
        probe["certbot"]["lease_age_seconds"] = 5
        report = _findings(self.manifest, probe)
        self.assertIn("E_PRECONDITION", _codes(report))

    def test_invalid_compose_configuration_is_blocking(self):
        probe = support.synthetic_probe()
        probe["compose"]["llmproxy"] = {"valid": False, "state": "config_invalid"}
        report = _findings(self.manifest, probe)
        self.assertIn("E_PRECONDITION", _codes(report))
        self.assertFalse(report.ok)

    def test_machine_id_mismatch_is_reported(self):
        data = support.example_data()
        data["source"]["expected_machine_id"] = support.MACHINE_ID
        manifest = manifest_module.from_object(data)
        probe = support.synthetic_probe(machine_id="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        report = _findings(manifest, probe)
        self.assertIn("E_HOST_IDENTITY_MISMATCH", _codes(report))

    def test_trusted_file_change_is_drift(self):
        probe = support.synthetic_probe()
        probe["trusted_fingerprints"]["/usr/local/sbin/certbot-http01-guard"] = "9" * 64
        report = _findings(self.manifest, probe)
        self.assertIn("E_TRUST_MISMATCH", _codes(report))
        self.assertFalse(report.ok)

    def test_missing_trusted_file_is_drift(self):
        probe = support.synthetic_probe()
        del probe["trusted_fingerprints"]["/etc/certbot-http01-guard.enabled"]
        report = _findings(self.manifest, probe)
        self.assertIn("E_TRUST_MISMATCH", _codes(report))

    def test_unpinned_renewal_hook_command_is_conflict(self):
        probe = support.synthetic_probe()
        probe["certbot"]["renewal_hook_fingerprints"]["kewlsub.duckdns.org.conf"]["pre_hook"] = "f" * 64
        report = _findings(self.manifest, probe)
        self.assertIn("E_CONFLICT", _codes(report))
        self.assertTrue(any("pre_hook" in (item.resource or "") for item in report.blocking))

    def test_unpinned_hook_directory_entry_is_conflict(self):
        probe = support.synthetic_probe()
        probe["certbot"]["renewal_hook_dirs"]["/etc/letsencrypt/renewal-hooks/deploy"] = {
            "rogue.sh": "1" * 64
        }
        report = _findings(self.manifest, probe)
        self.assertIn("E_CONFLICT", _codes(report))

    def test_missing_machine_id_is_probe_incomplete(self):
        probe = support.synthetic_probe(machine_id=None)
        report = _findings(self.manifest, probe)
        self.assertIn("E_PROBE_INCOMPLETE", _codes(report))

    def test_probe_error_token_is_probe_incomplete(self):
        probe = support.synthetic_probe(errors=["docker_inspect_failed"])
        report = _findings(self.manifest, probe)
        self.assertIn("E_PROBE_INCOMPLETE", _codes(report))

    def test_unavailable_systemd_is_unsupported(self):
        probe = support.synthetic_probe(systemd={"present": False, "units": {}, "unit_files": []})
        report = _findings(self.manifest, probe)
        self.assertIn("E_UNSUPPORTED", _codes(report))

    def test_missing_compose_project_is_probe_incomplete(self):
        probe = support.synthetic_probe(compose={"llmproxy": {"valid": True, "state": "valid"}})
        report = _findings(self.manifest, probe)
        self.assertIn("E_PROBE_INCOMPLETE", _codes(report))

    def test_undeclared_compose_service_is_drift(self):
        probe = support.synthetic_probe()
        probe["compose"]["llmproxy"] = {"valid": True, "state": "valid",
                                        "services": ["litellm", "caddy", "agent-relay"]}
        report = _findings(self.manifest, probe)
        self.assertIn("E_INVENTORY_DRIFT", _codes(report))

    def test_exact_mount_mismatch_is_drift(self):
        probe = support.synthetic_probe()
        for item in probe["containers"]:
            if item["name"] == "caddy":
                item["mounts"][0]["rw"] = True  # manifest pins it read-only
        report = _findings(self.manifest, probe)
        self.assertIn("E_INVENTORY_DRIFT", _codes(report))

    def test_inspect_object_never_prints_volume_options(self):
        probe = support.synthetic_probe()
        for item in probe["volumes"]:
            item["options"] = {"type": "none", "password": "CANARY-volume-option"}
        inventory = Inventory.from_probe(probe)
        blob = json.dumps(inventory.to_object())
        self.assertNotIn("CANARY-volume-option", blob)
        self.assertNotIn("options", blob)

    def test_stopped_included_container_is_warning_not_blocker(self):
        probe = support.synthetic_probe()
        for item in probe["containers"]:
            if item["name"] == "caddy":
                item["running"] = False
                item["status"] = "exited"
        report = _findings(self.manifest, probe)
        self.assertTrue(report.ok, [item.to_object() for item in report.blocking])
        self.assertTrue(any(item.resource == "caddy" for item in report.warnings))


class InventoryTrustAndDependencyTest(unittest.TestCase):
    """REVIEW-2 item 11: trust set, scheduler content, dependency gates."""

    def setUp(self):
        self.manifest = support.approved_manifest(tempfile.mkdtemp(prefix="inv-trust-"))

    def _report(self, probe):
        return compare(self.manifest, Inventory.from_probe(probe))

    def test_hidden_docker_data_root_is_conflict(self):
        probe = support.synthetic_probe()
        probe["docker"]["root_dir"] = "/opt/llmproxy/caddy"
        report = self._report(probe)
        self.assertIn("E_CONFLICT", _codes(report))
        self.assertTrue(any("Docker data-root" in item.message for item in report.blocking))

    def test_unknown_docker_data_root_is_probe_incomplete(self):
        probe = support.synthetic_probe()
        del probe["docker"]["root_dir"]
        self.assertIn("E_PROBE_INCOMPLETE", _codes(self._report(probe)))

    def test_old_docker_is_unsupported(self):
        probe = support.synthetic_probe()
        probe["docker"]["version"] = "19.03.8"
        self.assertIn("E_UNSUPPORTED", _codes(self._report(probe)))

    def test_old_compose_is_unsupported(self):
        probe = support.synthetic_probe()
        probe["docker"]["compose_version"] = "1.29.2"
        self.assertIn("E_UNSUPPORTED", _codes(self._report(probe)))

    def test_missing_dependency_version_is_probe_incomplete(self):
        probe = support.synthetic_probe()
        probe["python"] = None
        self.assertIn("E_PROBE_INCOMPLETE", _codes(self._report(probe)))

    def test_old_systemd_is_unsupported(self):
        probe = support.synthetic_probe()
        probe["systemd"]["version"] = "systemd 219"
        self.assertIn("E_UNSUPPORTED", _codes(self._report(probe)))

    def test_missing_gnu_tar_is_rejected(self):
        probe = support.synthetic_probe()
        probe["tar"] = {"present": False, "gnu": False, "version": None}
        probe["errors"] = ["tar_missing"]
        self.assertIn("E_PROBE_INCOMPLETE", _codes(self._report(probe)))

    def test_non_gnu_tar_is_unsupported(self):
        probe = support.synthetic_probe()
        probe["tar"] = {"present": True, "gnu": False, "version": "bsdtar 3.5.2"}
        self.assertIn("E_UNSUPPORTED", _codes(self._report(probe)))

    def test_guard_permission_drift_is_trust_mismatch(self):
        probe = support.synthetic_probe()
        probe["trusted_modes"]["/usr/local/sbin/certbot-http01-guard"]["mode"] = "0777"
        report = self._report(probe)
        self.assertIn("E_TRUST_MISMATCH", _codes(report))
        self.assertTrue(any("permissions" in item.message for item in report.blocking))

    def test_missing_permission_facts_is_probe_incomplete(self):
        probe = support.synthetic_probe()
        probe["trusted_modes"] = {}
        self.assertIn("E_PROBE_INCOMPLETE", _codes(self._report(probe)))

    def test_trusted_file_symlink_is_trust_mismatch(self):
        probe = support.synthetic_probe()
        probe["trusted_modes"]["/usr/local/sbin/certbot-http01-guard"]["is_symlink"] = True
        self.assertIn("E_TRUST_MISMATCH", _codes(self._report(probe)))

    def test_empty_renewal_hook_inventory_is_probe_incomplete(self):
        probe = support.synthetic_probe()
        probe["certbot"]["renewal_hook_dirs"] = {}
        self.assertIn("E_PROBE_INCOMPLETE", _codes(self._report(probe)))

    def test_unprobed_declared_hook_directory_is_probe_incomplete(self):
        probe = support.synthetic_probe()
        del probe["certbot"]["renewal_hook_dirs"]["/etc/letsencrypt/renewal-hooks/deploy"]
        self.assertIn("E_PROBE_INCOMPLETE", _codes(self._report(probe)))

    def test_empty_renewal_file_inventory_is_probe_incomplete(self):
        probe = support.synthetic_probe()
        probe["certbot"]["renewal_files"] = []
        self.assertIn("E_PROBE_INCOMPLETE", _codes(self._report(probe)))

    def test_missing_lineage_renewal_file_is_drift(self):
        probe = support.synthetic_probe()
        probe["certbot"]["renewal_files"] = ["other.example.org.conf"]
        self.assertIn("E_INVENTORY_DRIFT", _codes(self._report(probe)))

    def test_empty_certbot_inventory_is_probe_incomplete(self):
        probe = support.synthetic_probe()
        probe["certbot"] = {"present": False}
        self.assertIn("E_PROBE_INCOMPLETE", _codes(self._report(probe)))

    def test_missing_certbot_binary_is_warning_when_files_are_pinned(self):
        probe = support.synthetic_probe()
        probe["certbot"]["present"] = False
        probe["certbot"]["binary"] = None
        report = self._report(probe)
        self.assertTrue(report.ok, [item.to_object() for item in report.blocking])
        self.assertTrue(any(item.resource == "certbot" for item in report.warnings))

    def test_unpinned_cron_scheduler_is_conflict(self):
        probe = support.synthetic_probe()
        probe["cron_certbot"] = [{"path": "/etc/cron.d/certbot", "sha256": "f" * 64,
                                  "source": "cron"}]
        self.assertIn("E_CONFLICT", _codes(self._report(probe)))

    def _manifest_with_pinned_cron(self, digest="f" * 64):
        from vps3xui import manifest as manifest_module

        data = copy.deepcopy(self.manifest.data)
        data["trusted_files"].append({"path": "/etc/cron.d/certbot", "sha256": digest})
        return manifest_module.from_object(data)

    def _probe_with_cron(self, digest="f" * 64):
        probe = support.synthetic_probe()
        probe["cron_certbot"] = [{"path": "/etc/cron.d/certbot", "sha256": digest,
                                  "source": "cron"}]
        probe["trusted_fingerprints"]["/etc/cron.d/certbot"] = digest
        return probe

    def test_pinned_cron_scheduler_is_refused_even_when_guard_enabled(self):
        # R4: a pinned digest plus an enabled HTTP-01 guard never proves the
        # scheduler is inactive, so P0 refuses it instead of allowing it.
        manifest = self._manifest_with_pinned_cron()
        report = compare(manifest, Inventory.from_probe(self._probe_with_cron()))
        self.assertIn("E_CONFLICT", _codes(report))
        self.assertFalse(report.ok)

    def test_pinned_cron_scheduler_blocks_the_backup_plan_gate(self):
        from vps3xui.errors import ToolError

        manifest = self._manifest_with_pinned_cron()
        report = compare(manifest, Inventory.from_probe(self._probe_with_cron()))
        with self.assertRaises(ToolError) as caught:
            report.raise_if_blocking()
        self.assertEqual(caught.exception.code, "E_CONFLICT")

    def test_distro_claimed_pinned_cron_scheduler_is_refused(self):
        # An entry claiming distro origin is still refused without probe
        # evidence that its own conditions keep it inactive under systemd.
        manifest = self._manifest_with_pinned_cron()
        probe = self._probe_with_cron()
        probe["cron_certbot"] = [{"path": "/etc/cron.d/certbot", "sha256": "f" * 64,
                                  "source": "distro"}]
        report = compare(manifest, Inventory.from_probe(probe))
        self.assertIn("E_CONFLICT", _codes(report))
        self.assertTrue(any(item.resource == "distro:/etc/cron.d/certbot"
                            for item in report.blocking))

    def test_cron_scheduler_with_missing_digest_is_refused(self):
        manifest = self._manifest_with_pinned_cron()
        probe = self._probe_with_cron()
        probe["cron_certbot"] = [{"path": "/etc/cron.d/certbot", "source": "cron"}]
        report = compare(manifest, Inventory.from_probe(probe))
        self.assertIn("E_CONFLICT", _codes(report))

    def test_empty_cron_scheduler_inventory_is_valid(self):
        probe = support.synthetic_probe()
        probe["cron_certbot"] = []
        report = self._report(probe)
        self.assertTrue(report.ok, [item.to_object() for item in report.blocking])

    SYSTEMD_UNIT_DIRS = ("/etc/systemd/system", "/lib/systemd/system",
                         "/usr/lib/systemd/system")

    def _declared_unit_names(self):
        certbot = self.manifest.data["certbot"]
        return [certbot["service_unit"], certbot["timer_unit"],
                certbot["cleanup_service"], certbot["cleanup_timer"]]

    def _manifest_with_pinned_paths(self, entries):
        data = copy.deepcopy(self.manifest.data)
        for path, digest in entries:
            data["trusted_files"] = [
                item for item in data["trusted_files"] if item["path"] != path
            ]
            data["trusted_files"].append({"path": path, "sha256": digest})
        return manifest_module.from_object(data)

    def _probe_with_systemd_entries(self, entries):
        probe = support.synthetic_probe()
        probe["cron_certbot"] = [
            {"path": path, "sha256": digest, "source": "systemd"}
            for path, digest in entries
        ]
        for path, digest in entries:
            probe["trusted_fingerprints"][path] = digest
        return probe

    def test_declared_systemd_units_pass_when_each_is_pinned(self):
        # Real probe shape: distro/cleanup units are content-discovered and
        # labelled source=systemd. Exact declared, exactly-pinned units are the
        # only systemd-source case allowed to pass.
        entries = [
            ("/etc/systemd/system/%s" % name, ("%d" % (index + 5)) * 64)
            for index, name in enumerate(self._declared_unit_names())
        ]
        manifest = self._manifest_with_pinned_paths(entries)
        report = compare(manifest,
                         Inventory.from_probe(self._probe_with_systemd_entries(entries)))
        self.assertTrue(report.ok, [item.to_object() for item in report.blocking])

    def test_declared_systemd_units_pass_in_supported_directories(self):
        names = self._declared_unit_names()
        entries = [
            ("/lib/systemd/system/%s" % names[0], "a" * 64),
            ("/usr/lib/systemd/system/%s" % names[1], "b" * 64),
        ]
        manifest = self._manifest_with_pinned_paths(entries)
        report = compare(manifest,
                         Inventory.from_probe(self._probe_with_systemd_entries(entries)))
        self.assertTrue(report.ok, [item.to_object() for item in report.blocking])

    def test_pinned_unrelated_systemd_scheduler_is_refused(self):
        entries = [
            ("/etc/systemd/system/certbot-rogue.service", "c" * 64),
            ("/etc/systemd/system/certbot-renamed.timer", "d" * 64),
        ]
        manifest = self._manifest_with_pinned_paths(entries)
        report = compare(manifest,
                         Inventory.from_probe(self._probe_with_systemd_entries(entries)))
        self.assertIn("E_CONFLICT", _codes(report))
        self.assertFalse(report.ok)

    def test_systemd_source_on_cron_path_is_refused(self):
        entries = [("/etc/cron.d/certbot", "e" * 64)]
        manifest = self._manifest_with_pinned_paths(entries)
        report = compare(manifest,
                         Inventory.from_probe(self._probe_with_systemd_entries(entries)))
        self.assertIn("E_CONFLICT", _codes(report))

    def test_declared_unit_in_subdirectory_is_refused(self):
        path = "/etc/systemd/system/extra/%s" % self._declared_unit_names()[1]
        entries = [(path, "6" * 64)]
        manifest = self._manifest_with_pinned_paths(entries)
        report = compare(manifest,
                         Inventory.from_probe(self._probe_with_systemd_entries(entries)))
        self.assertIn("E_CONFLICT", _codes(report))

    def test_declared_systemd_unit_without_pin_is_refused(self):
        path = "/etc/systemd/system/%s" % self._declared_unit_names()[0]
        report = compare(self.manifest, Inventory.from_probe(
            self._probe_with_systemd_entries([(path, "9" * 64)])))
        self.assertIn("E_CONFLICT", _codes(report))

    def test_declared_systemd_unit_with_mismatched_digest_is_refused(self):
        path = "/etc/systemd/system/%s" % self._declared_unit_names()[0]
        manifest = self._manifest_with_pinned_paths([(path, "8" * 64)])
        probe = self._probe_with_systemd_entries([(path, "8" * 64)])
        probe["cron_certbot"] = [{"path": path, "sha256": "7" * 64,
                                  "source": "systemd"}]
        report = compare(manifest, Inventory.from_probe(probe))
        self.assertIn("E_CONFLICT", _codes(report))

    def test_declared_systemd_unit_with_empty_digest_is_refused(self):
        path = "/etc/systemd/system/%s" % self._declared_unit_names()[0]
        manifest = self._manifest_with_pinned_paths([(path, "8" * 64)])
        probe = self._probe_with_systemd_entries([(path, "8" * 64)])
        probe["cron_certbot"] = [{"path": path, "sha256": "",
                                  "source": "systemd"}]
        report = compare(manifest, Inventory.from_probe(probe))
        self.assertIn("E_CONFLICT", _codes(report))

    def test_pinned_cron_scheduler_still_conflicts_without_guard(self):
        manifest = self._manifest_with_pinned_cron()
        probe = self._probe_with_cron()
        probe["certbot"]["guard_enabled"] = False
        self.assertIn("E_CONFLICT", _codes(compare(manifest, Inventory.from_probe(probe))))

    def test_cron_content_change_is_conflict(self):
        manifest = self._manifest_with_pinned_cron()
        probe = self._probe_with_cron(digest="0" * 64)
        self.assertIn("E_CONFLICT", _codes(compare(manifest, Inventory.from_probe(probe))))


if __name__ == "__main__":
    unittest.main()
