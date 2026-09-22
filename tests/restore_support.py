"""Synthetic P1 restore fixtures shared by every restore stream's tests.

Fixtures cover a complete, consistent restore scenario plus incomplete and
contradictory variants. All identities are synthetic: the target never shares
a machine-id or host key with ``support.MACHINE_ID``/``support.HOST_KEY``.
"""

from __future__ import annotations

import copy
import datetime
import os
from typing import Any, Dict, Optional, Tuple

import support
from vps3xui.restore import contracts
from vps3xui.util import json_digest, sha256_file
from vps3xui.verify import verify_directory

NOW = datetime.datetime(2026, 9, 23, 12, 0, 0, tzinfo=datetime.timezone.utc)
TARGET_ALIAS = "vps-restore-target"
TARGET_MACHINE_ID = "b" * 32
TARGET_HOST_KEY = "SHA256:TargetHostKeyFingerprintSyntheticValue0000"
TARGET_RESOLVED = {"hostname": "203.0.113.20", "port": 22, "user": "root"}
RELEASE_DIGEST = "c" * 64

DEFAULT_OPERATIONS = {
    "prepare": ["install_docker_from_verified_adapter", "check_certbot_timer_inactive"],
    "stage": ["transfer_payload", "restore_bind_trees", "restore_volumes",
              "pull_images_by_digest", "create_containers", "apply_fail2ban_layers",
              "prepare_certbot_guard"],
    "activate": ["start_containers_in_order"],
    "certbot_activate": ["enable_certbot_guard_and_timer"],
}


def target_facts(**overrides: Any) -> Dict[str, Any]:
    values = {
        "ssh_alias": TARGET_ALIAS,
        "host_key_fingerprint": TARGET_HOST_KEY,
        "machine_id": TARGET_MACHINE_ID,
        "resolved": dict(TARGET_RESOLVED),
        "os_id": "ubuntu",
        "os_version": "24.04",
        "arch": "x86_64",
    }
    values.update(overrides)
    return contracts.build_target_facts(**values)


def same_machine_target_facts() -> Dict[str, Any]:
    """A different alias that resolves to the source machine: must be refused."""
    return target_facts(ssh_alias="vps-3xui-alt", machine_id=support.MACHINE_ID)


def verified_backup(tmp: str):
    """Real P0 worker copy, verified; returns (manifest, backup_dir, backup identity)."""
    manifest, backup_dir, _report, _system = support.complete_backup(tmp)
    result = verify_directory(backup_dir, manifest)
    assert result.ok, result.error and result.error.to_error_object()
    return manifest, backup_dir, contracts.backup_identity(backup_dir, manifest, result)


def source_record(backup: Dict[str, Any], **source_overrides: Any) -> Dict[str, Any]:
    source = {
        "ssh_alias": "vps-3xui",
        "host_key_fingerprint": support.HOST_KEY,
        "machine_id": support.MACHINE_ID,
    }
    source.update(source_overrides)
    return {
        "schema_version": 1,
        "kind": "vps3xui.restore.source_record",
        "backup_id": backup["backup_id"],
        "backup_digest": backup["backup_digest"],
        "manifest_id": backup["manifest_id"],
        "manifest_digest": backup["manifest_digest"],
        "source": source,
        "obtained": {
            "method": "source_job_request",
            "source_job_id": backup["backup_id"],
            "observed_at": contracts.format_time(NOW),
        },
    }


def restore_plan(manifest, backup, target=None, source=None, now=None, **kwargs):
    target = target or target_facts()
    source = source or contracts.resolve_source_identity(backup, manifest)
    return contracts.build_restore_plan(
        manifest, backup, source, target,
        operations=kwargs.pop("operations", DEFAULT_OPERATIONS),
        space=kwargs.pop("space", {"required_bytes": 10 * 1024 ** 3, "free_bytes": 40 * 1024 ** 3}),
        now=now or NOW,
        **kwargs
    )


def scenario(tmp: str) -> Tuple[Any, str, Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    """Complete consistent scenario: (manifest, backup_dir, backup, plan, request)."""
    manifest, backup_dir, backup = verified_backup(tmp)
    plan = restore_plan(manifest, backup)
    request = contracts.build_restore_request(plan, RELEASE_DIGEST, now=NOW)
    return manifest, backup_dir, backup, plan, request


def source_observation(plan: Dict[str, Any], observed_at: Optional[datetime.datetime] = None,
                       fencing: str = "docker_units_masked", **overrides: Any) -> Dict[str, Any]:
    """Stopped and fenced source, observed over the pinned channel."""
    observation = {
        "schema_version": 1,
        "kind": "vps3xui.restore.source_observation",
        "observed_at": contracts.format_time(observed_at or NOW),
        "channel": "ssh_pinned_host_key",
        "source": {
            "ssh_alias": plan["source"]["ssh_alias"],
            "host_key_fingerprint": plan["source"]["host_key_fingerprint"],
            "machine_id": plan["source"]["machine_id"],
        },
        "probe_complete": True,
        "docker": {
            "service": {"load_state": "masked", "active_state": "inactive"},
            "socket": {"load_state": "masked", "active_state": "inactive"},
        },
        "containers": [
            {"name": item["name"], "present": True, "running": False, "restart_policy": "no"}
            for item in plan["resources"]["containers"]
        ],
        "fencing": {"method": fencing},
    }
    observation.update(overrides)
    return observation


def cutover_attestation(plan: Dict[str, Any], attested_at: Optional[datetime.datetime] = None,
                        permitted: bool = True, channel: bool = True) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "kind": "vps3xui.restore.cutover_attestation",
        "job_id": plan["job_id"],
        "plan_identity": plan["identity"],
        "attested_at": contracts.format_time(attested_at or NOW),
        "operator_decision": {
            "cutover_permitted": permitted,
            "statement": "Operator confirmed source OAuth service is stopped for cutover.",
        },
        "independent_control_channel": {
            "confirmed": channel,
            "description": "Provider web console for the source VPS.",
        },
    }


def applied_step(job_id: str, seq: int, step_id: str, stage: str = "prepare",
                 kind: str = "package", resource: str = "docker-ce",
                 ownership: str = "created_by_job"):
    """(intent, outcome) journal pair of one verified step."""
    intent = contracts.journal_intent(job_id, seq, step_id, stage, kind, resource, ownership,
                                      {"state": "installed"}, now=NOW)
    outcome = contracts.journal_outcome(intent, seq + 1, "applied", {"state": "installed"}, now=NOW)
    return intent, outcome


def mutated(record: Dict[str, Any], path: str, value: Any) -> Dict[str, Any]:
    """Deep copy with one dotted field replaced (contradictory variants)."""
    clone = copy.deepcopy(record)
    node = clone
    keys = path.split(".")
    for key in keys[:-1]:
        node = node[key]
    node[keys[-1]] = value
    return clone


def sums_digest(backup_dir: str) -> str:
    return sha256_file(os.path.join(backup_dir, "SHA256SUMS"), nofollow=True)


__all__ = [
    "NOW", "TARGET_ALIAS", "TARGET_MACHINE_ID", "TARGET_HOST_KEY", "RELEASE_DIGEST",
    "target_facts", "same_machine_target_facts", "verified_backup", "source_record",
    "restore_plan", "scenario", "source_observation", "cutover_attestation",
    "applied_step", "mutated", "sums_digest", "json_digest",
]
