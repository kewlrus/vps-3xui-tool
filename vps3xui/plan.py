"""Operation plan: an expiring, machine-bound description of a backup.

A plan binds the source host key fingerprint, machine-id, manifest, a
structural inventory digest, the tool version, bounded runtime/stop limits and
an expiry. Its identity is the digest of the *whole* plan, so a changed tool
version, expiry, stop list, mount, volume option, image or path changes the
identity. Every mutating stage recomputes these fields and rejects a mismatch
as ``E_PLAN_STALE`` instead of silently adapting.
"""

from __future__ import annotations

import datetime
import os
from typing import Any, Dict, List, Optional

from . import TOOL_VERSION
from .errors import ToolError
from .util import json_digest

PLAN_SCHEMA_VERSION = 1
DEFAULT_TTL_SECONDS = 30 * 60
DEFAULT_RUNTIME_MAX_SECONDS = 900
DEFAULT_TIMEOUT_STOP_SECONDS = 90

# Runtime/stop bounds are part of the reviewed plan, not unvalidated switches.
RUNTIME_MAX_SECONDS_LIMIT = (60, 3600)
TIMEOUT_STOP_SECONDS_LIMIT = (30, 600)
ESTIMATE_MARGIN_BYTES = 512 * 1024 * 1024


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _format(moment: datetime.datetime) -> str:
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> datetime.datetime:
    text = value.replace("Z", "+00:00")
    try:
        moment = datetime.datetime.fromisoformat(text)
    except ValueError:
        raise ToolError("E_PLAN_INVALID", "Plan timestamp is malformed.")
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    return moment


def inventory_structural_digest(inventory) -> str:
    """Digest of the parts of the inventory a plan depends on.

    Timestamps, sizes and free space are intentionally excluded so the digest
    is a stable structural fingerprint, not a noisy measurement.
    """
    containers = []
    for item in sorted(inventory.containers.values(), key=lambda c: c.get("name") or ""):
        containers.append(
            {
                "name": item.get("name"),
                "id": item.get("id"),
                "running": bool(item.get("running")),
                "image": item.get("image"),
                "repo_digests": sorted(item.get("repo_digests") or []),
                "compose_project": item.get("compose_project"),
                "compose_service": item.get("compose_service"),
                "mounts": sorted(
                    [
                        {
                            "type": mount.get("type"),
                            "name": mount.get("name"),
                            "source": mount.get("source"),
                            "destination": mount.get("destination"),
                            "rw": bool(mount.get("rw")),
                        }
                        for mount in (item.get("mounts") or [])
                    ],
                    key=lambda m: (m["destination"] or "", m["type"] or ""),
                ),
            }
        )
    volumes = []
    for item in sorted(inventory.volumes.values(), key=lambda v: v.get("name") or ""):
        volumes.append(
            {
                "name": item.get("name"),
                "driver": item.get("driver"),
                "options": item.get("options") or {},
            }
        )
    systemd_units = {
        unit: {
            "load_state": state.get("load_state"),
            "active_state": state.get("active_state"),
            "unit_file_state": state.get("unit_file_state"),
        }
        for unit, state in sorted((inventory.systemd.get("units") or {}).items())
    }
    cron_certbot = []
    for entry in inventory.cron_certbot or []:
        if isinstance(entry, dict):
            cron_certbot.append({
                "path": entry.get("path"),
                "sha256": entry.get("sha256"),
                "source": entry.get("source"),
            })
        else:
            cron_certbot.append({"path": str(entry), "sha256": None, "source": None})
    cron_certbot.sort(key=lambda item: (item["path"] or "", item["sha256"] or ""))
    at_queue = inventory.at_queue or {}
    at_directories = []
    for entry in at_queue.get("directories") or []:
        if isinstance(entry, dict):
            at_directories.append({
                "path": entry.get("path"),
                "state": entry.get("state"),
                "jobs": entry.get("jobs"),
            })
    at_directories.sort(key=lambda item: (item["path"] or "", item["state"] or ""))
    trusted_modes = {
        path: {
            "mode": (info or {}).get("mode"),
            "uid": (info or {}).get("uid"),
            "gid": (info or {}).get("gid"),
            "is_symlink": bool((info or {}).get("is_symlink")),
        }
        for path, info in sorted((inventory.trusted_modes or {}).items())
    }
    structural = {
        "machine_id": inventory.machine_id,
        "containers": containers,
        "volumes": volumes,
        "systemd_units": systemd_units,
        "systemd_unit_files": sorted(inventory.systemd.get("unit_files") or []),
        "certbot": {
            "present": inventory.certbot.get("present"),
            "guard_present": inventory.certbot.get("guard_present"),
            "guard_enabled": inventory.certbot.get("guard_enabled"),
            "renewal_files": sorted(inventory.certbot.get("renewal_files") or []),
            "renewal_hooks": inventory.certbot.get("renewal_hooks") or {},
        },
        "cron_certbot": cron_certbot,
        "at_queue": {
            "state": at_queue.get("state"),
            "tooling": {
                "at": (at_queue.get("tooling") or {}).get("at"),
                "atq": (at_queue.get("tooling") or {}).get("atq"),
            },
            "atq": {
                "present": (at_queue.get("atq") or {}).get("present"),
                "observed": (at_queue.get("atq") or {}).get("observed"),
                "count": (at_queue.get("atq") or {}).get("count"),
            },
            "directories": at_directories,
        },
        "compose": {
            project: {"valid": (info or {}).get("valid"),
                      "services": sorted((info or {}).get("services") or [])}
            for project, info in sorted((inventory.compose or {}).items())
        },
        # Private fingerprints of configuration inputs: editing any of them
        # changes the structural digest and therefore stales the plan.
        "config_fingerprints": dict(inventory.config_fingerprints or {}),
        "trusted_fingerprints": dict(inventory.trusted_fingerprints or {}),
        "trusted_modes": trusted_modes,
        "dependencies": {
            "python": inventory.python,
            "docker": (inventory.docker or {}).get("version"),
            "compose": (inventory.docker or {}).get("compose_version"),
            "systemd": (inventory.systemd or {}).get("version"),
            "docker_root_dir": (inventory.docker or {}).get("root_dir"),
            "tar": {
                "present": (inventory.tar or {}).get("present"),
                "gnu": (inventory.tar or {}).get("gnu"),
                "version": (inventory.tar or {}).get("version"),
            },
        },
        "ufw": {
            "present": inventory.ufw.get("present"),
            "active": inventory.ufw.get("active"),
        },
    }
    return json_digest(structural)


def _estimate_required_bytes(manifest, inventory) -> int:
    total = 0
    for tree in manifest.bind_trees:
        root = tree["root"].rstrip("/")
        for include in tree["includes"]:
            joined = (root + "/" + include) if root else "/" + include
            entry = inventory.paths.get(joined) or {}
            size = entry.get("size_bytes")
            if isinstance(size, int):
                total += size
    for volume in manifest.volumes:
        observed = inventory.volumes.get(volume["name"]) or {}
        mountpoint = observed.get("mountpoint")
        if mountpoint:
            entry = inventory.paths.get(mountpoint) or {}
            size = entry.get("size_bytes")
            if isinstance(size, int):
                total += size
    for layer in manifest.writable_layers:
        key = "%s:%s" % (layer["container"], layer["path"])
        entry = inventory.writable_layer.get(key) or {}
        size = entry.get("size_bytes")
        if isinstance(size, int):
            total += size
    for reference in manifest.reference_artifacts:
        entry = inventory.paths.get(reference["source"]) or {}
        size = entry.get("size_bytes")
        if isinstance(size, int):
            total += size
    # Staging/sums/report files are small but not free; always add the fixed
    # margin on top of the copied data.
    return int(total * 1.25) + ESTIMATE_MARGIN_BYTES


REQUIRED_FREE_SPACE_TARGETS = ("/", "/var/backups")


def available_free_bytes(inventory) -> int:
    """Minimum free space across the mountpoints the copy actually needs.

    Both the staging root and the backup root must have known, non-zero free
    space; an unknown or zero value fails closed instead of guessing.
    """
    values = []
    for target in REQUIRED_FREE_SPACE_TARGETS:
        entry = inventory.space.get(target)
        if not isinstance(entry, dict) or not isinstance(entry.get("free_bytes"), int):
            raise ToolError("E_PRECONDITION",
                            "Free space on a required mountpoint is unknown.",
                            resource="disk:%s" % target, next_action="inspect_storage")
        if entry["free_bytes"] <= 0:
            raise ToolError("E_PRECONDITION",
                            "Free space on a required mountpoint is zero.",
                            resource="disk:%s" % target, next_action="free_space")
        values.append(entry["free_bytes"])
    return min(values)


def _stop_plan(manifest, inventory):
    stop_containers: List[Dict[str, Any]] = []
    leave_stopped: List[str] = []
    for item in manifest.included_running_containers():
        observed = inventory.containers.get(item["name"])
        if observed and observed.get("running"):
            stop_containers.append(
                {
                    "name": item["name"],
                    "id": observed.get("id"),
                    "restart_order": item["restart_order"],
                }
            )
        else:
            leave_stopped.append(item["name"])
    for item in manifest.containers:
        if item["name"] in leave_stopped:
            continue
        observed = inventory.containers.get(item["name"])
        if not observed or not observed.get("running"):
            leave_stopped.append(item["name"])
    return (
        sorted(stop_containers, key=lambda c: (c["restart_order"], c["name"])),
        sorted(set(leave_stopped)),
    )


def plan_identity(plan: Dict[str, Any]) -> str:
    """Digest of the whole canonical plan (no self-reference)."""
    clone = dict(plan)
    clone.pop("identity", None)
    clone.pop("input_digest", None)
    clone.pop("approved", None)
    return json_digest(clone)


def check_runtime_bounds(runtime_max_seconds: int, timeout_stop_seconds: int) -> None:
    low, high = RUNTIME_MAX_SECONDS_LIMIT
    if not isinstance(runtime_max_seconds, int) or not (low <= runtime_max_seconds <= high):
        raise ToolError("E_PLAN_INVALID", "Runtime limit is outside the approved bounds.",
                        resource="runtime_max_seconds", next_action="use_bounded_runtime")
    low, high = TIMEOUT_STOP_SECONDS_LIMIT
    if not isinstance(timeout_stop_seconds, int) or not (low <= timeout_stop_seconds <= high):
        raise ToolError("E_PLAN_INVALID", "Stop-timeout is outside the approved bounds.",
                        resource="timeout_stop_seconds", next_action="use_bounded_timeout")


def build_plan(
    manifest,
    inventory,
    host_key_fingerprint: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    runtime_max_seconds: int = DEFAULT_RUNTIME_MAX_SECONDS,
    timeout_stop_seconds: int = DEFAULT_TIMEOUT_STOP_SECONDS,
    host_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    now = _utcnow()
    expires = now + datetime.timedelta(seconds=int(ttl_seconds))
    check_runtime_bounds(int(runtime_max_seconds), int(timeout_stop_seconds))
    expected_fingerprint = manifest.expected_host_key_fingerprint
    if expected_fingerprint and expected_fingerprint != host_key_fingerprint:
        raise ToolError("E_HOST_IDENTITY_MISMATCH",
                        "Observed host key fingerprint does not match the approved manifest.",
                        resource="host_key", next_action="review_host")
    stop_containers, leave_stopped = _stop_plan(manifest, inventory)
    free_bytes = available_free_bytes(inventory)
    plan = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "command": "backup.plan",
        "created_at": _format(now),
        "expires_at": _format(expires),
        "tool_version": TOOL_VERSION,
        "role": "source",
        "runtime_max_seconds": int(runtime_max_seconds),
        "timeout_stop_seconds": int(timeout_stop_seconds),
        "manifest": {"manifest_id": manifest.manifest_id, "digest": manifest.digest},
        "host": {
            "ssh_alias": manifest.ssh_alias,
            "host_key_fingerprint": host_key_fingerprint,
            "machine_id": inventory.machine_id,
            "os_id": inventory.os.get("id"),
            "os_version": inventory.os.get("version_id"),
            "arch": inventory.arch,
            # Resolved connection context (hostname/port/user/key) is part of the
            # plan identity so a changed resolved host cannot reuse a plan.
            "resolved": dict(host_context or {}),
        },
        "inventory_digest": inventory_structural_digest(inventory),
        "required_artifacts": manifest.required_artifacts(),
        "stop_containers": stop_containers,
        "leave_stopped": leave_stopped,
        "volumes": [
            {"name": volume["name"], "artifact": volume["artifact"],
             "driver": volume.get("driver"),
             "options": volume.get("options") or {},
             "mountpoint": (inventory.volumes.get(volume["name"]) or {}).get("mountpoint")}
            for volume in manifest.volumes
        ],
        "images": [
            {"container": container["name"], "repo_digest": container["image"].get("repo_digest")}
            for container in manifest.containers if container.get("included")
        ],
        "bind_trees": [dict(tree) for tree in manifest.bind_trees],
        "writable_layers": [dict(layer) for layer in manifest.writable_layers],
        "reference_only_artifacts": manifest.reference_only_artifacts(),
        "certbot": {
            "lineage": manifest.certbot["lineage"],
            "lease_active_at_plan": inventory.lease_active(int(manifest.certbot["max_lease_seconds"])),
            "permitted_hooks": list(manifest.certbot["permitted_hooks"]),
            "artifact": manifest.certbot["artifact"],
        },
        "space": {
            "required_bytes_estimate": _estimate_required_bytes(manifest, inventory),
            "free_bytes": free_bytes,
        },
        "downtime_impact": [
            "Stopping litellm and caddy interrupts both LLM clients (Claude Code, Codex).",
            "Stopping 3xui_app interrupts the panel, Xray and MTProto.",
            "The backup worker returns the originally running containers; the agent does not drive it.",
        ],
        "operations": [
            "re-check host identity and preconditions under lock",
            "fsync source state, then record original container/timer state",
            "verify no active Certbot HTTP-01 lease and disable approved renewal triggers",
            "stop only the recorded originally running container ids in manifest order",
            "copy bind trees, named volumes and declared writable-layer directories",
            "restart the recorded container ids immediately after copying data",
            "restore the exact original timer/service state",
            "compute SHA256SUMS, validate archives, and publish COMPLETE only after finalization",
        ],
    }
    plan["input_digest"] = plan_identity(plan)
    plan["identity"] = plan["input_digest"]
    return plan


_REQUIRED_PLAN_FIELDS = [
    "schema_version", "role", "manifest", "host", "inventory_digest",
    "input_digest", "required_artifacts", "stop_containers", "expires_at",
    "runtime_max_seconds", "timeout_stop_seconds", "tool_version",
]


def validate_plan_shape(plan: Any) -> Dict[str, Any]:
    if not isinstance(plan, dict):
        raise ToolError("E_PLAN_INVALID", "Plan must be a JSON object.")
    for key in _REQUIRED_PLAN_FIELDS:
        if key not in plan:
            raise ToolError("E_PLAN_INVALID", "Plan is missing required field %r." % key)
    if plan["schema_version"] != PLAN_SCHEMA_VERSION:
        raise ToolError("E_PLAN_INVALID", "Unsupported plan schema version.")
    if plan["role"] != "source":
        raise ToolError("E_PLAN_INVALID", "Plan role is not a backup source plan.")
    check_runtime_bounds(plan.get("runtime_max_seconds"), plan.get("timeout_stop_seconds"))
    return plan


def verify_plan(
    plan: Dict[str, Any],
    manifest,
    inventory,
    host_key_fingerprint: Optional[str],
    now: Optional[datetime.datetime] = None,
    host_context: Optional[Dict[str, Any]] = None,
) -> None:
    """Recompute every plan field from live facts and reject any mismatch."""
    validate_plan_shape(plan)
    moment = now or _utcnow()
    if moment > parse_time(plan["expires_at"]):
        raise ToolError("E_PLAN_EXPIRED", "Plan has expired; build a fresh plan.",
                        resource="plan", next_action="rebuild_plan")
    if plan["tool_version"] != TOOL_VERSION:
        raise ToolError("E_PLAN_STALE", "Plan was built by a different tool version.",
                        resource="tool_version", next_action="rebuild_plan")
    if plan["manifest"]["manifest_id"] != manifest.manifest_id or plan["manifest"]["digest"] != manifest.digest:
        raise ToolError("E_PLAN_STALE", "Plan was built for a different manifest.",
                        resource="manifest", next_action="rebuild_plan")
    if plan["host"]["ssh_alias"] != manifest.ssh_alias:
        raise ToolError("E_PLAN_STALE", "Plan is bound to a different SSH alias.",
                        resource="ssh_alias", next_action="rebuild_plan")
    if host_context:
        planned_context = dict(plan["host"].get("resolved") or {})
        if planned_context and planned_context != dict(host_context):
            raise ToolError("E_HOST_IDENTITY_MISMATCH",
                            "The resolved SSH connection context changed since the plan was built.",
                            resource="ssh_context", next_action="rebuild_plan")
    if not host_key_fingerprint:
        raise ToolError("E_HOST_KEY_UNKNOWN", "No verified host key is available for this alias.",
                        resource=manifest.ssh_alias, next_action="pin_host_key")
    expected_fingerprint = manifest.expected_host_key_fingerprint
    if expected_fingerprint and expected_fingerprint != host_key_fingerprint:
        raise ToolError("E_HOST_IDENTITY_MISMATCH",
                        "Observed host key fingerprint does not match the approved manifest.",
                        resource="host_key", next_action="review_host")
    if plan["host"].get("host_key_fingerprint") != host_key_fingerprint:
        raise ToolError("E_HOST_IDENTITY_MISMATCH", "Host key fingerprint changed since the plan was built.",
                        resource="host_key", next_action="review_host")
    if plan["host"].get("machine_id") != inventory.machine_id:
        raise ToolError("E_HOST_IDENTITY_MISMATCH", "Machine-id changed since the plan was built.",
                        resource="machine-id", next_action="review_host")
    if plan["inventory_digest"] != inventory_structural_digest(inventory):
        raise ToolError("E_PLAN_STALE", "Inventory changed since the plan was built.",
                        resource="inventory", next_action="rebuild_plan")
    if list(plan["required_artifacts"]) != manifest.required_artifacts():
        raise ToolError("E_PLAN_STALE", "Required artifact set changed since the plan was built.",
                        resource="artifacts", next_action="rebuild_plan")
    stop_containers, leave_stopped = _stop_plan(manifest, inventory)
    if plan["stop_containers"] != stop_containers or plan["leave_stopped"] != leave_stopped:
        raise ToolError("E_PLAN_STALE", "Recorded stop/leave set changed since the plan was built.",
                        resource="stop_containers", next_action="rebuild_plan")
    # The identity covers the whole plan (mounts, volume options, images, paths,
    # runtime bounds, expiry, certbot block, ...). A tampered plan is rejected.
    if plan.get("identity") != plan_identity(plan):
        raise ToolError("E_PLAN_STALE", "Plan identity does not match its contents.",
                        resource="plan", next_action="rebuild_plan")
    free_bytes = available_free_bytes(inventory)
    estimate = int((plan.get("space") or {}).get("required_bytes_estimate") or 0)
    if estimate <= 0:
        raise ToolError("E_PRECONDITION", "Required space could not be estimated.",
                        resource="disk", next_action="inspect_storage")
    if free_bytes < estimate:
        raise ToolError("E_PRECONDITION", "Estimated space is not available for the backup.",
                        resource="disk", next_action="free_space_or_reduce_scope")


def save_plan(plan: Dict[str, Any], path: str) -> None:
    from .util import write_json

    write_json(path, plan, mode=0o600)


def load_plan(path: str) -> Dict[str, Any]:
    from .util import read_json

    if not os.path.isfile(path):
        raise ToolError("E_CONTRACT", "Plan file not found.",
                        resource=os.path.basename(path), next_action="run_backup_plan")
    try:
        plan = read_json(path)
    except (ValueError, OSError):
        raise ToolError("E_PLAN_INVALID", "Plan is not valid JSON.")
    return validate_plan_shape(plan)
