"""Shared P1 restore contract: versioned records, identities and stage interfaces.

Every restore stream (plan, prepare, transfer, data, containers, guard,
activation, diagnostics) exchanges the typed records defined here and the
receipts of *verified* steps, never shell commands. The module is pure: it
reads a local backup directory for identity, validates records against the
``config/restore-*.schema.json`` files and raises curated ``ToolError``s. It
performs no SSH, Docker or host writes.

Fail-closed rules fixed by this contract:

* Source identity is never guessed from an alias, reachability or container
  names. A P0 (format 1) backup carries no host key/machine-id, so identity
  comes only from approved manifest pins or an explicitly bound source record.
* A target sharing a machine-id or host key with the source is refused, no
  matter how many aliases point at it.
* A restore job ID is derived from the backup digest and the target identity,
  so every stage plan of one restore names the same job; plans stay short-lived.
* Cutover needs a fresh machine observation of the stopped, fenced source over
  the pinned channel *and* a separate operator attestation. An unreachable
  source is not evidence.
"""

from __future__ import annotations

import datetime
import json
import os
from typing import Any, Dict, Iterable, List, Optional

try:  # Python 3.8+: structural interfaces for independent stream implementations.
    from typing import Protocol
except ImportError:  # pragma: no cover - Python < 3.8 is unsupported anyway
    Protocol = object  # type: ignore

from .. import TOOL_VERSION
from ..errors import ToolError
from ..jsonschema_lite import SchemaError, validate
from ..plan import parse_time
from ..util import is_symlink, json_digest, read_bytes_nofollow, sha256_file, validate_id

RESTORE_SCHEMA_VERSION = 1
# Backup metadata versions this restore understands. Format 1 (P0) has no
# source identity; a future format 2 must add a compatible reader here first.
SUPPORTED_BACKUP_FORMATS = (1,)
BACKUP_METADATA_NAME = "backup.json"
SUMS_NAME = "SHA256SUMS"

DEFAULT_PLAN_TTL_SECONDS = 30 * 60
DEFAULT_CUTOVER_MAX_AGE_SECONDS = 300
CUTOVER_MAX_AGE_LIMITS = (60, 900)
CLOCK_SKEW_SECONDS = 60
JOB_ID_PREFIX = "rst-"

CONFIG_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "config"))
SCHEMA_FILES = {
    "plan": "restore-plan.schema.json",
    "source_record": "restore-source-record.schema.json",
    "request": "restore-request.schema.json",
    "journal_entry": "restore-journal-entry.schema.json",
    "receipt": "restore-receipt.schema.json",
    "source_observation": "restore-source-observation.schema.json",
    "cutover_attestation": "restore-cutover-attestation.schema.json",
}

# -- stages and job states ----------------------------------------------------

STAGES = ("prepare", "stage", "activate", "verify", "certbot_activate")
# Job state after each stage completes with verified receipts.
STAGE_COMPLETE_STATE = {
    "prepare": "prepared",
    "stage": "staged",
    "activate": "activated",
    "verify": "verified",
    "certbot_activate": "certbot_active",
}
# Job states from which a stage may start (or resume after a retry).
STAGE_ENTRY_STATES = {
    "prepare": ("planned", "preparing"),
    "stage": ("prepared", "staging"),
    "activate": ("staged", "activating"),
    "verify": ("activated", "verifying", "verified"),
    "certbot_activate": ("verified", "certbot_activating"),
}
STAGE_RUNNING_STATE = {
    "prepare": "preparing",
    "stage": "staging",
    "activate": "activating",
    "verify": "verifying",
    "certbot_activate": "certbot_activating",
}
TERMINAL_BLOCKING_STATES = ("failed", "recovery_required", "unknown")
JOB_STATES = (
    ("planned",) + tuple(STAGE_RUNNING_STATE.values()) + tuple(STAGE_COMPLETE_STATE.values())
    + TERMINAL_BLOCKING_STATES
)

CHECK_STATUSES = ("passed", "failed", "not_run", "unknown")
STEP_OUTCOMES = ("applied", "not_applied", "failed", "unknown")
OWNERSHIP = ("created_by_job", "preexisting_accepted")
RESOURCE_KINDS = (
    "package", "service_unit", "directory", "file_tree", "volume", "image",
    "container", "writable_layer", "certbot_automation", "payload",
)

# Receipt kinds, the stage that produces them, and what each stage consumes.
RECEIPT_STAGE = {
    "prepared_target": "prepare",
    "verified_payload": "stage",
    "data_restored": "stage",
    "containers_created": "stage",
    "guard_prepared": "stage",
    "activation": "activate",
    "verification_report": "verify",
    "certbot_activated": "certbot_activate",
}
STAGE_REQUIRES = {
    "prepare": (),
    "stage": ("prepared_target",),
    "activate": ("prepared_target", "verified_payload", "data_restored",
                 "containers_created", "guard_prepared"),
    "verify": ("activation",),
    "certbot_activate": ("guard_prepared", "activation", "verification_report"),
}
STAGE_PRODUCES = {
    stage: tuple(kind for kind, owner in sorted(RECEIPT_STAGE.items()) if owner == stage)
    for stage in STAGES
}

# -- supported target platforms -------------------------------------------------

# Bounded matrix, confirmed by the owner (2026-09-23): Ubuntu 24.04 on x86_64
# only, as on the source. ``install_confirmed`` stays False until the installer
# is verified on a real Linux target (P1-04/P1-15); planning accepts the
# platform, but prepare must refuse to install packages before that.
SUPPORTED_PLATFORMS = (
    {
        "platform_id": "ubuntu-24.04-amd64",
        "os_id": "ubuntu",
        "os_version": "24.04",
        "arch": "x86_64",
        "docker_source": "docker-apt-repository",
        "install_confirmed": False,
    },
)


def resolve_platform(os_id: Any, os_version: Any, arch: Any) -> Dict[str, Any]:
    for item in SUPPORTED_PLATFORMS:
        if (item["os_id"], item["os_version"], item["arch"]) == (os_id, os_version, arch):
            return dict(item)
    raise ToolError("E_UNSUPPORTED", "Target OS, release or architecture is not supported for restore.",
                    resource="platform", next_action="choose_supported_target")


def require_install_confirmed(platform_id: str) -> Dict[str, Any]:
    for item in SUPPORTED_PLATFORMS:
        if item["platform_id"] == platform_id:
            if not item["install_confirmed"]:
                raise ToolError("E_PRECONDITION",
                                "Package installation on this platform is not yet confirmed.",
                                resource=platform_id, next_action="confirm_platform")
            return dict(item)
    raise ToolError("E_UNSUPPORTED", "Unknown restore platform.",
                    resource="platform", next_action="choose_supported_target")


# -- time and schema helpers ----------------------------------------------------

def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def format_time(moment: datetime.datetime) -> str:
    return moment.astimezone(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _time(value: Any, what: str) -> datetime.datetime:
    if not isinstance(value, str):
        raise ToolError("E_PLAN_INVALID", "Timestamp is missing.", resource=what)
    try:
        return parse_time(value)
    except ToolError:
        raise ToolError("E_PLAN_INVALID", "Timestamp is malformed.", resource=what)


_SCHEMA_CACHE: Dict[str, Dict[str, Any]] = {}


def load_schema(kind: str) -> Dict[str, Any]:
    if kind not in _SCHEMA_CACHE:
        with open(os.path.join(CONFIG_DIR, SCHEMA_FILES[kind]), "r", encoding="utf-8") as handle:
            _SCHEMA_CACHE[kind] = json.load(handle)
    return _SCHEMA_CACHE[kind]


def check_schema(kind: str, instance: Any, code: str = "E_PLAN_INVALID") -> Dict[str, Any]:
    try:
        validate(instance, load_schema(kind))
    except SchemaError as error:
        # Only the pointer and the fixed message: never the offending value.
        raise ToolError(code, "Restore %s does not match its schema." % kind.replace("_", " "),
                        resource=error.path, next_action="rebuild_input")
    return instance


def record_digest(record: Dict[str, Any], exclude: Iterable[str] = ()) -> str:
    clone = dict(record)
    for key in exclude:
        clone.pop(key, None)
    return json_digest(clone)


# -- backup identity ------------------------------------------------------------

def backup_identity(backup_dir: str, manifest, verified) -> Dict[str, Any]:
    """Identity of a locally verified backup.

    ``verified`` is the ``VerifyResult`` of ``verify.verify_directory`` with
    ``require_complete=True``; the caller runs it so this module stays free of
    archive scanning. The backup digest is the sha256 of ``SHA256SUMS``, which
    covers ``backup.json``, every artifact and the source report.
    """
    if verified is None or not getattr(verified, "ok", False):
        raise ToolError("E_VERIFY_FAILED", "Backup did not pass verification; it cannot be restored.",
                        resource="backup", next_action="verify_backup")
    metadata_path = os.path.join(backup_dir, BACKUP_METADATA_NAME)
    sums_path = os.path.join(backup_dir, SUMS_NAME)
    for path in (metadata_path, sums_path):
        if is_symlink(path) or not os.path.isfile(path):
            raise ToolError("E_MISSING_ARTIFACT", "Backup identity file is missing.",
                            resource=os.path.basename(path), next_action="reject_backup")
    try:
        metadata = json.loads(read_bytes_nofollow(metadata_path).decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        raise ToolError("E_VERIFY_FAILED", "Backup metadata is not valid JSON.",
                        resource=BACKUP_METADATA_NAME, next_action="reject_backup")
    if not isinstance(metadata, dict):
        raise ToolError("E_VERIFY_FAILED", "Backup metadata must be an object.",
                        resource=BACKUP_METADATA_NAME, next_action="reject_backup")
    if metadata.get("schema_version") not in SUPPORTED_BACKUP_FORMATS:
        raise ToolError("E_UNSUPPORTED", "Backup format version is not supported for restore.",
                        resource=BACKUP_METADATA_NAME, next_action="reject_backup")
    if metadata.get("manifest_id") != manifest.manifest_id or metadata.get("manifest_digest") != manifest.digest:
        raise ToolError("E_TRUST_MISMATCH", "Backup was made with a different manifest.",
                        resource="manifest", next_action="select_backup_manifest")
    backup_id = metadata.get("backup_id")
    validate_id(backup_id if isinstance(backup_id, str) else "", "backup_id")
    platform_info = metadata.get("platform") if isinstance(metadata.get("platform"), dict) else {}
    identity = {
        "backup_id": backup_id,
        "backup_digest": sha256_file(sums_path, nofollow=True),
        "format_version": metadata["schema_version"],
        "manifest_id": manifest.manifest_id,
        "manifest_digest": manifest.digest,
        "tool_version": str(metadata.get("tool_version") or "")[:64],
        "created_at": str(metadata.get("created_at") or "")[:40],
        "source_arch": str(platform_info.get("machine") or "")[:32],
        "required_artifacts": manifest.required_artifacts(),
        "reference_only_artifacts": manifest.reference_only_artifacts(),
    }
    if list(metadata.get("required_artifacts") or []) != identity["required_artifacts"]:
        raise ToolError("E_VERIFY_FAILED", "Backup metadata lists a different artifact set.",
                        resource=BACKUP_METADATA_NAME, next_action="reject_backup")
    return identity


# -- source identity ------------------------------------------------------------

def _identity(record: Dict[str, Any]) -> Dict[str, str]:
    return {
        "ssh_alias": record["ssh_alias"],
        "host_key_fingerprint": record["host_key_fingerprint"],
        "machine_id": record["machine_id"],
    }


def resolve_source_identity(
    backup: Dict[str, Any],
    manifest,
    source_record: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Decide the verifiable source identity of a backup, or refuse.

    Accepted evidence, in order: an explicitly bound source record (which must
    agree with any manifest pins) or complete manifest pins of the very manifest
    the backup was made with. A single pin, a mismatch, or nothing is refused.
    """
    if backup.get("manifest_digest") != manifest.digest:
        raise ToolError("E_TRUST_MISMATCH", "Manifest does not belong to this backup.",
                        resource="manifest", next_action="select_backup_manifest")
    pinned_machine = manifest.expected_machine_id
    pinned_key = manifest.expected_host_key_fingerprint
    pins_complete = bool(pinned_machine) and bool(pinned_key)
    if source_record is not None:
        check_schema("source_record", source_record, code="E_TRUST_MISMATCH")
        bound = (
            source_record["backup_id"] == backup["backup_id"]
            and source_record["backup_digest"] == backup["backup_digest"]
            and source_record["manifest_id"] == backup["manifest_id"]
            and source_record["manifest_digest"] == backup["manifest_digest"]
            and source_record["obtained"]["source_job_id"] == backup["backup_id"]
        )
        if not bound:
            raise ToolError("E_TRUST_MISMATCH", "Source record is not bound to this backup.",
                            resource="source_record", next_action="obtain_source_record")
        source = source_record["source"]
        if (pinned_machine and pinned_machine != source["machine_id"]) or (
            pinned_key and pinned_key != source["host_key_fingerprint"]
        ):
            raise ToolError("E_TRUST_MISMATCH", "Source record contradicts the manifest pins.",
                            resource="source_record", next_action="review_source_identity")
        result = _identity(source)
        result["provenance"] = "source_record"
        return result
    if pins_complete:
        return {
            "ssh_alias": manifest.ssh_alias,
            "host_key_fingerprint": pinned_key,
            "machine_id": pinned_machine,
            "provenance": "manifest_pins",
        }
    raise ToolError("E_PRECONDITION",
                    "Source identity of this backup is not established; restore is refused.",
                    resource="source_identity", next_action="provide_source_record")


# -- target facts and job identity ----------------------------------------------

def build_target_facts(
    ssh_alias: str,
    host_key_fingerprint: Optional[str],
    machine_id: Optional[str],
    resolved: Dict[str, Any],
    os_id: Optional[str],
    os_version: Optional[str],
    arch: Optional[str],
) -> Dict[str, Any]:
    if not host_key_fingerprint:
        raise ToolError("E_HOST_KEY_UNKNOWN", "No verified host key is available for the target.",
                        resource="target", next_action="pin_host_key")
    if not machine_id:
        raise ToolError("E_PROBE_INCOMPLETE", "Target machine-id is unknown.",
                        resource="target", next_action="inspect_target")
    platform = resolve_platform(os_id, os_version, arch)
    facts = {
        "ssh_alias": ssh_alias,
        "host_key_fingerprint": host_key_fingerprint,
        "machine_id": machine_id,
        "resolved": dict(resolved or {}),
        "os_id": os_id,
        "os_version": os_version,
        "arch": arch,
        "platform_id": platform["platform_id"],
    }
    try:
        validate(facts, load_schema("plan")["properties"]["target"])
    except SchemaError as error:
        raise ToolError("E_PROBE_INCOMPLETE", "Target facts are malformed.",
                        resource=error.path, next_action="inspect_target")
    return facts


def check_target_distinct(source: Dict[str, Any], target: Dict[str, Any]) -> None:
    """Refuse a target that is the source machine, whatever alias names it."""
    if (source["machine_id"] == target["machine_id"]
            or source["host_key_fingerprint"] == target["host_key_fingerprint"]):
        raise ToolError("E_HOST_IDENTITY_MISMATCH",
                        "Restore target is the source machine; choose a separate target.",
                        resource="target", next_action="choose_separate_target")


def restore_job_id(backup: Dict[str, Any], target: Dict[str, Any]) -> str:
    """Stable job ID: one restore of one backup onto one target machine."""
    digest = json_digest({
        "backup_digest": backup["backup_digest"],
        "manifest_digest": backup["manifest_digest"],
        "target_host_key_fingerprint": target["host_key_fingerprint"],
        "target_machine_id": target["machine_id"],
    })
    return JOB_ID_PREFIX + digest[:24]


# -- restore plan ---------------------------------------------------------------

def plan_resources(manifest) -> Dict[str, List[Any]]:
    """Allowlist of target resources a restore job may create, from the manifest."""
    return {
        "bind_trees": [
            {"artifact": tree["artifact"], "root": tree["root"], "includes": list(tree["includes"])}
            for tree in manifest.bind_trees
        ],
        "volumes": [
            {"name": volume["name"], "driver": volume["driver"], "artifact": volume["artifact"]}
            for volume in manifest.volumes
        ],
        "containers": [
            {
                "name": item["name"],
                "compose_project": item["compose_project"],
                "service": item["service"],
                "expected_state": item["expected_state"],
                "restart_order": item["restart_order"],
            }
            for item in manifest.containers if item.get("included")
        ],
        "images": sorted({
            item["image"]["repo_digest"] for item in manifest.containers
            if item.get("included") and item["image"].get("repo_digest")
        }),
        "writable_layers": [
            {"container": layer["container"], "path": layer["path"], "artifact": layer["artifact"]}
            for layer in manifest.writable_layers
        ],
        "reference_only_artifacts": manifest.reference_only_artifacts(),
    }


def restore_plan_identity(plan: Dict[str, Any]) -> str:
    return record_digest(plan, exclude=("identity", "input_digest"))


def build_restore_plan(
    manifest,
    backup: Dict[str, Any],
    source: Dict[str, Any],
    target: Dict[str, Any],
    operations: Dict[str, List[str]],
    space: Dict[str, int],
    conflicts: Optional[List[Dict[str, Any]]] = None,
    deferred_checks: Optional[List[Dict[str, Any]]] = None,
    input_facts: Optional[Dict[str, Any]] = None,
    now: Optional[datetime.datetime] = None,
    ttl_seconds: int = DEFAULT_PLAN_TTL_SECONDS,
    cutover_max_age_seconds: int = DEFAULT_CUTOVER_MAX_AGE_SECONDS,
) -> Dict[str, Any]:
    """Assemble and validate a plan. Conflicts block: no plan is produced."""
    if conflicts:
        raise ToolError("E_CONFLICT", "Target has conflicting resources; no plan was written.",
                        resource=str(conflicts[0].get("resource", "target"))[:80],
                        next_action="resolve_target_conflicts")
    check_target_distinct(source, target)
    if int(space.get("free_bytes", 0)) < int(space.get("required_bytes", 0)):
        raise ToolError("E_PRECONDITION", "Target does not have the required free space.",
                        resource="disk", next_action="free_space_or_choose_target")
    moment = now or utcnow()
    plan: Dict[str, Any] = {
        "schema_version": RESTORE_SCHEMA_VERSION,
        "command": "restore.plan",
        "role": "target",
        "created_at": format_time(moment),
        "expires_at": format_time(moment + datetime.timedelta(seconds=ttl_seconds)),
        "tool_version": TOOL_VERSION,
        "job_id": restore_job_id(backup, target),
        "manifest": {"manifest_id": manifest.manifest_id, "digest": manifest.digest},
        "backup": dict(backup),
        "source": dict(source),
        "target": dict(target),
        "target_facts_digest": json_digest(target),
        "resources": plan_resources(manifest),
        "operations": {stage: list(operations.get(stage, [])) for stage in
                       ("prepare", "stage", "activate", "certbot_activate")},
        "conflicts": [],
        "deferred_checks": list(deferred_checks or []),
        "space": {"required_bytes": int(space["required_bytes"]), "free_bytes": int(space["free_bytes"])},
        "activation_boundary": {
            "requires_cutover_evidence": True,
            "max_evidence_age_seconds": int(cutover_max_age_seconds),
            "automatic_source_actions": [],
        },
    }
    plan["input_digest"] = json_digest(input_facts if input_facts is not None else {"target": target})
    plan["identity"] = restore_plan_identity(plan)
    return validate_restore_plan(plan)


def validate_restore_plan(plan: Any) -> Dict[str, Any]:
    """Shape, identity and internal consistency; no live facts are needed."""
    if not isinstance(plan, dict):
        raise ToolError("E_PLAN_INVALID", "Restore plan must be a JSON object.", resource="plan")
    check_schema("plan", plan)
    if plan["identity"] != restore_plan_identity(plan):
        raise ToolError("E_PLAN_STALE", "Restore plan identity does not match its contents.",
                        resource="plan", next_action="rebuild_plan")
    if plan["job_id"] != restore_job_id(plan["backup"], plan["target"]):
        raise ToolError("E_PLAN_INVALID", "Restore plan names a job of a different backup or target.",
                        resource="job_id", next_action="rebuild_plan")
    if plan["target_facts_digest"] != json_digest(plan["target"]):
        raise ToolError("E_PLAN_INVALID", "Restore plan target facts digest is inconsistent.",
                        resource="target", next_action="rebuild_plan")
    if plan["manifest"]["digest"] != plan["backup"]["manifest_digest"]:
        raise ToolError("E_PLAN_INVALID", "Restore plan manifest differs from the backup manifest.",
                        resource="manifest", next_action="rebuild_plan")
    if _time(plan["expires_at"], "expires_at") <= _time(plan["created_at"], "created_at"):
        raise ToolError("E_PLAN_INVALID", "Restore plan expiry precedes its creation.",
                        resource="expires_at", next_action="rebuild_plan")
    resolve_platform(plan["target"]["os_id"], plan["target"]["os_version"], plan["target"]["arch"])
    check_target_distinct(plan["source"], plan["target"])
    return plan


def verify_restore_plan(
    plan: Dict[str, Any],
    manifest,
    backup: Dict[str, Any],
    target_live: Dict[str, Any],
    now: Optional[datetime.datetime] = None,
) -> None:
    """Re-check a plan against live target facts before any stage writes."""
    validate_restore_plan(plan)
    moment = now or utcnow()
    if moment > _time(plan["expires_at"], "expires_at"):
        raise ToolError("E_PLAN_EXPIRED", "Restore plan has expired; build a fresh plan.",
                        resource="plan", next_action="rebuild_plan")
    if plan["tool_version"] != TOOL_VERSION:
        raise ToolError("E_PLAN_STALE", "Restore plan was built by a different tool version.",
                        resource="tool_version", next_action="rebuild_plan")
    if plan["manifest"] != {"manifest_id": manifest.manifest_id, "digest": manifest.digest}:
        raise ToolError("E_PLAN_STALE", "Restore plan was built for a different manifest.",
                        resource="manifest", next_action="rebuild_plan")
    if plan["backup"] != backup:
        raise ToolError("E_PLAN_STALE", "Restore plan was built for a different backup.",
                        resource="backup", next_action="rebuild_plan")
    planned = plan["target"]
    if target_live.get("host_key_fingerprint") != planned["host_key_fingerprint"]:
        raise ToolError("E_HOST_IDENTITY_MISMATCH", "Target host key changed since the plan was built.",
                        resource="host_key", next_action="review_host")
    if target_live.get("machine_id") != planned["machine_id"]:
        raise ToolError("E_HOST_IDENTITY_MISMATCH", "Target machine-id changed since the plan was built.",
                        resource="machine-id", next_action="review_host")
    if dict(target_live.get("resolved") or {}) != planned["resolved"]:
        raise ToolError("E_HOST_IDENTITY_MISMATCH",
                        "Resolved target connection changed since the plan was built.",
                        resource="ssh_context", next_action="rebuild_plan")
    if json_digest(target_live) != plan["target_facts_digest"]:
        raise ToolError("E_PLAN_STALE", "Target facts changed since the plan was built.",
                        resource="target", next_action="rebuild_plan")


# -- immutable request and retry ------------------------------------------------

def build_restore_request(plan: Dict[str, Any], release_digest: str,
                          now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    validate_restore_plan(plan)
    request = {
        "schema_version": RESTORE_SCHEMA_VERSION,
        "kind": "vps3xui.restore.request",
        "job_id": plan["job_id"],
        "initial_plan_identity": plan["identity"],
        "backup_digest": plan["backup"]["backup_digest"],
        "manifest_digest": plan["manifest"]["digest"],
        "source": _identity(plan["source"]),
        "target": _identity(plan["target"]),
        "tool_version": plan["tool_version"],
        "release_digest": release_digest,
        "created_at": format_time(now or utcnow()),
    }
    return check_schema("request", request)


def request_matches_plan(request: Dict[str, Any], plan: Dict[str, Any]) -> str:
    """Retry rule for ``--plan``: same job, backup, source and target resumes.

    Returns ``"resume"``. The request is immutable; a later stage plan with a
    new identity is accepted only while every binding field is unchanged.
    """
    check_schema("request", request)
    validate_restore_plan(plan)
    if request["job_id"] != plan["job_id"]:
        raise ToolError("E_REQUEST_ID_CONFLICT", "Plan names a different restore job.",
                        resource="job_id", next_action="use_matching_plan")
    same = (
        request["backup_digest"] == plan["backup"]["backup_digest"]
        and request["manifest_digest"] == plan["manifest"]["digest"]
        and request["source"] == _identity(plan["source"])
        and request["target"] == _identity(plan["target"])
    )
    if not same:
        raise ToolError("E_REQUEST_ID_CONFLICT",
                        "Existing restore job was registered with different bindings.",
                        resource=request["job_id"], next_action="inspect_restore_job")
    if request["tool_version"] != plan["tool_version"]:
        # An active job never switches code: a new tool version must not resume it.
        raise ToolError("E_PLAN_STALE", "Restore job belongs to a different tool version.",
                        resource="tool_version", next_action="use_job_release")
    return "resume"


def check_stage_entry(job_state: str, stage: str) -> None:
    if stage not in STAGES:
        raise ToolError("E_CONTRACT", "Unknown restore stage.", resource="stage")
    if job_state in TERMINAL_BLOCKING_STATES:
        raise ToolError("E_JOB_INCOMPLETE", "Restore job needs recovery or review before continuing.",
                        resource=job_state, next_action="inspect_restore_job")
    if job_state not in STAGE_ENTRY_STATES[stage]:
        raise ToolError("E_PRECONDITION", "Restore job is not at the boundary for this stage.",
                        resource=job_state, next_action="run_previous_stage")


# -- step and ownership journal -------------------------------------------------

def journal_intent(job_id: str, seq: int, step_id: str, stage: str, kind: str, resource: str,
                   ownership: str, expected: Dict[str, Any],
                   now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    """Durable intent, written *before* the effect."""
    entry = {
        "schema_version": RESTORE_SCHEMA_VERSION,
        "job_id": job_id,
        "seq": seq,
        "step_id": step_id,
        "stage": stage,
        "phase": "intent",
        "kind": kind,
        "resource": resource,
        "ownership": ownership,
        "expected": dict(expected),
        "recorded_at": format_time(now or utcnow()),
    }
    return check_schema("journal_entry", entry, code="E_STATE_WRITE_FAILED")


def journal_outcome(intent: Dict[str, Any], seq: int, outcome: str, observed: Optional[Dict[str, Any]],
                    error: Optional[Dict[str, Any]] = None,
                    now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    """Outcome from *observed* state; ``applied`` without an observation is refused."""
    if outcome == "applied" and not observed:
        raise ToolError("E_CONTRACT", "An applied step needs an observed result.",
                        resource=intent["step_id"])
    entry = dict(intent)
    entry.update({
        "seq": seq,
        "phase": "outcome",
        "observed": dict(observed) if observed is not None else None,
        "outcome": outcome,
        "error": dict(error) if error is not None else None,
        "recorded_at": format_time(now or utcnow()),
    })
    return check_schema("journal_entry", entry, code="E_STATE_WRITE_FAILED")


def replay_journal(entries: List[Dict[str, Any]], job_id: str) -> Dict[str, Dict[str, Any]]:
    """Validate a journal and return the state of every step.

    An intent with no outcome is ``unknown``: the effect may or may not have
    happened and the step needs reconciliation, never an assumed success.
    """
    steps: Dict[str, Dict[str, Any]] = {}
    expected_seq = 1
    for entry in entries:
        check_schema("journal_entry", entry, code="E_RECOVERY_REQUIRED")
        if entry["job_id"] != job_id:
            raise ToolError("E_NOT_OWNED", "Journal entry belongs to a different job.",
                            resource=entry["step_id"], next_action="inspect_restore_job")
        if entry["seq"] != expected_seq:
            raise ToolError("E_RECOVERY_REQUIRED", "Journal sequence is broken.",
                            resource=entry["step_id"], next_action="inspect_restore_job")
        expected_seq += 1
        step = steps.get(entry["step_id"])
        if entry["phase"] == "intent":
            if step is not None and step["outcome"] != "not_applied" and step["outcome"] != "failed":
                raise ToolError("E_RECOVERY_REQUIRED", "Step was re-attempted without a settled outcome.",
                                resource=entry["step_id"], next_action="inspect_restore_job")
            steps[entry["step_id"]] = {
                "stage": entry["stage"], "kind": entry["kind"], "resource": entry["resource"],
                "ownership": entry["ownership"], "expected": entry["expected"],
                "outcome": "unknown", "observed": None, "error": None,
            }
            continue
        if step is None or step["outcome"] != "unknown":
            raise ToolError("E_RECOVERY_REQUIRED", "Journal outcome has no open intent.",
                            resource=entry["step_id"], next_action="inspect_restore_job")
        for field in ("stage", "kind", "resource", "ownership", "expected"):
            if entry[field] != step[field]:
                raise ToolError("E_RECOVERY_REQUIRED", "Journal outcome contradicts its intent.",
                                resource=entry["step_id"], next_action="inspect_restore_job")
        step.update({"outcome": entry["outcome"], "observed": entry.get("observed"),
                     "error": entry.get("error")})
    return steps


def owned_resources(steps: Dict[str, Dict[str, Any]]) -> List[Dict[str, str]]:
    """Resources this job may later clean up: created by it and possibly present.

    ``preexisting_accepted`` resources are never owned, and a step that did not
    apply leaves nothing to own.
    """
    owned = []
    for step_id in sorted(steps):
        step = steps[step_id]
        if step["ownership"] == "created_by_job" and step["outcome"] in ("applied", "unknown"):
            owned.append({"step_id": step_id, "kind": step["kind"], "resource": step["resource"],
                          "outcome": step["outcome"]})
    return owned


# -- stage receipts -------------------------------------------------------------

def build_receipt(kind: str, plan: Dict[str, Any], steps: Dict[str, Dict[str, Any]],
                  step_ids: List[str], observed: Dict[str, Any],
                  now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    """Receipt of verified steps. Every named step must be journaled as applied."""
    if kind not in RECEIPT_STAGE:
        raise ToolError("E_CONTRACT", "Unknown receipt kind.", resource="receipt")
    if not observed:
        raise ToolError("E_CONTRACT", "A receipt needs observed state.", resource=kind)
    for step_id in step_ids:
        step = steps.get(step_id)
        if step is None or step["outcome"] != "applied" or step["stage"] != RECEIPT_STAGE[kind]:
            raise ToolError("E_VERIFY_FAILED", "Receipt names a step without a verified result.",
                            resource=step_id, next_action="inspect_restore_job")
    receipt = {
        "schema_version": RESTORE_SCHEMA_VERSION,
        "kind": kind,
        "job_id": plan["job_id"],
        "stage": RECEIPT_STAGE[kind],
        "plan_identity": plan["identity"],
        "backup_digest": plan["backup"]["backup_digest"],
        "target": {
            "host_key_fingerprint": plan["target"]["host_key_fingerprint"],
            "machine_id": plan["target"]["machine_id"],
        },
        "steps": list(step_ids),
        "observed": dict(observed),
        "verified": True,
        "created_at": format_time(now or utcnow()),
    }
    receipt["receipt_digest"] = record_digest(receipt, exclude=("receipt_digest",))
    return check_schema("receipt", receipt, code="E_VERIFY_FAILED")


def validate_receipt(receipt: Any, request: Dict[str, Any], kind: str) -> Dict[str, Any]:
    """A consumer accepts only a receipt of its own job, backup and target."""
    if not isinstance(receipt, dict):
        raise ToolError("E_VERIFY_FAILED", "Receipt is missing.", resource=kind,
                        next_action="run_previous_stage")
    check_schema("receipt", receipt, code="E_VERIFY_FAILED")
    if receipt["kind"] != kind or receipt["stage"] != RECEIPT_STAGE[kind]:
        raise ToolError("E_VERIFY_FAILED", "Receipt is of a different kind.", resource=kind)
    if receipt["receipt_digest"] != record_digest(receipt, exclude=("receipt_digest",)):
        raise ToolError("E_VERIFY_FAILED", "Receipt digest does not match its contents.",
                        resource=kind, next_action="inspect_restore_job")
    bound = (
        receipt["job_id"] == request["job_id"]
        and receipt["backup_digest"] == request["backup_digest"]
        and receipt["target"]["host_key_fingerprint"] == request["target"]["host_key_fingerprint"]
        and receipt["target"]["machine_id"] == request["target"]["machine_id"]
    )
    if not bound:
        raise ToolError("E_NOT_OWNED", "Receipt belongs to a different job, backup or target.",
                        resource=kind, next_action="inspect_restore_job")
    return receipt


def check_stage_inputs(stage: str, receipts: Dict[str, Any], request: Dict[str, Any]) -> None:
    for kind in STAGE_REQUIRES[stage]:
        validate_receipt(receipts.get(kind), request, kind)


# -- cutover evidence ------------------------------------------------------------

def _fresh(observed_at: str, now: datetime.datetime, max_age: int, what: str) -> None:
    moment = _time(observed_at, what)
    if moment - now > datetime.timedelta(seconds=CLOCK_SKEW_SECONDS):
        raise ToolError("E_PRECONDITION", "Cutover evidence is dated in the future.",
                        resource=what, next_action="collect_cutover_evidence")
    if now - moment > datetime.timedelta(seconds=max_age):
        raise ToolError("E_PRECONDITION", "Cutover evidence is too old.",
                        resource=what, next_action="collect_cutover_evidence")


def _source_fenced(observation: Dict[str, Any], plan: Dict[str, Any]) -> None:
    included = sorted(item["name"] for item in plan["resources"]["containers"])
    by_name = {}
    for item in observation["containers"]:
        if item["name"] in by_name:
            raise ToolError("E_PRECONDITION", "Source observation lists a container twice.",
                            resource="source", next_action="collect_cutover_evidence")
        by_name[item["name"]] = item
    missing = [name for name in included if name not in by_name]
    if missing:
        raise ToolError("E_PRECONDITION", "Source observation does not cover every container.",
                        resource=missing[0], next_action="collect_cutover_evidence")
    for name in included:
        item = by_name[name]
        if item["present"] and item["running"] is not False:
            # ``None`` is an unknown run state: not proof of a stop.
            raise ToolError("E_PRECONDITION", "Source container is not proven stopped.",
                            resource=name, next_action="stop_source")
    method = observation["fencing"]["method"]
    if method == "docker_units_masked":
        for unit in ("service", "socket"):
            state = observation["docker"][unit]
            if state["load_state"] != "masked" or state["active_state"] != "inactive":
                raise ToolError("E_PRECONDITION", "Source Docker is not masked and inactive.",
                                resource="docker.%s" % unit, next_action="fence_source")
    else:
        for name in included:
            item = by_name[name]
            if item["present"] and item["restart_policy"] != "no":
                raise ToolError("E_PRECONDITION", "Source container can restart on its own.",
                                resource=name, next_action="fence_source")


def evaluate_cutover(
    observation: Optional[Dict[str, Any]],
    attestation: Optional[Dict[str, Any]],
    request: Dict[str, Any],
    plan: Dict[str, Any],
    now: Optional[datetime.datetime] = None,
) -> Dict[str, Any]:
    """Accept cutover only with both a machine observation and an operator attestation.

    The observation must come over the pinned channel from the recorded source
    identity; an unreachable source yields no observation and is refused.
    """
    if observation is None:
        raise ToolError("E_PRECONDITION",
                        "No machine observation of the stopped source; lack of a connection is not evidence.",
                        resource="source", next_action="collect_cutover_evidence")
    if attestation is None:
        raise ToolError("E_PRECONDITION", "Operator cutover attestation is missing.",
                        resource="attestation", next_action="record_operator_decision")
    check_schema("source_observation", observation, code="E_PRECONDITION")
    check_schema("cutover_attestation", attestation, code="E_PRECONDITION")
    validate_restore_plan(plan)
    moment = now or utcnow()
    max_age = int(plan["activation_boundary"]["max_evidence_age_seconds"])
    if request["job_id"] != plan["job_id"]:
        raise ToolError("E_REQUEST_ID_CONFLICT", "Plan names a different restore job.", resource="job_id")
    observed_source = observation["source"]
    if (observed_source["machine_id"] != request["source"]["machine_id"]
            or observed_source["host_key_fingerprint"] != request["source"]["host_key_fingerprint"]):
        raise ToolError("E_HOST_IDENTITY_MISMATCH", "Observation is not from the recorded source.",
                        resource="source", next_action="collect_cutover_evidence")
    if (observed_source["machine_id"] == request["target"]["machine_id"]
            or observed_source["host_key_fingerprint"] == request["target"]["host_key_fingerprint"]):
        raise ToolError("E_HOST_IDENTITY_MISMATCH", "Observation came from the target, not the source.",
                        resource="source", next_action="collect_cutover_evidence")
    if not observation["probe_complete"]:
        raise ToolError("E_PROBE_INCOMPLETE", "Source observation is incomplete.",
                        resource="source", next_action="collect_cutover_evidence")
    _fresh(observation["observed_at"], moment, max_age, "observation")
    _source_fenced(observation, plan)
    if attestation["job_id"] != request["job_id"] or attestation["plan_identity"] != plan["identity"]:
        raise ToolError("E_PRECONDITION", "Operator attestation is for a different job or plan.",
                        resource="attestation", next_action="record_operator_decision")
    _fresh(attestation["attested_at"], moment, max_age, "attestation")
    if attestation["operator_decision"]["cutover_permitted"] is not True:
        raise ToolError("E_PRECONDITION", "Operator has not permitted cutover.",
                        resource="attestation", next_action="record_operator_decision")
    if attestation["independent_control_channel"]["confirmed"] is not True:
        raise ToolError("E_PRECONDITION", "Independent source control channel is not confirmed.",
                        resource="attestation", next_action="confirm_control_channel")
    return {
        "observation_digest": json_digest(observation),
        "attestation_digest": json_digest(attestation),
        "fencing_method": observation["fencing"]["method"],
        "observed_at": observation["observed_at"],
        "attested_at": attestation["attested_at"],
        "evaluated_at": format_time(moment),
    }


# -- diagnostics ----------------------------------------------------------------

# Machine checks the verify stage runs; manual ones are only ever reported,
# never inferred. ``required`` machine checks decide the overall result.
DIAGNOSTIC_CHECKS = {
    "target_identity": {"source": "machine", "required": True},
    "containers_running": {"source": "machine", "required": True},
    "container_digests": {"source": "machine", "required": True},
    "mounts_and_volumes": {"source": "machine", "required": True},
    "local_listeners": {"source": "machine", "required": True},
    "response_from_target": {"source": "machine", "required": True},
    "certbot_timer_inactive": {"source": "machine", "required": True},
    "model_generation": {"source": "manual", "required": False},
    "telegram_client": {"source": "manual", "required": False},
    "acme_challenge": {"source": "manual", "required": False},
}


def build_verification_report(job_id: str, checks: Dict[str, str]) -> Dict[str, Any]:
    """Status per check; missing machine checks are ``unknown``, manual ``not_run``."""
    statuses: Dict[str, str] = {}
    for name, spec in sorted(DIAGNOSTIC_CHECKS.items()):
        status = checks.get(name, "unknown" if spec["source"] == "machine" else "not_run")
        if status not in CHECK_STATUSES:
            raise ToolError("E_CONTRACT", "Unknown diagnostic status.", resource=name)
        if spec["source"] == "manual" and status == "passed":
            # A manual check cannot be marked passed by a machine run.
            raise ToolError("E_CONTRACT", "Manual checks are reported, not machine-passed.",
                            resource=name)
        statuses[name] = status
    unknown = sorted(set(checks) - set(DIAGNOSTIC_CHECKS))
    if unknown:
        raise ToolError("E_CONTRACT", "Unknown diagnostic check.", resource=unknown[0])
    required = [name for name, spec in DIAGNOSTIC_CHECKS.items() if spec["required"]]
    if any(statuses[name] == "failed" for name in required):
        overall = "failed"
    elif all(statuses[name] == "passed" for name in required):
        overall = "passed"
    else:
        overall = "unknown"
    return {
        "schema_version": RESTORE_SCHEMA_VERSION,
        "job_id": job_id,
        "overall": overall,
        "machine_checks": {n: s for n, s in statuses.items() if DIAGNOSTIC_CHECKS[n]["source"] == "machine"},
        "manual_checks": {n: s for n, s in statuses.items() if DIAGNOSTIC_CHECKS[n]["source"] == "manual"},
    }


# -- stream interfaces ------------------------------------------------------------

class StageContext(object):
    """What the orchestrator hands to a stream: typed records, no shell."""

    def __init__(self, request: Dict[str, Any], plan: Dict[str, Any],
                 receipts: Dict[str, Dict[str, Any]], journal) -> None:
        self.request = request
        self.plan = plan
        self.receipts = receipts
        # ``journal`` provides ``intent(...)`` / ``outcome(...)`` backed by the
        # durable job store (P1-02); streams never write job state directly.
        self.journal = journal


class RestorePlanner(Protocol):
    def build(self, backup_dir: str, manifest, target_alias: str,
              source_record: Optional[Dict[str, Any]]) -> Dict[str, Any]: ...


class TargetPreparer(Protocol):
    """prepare: platform, Docker from the verified adapter, no renewal started."""
    def prepare(self, context: StageContext) -> Dict[str, Any]: ...  # -> prepared_target


class PayloadTransfer(Protocol):
    """transfer: copy + target-side verify of the exact artifact set."""
    def transfer(self, context: StageContext, backup_dir: str) -> Dict[str, Any]: ...  # -> verified_payload


class DataStager(Protocol):
    def restore_data(self, context: StageContext) -> Dict[str, Any]: ...  # -> data_restored


class ContainerStager(Protocol):
    """Pull by digest, create from Compose, apply both Fail2ban layers; stay stopped."""
    def create_containers(self, context: StageContext) -> Dict[str, Any]: ...  # -> containers_created


class GuardPreparer(Protocol):
    def prepare_guard(self, context: StageContext) -> Dict[str, Any]: ...  # -> guard_prepared


class Activator(Protocol):
    def activate(self, context: StageContext, cutover: Dict[str, Any]) -> Dict[str, Any]: ...  # -> activation


class Diagnostics(Protocol):
    def verify(self, context: StageContext) -> Dict[str, Any]: ...  # -> verification_report
