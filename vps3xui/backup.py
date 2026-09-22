"""Backup orchestration: plan, start, status, verify, fetch, recover.

The local CLI never performs a step-by-step cold backup. It registers the
request locally, then hands the authoritative reservation to the host stack
lock (``vps3xui.remote_ops``), which refuses while any prior job is still
blocking, writes an immutable request/plan and launches the pinned worker.
Every mutating command requires ``--apply`` and re-verifies the machine
binding before any effect.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional

from . import TOOL_VERSION
from .errors import ToolError
from .inventory import compare, probe_spec
from .jobs import JobStore
from .plan import build_plan, load_plan, save_plan, verify_plan
from .release import (
    build_release_archive,
    content_addressed_release_dir,
    release_archive_digest,
)
from .util import ensure_dir, is_symlink, json_digest, require_private_dir, validate_id
from .verify import COMPLETE_NAME, REPORT_NAME, SUMS_NAME, verify_directory

REMOTE_ROOT = "/var/lib/vps3xui"
REMOTE_BACKUPS = "/var/backups/vps3xui"
RELEASE_ROOT = "/opt/vps3xui/releases"
PARTIAL_MARKER = ".partial"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def schema_version() -> int:
    return 1


def _result(command: str, state: str, operation_complete: Optional[bool] = None, **fields: Any) -> Dict[str, Any]:
    if operation_complete is None:
        operation_complete = state in ("succeeded", "verified")
    obj = {
        "schema_version": schema_version(),
        "command": command,
        "state": state,
        "operation_complete": bool(operation_complete),
        "error": None,
    }
    obj.update(fields)
    return obj


def _host_context(host) -> Optional[Dict[str, Any]]:
    """Resolved connection context, when the host implementation exposes it."""
    getter = getattr(host, "host_context", None)
    if getter is None:
        return None
    try:
        return getter()
    except ToolError:
        raise
    except Exception:  # noqa: BLE001 - context is best effort, identity checks still run
        return None


def job_dir(job_id: str) -> str:
    return "%s/jobs/%s" % (REMOTE_ROOT, job_id)


def backup_dir(job_id: str) -> str:
    return "%s/%s" % (REMOTE_BACKUPS, job_id)


def _require_apply(apply: bool, command: str) -> None:
    if not apply:
        raise ToolError(
            "E_CONTRACT",
            "%s changes the source and requires --apply. --apply records intent; it is not human consent." % command,
            resource="apply",
            next_action="confirm_with_owner",
        )


# -- plan -----------------------------------------------------------------
def run_plan(host, manifest, ttl_seconds: int,
             runtime_max_seconds: Optional[int] = None,
             timeout_stop_seconds: Optional[int] = None):
    inventory = host.probe(probe_spec(manifest))
    drift = compare(manifest, inventory)
    drift.raise_if_blocking()
    fingerprint = host.fingerprint()
    kwargs = {}
    if runtime_max_seconds is not None:
        kwargs["runtime_max_seconds"] = runtime_max_seconds
    if timeout_stop_seconds is not None:
        kwargs["timeout_stop_seconds"] = timeout_stop_seconds
    plan = build_plan(manifest, inventory, fingerprint, ttl_seconds=ttl_seconds,
                      host_context=_host_context(host), **kwargs)
    plan["approved"] = manifest.approved
    return plan, drift, inventory, fingerprint


def write_plan(plan: Dict[str, Any], out_path: str) -> None:
    save_plan(plan, out_path)


def plan_result(plan: Dict[str, Any], out_path: str, drift) -> Dict[str, Any]:
    return _result(
        "backup.plan",
        "planned",
        operation_complete=True,
        plan_path=os.path.abspath(out_path),
        plan_digest=plan["identity"],
        expires_at=plan["expires_at"],
        runtime_max_seconds=plan["runtime_max_seconds"],
        timeout_stop_seconds=plan["timeout_stop_seconds"],
        manifest_id=plan["manifest"]["manifest_id"],
        approved=plan.get("approved", False),
        stop_containers=[item["name"] for item in plan["stop_containers"]],
        leave_stopped=plan["leave_stopped"],
        required_artifacts=plan["required_artifacts"],
        space=plan["space"],
        downtime_impact=plan["downtime_impact"],
        warnings=[item.to_object() for item in drift.warnings],
    )


# -- start ----------------------------------------------------------------
def run_start(
    host,
    manifest,
    plan_path: str,
    request_id: str,
    state_dir: Optional[str],
    apply: bool,
) -> Dict[str, Any]:
    _require_apply(apply, "backup start")
    if not manifest.approved:
        raise ToolError(
            "E_MANIFEST_NOT_APPROVED",
            "The manifest is not approved for this inventory; backup completeness is blocked.",
            resource=manifest.manifest_id,
            next_action="approve_inventory",
        )
    validate_id(request_id, "request_id")
    plan = load_plan(plan_path)
    store = JobStore(state_dir)
    with store.lock():
        existing = store.load_request(request_id)
        if existing is not None:
            if (existing.get("plan_digest") != plan["identity"]
                    or existing.get("manifest_id") != manifest.manifest_id):
                raise ToolError(
                    "E_REQUEST_ID_CONFLICT",
                    "Request id is already registered for a different plan.",
                    resource=request_id,
                    next_action="use_new_request_id",
                )
            # A record that never reached a running reservation must be retried,
            # not reported as "unknown" forever.
            if existing.get("state") not in ("registered", "submission_failed"):
                return _reconcile_existing(host, store, existing, request_id)
        store.assert_no_blocking_work(ignoring_request_id=request_id)
        inventory = host.probe(probe_spec(manifest))
        drift = compare(manifest, inventory)
        drift.raise_if_blocking()
        fingerprint = host.fingerprint()
        verify_plan(plan, manifest, inventory, fingerprint, host_context=_host_context(host))

        unit_name = "vps3xui-backup-%s" % request_id
        remote_job = job_dir(request_id)
        remote_backup = backup_dir(request_id)
        archive = build_release_archive(manifest)
        digest = release_archive_digest(archive)
        release_path = content_addressed_release_dir(TOOL_VERSION, digest)
        delivered = host.ensure_release(release_path, archive)

        request_payload = {
            "schema_version": 1,
            "request_id": request_id,
            "job_id": request_id,
            "tool_version": TOOL_VERSION,
            "manifest_id": manifest.manifest_id,
            "manifest_digest": manifest.digest,
            "manifest": manifest.data,
            "plan_digest": plan["identity"],
            "machine_id": inventory.machine_id,
            "host_key_fingerprint": fingerprint,
            "unit_name": unit_name,
            "backup_dir": remote_backup,
            "release_dir": release_path,
            "release_digest": delivered,
            "stop_containers": plan["stop_containers"],
            "leave_stopped": plan["leave_stopped"],
            "runtime_max_seconds": plan["runtime_max_seconds"],
            "timeout_stop_seconds": plan["timeout_stop_seconds"],
            "required_bytes_estimate": int((plan.get("space") or {}).get("required_bytes_estimate") or 0),
            "created_at": plan["created_at"],
        }
        if existing is None:
            store.register_request(
                request_id,
                plan_digest=plan["identity"],
                manifest_id=manifest.manifest_id,
                ssh_alias=manifest.ssh_alias,
                extra={
                    "machine_id": inventory.machine_id,
                    "unit_name": unit_name,
                    "job_dir": remote_job,
                    "backup_dir": remote_backup,
                    "release_dir": release_path,
                },
            )
        else:
            store.update_request(
                request_id,
                machine_id=inventory.machine_id,
                unit_name=unit_name,
                job_dir=remote_job,
                backup_dir=remote_backup,
                release_dir=release_path,
            )
        try:
            reservation = host.reserve_and_launch(
                REMOTE_ROOT,
                remote_job,
                request_payload,
                plan,
                {
                    "unit_name": unit_name,
                    "release_dir": release_path,
                    "job_dir": remote_job,
                    "runtime_max_seconds": plan["runtime_max_seconds"],
                    "timeout_stop_seconds": plan["timeout_stop_seconds"],
                },
            )
        except ToolError as error:
            if error.code in ("E_JOB_INCOMPLETE", "E_REQUEST_ID_CONFLICT"):
                raise
            store.update_request(request_id, state="submission_failed", last_error_code=error.code)
            raise
        state = reservation.get("state") or "accepted"
        store.update_request(
            request_id,
            state=state,
            submitted_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            last_error_code=None,
        )
        return _result(
            "backup.start",
            state,
            operation_complete=False,
            request_id=request_id,
            job_id=request_id,
            unit_name=unit_name,
            backup_dir=remote_backup,
            release_digest=delivered,
            reserved=bool(reservation.get("reserved")),
            resolved_existing=bool(reservation.get("existing")),
            launched=bool(reservation.get("launched")) or bool(reservation.get("reserved")),
        )


def _reconcile_existing(host, store: JobStore, record: Dict[str, Any], job_id: str) -> Dict[str, Any]:
    """A repeated request resolves the authoritative remote state."""
    remote = _remote_status(host, job_id)
    state = remote.get("state") or record.get("state") or "accepted"
    if state != record.get("state"):
        store.update_request(job_id, state=state)
    return _result(
        "backup.start",
        state,
        operation_complete=state in ("succeeded", "failed"),
        request_id=job_id,
        job_id=job_id,
        unit_name=record.get("unit_name"),
        backup_dir=record.get("backup_dir"),
        resolved_existing=True,
        evidence=remote.get("evidence"),
    )


# -- status ---------------------------------------------------------------
def _remote_status(host, job_id: str) -> Dict[str, Any]:
    try:
        return host.remote_job_status(REMOTE_ROOT, job_id)
    except ToolError:
        raise
    except (OSError, ValueError, TypeError) as exc:  # boundary safety
        raise ToolError("E_EXECUTION", "Remote job status could not be read (%s)." % type(exc).__name__,
                        resource=job_id, next_action="inspect_remote_state")


def run_status(host, job_id: str, state_dir: Optional[str]) -> Dict[str, Any]:
    validate_id(job_id, "job_id")
    store = JobStore(state_dir)
    record = store.load_request(job_id) or {}
    remote = _remote_status(host, job_id)
    state = remote.get("state") or "unknown"
    if record and record.get("state") not in (None, state):
        store.update_request(job_id, state=state)
    return _result(
        "job.status",
        state,
        operation_complete=state in ("succeeded", "failed"),
        job_id=job_id,
        unit_name=record.get("unit_name"),
        backup_dir=record.get("backup_dir") or backup_dir(job_id),
        evidence=remote.get("evidence"),
        report=remote.get("report"),
    )


# -- verify ---------------------------------------------------------------
def _verified_remote_request(host, manifest, job_id: str) -> Dict[str, Any]:
    """Validate the job's immutable remote request as the verify authority.

    A fresh client has no local record, so the pinned release and backup path
    come from the host itself. Every binding is checked against the fixed job
    path, the live host key and the local manifest before any path is used.
    """
    def refuse(message: str, code: str = "E_PRECONDITION", resource: str = job_id,
               next_action: str = "inspect_source_job") -> ToolError:
        return ToolError(code, message, resource=resource, next_action=next_action)

    try:
        request = host.read_json_file("%s/request.json" % job_dir(job_id))
    except ToolError:
        raise
    except (OSError, ValueError, TypeError):
        raise refuse("The remote job request is unreadable; verification is refused.")
    if not isinstance(request, dict):
        raise refuse("The remote job has no immutable request; verification is refused.")
    if request.get("job_id") != job_id or request.get("request_id") != job_id:
        raise refuse("The remote request belongs to a different job.")
    expected_fingerprint = request.get("host_key_fingerprint")
    if not expected_fingerprint or expected_fingerprint != host.fingerprint():
        raise refuse("The host key fingerprint does not match the job's registered context.",
                     code="E_HOST_IDENTITY_MISMATCH", resource="host_key", next_action="review_host")
    if (request.get("manifest_id") != manifest.manifest_id
            or request.get("manifest_digest") != manifest.digest
            or not isinstance(request.get("manifest"), dict)
            or json_digest(request["manifest"]) != manifest.digest):
        raise refuse("The remote request is bound to a different manifest.",
                     code="E_CONFLICT", next_action="use_job_manifest")
    version = request.get("tool_version")
    digest = request.get("release_digest")
    if (not isinstance(version, str) or not _VERSION_RE.match(version)
            or not isinstance(digest, str) or not _SHA256_RE.match(digest)
            or request.get("release_dir") != content_addressed_release_dir(version, digest)):
        raise refuse("The remote request has no valid pinned release binding.")
    if request.get("backup_dir") != backup_dir(job_id):
        raise refuse("The remote request names an unexpected backup path.")
    return request


def run_verify_job(host, manifest, job_id: str, state_dir: Optional[str]) -> Dict[str, Any]:
    validate_id(job_id, "job_id")
    store = JobStore(state_dir)
    record = store.load_request(job_id) or {}
    remote = _remote_status(host, job_id)
    state = remote.get("state")
    if state != "succeeded" or not remote.get("operation_complete"):
        return _result(
            "backup.verify",
            "failed",
            operation_complete=False,
            job_id=job_id,
            error={
                "code": "E_VERIFY_FAILED",
                "message": "Source job did not reach a proven success; verification is not meaningful.",
                "resource": job_id,
                "next_action": "inspect_source_job",
            },
        )
    request = _verified_remote_request(host, manifest, job_id)
    remote_job = job_dir(job_id)
    remote_backup = request["backup_dir"]
    remote_release = request["release_dir"]
    # A local record is optional; when present it must agree with the host, so
    # a stale record can neither redirect nor silently mask a divergence.
    for key, value in (("job_dir", remote_job), ("backup_dir", remote_backup),
                       ("release_dir", remote_release)):
        if record.get(key) not in (None, value):
            raise ToolError("E_CONFLICT", "The local job record disagrees with the remote request.",
                            resource=key, next_action="inspect_local_state")
    manifest_path = "%s/manifest.json" % remote_job
    result = host.remote_verify(remote_release, remote_backup, manifest_path)
    ok = bool(result.get("ok"))
    return _result(
        "backup.verify",
        "verified" if ok else "failed",
        operation_complete=ok,
        job_id=job_id,
        backup_dir=remote_backup,
        verification=result,
        error=None if ok else (result.get("error") or {
            "code": "E_VERIFY_FAILED",
            "message": "Remote verification failed.",
            "resource": job_id,
            "next_action": "inspect_source_job",
        }),
    )


def run_verify_directory(manifest, directory: str) -> Dict[str, Any]:
    result = verify_directory(directory, manifest, require_complete=True)
    return _result(
        "backup.verify",
        "verified" if result.ok else "failed",
        operation_complete=result.ok,
        directory=os.path.abspath(directory),
        verification=result.to_object(),
        error=None if result.ok else result.error.to_error_object(),
    )


# -- fetch ----------------------------------------------------------------
def run_fetch(host, manifest, job_id: str, destination: str, state_dir: Optional[str],
              apply: bool) -> Dict[str, Any]:
    _require_apply(apply, "backup fetch")
    validate_id(job_id, "job_id")
    store = JobStore(state_dir)
    record = store.load_request(job_id) or {}
    remote_job = record.get("job_dir") or job_dir(job_id)
    remote_backup = record.get("backup_dir") or backup_dir(job_id)
    status = run_status(host, job_id, state_dir)
    if status["state"] != "succeeded" or not status.get("operation_complete"):
        raise ToolError(
            "E_PRECONDITION",
            "Source job has not proven success; fetch is refused.",
            resource=job_id,
            next_action="inspect_source_job",
        )
    # Preserve symlink components so the checks here and require_private_dir
    # can reject them before writing or changing directory permissions.
    destination = os.path.abspath(destination)
    if os.path.abspath(remote_backup) == destination:
        raise ToolError("E_PRECONDITION", "Destination equals the remote backup path.",
                        resource=os.path.basename(destination), next_action="use_other_destination")
    if is_symlink(destination):
        raise ToolError("E_UNSAFE_PATH", "Destination is a symlink.",
                        resource=os.path.basename(destination), next_action="use_real_path")
    if os.path.isdir(destination) and os.listdir(destination):
        raise ToolError("E_PRECONDITION", "Destination directory is not empty; refusing to overwrite.",
                        resource=os.path.basename(destination), next_action="use_empty_destination")
    require_private_dir(destination, 0o700)
    # A sibling partial marker is written first and removed only after the copy
    # verifies; COMPLETE is fetched last so a verified copy always ends up with
    # it and an interrupted fetch never looks complete.
    partial = destination.rstrip("/") + PARTIAL_MARKER
    if os.path.lexists(partial):
        raise ToolError("E_PRECONDITION", "A previous partial fetch left a marker.",
                        resource=os.path.basename(destination), next_action="use_empty_destination")
    with open(partial, "wb") as handle:
        handle.write(b"partial\n")
    os.chmod(partial, 0o600)

    payload_names = manifest.required_artifacts() + [REPORT_NAME, SUMS_NAME]
    fetched: List[Dict[str, Any]] = []
    try:
        for name in payload_names:
            _fetch_one(host, remote_backup, destination, name)
            fetched.append({"name": name, "size": os.path.getsize(os.path.join(destination, name))})
        interim = verify_directory(destination, manifest, require_complete=False)
        if not interim.ok:
            return _result(
                "backup.fetch", "failed", operation_complete=False,
                job_id=job_id, destination=destination, fetched=fetched,
                verification=interim.to_object(), error=interim.error.to_error_object(),
            )
        _fetch_one(host, remote_backup, destination, COMPLETE_NAME)
        fetched.append({"name": COMPLETE_NAME,
                        "size": os.path.getsize(os.path.join(destination, COMPLETE_NAME))})
    except ToolError as error:
        raise ToolError(
            error.code,
            "Fetch did not complete; the destination holds a partial copy.",
            resource=error.resource or job_id,
            next_action="retry_fetch_to_empty_destination",
        )
    result = verify_directory(destination, manifest, require_complete=True)
    if not result.ok:
        return _result(
            "backup.fetch",
            "failed",
            operation_complete=False,
            job_id=job_id,
            destination=destination,
            fetched=fetched,
            verification=result.to_object(),
            error=result.error.to_error_object(),
        )
    os.unlink(partial)
    return _result(
        "backup.fetch",
        "verified",
        operation_complete=True,
        job_id=job_id,
        destination=destination,
        fetched=fetched,
        verification=result.to_object(),
    )


def _fetch_one(host, remote_backup: str, destination: str, name: str) -> None:
    """Fetch one artifact no-follow, exclusively, then rename into place."""
    final_path = os.path.join(destination, name)
    if os.path.lexists(final_path):
        raise ToolError("E_PRECONDITION", "Refusing to clobber an existing file.",
                        resource=name, next_action="use_empty_destination")
    temp_path = final_path + ".partial"
    host.fetch_file("%s/%s" % (remote_backup, name), temp_path)
    if is_symlink(temp_path) or not os.path.isfile(temp_path):
        raise ToolError("E_UNSAFE_PATH", "Fetched path is not a regular file.",
                        resource=name, next_action="reject_fetch")
    os.chmod(temp_path, 0o600)
    os.replace(temp_path, final_path)


def run_recover(host, job_id: str, state_dir: Optional[str], apply: bool,
                wait_seconds: int = 30) -> Dict[str, Any]:
    """Independent disaster recovery: derive the job from the *remote* state.

    A local record is not required. The pinned release, machine-id and host-key
    fingerprint are read from the remote immutable request, the current host key
    is re-verified, and the fixed recover unit is launched under the host stack
    lock by ``remote_ops``.
    """
    _require_apply(apply, "job recover")
    validate_id(job_id, "job_id")
    store = JobStore(state_dir)
    remote_request = host.read_json_file("%s/jobs/%s/request.json" % (REMOTE_ROOT, job_id))
    if not isinstance(remote_request, dict):
        raise ToolError(
            "E_PRECONDITION",
            "The remote job has no immutable request; recover cannot be derived from the host.",
            resource=job_id,
            next_action="inspect_source_job",
        )
    expected_fingerprint = remote_request.get("host_key_fingerprint")
    live_fingerprint = host.fingerprint()
    if expected_fingerprint and expected_fingerprint != live_fingerprint:
        raise ToolError(
            "E_HOST_IDENTITY_MISMATCH",
            "The host key fingerprint no longer matches the job's registered context.",
            resource="host_key",
            next_action="review_host",
        )
    result = host.remote_recover(REMOTE_ROOT, job_id)
    if isinstance(result, dict) and result.get("ok") is False:
        error = result.get("error") or {}
        raise ToolError(
            error.get("code") or "E_EXECUTION",
            error.get("message") or "Remote recovery could not be launched.",
            resource=error.get("resource"),
            next_action=error.get("next_action"),
        )
    unit_name = (result or {}).get("unit_name") or ("vps3xui-recover-%s" % job_id)
    deadline = time.time() + max(0, wait_seconds)
    status = run_status(host, job_id, state_dir)
    while wait_seconds > 0 and status["state"] not in ("failed", "succeeded") and time.time() < deadline:
        time.sleep(2)
        status = run_status(host, job_id, state_dir)
    state = status["state"]
    if store.load_request(job_id) is not None:
        store.update_request(job_id, state=state)
    return _result(
        "job.recover",
        state,
        operation_complete=state in ("succeeded", "failed"),
        job_id=job_id,
        unit_name=unit_name,
        recovered=True,
        report=status.get("report"),
    )


def release_manifest_digest(manifest) -> str:
    from .util import json_digest

    return json_digest(manifest.data)


def release_digest(archive: bytes) -> str:
    return release_archive_digest(archive)
