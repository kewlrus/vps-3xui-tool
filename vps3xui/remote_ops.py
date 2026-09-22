#!/usr/bin/env python3
"""Fixed remote stack operations, shipped to the host over stdin.

This is the authoritative coordination point for a source host. It is stdlib
only and never prints file contents or environment values. The CLI, the worker,
the finalizer and ``job recover`` all funnel their coordination through the
shared :mod:`vps3xui.coordination` primitives, so *one* host-wide ``flock``
serialises reservations, launches and recovery.

Commands (argv):

* ``reserve-and-launch ROOT [BASE64]`` -- JSON job/request/plan/launch data on
  stdin (or a base64 argv token). Under the host stack lock: refuse while a prior
  job is still blocking, write the immutable ``request.json``/``plan.json``
  (O_EXCL, no-follow), launch the *fixed* systemd unit built from the supplied
  metadata, and return a bounded JSON result. Omitting ``launch`` reserves
  without launching (used to test the lock itself).
* ``status ROOT JOB_ID`` -- durable, reconciled job status (boot-id and unit
  liveness aware).
* ``blocking ROOT`` -- list jobs that must block new work.
* ``owns ROOT JOB_ID`` -- verify that a job dir carries a valid, owned
  reservation for exactly this request id.
* ``recover ROOT JOB_ID`` -- under the lock, refuse a live unit and launch the
  fixed recover unit for an owned job (works without any local record).
* ``release-note ROOT JOB_ID`` -- record that recovery for a job finished.

Exit codes: 0 success, 2 contract, 3 precondition/conflict, 4 execution.
Result objects carry a stable ``error.code`` on failure.
"""

import base64
import json
import os
import re
import subprocess
import sys

try:  # in-package import (``python3 -m vps3xui.remote_ops``)
    from . import coordination as coord
except Exception:
    coord = None
    try:  # developer convenience: run the file directly from the repo tree
        _repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _repo not in sys.path:
            sys.path.insert(0, _repo)
        from vps3xui import coordination as coord  # type: ignore[no-redef]
    except Exception:
        coord = None
    if coord is None:  # shipped standalone over stdin: primitives are concatenated
        coord = sys.modules[__name__]

EXIT_CONTRACT = 2
EXIT_PRECONDITION = 3
EXIT_EXECUTION = 4

# Mirrors vps3xui.plan; a unit test asserts they stay identical.
RUNTIME_MAX_SECONDS_LIMIT = (60, 3600)
TIMEOUT_STOP_SECONDS_LIMIT = (30, 600)

_UNIT_RE = re.compile(r"^vps3xui-(?:backup|recover)-[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ABS_RE = re.compile(r"^/[A-Za-z0-9._/@:+-]*$")


def _emit(obj, code=0):
    json.dump(obj, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return code


def _error(code, message, resource=None, next_action=None, exit_code=EXIT_PRECONDITION):
    return (
        {
            "schema_version": 1,
            "ok": False,
            "error": {
                "code": code,
                "message": message,
                "resource": resource,
                "next_action": next_action,
            },
        },
        exit_code,
    )


def _ok(obj):
    obj.setdefault("schema_version", 1)
    obj.setdefault("ok", True)
    return (obj, 0)


def _valid_abs_path(value):
    if not isinstance(value, str) or not _ABS_RE.match(value):
        return False
    if ".." in value.split("/") or "//" in value:
        return False
    return True


def _systemd_run_argv(kind, launch):
    """Build the fixed ``systemd-run`` argv from validated launch metadata.

    Returns ``(argv, None)`` on success or ``(None, (code, message))`` when the
    metadata is missing or unsafe. No caller-supplied argv is ever executed.
    """
    if not isinstance(launch, dict):
        return None, ("E_CONTRACT", "Launch metadata must be an object.")
    unit = launch.get("unit_name")
    release_dir = launch.get("release_dir")
    job = launch.get("job_dir")
    if not isinstance(unit, str) or not _UNIT_RE.match(unit):
        return None, ("E_CONTRACT", "Launch unit name is not an approved vps3xui unit.")
    if not _valid_abs_path(release_dir):
        return None, ("E_CONTRACT", "Launch release_dir must be a safe absolute path.")
    if not _valid_abs_path(job) or ".." in job.split("/"):
        return None, ("E_CONTRACT", "Launch job_dir must be a safe absolute path.")
    worker = os.path.join(release_dir, "bin", "vps3xui-worker")
    finalizer = os.path.join(release_dir, "bin", "vps3xui-finalizer")
    if kind == "recover":
        return [
            "systemd-run",
            # Enqueue and return: the recover unit's finalizer acquires the same
            # host stack lock the caller holds while launching.
            "--no-block",
            "--unit=%s" % unit,
            "--property=Type=oneshot",
            "--property=RuntimeMaxSec=900",
            "--property=KillMode=control-group",
            "--property=StandardOutput=journal",
            "--property=StandardError=journal",
            finalizer,
            "--recover",
            "--release-dir",
            release_dir,
            job,
        ], None
    runtime = launch.get("runtime_max_seconds")
    stop = launch.get("timeout_stop_seconds")
    low, high = RUNTIME_MAX_SECONDS_LIMIT
    if not isinstance(runtime, int) or isinstance(runtime, bool) or not (low <= runtime <= high):
        return None, ("E_CONTRACT", "Launch runtime bound is outside the approved range.")
    low, high = TIMEOUT_STOP_SECONDS_LIMIT
    if not isinstance(stop, int) or isinstance(stop, bool) or not (low <= stop <= high):
        return None, ("E_CONTRACT", "Launch stop bound is outside the approved range.")
    return [
        "systemd-run",
        "--unit=%s" % unit,
        "--property=Type=exec",
        "--property=RuntimeMaxSec=%d" % runtime,
        "--property=TimeoutStopSec=%d" % stop,
        "--property=KillMode=control-group",
        # The automatic finalizer runs in *default* mode: only an explicit
        # ``job recover`` may ask for recovery mode, which never upgrades a
        # partial copy to success.
        "--property=ExecStopPost=%s --release-dir %s %s" % (finalizer, release_dir, job),
        "--property=StandardOutput=journal",
        "--property=StandardError=journal",
        worker,
        "--release-dir",
        release_dir,
        job,
    ], None


def _launch(argv):
    """Run the fixed systemd unit. Returns None on success or (code, message)."""
    try:
        proc = subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return ("E_EXECUTION", "The systemd launch command could not be run.")
    if proc.returncode != 0:
        return ("E_EXECUTION", "The systemd launch command failed.")
    return None


def cmd_blocking(root):
    with coord.stack_lock(root):
        blocking = coord.scan_blocking(root)
    return _ok({"blocking": blocking})


def _plan_digest(plan):
    return plan.get("identity") if isinstance(plan, dict) else None


def cmd_reserve_and_launch(root, encoded=None):
    try:
        if encoded:
            raw = base64.b64decode(encoded.encode("ascii")).decode("utf-8")
        else:
            raw = sys.stdin.read()
        payload = json.loads(raw or "{}")
    except (ValueError, UnicodeDecodeError):
        return _error("E_CONTRACT", "Reservation payload is not JSON.", exit_code=EXIT_CONTRACT)
    if not isinstance(payload, dict):
        return _error("E_CONTRACT", "Reservation payload must be an object.", exit_code=EXIT_CONTRACT)
    job_id = payload.get("job_id")
    if not isinstance(job_id, str) or not job_id:
        return _error("E_CONTRACT", "Reservation job_id is required.", exit_code=EXIT_CONTRACT)
    try:
        coord.validate_id(job_id, "job_id")
    except coord.ToolError as error:
        return _error(error.code, error.message, resource=error.resource, exit_code=EXIT_CONTRACT)
    request = payload.get("request")
    plan = payload.get("plan")
    launch = payload.get("launch")
    if not isinstance(request, dict) or not isinstance(plan, dict):
        return _error("E_CONTRACT", "Reservation request/plan must be objects.", exit_code=EXIT_CONTRACT)
    wants_launch = bool(launch)
    argv = None
    if wants_launch:
        argv, problem = _systemd_run_argv("backup", launch)
        if problem is not None:
            return _error(problem[0], problem[1], exit_code=EXIT_CONTRACT)
    if launch:
        if launch.get("job_dir") and os.path.abspath(launch["job_dir"]) != coord.job_dir(root, job_id):
            return _error("E_CONTRACT", "Launch job_dir does not match the reservation.",
                          resource=job_id, exit_code=EXIT_CONTRACT)

    try:
        with coord.stack_lock(root):
            for item in coord.scan_blocking(root):
                if item["job_id"] != job_id:
                    return _error(
                        "E_JOB_INCOMPLETE",
                        "An incomplete job blocks new work until it is resolved with job recover.",
                        resource=item["job_id"], next_action="job_recover")
            job_path = coord.job_dir(root, job_id)
            if os.path.isfile(os.path.join(job_path, coord.REQUEST_FILE)):
                return _resume_existing(root, job_id, job_path, request, launch, argv, wants_launch)
            return _create_and_launch(root, job_id, job_path, request, plan, launch, argv, wants_launch)
    except coord.ToolError as error:
        return _error(error.code, error.message, resource=error.resource, exit_code=EXIT_PRECONDITION)
    except (OSError, ValueError) as exc:
        return _error("E_EXECUTION", "Remote coordination failed (%s)." % type(exc).__name__,
                      exit_code=EXIT_EXECUTION)


def _resume_existing(root, job_id, job_path, request, launch, argv, wants_launch):
    prior = coord.read_request(job_path) or {}
    if (prior.get("plan_digest") != request.get("plan_digest")
            or prior.get("manifest_id") != request.get("manifest_id")):
        return _error("E_REQUEST_ID_CONFLICT",
                      "Request id is already registered for a different plan.",
                      resource=job_id, next_action="use_new_request_id")
    state, corrupt = coord.read_state(job_path)
    if corrupt:
        return _ok({"reserved": False, "existing": True, "job_id": job_id,
                    "state": "unknown", "reconciled": True})
    marker = coord.read_launched(root, job_id)
    if wants_launch and marker is None and state == "accepted":
        # Registration happened but the unit was never launched: finish it now.
        problem = _record_and_launch(root, job_id, launch, argv)
        if problem is not None:
            return _error(problem[0], problem[1], resource=job_id,
                          next_action="inspect_source_job", exit_code=EXIT_EXECUTION)
        return _ok({"reserved": False, "existing": True, "job_id": job_id,
                    "state": state, "reconciled": True, "launched": True})
    if marker is not None and marker.get("phase") == "pending" and state in coord.LIVE_STATES:
        # A launch was attempted but never confirmed. Never launch a second unit;
        # the job needs an explicit, independent recover.
        return _ok({"reserved": False, "existing": True, "job_id": job_id,
                    "state": "interrupted", "reconciled": True,
                    "evidence": "unconfirmed_launch"})
    return _ok({"reserved": False, "existing": True, "job_id": job_id,
                "state": state, "reconciled": True})


def _create_and_launch(root, job_id, job_path, request, plan, launch, argv, wants_launch):
    coord.require_private_dir(job_path, 0o700)
    coord.write_exclusive(os.path.join(job_path, coord.RESERVATION_FILE), {
        "schema_version": coord.RESERVATION_SCHEMA_VERSION,
        "job_id": job_id,
        "plan_digest": request.get("plan_digest"),
        "manifest_id": request.get("manifest_id"),
    })
    coord.write_exclusive(os.path.join(job_path, coord.REQUEST_FILE), request)
    coord.write_exclusive(os.path.join(job_path, coord.PLAN_FILE), plan)
    if isinstance(request.get("manifest"), dict):
        coord.write_exclusive(os.path.join(job_path, coord.MANIFEST_FILE), request["manifest"])
    if wants_launch:
        problem = _record_and_launch(root, job_id, launch, argv)
        if problem is not None:
            return _error(problem[0], problem[1], resource=job_id,
                          next_action="inspect_source_job", exit_code=EXIT_EXECUTION)
    return _ok({"reserved": True, "existing": False, "job_id": job_id, "state": "accepted"})


def _record_and_launch(root, job_id, launch, argv):
    """Record 'pending' before launching so a retry never launches a second unit."""
    unit = launch.get("unit_name")
    boot = coord.boot_id()
    coord.replace_json(os.path.join(coord.job_dir(root, job_id), coord.LAUNCHED_FILE),
                       {"schema_version": coord.RESERVATION_SCHEMA_VERSION, "job_id": job_id,
                        "unit_name": unit, "phase": "pending", "boot_id": boot})
    problem = _launch(argv)
    if problem is None:
        coord.replace_json(os.path.join(coord.job_dir(root, job_id), coord.LAUNCHED_FILE),
                           {"schema_version": coord.RESERVATION_SCHEMA_VERSION, "job_id": job_id,
                            "unit_name": unit, "phase": "launched", "boot_id": boot})
    return problem


def cmd_status(root, job_id):
    try:
        coord.validate_id(job_id, "job_id")
    except coord.ToolError as error:
        return _error(error.code, error.message, resource=error.resource, exit_code=EXIT_CONTRACT)
    job_path = coord.job_dir(root, job_id)
    if not os.path.isdir(job_path):
        return _ok({"job_id": job_id, "state": "unknown",
                    "evidence": "missing_state_and_report", "operation_complete": False})
    state, corrupt = coord.read_state(job_path)
    if corrupt:
        return _ok({"job_id": job_id, "state": "unknown",
                    "evidence": "corrupt_state", "operation_complete": False})
    marker = coord.read_launched(root, job_id)
    evidence = "state_only"
    try:
        present, report = coord.read_json_nofollow(os.path.join(job_path, coord.REPORT_FILE))
        evidence = "state_and_report" if present else "state_only"
    except (ValueError, OSError):
        report = None
    # Completion-evidence consistency: a durable first-cause journal, a failed
    # or missing report, or a stale COMPLETE marker under a non-success state
    # fails closed BEFORE any new work, verify or fetch can read this job as a
    # success. The actionable state is recovery_required; ``job recover`` owns
    # the reconciliation and any marker revocation.
    conflict = coord.completion_conflict(job_path)
    if conflict is not None:
        return _ok({"job_id": job_id, "state": "recovery_required",
                    "evidence": conflict, "operation_complete": False,
                    "report": report})
    # Boot-id / unit liveness reconciliation: a dead unit or a new boot is never
    # eternal "copying".
    if state in coord.LIVE_STATES and marker:
        if marker.get("phase") == "pending":
            # A launch was recorded but never confirmed as started.
            state, evidence = "interrupted", "unconfirmed_launch"
        else:
            current_boot = coord.boot_id()
            if marker.get("boot_id") and current_boot and marker["boot_id"] != current_boot:
                state, evidence = "interrupted", "boot_changed"
            elif marker.get("unit_name"):
                active = coord.unit_active(marker["unit_name"])
                if active is False:
                    state, evidence = "interrupted", "unit_not_active"
    complete = state in coord.COMPLETE_STATES
    if state == "succeeded" and not _has_complete(job_path):
        complete = False
        state = "interrupted"
    return _ok({"job_id": job_id, "state": state, "evidence": evidence,
                "operation_complete": complete, "report": report})


def _has_complete(job_path):
    backup = coord.backup_dir_of(job_path)
    if isinstance(backup, str) and coord.has_complete(backup):
        return True
    return coord.has_complete(job_path)


def cmd_owns(root, job_id):
    try:
        coord.validate_id(job_id, "job_id")
        owned = coord.reservation_owned(root, job_id)
    except coord.ToolError as error:
        return _error(error.code, error.message, resource=error.resource, exit_code=EXIT_CONTRACT)
    return _ok({"job_id": job_id, "owned": owned})


def cmd_recover(root, job_id):
    try:
        coord.validate_id(job_id, "job_id")
    except coord.ToolError as error:
        return _error(error.code, error.message, resource=error.resource, exit_code=EXIT_CONTRACT)
    try:
        with coord.stack_lock(root):
            if not coord.reservation_owned(root, job_id):
                return _error("E_NOT_OWNED", "This job has no valid reservation owned by this host.",
                              resource=job_id, next_action="inspect_remote_state")
            job_path = coord.job_dir(root, job_id)
            request = coord.read_request(job_path) or {}
            live_unit = request.get("unit_name")
            if live_unit and coord.unit_active(live_unit) is True:
                return _error("E_UNIT_BUSY", "The job's unit is still running; recover is refused.",
                              resource=job_id, next_action="wait_for_unit")
            launch = {
                "unit_name": "vps3xui-recover-%s" % job_id,
                "release_dir": request.get("release_dir"),
                "job_dir": job_path,
            }
            argv, problem = _systemd_run_argv("recover", launch)
            if problem is not None:
                return _error(problem[0], problem[1], resource=job_id, exit_code=EXIT_CONTRACT)
            problem = _launch(argv)
            if problem is not None:
                return _error(problem[0], problem[1], resource=job_id,
                              next_action="inspect_source_job", exit_code=EXIT_EXECUTION)
            return _ok({"job_id": job_id, "recovered": True, "unit_name": launch["unit_name"]})
    except coord.ToolError as error:
        return _error(error.code, error.message, resource=error.resource, exit_code=EXIT_PRECONDITION)
    except (OSError, ValueError) as exc:
        return _error("E_EXECUTION", "Remote recovery failed (%s)." % type(exc).__name__,
                      exit_code=EXIT_EXECUTION)


def cmd_release_note(root, job_id):
    try:
        coord.validate_id(job_id, "job_id")
        coord.replace_json(os.path.join(coord.job_dir(root, job_id), coord.RECOVERY_FILE),
                           {"job_id": job_id, "recorded": True})
    except coord.ToolError as error:
        return _error(error.code, error.message, resource=error.resource, exit_code=EXIT_PRECONDITION)
    except (OSError, ValueError):
        return _error("E_STATE_WRITE_FAILED", "Recovery note could not be written.",
                      resource=job_id, exit_code=EXIT_EXECUTION)
    return _ok({"job_id": job_id, "recorded": True})


def main(argv):
    if len(argv) < 3:
        return _error("E_CONTRACT", "remote_ops requires ROOT and a command.",
                      next_action="check_help", exit_code=EXIT_CONTRACT)
    root = argv[1]
    command = argv[2]
    rest = argv[3:]
    try:
        if command == "blocking":
            obj, code = cmd_blocking(root)
        elif command == "reserve-and-launch":
            obj, code = cmd_reserve_and_launch(root, rest[0] if rest else None)
        elif command == "status" and rest:
            obj, code = cmd_status(root, rest[0])
        elif command == "owns" and rest:
            obj, code = cmd_owns(root, rest[0])
        elif command == "recover" and rest:
            obj, code = cmd_recover(root, rest[0])
        elif command == "release-note" and rest:
            obj, code = cmd_release_note(root, rest[0])
        else:
            obj, code = _error("E_CONTRACT", "Unknown remote_ops command.", exit_code=EXIT_CONTRACT)
    except (OSError, ValueError) as exc:
        obj, code = _error("E_EXECUTION", "Remote coordination failed (%s)." % type(exc).__name__,
                           exit_code=EXIT_EXECUTION)
    return _emit(obj, code=code)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
