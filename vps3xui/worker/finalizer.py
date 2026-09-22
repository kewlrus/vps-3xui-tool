"""Independent, idempotent finalizer / recovery runner.

Used two ways:

* as the systemd ``ExecStopPost`` for the backup unit (default mode), so the
  original containers and timer state are restored even if the worker is
  killed by ``RuntimeMaxSec``, ``SIGKILL`` or a host-side failure;
* as ``job recover`` on the host, to finish recovery of a job whose evidence
  shows ``recovery_required`` or ``unknown``.

Only this process may publish the ``COMPLETE`` marker, and it does so last and
only after its own final evidence checks. It never converts a failed backup
into a success, preserves the worker's original failure and the unit's own
result separately, and attempts recovery even when the worker died abruptly.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
from typing import Any, Dict, Optional, Tuple

from .. import coordination as coord
from ..errors import ToolError
from ..jobs import COMPLETE_STATES
from . import failure_journal, jobctx
from .jobctx import (
    COMPLETE_MARKER,
    INITIAL_STATE_FILE,
    REPORT_FILE,
    REQUEST_FILE,
    STATE_FILE,
    JobContext,
    now_iso,
)

_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)

# Mirrored from ``backup_worker`` (the shipped standalone modules cannot share a
# helper): the fields the worker writes into ``report.json`` to prove durably
# that a caught failure began no host effect.
PREFLIGHT_EVIDENCE_KEY = "preflight_evidence"
PRE_EFFECT_PHASES = ("accepted", "preflight")
PRE_EFFECT_STATES = ("accepted", "preflight", "failed")
NO_EFFECTS_REASON = "no_effects_preflight_failure"


def _read_initial_state(ctx: JobContext) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Read ``initial-state.json``, distinguishing absent from untrustworthy.

    Returns ``(recorded_state_or_None, problem_or_None)``: a genuinely absent
    file is ``(None, None)``, while a present file that is a symlink, corrupt,
    not an object or an empty object is ``(None, <short reason>)``. A
    present-but-untrusted file must never be read as absence by the no-effects
    fastpath; an object with a missing/malformed field is still returned so the
    existing identity gate classifies it (``recovery_required``).
    """
    try:
        present, value = coord.read_json_nofollow(ctx.path(INITIAL_STATE_FILE))
    except (ValueError, OSError):
        return None, "initial_state_unreadable"
    if not present:
        return None, None
    if not isinstance(value, dict) or not value:
        return None, "initial_state_malformed"
    return value, None


def _proven_no_effects(ctx: JobContext, report: Dict[str, Any], request: Dict[str, Any],
                       state: str, initial: Optional[Dict[str, Any]],
                       initial_problem: Optional[str], auth_problem: Optional[str],
                       marker_present: bool, reported_marker: bool,
                       conflict: Optional[str], pending_revocation: bool) -> bool:
    """True only for a durable, fully agreeing proof that no effect ever began.

    Every piece of independent evidence must agree: the worker's explicit
    ``effects_started == false`` record in a pre-effects phase, bound to this
    job, request id and plan digest; no produced copy; no ``COMPLETE`` anywhere;
    no contradictory completion conflict and no pending revocation; the request
    backup directory absent (never created) and a recorded original state, if
    any, that never advanced past preflight (Certbot/lease unrecorded). Anything
    missing, mismatched or inconsistent returns False so the job stays
    ``unknown``/``recovery_required`` and cannot bypass the F3 gates.
    """
    if initial_problem is not None:
        return False
    # The request-authoritative backup directory must never have been created.
    if auth_problem != "backup_dir_missing":
        return False
    if conflict is not None or pending_revocation:
        return False
    if marker_present or reported_marker:
        return False
    if _copy_produced(report, state):
        return False
    if state not in PRE_EFFECT_STATES:
        return False
    if initial is not None:
        # A present recorded state must look like the preflight snapshot and
        # must never have advanced into quiesce: a missing/malformed machine
        # identity or a recorded Certbot/lease phase means effects may have
        # begun, so the identity-gated recovery path must run instead.
        machine = initial.get("machine_id")
        if not isinstance(machine, str) or not machine.strip():
            return False
        if initial.get("certbot") is not None or initial.get("lease_active") is not None:
            return False
    evidence = report.get(PREFLIGHT_EVIDENCE_KEY) if isinstance(report, dict) else None
    if not isinstance(evidence, dict):
        return False
    if evidence.get("effects_started") is not False:
        return False
    if evidence.get("phase") not in PRE_EFFECT_PHASES:
        return False
    job_id = os.path.basename(os.path.abspath(ctx.job_dir).rstrip("/"))
    if report.get("job_id") != job_id or evidence.get("job_id") != job_id:
        return False
    if not isinstance(request, dict):
        return False
    request_id = request.get("request_id") or request.get("job_id")
    if not isinstance(request_id, str) or evidence.get("request_id") != request_id:
        return False
    plan_digest = request.get("plan_digest")
    if not isinstance(plan_digest, str) or evidence.get("plan_digest") != plan_digest:
        return False
    return True


def _load_primary_failure(ctx: JobContext):
    """Read the durable primary failure journal independently of the report.

    Returns ``(failure, problem)``. A missing journal returns ``(None, None)``
    so the caller falls back to ``report["original_failure"]``. A journal that
    is present but cannot be read as the expected object fails closed with a
    shared, curated problem that never carries the raw contents; the file is
    left in place and the identity-gated recovery attempt still runs. The
    classification is the same helper the worker writes through, so a valid
    first cause, a legacy minimal journal and a wrong-job or malformed record
    are all interpreted identically on both sides.
    """
    state = failure_journal.read_state(ctx.job_dir, os.path.basename(ctx.job_dir))
    if state["status"] == failure_journal.ABSENT:
        return None, None
    if state["status"] == failure_journal.VALID:
        return state["failure"], None
    return None, failure_journal.problem(state["reason"])


def _proven_success(ctx: JobContext, backup_dir: str, manifest) -> Optional[ToolError]:
    """Final evidence checks before COMPLETE is allowed to exist."""
    from ..verify import verify_directory

    if not backup_dir or not os.path.isdir(backup_dir):
        return ToolError("E_MISSING_ARTIFACT", "The backup directory is missing.",
                         resource="backup", next_action="inspect_source_job")
    result = verify_directory(backup_dir, manifest, require_complete=False)
    if not result.ok:
        return result.error or ToolError("E_VERIFY_FAILED", "Final verification failed.",
                                         resource="backup")
    marker = os.path.join(backup_dir, COMPLETE_MARKER)
    if os.path.islink(marker):
        return ToolError("E_UNSAFE_PATH", "COMPLETE marker is a symlink.", resource="COMPLETE")
    return None


def _read_report(ctx: JobContext) -> Tuple[Dict[str, Any], Optional[str]]:
    """Read ``report.json`` strictly; ``(object, None)`` or ``({}, reason)``."""
    try:
        present, value = coord.read_json_nofollow(ctx.path(REPORT_FILE))
    except (ValueError, OSError):
        return {}, "report_corrupt"
    if not present:
        return {}, "report_missing"
    if not isinstance(value, dict):
        return {}, "report_corrupt"
    return value, None


def _authoritative_backup_dir(ctx: JobContext, request: Dict[str, Any],
                              report: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """Resolve this job's immutable backup directory for a completion decision.

    The request's ``backup_dir`` is the authority; the report may only agree.
    Returns ``(path, None)`` or ``(None, problem)``. A missing/relative binding,
    a report disagreement, a symlink component anywhere in the path, a non
    directory, or backup metadata that names another job or manifest refuses
    without touching the filesystem -- the caller must not guess a target.
    """
    requested = request.get("backup_dir") if isinstance(request, dict) else None
    if not isinstance(requested, str) or not requested.startswith("/"):
        return None, "backup_dir_unrecorded"
    candidate = os.path.abspath(requested)
    job_id = os.path.basename(ctx.job_dir)
    reported = report.get("backup_dir") if isinstance(report, dict) else None
    if isinstance(reported, str) and reported and os.path.abspath(reported) != candidate:
        return None, "backup_dir_conflict"
    bound_job = report.get("job_id") if isinstance(report, dict) else None
    if isinstance(bound_job, str) and bound_job and bound_job != job_id:
        return None, "report_job_mismatch"
    try:
        unsafe = coord.symlink_ancestors(candidate)
    except OSError:
        return None, "backup_dir_unreadable"
    if unsafe:
        return None, "unsafe_backup_path"
    try:
        info = os.lstat(candidate)
    except FileNotFoundError:
        return None, "backup_dir_missing"
    except OSError:
        return None, "backup_dir_unreadable"
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return None, "unsafe_backup_path"
    metadata_path = os.path.join(candidate, "backup.json")
    if os.path.lexists(metadata_path):
        try:
            _present, metadata = coord.read_json_nofollow(metadata_path)
        except (ValueError, OSError):
            return None, "backup_metadata_unreadable"
        if not isinstance(metadata, dict):
            return None, "backup_metadata_malformed"
        backup_id = metadata.get("backup_id")
        if isinstance(backup_id, str) and backup_id != job_id:
            return None, "backup_metadata_mismatch"
        manifest_id = report.get("manifest_id") if isinstance(report, dict) else None
        meta_manifest = metadata.get("manifest_id")
        if isinstance(manifest_id, str) and isinstance(meta_manifest, str) and manifest_id != meta_manifest:
            return None, "backup_metadata_mismatch"
    return candidate, None


def _marker_regular(backup_dir: Optional[str]) -> bool:
    """True only for a durable-looking success marker.

    A non-empty regular, non-symlink ``COMPLETE`` inside ``backup_dir``, whose
    path has no symlink ancestor. A zero-byte marker and a marker reached
    through a symlinked ancestor are never treated as an idempotent success.
    """
    if not backup_dir:
        return False
    try:
        if coord.symlink_ancestors(backup_dir):
            return False
    except OSError:
        return False
    try:
        info = os.lstat(os.path.join(backup_dir, COMPLETE_MARKER))
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_size > 0


def _fsync_dir_fd(fd: int) -> None:
    """Durability seam for the marker revocation (patchable in tests)."""
    os.fsync(fd)


def _prior_revocation(report: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The revocation record a previous recovery run persisted, if any."""
    recovery = report.get("recovery") if isinstance(report, dict) else None
    if not isinstance(recovery, dict):
        return None
    revocation = recovery.get("revocation")
    return revocation if isinstance(revocation, dict) else None


def _revocation_pending(report: Dict[str, Any]) -> bool:
    """True when a previous run left a revocation it could not finish.

    The next recovery must retry it -- in particular an unlink whose fsync
    failed is only resolved by fsyncing the directory again, never by reading
    the marker's absence as a durable result.
    """
    prior = _prior_revocation(report)
    return prior is not None and prior.get("ok") is False


def _copy_produced(report: Dict[str, Any], state: str) -> bool:
    """True when the evidence shows a copy was actually produced.

    Mirrors the same predicate in ``coordination``: only a verified copy or a
    ``copied``/``succeeded`` state counts, so a job that legitimately failed
    before copying is never forced to resolve a backup path it never created.
    """
    if isinstance(report, dict):
        if report.get("data_integrity") == "verified":
            return True
        if report.get("state") in ("copied", "succeeded"):
            return True
    return state in ("copied", "succeeded")


def _revoke_stale_complete(backup_dir: str) -> Optional[str]:
    """Delete this job's stale ``COMPLETE`` marker durably.

    Returns ``None`` once the marker is gone and the directory entry is durable,
    or a short reason when it cannot be proven. The directory is opened
    no-follow and the marker is unlinked through that descriptor after an
    ``lstat`` proved it a plain file, so a symlinked directory or marker is
    never followed and nothing else is ever removed.
    """
    try:
        dir_fd = os.open(backup_dir, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW)
    except OSError:
        return "backup_dir_unopenable"
    try:
        try:
            info = os.lstat(COMPLETE_MARKER, dir_fd=dir_fd)
        except FileNotFoundError:
            # A previous attempt may have unlinked the marker without proving
            # the directory entry durable (a failed fsync). Absence is only
            # resolved once this retry fsyncs the directory it would have been
            # removed from; the caller never assumes durable absence.
            try:
                _fsync_dir_fd(dir_fd)
            except OSError:
                return "marker_fsync_failed"
            return None
        except OSError:
            return "marker_unreadable"
        if not stat.S_ISREG(info.st_mode):
            return "marker_not_regular"
        try:
            os.unlink(COMPLETE_MARKER, dir_fd=dir_fd)
        except OSError:
            return "marker_unlink_failed"
        try:
            _fsync_dir_fd(dir_fd)
        except OSError:
            return "marker_fsync_failed"
        return None
    finally:
        os.close(dir_fd)


def _unit_outcome_problem(service_result: Optional[Dict[str, Any]]) -> Optional[str]:
    """Classify the unit result; ``None`` means a proven, complete clean exit.

    The automatic finalizer may publish ``COMPLETE`` only when the unit reported
    the full triple ``SERVICE_RESULT=success``, ``EXIT_CODE=exited``,
    ``EXIT_STATUS=0``. An absent result (``None``/``{}``), any missing or blank
    field, and any ``timeout``/``signal``/``exit-code``/``oom-kill`` or non-zero
    status are refusals, never a success. The reason string is recorded next to
    the retained unit metadata so missing evidence stays distinguishable from a
    real unit failure.
    """
    if not isinstance(service_result, dict) or not service_result:
        return "unit_evidence_missing"
    result = str(service_result.get("SERVICE_RESULT") or "").strip()
    exit_code = str(service_result.get("EXIT_CODE") or "").strip()
    exit_status = str(service_result.get("EXIT_STATUS") or "").strip()
    if result != "success" or exit_code != "exited" or exit_status != "0":
        return "unit_evidence_incomplete"
    return None


def _unit_outcome_ok(service_result: Optional[Dict[str, Any]]) -> bool:
    """True only for a confirmed, complete normal unit exit (see the helper)."""
    return _unit_outcome_problem(service_result) is None


def _identity_error(system, initial: Dict[str, Any]) -> Optional[str]:
    """Verify the current machine matches the recorded one before any action.

    A missing, malformed or unreadable recorded identity, and any readable
    identity that differs from this host, is a hard failure: the caller must
    perform no Docker or Certbot mutation when this returns a value.
    """
    expected = initial.get("machine_id")
    if expected is None or expected == "":
        return "machine_id_unrecorded"
    if not isinstance(expected, str) or not expected.strip():
        return "machine_id_malformed"
    try:
        observed = system.machine_id()
    except Exception:  # noqa: BLE001 - unreadable identity is a hard failure
        return "machine_id_unreadable"
    if not isinstance(observed, str) or not observed.strip():
        return "machine_id_unreadable"
    if observed != expected:
        return "machine_id_changed"
    return None


def _recorded_names(recorded: Any) -> List[str]:
    """Best-effort names for the failure report; never raises on bad records."""
    names: List[str] = []
    if isinstance(recorded, list):
        for item in recorded:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                names.append(item["name"])
            else:
                names.append("<malformed>")
    return names


def _container_error(system, initial: Dict[str, Any], recorded: Any,
                     leave_stopped: Any) -> Optional[str]:
    """Validate recorded container identities against the current host.

    Runs BEFORE any mutation. The recorded records must be well-formed, name a
    container that was observed running by the worker, and still match the
    *exact* current container id. Missing/mismatched/malformed/unreadable
    records fail closed so no container is started on a changed host.
    """
    if recorded is None:
        return "container_records_unrecorded"
    if not isinstance(recorded, list):
        return "container_records_malformed"

    seen = set()
    for item in recorded:
        if not isinstance(item, dict):
            return "container_record_malformed"
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            return "container_record_malformed"
        if name in seen:
            return "container_record_duplicate"
        seen.add(name)
        # A record without a full container id means the entry was not observed
        # as a running container; originally stopped entries are never started.
        container_id = item.get("id")
        if not isinstance(container_id, str) or not container_id.strip():
            return "container_id_unrecorded"

    if seen & {name for name in (leave_stopped or []) if isinstance(name, str)}:
        return "container_record_conflict"

    snapshot = initial.get("containers")
    if isinstance(snapshot, dict):
        for item in recorded:
            fact = snapshot.get(item["name"])
            if isinstance(fact, dict) and fact.get("running") is False:
                return "container_record_not_running"

    if not recorded:
        return None
    try:
        facts = system.container_states([item["name"] for item in recorded])
    except Exception:  # noqa: BLE001 - an unreadable host is a hard failure
        return "container_inspect_failed"
    if not isinstance(facts, dict):
        return "container_inspect_failed"
    for item in recorded:
        fact = facts.get(item["name"])
        if not isinstance(fact, dict) or not fact.get("id"):
            return "container_missing"
        # Exact equality: a reused name with a different container id, and any
        # prefix-only match, are never accepted as the recorded container.
        if fact.get("id") != item["id"]:
            return "container_id_mismatch"
    return None


def recover(job_dir: str, system, manifest, service_result: Optional[Dict[str, Any]] = None,
            explicit: bool = False) -> Dict[str, Any]:
    """Restore only the resources recorded for this job. Idempotent.

    Holds the host stack lock and requires this job's durable reservation, so a
    finalizer can never race a new reservation or recover another host's job.
    ``explicit`` marks a ``job recover`` invocation; an explicit recover never
    upgrades a partial (non-``copied``) backup to success.
    """
    job_id = os.path.basename(os.path.abspath(job_dir).rstrip("/"))
    root = coord.root_for_job_dir(job_dir)
    # A bounded wait lets a launcher that holds the lock for the (fast)
    # enqueue release it, without ever waiting out a real running worker.
    with coord.stack_lock(root, wait_seconds=15):
        coord.assert_owned(root, job_id)
        return _recover_locked(job_dir, system, manifest, service_result, explicit)


def _recover_locked(job_dir: str, system, manifest,
                    service_result: Optional[Dict[str, Any]], explicit: bool) -> Dict[str, Any]:
    ctx = JobContext(job_dir)
    state = (ctx.read_json(STATE_FILE) or {}).get("state", "accepted")
    report, _report_problem = _read_report(ctx)
    request = ctx.read_json(REQUEST_FILE) or {}
    # The durable journal is authoritative for the FIRST cause. It is read
    # before any terminal decision, independent of the report, the unit outcome
    # and the recovery result; the report is only a fallback when no journal
    # was ever written. A present but untrusted journal fails closed.
    journal_failure, journal_problem = _load_primary_failure(ctx)
    original_failure = journal_failure or journal_problem or report.get("original_failure")

    # Contradictory completion evidence is resolved conservatively: the
    # immutable request path is the only authority, a stale marker may only be
    # revoked inside that validated directory, and a *proven* complete job is
    # never touched. Only when every piece agrees may ``already_complete`` short
    # circuit, so a failure journal, a failed report or a stale/unsafe marker can
    # never be reported as success merely because a ``COMPLETE`` file exists.
    auth_backup, auth_problem = _authoritative_backup_dir(ctx, request, report)
    # A binding disagreement only blocks a job that actually produced a copy;
    # a legitimate failure before copying has no backup directory to resolve.
    binding_problem = (auth_problem if auth_problem is not None
                       and _copy_produced(report, state) else None)
    # A reported path is not an authority, but a marker sitting there is still
    # evidence that cannot be safely revoked while the binding is unresolved.
    reported_backup = report.get("backup_dir") if isinstance(report, dict) else None
    reported_marker = (_marker_regular(reported_backup)
                       if isinstance(reported_backup, str) else False)
    conflict = coord.completion_conflict(ctx.job_dir)
    marker_present = _marker_regular(auth_backup)
    pending_revocation = _revocation_pending(report)
    prior_revocation = _prior_revocation(report)
    # The immutable request path is the sole target for a success write or a
    # marker revocation. A report-selected path, the job-directory default and
    # a disagreement with the request are never used to guess a target.
    record_backup = auth_backup if auth_problem is None else None
    if (conflict is None and auth_problem is None and marker_present
            and not pending_revocation):
        return {"state": "succeeded", "recovered": True, "already_complete": True}

    initial, initial_problem = _read_initial_state(ctx)
    if _proven_no_effects(ctx, report, request, state, initial, initial_problem,
                          auth_problem, marker_present, reported_marker, conflict,
                          pending_revocation):
        # A preflight-only failure with a durable, fully agreeing no-effects
        # proof. Bookkeeping only: no container started, no Certbot trigger
        # restored and no marker written, so no restored-host claim is made and
        # the job ends terminal ``failed`` without blocking new work.
        recovery = {
            "no_effects": True,
            "effects_started": False,
            "reason": NO_EFFECTS_REASON,
        }
        _write_terminal(ctx, report, "failed", original_failure, recovery, service_result)
        return {"state": "failed", "recovered": False, "reason": NO_EFFECTS_REASON,
                "no_effects": True, "effects_started": False}
    if initial is None:
        reason = initial_problem or "missing_initial_state"
        unresolved = {"recovered": False, "reason": reason}
        revocation = None
        new_state = "unknown"
        if binding_problem is not None:
            unresolved["binding_problem"] = binding_problem
        if conflict is not None and (marker_present or auth_problem is not None):
            # No recorded machine means no proven host: never delete a marker.
            revocation = {"ok": False, "reason": "identity_unverified"}
            unresolved["revocation"] = revocation
            new_state = "recovery_required"
        _write_terminal(ctx, report, new_state, original_failure, unresolved, service_result)
        result = {"state": new_state, "recovered": False, "reason": reason}
        if revocation is not None:
            result["revocation"] = revocation
        if binding_problem is not None:
            result["binding_problem"] = binding_problem
        return result

    if service_result is not None:
        # Retain exactly what the unit reported, even a partial/empty mapping,
        # so missing or incomplete evidence stays auditable in the report.
        report["unit_result"] = service_result

    # Check the machine and container identities BEFORE touching anything. A
    # wrong/missing/unreadable machine, or an unvalidatable container record,
    # fails closed here: no Docker start and no Certbot restore may run on a
    # host whose recorded identity was not proven first.
    identity_error = _identity_error(system, initial)
    raw_recorded = initial.get("stop_containers")
    recorded = raw_recorded if isinstance(raw_recorded, list) else []
    container_error = None
    if identity_error is None:
        container_error = _container_error(system, initial, raw_recorded,
                                           initial.get("leave_stopped"))

    # Revoke a contradictory COMPLETE *before* any durable non-success report or
    # state. The marker is removed only inside this job's validated backup
    # directory and only once the recorded machine has been proven; every
    # unresolved case (wrong/unreadable machine, unsafe path or a failed unlink)
    # keeps the first cause and the marker and is reported as
    # ``recovery_required``. A failed fsync happens after the unlink already
    # succeeded: the entry is gone but durability is unproven, so the revocation
    # is recorded as pending and the next recovery retries the fsync instead of
    # reading the missing marker as a finished result.
    revocation: Optional[Dict[str, Any]] = None
    marker_evidence = (marker_present or reported_marker
                       or conflict in ("marker_unsafe", "stale_complete"))
    if auth_problem is not None and (marker_evidence or pending_revocation):
        revocation = {"ok": False, "reason": auth_problem}
    elif conflict == "marker_unsafe":
        revocation = {"ok": False, "reason": "marker_not_regular"}
    elif marker_present or pending_revocation:
        if identity_error is not None:
            revocation = {"ok": False, "reason": "identity_unverified"}
        else:
            problem = _revoke_stale_complete(auth_backup)
            if problem is None:
                revocation = {"ok": True, "revoked": True}
                marker_present = False
            else:
                revocation = {"ok": False, "reason": problem}
    revocation_failed = revocation is not None and not revocation.get("ok")

    started: List[str] = []
    failures: List[str] = []
    docker_error: Optional[str] = None
    certbot_restored = False
    if identity_error is None and container_error is None:
        for item in recorded:
            # One container at a time, in the recorded order. A Docker
            # inspection/start failure must not stop the timer restore below.
            try:
                system.start_containers([item["id"]])
            except Exception:  # noqa: BLE001 - recovery must attempt every resource
                docker_error = docker_error or "start_failed"
            try:
                facts = system.container_states([item["name"]])
            except Exception:  # noqa: BLE001
                docker_error = docker_error or "inspect_failed"
                failures.append(item["name"])
                continue
            fact = facts.get(item["name"])
            if fact and fact.get("running") and fact.get("id") == item.get("id"):
                started.append(item["name"])
            else:
                failures.append(item["name"])

        certbot_state = initial.get("certbot")
        if certbot_state is not None:
            try:
                system.restore_certbot_triggers(certbot_state, manifest)
                certbot_restored = True
            except Exception:  # noqa: BLE001
                certbot_restored = False
        else:
            certbot_restored = True
    else:
        failures = _recorded_names(raw_recorded)

    recovered = (identity_error is None and container_error is None
                 and not failures and certbot_restored)
    recovery = {
        "containers_started": started,
        "container_failures": failures,
        "certbot_restored": certbot_restored,
        "recovery_complete": recovered,
    }
    if identity_error is not None:
        recovery["identity_error"] = identity_error
    if container_error is not None:
        recovery["container_error"] = container_error
    if docker_error is not None:
        recovery["docker_error"] = docker_error
    if revocation is not None:
        recovery["revocation"] = revocation
    elif prior_revocation is not None:
        # Keep the audit record of an already-finished revocation.
        recovery["revocation"] = prior_revocation
    if binding_problem is not None:
        # Persist the curated reason so every repeated recovery keeps returning
        # ``recovery_required`` until the binding is actually repaired.
        recovery["binding_problem"] = binding_problem

    if revocation_failed:
        new_state = "recovery_required"
    elif not recovered:
        new_state = "recovery_required"
    elif binding_problem is not None:
        # Path/metadata binding disagreement: the copy itself may be sound and
        # source recovery has already run above on the verified host, but
        # success cannot be proven for any directory. Report the diagnostic and
        # never mutate the report-selected or any other backup directory.
        new_state = "recovery_required"
    elif original_failure is not None:
        # Recovery worked, but a failed operation never becomes success.
        new_state = "failed"
    elif state == "copied" and not explicit:
        if not _unit_outcome_ok(service_result):
            # The raw unit metadata is retained separately in ``unit_result``;
            # this error only records that the evidence was not a clean exit.
            original_failure = {
                "code": "E_UNIT_FAILED",
                "message": "The backup unit did not report a complete clean exit; "
                           "COMPLETE is refused.",
                "resource": "unit",
                "detail": {"reason": _unit_outcome_problem(service_result)},
            }
            new_state = "failed"
        else:
            problem = _proven_success(ctx, auth_backup, manifest)
            if problem is None:
                # Persist the terminal report/state BEFORE the marker, so a late
                # evidence-write failure cannot leave a valid portable success.
                _write_terminal(ctx, report, "succeeded", None, recovery, service_result,
                                backup_dir=record_backup)
                _publish_complete(ctx, auth_backup)
                result = {
                    "state": "succeeded",
                    "recovered": recovered,
                    "containers_started": started,
                    "container_failures": failures,
                    "certbot_restored": certbot_restored,
                    "unit_result": service_result or None,
                }
                if revocation is not None:
                    result["revocation"] = revocation
                return result
            original_failure = problem.to_error_object()
            new_state = "failed"
    elif state == "copied" and explicit:
        # An explicit recover never upgrades a partial copy to success.
        new_state = "failed" if original_failure else "recovery_required"
    else:
        new_state = "unknown" if state == "unknown" else "failed"

    _write_terminal(ctx, report, new_state, original_failure, recovery, service_result,
                    backup_dir=record_backup)
    result = {
        "state": new_state,
        "recovered": recovered,
        "containers_started": started,
        "container_failures": failures,
        "certbot_restored": certbot_restored,
        "unit_result": service_result or None,
    }
    if revocation is not None:
        result["revocation"] = revocation
    if binding_problem is not None:
        result["binding_problem"] = binding_problem
    return result


def _publish_complete(ctx: JobContext, backup_dir: str) -> None:
    """Publish the success marker last, atomically and no-follow."""
    from ..util import atomic_write_bytes

    atomic_write_bytes(os.path.join(backup_dir, COMPLETE_MARKER), b"complete\n", mode=0o600)


def _write_terminal(ctx: JobContext, report: Dict[str, Any], new_state: str,
                    original_failure: Optional[Dict[str, Any]], recovery: Dict[str, Any],
                    service_result: Optional[Dict[str, Any]], backup_dir: Optional[str] = None) -> None:
    report = dict(report)
    if recovery.get("no_effects"):
        # Nothing was stopped, masked or copied, so there is no source runtime
        # to restore and no restored-host claim to make.
        source_runtime_recovery = "not_run"
    else:
        source_runtime_recovery = "verified" if recovery.get("recovery_complete") else "failed"
    report.update(
        {
            "schema_version": report.get("schema_version", 1),
            "job_id": os.path.basename(ctx.job_dir),
            "state": new_state,
            "source_runtime_recovery": source_runtime_recovery,
            "original_failure": original_failure,
            "recovery": recovery,
            "completed_at": now_iso(),
        }
    )
    if backup_dir:
        report["backup_dir"] = backup_dir
    if service_result:
        report["unit_result"] = service_result
    ctx.write_json(REPORT_FILE, report)
    ctx.write_json(STATE_FILE, {"state": new_state, "updated_at": now_iso(), "step": "recover"})
    ctx.append_event({"state": new_state, "step": "recover",
                      "outcome": "ok" if recovery.get("recovery_complete") else "failed"})


def service_result_from_env(environ) -> Optional[Dict[str, Any]]:
    keys = ("SERVICE_RESULT", "EXIT_CODE", "EXIT_STATUS")
    result = {key: environ.get(key) for key in keys if environ.get(key) is not None}
    return result or None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="vps3xui-finalizer")
    parser.add_argument("job_dir")
    parser.add_argument("--release-dir", default=None)
    parser.add_argument("--recover", action="store_true",
                        help="explicit job recover mode")
    args = parser.parse_args(argv)
    import json

    os.umask(0o077)
    from .. import manifest as manifest_module
    from .system import RealSystem

    release_dir = args.release_dir or os.environ.get("VPS3XUI_RELEASE_DIR")
    # The job-directory manifest is authoritative for the job; the release copy
    # is only a fallback for a job whose manifest file is absent.
    manifest_path = os.path.join(args.job_dir, "manifest.json")
    if not os.path.isfile(manifest_path):
        if not release_dir:
            raise SystemExit("the job has no manifest and no --release-dir was given")
        manifest_path = os.path.join(release_dir, "manifest.json")
    manifest = manifest_module.load(manifest_path)
    result = recover(args.job_dir, RealSystem(release_dir=release_dir), manifest,
                     service_result=service_result_from_env(os.environ), explicit=args.recover)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("state") == "succeeded" else 1


if __name__ == "__main__":
    sys.exit(main())
