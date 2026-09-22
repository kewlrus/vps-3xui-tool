"""Durable host-side restore job: request, state machine, effect journal, receipts.

A restore job lives on the *target* host under ``<root>/restore-jobs/<job_id>``,
next to P0 backup jobs and under the same :func:`coordination.stack_lock`, so
one lock covers backup, restore and recover of this stack on the host. Until
the job reaches a settled state (:data:`coordination.RESTORE_SETTLED_STATES`)
it blocks every other backup/restore/recover there, and vice versa.

Layout of a job directory (``0700``; every file ``0600``, written atomically
and fsynced together with its directory)::

    request.json            immutable binding: job, backup, manifest, source, target
    state.json              the recorded job state (the commit point of a stage)
    journal/000001.json     one immutable entry per intent/outcome, contiguous seq
    receipts/<kind>.json    verified stage receipts
    attempts/000001.json    one record per stage attempt (later results)
    failure.json            the *first* failure cause, never replaced
    launched.json           runtime launch marker (see :mod:`.runtime`)

Rules this module enforces:

* intent is durable *before* the effect; a failed intent write raises and the
  effect must not run. The outcome is recorded after observation. An intent
  without an outcome, or an explicit ``unknown`` outcome, makes the job
  ``unknown``: the store never assumes success and never deletes anything.
* a step on a resource that already existed is never ``created_by_job``; the
  pre-effect presence must be observed, not guessed.
* a retry is only the same job, backup, manifest, source and target
  (:func:`contracts.request_matches_plan`); anything else is a conflict.
* ``staged`` is a boundary, not permission to start: ``activate`` additionally
  needs accepted cutover evidence (P1-09), and :meth:`RestoreJob.status`
  always reports ``start_permitted: False``.
"""

from __future__ import annotations

import contextlib
import datetime
import json
import os
import tempfile
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .. import coordination as coord
from ..errors import ToolError
from ..plan import parse_time
from . import contracts

REQUEST_FILE = "request.json"
STATE_FILE = "state.json"
FAILURE_FILE = "failure.json"
JOURNAL_DIR = "journal"
RECEIPTS_DIR = "receipts"
ATTEMPTS_DIR = "attempts"

STATE_SCHEMA_VERSION = 1
SEQ_WIDTH = 6

# A failure with one of these codes means foreign or contradictory evidence:
# the job must be reviewed before anything else touches the target.
RECOVERY_CODES = ("E_NOT_OWNED", "E_RECOVERY_REQUIRED", "E_HOST_IDENTITY_MISMATCH")

RUNNING_STAGE = {state: stage for stage, state in contracts.STAGE_RUNNING_STATE.items()}


def _now(now: Optional[datetime.datetime]) -> str:
    return contracts.format_time(now or contracts.utcnow())


def _seq_name(seq: int) -> str:
    return "%0*d.json" % (SEQ_WIDTH, seq)


def _dump(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def publish_exclusive(path: str, obj: Any) -> None:
    """Durably create ``path`` exactly once: never torn, never replaced.

    The entry is written and fsynced under a temporary name, then hard-linked to
    its final name (``link`` fails when the name exists) and the directory is
    fsynced. A crash leaves either no entry or a complete one.
    """
    directory = os.path.dirname(os.path.abspath(path))
    coord.require_private_dir(directory, 0o700)
    try:
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    except OSError:
        raise ToolError("E_STATE_WRITE_FAILED", "Cannot create a temporary journal file.",
                        resource=os.path.basename(path), next_action="inspect_restore_job")
    try:
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(_dump(obj))
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            raise ToolError("E_STATE_WRITE_FAILED", "Journal entry could not be written durably.",
                            resource=os.path.basename(path), next_action="inspect_restore_job")
        try:
            os.link(tmp, path)
        except FileExistsError:
            raise ToolError("E_CONFLICT", "Refusing to replace an existing record.",
                            resource=os.path.basename(path), next_action="inspect_restore_job")
        except OSError:
            raise ToolError("E_STATE_WRITE_FAILED", "Journal entry could not be published.",
                            resource=os.path.basename(path), next_action="inspect_restore_job")
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    coord.fsync_dir(directory)


def _read_object(path: str, code: str = "E_RECOVERY_REQUIRED") -> Optional[Dict[str, Any]]:
    try:
        present, value = coord.read_json_nofollow(path)
    except (ValueError, OSError):
        raise ToolError(code, "Restore job record is unreadable or unsafe.",
                        resource=os.path.basename(path), next_action="inspect_restore_job")
    if not present:
        return None
    if not isinstance(value, dict):
        raise ToolError(code, "Restore job record is not an object.",
                        resource=os.path.basename(path), next_action="inspect_restore_job")
    return value


def _numbered(directory: str) -> List[Tuple[int, str]]:
    """Contiguous ``000001.json``… entries; anything else is refused."""
    if coord.is_symlink(directory):
        raise ToolError("E_UNSAFE_PATH", "Restore job directory is a symlink.",
                        resource=os.path.basename(directory), next_action="inspect_restore_job")
    if not os.path.isdir(directory):
        return []
    found = []
    for name in os.listdir(directory):
        if name.startswith(".tmp-"):
            continue  # an unpublished entry: its write never returned
        stem = name[:-5] if name.endswith(".json") else ""
        if len(stem) != SEQ_WIDTH or not stem.isdigit() or int(stem) < 1:
            raise ToolError("E_RECOVERY_REQUIRED", "Unexpected file in the restore job record.",
                            resource=os.path.basename(directory), next_action="inspect_restore_job")
        found.append((int(stem), os.path.join(directory, name)))
    found.sort()
    for index, (seq, _path) in enumerate(found, start=1):
        if seq != index:
            raise ToolError("E_RECOVERY_REQUIRED", "Restore job record sequence is broken.",
                            resource=os.path.basename(directory), next_action="inspect_restore_job")
    return found


class RestoreJobStore(object):
    """Host-side registry of restore jobs under a coordination ``root``."""

    def __init__(self, root: str) -> None:
        self.root = os.path.abspath(root)

    def job_path(self, job_id: str) -> str:
        return coord.restore_job_dir(self.root, job_id)

    def exists(self, job_id: str) -> bool:
        return os.path.isfile(os.path.join(self.job_path(job_id), REQUEST_FILE))

    @contextlib.contextmanager
    def locked(self, wait_seconds: float = 0) -> Iterator[None]:
        """The host stack lock shared with P0 backup, finalizer and recover."""
        with coord.stack_lock(self.root, wait_seconds):
            yield

    def register(self, plan: Dict[str, Any], release_digest: str,
                 now: Optional[datetime.datetime] = None,
                 wait_seconds: float = 0) -> Tuple[Dict[str, Any], bool]:
        """Idempotently register a restore job. Returns ``(request, created)``.

        A lost response is safe: repeating the same plan bindings resolves the
        existing job. Different bindings under the same job are a conflict, and
        any other unfinished backup/restore on this host blocks a new job.
        """
        contracts.validate_restore_plan(plan)
        job_id = plan["job_id"]
        with self.locked(wait_seconds):
            path = self.job_path(job_id)
            if coord.is_symlink(path):
                raise ToolError("E_UNSAFE_PATH", "Restore job directory is a symlink.",
                                resource=job_id, next_action="inspect_restore_job")
            if os.path.lexists(path):
                request = _read_object(os.path.join(path, REQUEST_FILE))
                if request is None:
                    raise ToolError("E_RECOVERY_REQUIRED", "Restore job directory has no request.",
                                    resource=job_id, next_action="inspect_restore_job")
                contracts.request_matches_plan(request, plan)
                return request, False
            coord.assert_no_blocking(self.root, ignoring_restore=job_id)
            request = contracts.build_restore_request(plan, release_digest, now=now)
            self._create(job_id, request, now)
            return request, True

    def _create(self, job_id: str, request: Dict[str, Any],
                now: Optional[datetime.datetime]) -> None:
        parent = coord.restore_jobs_root(self.root)
        coord.require_private_dir(parent, 0o700)
        try:
            staging = tempfile.mkdtemp(prefix=".tmp-", dir=parent)
        except OSError:
            raise ToolError("E_STATE_WRITE_FAILED", "Restore job directory could not be created.",
                            resource=job_id, next_action="retry_state_write")
        try:
            os.chmod(staging, 0o700)
            coord.write_exclusive(os.path.join(staging, REQUEST_FILE), request)
            coord.write_exclusive(os.path.join(staging, STATE_FILE),
                                  _state_record(job_id, "planned", None, 0, now))
            # Publish the complete directory in one step; the lock excludes a
            # concurrent creator, so the target name cannot appear meanwhile.
            os.rename(staging, os.path.join(parent, job_id))
            staging = None  # type: ignore[assignment]
        except OSError:
            raise ToolError("E_STATE_WRITE_FAILED", "Restore job could not be registered durably.",
                            resource=job_id, next_action="retry_state_write")
        finally:
            if staging is not None:
                _remove_unpublished(staging)
        coord.fsync_dir(parent)

    def open(self, job_id: str) -> "RestoreJob":
        """A handle for reads; mutating methods require :meth:`session`."""
        if not self.exists(job_id):
            raise ToolError("E_JOB_NOT_FOUND", "Restore job is not registered on this host.",
                            resource=job_id, next_action="restore_plan")
        return RestoreJob(self, job_id)

    @contextlib.contextmanager
    def session(self, job_id: str, wait_seconds: float = 0) -> Iterator["RestoreJob"]:
        """Hold the stack lock for the whole effect window of one attempt."""
        with self.locked(wait_seconds):
            job = self.open(job_id)
            job._locked = True
            try:
                yield job
            finally:
                job._locked = False


def _remove_unpublished(staging: str) -> None:
    """Remove this call's own unpublished staging directory (never a job)."""
    for name in (REQUEST_FILE, STATE_FILE):
        try:
            os.unlink(os.path.join(staging, name))
        except OSError:
            pass
    try:
        os.rmdir(staging)
    except OSError:
        pass


def _state_record(job_id: str, state: str, stage: Optional[str], attempt: int,
                  now: Optional[datetime.datetime], reason: Optional[str] = None) -> Dict[str, Any]:
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "job_id": job_id,
        "state": state,
        "stage": stage,
        "attempt": attempt,
        "reason": reason,
        "updated_at": _now(now),
    }


class RestoreJob(object):
    """One restore job. Streams reach it through :meth:`intent`/:meth:`outcome`."""

    def __init__(self, store: RestoreJobStore, job_id: str) -> None:
        self.store = store
        self.job_id = job_id
        self.path = store.job_path(job_id)
        self._locked = False

    # -- reads -------------------------------------------------------------
    def request(self) -> Dict[str, Any]:
        request = _read_object(os.path.join(self.path, REQUEST_FILE))
        if request is None:
            raise ToolError("E_RECOVERY_REQUIRED", "Restore request is missing.",
                            resource=self.job_id, next_action="inspect_restore_job")
        contracts.check_schema("request", request, code="E_RECOVERY_REQUIRED")
        if request["job_id"] != self.job_id:
            raise ToolError("E_NOT_OWNED", "Restore request belongs to a different job.",
                            resource=self.job_id, next_action="inspect_restore_job")
        return request

    def state_record(self) -> Dict[str, Any]:
        record = _read_object(os.path.join(self.path, STATE_FILE))
        if (record is None or record.get("job_id") != self.job_id
                or record.get("state") not in contracts.JOB_STATES):
            raise ToolError("E_RECOVERY_REQUIRED", "Restore job state is missing or invalid.",
                            resource=self.job_id, next_action="inspect_restore_job")
        return record

    def journal(self) -> List[Dict[str, Any]]:
        entries = []
        for _seq, path in _numbered(os.path.join(self.path, JOURNAL_DIR)):
            entries.append(_read_object(path))
        return entries

    def steps(self) -> Dict[str, Dict[str, Any]]:
        return contracts.replay_journal(self.journal(), self.job_id)

    def receipts(self) -> Dict[str, Dict[str, Any]]:
        """Stored receipts, each re-validated against this job's request."""
        directory = os.path.join(self.path, RECEIPTS_DIR)
        if coord.is_symlink(directory):
            raise ToolError("E_UNSAFE_PATH", "Receipts directory is a symlink.",
                            resource=self.job_id, next_action="inspect_restore_job")
        if not os.path.isdir(directory):
            return {}
        request = self.request()
        receipts = {}
        for name in sorted(os.listdir(directory)):
            if name.startswith(".tmp-"):
                continue
            kind = name[:-5] if name.endswith(".json") else ""
            if kind not in contracts.RECEIPT_STAGE:
                raise ToolError("E_RECOVERY_REQUIRED", "Unexpected file among restore receipts.",
                                resource=self.job_id, next_action="inspect_restore_job")
            receipt = _read_object(os.path.join(directory, name), code="E_VERIFY_FAILED")
            receipts[kind] = contracts.validate_receipt(receipt, request, kind)
        return receipts

    def primary_failure(self) -> Optional[Dict[str, Any]]:
        return _read_object(os.path.join(self.path, FAILURE_FILE))

    def attempts(self) -> List[Dict[str, Any]]:
        return [_read_object(path) for _seq, path in _numbered(os.path.join(self.path, ATTEMPTS_DIR))]

    def status(self, interruption: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Read-only view; the effective state never claims more than the evidence.

        ``interruption`` is the runtime observation (:func:`.runtime.observe`).
        """
        recorded = None
        problem = None
        steps: Dict[str, Dict[str, Any]] = {}
        receipts: Dict[str, Dict[str, Any]] = {}
        try:
            recorded = self.state_record()
            steps = self.steps()
            receipts = self.receipts()
        except ToolError as error:
            problem = error.code
        failure = None
        try:
            failure = self.primary_failure()
        except ToolError as error:
            problem = problem or error.code
        state = recorded["state"] if recorded else "recovery_required"
        effective = _effective_state(state, steps, problem)
        unknown = sorted(step_id for step_id, step in steps.items() if step["outcome"] == "unknown")
        interrupted = bool(interruption and interruption.get("interrupted"))
        return {
            "job_id": self.job_id,
            "state": effective,
            "recorded_state": recorded["state"] if recorded else None,
            "stage": recorded.get("stage") if recorded else None,
            "attempt": recorded.get("attempt") if recorded else None,
            "settled": effective in coord.RESTORE_SETTLED_STATES and not interrupted,
            "blocking": effective not in coord.RESTORE_SETTLED_STATES or interrupted,
            "interruption": interruption,
            "unknown_steps": unknown,
            "owned_resources": contracts.owned_resources(steps),
            "receipts": sorted(receipts),
            "primary_failure": _failure_summary(failure),
            "record_problem": problem,
            # Reaching ``staged`` never permits start: activate needs cutover evidence.
            "start_permitted": False,
            "next_action": _next_action(effective, interrupted),
        }

    # -- mutation (under the stack lock) -------------------------------------
    def _require_lock(self) -> None:
        if not self._locked:
            raise ToolError("E_CONTRACT", "Restore job changes require the stack lock.",
                            resource=self.job_id, next_action="use_session")

    def _write_state(self, state: str, stage: Optional[str], attempt: int,
                     now: Optional[datetime.datetime], reason: Optional[str] = None) -> None:
        coord.replace_json(os.path.join(self.path, STATE_FILE),
                           _state_record(self.job_id, state, stage, attempt, now, reason))

    def _effective(self) -> Tuple[Dict[str, Any], Dict[str, Dict[str, Any]]]:
        record = self.state_record()
        steps = self.steps()
        if any(step["outcome"] == "unknown" for step in steps.values()):
            raise ToolError("E_JOB_INCOMPLETE", "A step has an undetermined result; reconcile first.",
                            resource=self.job_id, next_action="inspect_restore_job")
        return record, steps

    def begin_stage(self, stage: str, plan: Dict[str, Any],
                    now: Optional[datetime.datetime] = None,
                    cutover: Optional[Dict[str, Any]] = None,
                    unit_name: Optional[str] = None) -> Dict[str, Any]:
        """Enter (or resume) ``stage`` for the same job, backup and target.

        Returns the attempt record. The previous attempt of an interrupted stage
        is closed as ``interrupted``; its effects stay in the journal.
        """
        self._require_lock()
        request = self.request()
        contracts.request_matches_plan(request, plan)
        moment = now or contracts.utcnow()
        if moment > parse_time(plan["expires_at"]):
            raise ToolError("E_PLAN_EXPIRED", "Restore plan has expired; build a fresh plan.",
                            resource="plan", next_action="rebuild_plan")
        record, _steps = self._effective()
        contracts.check_stage_entry(record["state"], stage)
        running = contracts.STAGE_RUNNING_STATE[stage]
        if record["state"] == running and record.get("stage") != stage:
            raise ToolError("E_RECOVERY_REQUIRED", "Restore job state contradicts its stage.",
                            resource=self.job_id, next_action="inspect_restore_job")
        contracts.check_stage_inputs(stage, self.receipts(), request)
        if stage == "activate" and not _cutover_accepted(cutover):
            raise ToolError("E_PRECONDITION",
                            "A staged job is not permission to start: cutover evidence is required.",
                            resource="cutover", next_action="collect_cutover_evidence")
        attempts = self.attempts()
        if attempts and attempts[-1].get("result") is None:
            self._close_attempt(attempts[-1], "interrupted", None, moment)
        attempt = {
            "schema_version": STATE_SCHEMA_VERSION,
            "job_id": self.job_id,
            "attempt": len(attempts) + 1,
            "stage": stage,
            "plan_identity": plan["identity"],
            "unit_name": unit_name,
            "cutover": dict(cutover) if cutover else None,
            "started_at": _now(moment),
            "ended_at": None,
            "result": None,
            "error": None,
        }
        publish_exclusive(os.path.join(self.path, ATTEMPTS_DIR, _seq_name(attempt["attempt"])), attempt)
        self._write_state(running, stage, attempt["attempt"], moment)
        return attempt

    def _close_attempt(self, attempt: Dict[str, Any], result: str,
                       error: Optional[Dict[str, Any]], moment: datetime.datetime) -> None:
        closed = dict(attempt)
        closed.update({"result": result, "error": error, "ended_at": _now(moment)})
        coord.replace_json(os.path.join(self.path, ATTEMPTS_DIR, _seq_name(attempt["attempt"])), closed)

    def _running_stage(self) -> Tuple[str, Dict[str, Any]]:
        record = self.state_record()
        stage = RUNNING_STAGE.get(record["state"])
        if stage is None or record.get("stage") != stage:
            raise ToolError("E_PRECONDITION", "No restore stage is running.",
                            resource=record["state"], next_action="begin_stage")
        return stage, record

    def intent(self, step_id: str, kind: str, resource: str, ownership: str,
               expected: Dict[str, Any], preexisting: Optional[bool],
               now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
        """Durably record the intended effect *before* performing it.

        ``preexisting`` is the observed presence of ``resource`` before the
        effect: ``None`` (not determined) refuses, and an existing resource is
        never claimed as ``created_by_job`` unless this job already owns it.
        """
        self._require_lock()
        stage, _record = self._running_stage()
        entries = self.journal()
        steps = contracts.replay_journal(entries, self.job_id)
        if any(step["outcome"] == "unknown" for step in steps.values()):
            raise ToolError("E_JOB_INCOMPLETE", "A step has an undetermined result; reconcile first.",
                            resource=self.job_id, next_action="inspect_restore_job")
        if preexisting is None:
            raise ToolError("E_PRECONDITION", "Resource presence before the effect is undetermined.",
                            resource=resource, next_action="inspect_target")
        previous = steps.get(step_id)
        if previous is not None:
            if previous["outcome"] == "applied":
                raise ToolError("E_CONFLICT", "Step is already applied; reuse its result.",
                                resource=step_id, next_action="inspect_restore_job")
            if (previous["kind"], previous["resource"], previous["ownership"]) != (kind, resource, ownership):
                raise ToolError("E_CONFLICT", "A retried step must target the same resource.",
                                resource=step_id, next_action="inspect_restore_job")
        owned = _owned_by_job(steps, kind, resource)
        for other_id, other in steps.items():
            if other_id != step_id and (other["kind"], other["resource"]) == (kind, resource) \
                    and other["ownership"] != ownership:
                raise ToolError("E_CONFLICT", "Resource ownership contradicts an earlier step.",
                                resource=resource, next_action="inspect_restore_job")
        if ownership == "created_by_job" and preexisting and not owned:
            raise ToolError("E_NOT_OWNED", "Refusing to take over a resource this job did not create.",
                            resource=resource, next_action="inspect_target")
        if ownership == "preexisting_accepted" and not preexisting:
            raise ToolError("E_PRECONDITION", "An accepted pre-existing resource is absent.",
                            resource=resource, next_action="inspect_target")
        entry = contracts.journal_intent(self.job_id, len(entries) + 1, step_id, stage, kind,
                                         resource, ownership, expected, now=now)
        self._append(entry)
        return entry

    def outcome(self, intent: Dict[str, Any], outcome: str, observed: Optional[Dict[str, Any]],
                error: Optional[Dict[str, Any]] = None,
                now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
        """Record the *observed* result of an intent.

        ``unknown`` (the command result could not be determined) is recorded and
        stops the job: nothing may continue until the step is reconciled.
        """
        self._require_lock()
        entries = self.journal()
        steps = contracts.replay_journal(entries, self.job_id)
        step = steps.get(intent.get("step_id"))
        latest = [entry for entry in entries if entry["step_id"] == intent.get("step_id")]
        if step is None or step["outcome"] != "unknown" or not latest or latest[-1] != intent:
            raise ToolError("E_CONFLICT", "Outcome does not match the open intent of this step.",
                            resource=str(intent.get("step_id")), next_action="inspect_restore_job")
        if outcome not in contracts.STEP_OUTCOMES:
            raise ToolError("E_CONTRACT", "Unknown step outcome.", resource=intent["step_id"])
        entry = contracts.journal_outcome(intent, len(entries) + 1, outcome, observed, error, now=now)
        self._append(entry)
        if outcome == "unknown":
            stage, record = self._running_stage()
            self._record_failure(stage, record.get("attempt"), "E_EXECUTION",
                                 "A step result could not be determined.", intent["step_id"], now)
            self._write_state("unknown", stage, record.get("attempt") or 0, now, reason="step_unknown")
        return entry

    def _append(self, entry: Dict[str, Any]) -> None:
        path = os.path.join(self.path, JOURNAL_DIR, _seq_name(entry["seq"]))
        publish_exclusive(path, entry)

    def complete_stage(self, receipts: Dict[str, Dict[str, Any]],
                       now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
        """Commit the stage with exactly its verified receipts; state is written last."""
        self._require_lock()
        stage, record = self._running_stage()
        request = self.request()
        steps = self.steps()
        try:
            if set(receipts) != set(contracts.STAGE_PRODUCES[stage]):
                raise ToolError("E_VERIFY_FAILED", "Stage receipts do not match the stage contract.",
                                resource=stage, next_action="inspect_restore_job")
            stage_steps = {step_id: step for step_id, step in steps.items() if step["stage"] == stage}
            if any(step["outcome"] == "unknown" for step in stage_steps.values()):
                raise ToolError("E_VERIFY_FAILED", "Stage has a step with an undetermined result.",
                                resource=stage, next_action="inspect_restore_job")
            for kind in sorted(receipts):
                receipt = contracts.validate_receipt(receipts[kind], request, kind)
                for step_id in receipt["steps"]:
                    step = stage_steps.get(step_id)
                    if step is None or step["outcome"] != "applied":
                        raise ToolError("E_VERIFY_FAILED", "Receipt names a step without a journaled result.",
                                        resource=step_id, next_action="inspect_restore_job")
        except ToolError as error:
            self.fail_stage(error, retryable=False, now=now)
            raise
        for kind in sorted(receipts):
            coord.replace_json(os.path.join(self.path, RECEIPTS_DIR, kind + ".json"), receipts[kind])
        moment = now or contracts.utcnow()
        attempts = self.attempts()
        if attempts and attempts[-1].get("result") is None:
            self._close_attempt(attempts[-1], "completed", None, moment)
        state = contracts.STAGE_COMPLETE_STATE[stage]
        self._write_state(state, stage, record.get("attempt") or 0, moment)
        return {"job_id": self.job_id, "state": state, "receipts": sorted(receipts)}

    def fail_stage(self, error: ToolError, retryable: bool,
                   now: Optional[datetime.datetime] = None,
                   step_id: Optional[str] = None) -> str:
        """Record a stage failure; the first cause is kept, later ones go to attempts.

        Returns the new job state. A retryable failure with every step settled
        leaves the stage state so the *same* job may retry it; undetermined
        steps make the job ``unknown`` and foreign evidence ``recovery_required``.
        """
        self._require_lock()
        moment = now or contracts.utcnow()
        record = self.state_record()
        stage = RUNNING_STAGE.get(record["state"]) or record.get("stage")
        attempt_no = record.get("attempt") or 0
        self._record_failure(stage, attempt_no, error.code, error.message, step_id, moment,
                             resource=error.resource)
        attempts = self.attempts()
        summary = {"code": error.code, "resource": coord.bounded(error.resource, 128)
                   if error.resource else None}
        if attempts and attempts[-1].get("result") is None:
            self._close_attempt(attempts[-1], "failed", summary, moment)
        try:
            steps = self.steps()
            undetermined = any(step["outcome"] == "unknown" for step in steps.values())
        except ToolError:
            steps, undetermined = {}, None
        if undetermined is None or error.code in RECOVERY_CODES:
            state = "recovery_required"
        elif undetermined:
            state = "unknown"
        elif retryable and record["state"] in RUNNING_STAGE:
            state = record["state"]
        else:
            state = "failed"
        self._write_state(state, stage, attempt_no, moment, reason=error.code)
        return state

    def _record_failure(self, stage: Optional[str], attempt: Optional[int], code: str,
                        message: str, step_id: Optional[str],
                        now: Optional[datetime.datetime], resource: Optional[str] = None) -> None:
        """Create ``failure.json`` once; an existing first cause is never replaced."""
        path = os.path.join(self.path, FAILURE_FILE)
        if os.path.lexists(path):
            return
        coord.write_exclusive(path, {
            "schema_version": STATE_SCHEMA_VERSION,
            "job_id": self.job_id,
            "stage": stage,
            "attempt": attempt,
            "code": code,
            "message": coord.bounded(message, 300),
            "resource": coord.bounded(resource, 128) if resource else None,
            "step_id": step_id,
            "recorded_at": _now(now),
        })

    def reconcile(self, interruption: Optional[Dict[str, Any]] = None,
                  now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
        """Persist what the evidence proves after a crash, timeout or reboot.

        Undetermined steps make the job ``unknown``; a broken record makes it
        ``recovery_required``. Nothing is started, stopped or deleted: there is
        no automatic recovery, on boot or otherwise.
        """
        self._require_lock()
        view = self.status(interruption)
        recorded = view["recorded_state"]
        target = view["state"]
        attempts: List[Dict[str, Any]] = []
        try:
            attempts = self.attempts()
        except ToolError:
            pass
        interrupted = bool(interruption and interruption.get("interrupted"))
        if attempts and attempts[-1].get("result") is None and (interrupted or target != recorded):
            last = attempts[-1]
            self._close_attempt(last, "interrupted",
                                {"code": "E_INTERRUPTED",
                                 "resource": (interruption or {}).get("reason")},
                                now or contracts.utcnow())
            if target != "recovery_required":
                self._record_failure(last.get("stage"), last.get("attempt"), "E_INTERRUPTED",
                                     "Stage attempt was interrupted before completion.",
                                     (view["unknown_steps"] or [None])[0], now,
                                     resource=(interruption or {}).get("reason"))
        if recorded is not None and target != recorded:
            record = self.state_record()
            self._write_state(target, record.get("stage"), record.get("attempt") or 0, now,
                              reason=view["record_problem"] or "reconciled")
        return self.status(interruption)

    def context(self, plan: Dict[str, Any]) -> contracts.StageContext:
        """The typed :class:`contracts.StageContext` handed to a stream."""
        self._require_lock()
        return contracts.StageContext(self.request(), plan, self.receipts(), self)


def _owned_by_job(steps: Dict[str, Dict[str, Any]], kind: str, resource: str) -> bool:
    return any(step["ownership"] == "created_by_job" and step["outcome"] in ("applied", "unknown")
               and (step["kind"], step["resource"]) == (kind, resource) for step in steps.values())


def _effective_state(state: str, steps: Dict[str, Dict[str, Any]], problem: Optional[str]) -> str:
    if problem is not None or state == "recovery_required":
        return "recovery_required"
    if any(step["outcome"] == "unknown" for step in steps.values()):
        return "unknown"
    return state


def _cutover_accepted(cutover: Optional[Dict[str, Any]]) -> bool:
    """Shape check of :func:`contracts.evaluate_cutover` output (evaluated by P1-09)."""
    if not isinstance(cutover, dict):
        return False
    return all(isinstance(cutover.get(field), str) and cutover.get(field)
               for field in ("observation_digest", "attestation_digest", "fencing_method",
                             "evaluated_at"))


def _failure_summary(failure: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not failure:
        return None
    return {field: failure.get(field) for field in ("code", "stage", "attempt", "step_id", "recorded_at")}


def _next_action(state: str, interrupted: bool) -> str:
    if state in ("unknown", "recovery_required"):
        return "inspect_restore_job"
    if state == "failed":
        return "review_restore_failure"
    if interrupted or state in RUNNING_STAGE:
        return "resume_same_stage"
    for stage in contracts.STAGES:
        if state in contracts.STAGE_ENTRY_STATES[stage] and state not in RUNNING_STAGE:
            return "restore_" + stage
    return "none"


def scan_restore_jobs(root: str) -> List[Dict[str, Any]]:
    """Status of every restore job under ``root`` (read-only)."""
    store = RestoreJobStore(root)
    parent = coord.restore_jobs_root(root)
    if not os.path.isdir(parent) or coord.is_symlink(parent):
        return []
    views = []
    for name in sorted(os.listdir(parent)):
        if name.startswith(".tmp-"):
            continue
        try:
            views.append(store.open(name).status())
        except ToolError as error:
            views.append({"job_id": name, "state": "recovery_required", "blocking": True,
                          "record_problem": error.code})
    return views

