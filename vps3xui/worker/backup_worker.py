"""Autonomous backup worker: the durable state machine that runs on the host.

The worker is pinned by version, launched by systemd with runtime/stop bounds
and ``KillMode=control-group`` and continues without the model or an SSH
session. Before any effect it acquires the host-wide stack lock, proves it is
the reserved owner of this job, re-probes the source and re-verifies the whole
reviewed plan against live facts (expiry, trust, mounts, volumes, paths, image
digests, boot/machine identity and free space). It records original state
durably before changing anything, stops only recorded originally-running
container ids, copies the declared data, restarts those ids, restores the exact
original timer state and leaves ``COMPLETE`` to the independent finalizer.

An interrupted run is never restarted: a job whose durable state already shows
effects is marked ``interrupted`` and only the finalizer recovers it.

All host effects go through a small ``SystemOps`` object. ``RealSystem`` uses
Docker/systemd/GNU tar; the test suite uses a synthetic in-process system, so
the failure transitions below are exercised for real rather than mocked.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Optional

from .. import TOOL_VERSION
from .. import coordination as coord
from ..adapters import archive as archive_adapter
from ..errors import ToolError
from ..inventory import compare, probe_spec
from ..plan import verify_plan
from ..util import require_private_dir, sha256_file, write_json
from . import failure_journal
from .jobctx import (
    INITIAL_STATE_FILE,
    PLAN_FILE,
    REPORT_FILE,
    REQUEST_FILE,
    STATE_FILE,
    JobContext,
    now_iso,
)

REPORT_SCHEMA_VERSION = 1

# Bounded, ownership-aware launcher-to-worker lock handoff. The submitter
# (``remote_ops._create_and_launch``) holds the host stack lock across the
# ``systemd-run --property=Type=exec`` call and the launch-receipt write, so the
# worker is exec'd while the lock is still held. Rather than exit ``E_LOCKED``
# before it can persist the original state, the worker waits a finite window
# that strictly exceeds the submitter's own bound (``remote_ops._launch`` uses a
# 120s timeout, plus the receipt write). The wait is always bounded; a worker
# that is not this job's reserved owner never waits at all.
LOCK_HANDOFF_SECONDS = 150

# Durable no-effects proof written into ``report.json`` when a failure is caught
# before ``changes_started`` (i.e. no Docker stop, no Certbot mutation, no copy
# ever began). The independent finalizer reads exactly these field names and
# phase set -- keep them in sync with ``finalizer``'s mirrored constants.
PREFLIGHT_EVIDENCE_KEY = "preflight_evidence"
PRE_EFFECT_PHASES = ("accepted", "preflight")


class RecoveryError(Exception):
    def __init__(self, message: str, code: str = "E_RECOVERY_REQUIRED", resource: Optional[str] = None):
        super(RecoveryError, self).__init__(message)
        self.code = code
        self.message = message
        self.resource = resource


class BackupWorker(object):
    def __init__(self, system, job_dir: str, manifest,
                 probe: Optional[Callable[[Dict[str, Any]], Any]] = None):
        self.system = system
        self.manifest = manifest
        self.ctx = JobContext(job_dir)
        self.backup_dir = os.path.join(self.ctx.job_dir, "backup")
        self.probe = probe if probe is not None else getattr(system, "probe", None)
        self.request: Dict[str, Any] = {}
        self.initial_state: Dict[str, Any] = {}
        self.original_failure: Optional[Dict[str, Any]] = None
        self.recovery_result: Dict[str, Any] = {}
        self.artifacts: List[Dict[str, Any]] = []
        self.changes_started = False
        self.state = "accepted"

    # -- helpers ----------------------------------------------------------
    def _set_state(self, state: str, **fields: Any) -> None:
        previous = self.state
        self.state = state
        payload = {
            "schema_version": 1,
            "job_id": os.path.basename(self.ctx.job_dir.rstrip("/")),
            "state": state,
            "previous_state": previous,
            "updated_at": now_iso(),
            "tool_version": TOOL_VERSION,
        }
        payload.update(fields)
        self.ctx.write_json(STATE_FILE, payload)
        self.ctx.append_event({"state": state, "previous_state": previous, "step": fields.get("step")})

    def _record_failure(self, code: str, message: str, resource: Optional[str] = None) -> None:
        """Persist the primary failure independently, before any recovery.

        The journal is first-write-only: existing bytes -- valid, malformed,
        unreadable or owned by another writer -- are never overwritten. When
        this call cannot own the path (a previous run, a competing creator or
        an unwritable directory), the on-disk first cause is re-read and
        adopted; a truly absent file that cannot be created leaves only the
        in-memory cause, which the report still carries.
        """
        if self.original_failure is not None:
            return
        in_memory = {"code": code, "message": message, "resource": resource}
        job_id = os.path.basename(self.ctx.job_dir.rstrip("/"))
        try:
            created = failure_journal.record(self.ctx.job_dir, code=code, message=message,
                                             resource=resource, job_id=job_id)
        except (ToolError, OSError, ValueError):
            created = False
        if created:
            self.original_failure = in_memory
        else:
            persisted = failure_journal.read_state(self.ctx.job_dir, job_id)
            self.original_failure = failure_journal.reported_failure(persisted, in_memory)
        self.ctx.append_event({"step": "failure", "code": code, "resource": resource})

    # -- steps ------------------------------------------------------------
    def _preflight(self) -> None:
        self._set_state("preflight", step="preflight")
        self.request = self.ctx.read_json(REQUEST_FILE) or {}
        requested_backup_dir = self.request.get("backup_dir")
        if isinstance(requested_backup_dir, str) and requested_backup_dir.startswith("/"):
            self.backup_dir = requested_backup_dir
        expected_machine = self.request.get("machine_id")
        observed = self.system.machine_id()
        if expected_machine and expected_machine != observed:
            raise ToolError(
                "E_HOST_IDENTITY_MISMATCH",
                "Machine-id changed after the job was registered.",
                resource="machine-id",
                next_action="recover_and_review",
            )

        # Re-verify the full reviewed plan against a fresh inventory under lock.
        plan = self.ctx.read_json(PLAN_FILE)
        if not isinstance(plan, dict):
            raise ToolError("E_PLAN_STALE", "The job directory has no reviewed plan.",
                            resource="plan", next_action="job_recover")
        if self.request.get("plan_digest") and self.request["plan_digest"] != plan.get("identity"):
            raise ToolError("E_PLAN_STALE", "The job's plan digest does not match its plan.",
                            resource="plan", next_action="job_recover")
        if self.probe is None:
            raise ToolError("E_RUNTIME_MISSING", "No probe is available to re-verify the plan.",
                            resource="probe", next_action="inspect_worker")
        inventory = self.probe(probe_spec(self.manifest))
        compare(self.manifest, inventory).raise_if_blocking()
        verify_plan(plan, self.manifest, inventory,
                    self.request.get("host_key_fingerprint"),
                    host_context=self.request.get("host_context") or None)

        recorded = self.request.get("stop_containers") or []
        self.initial_state = {
            "schema_version": 1,
            "recorded_at": now_iso(),
            "machine_id": observed,
            "stop_containers": recorded,
            "leave_stopped": self.request.get("leave_stopped") or [],
            "containers": {},
            "certbot": None,
            "lease_active": None,
        }
        names = [item["name"] for item in self.manifest.containers]
        facts = self.system.container_states(names)
        self.initial_state["containers"] = facts
        recorded_names = {item["name"] for item in recorded}
        for item in recorded:
            fact = facts.get(item["name"])
            if not fact or not fact.get("running"):
                raise ToolError(
                    "E_PLAN_STALE",
                    "A container that the plan recorded as running is not running.",
                    resource=item["name"], next_action="rebuild_plan")
            if fact.get("id") != item.get("id"):
                raise ToolError(
                    "E_PLAN_STALE",
                    "A container id changed since the plan was built.",
                    resource=item["name"], next_action="rebuild_plan")
        for name, fact in facts.items():
            if fact and fact.get("running") and name not in recorded_names:
                declared = self.manifest.container(name)
                if declared is None or declared.get("included") is False:
                    raise ToolError(
                        "E_PLAN_STALE",
                        "A container started after the plan and may be writing data.",
                        resource=name, next_action="rebuild_plan")
        for name in self.system.running_container_names():
            if name in recorded_names:
                continue
            declared = self.manifest.container(name)
            if declared is None:
                raise ToolError("E_PLAN_STALE",
                                "A running container is absent from the approved manifest.",
                                resource=name, next_action="rebuild_plan")
            if declared.get("included") is False:
                raise ToolError("E_PLAN_STALE",
                                "A container marked as excluded is running and may be writing data.",
                                resource=name, next_action="rebuild_plan")
            if declared.get("expected_state") == "running":
                raise ToolError("E_PLAN_STALE",
                                "An included running container was not recorded by the plan.",
                                resource=name, next_action="rebuild_plan")
        if self.system.check_lease(self.manifest):
            raise ToolError(
                "E_PRECONDITION",
                "An active Certbot HTTP-01 lease is present; copy must not start.",
                resource=self.manifest.certbot["lease_path"], next_action="wait_for_lease")
        required = self.manifest.required_artifacts()
        estimate = int(self.request.get("required_bytes_estimate") or 0)
        free = self.system.free_bytes(self.system.backup_root())
        if estimate <= 0:
            raise ToolError("E_PRECONDITION", "Required space could not be estimated.",
                            resource="disk", next_action="inspect_storage")
        if free <= 0:
            raise ToolError("E_PRECONDITION", "Free space at the backup root is unknown or zero.",
                            resource="disk", next_action="inspect_storage")
        if free < estimate:
            raise ToolError("E_PRECONDITION", "Estimated space is not available for the backup.",
                            resource="disk", next_action="free_space_or_reduce_scope")
        self.system.fsync_paths(self.manifest)
        require_private_dir(self.ctx.job_dir, 0o700)
        self.ctx.write_json(INITIAL_STATE_FILE, self.initial_state)
        if not self.ctx.exists(INITIAL_STATE_FILE):
            raise ToolError("E_STATE_WRITE_FAILED", "Original state could not be recorded.",
                            resource=INITIAL_STATE_FILE, next_action="abort")
        self.ctx.append_event({"step": "preflight", "outcome": "ok", "count": len(required)})

    def _quiesce(self) -> None:
        self._set_state("quiescing", step="quiesce")
        certbot_state = self.system.certbot_state(self.manifest)
        self.initial_state["certbot"] = certbot_state
        self.initial_state["lease_active"] = self.system.check_lease(self.manifest)
        self.ctx.write_json(INITIAL_STATE_FILE, self.initial_state)
        self.changes_started = True
        self.system.disable_certbot_triggers(self.manifest)
        if self.system.certbot_renewal_active(self.manifest) or self.system.check_lease(self.manifest):
            self.system.restore_certbot_triggers(certbot_state, self.manifest)
            raise ToolError(
                "E_CONFLICT",
                "A Certbot renewal started while triggers were being disabled.",
                resource=self.manifest.certbot["timer_unit"],
                next_action="review_certbot_schedulers")
        facts = self.system.container_states([c["name"] for c in self.manifest.containers])
        for item in self.initial_state["stop_containers"]:
            fact = facts.get(item["name"])
            if not fact or fact.get("id") != item.get("id") or not fact.get("running"):
                self.system.restore_certbot_triggers(certbot_state, self.manifest)
                raise ToolError(
                    "E_PLAN_STALE",
                    "Container state changed after preflight and before stop.",
                    resource=item["name"], next_action="rebuild_plan")
        self.ctx.append_event({"step": "quiesce", "outcome": "ok"})

    def _copy(self) -> None:
        self._set_state("copying", step="copy")
        recorded = [item for item in self.initial_state["stop_containers"]]
        for item in recorded:
            self.system.stop_containers([item["id"]])
        facts = self.system.container_states([item["name"] for item in recorded])
        for item in recorded:
            fact = facts.get(item["name"])
            if fact and fact.get("running"):
                raise ToolError("E_EXECUTION", "A container did not stop before copying.",
                                resource=item["name"], next_action="inspect_runtime")
        require_private_dir(self.backup_dir, 0o700)
        for tree in self.manifest.bind_trees:
            self.system.copy_bind_tree(self.backup_dir, tree)
        for volume in self.manifest.volumes:
            self.system.copy_volume(self.backup_dir, volume)
        id_by_name = {item["name"]: item["id"] for item in recorded}
        for layer in self.manifest.writable_layers:
            self.system.copy_writable_layer(self.backup_dir, layer,
                                            container_id=id_by_name.get(layer["container"]))
        self.system.copy_certbot_automation(self.backup_dir, self.manifest)
        self.system.copy_reference_artifacts(self.backup_dir, self.manifest)
        self.system.write_metadata(self.backup_dir, self.manifest, self.initial_state)
        self._assert_required_present()
        self.ctx.append_event({"step": "copy", "outcome": "ok",
                               "count": len(self.manifest.required_artifacts())})

    def _assert_required_present(self) -> None:
        for name in self.manifest.required_artifacts():
            path = os.path.join(self.backup_dir, name)
            if not os.path.isfile(path) or os.path.getsize(path) == 0:
                raise ToolError("E_MISSING_ARTIFACT",
                                "A required artifact was not produced by the copy step.",
                                resource=name, next_action="inspect_worker")

    def _recover(self) -> Dict[str, Any]:
        self._set_state("recovering", step="recover")
        recorded = self.initial_state.get("stop_containers") or []
        started: List[str] = []
        failures: List[str] = []
        start_error: Optional[Exception] = None
        for item in recorded:
            try:
                self.system.start_containers([item["id"]])
            except Exception as error:  # noqa: BLE001 - recovery must attempt every step
                if start_error is None:
                    start_error = error
        facts = self.system.container_states([item["name"] for item in recorded])
        for item in recorded:
            fact = facts.get(item["name"])
            if fact and fact.get("running") and fact.get("id") == item["id"]:
                started.append(item["name"])
            else:
                failures.append(item["name"])
        certbot_restored = False
        certbot_state = self.initial_state.get("certbot")
        if certbot_state is not None:
            try:
                self.system.restore_certbot_triggers(certbot_state, self.manifest)
                certbot_restored = True
            except Exception:  # noqa: BLE001
                certbot_restored = False
        self.recovery_result = {
            "containers_started": started,
            "container_failures": failures,
            "certbot_restored": certbot_restored,
            "recovery_complete": not failures and certbot_restored,
        }
        self.ctx.append_event({"step": "recover",
                               "outcome": "ok" if not failures else "failed", "count": len(started)})
        if failures or not certbot_restored:
            if self.original_failure is None and isinstance(start_error, ToolError):
                self._record_failure(start_error.code,
                                     "Container restart failed during recovery.",
                                     resource=(failures[0] if failures else None))
            raise RecoveryError(
                "Source runtime recovery did not complete for every recorded resource.",
                resource=(failures[0] if failures else "certbot"))
        return self.recovery_result

    def _verify(self) -> None:
        self._set_state("verifying", step="verify")
        self._assert_required_present()
        names = self.manifest.required_artifacts()
        from ..verify import REPORT_NAME, build_sums

        self.artifacts = []
        for name in names:
            path = os.path.join(self.backup_dir, name)
            self.artifacts.append({"name": name, "sha256": sha256_file(path),
                                   "size": os.path.getsize(path)})
            if name.endswith(".tar"):
                from ..verify import _check_membership
                report = archive_adapter.validate_tar(path)
                _check_membership(self.manifest, name, report)
        write_json(
            os.path.join(self.backup_dir, REPORT_NAME),
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "job_id": os.path.basename(self.ctx.job_dir),
                "tool_version": TOOL_VERSION,
                "manifest_id": self.manifest.manifest_id,
                "manifest_digest": self.manifest.digest,
                "copy_state": "copied",
                "state": "copied",
                "data_integrity": "verified",
                "source_runtime_recovery": "verified",
                "passive_proxy_checks": "not_run",
                "model_generation": "not_run",
                "telegram_client_test": "not_run",
                "restore_drill": "not_run",
                "required_artifacts": names,
                "artifacts": self.artifacts,
                "original_failure": None,
                "recovery": self.recovery_result,
                "completed_at": now_iso(),
            },
            mode=0o600,
        )
        sums = build_sums(self.backup_dir, names + [REPORT_NAME])
        coord.atomic_write_bytes(os.path.join(self.backup_dir, "SHA256SUMS"), sums, mode=0o600)
        self.ctx.append_event({"step": "verify", "outcome": "ok", "count": len(names)})

    # -- report / entry ---------------------------------------------------
    def _no_effects_evidence(self, phase: str) -> Optional[Dict[str, Any]]:
        """Durable proof that a caught failure happened before any host effect.

        Only a failure caught while ``changes_started`` is False and the worker
        was still in a pre-effects phase qualifies. The record binds the proof
        to this job and the immutable request (job id, request id and plan
        digest) so the independent finalizer can refuse a stale, foreign or
        forged report. ``None`` means the worker cannot prove that no effect
        began; the job must then stay ``unknown`` and be recovered explicitly.
        """
        if phase not in PRE_EFFECT_PHASES:
            return None
        request = self.request if isinstance(self.request, dict) else {}
        request_id = request.get("request_id") or request.get("job_id")
        plan_digest = request.get("plan_digest")
        if not isinstance(request_id, str) or not request_id.strip():
            return None
        if not isinstance(plan_digest, str) or not plan_digest.strip():
            return None
        return {
            "effects_started": False,
            "phase": phase,
            "job_id": os.path.basename(self.ctx.job_dir.rstrip("/")),
            "request_id": request_id,
            "plan_digest": plan_digest,
        }

    def _write_report(self, state: str, evidence: Optional[Dict[str, Any]] = None) -> None:
        report = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "job_id": os.path.basename(self.ctx.job_dir),
            "tool_version": TOOL_VERSION,
            "backup_dir": self.backup_dir,
            "manifest_id": self.manifest.manifest_id,
            "manifest_digest": self.manifest.digest,
            "state": state,
            "data_integrity": "verified" if state in ("copied", "succeeded") else "not_run",
            "source_runtime_recovery": (
                "verified" if self.recovery_result.get("recovery_complete") else
                "failed" if state == "recovery_required" else "not_run"
            ),
            "passive_proxy_checks": "not_run",
            "model_generation": "not_run",
            "telegram_client_test": "not_run",
            "restore_drill": "not_run",
            "required_artifacts": self.manifest.required_artifacts(),
            "artifacts": self.artifacts,
            "original_failure": self.original_failure,
            "recovery": self.recovery_result,
            "completed_at": now_iso(),
        }
        if evidence is not None:
            report[PREFLIGHT_EVIDENCE_KEY] = evidence
        self.ctx.write_json(REPORT_FILE, report)

    def run(self) -> Dict[str, Any]:
        job_id = os.path.basename(self.ctx.job_dir.rstrip("/"))
        root = coord.root_for_job_dir(self.ctx.job_dir)
        # Ownership-aware: only this job's reserved owner may wait for the
        # launcher lock. A stray or duplicate worker (no/mismatched reservation)
        # fails immediately instead of occupying the host for the handoff bound.
        coord.assert_owned(root, job_id)
        with coord.stack_lock(root, wait_seconds=LOCK_HANDOFF_SECONDS):
            coord.assert_owned(root, job_id)
            coord.assert_no_blocking(root, ignoring=job_id)
            return self._run_locked(job_id)

    def _run_locked(self, job_id: str) -> Dict[str, Any]:
        existing = self.ctx.read_json(STATE_FILE) or {}
        self.state = existing.get("state", "accepted")
        if self.state in coord.COMPLETE_STATES:
            report = self.ctx.read_json(REPORT_FILE) or {}
            # A terminal job whose evidence contradicts its completion claim
            # must not be reported as a success by a rerun: no preflight, copy
            # or start runs here, and only the finalizer may reconcile it.
            conflict = coord.completion_conflict(self.ctx.job_dir)
            if conflict is None:
                return report or {"state": self.state}
            persisted = failure_journal.read_state(self.ctx.job_dir, job_id)
            self.original_failure = (
                failure_journal.reported_failure(persisted) or report.get("original_failure")
            )
            return {
                "state": "recovery_required",
                "recovered": False,
                "reason": conflict,
                "original_failure": self.original_failure,
            }
        persisted = self.ctx.read_json(INITIAL_STATE_FILE)
        if persisted:
            self.initial_state = persisted
        # The durable journal is authoritative for the FIRST cause, even when
        # it cannot be trusted; the report is only a fallback.
        journal = failure_journal.read_state(self.ctx.job_dir, job_id)
        self.original_failure = (
            failure_journal.reported_failure(journal)
            or (self.ctx.read_json(REPORT_FILE) or {}).get("original_failure")
        )
        if self.state not in ("accepted",) or journal["status"] != failure_journal.ABSENT:
            # A previous run already started effects for this job, or left
            # first-failure evidence on disk. Never re-run preflight (which
            # would stop/copy again); only the finalizer may recover the
            # recorded state.
            self._record_failure("E_INTERRUPTED",
                                 "A previous worker run did not finish; use job recover.",
                                 resource=job_id)
            self._set_state("interrupted", step="interrupted")
            self._write_report("interrupted")
            return self.ctx.read_json(REPORT_FILE) or {}
        try:
            self._preflight()
            self._quiesce()
            self._copy()
            try:
                self._recover()
            except RecoveryError as recovery_error:
                self._record_failure("E_RECOVERY_REQUIRED", recovery_error.message, recovery_error.resource)
                self._set_state("recovery_required", step="recover")
                self._write_report("recovery_required")
                return self.ctx.read_json(REPORT_FILE) or {}
            self._verify()
            self._set_state("copied", step="finalize")
            self._write_report("copied")
            return self.ctx.read_json(REPORT_FILE) or {}
        except (ToolError, OSError, ValueError, KeyError, TypeError) as error:
            # Capture the phase the failure was raised in before the state is
            # rewritten to ``failed``: a failure caught with ``changes_started``
            # still False never began any host effect.
            phase = self.state
            if isinstance(error, ToolError):
                code, message, resource = error.code, error.message, error.resource
            else:
                code = "E_EXECUTION"
                message = "The worker stopped on an unexpected runtime error."
                resource = None
            self._record_failure(code, message, resource)
            evidence: Optional[Dict[str, Any]] = None
            if self.changes_started:
                try:
                    self._recover()
                except RecoveryError as recovery_error:
                    self._record_failure("E_RECOVERY_REQUIRED", recovery_error.message, recovery_error.resource)
                    self._set_state("recovery_required", step="failed")
                    self._write_report("recovery_required")
                    return self.ctx.read_json(REPORT_FILE) or {}
            else:
                evidence = self._no_effects_evidence(phase)
            self._set_state("failed", step="failed")
            self._write_report("failed", evidence)
            return self.ctx.read_json(REPORT_FILE) or {}


def main(argv=None) -> int:
    """Entry point used by the shipped ``bin/vps3xui-worker`` wrapper."""
    import argparse
    import json
    import sys

    from .. import manifest as manifest_module
    from .system import RealSystem

    os.umask(0o077)
    parser = argparse.ArgumentParser(prog="vps3xui-worker")
    parser.add_argument("job_dir")
    parser.add_argument("--release-dir", default=os.environ.get("VPS3XUI_RELEASE_DIR"))
    args = parser.parse_args(argv)
    # The manifest saved in the job directory is authoritative for the job.
    manifest_path = os.path.join(args.job_dir, "manifest.json")
    if not os.path.isfile(manifest_path):
        if not args.release_dir:
            raise SystemExit("the job has no manifest and no --release-dir was given")
        manifest_path = os.path.join(args.release_dir, "manifest.json")
    manifest = manifest_module.load(manifest_path)
    worker = BackupWorker(RealSystem(release_dir=args.release_dir), args.job_dir, manifest)
    report = worker.run()
    print(json.dumps({"state": report.get("state"),
                      "code": (report.get("original_failure") or {}).get("code")},
                     sort_keys=True))
    return 0 if report.get("state") == "copied" else 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
