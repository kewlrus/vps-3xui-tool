"""Durable local job/request registry, locking and idempotency.

The remote job directory is authoritative for a running operation, but the
local registry is what prevents a duplicate backup when ``backup start`` loses
its SSH response after submission: the request id is written locally *before*
anything is sent, so a retry with the same id resolves the existing record
instead of creating a second job.
"""

from __future__ import annotations

import contextlib
import datetime
import fcntl
import os
from typing import Any, Dict, Iterator, List, Optional

from .errors import ToolError
from .util import read_json, require_private_dir, validate_id, write_json

# Worker states. Terminal states have finished recovery; the rest block new work.
WORKER_STATES = [
    "accepted",
    "preflight",
    "quiescing",
    "copying",
    "recovering",
    "verifying",
    "copied",
    "succeeded",
    "failed",
    "recovery_required",
    "unknown",
    "interrupted",
]

COMPLETE_STATES = {"succeeded", "failed"}
BLOCKING_STATES = [state for state in WORKER_STATES if state not in COMPLETE_STATES]

REQUEST_SCHEMA_VERSION = 1


def default_state_dir() -> str:
    base = os.environ.get("VPS3XUI_STATE_DIR")
    if base:
        return base
    xdg = os.environ.get("XDG_STATE_HOME")
    if not xdg:
        xdg = os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(xdg, "vps3xui")


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class JobStore(object):
    def __init__(self, root: Optional[str] = None):
        self.root = os.path.abspath(root or default_state_dir())
        self.requests_dir = os.path.join(self.root, "requests")
        self.lock_path = os.path.join(self.root, "lock")
        require_private_dir(self.root, 0o700)
        require_private_dir(self.requests_dir, 0o700)

    # -- request registry -------------------------------------------------
    def request_path(self, request_id: str) -> str:
        validate_id(request_id, "request_id")
        return os.path.join(self.requests_dir, request_id + ".json")

    def load_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        path = self.request_path(request_id)
        if not os.path.isfile(path):
            return None
        try:
            return read_json(path)
        except ValueError:
            raise ToolError(
                "E_CONTRACT",
                "Local request record is corrupt.",
                resource=request_id,
                next_action="inspect_local_state",
            )

    def list_requests(self) -> List[Dict[str, Any]]:
        records = []
        try:
            names = sorted(os.listdir(self.requests_dir))
        except OSError:
            return records
        for name in names:
            if not name.endswith(".json"):
                continue
            try:
                record = read_json(os.path.join(self.requests_dir, name))
            except (OSError, ValueError):
                continue
            if isinstance(record, dict) and "request_id" in record:
                records.append(record)
        return records

    def blocking_requests(self) -> List[Dict[str, Any]]:
        return [
            record
            for record in self.list_requests()
            if record.get("state") not in COMPLETE_STATES
        ]

    def assert_no_blocking_work(self, ignoring_request_id: Optional[str] = None) -> None:
        for record in self.blocking_requests():
            if record.get("request_id") == ignoring_request_id:
                continue
            raise ToolError(
                "E_JOB_INCOMPLETE",
                "An incomplete job blocks new work until it is resolved with job recover.",
                resource=record.get("request_id"),
                next_action="job_recover",
            )

    def register_request(
        self,
        request_id: str,
        plan_digest: str,
        manifest_id: str,
        ssh_alias: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Idempotently register a request id before remote submission.

        Same id and same plan resolves the existing record; a different plan
        under an existing id is a hard conflict.
        """
        validate_id(request_id, "request_id")
        existing = self.load_request(request_id)
        if existing is not None:
            if existing.get("plan_digest") != plan_digest or existing.get("manifest_id") != manifest_id:
                raise ToolError(
                    "E_REQUEST_ID_CONFLICT",
                    "Request id is already registered for a different plan.",
                    resource=request_id,
                    next_action="use_new_request_id",
                )
            return existing
        record = {
            "schema_version": REQUEST_SCHEMA_VERSION,
            "request_id": request_id,
            "job_id": request_id,
            "plan_digest": plan_digest,
            "manifest_id": manifest_id,
            "ssh_alias": ssh_alias,
            "state": "registered",
            "registered_at": _utcnow(),
            "submitted_at": None,
            "unit_name": None,
            "backup_dir": None,
            "last_error_code": None,
        }
        if extra:
            record.update(extra)
        write_json(self.request_path(request_id), record, mode=0o600)
        return record

    def update_request(self, request_id: str, **fields: Any) -> Dict[str, Any]:
        record = self.load_request(request_id)
        if record is None:
            raise ToolError("E_JOB_NOT_FOUND", "Request is not registered locally.", resource=request_id)
        record.update(fields)
        write_json(self.request_path(request_id), record, mode=0o600)
        return record

    # -- exclusive lock ---------------------------------------------------
    @contextlib.contextmanager
    def lock(self, wait_seconds: int = 0) -> Iterator[None]:
        """Exclusive lock covering registration, work and finalization."""
        require_private_dir(self.root, 0o700)
        fd = os.open(self.lock_path,
                    os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            if wait_seconds <= 0:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    raise ToolError(
                        "E_LOCKED",
                        "Another vps3xui operation holds the lock.",
                        resource=os.path.basename(self.root),
                        next_action="wait_or_inspect",
                    )
            else:
                import time

                deadline = time.time() + wait_seconds
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except OSError:
                        if time.time() >= deadline:
                            raise ToolError(
                                "E_LOCKED",
                                "Another vps3xui operation holds the lock.",
                                resource=os.path.basename(self.root),
                                next_action="wait_or_inspect",
                            )
                        time.sleep(0.2)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "schema_version": REQUEST_SCHEMA_VERSION,
            "requests": sorted(self.list_requests(), key=lambda item: item.get("request_id") or ""),
            "blocking": [item.get("request_id") for item in self.blocking_requests()],
        }
