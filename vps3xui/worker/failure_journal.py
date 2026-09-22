"""Shared, first-write-only primary-failure journal semantics.

``failure.json`` records a job's *first* cause. The worker writes it, at most
once, before any recovery; the independent finalizer reads it as the
authoritative cause instead of trusting a later report. Both must agree on
exactly three states for the file and share the identical classification:

* :data:`ABSENT` -- no file: the only state in which a first write is allowed;
* :data:`VALID` -- a readable object naming a failure code;
* :data:`INVALID` -- present but untrusted (unreadable, empty, malformed,
  non-regular, symlinked, the wrong job, or an unsupported schema).

The journal is published with an exclusive, no-follow create and is never
replaced or erased, so the first cause survives a rerun, a second
``_record_failure`` call, a competing writer and a crash. A present but
untrusted journal is surfaced as a curated, content-free diagnostic instead of
its raw bytes. Reading is deliberately bounded and cannot block: the path is
``lstat``-ed first (a non-regular or oversized file is refused before it is
ever opened), then opened no-follow and non-blocking, and the descriptor is
``fstat``-verified against the ``lstat`` result before any byte is read.
"""

from __future__ import annotations

import json
import os
import stat
from typing import Any, Dict, Optional

from ..coordination import create_exclusive, fsync_dir
from ..errors import ToolError
from .jobctx import FAILURE_FILE, now_iso

SCHEMA_VERSION = 1

#: A first-cause journal is a small object; anything larger is refused before
#: its bytes are read, so a corrupt or hostile file can never be pulled into
#: memory (or a blocking pipe can never be drained) as if it were evidence.
MAX_JOURNAL_BYTES = 64 * 1024

ABSENT = "absent"
VALID = "valid"
INVALID = "invalid"

UNREADABLE = "failure_journal_unreadable"
MALFORMED = "failure_journal_malformed"
JOB_MISMATCH = "failure_journal_job_mismatch"
UNSUPPORTED = "failure_journal_unsupported"
OVERSIZED = "failure_journal_oversized"

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

_PROBLEM_MESSAGES = {
    UNREADABLE: (
        "The persisted primary failure journal is unreadable; the original "
        "failure cannot be trusted."
    ),
    MALFORMED: (
        "The persisted primary failure journal is malformed; the original "
        "failure cannot be trusted."
    ),
    JOB_MISMATCH: (
        "The persisted primary failure journal was written for a different "
        "job; the original failure cannot be trusted."
    ),
    UNSUPPORTED: (
        "The persisted primary failure journal uses an unsupported schema; the "
        "original failure cannot be trusted."
    ),
    OVERSIZED: (
        "The persisted primary failure journal is larger than a first-cause "
        "record; the original failure cannot be trusted."
    ),
}


class _JournalUnreadable(Exception):
    """The journal could not be read as a bounded regular file."""


class _JournalOversized(Exception):
    """The journal is larger than the bounded first-cause record allows."""


def _invalid(reason: str) -> Dict[str, Any]:
    return {"status": INVALID, "failure": None, "reason": reason}


def problem(reason: str) -> Dict[str, Any]:
    """A curated, content-free failure for a journal that cannot be trusted."""
    message = _PROBLEM_MESSAGES.get(reason)
    if message is None:
        raise ValueError("unknown failure journal problem: %r" % (reason,))
    return {
        "code": "E_EXECUTION",
        "message": message,
        "resource": FAILURE_FILE,
        "detail": {"reason": reason},
    }


def _provenance_problem(persisted: Dict[str, Any], expected_job_id: Optional[str]) -> Optional[str]:
    """Validate the writer-provenance fields the full journal carries.

    A legacy journal written before provenance fields existed (no
    ``schema_version`` and no ``job_id``) is still accepted, but a field that is
    present and wrong fails closed so another job's record can never be read as
    this job's first cause.
    """
    if "schema_version" in persisted:
        version = persisted.get("schema_version")
        if isinstance(version, bool) or version != SCHEMA_VERSION:
            return UNSUPPORTED
    if expected_job_id is not None and "job_id" in persisted:
        job_id = persisted.get("job_id")
        if not isinstance(job_id, str) or job_id != expected_job_id:
            return JOB_MISMATCH
    return None


def _read_bounded(path: str, expected: os.stat_result) -> bytes:
    """Read the journal, refusing to block, follow or over-read.

    ``lstat`` already proved a small regular file. The descriptor is opened
    no-follow and non-blocking, then ``fstat``-verified to be exactly that file
    (device/inode) *before* any byte is read, so a FIFO or another file swapped
    in between the two calls is refused instead of read or blocked on.
    """
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK)
    except OSError:
        raise _JournalUnreadable()
    try:
        try:
            info = os.fstat(fd)
        except OSError:
            raise _JournalUnreadable()
        if not stat.S_ISREG(info.st_mode):
            raise _JournalUnreadable()
        if (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino):
            raise _JournalUnreadable()
        if info.st_size > MAX_JOURNAL_BYTES:
            raise _JournalOversized()
        chunks = []
        remaining = MAX_JOURNAL_BYTES + 1
        while remaining > 0:
            try:
                block = os.read(fd, remaining)
            except OSError:
                raise _JournalUnreadable()
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    if len(raw) > MAX_JOURNAL_BYTES:
        raise _JournalOversized()
    return raw


def read_state(job_dir: str, expected_job_id: Optional[str] = None) -> Dict[str, Any]:
    """Classify ``failure.json`` as absent, valid or untrusted.

    Returns ``{"status", "failure", "reason"}``: ``failure`` is the trimmed
    primary cause for a valid journal only; ``reason`` is one of the problem
    codes for an invalid one. Only a genuine ``lstat`` ``FileNotFoundError`` is
    absence -- every other stat or read error is unknown evidence, never a
    missing journal -- and the raw contents are never returned.
    """
    path = os.path.join(job_dir, FAILURE_FILE)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return {"status": ABSENT, "failure": None, "reason": None}
    except OSError:
        return _invalid(UNREADABLE)
    if not stat.S_ISREG(info.st_mode):
        return _invalid(UNREADABLE)
    if info.st_size > MAX_JOURNAL_BYTES:
        return _invalid(OVERSIZED)
    try:
        raw = _read_bounded(path, info)
    except _JournalOversized:
        return _invalid(OVERSIZED)
    except (_JournalUnreadable, OSError):
        return _invalid(UNREADABLE)
    try:
        persisted = json.loads(raw.decode("utf-8"))
    except ValueError:
        return _invalid(MALFORMED)
    if not isinstance(persisted, dict):
        return _invalid(MALFORMED)
    code = persisted.get("code")
    if not isinstance(code, str) or not code.strip():
        return _invalid(MALFORMED)
    reason = _provenance_problem(persisted, expected_job_id)
    if reason is not None:
        return _invalid(reason)
    return {
        "status": VALID,
        "failure": {
            "code": code,
            "message": persisted.get("message"),
            "resource": persisted.get("resource"),
        },
        "reason": None,
    }


def reported_failure(state: Dict[str, Any],
                     fallback: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """The authoritative first cause for an already-classified journal state.

    An absent journal has no cause, so the caller's ``fallback`` (a report
    cause, or the in-memory cause a worker just failed to persist) is used. A
    present journal always wins, including the curated diagnostic for an
    untrusted one.
    """
    if state.get("status") == ABSENT:
        return fallback
    failure = state.get("failure")
    if isinstance(failure, dict):
        return failure
    return problem(state.get("reason") or MALFORMED)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write to the primary failure journal")
        view = view[written:]


def record(job_dir: str, code: str, message: Optional[str] = None,
           resource: Optional[str] = None, job_id: Optional[str] = None) -> bool:
    """Publish the first failure durably, only while the file is truly absent.

    Returns ``True`` when this call created the journal -- the only permitted
    write. Returns ``False`` when something already owns the path (a previous
    run, a competing creator that won the race, or a raced-in symlink): nothing
    is opened, replaced or erased. Serialization happens before the exclusive
    create and a write/fsync error is re-raised without unlinking the bytes
    already written, so no failure mode here ever erases first-cause evidence.
    """
    if job_id is None:
        job_id = os.path.basename(os.path.abspath(job_dir).rstrip("/"))
    payload: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "job_id": job_id,
        "code": code,
        "message": message,
        "resource": resource,
        "recorded_at": now_iso(),
    }
    try:
        data = json.dumps(payload, indent=2, sort_keys=True,
                          ensure_ascii=False).encode("utf-8") + b"\n"
    except (TypeError, ValueError):
        raise ToolError("E_STATE_WRITE_FAILED", "The primary failure could not be serialized.",
                        resource=FAILURE_FILE, next_action="retry_state_write")
    path = os.path.join(job_dir, FAILURE_FILE)
    try:
        fd = create_exclusive(path, 0o600)
    except ToolError:
        if os.path.lexists(path):
            # A competing creator (or earlier evidence) owns the path; the
            # caller re-reads it instead of overwriting.
            return False
        raise
    try:
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    # Durably publish the new directory entry, exactly like the other atomic
    # state writers. A failure here still leaves the bytes in place.
    fsync_dir(os.path.dirname(os.path.abspath(path)))
    return True
