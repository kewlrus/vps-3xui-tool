"""Shared reviewed primitives plus the host-wide stack lock and reservation.

This module is deliberately *stdlib only* so the exact same reviewed code can be
shipped to a source host over stdin (``remote_ops``) and imported by the
in-package ``worker``/``finalizer``/``backup`` paths. It therefore owns the small
filesystem primitives that must not diverge between those two contexts
(``ensure_dir``, ``require_private_dir``, ``atomic_write_bytes``,
``read_bytes_nofollow``, ``create_exclusive``, ``validate_id``); ``vps3xui.util``
re-exports them.

Coordination contract:

* ``backup start`` reserves and launches under :func:`stack_lock`;
* the worker holds the lock for its whole effect window and must be the reserved
  owner;
* the finalizer re-acquires the lock, restores the source and publishes
  ``COMPLETE`` last;
* ``job recover`` re-acquires the lock, refuses a live unit and finishes a job it
  owns;
* a P1 restore job (``restore-jobs/<id>``) takes the same lock, and until it
  reaches a settled state it blocks backups, recovers and other restores of this
  stack on the host, exactly as an unfinished backup blocks it.

Nothing here prints file contents or environment values.
"""

from __future__ import annotations

import contextlib
import datetime
import errno
import fcntl
import json
import os
import re
import stat
import tempfile
import time
from typing import Any, Dict, Iterator, List, Optional, Tuple

try:  # normal in-package import
    from .errors import ToolError
except Exception:  # pragma: no cover - shipped standalone over stdin
    class ToolError(Exception):  # type: ignore[no-redef]
        """Minimal compatible error for the shipped standalone code path."""

        def __init__(self, code, message, resource=None, next_action=None):
            super(ToolError, self).__init__(message)
            self.code = code
            self.message = message
            self.resource = resource
            self.next_action = next_action


STATE_FILE = "state.json"
REQUEST_FILE = "request.json"
PLAN_FILE = "plan.json"
MANIFEST_FILE = "manifest.json"
REPORT_FILE = "report.json"
EVENTS_FILE = "events.log"
INITIAL_STATE_FILE = "initial-state.json"
FAILURE_FILE = "failure.json"
RESERVATION_FILE = "reservation.json"
LAUNCHED_FILE = "launched.json"
RECOVERY_FILE = "recovery.json"
COMPLETE_FILE = "COMPLETE"

RESERVATION_SCHEMA_VERSION = 1

COMPLETE_STATES = ("succeeded", "failed")
# States that mean effects may have started: a rerun must never repeat them.
MID_STATES = (
    "preflight",
    "quiescing",
    "copying",
    "recovering",
    "verifying",
    "copied",
    "recovery_required",
    "unknown",
    "interrupted",
)
# Restore jobs live beside backup jobs under the same root and lock. Only a
# restore that delivered a verified target is settled; every other restore
# state (a paused stage boundary included) keeps blocking new work.
RESTORE_JOBS_DIR = "restore-jobs"
RESTORE_SETTLED_STATES = ("verified", "certbot_active")
# States where a dead unit means the job was interrupted rather than finished.
LIVE_STATES = ("accepted", "preflight", "quiescing", "copying", "recovering", "verifying")

DEFAULT_DIR_MODE = 0o700
DEFAULT_FILE_MODE = 0o600
MAX_ID_LENGTH = 63

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,%d}$" % MAX_ID_LENGTH)

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)

_PLATFORM_SYMLINKS: Optional[set] = None


# -- primitives --------------------------------------------------------------
def bounded(text: Optional[str], limit: int = 400) -> str:
    if not text:
        return ""
    flat = " ".join(str(text).split())
    if len(flat) > limit:
        return flat[: limit - 3] + "..."
    return flat


def validate_id(value: str, what: str = "id") -> str:
    """Return a validated identifier or raise ``E_UNSAFE_ID``.

    Identifiers become path components and unit names, so separators, ``..`` and
    leading dots/dashes are refused.
    """
    if not isinstance(value, str) or not ID_RE.match(value):
        raise ToolError("E_UNSAFE_ID", "Identifier %r is not a safe %s." % (bounded(repr(value), 80), what),
                        resource=what, next_action="use_safe_identifier")
    if value in (".", "..") or ".." in value.split("."):
        raise ToolError("E_UNSAFE_ID", "Identifier %r is not safe." % what, resource=what)
    return value


def is_symlink(path: str) -> bool:
    try:
        return stat.S_ISLNK(os.lstat(path).st_mode)
    except OSError:
        return False


def owned_by_current_user(path: str) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return info.st_uid == os.geteuid()


def _platform_symlinks() -> set:
    """Platform mount links (macOS ``/var``/``/tmp`` -> ``/private``).

    These are pre-existing and outside any caller's writable root; every other
    symlink component is refused.
    """
    links = set()
    probe = os.path.abspath(tempfile.gettempdir())
    while probe and probe != os.path.dirname(probe):
        if is_symlink(probe):
            links.add(probe)
        probe = os.path.dirname(probe)
    return links


def _symlink_ancestors(path: str, trust_root: Optional[str] = None) -> List[str]:
    global _PLATFORM_SYMLINKS
    if _PLATFORM_SYMLINKS is None:
        _PLATFORM_SYMLINKS = _platform_symlinks()
    accepted = set(_PLATFORM_SYMLINKS)
    if trust_root:
        probe = os.path.abspath(trust_root)
        while probe and probe != os.path.dirname(probe):
            accepted.add(probe)
            probe = os.path.dirname(probe)
    found = []
    probe = os.path.abspath(path)
    while probe and probe != os.path.dirname(probe):
        if is_symlink(probe) and probe not in accepted:
            found.append(probe)
        probe = os.path.dirname(probe)
    return found


def symlink_ancestors(path: str, trust_root: Optional[str] = None) -> List[str]:
    """Public alias: every symlink component of ``path`` except platform links."""
    return _symlink_ancestors(path, trust_root=trust_root)


def ensure_dir(path: str, mode: int = DEFAULT_DIR_MODE, trust_root: Optional[str] = None) -> str:
    """Create ``path`` (and only the missing components) with ``mode``.

    Every existing component is validated first, so a symlink ancestor can never
    redirect a write or a chmod. Existing directories are never re-mode'd and
    no unrelated parent is ever chmodded.
    """
    path = os.path.abspath(path)
    unsafe = _symlink_ancestors(path, trust_root=trust_root)
    if unsafe:
        raise ToolError("E_UNSAFE_PATH", "Directory path has a symlink component.",
                        resource=os.path.basename(unsafe[0]), next_action="use_real_directory")
    missing: List[str] = []
    probe = path
    while True:
        try:
            info = os.lstat(probe)
        except FileNotFoundError:
            info = None
        except OSError:
            raise ToolError("E_STATE_WRITE_FAILED", "Directory path could not be inspected.",
                            resource=os.path.basename(probe), next_action="check_permissions")
        if info is not None:
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise ToolError("E_UNSAFE_PATH", "Directory path is not a real directory.",
                                resource=os.path.basename(probe), next_action="use_real_directory")
            break
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        missing.append(probe)
        probe = parent
    for component in reversed(missing):
        try:
            os.mkdir(component, mode)
        except FileExistsError:
            # A concurrent creator owns this component; validate it without
            # changing its mode.
            try:
                info = os.lstat(component)
            except OSError:
                raise ToolError("E_UNSAFE_PATH", "Directory path could not be inspected.",
                                resource=os.path.basename(component), next_action="use_real_directory")
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise ToolError("E_UNSAFE_PATH", "Directory path is not a real directory.",
                                resource=os.path.basename(component), next_action="use_real_directory")
            continue
        except OSError:
            raise ToolError("E_STATE_WRITE_FAILED", "Directory could not be created.",
                            resource=os.path.basename(component), next_action="check_permissions")
        # Only a component created by this call is re-mode'd to the requested
        # mode. The directory fd plus inode check keeps that chmod from
        # following a race-swapped symlink or touching a different directory.
        try:
            created_info = os.lstat(component)
        except OSError:
            raise ToolError("E_STATE_WRITE_FAILED", "Directory could not be inspected.",
                            resource=os.path.basename(component), next_action="check_permissions")
        if stat.S_ISLNK(created_info.st_mode) or not stat.S_ISDIR(created_info.st_mode):
            raise ToolError("E_UNSAFE_PATH", "Directory path is not a real directory.",
                            resource=os.path.basename(component), next_action="use_real_directory")
        flags = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW
        try:
            fd = os.open(component, flags)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise ToolError("E_UNSAFE_PATH", "Directory was replaced while being created.",
                                resource=os.path.basename(component), next_action="use_real_directory")
            raise ToolError("E_STATE_WRITE_FAILED", "Directory mode could not be set.",
                            resource=os.path.basename(component), next_action="check_permissions")
        try:
            opened_info = os.fstat(fd)
            if (not stat.S_ISDIR(opened_info.st_mode)
                    or (opened_info.st_dev, opened_info.st_ino) != (created_info.st_dev, created_info.st_ino)):
                raise ToolError("E_UNSAFE_PATH", "Directory was replaced while being created.",
                                resource=os.path.basename(component), next_action="use_real_directory")
            os.fchmod(fd, mode)
        except ToolError:
            raise
        except OSError:
            raise ToolError("E_STATE_WRITE_FAILED", "Directory mode could not be set.",
                            resource=os.path.basename(component), next_action="check_permissions")
        finally:
            os.close(fd)
    try:
        final_info = os.lstat(path)
    except OSError:
        raise ToolError("E_STATE_WRITE_FAILED", "Directory could not be created.",
                        resource=os.path.basename(path), next_action="check_permissions")
    if stat.S_ISLNK(final_info.st_mode) or not stat.S_ISDIR(final_info.st_mode):
        raise ToolError("E_UNSAFE_PATH", "Directory path is not a real directory.",
                        resource=os.path.basename(path), next_action="use_real_directory")
    return path


def require_private_dir(path: str, mode: int = DEFAULT_DIR_MODE, trust_root: Optional[str] = None) -> str:
    """Ensure ``path`` exists as a real, owned, private directory.

    Ownership is checked before any chmod, so an existing or raced-in foreign
    directory is never re-mode'd. The final component is opened no-follow and
    the mode is applied through that descriptor.
    """
    path = os.path.abspath(path)
    if is_symlink(path):
        raise ToolError("E_UNSAFE_PATH", "Directory is a symlink.",
                        resource=os.path.basename(path), next_action="use_real_directory")
    ensure_dir(path, mode, trust_root=trust_root)
    try:
        fd = os.open(path, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise ToolError("E_UNSAFE_PATH", "Directory is not a real directory.",
                            resource=os.path.basename(path), next_action="use_real_directory")
        raise ToolError("E_STATE_WRITE_FAILED", "Directory could not be opened.",
                        resource=os.path.basename(path), next_action="fix_permissions")
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            raise ToolError("E_UNSAFE_PATH", "Path is not a real directory.",
                            resource=os.path.basename(path), next_action="use_real_directory")
        if info.st_uid != os.geteuid():
            raise ToolError("E_STATE_WRITE_FAILED", "Directory is not owned by the current user.",
                            resource=os.path.basename(path), next_action="fix_permissions")
        if stat.S_IMODE(info.st_mode) != mode:
            try:
                os.fchmod(fd, mode)
            except OSError:
                raise ToolError("E_STATE_WRITE_FAILED", "Directory mode could not be set.",
                                resource=os.path.basename(path), next_action="fix_permissions")
    finally:
        os.close(fd)
    return path


def fsync_dir(path: str) -> None:
    """fsync a directory; a failure to open it is an error, never swallowed."""
    try:
        fd = os.open(path, os.O_RDONLY | _O_DIRECTORY)
    except OSError:
        raise ToolError("E_STATE_WRITE_FAILED", "Directory could not be opened for fsync.",
                        resource=os.path.basename(path), next_action="check_permissions")
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write_bytes(path: str, data: bytes, mode: int = DEFAULT_FILE_MODE,
                       strict: bool = True) -> None:
    """Durably replace ``path`` with ``data`` via a same-directory temp file."""
    directory = os.path.dirname(os.path.abspath(path))
    if is_symlink(path):
        raise ToolError("E_UNSAFE_PATH", "Refusing to replace a symlink.",
                        resource=os.path.basename(path), next_action="use_real_path")
    ensure_dir(directory)
    try:
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    except OSError:
        raise ToolError("E_STATE_WRITE_FAILED", "Cannot create a temporary file.",
                        resource=os.path.basename(path), next_action="check_permissions")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        tmp = None  # type: ignore[assignment]
    except OSError:
        if strict:
            raise ToolError("E_STATE_WRITE_FAILED", "State file could not be written durably.",
                            resource=os.path.basename(path), next_action="retry_state_write")
        raise
    finally:
        if tmp is not None and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
    try:
        os.chmod(path, mode)
    except OSError:
        pass
    fsync_dir(directory)


def create_exclusive(path: str, mode: int = DEFAULT_FILE_MODE) -> int:
    """Open ``path`` for exclusive, no-follow creation. Returns a file descriptor."""
    directory = os.path.dirname(os.path.abspath(path))
    ensure_dir(directory)
    try:
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW, mode)
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            raise ToolError("E_PRECONDITION", "Refusing to clobber an existing path.",
                            resource=os.path.basename(path), next_action="use_fresh_path")
        raise ToolError("E_STATE_WRITE_FAILED", "Cannot create the file.",
                        resource=os.path.basename(path), next_action="check_permissions")


def read_bytes_nofollow(path: str) -> bytes:
    """Read a regular file without following a final symlink."""
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise ToolError("E_UNSAFE_PATH", "Refusing to read a symlink.",
                            resource=os.path.basename(path), next_action="use_real_file")
        raise
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ToolError("E_UNSAFE_PATH", "Refusing to read a non-regular file.",
                            resource=os.path.basename(path), next_action="use_real_file")
        chunks = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        return b"".join(chunks)
    finally:
        os.close(fd)


# -- paths -------------------------------------------------------------------
def jobs_root(root: str) -> str:
    return os.path.join(os.path.abspath(root), "jobs")


def job_dir(root: str, job_id: str) -> str:
    validate_id(job_id, "job_id")
    return os.path.join(jobs_root(root), job_id)


def restore_jobs_root(root: str) -> str:
    return os.path.join(os.path.abspath(root), RESTORE_JOBS_DIR)


def restore_job_dir(root: str, job_id: str) -> str:
    validate_id(job_id, "job_id")
    return os.path.join(restore_jobs_root(root), job_id)


def root_for_job_dir(job_path: str) -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(job_path)))


def lock_path(root: str) -> str:
    return os.path.join(os.path.abspath(root), "lock")


# -- durable reads/writes ----------------------------------------------------
def read_json_nofollow(path: str) -> Tuple[bool, Any]:
    """Return ``(present, value)``; raise ``ValueError`` on a corrupt/unsafe file."""
    if not os.path.lexists(path):
        return False, None
    if is_symlink(path):
        raise ValueError("symlink state file")
    try:
        data = read_bytes_nofollow(path)
    except ToolError:
        raise ValueError("unsafe state file")
    return True, json.loads(data.decode("utf-8"))


def write_exclusive(path: str, obj: Any) -> None:
    """Create ``path`` once, no-follow, private and durable."""
    directory = os.path.dirname(os.path.abspath(path))
    require_private_dir(directory, 0o700)
    data = (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            raise ToolError("E_PRECONDITION", "Refusing to replace an existing state file.",
                            resource=os.path.basename(path), next_action="inspect_remote_state")
        raise ToolError("E_STATE_WRITE_FAILED", "Remote state file could not be created.",
                        resource=os.path.basename(path), next_action="inspect_remote_state")
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_dir(directory)


def replace_json(path: str, obj: Any) -> None:
    data = (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    atomic_write_bytes(path, data, mode=0o600)


# -- the host stack lock -----------------------------------------------------
@contextlib.contextmanager
def stack_lock(root: str, wait_seconds: float = 0) -> Iterator[None]:
    """Exclusive host-wide lock covering reservation, effects and finalization.

    ``wait_seconds`` is a *bounded* wait (``0`` means a single non-blocking
    attempt). It never waits unbounded, and it measures the deadline with a
    monotonic clock so a wall-clock jump cannot extend or truncate the bound.
    """
    require_private_dir(os.path.abspath(root), 0o700)
    path = lock_path(root)
    if is_symlink(path):
        raise ToolError("E_UNSAFE_PATH", "The stack lock path is a symlink.",
                        resource="lock", next_action="inspect_remote_state")
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | _O_NOFOLLOW, 0o600)
    except OSError:
        raise ToolError("E_STATE_WRITE_FAILED", "The stack lock could not be opened.",
                        resource="lock", next_action="inspect_remote_state")
    try:
        if wait_seconds and wait_seconds > 0:
            deadline = time.monotonic() + float(wait_seconds)
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ToolError("E_LOCKED", "Another vps3xui operation holds the stack lock.",
                                        resource=os.path.basename(root), next_action="wait_or_inspect")
                    time.sleep(min(0.2, remaining))
        else:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise ToolError("E_LOCKED", "Another vps3xui operation holds the stack lock.",
                                resource=os.path.basename(root), next_action="wait_or_inspect")
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


# -- reservation / ownership -------------------------------------------------
def read_state(job_path: str) -> Tuple[str, bool]:
    """Return ``(state, corrupt)``; a missing state file is not silently absent."""
    try:
        present, state_obj = read_json_nofollow(os.path.join(job_path, STATE_FILE))
    except (ValueError, OSError):
        return "unknown", True
    try:
        report_present, report = read_json_nofollow(os.path.join(job_path, REPORT_FILE))
    except (ValueError, OSError):
        return "unknown", True
    state = None
    if present and isinstance(state_obj, dict):
        state = state_obj.get("state")
    if state is None and report_present and isinstance(report, dict):
        state = report.get("state")
    if state is None:
        return "accepted", False
    return state, False


def read_reservation(job_path: str) -> Optional[Dict[str, Any]]:
    try:
        present, value = read_json_nofollow(os.path.join(job_path, RESERVATION_FILE))
    except (ValueError, OSError):
        return None
    return value if present and isinstance(value, dict) else None


def read_request(job_path: str) -> Optional[Dict[str, Any]]:
    try:
        present, value = read_json_nofollow(os.path.join(job_path, REQUEST_FILE))
    except (ValueError, OSError):
        return None
    return value if present and isinstance(value, dict) else None


def reservation_owned(root: str, job_id: str) -> bool:
    job_path = job_dir(root, job_id)
    reservation = read_reservation(job_path)
    request = read_request(job_path)
    if not reservation or not request:
        return False
    if reservation.get("schema_version") != RESERVATION_SCHEMA_VERSION:
        return False
    if reservation.get("job_id") != job_id or request.get("job_id") != job_id:
        return False
    if reservation.get("plan_digest") != request.get("plan_digest"):
        return False
    if reservation.get("manifest_id") != request.get("manifest_id"):
        return False
    return True


def assert_owned(root: str, job_id: str) -> Dict[str, Any]:
    if not reservation_owned(root, job_id):
        raise ToolError("E_NOT_OWNED",
                        "This job has no valid reservation owned by this host.",
                        resource=job_id, next_action="inspect_remote_state")
    return read_request(job_dir(root, job_id)) or {}


def record_launch_marker(root: str, job_id: str, unit_name: str, phase: str,
                         boot: Optional[str] = None) -> None:
    replace_json(os.path.join(job_dir(root, job_id), LAUNCHED_FILE), {
        "schema_version": RESERVATION_SCHEMA_VERSION,
        "job_id": job_id,
        "unit_name": unit_name,
        "phase": phase,
        "boot_id": boot,
        "recorded_at": _utcnow(),
    })


def read_launched(root: str, job_id: str) -> Optional[Dict[str, Any]]:
    try:
        present, value = read_json_nofollow(os.path.join(job_dir(root, job_id), LAUNCHED_FILE))
    except (ValueError, OSError):
        return None
    return value if present and isinstance(value, dict) else None


def has_complete(backup_dir: str) -> bool:
    present, _unsafe = _marker_state(backup_dir)
    return present


def backup_dir_of(job_path: str) -> Optional[str]:
    request = read_request(job_path) or {}
    value = request.get("backup_dir")
    return value if isinstance(value, str) else None


def _marker_state(directory: Optional[str]) -> Tuple[bool, bool]:
    """Classify ``COMPLETE`` inside ``directory``.

    Returns ``(present, unsafe)``. ``present`` is true only for a non-empty,
    regular, non-symlink marker whose directory has no symlink ancestor;
    ``unsafe`` is true when something exists at the path but cannot be trusted
    that way (a symlink, an empty file, a directory, an unreadable entry or a
    symlinked ancestor). A symlinked marker is never followed and a zero-byte
    marker is never an idempotent success.
    """
    if not isinstance(directory, str) or not directory:
        return False, False
    try:
        if symlink_ancestors(directory):
            return False, True
    except OSError:
        return False, True
    try:
        info = os.lstat(os.path.join(directory, COMPLETE_FILE))
    except FileNotFoundError:
        return False, False
    except OSError:
        return False, True
    if stat.S_ISREG(info.st_mode) and info.st_size > 0:
        return True, False
    return False, True


def _journal_present(job_path: str) -> bool:
    """True whenever a durable first-cause journal exists, whatever it holds."""
    try:
        os.lstat(os.path.join(job_path, FAILURE_FILE))
    except FileNotFoundError:
        return False
    except OSError:
        # An unreadable directory is unresolved evidence, never absence.
        return True
    return True


def _report_object(job_path: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Read ``report.json`` as an object; ``(None, reason)`` when it is not one."""
    try:
        present, value = read_json_nofollow(os.path.join(job_path, REPORT_FILE))
    except (ValueError, OSError):
        return None, "corrupt"
    if not present:
        return None, "missing"
    if not isinstance(value, dict):
        return None, "corrupt"
    return value, None


def _unit_success_proven(unit: Any) -> bool:
    """The persisted R6 unit triple (mirrored by the worker's own check)."""
    if not isinstance(unit, dict):
        return False
    expected = {"SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": "0"}
    for key, want in expected.items():
        value = unit.get(key)
        if not isinstance(value, str) or value.strip() != want:
            return False
    return True


def _success_binding_problem(job_path: str, report: Dict[str, Any]) -> Optional[str]:
    """Check that a success report names this job, request and manifest.

    The immutable ``request.json`` is the authority; the report and any
    ``backup.json`` beside the marker may only agree. A missing, relative or
    mismatched binding is a refusal, never a guess about which directory the
    operation really produced.
    """
    job_id = os.path.basename(os.path.abspath(job_path).rstrip("/"))
    request = read_request(job_path)
    if not isinstance(request, dict):
        return "request_missing"
    requested = request.get("backup_dir")
    if not isinstance(requested, str) or not requested.startswith("/"):
        return "backup_dir_unrecorded"
    candidate = os.path.abspath(requested)
    reported = report.get("backup_dir")
    if not isinstance(reported, str) or not reported or os.path.abspath(reported) != candidate:
        return "backup_dir_conflict"
    manifest_id = request.get("manifest_id")
    if not isinstance(manifest_id, str) or not manifest_id:
        return "manifest_unrecorded"
    if report.get("manifest_id") != manifest_id:
        return "manifest_mismatch"
    for value in (request.get("job_id"), report.get("job_id")):
        if isinstance(value, str) and value and value != job_id:
            return "job_id_mismatch"
    metadata_path = os.path.join(candidate, "backup.json")
    if os.path.lexists(metadata_path):
        try:
            present, metadata = read_json_nofollow(metadata_path)
        except (ValueError, OSError):
            return "backup_metadata_unreadable"
        if not present or not isinstance(metadata, dict):
            return "backup_metadata_malformed"
        backup_id = metadata.get("backup_id")
        if isinstance(backup_id, str) and backup_id and backup_id != job_id:
            return "backup_metadata_mismatch"
        meta_manifest = metadata.get("manifest_id")
        if isinstance(meta_manifest, str) and meta_manifest and meta_manifest != manifest_id:
            return "backup_metadata_mismatch"
    return None


def _cleanup_pending(report: Optional[Dict[str, Any]]) -> Optional[str]:
    """A recorded unfinished revocation or unresolved binding, however short.

    A job whose last recovery could not finish its marker revocation or whose
    backup binding never agreed is not terminal, even when the state file says
    ``failed``: incomplete cleanup must never permit new work.
    """
    recovery = report.get("recovery") if isinstance(report, dict) else None
    if not isinstance(recovery, dict):
        return None
    revocation = recovery.get("revocation")
    if isinstance(revocation, dict) and revocation.get("ok") is False:
        return "revocation_pending"
    binding = recovery.get("binding_problem")
    if isinstance(binding, str) and binding:
        return "binding_unresolved"
    return None


def _copy_produced(report: Optional[Dict[str, Any]], state: str) -> bool:
    """True when the evidence shows a copy was actually produced.

    Only a verified copy or a ``copied``/``succeeded`` state counts. A job that
    legitimately failed before copying is never forced to resolve a backup path
    it never created.
    """
    if isinstance(report, dict):
        if report.get("data_integrity") == "verified":
            return True
        if report.get("state") in ("copied", "succeeded"):
            return True
    return state in ("copied", "succeeded")


def completion_conflict(job_path: str) -> Optional[str]:
    """A conservative, self-contained check for contradictory completion evidence.

    Returns a short reason when a job's terminal or success evidence cannot be
    trusted, or ``None`` when the available evidence agrees. A success claim
    must carry a genuinely writer-produced terminal success report -- the exact
    ``succeeded`` state, no retained first failure, a verified source runtime
    recovery, ``recovery_complete`` true, the persisted R6 unit triple and
    request/job/manifest bindings -- plus a non-empty regular ``COMPLETE`` at
    the request-authoritative path. Anything else (a durable first-cause
    journal, a missing/unreadable report, a ``copied`` report under a
    ``succeeded`` state, a failed/unproven recovery or a stale marker under a
    non-success state) is a refusal. The check re-reads the evidence with this
    module's own primitives only, so the shipped standalone
    ``remote_ops``/``coordination`` path stays valid when no package helper was
    shipped alongside it.
    """
    state, corrupt = read_state(job_path)
    if corrupt:
        return "corrupt_evidence"
    report, report_problem = _report_object(job_path)
    journal = _journal_present(job_path)
    marker, unsafe_marker = _marker_state(backup_dir_of(job_path))
    job_marker, unsafe_job_marker = _marker_state(job_path)
    if unsafe_marker or unsafe_job_marker:
        return "marker_unsafe"
    marked = marker or job_marker
    if state == "succeeded":
        if journal:
            return "failure_journal_present"
        if report_problem:
            return "report_%s" % report_problem
        if report.get("state") != "succeeded":
            return "report_state_conflict"
        if report.get("original_failure") is not None:
            return "report_original_failure"
        if report.get("source_runtime_recovery") != "verified":
            return "report_recovery_unverified"
        recovery = report.get("recovery")
        if not isinstance(recovery, dict) or recovery.get("recovery_complete") is not True:
            return "report_recovery_incomplete"
        if not _unit_success_proven(report.get("unit_result")):
            return "report_unit_unproven"
        pending = _cleanup_pending(report)
        if pending is not None:
            return pending
        binding = _success_binding_problem(job_path, report)
        if binding is not None:
            return binding
        if not marked:
            return "missing_complete"
        return None
    if marked:
        return "stale_complete"
    pending = _cleanup_pending(report)
    if pending is not None:
        return pending
    if _copy_produced(report, state) and _success_binding_problem(job_path, report) is not None:
        return "binding_unresolved"
    return None


def is_complete(job_path: str) -> Tuple[bool, str]:
    """``(complete, state)``: a terminal job is complete only when its evidence agrees.

    A ``succeeded`` state is complete only when no durable first-cause journal,
    failed/contradictory report or stale success marker refutes it, so an
    existing stale ``COMPLETE`` never permits new work or a success verify/fetch.
    """
    state, corrupt = read_state(job_path)
    if corrupt:
        return False, state
    if state not in COMPLETE_STATES:
        return False, state
    if completion_conflict(job_path) is not None:
        return False, state
    return True, state


def restore_is_settled(job_path: str) -> Tuple[bool, str]:
    """``(settled, state)`` of a restore job; a missing or corrupt state blocks."""
    try:
        present, value = read_json_nofollow(os.path.join(job_path, STATE_FILE))
    except (ValueError, OSError):
        return False, "unknown"
    if not present:
        return False, "planned"
    if not isinstance(value, dict) or not isinstance(value.get("state"), str):
        return False, "unknown"
    state = value["state"]
    return state in RESTORE_SETTLED_STATES, state


def scan_blocking(root: str) -> List[Dict[str, str]]:
    blocking: List[Dict[str, str]] = []
    jobs = jobs_root(root)
    if os.path.isdir(jobs):
        for name in sorted(os.listdir(jobs)):
            job_path = os.path.join(jobs, name)
            if not os.path.isdir(job_path) or is_symlink(job_path):
                continue
            complete, state = is_complete(job_path)
            if not complete:
                blocking.append({"job_id": name, "state": state})
    restores = restore_jobs_root(root)
    if is_symlink(restores):
        # A redirected restore registry is unresolved evidence, never absence.
        blocking.append({"job_id": RESTORE_JOBS_DIR, "state": "unknown", "kind": "restore"})
    elif os.path.isdir(restores):
        for name in sorted(os.listdir(restores)):
            if name.startswith(".tmp-"):
                # An unpublished registration: no job id starts with a dot and
                # no effect runs before the directory is published.
                continue
            job_path = os.path.join(restores, name)
            if is_symlink(job_path) or not os.path.isdir(job_path):
                blocking.append({"job_id": name, "state": "unknown", "kind": "restore"})
                continue
            settled, state = restore_is_settled(job_path)
            if not settled:
                blocking.append({"job_id": name, "state": state, "kind": "restore"})
    return blocking


def assert_no_blocking(root: str, ignoring: Optional[str] = None,
                       ignoring_restore: Optional[str] = None) -> None:
    """Refuse new work while another job is unfinished.

    ``ignoring`` names the caller's own backup job and ``ignoring_restore`` its
    own restore job; a job of the other kind with the same name still blocks.
    """
    for item in scan_blocking(root):
        own = ignoring_restore if item.get("kind") == "restore" else ignoring
        if own is not None and item["job_id"] == own:
            continue
        raise ToolError("E_JOB_INCOMPLETE",
                        "An incomplete job blocks new work until it is resolved with job recover.",
                        resource=item["job_id"], next_action="job_recover")


# -- host facts --------------------------------------------------------------
def boot_id() -> Optional[str]:
    try:
        with open("/proc/sys/kernel/random/boot_id", "r", encoding="utf-8") as handle:
            return handle.read().strip() or None
    except OSError:
        return None


def unit_active(unit_name: str) -> Optional[bool]:
    """Best-effort systemd liveness. ``None`` when systemd cannot be consulted."""
    import subprocess

    try:
        proc = subprocess.run(["systemctl", "is-active", unit_name],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    text = proc.stdout.decode("utf-8", "replace").strip()
    if text == "active":
        return True
    if text in ("inactive", "failed", ""):
        return False
    return None


def _utcnow() -> str:
    return (datetime.datetime.now(datetime.timezone.utc)
            .replace(microsecond=0).isoformat().replace("+00:00", "Z"))


def utcnow() -> str:
    """Public alias used by worker/job state writers."""
    return _utcnow()
