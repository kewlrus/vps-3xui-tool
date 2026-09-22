"""Bounded, connection-independent runtime of target restore stages.

A long target stage runs as its own transient systemd unit, so losing the SSH
client neither stops nor duplicates it. The unit is bounded by ``RuntimeMaxSec``
and ``TimeoutStopSec`` and killed as a whole control group. Its launch is
recorded in the job directory *before* ``systemd-run`` (``pending``) and
confirmed after it (``launched``) together with the boot id.

Observable state after a reboot or a lost unit: the job keeps its recorded
state, :func:`observe` reports ``interrupted`` with the reason (``boot_changed``,
``unit_not_active``, ``unconfirmed_launch``) and :meth:`RestoreJob.reconcile`
turns undetermined steps into ``unknown``. Nothing restarts on boot: transient
units do not survive a reboot and there is no automatic recovery. The source
backup finalizer is never attached to a restore unit; it restores *source*
containers and is not a generic container start.
"""

from __future__ import annotations

import datetime
import os
import re
import subprocess
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .. import coordination as coord
from ..errors import ToolError
from . import contracts
from .job import RestoreJob, _now

LAUNCHED_FILE = "launched.json"
LAUNCH_SCHEMA_VERSION = 1

RUNTIME_MAX_SECONDS_LIMIT = (60, 4 * 3600)
TIMEOUT_STOP_SECONDS_LIMIT = (30, 600)
STEP_TIMEOUT_LIMIT = (1, 3600)

RESTORE_WORKER = os.path.join("bin", "vps3xui-restore-worker")
UNIT_RE = re.compile(r"^vps3xui-restore-(%s)-(rst-[0-9a-f]{24})-([0-9]{1,6})$"
                     % "|".join(stage.replace("_", "-") for stage in contracts.STAGES))


def unit_name(job_id: str, stage: str, attempt: int) -> str:
    if stage not in contracts.STAGES:
        raise ToolError("E_CONTRACT", "Unknown restore stage.", resource="stage")
    name = "vps3xui-restore-%s-%s-%d" % (stage.replace("_", "-"), job_id, attempt)
    if not UNIT_RE.match(name):
        raise ToolError("E_CONTRACT", "Restore unit name is not derivable from this job.",
                        resource=job_id)
    return name


def _bounded_int(value: Any, limits: Tuple[int, int], what: str) -> int:
    low, high = limits
    if not isinstance(value, int) or isinstance(value, bool) or not (low <= value <= high):
        raise ToolError("E_CONTRACT", "Restore runtime bound is outside the approved range.",
                        resource=what)
    return value


def _safe_abs(path: Any, what: str) -> str:
    if (not isinstance(path, str) or not path.startswith("/") or ".." in path.split("/")
            or any(ch in path for ch in " \t\n\r'\"\\;$`")):
        raise ToolError("E_CONTRACT", "Restore launch path is not a safe absolute path.",
                        resource=what)
    return path


def systemd_run_argv(job: RestoreJob, stage: str, attempt: int, release_dir: str,
                     runtime_max_seconds: int, timeout_stop_seconds: int) -> List[str]:
    """Fixed ``systemd-run`` argv of one stage attempt; nothing caller-supplied runs.

    There is deliberately no ``ExecStopPost``: the source finalizer is not a
    target recovery, and the next locked status call reconciles the result.
    """
    runtime = _bounded_int(runtime_max_seconds, RUNTIME_MAX_SECONDS_LIMIT, "runtime_max_seconds")
    stop = _bounded_int(timeout_stop_seconds, TIMEOUT_STOP_SECONDS_LIMIT, "timeout_stop_seconds")
    release = _safe_abs(release_dir, "release_dir")
    job_path = _safe_abs(job.path, "job_dir")
    if os.path.abspath(job_path) != job.store.job_path(job.job_id):
        raise ToolError("E_CONTRACT", "Launch job_dir does not match the restore job.",
                        resource=job.job_id)
    return [
        "systemd-run",
        "--unit=%s" % unit_name(job.job_id, stage, attempt),
        "--property=Type=exec",
        "--property=RuntimeMaxSec=%d" % runtime,
        "--property=TimeoutStopSec=%d" % stop,
        "--property=KillMode=control-group",
        "--property=StandardOutput=journal",
        "--property=StandardError=journal",
        os.path.join(release, RESTORE_WORKER),
        "--stage",
        stage,
        "--release-dir",
        release,
        job_path,
    ]


def record_launch(job: RestoreJob, unit: str, phase: str, boot: Optional[str],
                  now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    """``pending`` before ``systemd-run``, ``launched`` after it returned success."""
    job._require_lock()
    if phase not in ("pending", "launched"):
        raise ToolError("E_CONTRACT", "Unknown launch phase.", resource="phase")
    match = UNIT_RE.match(unit or "")
    if not match or match.group(2) != job.job_id:
        raise ToolError("E_NOT_OWNED", "Launch unit does not belong to this restore job.",
                        resource=job.job_id, next_action="inspect_restore_job")
    marker = {
        "schema_version": LAUNCH_SCHEMA_VERSION,
        "job_id": job.job_id,
        "unit_name": unit,
        "phase": phase,
        "boot_id": boot,
        "recorded_at": _now(now),
    }
    coord.replace_json(os.path.join(job.path, LAUNCHED_FILE), marker)
    return marker


def read_launch(job: RestoreJob) -> Optional[Dict[str, Any]]:
    try:
        present, value = coord.read_json_nofollow(os.path.join(job.path, LAUNCHED_FILE))
    except (ValueError, OSError):
        return {"corrupt": True}
    if not present:
        return None
    if not isinstance(value, dict) or value.get("job_id") != job.job_id:
        return {"corrupt": True}
    return value


def observe(job: RestoreJob, boot: Optional[str] = None,
            unit_active: Callable[[str], Optional[bool]] = coord.unit_active) -> Dict[str, Any]:
    """What the host proves about the last launched unit (read-only).

    ``live`` is True/False/None; ``None`` means systemd could not answer and
    never counts as "stopped". ``interrupted`` is set only on positive evidence.
    """
    marker = read_launch(job)
    if marker is None:
        return {"interrupted": False, "live": False, "reason": "not_launched", "unit_name": None}
    if marker.get("corrupt"):
        return {"interrupted": True, "live": None, "reason": "launch_marker_invalid",
                "unit_name": None}
    unit = marker.get("unit_name")
    recorded_boot = marker.get("boot_id")
    if boot and recorded_boot and boot != recorded_boot:
        # Transient units die with the boot and are not restarted.
        return {"interrupted": True, "live": False, "reason": "boot_changed", "unit_name": unit}
    live = unit_active(unit) if isinstance(unit, str) else None
    if live is True:
        return {"interrupted": False, "live": True, "reason": "unit_active", "unit_name": unit}
    if live is None:
        return {"interrupted": False, "live": None, "reason": "unit_state_unknown", "unit_name": unit}
    if marker.get("phase") == "pending":
        return {"interrupted": True, "live": False, "reason": "unconfirmed_launch", "unit_name": unit}
    try:
        state = job.state_record()["state"]
    except ToolError:
        state = "recovery_required"
    if state in contracts.STAGE_RUNNING_STATE.values():
        return {"interrupted": True, "live": False, "reason": "unit_not_active", "unit_name": unit}
    return {"interrupted": False, "live": False, "reason": "unit_finished", "unit_name": unit}


def assert_not_live(job: RestoreJob, boot: Optional[str] = None,
                    unit_active: Callable[[str], Optional[bool]] = coord.unit_active) -> Dict[str, Any]:
    """Refuse a retry while the previous unit runs or its liveness is unknown."""
    view = observe(job, boot, unit_active)
    if view["live"] is True:
        raise ToolError("E_UNIT_BUSY", "A restore unit of this job is still running.",
                        resource=view["unit_name"], next_action="wait_or_inspect")
    if view["live"] is None:
        raise ToolError("E_PRECONDITION", "Restore unit liveness could not be determined.",
                        resource=view["unit_name"], next_action="inspect_restore_job")
    return view


def run_bounded(argv: Sequence[str], timeout_seconds: int,
                runner: Callable[..., Any] = subprocess.run) -> Tuple[str, Optional[int]]:
    """Run one fixed target command with a hard timeout; returns ``(result, rc)``.

    ``not_started``: the program is absent, so no effect happened. ``exited``:
    it ended with ``rc``; an exit status is not an observed effect, so the
    caller still observes the resource before journaling ``applied``.
    ``unknown``: it timed out or its end is unobservable, and the step outcome
    must be ``unknown``. Output is discarded and never reported.
    """
    timeout = _bounded_int(timeout_seconds, STEP_TIMEOUT_LIMIT, "timeout_seconds")
    if not argv or not all(isinstance(part, str) and part for part in argv):
        raise ToolError("E_CONTRACT", "Restore command must be a fixed argv.", resource="argv")
    try:
        proc = runner(list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "unknown", None
    except FileNotFoundError:
        return "not_started", None
    except (OSError, subprocess.SubprocessError):
        return "unknown", None
    returncode = getattr(proc, "returncode", None)
    if not isinstance(returncode, int) or isinstance(returncode, bool):
        return "unknown", None
    return "exited", returncode
