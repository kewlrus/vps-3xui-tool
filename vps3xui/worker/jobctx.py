"""Durable job directory: atomic writes, bounded event log, no secret content."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

from ..util import atomic_write_bytes, read_json, require_private_dir

STATE_FILE = "state.json"
REQUEST_FILE = "request.json"
PLAN_FILE = "plan.json"
INITIAL_STATE_FILE = "initial-state.json"
FAILURE_FILE = "failure.json"
REPORT_FILE = "report.json"
EVENTS_FILE = "events.log"
COMPLETE_MARKER = "COMPLETE"


def now_iso() -> str:
    import datetime

    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


class JobContext(object):
    def __init__(self, job_dir: str):
        self.job_dir = os.path.abspath(job_dir)
        require_private_dir(self.job_dir, 0o700)

    def path(self, name: str) -> str:
        return os.path.join(self.job_dir, name)

    def exists(self, name: str) -> bool:
        return os.path.isfile(self.path(name))

    def read_json(self, name: str) -> Optional[Dict[str, Any]]:
        path = self.path(name)
        if not os.path.isfile(path):
            return None
        try:
            return read_json(path)
        except ValueError:
            return None

    def write_json(self, name: str, obj: Any, mode: int = 0o600) -> None:
        if not isinstance(name, str) or "/" in name or name.startswith("."):
            raise ValueError("unsafe state file name")
        data = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
        atomic_write_bytes(self.path(name), data, mode=mode)

    def append_event(self, event: Dict[str, Any]) -> None:
        safe = {key: value for key, value in event.items() if key in EVENT_FIELDS}
        safe.setdefault("ts", now_iso())
        line = json.dumps(safe, sort_keys=True, ensure_ascii=False) + "\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path(EVENTS_FILE), flags, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)


EVENT_FIELDS = {
    "ts",
    "state",
    "previous_state",
    "step",
    "outcome",
    "code",
    "resource",
    "artifact",
    "count",
}
