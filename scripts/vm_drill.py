#!/usr/bin/env python3
"""VM-only orchestration for the vps3xui restore drill.

The shell wrapper owns the portable checks, disposable-root guards and the
NOT RUN decision. This module owns the Linux-only work:

* explicit argv lists for the shipped ``bin/vps3xui-worker`` and
  ``bin/vps3xui-finalizer`` entrypoints (never a command plus arguments in one
  executable argument);
* systemd command-line escaping for ``ExecStopPost``;
* independent synthetic jobs for success+restore, SIGKILL during copying, a
  real ``RuntimeMaxSec`` expiry during copying, and loss of the submitting
  parent after the worker is already managed by systemd;
* restoration of the worker's actual artifacts into ledger-owned, isolated
  destinations, including the two real ``docker cp`` Fail2ban writable-layer
  archives into a created-stopped container.

The copy-barrier shim placed on the worker's PATH is an explicitly test-only
throttle. It changes no product code, adds no product fault flag and does not
forge a success: the worker still performs its normal copy and the finalizer
still derives the outcome from the real systemd unit result.

This module must only run on the explicitly disposable Linux host accepted by
``vm-restore-drill.sh``. It prints ``NOT RUN`` and exits 3 when the required
Linux tooling is missing; it never reports an all-pass result for a skipped
metadata check.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import secrets
import signal
import stat
import subprocess
import sys
import tarfile
import time
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import vm_restore_fixture as fixture  # noqa: E402

TERMINAL_STATES = ("succeeded", "failed")
REQUEST_NAME = "request.json"
PLAN_NAME = "plan.json"
EVIDENCE_MARKER_NAME = ".vps3xui-drill-evidence-owner"
DEFAULT_COMMAND_TIMEOUT = 120
EXIT_NOT_RUN = 3
EXIT_FAILED = 1


class DrillFailure(Exception):
    pass


def _fail(message: str) -> None:
    raise DrillFailure(message)


def _run_bounded(argv: List[str], timeout: int = DEFAULT_COMMAND_TIMEOUT,
                 **kwargs: Any) -> Optional[subprocess.CompletedProcess]:
    """Run a subprocess with a hard timeout; return ``None`` on a timeout.

    No drill observation may block forever: a hung ``docker inspect`` or
    ``systemctl show`` would otherwise stop the harness before cleanup and
    evidence preservation could run.
    """
    config = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
    config.update(kwargs)
    try:
        return subprocess.run(argv, timeout=timeout, **config)
    except subprocess.TimeoutExpired:
        return None


def systemd_quote(value: str) -> str:
    """Quote one argv element for a systemd command line.

    systemd.service(5) parses command lines with its own C-style quoting and
    performs ``$`` variable substitution. Quoting every element keeps spaces
    and shell metacharacters inert without relying on a shell.
    """
    escaped = (value.replace("\\", "\\\\").replace('"', '\\"')
               .replace("%", "%%").replace("$", "$$"))
    return '"%s"' % escaped


def systemd_escape_argv(argv: List[str]) -> str:
    if not argv:
        _fail("refusing to build an empty systemd command line")
    return " ".join(systemd_quote(item) for item in argv)


def systemd_split_argv(text: str) -> List[str]:
    """Inverse of :func:`systemd_escape_argv`, for local round-trip tests."""
    result: List[str] = []
    current: List[str] = []
    index = 0
    in_quotes = False
    while index < len(text):
        char = text[index]
        if char == '"':
            in_quotes = not in_quotes
            index += 1
            continue
        if char == "\\" and index + 1 < len(text):
            current.append(text[index + 1])
            index += 2
            continue
        if char == "%" and index + 1 < len(text) and text[index + 1] == "%":
            current.append("%")
            index += 2
            continue
        if char == "$" and index + 1 < len(text) and text[index + 1] == "$":
            current.append("$")
            index += 2
            continue
        if char.isspace() and not in_quotes:
            if current:
                result.append("".join(current))
                current = []
            index += 1
            continue
        current.append(char)
        index += 1
    if in_quotes:
        _fail("unterminated quote in systemd command line")
    if current:
        result.append("".join(current))
    return result


def worker_argv(release_dir: str, job_dir: str) -> List[str]:
    return [os.path.join(release_dir, "bin", "vps3xui-worker"),
            "--release-dir", release_dir, job_dir]


def finalizer_argv(release_dir: str, job_dir: str, recover: bool = False) -> List[str]:
    argv = [os.path.join(release_dir, "bin", "vps3xui-finalizer")]
    if recover:
        argv.append("--recover")
    argv.extend(["--release-dir", release_dir, job_dir])
    return argv


def systemd_run_argv(unit: str, worker: List[str], finalizer: List[str],
                     token: str, runtime_max_sec: int, timeout_stop_sec: int,
                     environment: Optional[Dict[str, str]] = None) -> List[str]:
    argv = [
        "systemd-run",
        "--unit=%s" % unit,
        "--collect",
        "--property=Type=exec",
        "--property=RuntimeMaxSec=%d" % runtime_max_sec,
        "--property=TimeoutStopSec=%d" % timeout_stop_sec,
        "--property=KillMode=control-group",
        "--property=SendSIGKILL=yes",
        "--property=Description=%s%s" % (fixture.UNIT_TOKEN_PREFIX, token),
        "--property=ExecStopPost=%s" % systemd_escape_argv(finalizer),
        "--property=StandardOutput=journal",
        "--property=StandardError=journal",
    ]
    for key in sorted((environment or {}).keys()):
        value = (environment or {})[key]
        argv.append("--property=Environment=%s=%s" % (key, systemd_quote(value)))
    argv.extend(worker)
    return argv


def _read_json(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _snapshot_tree(paths: List[str]) -> Dict[str, str]:
    snapshot: Dict[str, str] = {}
    for root in paths:
        if os.path.isfile(root) or os.path.islink(root):
            try:
                snapshot[root] = _sha256_file(root)
            except OSError:
                snapshot[root] = "unreadable"
            continue
        for base, _dirs, files in os.walk(root, followlinks=False):
            for name in sorted(files):
                full = os.path.join(base, name)
                try:
                    snapshot[full] = _sha256_file(full)
                except OSError:
                    snapshot[full] = "unreadable"
    return snapshot


class Driver(object):
    """Real Linux driver used by the VM drill. Tests provide a duck-typed fake."""

    def __init__(self, release_dir: str, drill_root: str, image: str,
                 identifier: str, ledger_path: str, evidence_dir: str):
        self.release_dir = release_dir
        self.drill_root = drill_root
        self.image = image
        self.identifier = identifier
        self.ledger_path = ledger_path
        self.evidence_dir = evidence_dir
        self.host = fixture.Host()
        self.names = fixture.fixture_identity(identifier)
        self.log_lines: List[str] = []
        self.commands: List[List[str]] = []
        self.fixture_info: Dict[str, Any] = {}
        self.primary_job = ""
        self.manifest = None
        self.copy_shim_dir = os.path.join(drill_root, "drill-bin")
        self.launch_argv: List[str] = []
        self.jobs: List[Tuple[str, str]] = []

    # -- logging / evidence ------------------------------------------------
    def log(self, message: str) -> None:
        line = "[%s] %s" % (time.strftime("%H:%M:%S"), message)
        self.log_lines.append(line)
        print("  - %s" % message, flush=True)

    def run(self, argv: List[str], **kwargs: Any) -> subprocess.CompletedProcess:
        self.commands.append(list(argv))
        kwargs.setdefault("timeout", DEFAULT_COMMAND_TIMEOUT)
        try:
            result = subprocess.run(argv, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, **kwargs)
        except subprocess.TimeoutExpired:
            _fail("command timed out after %ss: %s"
                  % (kwargs["timeout"], argv[0] if argv else ""))
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip()
            _fail("command failed (%s): %s" % (result.returncode, detail[:300]))
        return result

    # -- fixture -----------------------------------------------------------
    def create_fixture(self) -> None:
        self.log("creating the synthetic fixture %s" % self.names["prefix"])
        self.fixture_info = fixture.create(self.identifier, self.image,
                                           self.release_dir, self.ledger_path,
                                           self.host)
        self.primary_job = self.fixture_info["job_dir"]
        self.jobs.append(("success", self.primary_job))
        from vps3xui import manifest as manifest_module
        self.manifest = manifest_module.load(os.path.join(self.primary_job, "manifest.json"))

    def new_job(self, label: str) -> str:
        job_id = "%s-%s" % (self.names["id"], label)
        job_id = job_id[:63]
        job_dir = fixture.create_owned_job(self.ledger_path, job_id,
                                           self.primary_job, self.host)
        self.jobs.append((label, job_dir))
        self.log("created independent job %s" % job_id)
        return job_dir

    def new_barrier(self, label: str) -> str:
        path = os.path.join(self.drill_root, "barrier-%s" % label)
        fixture.create_owned_tree(self.ledger_path, path, self.host)
        return path

    def write_copy_shim(self) -> str:
        probe = _run_bounded(["sh", "-c", "command -v tar"], timeout=30,
                             stderr=subprocess.DEVNULL)
        real_tar = probe.stdout.decode().strip() if probe is not None else ""
        if not real_tar:
            _fail("GNU tar is required for the copy-barrier shim")
        shim = os.path.join(self.copy_shim_dir, "tar")
        fixture.create_owned_dir(self.ledger_path, self.copy_shim_dir, self.host)
        content = (
            "#!/bin/sh\n"
            "set -eu\n"
            "real_tar=%s\n"
            "case \" $* \" in\n"
            "  *\" -cpf \"*)\n"
            "    if [ -n \"${VPS3XUI_DRILL_COPY_BARRIER:-}\" ]; then\n"
            "      : > \"$VPS3XUI_DRILL_COPY_BARRIER/reached\"\n"
            "      while [ ! -e \"$VPS3XUI_DRILL_COPY_BARRIER/release\" ]; do\n"
            "        sleep 0.2\n"
            "      done\n"
            "    fi\n"
            "    ;;\n"
            "esac\n"
            "exec \"$real_tar\" \"$@\"\n" % real_tar
        )
        fixture.write_owned_file(self.ledger_path, shim, content, 0o755, self.host)
        return self.copy_shim_dir

    # -- launch ------------------------------------------------------------
    def unit_name(self, label: str) -> str:
        return "%s-worker-%s" % (self.names["prefix"], label)

    def ledger_token(self) -> str:
        """The validated per-run ownership token from the durable ledger.

        ``systemd_run_argv`` writes this token into the unit Description and
        ``fixture.confirm_unit`` refuses a unit that does not carry it, so the
        value is read from the validated ledger at launch time rather than
        trusted from an in-memory mapping that could have gone stale.
        """
        return fixture.ledger_token(self.ledger_path, self.host)

    def _environment(self, barrier_dir: Optional[str]) -> Dict[str, str]:
        value = {"PATH": "%s:%s" % (self.copy_shim_dir, os.environ.get("PATH", ""))}
        if barrier_dir:
            value["VPS3XUI_DRILL_COPY_BARRIER"] = barrier_dir
        return value

    def _reserve_and_launch(self, job_dir: str, unit: str, runtime_max_sec: int,
                            timeout_stop_sec: int,
                            barrier_dir: Optional[str]) -> None:
        worker = worker_argv(self.release_dir, job_dir)
        finalizer = finalizer_argv(self.release_dir, job_dir)
        log_path = os.path.join(self.evidence_dir, "systemd-%s.json" % unit)
        with open(log_path, "w", encoding="utf-8") as handle:
            json.dump({"worker": worker, "finalizer": finalizer,
                       "exec_stop_post": systemd_escape_argv(finalizer),
                       "runtime_max_sec": runtime_max_sec,
                       "timeout_stop_sec": timeout_stop_sec},
                      handle, indent=2, sort_keys=True)
        fixture.reserve_unit(self.ledger_path, unit, self.host)
        argv = systemd_run_argv(unit, worker, finalizer, self.ledger_token(),
                                runtime_max_sec, timeout_stop_sec,
                                self._environment(barrier_dir))
        self.launch_argv = argv
        self.run(argv)
        # ``--collect`` unloads a short unit as soon as it finishes, so the
        # launch receipt tolerates a unit that systemd has already collected.
        fixture.confirm_unit(self.ledger_path, unit, self.host)

    def launch(self, job_dir: str, unit: str, runtime_max_sec: int,
               timeout_stop_sec: int, barrier_dir: Optional[str] = None) -> None:
        self.log("launching %s with RuntimeMaxSec=%d" % (unit, runtime_max_sec))
        self._reserve_and_launch(job_dir, unit, runtime_max_sec, timeout_stop_sec, barrier_dir)

    def launch_via_submitter(self, job_dir: str, unit: str, runtime_max_sec: int,
                             timeout_stop_sec: int, barrier_dir: str) -> subprocess.Popen:
        token = self.ledger_token()
        config_path = os.path.join(self.evidence_dir, "submit-%s.json" % unit)
        with open(config_path, "w", encoding="utf-8") as handle:
            json.dump({
                "release_dir": self.release_dir,
                "ledger_path": self.ledger_path,
                "job_dir": job_dir,
                "unit": unit,
                "token": token,
                "runtime_max_sec": runtime_max_sec,
                "timeout_stop_sec": timeout_stop_sec,
                "barrier_dir": barrier_dir,
                "drill_bin": self.copy_shim_dir,
            }, handle, indent=2, sort_keys=True)
        self.log("starting a separate submitting parent for %s" % unit)
        return subprocess.Popen([sys.executable, os.path.abspath(__file__),
                                 "--submit", config_path],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # -- observation -------------------------------------------------------
    def wait_barrier(self, barrier_dir: str, timeout_sec: int) -> None:
        marker = os.path.join(barrier_dir, "reached")
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            if os.path.exists(marker):
                self.log("worker reached the deterministic copy barrier")
                return
            time.sleep(0.25)
        _fail("the worker never reached the copy barrier within %ds" % timeout_sec)

    def release_barrier(self, barrier_dir: str) -> None:
        with open(os.path.join(barrier_dir, "release"), "wb") as handle:
            handle.write(b"release\n")

    def job_state(self, job_dir: str) -> str:
        return (_read_json(os.path.join(job_dir, "state.json")).get("state") or "")

    def job_report(self, job_dir: str) -> Dict[str, Any]:
        return _read_json(os.path.join(job_dir, "report.json"))

    def wait_terminal(self, job_dir: str, timeout_sec: int) -> str:
        deadline = time.time() + timeout_sec
        state = ""
        while time.time() < deadline:
            state = self.job_state(job_dir)
            if state in TERMINAL_STATES:
                return state
            time.sleep(0.5)
        _fail("job %s did not reach a terminal state (last=%s)" % (job_dir, state))

    def wait_finalized(self, job_dir: str, unit: str, timeout_sec: int) -> str:
        """Wait for the *finalizer* to finish, not just a terminal state file.

        The automatic finalizer writes the terminal report/state and only then
        publishes ``COMPLETE`` (``vps3xui/worker/finalizer.py``), so a success
        job can briefly read ``succeeded`` with no marker. It also runs as the
        unit's ``ExecStopPost``, keeping the unit ``deactivating``. This waits
        for all of: a terminal state, a stable terminal report, the unit proven
        stopped/absent, and - on success - the published ``COMPLETE`` marker.
        """
        deadline = time.time() + timeout_sec
        previous = None
        state = ""
        runtime = "unknown"
        while time.time() < deadline:
            state = self.job_state(job_dir)
            report = self.job_report(job_dir)
            runtime = self.unit_runtime_state(unit)
            marker = os.path.exists(self.complete_path(job_dir))
            if state in TERMINAL_STATES and runtime in ("stopped", "absent"):
                if state != "succeeded" or marker:
                    snapshot = (state, report.get("completed_at"), report.get("state"), marker)
                    if snapshot == previous:
                        return state
                    previous = snapshot
            time.sleep(0.5)
        _fail("job %s was not finalized within %ds (state=%s unit=%s)"
              % (job_dir, timeout_sec, state, runtime))

    def assert_copying(self, job_dir: str) -> Dict[str, Any]:
        """Prove the interruption happened *during copying* on a stable source.

        At the deterministic copy barrier the durable state must be
        ``copying``, every originally-running container the worker recorded must
        already be stopped, and the originally-stopped container must still be
        stopped with its recorded id. Returns the recorded identities for the
        post-recovery comparison.
        """
        state = self.job_state(job_dir)
        if state != "copying":
            _fail("job %s was in state %s at the copy barrier, not copying"
                  % (job_dir, state))
        initial = _read_json(os.path.join(job_dir, "initial-state.json"))
        recorded = initial.get("stop_containers") or []
        if not recorded:
            _fail("job %s recorded no containers to stop during copying" % job_dir)
        for item in recorded:
            name = item["name"]
            if not item.get("id"):
                _fail("the drill recorded no identity for the source container %s" % name)
            observed = self.container_state(name)
            if observed != "stopped":
                _fail("recorded source container %s was %s during copying, not stopped"
                      % (name, observed))
            if self.container_identity(name) != item["id"]:
                _fail("recorded source container %s was replaced during copying" % name)
        idle = self.names["idle_container"]
        idle_fact = (initial.get("containers") or {}).get(idle) or {}
        idle_id = idle_fact.get("id") or ""
        if not idle_id:
            _fail("the drill recorded no identity for the originally-stopped container %s"
                  % idle)
        observed = self.container_state(idle)
        if observed != "stopped":
            _fail("the originally-stopped container %s was %s during copying, not stopped"
                  % (idle, observed))
        if self.container_identity(idle) != idle_id:
            _fail("the originally-stopped container %s was replaced during copying" % idle)
        return {"stop_containers": recorded,
                "idle_container": {"name": idle, "id": idle_id}}

    def container_id(self, name: str) -> str:
        result = _run_bounded(["docker", "inspect", "--format", "{{.Id}}", name],
                              stderr=subprocess.DEVNULL)
        if result is None or result.returncode != 0:
            return ""
        return result.stdout.decode("utf-8", "replace").strip()

    def container_state(self, name: str) -> str:
        """Strict ``"running"``/``"stopped"``/``"absent"``/``"unknown"``.

        A Docker error, a missing container and a timed-out inspect are never
        collapsed into "stopped"; only a proven stopped container passes a gate.
        """
        return fixture.container_runtime_state(name, self.host)

    def container_identity(self, name: str) -> str:
        """Return the full container id, or ``""`` when it cannot be proven."""
        return fixture.container_identity(name, self.host)

    def complete_path(self, job_dir: str) -> str:
        report = self.job_report(job_dir)
        backup_dir = report.get("backup_dir") or os.path.join(job_dir, "backup")
        return os.path.join(backup_dir, "COMPLETE")

    def kill_unit(self, unit: str) -> None:
        self.log("sending SIGKILL to every process in %s" % unit)
        self.run(["systemctl", "kill", "--kill-who=all", "--signal=SIGKILL", unit])

    def unit_runtime_state(self, unit: str) -> str:
        """``"running"``/``"stopped"``/``"absent"``/``"unknown"``.

        Reuses the fixture's R1 lookup: a systemd bus failure is ``"unknown"``
        and must never be read as "the unit stopped".
        """
        return fixture.unit_runtime_state(unit, self.host)

    def unit_active(self, unit: str) -> bool:
        return self.unit_runtime_state(unit) == "running"

    def wait_unit_inactive(self, unit: str, timeout_sec: int) -> str:
        """Wait until the unit is provably stopped/absent; return that state."""
        deadline = time.time() + timeout_sec
        last = "unknown"
        while time.time() < deadline:
            last = self.unit_runtime_state(unit)
            if last in ("stopped", "absent"):
                return last
            # "unknown" (bus error) is never treated as inactive; keep waiting
            # until the deadline, then fail with the observed state.
            time.sleep(0.5)
        _fail("unit %s did not become provably inactive within %ds (last=%s)"
              % (unit, timeout_sec, last))

    def preserve_job_evidence(self, label: str, job_dir: str) -> None:
        """Copy the durable job artifacts into the evidence dir *before* cleanup.

        Fixture cleanup removes the ledger-owned job directories, so the
        scenario ``report.json``/``state.json``/``initial-state.json`` (which
        carry the real ``unit_result``) must be captured now. Missing files are
        recorded as absent rather than skipped silently.
        """
        target = os.path.join(self.evidence_dir, "jobs", label)
        os.makedirs(target, mode=0o700, exist_ok=True)
        for name in ("report.json", "state.json", "initial-state.json", "events.log",
                     REQUEST_NAME, PLAN_NAME):
            source = os.path.join(job_dir, name)
            try:
                with open(source, "rb") as handle:
                    blob = handle.read()
            except OSError:
                continue
            with open(os.path.join(target, name), "wb") as handle:
                handle.write(blob)

    def preserve_all_evidence(self) -> None:
        for label, job_dir in self.jobs:
            try:
                self.preserve_job_evidence(label, job_dir)
            except OSError as exc:
                self.log("could not preserve evidence for %s: %s" % (label, exc))

    def kill_submitter(self, submitter: subprocess.Popen) -> None:
        if submitter.poll() is None:
            submitter.send_signal(signal.SIGKILL)
        try:
            submitter.wait(timeout=30)
        except subprocess.TimeoutExpired:
            _fail("the submitting parent did not exit after SIGKILL")

    def reap_submitter(self, submitter: subprocess.Popen) -> None:
        """SIGKILL and collect the submitter on every exit path, including a
        barrier-wait failure, so a stalled drill never leaks the transport
        parent process."""
        try:
            if submitter.poll() is None:
                submitter.send_signal(signal.SIGKILL)
            try:
                submitter.wait(timeout=30)
            except subprocess.TimeoutExpired:
                pass
        except ProcessLookupError:
            pass

    def container_running(self, name: str) -> bool:
        result = _run_bounded(["docker", "inspect", "--format", "{{.State.Running}}", name],
                              stderr=subprocess.DEVNULL)
        return (result is not None and result.returncode == 0
                and result.stdout.decode().strip() == "true")

    def _systemd_unit_state(self, unit: str) -> Dict[str, str]:
        result = _run_bounded(["systemctl", "show", unit, "-p",
                               "LoadState,ActiveState,UnitFileState"],
                              stderr=subprocess.DEVNULL)
        state = {"load_state": "not-found", "active_state": "unknown",
                 "unit_file_state": "unknown"}
        if result is None or result.returncode != 0:
            return state
        for line in result.stdout.decode("utf-8", "replace").splitlines():
            key, _, value = line.partition("=")
            if key == "LoadState":
                state["load_state"] = value
            elif key == "ActiveState":
                state["active_state"] = value
            elif key == "UnitFileState":
                state["unit_file_state"] = value
        return state

    def assert_source_restored(self, job_dir: str) -> None:
        report = self.job_report(job_dir)
        if report.get("source_runtime_recovery") != "verified":
            _fail("source runtime recovery was not verified for %s" % job_dir)
        initial = _read_json(os.path.join(job_dir, "initial-state.json"))
        for item in initial.get("stop_containers") or []:
            name = item["name"]
            if not item.get("id"):
                _fail("the drill recorded no identity for the source container %s" % name)
            if self.container_state(name) != "running":
                _fail("source container %s is not running after recovery" % name)
            if self.container_identity(name) != item.get("id"):
                _fail("source container %s was replaced during recovery" % name)
        idle = self.names["idle_container"]
        if self.container_state(idle) != "stopped":
            _fail("the originally-stopped container %s was not stopped after recovery" % idle)
        expected_idle = (self.fixture_info.get("idle_container") or {}).get("id")
        if not expected_idle:
            expected_idle = ((initial.get("containers") or {}).get(idle) or {}).get("id")
        if not expected_idle:
            _fail("the drill recorded no identity for the originally-stopped container %s"
                  % idle)
        if self.container_identity(idle) != expected_idle:
            _fail("the originally-stopped container %s was replaced" % idle)
        expected = ((initial.get("certbot") or {}).get("units") or {})
        for unit, values in expected.items():
            observed = self._systemd_unit_state(unit)
            for key in ("load_state", "active_state", "unit_file_state"):
                if observed.get(key) != values.get(key):
                    _fail("Certbot trigger %s was not restored (%s: %s != %s)"
                          % (unit, key, observed.get(key), values.get(key)))

    # -- restore -----------------------------------------------------------
    def snapshot_firewall(self) -> Dict[str, str]:
        return _snapshot_tree(["/etc/ufw", "/etc/default/ufw"])

    def assert_firewall_unchanged(self, before: Dict[str, str]) -> None:
        after = self.snapshot_firewall()
        if after != before:
            _fail("the UFW reference sources changed during the restore drill")

    def _read_container_file(self, container: str, path: str) -> Tuple[bytes, Dict[str, Any]]:
        result = _run_bounded(["docker", "cp", "%s:%s" % (container, path), "-"],
                              stderr=subprocess.DEVNULL)
        if result is None:
            _fail("docker cp timed out reading %s from the restored container" % path)
        if result.returncode != 0:
            _fail("docker cp could not read %s from the restored container" % path)
        with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:*") as archive:
            members = [member for member in archive.getmembers() if member.isfile()]
            if len(members) != 1:
                _fail("restored container path %s did not contain exactly one file" % path)
            member = members[0]
            handle = archive.extractfile(member)
            facts = {"mode": "%04o" % (member.mode & 0o777),
                     "uid": member.uid, "gid": member.gid}
            return (handle.read() if handle is not None else b""), facts

    def _restored_file_facts(self, path: str) -> Dict[str, Any]:
        if os.path.islink(path) or not os.path.isfile(path):
            _fail("restored bind file is missing or not a regular file: %s" % path)
        info = os.lstat(path)
        return {
            "sha256": _sha256_file(path),
            "mode": "%04o" % stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
            "gid": info.st_gid,
            "size": info.st_size,
        }

    def _assert_restored_file(self, expected: Dict[str, Any], destination: str) -> Dict[str, Any]:
        """Compare one restored bind file with the seeded value and metadata."""
        path = os.path.join(destination, expected["path"].lstrip("/"))
        observed = self._restored_file_facts(path)
        for key in ("sha256", "mode", "uid", "gid"):
            if key in expected and str(observed.get(key)) != str(expected.get(key)):
                _fail("restored %s changed %s (%s != %s)"
                      % (expected["path"], key, observed.get(key), expected.get(key)))
        record = {"path": expected["path"], "sha256": observed["sha256"],
                  "mode": observed["mode"], "uid": observed["uid"], "gid": observed["gid"]}
        if expected.get("acl"):
            acl = _read_acl(path)
            if expected["acl"] not in acl:
                _fail("restored %s lost its ACL entry %s"
                      % (expected["path"], expected["acl"]))
            record["acl"] = expected["acl"]
        if expected.get("xattr_name"):
            value = _read_xattr(path, expected["xattr_name"])
            if value != expected.get("xattr_value"):
                _fail("restored %s lost xattr %s (%r != %r)"
                      % (expected["path"], expected["xattr_name"], value,
                         expected.get("xattr_value")))
            record["xattr_name"] = expected["xattr_name"]
            record["xattr_value"] = expected["xattr_value"]
        return record

    def restore_success(self, job_dir: str) -> Dict[str, Any]:
        from vps3xui.adapters import archive as archive_adapter
        from vps3xui.verify import verify_directory

        expectations = self.fixture_info.get("restore_expectations") or {}
        if not expectations:
            _fail("the fixture did not return restore expectations; refusing an "
                  "unverified restore")
        report = self.job_report(job_dir)
        backup_dir = report.get("backup_dir") or os.path.join(job_dir, "backup")
        verified = verify_directory(backup_dir, self.manifest, require_complete=True)
        if not verified.ok:
            _fail("the successful backup did not verify before extraction")
        restore_root = os.path.join(self.drill_root, "restore-" + os.path.basename(job_dir))
        fixture.create_owned_tree(self.ledger_path, restore_root, self.host)
        restored: Dict[str, Any] = {"backup_dir": backup_dir, "destinations": {}}

        bind_destinations: Dict[str, str] = {}
        for tree in self.manifest.bind_trees:
            artifact = os.path.join(backup_dir, tree["artifact"])
            destination = os.path.join(restore_root, "bind-" + tree["artifact"])
            fixture.create_owned_tree(self.ledger_path, destination, self.host)
            archive_adapter.safe_extract(artifact, destination)
            restored["destinations"][tree["artifact"]] = destination
            bind_destinations[tree["artifact"]] = destination
        volume_destinations: Dict[str, str] = {}
        for volume in self.manifest.volumes:
            artifact = os.path.join(backup_dir, volume["artifact"])
            destination = os.path.join(restore_root, "volume-" + volume["name"])
            fixture.create_owned_tree(self.ledger_path, destination, self.host)
            archive_adapter.safe_extract(artifact, destination)
            restored["destinations"][volume["artifact"]] = destination
            volume_destinations[volume["artifact"]] = destination
        if not self.manifest.bind_trees:
            _fail("the fixture manifest declared no bind tree to compare")

        # -- metadata / ACL / xattr round-trip ---------------------------
        bind_root = bind_destinations[self.manifest.bind_trees[0]["artifact"]]
        restored["bind_files"] = [
            self._assert_restored_file(entry, bind_root)
            for entry in expectations.get("bind_files") or []
        ]
        restored["links"] = []
        for link in expectations.get("links") or []:
            path = os.path.join(bind_root, link["path"].lstrip("/"))
            if not os.path.islink(path):
                _fail("restored Let's Encrypt link is missing or not a symlink: %s"
                      % link["path"])
            target = os.readlink(path)
            if target != link["target"]:
                _fail("restored link %s changed target (%s != %s)"
                      % (link["path"], target, link["target"]))
            restored["links"].append({"path": link["path"], "target": target})
        volume_expectation = expectations.get("volume") or {}
        if volume_expectation:
            volume_artifact = self.manifest.volumes[0]["artifact"]
            volume_dest = volume_destinations[volume_artifact]
            volume_path = os.path.join(volume_dest,
                                       volume_expectation["path"].lstrip("/"))
            if os.path.islink(volume_path) or not os.path.isfile(volume_path):
                _fail("restored volume file is missing: %s" % volume_expectation["path"])
            with open(volume_path, "r", encoding="utf-8") as handle:
                content = handle.read()
            if content != volume_expectation["content"]:
                _fail("restored volume %s changed content" % volume_expectation["name"])
            restored["volume"] = {"name": volume_expectation["name"],
                                  "path": volume_expectation["path"],
                                  "content": content}

        # -- real docker-cp Fail2ban restoration -------------------------
        for layer in self.manifest.writable_layers:
            artifact = os.path.join(backup_dir, layer["artifact"])
            archive_adapter.validate_tar(artifact)
        rendered = {
            "config": self.manifest.writable_layers[0],
            "data": self.manifest.writable_layers[1],
        } if len(self.manifest.writable_layers) == 2 else {}
        if not rendered:
            _fail("the fixture manifest did not declare the two Fail2ban writable layers")
        target = fixture.create_owned_container(self.ledger_path,
                                                self.names["restored_container"],
                                                self.image, self.host)
        for label in ("config", "data"):
            layer = rendered[label]
            artifact = os.path.join(backup_dir, layer["artifact"])
            parent = os.path.dirname(layer["path"]) or "/"
            with open(artifact, "rb") as handle:
                # -a preserves the numeric owner and mode recorded by the source
                # ``docker cp -a`` when it copied the writable layer out.
                copied = _run_bounded(
                    ["docker", "cp", "-a", "-", "%s:%s" % (target["name"], parent)],
                    stdin=handle)
            if copied is None:
                _fail("docker cp timed out restoring %s into %s"
                      % (layer["path"], target["name"]))
            if copied.returncode != 0:
                _fail("docker cp could not restore %s into %s" % (layer["path"], target["name"]))
        target_state = self.container_state(target["name"])
        if target_state != "stopped":
            _fail("the restored Fail2ban container was %s during restore, not stopped"
                  % target_state)
        fail2ban_expectation = expectations.get("fail2ban") or {}
        observed_fail2ban = []
        for entry in fail2ban_expectation.get("files") or []:
            content, facts = self._read_container_file(target["name"], entry["path"])
            digest = hashlib.sha256(content).hexdigest()
            if digest != entry["sha256"]:
                _fail("restored Fail2ban file %s changed content" % entry["path"])
            for key in ("mode", "uid", "gid"):
                if str(facts.get(key)) != str(entry.get(key)):
                    _fail("restored Fail2ban file %s changed %s (%s != %s)"
                          % (entry["path"], key, facts.get(key), entry.get(key)))
            observed_fail2ban.append({"path": entry["path"], "sha256": digest,
                                      "mode": facts["mode"], "uid": facts["uid"],
                                      "gid": facts["gid"]})
        if not observed_fail2ban:
            _fail("the fixture did not declare the Fail2ban restore expectations")
        # Path separation: neither synthetic payload may land in the other tree.
        config_bytes, _config_facts = self._read_container_file(
            target["name"], fail2ban_expectation["config_path"] + "/jail.local")
        data_bytes, _data_facts = self._read_container_file(
            target["name"], fail2ban_expectation["data_path"] + "/db.sqlite")
        if b"synthetic drill fail2ban database" in config_bytes:
            _fail("Fail2ban data was restored into the config location")
        if b"synthetic drill jail" in data_bytes:
            _fail("Fail2ban config was restored into the data location")
        restored["fail2ban_container"] = target["name"]
        restored["fail2ban_files"] = observed_fail2ban
        restored["fail2ban_stopped"] = self.container_state(target["name"]) == "stopped"
        return restored


def _read_acl(path: str) -> str:
    # ``-n`` keeps ACL entries numeric so the expected ``user:4242:rwx`` matches
    # even when a real account happens to own that uid on the drill host.
    return _bounded_metadata_tool(["getfacl", "-p", "-c", "-n", path], "getfacl", path)


def _read_xattr(path: str, name: str) -> str:
    return _bounded_metadata_tool(["getfattr", "-n", name, "--only-values", path],
                                  "getfattr", path)


def _bounded_metadata_tool(argv: List[str], tool: str, path: str,
                          timeout: int = DEFAULT_COMMAND_TIMEOUT) -> str:
    try:
        result = _run_bounded(argv, timeout=timeout, stderr=subprocess.DEVNULL)
    except OSError as exc:
        _fail("%s is required to verify restored metadata for %s: %s" % (tool, path, exc))
    if result is None:
        _fail("%s timed out verifying restored metadata for %s" % (tool, path))
    if result.returncode != 0:
        _fail("%s could not read restored metadata for %s" % (tool, path))
    return result.stdout.decode("utf-8", "replace")

def scenario_success(driver: Driver, job_dir: str) -> Dict[str, Any]:
    unit = driver.unit_name("success")
    driver.launch(job_dir, unit, 900, 90)
    state = driver.wait_finalized(job_dir, unit, 1800)
    if state != "succeeded":
        _fail("the success worker reached %s instead of succeeded" % state)
    if not os.path.exists(driver.complete_path(job_dir)):
        _fail("the successful worker did not publish COMPLETE")
    driver.assert_source_restored(job_dir)
    restored = driver.restore_success(job_dir)
    return {"state": state, "complete": True, "restored": restored}


def scenario_sigkill(driver: Driver, job_dir: str) -> Dict[str, Any]:
    unit = driver.unit_name("kill")
    barrier = driver.new_barrier("kill")
    driver.launch(job_dir, unit, 600, 90, barrier)
    driver.wait_barrier(barrier, 180)
    identities = driver.assert_copying(job_dir)
    driver.kill_unit(unit)
    state = driver.wait_finalized(job_dir, unit, 300)
    driver.wait_unit_inactive(unit, 120)
    if state == "succeeded":
        _fail("the SIGKILL scenario reported success")
    if os.path.exists(driver.complete_path(job_dir)):
        _fail("the SIGKILL scenario published COMPLETE")
    driver.assert_source_restored(job_dir)
    return {"state": state, "complete": False,
            "stopped_at_barrier": [item["name"] for item in identities["stop_containers"]]}


def scenario_timeout(driver: Driver, job_dir: str) -> Dict[str, Any]:
    unit = driver.unit_name("timeout")
    barrier = driver.new_barrier("timeout")
    driver.launch(job_dir, unit, 30, 90, barrier)
    driver.wait_barrier(barrier, 20)
    identities = driver.assert_copying(job_dir)
    state = driver.wait_finalized(job_dir, unit, 300)
    driver.wait_unit_inactive(unit, 180)
    report = driver.job_report(job_dir)
    unit_result = report.get("unit_result") or {}
    if unit_result.get("SERVICE_RESULT") != "timeout":
        _fail("the timeout scenario did not record a real systemd timeout result")
    if state == "succeeded" or os.path.exists(driver.complete_path(job_dir)):
        _fail("the timeout scenario fabricated success")
    driver.assert_source_restored(job_dir)
    return {"state": state, "complete": False,
            "stopped_at_barrier": [item["name"] for item in identities["stop_containers"]],
            "unit_result": unit_result}


def scenario_transport(driver: Driver, job_dir: str) -> Dict[str, Any]:
    unit = driver.unit_name("transport")
    barrier = driver.new_barrier("transport")
    submitter = driver.launch_via_submitter(job_dir, unit, 900, 90, barrier)
    try:
        driver.wait_barrier(barrier, 240)
        identities = driver.assert_copying(job_dir)
        driver.kill_submitter(submitter)
        if not driver.unit_active(unit):
            _fail("the worker was not still managed by systemd after the submitter died")
        driver.release_barrier(barrier)
    finally:
        driver.reap_submitter(submitter)
    state = driver.wait_finalized(job_dir, unit, 1800)
    if state != "succeeded":
        _fail("the transport-loss worker reached %s instead of succeeded" % state)
    if not os.path.exists(driver.complete_path(job_dir)):
        _fail("the transport-loss worker did not publish COMPLETE")
    driver.assert_source_restored(job_dir)
    return {"state": state, "complete": True,
            "stopped_at_barrier": [item["name"] for item in identities["stop_containers"]]}


def run_all(driver: Driver) -> Dict[str, Any]:
    firewall_before = driver.snapshot_firewall()
    driver.write_copy_shim()
    results: Dict[str, Any] = {}
    results["success"] = scenario_success(driver, driver.primary_job)
    results["sigkill"] = scenario_sigkill(driver, driver.new_job("kill"))
    results["timeout"] = scenario_timeout(driver, driver.new_job("timeout"))
    results["transport"] = scenario_transport(driver, driver.new_job("transport"))
    driver.assert_firewall_unchanged(firewall_before)
    results["ufw"] = {"applied": False, "source_hashes_unchanged": True}
    results["jobs"] = [{"label": label, "job_dir": job_dir}
                       for label, job_dir in driver.jobs]
    results["linux_executed"] = True
    return results


def _submit_main(config_path: str) -> int:
    with open(config_path, "r", encoding="utf-8") as handle:
        config = json.load(handle)
    host = fixture.Host()
    unit = config["unit"]
    worker = worker_argv(config["release_dir"], config["job_dir"])
    finalizer = finalizer_argv(config["release_dir"], config["job_dir"])
    environment = {"PATH": "%s:%s" % (config["drill_bin"], os.environ.get("PATH", "")),
                   "VPS3XUI_DRILL_COPY_BARRIER": config["barrier_dir"]}
    argv = systemd_run_argv(unit, worker, finalizer, config["token"],
                            config["runtime_max_sec"], config["timeout_stop_sec"],
                            environment)
    try:
        fixture.reserve_unit(config["ledger_path"], unit, host)
        subprocess.run(argv, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=config.get("launch_timeout", DEFAULT_COMMAND_TIMEOUT))
        fixture.confirm_unit(config["ledger_path"], unit, host)
    except Exception as exc:  # noqa: BLE001 - report a bounded submitter failure
        sys.stderr.write("submit failed: %s\n" % type(exc).__name__)
        return EXIT_FAILED
    while True:
        time.sleep(1)


def _tooling_problem() -> Optional[str]:
    required = ["docker", "systemd-run", "systemctl", "tar", "setfacl", "getfacl",
                "setfattr", "getfattr", "python3"]
    missing = []
    for name in required:
        probe = _run_bounded(["sh", "-c", "command -v %s" % name], timeout=30,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if probe is None or probe.returncode != 0:
            missing.append(name)
    if missing:
        return "missing required Linux tooling: %s" % ", ".join(missing)
    result = _run_bounded(["tar", "--version"], timeout=30)
    if result is None or b"GNU tar" not in result.stdout:
        return "GNU tar is required"
    return None


def _overlaps(first: str, second: str) -> bool:
    first = os.path.abspath(first).rstrip("/")
    second = os.path.abspath(second).rstrip("/")
    return (first == second or first.startswith(second + "/")
            or second.startswith(first + "/"))


def _path_ancestors(path: str) -> List[str]:
    """Every ancestor directory of ``path``, root-first, excluding ``/`` itself."""
    parts: List[str] = []
    current = os.path.abspath(path)
    while True:
        parent = os.path.dirname(current)
        if parent == current:
            break
        parts.append(current)
        current = parent
    parts.reverse()
    return parts


def prospective_owned_paths(identifier: str, image: str, ledger_path: str) -> List[str]:
    """The fixture paths cleanup would remove for ``identifier`` plus the ledger.

    Derived from the same ``fixture_identity``/``fixture_*`` helpers the fixture
    itself uses, so an evidence dir inside (or containing) any of them is refused
    before a single byte is written there.
    """
    names = fixture.fixture_identity(identifier)
    owned = [ledger_path, names["job_dir"]]
    owned.extend(fixture.fixture_dirs(names))
    owned.extend(item["path"] for item in fixture.fixture_symlinks(names))
    owned.extend(item["path"] for item in fixture.fixture_files(names, image))
    return [path for path in owned if isinstance(path, str) and path]


def _evidence_conflicts(evidence_dir: str, identifier: str, image: str,
                        ledger_path: str, drill_root: str) -> List[str]:
    conflicts = [path for path in prospective_owned_paths(identifier, image, ledger_path)
                 if _overlaps(evidence_dir, path)]
    if evidence_dir != drill_root and _overlaps(evidence_dir, drill_root):
        head = os.path.relpath(evidence_dir, drill_root).split(os.sep)[0]
        if head == "drill-bin" or head.startswith("barrier-") or head.startswith("restore-"):
            conflicts.append(os.path.join(drill_root, head))
    return conflicts


def prepare_evidence_dir(evidence_dir: str, drill_root: str, identifier: str,
                         image: str, ledger_path: str) -> str:
    """Exclusively create a brand-new evidence dir and stamp this run's marker.

    The wrapper calls this before it writes anything. A pre-existing directory,
    a symlinked ancestor, or a path overlapping a fixture/drill-owned tree is
    refused, so no previous ``fixture-plan.json``/``cleanup.log`` can be
    clobbered. The returned nonce is exported to ``vm_drill.main`` so a second
    Python invocation can prove the directory is this run's own.
    """
    if not os.path.isabs(evidence_dir):
        _fail("--evidence-dir must be an absolute path")
    if os.path.realpath(evidence_dir) == os.path.realpath(drill_root):
        _fail("refusing to use the drill scratch root itself as the evidence dir")
    for ancestor in _path_ancestors(evidence_dir):
        if os.path.islink(ancestor):
            _fail("refusing an evidence dir under a symlinked ancestor: %s" % ancestor)
        if os.path.exists(ancestor) and not os.path.isdir(ancestor):
            _fail("refusing an evidence dir under a non-directory: %s" % ancestor)
    if os.path.lexists(evidence_dir):
        _fail("refusing to reuse an existing evidence dir: %s" % evidence_dir)
    conflicts = _evidence_conflicts(evidence_dir, identifier, image, ledger_path, drill_root)
    if conflicts:
        _fail("refusing an evidence dir that overlaps the owned path %s" % conflicts[0])
    os.mkdir(evidence_dir, 0o700)
    nonce = secrets.token_hex(16)
    marker_path = os.path.join(evidence_dir, EVIDENCE_MARKER_NAME)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(marker_path, flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write((nonce + "\n").encode("utf-8"))
    return nonce


def validate_evidence_dir(evidence_dir: str, drill_root: str,
                          marker: Optional[str] = None,
                          identifier: Optional[str] = None,
                          image: Optional[str] = None,
                          ledger_path: Optional[str] = None) -> None:
    """Refuse an evidence dir that is not this run's freshly-created directory.

    The wrapper creates the directory exclusively and writes an owner marker
    whose nonce it exports; a reused, symlinked or unowned directory - and any
    path overlapping a fixture/drill-owned tree - is refused before the harness
    writes to it.
    """
    if not os.path.isabs(evidence_dir):
        _fail("--evidence-dir must be an absolute path")
    if os.path.realpath(evidence_dir) == os.path.realpath(drill_root):
        _fail("refusing to use the drill scratch root itself as the evidence dir")
    if os.path.islink(evidence_dir) or not os.path.isdir(evidence_dir):
        _fail("the evidence dir is not a directory: %s" % evidence_dir)
    marker_path = os.path.join(evidence_dir, EVIDENCE_MARKER_NAME)
    try:
        with open(marker_path, "r", encoding="utf-8") as handle:
            observed = handle.read().strip()
    except OSError:
        _fail("the evidence dir has no run-owner marker; use scripts/vm-restore-drill.sh")
    if not marker:
        _fail("this run has no evidence-dir marker nonce; use scripts/vm-restore-drill.sh")
    if observed != marker:
        _fail("the evidence dir was not created by this run (owner marker mismatch)")
    if os.path.exists(os.path.join(evidence_dir, "evidence.json")):
        _fail("refusing to reuse an evidence directory that already has evidence.json")
    if identifier and image and ledger_path:
        conflicts = _evidence_conflicts(evidence_dir, identifier, image, ledger_path,
                                        drill_root)
        if conflicts:
            _fail("refusing an evidence dir that overlaps the owned path %s" % conflicts[0])


def assert_evidence_separate(driver: Driver, evidence_dir: str) -> None:
    """Refuse an evidence dir inside (or containing) a ledger-owned path.

    Fixture cleanup removes every ledger-owned tree and directory, so evidence
    written there would be destroyed; evidence that *contains* a ledger path
    would also mix the run's owned state into retained evidence.
    """
    try:
        data = fixture.read_ledger(driver.host, driver.ledger_path)
    except fixture.LedgerError as exc:
        _fail("the ownership ledger is not readable: %s" % exc)
    if data is None:
        _fail("the ownership ledger is missing: %s" % driver.ledger_path)
    owned = [record.get("path") for field in fixture.LEDGER_LIST_FIELDS
             for record in (data.get(field) or [])]
    owned = [path for path in owned if isinstance(path, str) and path]
    for path in owned:
        if _overlaps(evidence_dir, path):
            _fail("refusing an evidence directory that overlaps the owned path %s"
                  % path)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="vm_drill")
    parser.add_argument("--release-dir")
    parser.add_argument("--drill-root")
    parser.add_argument("--image")
    parser.add_argument("--identifier")
    parser.add_argument("--ledger")
    parser.add_argument("--evidence-dir")
    parser.add_argument("--submit", metavar="CONFIG")
    parser.add_argument("--prepare-evidence", action="store_true",
                        help="exclusively create the evidence dir and stamp this run's marker")
    args = parser.parse_args(argv)
    if args.submit:
        return _submit_main(args.submit)
    if args.prepare_evidence:
        try:
            for value, name in ((args.evidence_dir, "--evidence-dir"),
                                (args.drill_root, "--drill-root"),
                                (args.image, "--image"),
                                (args.identifier, "--identifier"),
                                (args.ledger, "--ledger")):
                if not value:
                    _fail("%s is required" % name)
            nonce = prepare_evidence_dir(args.evidence_dir, args.drill_root,
                                         args.identifier, args.image, args.ledger)
        except DrillFailure as exc:
            sys.stderr.write("FAIL: %s\n" % exc)
            return EXIT_FAILED
        sys.stdout.write(nonce + "\n")
        return 0
    problem = _tooling_problem()
    if problem:
        sys.stderr.write("NOT RUN: %s\n" % problem)
        return EXIT_NOT_RUN
    for value, name in ((args.release_dir, "--release-dir"),
                        (args.drill_root, "--drill-root"),
                        (args.image, "--image"),
                        (args.identifier, "--identifier"),
                        (args.ledger, "--ledger"),
                        (args.evidence_dir, "--evidence-dir")):
        if not value:
            _fail("%s is required" % name)
    try:
        validate_evidence_dir(args.evidence_dir, args.drill_root,
                              os.environ.get("VPS3XUI_DRILL_EVIDENCE_MARKER"),
                              identifier=args.identifier, image=args.image,
                              ledger_path=args.ledger)
    except DrillFailure as exc:
        sys.stderr.write("FAIL: %s\n" % exc)
        return EXIT_FAILED
    driver = Driver(args.release_dir, args.drill_root, args.image,
                    args.identifier, args.ledger, args.evidence_dir)
    results: Optional[Dict[str, Any]] = None
    failure: Optional[Tuple[str, str]] = None
    try:
        driver.create_fixture()
        assert_evidence_separate(driver, args.evidence_dir)
        results = run_all(driver)
    except (DrillFailure, SystemExit, Exception) as exc:  # noqa: BLE001
        # The fixture raises SystemExit for a refusal; any unexpected exception
        # is still turned into FAILED evidence rather than a bare traceback.
        message = str(exc) if isinstance(exc, DrillFailure) else str(exc) or type(exc).__name__
        failure = (type(exc).__name__, message)
        driver.log("scenario failed: %s" % message)
    # Preserve the durable job artifacts before the shell cleanup trap removes
    # the ledger-owned job directories.
    driver.preserve_all_evidence()
    if failure is not None:
        evidence = {"ok": False, "error": failure[1], "error_type": failure[0],
                    "linux_executed": True, "commands": driver.commands,
                    "log": driver.log_lines,
                    "jobs": [{"label": label, "job_dir": job_dir}
                             for label, job_dir in driver.jobs]}
        with open(os.path.join(args.evidence_dir, "evidence.json"), "w",
                  encoding="utf-8") as handle:
            json.dump(evidence, handle, indent=2, sort_keys=True)
        sys.stderr.write("FAIL: %s\n" % failure[1])
        return EXIT_FAILED
    evidence = {"ok": True, "scenarios": results, "commands": driver.commands,
                "log": driver.log_lines,
                "jobs": [{"label": label, "job_dir": job_dir}
                         for label, job_dir in driver.jobs],
                "seam": ("a test-only PATH tar shim blocks the first tar create so "
                         "SIGKILL/RuntimeMaxSec/transport-loss happen during copying; "
                         "the worker still performs its normal copy and the finalizer "
                         "uses the real systemd outcome")}
    with open(os.path.join(args.evidence_dir, "evidence.json"), "w",
              encoding="utf-8") as handle:
        json.dump(evidence, handle, indent=2, sort_keys=True)
    print("restore drill: all VM checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
