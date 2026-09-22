"""Real host operations for the worker: Docker, systemd and GNU tar.

Every subprocess call discards child stderr and raises a curated ``ToolError``
on failure, so no raw remote output (environment, compose expansion, auth
files) can leak into job state or diagnostics.
"""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
from typing import Any, Dict, List, Optional

from ..adapters import archive as archive_adapter
from ..errors import ToolError
from ..util import require_private_dir, safe_tar_member, write_json
from .jobctx import now_iso
from .metadata import build_backup_json, build_images_json

DOCKER_STOP_TIMEOUT = 60

# Original Certbot trigger states this tool knows how to preserve exactly. An
# unknown or transitional value is refused rather than "restored" to a guess.
SUPPORTED_UNIT_FILE_STATES = (
    "enabled", "disabled", "static", "indirect", "masked", "masked-runtime",
)
MASKED_UNIT_FILE_STATES = ("masked", "masked-runtime")


def probe_source_bytes() -> bytes:
    """The exact shipped read-only probe source, for a controlled local child."""
    here = os.path.dirname(os.path.abspath(__file__))
    probe_path = os.path.join(os.path.dirname(here), "probe.py")
    with open(probe_path, "rb") as handle:
        return handle.read()


def run_local_probe(spec, timeout: int = 120):
    """Run the shipped probe as a controlled child and parse its JSON."""
    import base64
    import json

    from ..inventory import Inventory

    argv = ["python3", "-"]
    if spec is not None:
        token = base64.b64encode(json.dumps(spec, sort_keys=True).encode("utf-8")).decode("ascii")
        argv.append(token)
    try:
        proc = subprocess.run(argv, input=probe_source_bytes(), stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        raise ToolError("E_RUNTIME_MISSING", "The read-only probe could not be run.",
                        resource="probe", next_action="inspect_runtime")
    if proc.returncode != 0:
        raise ToolError("E_EXECUTION", "The read-only probe failed.",
                        resource="probe", next_action="inspect_runtime")
    try:
        return Inventory.from_probe(json.loads(proc.stdout.decode("utf-8", "replace")))
    except ValueError:
        raise ToolError("E_UNSUPPORTED", "The probe returned data that is not JSON.",
                        resource="probe", next_action="inspect_runtime")


def _run(argv: List[str], timeout: int = 120, stdout_path: Optional[str] = None) -> subprocess.CompletedProcess:
    try:
        if stdout_path is not None:
            # Create the artifact 0600 from the outset and never through a
            # symlink; docker cp writes into this descriptor.
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(stdout_path, flags, 0o600)
            with os.fdopen(fd, "wb") as handle:
                return subprocess.run(
                    argv, stdout=handle, stderr=subprocess.DEVNULL, timeout=timeout
                )
        return subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        raise ToolError("E_EXECUTION", "A host command timed out.", next_action="inspect_runtime")
    except OSError:
        raise ToolError("E_EXECUTION", "A host command could not be started.", next_action="inspect_runtime")


class RealSystem(object):
    def __init__(self, backup_root: str = "/var/backups/vps3xui", release_dir: Optional[str] = None):
        self._backup_root = backup_root
        self._release_dir = release_dir

    # -- identity / facts -------------------------------------------------
    def probe(self, spec=None, timeout: int = 120):
        """Re-run the shipped read-only probe as a controlled local child."""
        return run_local_probe(spec, timeout=timeout)
    def machine_id(self) -> str:
        try:
            with open("/etc/machine-id", "r", encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError:
            raise ToolError("E_RUNTIME_MISSING", "machine-id is unreadable.", resource="machine-id")

    def backup_root(self) -> str:
        require_private_dir(self._backup_root, 0o700)
        return self._backup_root

    def container_states(self, names: List[str]) -> Dict[str, Optional[Dict[str, Any]]]:
        facts: Dict[str, Optional[Dict[str, Any]]] = {}
        for name in names:
            result = _run(
                ["docker", "inspect", "--format", "{{.Id}} {{.State.Running}}", name],
                timeout=60,
            )
            if result.returncode != 0:
                facts[name] = None
                continue
            text = result.stdout.decode("utf-8", "replace").strip()
            parts = text.split()
            if len(parts) != 2:
                facts[name] = None
                continue
            facts[name] = {"name": name, "id": parts[0], "running": parts[1] == "true"}
        return facts

    def running_container_names(self) -> List[str]:
        result = _run(["docker", "ps", "--format", "{{.Names}}"], timeout=60)
        if result.returncode != 0:
            raise ToolError("E_EXECUTION", "Cannot list running containers.", resource="docker")
        return [line.strip() for line in result.stdout.decode("utf-8", "replace").splitlines() if line.strip()]

    def stop_containers(self, ids: List[str]) -> None:
        if not ids:
            return
        result = _run(["docker", "stop", "-t", str(DOCKER_STOP_TIMEOUT)] + ids, timeout=300)
        if result.returncode != 0:
            raise ToolError("E_EXECUTION", "Docker could not stop all containers.", resource="docker")

    def start_containers(self, ids: List[str]) -> None:
        if not ids:
            return
        result = _run(["docker", "start"] + ids, timeout=300)
        if result.returncode != 0:
            raise ToolError("E_EXECUTION", "Docker could not start all containers.", resource="docker")

    def free_bytes(self, path: str) -> int:
        try:
            st = os.statvfs(os.path.dirname(path) or "/")
        except OSError:
            return 0
        return st.f_frsize * st.f_bavail

    def fsync_paths(self, manifest) -> None:
        directories = set()
        for tree in manifest.bind_trees:
            root = tree["root"].rstrip("/") or "/"
            for include in tree["includes"]:
                candidate = os.path.join(root, include.lstrip("/"))
                directories.add(candidate if os.path.isdir(candidate) else os.path.dirname(candidate))
        for directory in sorted(directories):
            if not directory or not os.path.isdir(directory):
                continue
            try:
                fd = os.open(directory, os.O_RDONLY)
            except OSError:
                continue
            try:
                os.fsync(fd)
            except OSError:
                pass
            finally:
                os.close(fd)
        _run(["sync"], timeout=300)

    # -- certbot ----------------------------------------------------------
    def _unit_state(self, unit: str) -> Dict[str, Any]:
        result = _run(
            ["systemctl", "show", unit, "-p", "LoadState,ActiveState,UnitFileState"],
            timeout=30,
        )
        state = {"load_state": "not-found", "active_state": "unknown", "unit_file_state": "unknown"}
        if result.returncode != 0:
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

    def certbot_state(self, manifest) -> Dict[str, Any]:
        certbot = manifest.certbot
        units = [certbot["service_unit"], certbot["timer_unit"]]
        return {"units": {unit: self._unit_state(unit) for unit in units}}

    def _systemctl(self, args: List[str], timeout: int = 120) -> subprocess.CompletedProcess:
        result = _run(["systemctl"] + args, timeout=timeout)
        if result.returncode != 0:
            raise ToolError(
                "E_EXECUTION",
                "systemctl %s failed and its result cannot be ignored." % args[0],
                resource=args[-1] if args else "systemctl",
                next_action="inspect_runtime",
            )
        return result

    def disable_certbot_triggers(self, manifest) -> None:
        """Reversible, runtime-only mask of the Certbot trigger units.

        The cleanup units are never touched, enablement is never changed and the
        service is never stopped here. If a renewal is already running or a
        lease is present this refuses before changing anything. The exact
        original unit-file state of every trigger is snapshotted first, so a
        pre-existing ``masked``/``masked-runtime`` state is preserved instead of
        being destroyed by an unconditional ``unmask``.
        """
        certbot = manifest.certbot
        timer = certbot["timer_unit"]
        service = certbot["service_unit"]
        if self.certbot_renewal_active(manifest):
            raise ToolError("E_PRECONDITION", "A Certbot renewal is already running.",
                            resource=service, next_action="wait_for_renewal")
        if self.check_lease(manifest):
            raise ToolError("E_PRECONDITION", "An active Certbot HTTP-01 lease is present.",
                            resource=certbot["lease_path"], next_action="wait_for_lease")
        original = self.certbot_state(manifest)
        for unit in (timer, service):
            state = (original["units"].get(unit) or {}).get("unit_file_state")
            if state not in SUPPORTED_UNIT_FILE_STATES:
                raise ToolError(
                    "E_UNSUPPORTED",
                    "Certbot trigger %s is in an unsupported unit-file state." % unit,
                    resource=unit, next_action="review_certbot_schedulers")
        self._systemctl(["stop", timer])
        # --runtime keeps any pre-existing mask and enablement semantics intact
        # and is reversible without daemon-reload.
        self._systemctl(["mask", "--runtime", timer, service])
        # A return code of 0 is not proof of the mask; verify the real state.
        for unit in (timer, service):
            if self._unit_file_state(unit) not in MASKED_UNIT_FILE_STATES:
                raise ToolError(
                    "E_EXECUTION",
                    "Certbot trigger masking did not take effect for %s." % unit,
                    resource=unit, next_action="inspect_runtime")
        # Recheck for a race between observation and masking.
        if self.certbot_renewal_active(manifest) or self.check_lease(manifest):
            # Restore from the *original* snapshot, never a freshly re-sampled
            # (already masked) state.
            self.restore_certbot_triggers(original, manifest)
            raise ToolError("E_CONFLICT", "A Certbot renewal raced with trigger masking.",
                            resource=timer, next_action="review_certbot_schedulers")

    def restore_certbot_triggers(self, state: Dict[str, Any], manifest) -> None:
        certbot = manifest.certbot
        units = state.get("units") or {}
        timer = certbot["timer_unit"]
        service = certbot["service_unit"]
        for unit in (service, timer):
            original = units.get(unit) or {}
            want_state = original.get("unit_file_state")
            if want_state is None:
                continue
            if want_state not in SUPPORTED_UNIT_FILE_STATES:
                raise ToolError(
                    "E_UNSUPPORTED",
                    "Original Certbot trigger state for %s is unsupported." % unit,
                    resource=unit, next_action="review_certbot_schedulers")
            current = self._unit_file_state(unit)
            if want_state == "masked":
                if current != "masked":
                    self._systemctl(["mask", unit])
            elif want_state == "masked-runtime":
                if current != "masked-runtime":
                    self._systemctl(["mask", "--runtime", unit])
            else:
                # Never masked originally: undo only the runtime mask we applied.
                if current in MASKED_UNIT_FILE_STATES:
                    self._systemctl(["unmask", "--runtime", unit])
            final = self._unit_file_state(unit)
            if want_state in MASKED_UNIT_FILE_STATES:
                if final != want_state:
                    raise ToolError(
                        "E_EXECUTION",
                        "Certbot trigger %s did not return to its masked state." % unit,
                        resource=unit, next_action="inspect_runtime")
            elif final in MASKED_UNIT_FILE_STATES:
                raise ToolError(
                    "E_EXECUTION",
                    "Certbot trigger %s is still masked after restore." % unit,
                    resource=unit, next_action="inspect_runtime")

        for unit in (service, timer):
            original = units.get(unit) or {}
            want = original.get("active_state")
            if want is None:
                continue
            if want not in ("active", "inactive"):
                raise ToolError(
                    "E_UNSUPPORTED",
                    "Certbot unit %s was in a transitional state." % unit,
                    resource=unit, next_action="review_certbot_schedulers")
            active = self._unit_active(unit)
            if active is None:
                raise ToolError("E_EXECUTION", "Certbot unit state could not be observed.",
                                resource=unit, next_action="inspect_runtime")
            if want == "active" and not active:
                if unit == service:
                    # Never restart a renewal service; that would start one.
                    raise ToolError("E_CONFLICT",
                                    "Certbot service was active and must not be restarted here.",
                                    resource=unit, next_action="review_certbot_schedulers")
                self._systemctl(["start", unit])
            elif want == "inactive" and active:
                if unit == service:
                    raise ToolError("E_CONFLICT", "Certbot service is running but was inactive.",
                                    resource=unit, next_action="review_certbot_schedulers")
                self._systemctl(["stop", unit])

    def _unit_file_state(self, unit: str) -> Optional[str]:
        return self._unit_state(unit).get("unit_file_state")

    def _unit_active(self, unit: str) -> Optional[bool]:
        """Liveness observation: ``True``/``False``, or ``None`` when unknown."""
        try:
            result = _run(["systemctl", "is-active", unit], timeout=30)
        except ToolError:
            return None
        text = result.stdout.decode("utf-8", "replace").strip()
        if text == "active":
            return True
        if text in ("inactive", "failed", "dead"):
            return False
        return None

    def certbot_renewal_active(self, manifest) -> bool:
        service = manifest.certbot["service_unit"]
        active = self._unit_active(service)
        if active is None:
            raise ToolError("E_EXECUTION", "The Certbot service state could not be determined.",
                            resource=service, next_action="inspect_runtime")
        if active:
            return True
        # A renewal can also be a transient certbot process outside the unit.
        result = _run(["pgrep", "-x", "certbot"], timeout=30)
        if result.returncode == 0:
            return True
        if result.returncode == 1:
            return False
        raise ToolError("E_EXECUTION", "The Certbot process check failed.",
                        resource="certbot", next_action="inspect_runtime")

    def check_lease(self, manifest) -> bool:
        """Any present lease blocks; the mtime is never treated as a proof."""
        return os.path.exists(manifest.certbot["lease_path"])

    # -- copy -------------------------------------------------------------
    def _tar_create(self, dest_path: str, cwd: str, names: List[str]) -> None:
        safe = [safe_tar_member(name) for name in names]
        # ``--`` ends options so a file-list token can never be read as a flag.
        argv = ["tar", "--numeric-owner", "--acls", "--xattrs", "-cpf", dest_path,
                "-C", cwd, "--"] + safe
        result = _run(argv, timeout=7200)
        if result.returncode != 0:
            raise ToolError("E_EXECUTION", "tar could not create an archive.",
                            resource=os.path.basename(dest_path))
        if not os.path.isfile(dest_path) or os.path.islink(dest_path):
            raise ToolError("E_UNSAFE_PATH", "tar did not produce a regular archive.",
                            resource=os.path.basename(dest_path), next_action="inspect_runtime")
        os.chmod(dest_path, 0o600)

    def copy_bind_tree(self, dest_dir: str, tree: Dict[str, Any]) -> str:
        artifact = os.path.join(dest_dir, tree["artifact"])
        self._tar_create(artifact, tree["root"], list(tree["includes"]))
        return artifact

    def copy_volume(self, dest_dir: str, volume: Dict[str, Any]) -> str:
        result = _run(
            ["docker", "volume", "inspect", volume["name"], "--format", "{{.Mountpoint}}"],
            timeout=60,
        )
        if result.returncode != 0:
            raise ToolError("E_EXECUTION", "Volume mountpoint is unavailable.",
                            resource="volume:%s" % volume["name"])
        mountpoint = result.stdout.decode("utf-8", "replace").strip()
        if not mountpoint or not os.path.isdir(mountpoint):
            raise ToolError("E_PRECONDITION", "Volume mountpoint is not a directory.",
                            resource="volume:%s" % volume["name"])
        artifact = os.path.join(dest_dir, volume["artifact"])
        self._tar_create(artifact, mountpoint, ["./"])
        return artifact

    def copy_writable_layer(self, dest_dir: str, layer: Dict[str, Any],
                            container_id: Optional[str] = None) -> str:
        artifact = os.path.join(dest_dir, layer["artifact"])
        # Prefer the container id recorded in the plan; a name could have been
        # reused by a different container between plan and copy.
        target = container_id or layer["container"]
        result = _run(
            ["docker", "cp", "-a", "%s:%s" % (target, layer["path"]), "-"],
            timeout=1800,
            stdout_path=artifact,
        )
        if result.returncode != 0:
            raise ToolError("E_EXECUTION", "docker cp could not save the writable layer.",
                            resource=layer["artifact"])
        return artifact

    def copy_certbot_automation(self, dest_dir: str, manifest) -> str:
        certbot = manifest.certbot
        artifact = os.path.join(dest_dir, certbot["artifact"])
        names = [
            certbot["guard_path"].lstrip("/"),
            "etc/systemd/system/%s" % certbot["cleanup_service"],
            "etc/systemd/system/%s" % certbot["cleanup_timer"],
            certbot["dropin"].lstrip("/"),
            certbot["guard_enabled_path"].lstrip("/"),
        ]
        self._tar_create(artifact, "/", names)
        return artifact

    def copy_reference_artifacts(self, dest_dir: str, manifest) -> List[str]:
        produced: List[str] = []
        for reference in manifest.reference_artifacts:
            tar_names = [name for name in reference["artifacts"] if name.endswith(".tar")]
            for name in tar_names:
                artifact = os.path.join(dest_dir, name)
                self._tar_create(artifact, "/", [path.lstrip("/") for path in manifest.data["ufw"]["paths"]])
                produced.append(artifact)
            for name in reference["artifacts"]:
                if name.endswith(".tar"):
                    continue
                path = os.path.join(dest_dir, name)
                flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(path, flags, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(self._reference_text(name, manifest).encode("utf-8"))
                produced.append(path)
        return produced

    def _reference_text(self, name: str, manifest) -> str:
        """Reference-only UFW text. Never applied to any host."""
        if name == "ufw-meta.txt":
            result = _run(["ufw", "version"], timeout=15)
            version = result.stdout.decode("utf-8", "replace").strip() if result.returncode == 0 else "unavailable"
            return "%s\n%s\n" % (now_iso(), version)
        command = {
            "ufw-status.txt": ["ufw", "status", "verbose"],
            "ufw-numbered.txt": ["ufw", "status", "numbered"],
            "ufw-added.txt": ["ufw", "show", "added"],
        }.get(name)
        if command is None:
            return "reference artifact %s: unavailable\n" % name
        result = _run(command, timeout=30)
        if result.returncode != 0:
            return "reference artifact %s: unavailable\n" % name
        return result.stdout.decode("utf-8", "replace")

    def write_metadata(self, dest_dir: str, manifest, initial_state: Dict[str, Any]) -> None:
        write_json(
            os.path.join(dest_dir, "images.json"),
            build_images_json(manifest, now_iso()),
            mode=0o600,
        )
        write_json(
            os.path.join(dest_dir, "backup.json"),
            build_backup_json(
                manifest,
                os.path.basename(dest_dir.rstrip("/")),
                initial_state,
                now_iso(),
                {"system": platform.system(), "machine": platform.machine()},
            ),
            mode=0o600,
        )

    def validate_archive(self, path: str) -> Dict[str, Any]:
        report = archive_adapter.validate_tar(path)
        return report.to_object()
