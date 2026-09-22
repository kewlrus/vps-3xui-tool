"""Typed read-only inventory built from the shipped probe, plus manifest drift
detection. All comparisons are fail-closed: an unexplained resource blocks a
plan instead of being silently included or excluded.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .adapters.docker import DockerFacts
from .adapters.systemd import SystemdFacts
from .errors import ToolError
from .manifest import path_is_inside, paths_overlap, raw_artifact_pairs

# Reviewed dependency floors. Older or unobservable versions must block a plan
# before any change: metadata preservation and container facts depend on them.
MINIMUM_VERSIONS = {
    "python": (3, 8),
    "docker": (20, 10),
    "compose": (2, 0),
    "systemd": (240,),
}


def _version_tuple(text) -> Optional[tuple]:
    """Extract the leading numeric version from a tool's version string."""
    if not isinstance(text, str):
        return None
    match = None
    import re as _re

    match = _re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", text)
    if not match:
        return None
    return tuple(int(part) for part in match.groups() if part is not None)


class Finding(object):
    def __init__(self, code: str, message: str, resource: Optional[str] = None,
                 next_action: Optional[str] = None, blocking: bool = True):
        self.code = code
        self.message = message
        self.resource = resource
        self.next_action = next_action
        self.blocking = blocking

    def to_object(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "resource": self.resource,
            "next_action": self.next_action,
            "blocking": self.blocking,
        }


class DriftReport(object):
    def __init__(self, findings: List[Finding]):
        self.findings = findings

    @property
    def blocking(self) -> List[Finding]:
        return [item for item in self.findings if item.blocking]

    @property
    def warnings(self) -> List[Finding]:
        return [item for item in self.findings if not item.blocking]

    @property
    def ok(self) -> bool:
        return not self.blocking

    def first_blocking_error(self) -> Optional[ToolError]:
        for item in self.blocking:
            return ToolError(item.code, item.message, item.resource, item.next_action)
        return None

    def raise_if_blocking(self) -> None:
        error = self.first_blocking_error()
        if error is not None:
            raise error

    def to_object(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "blocking": [item.to_object() for item in self.blocking],
            "warnings": [item.to_object() for item in self.warnings],
        }


SUPPORTED_PROBE_VERSIONS = (1, 2, 3)

# Pending at-job queue facts are validated structurally, not trusted blindly: a
# probe's ``errors`` list is not the only thing that can block, because an
# unknown/unobserved queue, a contradictory state or a malformed fact must
# refuse even when no token is present.
AT_QUEUE_STATES = ("absent", "empty", "occupied", "unknown")
AT_QUEUE_DIR_STATES = ("empty", "occupied", "unknown")
AT_QUEUE_CONFLICT_MESSAGE = (
    "A pending at job was found; P0 cannot prove it will not renew Certbot and "
    "refuses to copy while it may run."
)


def _at_count(value) -> bool:
    """A job count is ``None`` or a non-negative int (never a bool)."""
    if value is None:
        return True
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _at_queue_findings(at_queue) -> List[Finding]:
    """Validate the probe's pending at-job facts and derive blocking findings.

    The block is derived from the validated facts rather than from the probe's
    ``errors`` list alone: an unknown or unobserved required queue, a
    contradictory state, or any malformed fact blocks even without an error
    token. A positive job count anywhere is treated as occupied even if the
    overall state is mislabelled. Malformed input blocks as
    ``E_PROBE_INCOMPLETE`` and never raises.
    """
    findings: List[Finding] = []

    def incomplete(detail: str, resource: str = "at_queue") -> None:
        findings.append(Finding(
            "E_PROBE_INCOMPLETE",
            "The pending at-job queue facts are unusable (%s); queued jobs cannot be ruled out." % detail,
            resource=resource,
            next_action="rerun_probe",
        ))

    def conflict(resource: str) -> None:
        findings.append(Finding(
            "E_CONFLICT", AT_QUEUE_CONFLICT_MESSAGE,
            resource=resource, next_action="review_at_queue",
        ))

    if not isinstance(at_queue, dict) or not at_queue:
        incomplete("the probe did not report the queue")
        return findings
    tooling = at_queue.get("tooling")
    atq = at_queue.get("atq")
    directories = at_queue.get("directories")
    state = at_queue.get("state")
    if (not isinstance(tooling, dict) or not isinstance(atq, dict)
            or not isinstance(directories, list) or not isinstance(state, str)):
        incomplete("malformed section")
        return findings
    if state not in AT_QUEUE_STATES:
        incomplete("unrecognised state")
        return findings
    for key in ("at", "atq"):
        value = tooling.get(key)
        if value is not None and not isinstance(value, str):
            incomplete("malformed tooling.%s" % key)
            return findings
    present = atq.get("present")
    observed = atq.get("observed")
    count = atq.get("count")
    if not isinstance(present, bool) or not isinstance(observed, bool) or not _at_count(count):
        incomplete("malformed atq facts")
        return findings
    dir_facts: List[tuple] = []
    for entry in directories:
        if not isinstance(entry, dict):
            incomplete("malformed spool entry")
            return findings
        path = entry.get("path")
        dir_state = entry.get("state")
        jobs = entry.get("jobs")
        if not isinstance(path, str) or not path:
            incomplete("malformed spool path")
            return findings
        if dir_state not in AT_QUEUE_DIR_STATES:
            incomplete("unrecognised spool state")
            return findings
        if not _at_count(jobs):
            incomplete("malformed spool job count")
            return findings
        dir_facts.append((path, dir_state, jobs))

    # A positive count anywhere is occupied, regardless of any label.
    occupied_paths = [path for (path, dir_state, jobs) in dir_facts
                      if dir_state == "occupied" or (jobs or 0) > 0]
    if occupied_paths:
        for path in occupied_paths:
            conflict("at:%s" % path)
        return findings
    if (count or 0) > 0:
        conflict("at:queue")
        return findings
    if state == "occupied":
        conflict("at:queue")
        return findings

    # Unknown / unobserved required queue blocks as incomplete evidence.
    if state == "unknown":
        incomplete("the queue state is unknown")
        return findings
    if any(dir_state == "unknown" for (_path, dir_state, _jobs) in dir_facts):
        incomplete("a spool is unreadable or unrecognised")
        return findings
    if present and not observed:
        incomplete("atq is present but was not observed")
        return findings
    if observed and count is None:
        incomplete("atq was observed without a count")
        return findings
    if observed and not present:
        incomplete("atq was observed but marked absent")
        return findings
    if count is not None and not observed:
        incomplete("atq reported a count without an observation")
        return findings
    if state == "absent" and (present or tooling.get("at") or tooling.get("atq") or dir_facts):
        incomplete("an absent state contradicts the observed facts")
        return findings
    if state == "empty" and not dir_facts and not (present and observed):
        incomplete("an empty state without an observed spool or atq")
        return findings
    return findings


class Inventory(object):
    def __init__(self, data: Dict[str, Any]):
        self.raw = data
        self.machine_id = data.get("machine_id")
        self.config_fingerprints = dict(data.get("config_fingerprints") or {})
        self.trusted_fingerprints = dict(data.get("trusted_fingerprints") or {})
        self.trusted_modes = dict(data.get("trusted_modes") or {})
        self.os = data.get("os") or {}
        self.arch = data.get("arch")
        self.python = data.get("python")
        self.tar = data.get("tar") or {}
        self.docker = data.get("docker") or {}
        self.errors = list(data.get("errors") or [])
        self.containers: Dict[str, Dict[str, Any]] = DockerFacts.parse_containers(
            data.get("containers")
        )
        self.volumes: Dict[str, Dict[str, Any]] = DockerFacts.parse_volumes(
            data.get("volumes")
        )
        self.systemd = data.get("systemd") or {"present": False, "units": {}, "unit_files": []}
        self.certbot = data.get("certbot") or {}
        self.cron_certbot = list(data.get("cron_certbot") or [])
        raw_at_queue = data.get("at_queue")
        self.at_queue = raw_at_queue if isinstance(raw_at_queue, dict) else {}
        self.ufw = data.get("ufw") or {}
        self.paths = data.get("paths") or {}
        self.writable_layer = data.get("writable_layer") or {}
        self.space = data.get("space") or {}
        self.compose = data.get("compose") or {}

    @classmethod
    def from_probe(cls, data: Dict[str, Any]) -> "Inventory":
        if not isinstance(data, dict) or data.get("probe_version") not in SUPPORTED_PROBE_VERSIONS:
            raise ToolError(
                "E_UNSUPPORTED",
                "Probe output is missing or has an unsupported version.",
                resource="probe",
                next_action="check_host_runtime",
            )
        return cls(data)

    # -- convenience views ------------------------------------------------
    def running_containers(self) -> List[Dict[str, Any]]:
        return [item for item in self.containers.values() if item.get("running")]

    def container_running(self, name: str) -> bool:
        item = self.containers.get(name)
        return bool(item and item.get("running"))

    def path_exists(self, path: str) -> bool:
        return bool((self.paths.get(path) or {}).get("exists"))

    def unit_state(self, unit: str) -> Dict[str, Any]:
        return (self.systemd.get("units") or {}).get(unit) or {}

    def lease_active(self, max_lease_seconds: int) -> bool:
        if not self.certbot.get("lease_present"):
            return False
        age = self.certbot.get("lease_age_seconds")
        if age is None:
            return True
        return age <= max_lease_seconds

    def declared_mount_sources(self, manifest) -> List[str]:
        sources: List[str] = []
        for volume in manifest.volumes:
            sources.append("volume:" + volume["name"])
        for tree in manifest.bind_trees:
            root = tree["root"].rstrip("/")
            for include in tree["includes"]:
                include = include.rstrip("/")
                joined = (root + "/" + include) if root else "/" + include
                sources.append(joined)
        return sources

    def to_object(self) -> Dict[str, Any]:
        return {
            "machine_id": self.machine_id,
            "os": self.os,
            "arch": self.arch,
            "docker": self.docker,
            "errors": self.errors,
            "containers": [
                {
                    "name": item.get("name"),
                    "image": item.get("image"),
                    "repo_digests": item.get("repo_digests"),
                    "running": item.get("running"),
                    "status": item.get("status"),
                    "compose_project": item.get("compose_project"),
                    "compose_service": item.get("compose_service"),
                }
                for item in sorted(self.containers.values(), key=lambda c: c.get("name") or "")
            ],
            "volumes": [
                {
                    "name": item.get("name"),
                    "driver": item.get("driver"),
                }
                for item in sorted(self.volumes.values(), key=lambda v: v.get("name") or "")
            ],
            "certbot": {
                "present": self.certbot.get("present"),
                "guard_present": self.certbot.get("guard_present"),
                "guard_enabled": self.certbot.get("guard_enabled"),
                "lease_present": self.certbot.get("lease_present"),
                "lease_age_seconds": self.certbot.get("lease_age_seconds"),
                "renewal_files": self.certbot.get("renewal_files"),
            },
            "ufw": self.ufw,
        }


def _declared_bind_paths(manifest) -> List[str]:
    paths: List[str] = []
    for tree in manifest.bind_trees:
        root = tree["root"].rstrip("/")
        for include in tree["includes"]:
            include = include.rstrip("/")
            paths.append((root + "/" + include) if root else "/" + include)
    return paths


def _mount_is_declared(mount: Dict[str, Any], manifest, declared_binds: List[str]) -> bool:
    kind = mount.get("type")
    if kind == "volume":
        return manifest.volume_by_name(mount.get("name") or "") is not None
    if kind == "bind":
        source = (mount.get("source") or "").rstrip("/")
        for declared in declared_binds:
            if source == declared or source.startswith(declared + "/"):
                return True
        return False
    # tmpfs, npipe and unknown mount kinds are not part of the approved model
    return False


def probe_spec(manifest) -> Dict[str, Any]:
    """Build the validated read-only probe spec from the manifest.

    The shipped probe code never changes; only this bounded JSON data varies.
    It carries the manifest's paths, Compose projects, Certbot unit names,
    writable-layer paths and configuration inputs so the probe observes the
    approved inventory rather than a hard-coded guess.
    """
    paths: List[str] = list(_required_present_paths(manifest))
    for extra in (
        manifest.certbot["lease_path"],
        manifest.certbot["dropin"],
    ):
        if extra and extra not in paths:
            paths.append(extra)
    for project in manifest.data["compose_projects"]:
        for path in project["files"]:
            if path and path not in paths:
                paths.append(path)
    config_files: List[str] = []
    for project in manifest.data["compose_projects"]:
        for path in project["files"]:
            if path and path not in config_files:
                config_files.append(path)
    for tree in manifest.bind_trees:
        root = tree["root"].rstrip("/")
        for include in tree["includes"]:
            inc = include.lstrip("/")
            joined = _norm_path((root + "/" + inc) if root else "/" + inc)
            if joined and joined not in config_files:
                config_files.append(joined)
    dropin = manifest.certbot["dropin"]
    if dropin and dropin not in config_files:
        config_files.append(dropin)
    writable_layers = [
        {"container": layer["container"], "path": layer["path"]}
        for layer in manifest.writable_layers
    ]
    compose_projects = [
        {"project": project["project"], "working_dir": project["working_dir"],
         "files": list(project["files"])}
        for project in manifest.data["compose_projects"]
    ]
    return {
        "paths": paths,
        "units": [
            manifest.certbot["service_unit"],
            manifest.certbot["timer_unit"],
            manifest.certbot["cleanup_service"],
            manifest.certbot["cleanup_timer"],
        ],
        "writable_layers": writable_layers,
        "compose_projects": compose_projects,
        "config_files": config_files,
        "space_paths": [reference["source"] for reference in manifest.reference_artifacts],
        "trusted_files": manifest.trusted_file_paths(),
        "renewal_hook_dirs": list(manifest.certbot.get("renewal_hook_dirs") or []),
        "backup_root": "/var/backups",
        "guard_path": manifest.certbot["guard_path"],
        "guard_enabled_path": manifest.certbot["guard_enabled_path"],
        "lease_path": manifest.certbot["lease_path"],
        "renewal_dir": "/etc/letsencrypt/renewal",
    }


def _norm_path(path: str) -> str:
    while "//" in path:
        path = path.replace("//", "/")
    return path


def _required_present_paths(manifest) -> List[str]:
    """Absolute host paths that must exist for a complete backup.

    Derived from the manifest (bind includes, reference sources, UFW paths and
    the Certbot guard helper), never from arbitrary manifest strings beyond
    schema/semantic validation.
    """
    paths: List[str] = []
    for tree in manifest.bind_trees:
        root = tree["root"].rstrip("/")
        for include in tree["includes"]:
            inc = include.lstrip("/")
            joined = (root + "/" + inc) if root else "/" + inc
            paths.append(_norm_path(joined if joined.startswith("/") else "/" + joined))
    for reference in manifest.reference_artifacts:
        paths.append(reference["source"])
    for path in manifest.data["ufw"]["paths"]:
        paths.append(path)
    paths.append(manifest.certbot["guard_path"])
    out: List[str] = []
    for path in paths:
        path = _norm_path(path)
        if path not in out:
            out.append(path)
    return out


def _mount_key(mount: Dict[str, Any]):
    return (
        mount.get("type"),
        mount.get("name"),
        mount.get("source"),
        mount.get("destination"),
        bool(mount.get("rw")),
    )


def _declared_systemd_scheduler(path, digest, source, declared_units, unit_dirs, manifest) -> bool:
    """True only for an exactly declared, digest-pinned systemd unit file.

    The probe labels content-discovered unit files ``source: "systemd"``. The
    worker masks the declared service/timer itself and the cleanup units are
    pinned automation, so those are the sole schedulers the P0 rule may pass.
    Every other source (cron, at, unknown) is refused without exception.
    """
    if source != "systemd":
        return False
    if not isinstance(path, str) or not isinstance(digest, str) or not digest:
        return False
    directory, _, name = path.rpartition("/")
    if directory not in unit_dirs or name not in declared_units:
        return False
    pinned = manifest.trusted_file_digest(path)
    return bool(pinned) and pinned == digest


def compare(manifest, inventory: Inventory) -> DriftReport:
    findings: List[Finding] = []

    # -- fail closed on missing probe facts ------------------------------
    # An incomplete or unavailable probe must block the plan; a silently
    # skipped section would let an unverified host look approved.
    for token in sorted(set(inventory.errors)):
        findings.append(
            Finding(
                "E_PROBE_INCOMPLETE",
                "The read-only probe reported an unavailable required section; the inventory is incomplete.",
                resource=token,
                next_action="rerun_probe_after_fixing_host",
            )
        )
    # The pending ``at``/batch queue is a mandatory safety fact. An absent
    # installation is fine, but a missing, unknown, unobserved or malformed
    # queue leaves queued jobs unruled out, so it blocks as incomplete evidence.
    findings.extend(_at_queue_findings(inventory.at_queue))
    if not inventory.machine_id:
        findings.append(
            Finding(
                "E_PROBE_INCOMPLETE",
                "The probe returned no machine-id.",
                resource="machine-id",
                next_action="inspect_host_facts",
            )
        )
    if not inventory.docker.get("present"):
        findings.append(
            Finding(
                "E_UNSUPPORTED",
                "Docker is unavailable; container facts cannot be verified.",
                resource="docker",
                next_action="install_or_enable_docker",
            )
        )
    if not inventory.systemd.get("present"):
        findings.append(
            Finding(
                "E_UNSUPPORTED",
                "systemd facts are unavailable; scheduler state cannot be verified.",
                resource="systemd",
                next_action="enable_systemd",
            )
        )
    for project in manifest.data["compose_projects"]:
        info = (inventory.compose or {}).get(project["project"])
        if not info:
            findings.append(
                Finding(
                    "E_PROBE_INCOMPLETE",
                    "A declared Compose project was not probed.",
                    resource="compose:%s" % project["project"],
                    next_action="rerun_probe",
                )
            )
        elif info.get("valid") is not True:
            findings.append(
                Finding(
                    "E_PRECONDITION",
                    "Compose configuration failed safe validation.",
                    resource="compose:%s" % project["project"],
                    next_action="fix_compose_or_review",
                )
            )
        else:
            observed_services = sorted(info.get("services") or [])
            declared_services = sorted(project.get("services") or [])
            if observed_services and observed_services != declared_services:
                findings.append(
                    Finding(
                        "E_INVENTORY_DRIFT",
                        "Compose services differ from the approved manifest.",
                        resource="compose:%s" % project["project"],
                        next_action="review_inventory",
                    )
                )
    for path in _required_present_paths(manifest):
        entry = inventory.paths.get(path)
        if entry is None:
            findings.append(
                Finding(
                    "E_PROBE_INCOMPLETE",
                    "A required path was not probed.",
                    resource=path,
                    next_action="rerun_probe",
                )
            )
        elif not entry.get("exists"):
            findings.append(
                Finding(
                    "E_INVENTORY_DRIFT",
                    "A required path is missing on the host.",
                    resource=path,
                    next_action="review_inventory",
                )
            )

    # -- reviewed runtime dependencies ------------------------------------
    # Missing or too-old dependencies must block the plan before any change.
    observed_versions = {
        "python": inventory.python,
        "docker": inventory.docker.get("version"),
        "compose": inventory.docker.get("compose_version"),
        "systemd": (inventory.systemd or {}).get("version"),
    }
    for token, minimum in sorted(MINIMUM_VERSIONS.items()):
        parsed = _version_tuple(observed_versions.get(token))
        if parsed is None:
            findings.append(
                Finding(
                    "E_PROBE_INCOMPLETE",
                    "A required dependency version was not observed.",
                    resource="dependency:%s" % token,
                    next_action="rerun_probe",
                )
            )
        elif parsed < minimum:
            findings.append(
                Finding(
                    "E_UNSUPPORTED",
                    "A required dependency is older than the reviewed minimum.",
                    resource="dependency:%s" % token,
                    next_action="upgrade_dependency",
                )
            )
    tar = inventory.tar or {}
    if not tar.get("present"):
        findings.append(
            Finding(
                "E_PROBE_INCOMPLETE",
                "GNU tar was not observed; archive metadata cannot be preserved.",
                resource="dependency:tar",
                next_action="install_gnu_tar",
            )
        )
    elif not tar.get("gnu") or _version_tuple(tar.get("version")) is None:
        findings.append(
            Finding(
                "E_UNSUPPORTED",
                "GNU tar is required to preserve ownership, mode and xattrs.",
                resource="dependency:tar",
                next_action="install_gnu_tar",
            )
        )

    # -- archive scope: physical Docker data-root, lease, overlaps ---------
    declared_includes = _declared_bind_paths(manifest)
    docker_root = inventory.docker.get("root_dir")
    if not docker_root:
        findings.append(
            Finding(
                "E_PROBE_INCOMPLETE",
                "The physical Docker data-root was not observed.",
                resource="docker.root_dir",
                next_action="rerun_probe",
            )
        )
    else:
        for include in declared_includes:
            if paths_overlap(include, docker_root):
                findings.append(
                    Finding(
                        "E_CONFLICT",
                        "A declared archive path overlaps the physical Docker data-root.",
                        resource=include,
                        next_action="narrow_includes",
                    )
                )
    lease = manifest.certbot.get("lease_path")
    for index, first in enumerate(declared_includes):
        for second in declared_includes[index + 1:]:
            if paths_overlap(first, second):
                findings.append(
                    Finding(
                        "E_CONFLICT",
                        "Two declared archive paths overlap; the restore owner is ambiguous.",
                        resource="%s ~ %s" % (first, second),
                        next_action="narrow_includes",
                    )
                )
    for include in declared_includes:
        if lease and path_is_inside(lease, include):
            findings.append(
                Finding(
                    "E_CONFLICT",
                    "The Certbot runtime lease is inside a declared archive path.",
                    resource=lease,
                    next_action="narrow_includes",
                )
            )
    artifact_owners: Dict[str, str] = {}
    for name, owner in raw_artifact_pairs(manifest):
        if name in artifact_owners and artifact_owners[name] != owner:
            findings.append(
                Finding(
                    "E_MANIFEST_INVALID",
                    "An artifact name is claimed by more than one resource.",
                    resource=name,
                    next_action="fix_manifest",
                )
            )
        artifact_owners[name] = owner

    # Machine identity is bound by plan, not drift; report only as a warning.
    expected_machine = manifest.expected_machine_id
    if expected_machine and inventory.machine_id and expected_machine != inventory.machine_id:
        findings.append(
            Finding(
                "E_HOST_IDENTITY_MISMATCH",
                "Observed machine-id does not match the manifest.",
                resource="machine-id",
                next_action="review_inventory",
            )
        )

    # Pending resources block completeness regardless of any guessed container
    # name: an unverified resource must be resolved by a fresh read-only
    # inventory before a plan can claim completeness.
    for entry in manifest.pending_approval:
        findings.append(
            Finding(
                "E_MANIFEST_PENDING_APPROVAL",
                "A resource is pending approval; backup completeness is blocked.",
                resource=entry.get("resource"),
                next_action="approve_inventory",
            )
        )

    # Trusted-file fingerprints (private) and exact Certbot hook pins.
    if manifest.approved:
        for item in manifest.trusted_files:
            observed = inventory.trusted_fingerprints.get(item["path"])
            if observed is None:
                findings.append(
                    Finding(
                        "E_TRUST_MISMATCH",
                        "A trusted file is missing or unreadable.",
                        resource=item["path"],
                        next_action="review_trusted_files",
                    )
                )
            elif observed != item["sha256"]:
                findings.append(
                    Finding(
                        "E_TRUST_MISMATCH",
                        "A trusted file changed since approval.",
                        resource=item["path"],
                        next_action="review_trusted_files",
                    )
                )
            # Permission pins are machine-bound: a content hash alone cannot
            # prove that a privileged helper is still root-owned and 0755.
            pinned_modes = {key: item.get(key) for key in ("mode", "uid", "gid")
                            if item.get(key) is not None}
            if pinned_modes:
                observed_modes = inventory.trusted_modes.get(item["path"])
                if observed_modes is None:
                    findings.append(
                        Finding(
                            "E_PROBE_INCOMPLETE",
                            "A trusted file's permissions were not observed.",
                            resource=item["path"],
                            next_action="rerun_probe",
                        )
                    )
                else:
                    for key, expected in sorted(pinned_modes.items()):
                        if observed_modes.get(key) != expected:
                            findings.append(
                                Finding(
                                    "E_TRUST_MISMATCH",
                                    "A trusted file's permissions changed since approval.",
                                    resource="%s:%s" % (item["path"], key),
                                    next_action="review_trusted_files",
                                )
                            )
                    if observed_modes.get("is_symlink"):
                        findings.append(
                            Finding(
                                "E_TRUST_MISMATCH",
                                "A trusted file is a symlink; the pinned bytes and permissions cannot be trusted.",
                                resource=item["path"],
                                next_action="review_trusted_files",
                            )
                        )
    hook_pins = manifest.certbot.get("hook_fingerprints") or {}
    for filename, hooks in (inventory.certbot.get("renewal_hook_fingerprints") or {}).items():
        for key, digest in (hooks or {}).items():
            pin = hook_pins.get("%s:%s" % (filename, key))
            if pin is None or pin != digest:
                findings.append(
                    Finding(
                        "E_CONFLICT",
                        "A Certbot renewal hook command is not pinned by an approved fingerprint.",
                        resource="%s:%s" % (filename, key),
                        next_action="review_certbot_hooks",
                    )
                )
    for directory, entries in (inventory.certbot.get("renewal_hook_dirs") or {}).items():
        for name, digest in (entries or {}).items():
            full = directory.rstrip("/") + "/" + name
            if manifest.trusted_file_digest(full) != digest:
                findings.append(
                    Finding(
                        "E_CONFLICT",
                        "An unpinned Certbot hook-directory entry exists.",
                        resource=full,
                        next_action="review_certbot_hooks",
                    )
                )

    # -- Certbot guard/hook inventory completeness -------------------------
    certbot_facts = inventory.certbot or {}
    inventory_facts = bool(
        certbot_facts.get("renewal_files")
        or certbot_facts.get("renewal_hooks")
        or certbot_facts.get("renewal_hook_dirs")
    )
    if not certbot_facts.get("present"):
        if not inventory_facts:
            findings.append(
                Finding(
                    "E_PROBE_INCOMPLETE",
                    "No Certbot automation facts were observed; the trust contract cannot be verified.",
                    resource="certbot",
                    next_action="rerun_probe",
                )
            )
        else:
            findings.append(
                Finding(
                    "E_PRECONDITION",
                    "The certbot binary was not observed; trust rests on the pinned automation files only.",
                    resource="certbot",
                    next_action="install_certbot_or_review_pins",
                    blocking=False,
                )
            )
    else:
        if not certbot_facts.get("guard_present"):
            findings.append(
                Finding(
                    "E_CONFLICT",
                    "The Certbot guard helper was not observed on the host.",
                    resource=manifest.certbot["guard_path"],
                    next_action="review_certbot_guard",
                )
            )
        if manifest.approved:
            renewal_files = list(certbot_facts.get("renewal_files") or [])
            renewal_name = manifest.renewal_file_path().rsplit("/", 1)[-1]
            if not renewal_files:
                findings.append(
                    Finding(
                        "E_PROBE_INCOMPLETE",
                        "The probe reported no Certbot renewal files; the trust contract cannot be verified.",
                        resource=manifest.renewal_file_path(),
                        next_action="rerun_probe",
                    )
                )
            elif renewal_name not in renewal_files:
                findings.append(
                    Finding(
                        "E_INVENTORY_DRIFT",
                        "The approved lineage renewal file is missing on the host.",
                        resource=manifest.renewal_file_path(),
                        next_action="review_certbot_renewal",
                    )
                )
            observed_dirs = certbot_facts.get("renewal_hook_dirs")
            if not isinstance(observed_dirs, dict) or not observed_dirs:
                findings.append(
                    Finding(
                        "E_PROBE_INCOMPLETE",
                        "The probe reported no Certbot renewal hook directories; hook trust cannot be verified.",
                        resource="renewal-hooks",
                        next_action="rerun_probe",
                    )
                )
            else:
                for directory in (manifest.certbot.get("renewal_hook_dirs") or []):
                    if directory not in observed_dirs:
                        findings.append(
                            Finding(
                                "E_PROBE_INCOMPLETE",
                                "A declared Certbot renewal hook directory was not probed.",
                                resource=directory,
                                next_action="rerun_probe",
                            )
                        )

    # Scheduler detection is content based. P0 refuses every observed Certbot
    # cron/at or unknown-source entry outright: a pinned digest proves which
    # bytes are present, not that the scheduler is inactive, and the HTTP-01
    # guard only governs temporary firewall access. The one exception is a
    # declared systemd unit file that the worker itself masks or that is the
    # pinned cleanup automation; it may pass only when its path is an immediate
    # file in a supported unit directory, its basename is declared in the
    # manifest, and the manifest pins the observed nonempty digest. Guard state
    # never authorizes a scheduler.
    allowed_unit_dirs = (
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    )
    declared_units = {
        str(manifest.certbot[key]).rpartition("/")[2]
        for key in ("service_unit", "timer_unit", "cleanup_service", "cleanup_timer")
        if manifest.certbot.get(key)
    }
    for entry in inventory.cron_certbot:
        if isinstance(entry, dict):
            path = entry.get("path")
            digest = entry.get("sha256")
            source = entry.get("source") or "cron"
        else:
            path, digest, source = str(entry), None, "cron"
        if _declared_systemd_scheduler(path, digest, source, declared_units,
                                       allowed_unit_dirs, manifest):
            continue
        findings.append(
            Finding(
                "E_CONFLICT",
                "A Certbot scheduler was found; P0 cannot prove it is inactive and refuses to copy while it may renew.",
                resource="%s:%s" % (source, path),
                next_action="review_certbot_schedulers",
            )
        )

    declared = {item["name"]: item for item in manifest.containers}
    declared_binds = _declared_bind_paths(manifest)

    # Unexpected running containers.
    for item in inventory.running_containers():
        name = item.get("name")
        declared_item = declared.get(name)
        if declared_item is None:
            findings.append(
                Finding(
                    "E_INVENTORY_DRIFT",
                    "A running container is absent from the approved manifest.",
                    resource=name,
                    next_action="review_inventory",
                )
            )
            continue
        if not declared_item.get("included"):
            findings.append(
                Finding(
                    "E_INVENTORY_DRIFT",
                    "A container marked as excluded is running and may be writing data.",
                    resource=name,
                    next_action="review_inventory",
                )
            )

    # Missing declared included containers.
    for item in manifest.containers:
        if item.get("included") and item["name"] not in inventory.containers:
            findings.append(
                Finding(
                    "E_INVENTORY_DRIFT",
                    "An included container from the manifest is missing on the host.",
                    resource=item["name"],
                    next_action="review_inventory",
                )
            )

    # Unexpected mounts on included containers, and non-local volume drivers.
    for name, item in inventory.containers.items():
        declared_item = declared.get(name)
        if declared_item is None or not declared_item.get("included"):
            continue
        for mount in item.get("mounts") or []:
            if not _mount_is_declared(mount, manifest, declared_binds):
                findings.append(
                    Finding(
                        "E_INVENTORY_DRIFT",
                        "A container has a mount that is not described by the manifest.",
                        resource="%s:%s" % (name, mount.get("destination") or mount.get("source")),
                        next_action="review_inventory",
                    )
                )
    # Exact per-container mount declarations, when the manifest pins them.
    for item in manifest.containers:
        declared_mounts = item.get("mounts")
        if declared_mounts is None or not item.get("included"):
            continue
        observed = inventory.containers.get(item["name"])
        if observed is None:
            continue
        observed_key = sorted(_mount_key(mount) for mount in (observed.get("mounts") or []))
        declared_key = sorted(_mount_key(mount) for mount in declared_mounts)
        if observed_key != declared_key:
            findings.append(
                Finding(
                    "E_INVENTORY_DRIFT",
                    "Container mounts differ from the approved manifest.",
                    resource=item["name"],
                    next_action="review_inventory",
                )
            )

    for volume in manifest.volumes:
        observed = inventory.volumes.get(volume["name"])
        if observed is None:
            findings.append(
                Finding(
                    "E_INVENTORY_DRIFT",
                    "A declared volume is missing on the host.",
                    resource="volume:%s" % volume["name"],
                    next_action="review_inventory",
                )
            )
            continue
        if observed.get("driver") not in (None, volume["driver"]):
            findings.append(
                Finding(
                    "E_UNSUPPORTED",
                    "A volume uses a driver other than the approved local driver.",
                    resource="volume:%s" % volume["name"],
                    next_action="review_volume_driver",
                )
            )
        observed_options = observed.get("options") or {}
        if observed_options != (volume.get("options") or {}):
            findings.append(
                Finding(
                    "E_INVENTORY_DRIFT",
                    "A volume has options that differ from the approved manifest.",
                    resource="volume:%s" % volume["name"],
                    next_action="review_inventory",
                )
            )

    # Image restorability (fail closed on local builds without a digest).
    for item in manifest.containers:
        if not item.get("included"):
            continue
        image = item["image"]
        if image["source"] == "local_build" and not image.get("repo_digest"):
            findings.append(
                Finding(
                    "E_IMAGE_NOT_RESTORABLE",
                    "An included container image is a local build without a repository digest.",
                    resource=item["name"],
                    next_action="publish_or_approve_reproduction",
                )
            )
        observed = inventory.containers.get(item["name"])
        if observed and image.get("repo_digest"):
            if image["repo_digest"] not in (observed.get("repo_digests") or []):
                findings.append(
                    Finding(
                        "E_INVENTORY_DRIFT",
                        "The running image digest differs from the approved manifest digest.",
                        resource=item["name"],
                        next_action="review_inventory",
                    )
                )

    # Certbot scheduler / hook conflicts (single shared rule set).
    certbot = manifest.certbot
    for item in SystemdFacts.certbot_conflicts(
        certbot,
        inventory.systemd.get("unit_files") or [],
        [],
        inventory.certbot.get("renewal_hooks") or {},
        bool(inventory.certbot.get("guard_present")),
        bool(inventory.certbot.get("guard_enabled")),
    ):
        findings.append(
            Finding(
                item["code"],
                item["message"],
                resource=item.get("resource"),
                next_action=item.get("next_action"),
            )
        )

    # Active HTTP-01 lease already in progress.
    if inventory.lease_active(int(certbot["max_lease_seconds"])):
        findings.append(
            Finding(
                "E_PRECONDITION",
                "An active Certbot HTTP-01 lease is present; backup must not start.",
                resource=certbot["lease_path"],
                next_action="wait_for_lease",
            )
        )


    # Containers that the manifest expects to run but are currently stopped.
    for item in manifest.containers:
        if item.get("included") and item.get("expected_state") == "running":
            if item["name"] in inventory.containers and not inventory.container_running(item["name"]):
                findings.append(
                    Finding(
                        "E_PRECONDITION",
                        "An included container is not running; it will not be started by the backup.",
                        resource=item["name"],
                        next_action="review_runtime_state",
                        blocking=False,
                    )
                )
    return DriftReport(findings)


def host_identity(inventory: Inventory, fingerprint: Optional[str]) -> Dict[str, Any]:
    return {
        "machine_id": inventory.machine_id,
        "host_key_fingerprint": fingerprint,
        "os_id": inventory.os.get("id"),
        "os_version": inventory.os.get("version_id"),
        "arch": inventory.arch,
    }
