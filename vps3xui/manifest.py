"""Typed inventory manifest: load, schema-validate and derive the required
artifact set. A manifest describes facts and typed paths only; it can never
carry executable commands or secret values.
"""

from __future__ import annotations

import os
import re as _re
from typing import Any, Dict, List, Optional

from . import jsonschema_lite
from .errors import ToolError
from .util import json_digest, read_json, safe_tar_member, validate_id

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SCHEMA_PATH = os.path.join(REPO_ROOT, "config", "manifest.schema.json")
EXAMPLE_MANIFEST_PATH = os.path.join(REPO_ROOT, "config", "manifest.example.json")
# Locations the reviewed automation is pinned against. They are part of the
# trust contract, not free-form manifest input.
RENEWAL_DIR = "/etc/letsencrypt/renewal"
SYSTEMD_ETC_DIR = "/etc/systemd/system"


class Manifest(object):
    def __init__(self, path: Optional[str], data: Dict[str, Any]):
        self.path = path
        self.data = data
        self.digest = json_digest(data)

    # -- identity ---------------------------------------------------------
    @property
    def manifest_id(self) -> str:
        return self.data["manifest_id"]

    @property
    def approved(self) -> bool:
        return bool(self.data.get("approved"))

    @property
    def ssh_alias(self) -> str:
        return self.data["source"]["ssh_alias"]

    @property
    def expected_machine_id(self) -> Optional[str]:
        return self.data["source"].get("expected_machine_id")

    @property
    def expected_host_key_fingerprint(self) -> Optional[str]:
        return self.data["source"].get("expected_host_key_fingerprint")

    # -- resource views ---------------------------------------------------
    @property
    def containers(self) -> List[Dict[str, Any]]:
        return list(self.data["containers"])

    def container(self, name: str) -> Optional[Dict[str, Any]]:
        for item in self.data["containers"]:
            if item["name"] == name:
                return item
        return None

    def included_running_containers(self) -> List[Dict[str, Any]]:
        items = [
            item
            for item in self.data["containers"]
            if item.get("included") and item.get("expected_state") == "running"
        ]
        return sorted(items, key=lambda item: (item["restart_order"], item["name"]))

    def included_stopped_containers(self) -> List[Dict[str, Any]]:
        return [
            item
            for item in self.data["containers"]
            if item.get("included") and item.get("expected_state") != "running"
        ]

    @property
    def volumes(self) -> List[Dict[str, Any]]:
        return list(self.data["volumes"])

    @property
    def bind_trees(self) -> List[Dict[str, Any]]:
        return list(self.data["bind_trees"])

    @property
    def writable_layers(self) -> List[Dict[str, Any]]:
        return list(self.data["writable_layers"])

    @property
    def reference_artifacts(self) -> List[Dict[str, Any]]:
        return list(self.data["reference_artifacts"])

    @property
    def metadata_artifacts(self) -> List[str]:
        return list(self.data["metadata_artifacts"])

    @property
    def certbot(self) -> Dict[str, Any]:
        return dict(self.data["certbot"])

    @property
    def pending_approval(self) -> List[Dict[str, Any]]:
        return list(self.data.get("pending_approval", []))

    @property
    def trusted_files(self) -> List[Dict[str, Any]]:
        return [dict(item) for item in self.data.get("trusted_files", [])]

    def trusted_file_paths(self) -> List[str]:
        return [item["path"] for item in self.trusted_files]

    def trusted_file_digest(self, path: str) -> Optional[str]:
        for item in self.trusted_files:
            if item["path"] == path:
                return item["sha256"]
        return None

    def renewal_file_path(self) -> str:
        return RENEWAL_DIR + "/" + self.certbot["lineage"] + ".conf"

    def required_trust_paths(self) -> List[str]:
        """The exact trust set an approved manifest must pin.

        Everything the reviewed automation depends on: the guard helper and its
        approval marker, the tool's cleanup units, the Certbot drop-in and the
        lineage renewal file. A subset trust contract must never approve a plan.
        """
        certbot = self.certbot
        paths = [
            certbot["guard_path"],
            certbot["guard_enabled_path"],
            certbot["dropin"],
            SYSTEMD_ETC_DIR + "/" + certbot["cleanup_service"],
            SYSTEMD_ETC_DIR + "/" + certbot["cleanup_timer"],
            self.renewal_file_path(),
        ]
        ordered: List[str] = []
        for path in paths:
            if path not in ordered:
                ordered.append(path)
        return ordered

    def required_hook_pins(self) -> List[str]:
        """Every permitted hook must be pinned for the lineage renewal file."""
        filename = self.renewal_file_path().rsplit("/", 1)[-1]
        return ["%s:%s" % (filename, key) for key in self.certbot["permitted_hooks"]]

    def pending_approval_names(self) -> List[str]:
        return [item["resource"] for item in self.pending_approval]

    # -- derived artifact sets -------------------------------------------
    def required_artifacts(self) -> List[str]:
        """Every immutable artifact a complete backup for this inventory needs.

        This is derived from the manifest, not from whatever a SHA256SUMS file
        happens to list, so a missing mandatory archive is caught.
        """
        names: List[str] = []
        for tree in self.bind_trees:
            names.append(tree["artifact"])
        for volume in self.volumes:
            names.append(volume["artifact"])
        for layer in self.writable_layers:
            names.append(layer["artifact"])
        for reference in self.reference_artifacts:
            names.extend(reference["artifacts"])
        names.append(self.certbot["artifact"])
        names.extend(self.metadata_artifacts)
        # stable, de-duplicated order
        seen = set()
        ordered: List[str] = []
        for name in names:
            if name not in seen:
                seen.add(name)
                ordered.append(name)
        return sorted(ordered)

    def artifact_owner(self, name: str) -> str:
        for tree in self.bind_trees:
            if tree["artifact"] == name:
                return tree["root"]
        for volume in self.volumes:
            if volume["artifact"] == name:
                return "volume:%s" % volume["name"]
        for layer in self.writable_layers:
            if layer["artifact"] == name:
                return "writable:%s%s" % (layer["container"], layer["path"])
        for reference in self.reference_artifacts:
            if name in reference["artifacts"]:
                return "reference:%s" % reference["source"]
        if name == self.certbot["artifact"]:
            return "certbot:%s" % self.certbot["lineage"]
        if name in self.metadata_artifacts:
            return "metadata"
        return "unknown"

    def sensitive_artifacts(self) -> List[str]:
        names: List[str] = []
        for tree in self.bind_trees:
            if tree.get("sensitive"):
                names.append(tree["artifact"])
        for volume in self.volumes:
            if volume.get("sensitive"):
                names.append(volume["artifact"])
        for layer in self.writable_layers:
            if layer.get("sensitive"):
                names.append(layer["artifact"])
        return sorted(set(names))

    def reference_only_artifacts(self) -> List[str]:
        names: List[str] = []
        for reference in self.reference_artifacts:
            if reference.get("never_apply"):
                names.extend(reference["artifacts"])
        return sorted(set(names))

    def volume_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        for volume in self.volumes:
            if volume["name"] == name:
                return volume
        return None

    def all_artifact_names(self) -> List[str]:
        extra = ["SHA256SUMS", "COMPLETE", "source-operation-report.json"]
        return self.required_artifacts() + extra


def load_schema(path: str = DEFAULT_SCHEMA_PATH) -> Dict[str, Any]:
    return read_json(path)


def from_object(data: Any, path: Optional[str] = None, schema_path: str = DEFAULT_SCHEMA_PATH) -> Manifest:
    if not isinstance(data, dict):
        raise ToolError("E_MANIFEST_INVALID", "Manifest root must be an object.")
    schema = load_schema(schema_path)
    try:
        jsonschema_lite.validate(data, schema)
    except jsonschema_lite.SchemaError as error:
        raise ToolError(
            "E_MANIFEST_INVALID",
            "Manifest does not match schema at %s." % error.path,
            resource=path or "manifest",
            next_action="fix_manifest",
        )
    manifest = Manifest(path, data)
    _validate_semantics(manifest)
    return manifest


def load(path: str, schema_path: str = DEFAULT_SCHEMA_PATH) -> Manifest:
    if not os.path.isfile(path):
        raise ToolError(
            "E_CONTRACT",
            "Manifest file not found.",
            resource=os.path.basename(path),
            next_action="pass_existing_manifest",
        )
    try:
        data = read_json(path)
    except ValueError:
        raise ToolError(
            "E_MANIFEST_INVALID",
            "Manifest is not valid JSON.",
            resource=os.path.basename(path),
            next_action="fix_manifest",
        )
    return from_object(data, path=path, schema_path=schema_path)


APPROVED_WRITABLE_LAYERS = {("3xui_app", "/etc/fail2ban"), ("3xui_app", "/var/lib/fail2ban")}
FIXED_CERTBOT = {"max_lease_seconds": 900, "cleanup_interval_seconds": 30}
_IMAGE_DIGEST_RE = _re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
_SHA256_RE = _re.compile(r"^[0-9a-f]{64}$")
_MODE_RE = _re.compile(r"^0[0-7]{3}$")


def raw_artifact_pairs(manifest: Manifest):
    """(artifact, owner) for every declared artifact before de-duplication."""
    for tree in manifest.bind_trees:
        yield tree["artifact"], "bind:%s" % tree["root"]
    for volume in manifest.volumes:
        yield volume["artifact"], "volume:%s" % volume["name"]
    for layer in manifest.writable_layers:
        yield layer["artifact"], "writable:%s%s" % (layer["container"], layer["path"])
    for reference in manifest.reference_artifacts:
        for name in reference["artifacts"]:
            yield name, "reference:%s" % reference["source"]
    yield manifest.certbot["artifact"], "certbot:%s" % manifest.certbot["lineage"]
    for name in manifest.metadata_artifacts:
        yield name, "metadata"


def _raw_artifact_pairs(manifest: Manifest):
    """Backwards-compatible alias for the pre-dedup artifact pairs."""
    return raw_artifact_pairs(manifest)


def normalized_path(path: str) -> str:
    """Absolute path with a single trailing slash rule and collapsed //."""
    path = str(path)
    while "//" in path:
        path = path.replace("//", "/")
    if len(path) > 1:
        path = path.rstrip("/")
    return path


def path_is_inside(path: str, root: str) -> bool:
    """True when ``path`` equals or is contained by the absolute ``root``."""
    path = normalized_path(path)
    root = normalized_path(root)
    if root == "/":
        return path.startswith("/")
    return path == root or path.startswith(root + "/")


def paths_overlap(first: str, second: str) -> bool:
    """True when one of two absolute paths contains the other."""
    return path_is_inside(first, second) or path_is_inside(second, first)


def _validate_semantics(manifest: Manifest) -> None:
    """Checks the schema cannot express: id safety, uniqueness, path sanity,
    scope limits and injection safety."""
    validate_id(manifest.manifest_id, "manifest_id")
    seen_containers = set()
    for container in manifest.containers:
        validate_id(container["name"], "container name")
        if container["name"] in seen_containers:
            raise ToolError("E_MANIFEST_INVALID", "Duplicate container name in manifest.",
                            resource=container["name"])
        seen_containers.add(container["name"])
        image = container["image"]
        if container.get("included"):
            digest = image.get("repo_digest")
            if image["source"] == "local_build" or not digest:
                raise ToolError(
                    "E_IMAGE_NOT_RESTORABLE",
                    "Included container has no repository digest.",
                    resource=container["name"], next_action="publish_or_approve_reproduction")
            if not _IMAGE_DIGEST_RE.match(digest):
                raise ToolError(
                    "E_IMAGE_NOT_RESTORABLE",
                    "Included container image digest is not a complete repository digest.",
                    resource=container["name"], next_action="fix_manifest")
            if not image.get("restorable"):
                raise ToolError("E_IMAGE_NOT_RESTORABLE",
                                "Included container image is not marked restorable.",
                                resource=container["name"], next_action="fix_manifest")

    # Artifact names must be safe and unique across *distinct* owners (checked
    # before de-duplication, so a collision cannot hide in the deduped list).
    seen_artifacts = {}
    for name, owner in _raw_artifact_pairs(manifest):
        if "/" in name or "\\" in name or name.startswith("."):
            raise ToolError("E_MANIFEST_INVALID", "Artifact name must be a bare filename.",
                            resource=name)
        validate_id(os.path.splitext(name)[0] or name, "artifact name")
        if name in seen_artifacts and seen_artifacts[name] != owner:
            raise ToolError("E_MANIFEST_INVALID", "Artifact name is used by more than one resource.",
                            resource=name)
        seen_artifacts[name] = owner

    declared_includes: List[str] = []
    for tree in manifest.bind_trees:
        if not tree["root"].startswith("/"):
            raise ToolError("E_MANIFEST_INVALID", "bind_trees.root must be absolute.")
        root = normalized_path(tree["root"])
        for include in tree["includes"]:
            safe_tar_member(include, "bind include")
            if include.startswith("var/lib/docker") or include.startswith("/var/lib/docker"):
                raise ToolError("E_MANIFEST_INVALID", "Docker data-root must not be archived.",
                                resource=include)
            include = include.rstrip("/")
            joined = (root + "/" + include.lstrip("/")) if root else "/" + include
            declared_includes.append(normalized_path(joined))
    # Two declared paths must never contain one another: the same bytes would be
    # archived twice and the restore owner would be ambiguous.
    for index, first in enumerate(declared_includes):
        for second in declared_includes[index + 1:]:
            if paths_overlap(first, second):
                raise ToolError(
                    "E_MANIFEST_INVALID",
                    "Two declared paths overlap; the archive scope is ambiguous.",
                    resource="%s ~ %s" % (first, second),
                    next_action="narrow_includes")
    for project in manifest.data["compose_projects"]:
        if not project["working_dir"].startswith("/"):
            raise ToolError("E_MANIFEST_INVALID", "compose working_dir must be absolute.")
    if manifest.data["ufw"].get("never_apply") is not True:
        raise ToolError("E_MANIFEST_INVALID", "UFW artifact must be marked never_apply.")
    for reference in manifest.reference_artifacts:
        if reference.get("never_apply") is not True:
            raise ToolError("E_MANIFEST_INVALID", "Reference artifacts must be marked never_apply.",
                            resource=reference["source"])
    if manifest.data.get("images", {}).get("archive_images") is not False:
        raise ToolError("E_MANIFEST_INVALID", "Docker images must never be archived.")
    # Writable layers are limited to the two approved Fail2ban paths.
    declared_layers = {(layer["container"], layer["path"]) for layer in manifest.writable_layers}
    if not declared_layers.issubset(APPROVED_WRITABLE_LAYERS):
        raise ToolError("E_MANIFEST_INVALID", "A writable layer is outside the approved Fail2ban paths.",
                        resource=str(sorted(declared_layers - APPROVED_WRITABLE_LAYERS)))
    # Volume options must be empty; no driver options are carried or applied.
    for volume in manifest.volumes:
        if volume.get("options"):
            raise ToolError("E_UNSUPPORTED", "A volume declares unsupported local driver options.",
                            resource="volume:%s" % volume["name"], next_action="remove_volume_options")
    # Certbot bounds are fixed, and the runtime lease must never be an artifact.
    certbot = manifest.certbot
    for key, expected in FIXED_CERTBOT.items():
        if int(certbot.get(key, -1)) != expected:
            raise ToolError("E_MANIFEST_INVALID", "Certbot %s must be %d." % (key, expected),
                            resource=certbot["lineage"])
    lease = certbot.get("lease_path")
    if lease in seen_artifacts:
        raise ToolError("E_MANIFEST_INVALID", "The Certbot runtime lease must not be archived.",
                        resource=lease)
    if lease:
        for include in declared_includes:
            if path_is_inside(lease, include):
                raise ToolError(
                    "E_MANIFEST_INVALID",
                    "The Certbot runtime lease is inside an archived path.",
                    resource=lease, next_action="narrow_includes")

    # Trusted-file fingerprints and exact hook-command pins. An *approved*
    # manifest must carry a non-empty trust contract; never fabricate hashes.
    trusted_paths = set()
    for item in manifest.trusted_files:
        path = item["path"]
        if path in trusted_paths:
            raise ToolError("E_MANIFEST_INVALID", "Duplicate trusted file path.",
                            resource=path)
        trusted_paths.add(path)
        if not _SHA256_RE.match(item["sha256"]):
            raise ToolError("E_MANIFEST_INVALID", "Trusted file digest is not a lowercase sha256.",
                            resource=path)
        for field in ("mode", "uid", "gid"):
            if item.get(field) is None:
                continue
            value = item[field]
            if field == "mode":
                if not isinstance(value, str) or not _MODE_RE.match(value):
                    raise ToolError("E_MANIFEST_INVALID",
                                    "A trusted file mode must be an octal string like '0755'.",
                                    resource=path)
            elif not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ToolError("E_MANIFEST_INVALID",
                                "A trusted file %s must be a non-negative integer." % field,
                                resource=path)
    hook_pins = certbot.get("hook_fingerprints") or {}
    permitted = set(certbot.get("permitted_hooks") or [])
    for key, digest in hook_pins.items():
        _filename, _, hook_key = key.partition(":")
        if not _filename or hook_key not in permitted:
            raise ToolError("E_MANIFEST_INVALID",
                            "Hook fingerprint keys must be 'renewal-file:hook_key' for a permitted hook.",
                            resource=key)
        if not _SHA256_RE.match(digest):
            raise ToolError("E_MANIFEST_INVALID", "Hook fingerprint is not a lowercase sha256.",
                            resource=key)
    for directory in certbot.get("renewal_hook_dirs") or []:
        if not directory.startswith("/"):
            raise ToolError("E_MANIFEST_INVALID", "renewal_hook_dirs entries must be absolute.",
                            resource=directory)
    if manifest.approved:
        if manifest.pending_approval:
            raise ToolError("E_MANIFEST_INVALID",
                            "An approved manifest must not keep resources pending approval.",
                            resource=manifest.manifest_id, next_action="resolve_pending")
        if not manifest.trusted_files:
            raise ToolError("E_MANIFEST_INVALID",
                            "An approved manifest must pin trusted file fingerprints.",
                            resource=manifest.manifest_id, next_action="add_trusted_files")
        # A *subset* trust contract must never approve a plan: the guard helper,
        # its marker, the cleanup units, the drop-in and the lineage renewal file
        # are all required pins.
        missing = [path for path in manifest.required_trust_paths()
                   if path not in trusted_paths]
        if missing:
            raise ToolError(
                "E_MANIFEST_INVALID",
                "An approved manifest must pin the full required trust set.",
                resource=",".join(sorted(missing)), next_action="rebuild_trust_contract")
        if not (certbot.get("renewal_hook_dirs") or []):
            raise ToolError(
                "E_MANIFEST_INVALID",
                "An approved manifest must declare its Certbot renewal hook directories.",
                resource=certbot["lineage"], next_action="probe_hook_dirs")
        planned_hooks = manifest.required_hook_pins()
        unpinned = [key for key in planned_hooks if key not in hook_pins]
        if unpinned:
            raise ToolError(
                "E_MANIFEST_INVALID",
                "An approved manifest must pin every permitted Certbot hook.",
                resource=",".join(sorted(unpinned)), next_action="pin_renewal_hooks")
        # Permission pins are machine-bound: the privileged guard helper must
        # carry an exact mode, owner and group, not merely a content hash.
        guard_pin = None
        for item in manifest.trusted_files:
            if item["path"] == certbot["guard_path"]:
                guard_pin = item
        for field in ("mode", "uid", "gid"):
            if guard_pin is None or guard_pin.get(field) is None:
                raise ToolError(
                    "E_MANIFEST_INVALID",
                    "An approved manifest must pin the guard helper's mode, uid and gid.",
                    resource=certbot["guard_path"], next_action="pin_guard_permissions")
