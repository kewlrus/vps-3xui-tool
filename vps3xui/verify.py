"""Portable backup verification.

Verification checks the *exact* set of required files derived from the manifest
plus the hashed source report, never merely "every listed hash matched". It
reads every trust-relevant file with ``O_NOFOLLOW``, rejects any extra or
unlisted file (dotfiles included), and requires the archive membership to cover
every declared bind tree rather than only forbidding unsafe members.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from .adapters import archive as archive_adapter
from .errors import ToolError
from .util import bounded, is_symlink, read_bytes_nofollow, sha256_file

SUMS_NAME = "SHA256SUMS"
COMPLETE_NAME = "COMPLETE"
REPORT_NAME = "source-operation-report.json"
ALLOWED_EXTRA = {SUMS_NAME, COMPLETE_NAME}

_SUMS_RE = re.compile(r"^([0-9a-f]{64}) [ *](.+)$")


class VerifyResult(object):
    def __init__(self) -> None:
        self.ok = True
        self.error: Optional[ToolError] = None
        self.checked: List[Dict[str, Any]] = []
        self.present: List[str] = []
        self.missing: List[str] = []
        self.mismatched: List[str] = []
        self.extra: List[str] = []
        self.total_bytes = 0

    def fail(self, error: ToolError) -> "VerifyResult":
        self.ok = False
        if self.error is None:
            self.error = error
        return self

    def to_object(self, include_checks: bool = False) -> Dict[str, Any]:
        obj: Dict[str, Any] = {
            "ok": self.ok,
            "present": self.present,
            "missing": self.missing,
            "mismatched": self.mismatched,
            "extra": self.extra,
            "total_bytes": self.total_bytes,
            "error": self.error.to_error_object() if self.error else None,
        }
        if include_checks:
            # Hashes of (possibly sensitive) artifacts stay out of ordinary CLI
            # output; they are available to explicit diagnostic callers only.
            obj["checks"] = self.checked
        return obj


def parse_sums_text(text: str) -> List[Tuple[str, str]]:
    entries: List[Tuple[str, str]] = []
    seen = set()
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        match = _SUMS_RE.match(line)
        if not match:
            raise ToolError("E_SUMS_INVALID", "SHA256SUMS contains a malformed line.",
                            resource=SUMS_NAME, next_action="reject_backup")
        digest, name = match.group(1), match.group(2)
        if name in (SUMS_NAME, COMPLETE_NAME):
            raise ToolError("E_SUMS_INVALID", "SHA256SUMS must not cover itself or the marker.",
                            resource=name, next_action="reject_backup")
        try:
            archive_adapter.canonical_relpath(name)
        except ToolError:
            raise ToolError("E_SUMS_INVALID", "SHA256SUMS contains an unsafe path.",
                            resource=bounded(name, 80), next_action="reject_backup")
        if name in seen:
            raise ToolError("E_SUMS_INVALID", "SHA256SUMS contains a duplicate entry.",
                            resource=name, next_action="reject_backup")
        seen.add(name)
        entries.append((digest, name))
    if not entries:
        raise ToolError("E_SUMS_INVALID", "SHA256SUMS is empty.",
                        resource=SUMS_NAME, next_action="reject_backup")
    return entries


def parse_sums_file(path: str) -> List[Tuple[str, str]]:
    if is_symlink(path) or not os.path.isfile(path):
        raise ToolError("E_MISSING_ARTIFACT", "SHA256SUMS is missing.",
                        resource=SUMS_NAME, next_action="reject_backup")
    try:
        text = read_bytes_nofollow(path).decode("utf-8")
    except ToolError:
        raise
    except (OSError, UnicodeDecodeError):
        raise ToolError("E_SUMS_INVALID", "SHA256SUMS is unreadable.",
                        resource=SUMS_NAME, next_action="reject_backup")
    return parse_sums_text(text)


def required_sums_names(manifest) -> List[str]:
    """The exact set SHA256SUMS must cover: artifacts plus the source report."""
    return sorted(set(manifest.required_artifacts()) | {REPORT_NAME})


def build_sums(backup_dir: str, names: List[str]) -> bytes:
    lines = []
    for name in sorted(names):
        path = os.path.join(backup_dir, name)
        if is_symlink(path) or not os.path.isfile(path):
            raise ToolError("E_MISSING_ARTIFACT", "Required artifact is missing before sums.",
                            resource=name, next_action="inspect_backup")
        lines.append("%s  %s" % (sha256_file(path, nofollow=True), name))
    return ("\n".join(lines) + "\n").encode("utf-8")


def _declared_includes(manifest, name: str) -> Optional[List[str]]:
    for tree in manifest.bind_trees:
        if tree["artifact"] == name:
            root = tree["root"].rstrip("/")
            return [
                ((root + "/" + include) if root else "/" + include).strip("/")
                for include in tree["includes"]
            ]
    return None


def _check_membership(manifest, name: str, report: archive_adapter.TarReport) -> None:
    declared = _declared_includes(manifest, name)
    if declared is None:
        return
    member_names = [member["name"] for member in report.members]
    if not member_names:
        raise ToolError("E_UNSAFE_ARCHIVE", "Archive is empty; it cannot contain the declared tree.",
                        resource=name, next_action="reject_archive")
    for member_name in member_names:
        if not any(member_name == item or member_name.startswith(item + "/") for item in declared):
            raise ToolError("E_UNSAFE_ARCHIVE", "Archive member is outside the declared include set.",
                            resource="%s:%s" % (name, member_name), next_action="reject_archive")
    for include in declared:
        if not any(item == include or item.startswith(include + "/") for item in member_names):
            raise ToolError("E_UNSAFE_ARCHIVE",
                            "Archive does not cover a declared include path.",
                            resource="%s:%s" % (name, include), next_action="reject_archive")


def _check_report(backup_dir: str, manifest) -> None:
    path = os.path.join(backup_dir, REPORT_NAME)
    if is_symlink(path) or not os.path.isfile(path):
        raise ToolError("E_MISSING_ARTIFACT", "The source operation report is missing.",
                        resource=REPORT_NAME, next_action="reject_backup")
    import json

    try:
        report = json.loads(read_bytes_nofollow(path).decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        raise ToolError("E_VERIFY_FAILED", "The source operation report is not valid JSON.",
                        resource=REPORT_NAME, next_action="reject_backup")
    if not isinstance(report, dict):
        raise ToolError("E_VERIFY_FAILED", "The source operation report is malformed.",
                        resource=REPORT_NAME, next_action="reject_backup")
    if report.get("manifest_id") != manifest.manifest_id:
        raise ToolError("E_VERIFY_FAILED", "The source operation report names a different manifest.",
                        resource=REPORT_NAME, next_action="reject_backup")
    if report.get("state") not in ("copied", "succeeded"):
        raise ToolError("E_VERIFY_FAILED", "The source operation report does not describe a good copy.",
                        resource=REPORT_NAME, next_action="reject_backup")
    if report.get("data_integrity") != "verified":
        raise ToolError("E_VERIFY_FAILED", "The source operation report does not claim verified data.",
                        resource=REPORT_NAME, next_action="reject_backup")
    # A retained first cause or a failed runtime recovery is contradictory
    # completion evidence: a copied ``state`` alone must never make a backup
    # verifiable, since the report may have been carried over from a run whose
    # source recovery did not complete.
    if report.get("original_failure") is not None:
        raise ToolError("E_VERIFY_FAILED",
                        "The source operation report retains a first failure; the copy is not a "
                        "proven success.",
                        resource=REPORT_NAME, next_action="inspect_source_job")
    if report.get("source_runtime_recovery") == "failed":
        raise ToolError("E_VERIFY_FAILED",
                        "The source operation report records a failed runtime recovery.",
                        resource=REPORT_NAME, next_action="inspect_source_job")


def _check_metadata(backup_dir: str, manifest) -> None:
    """Validate the versioned metadata artifacts against the manifest.

    Metadata must declare a supported schema version, agree with the manifest
    identity and required-artifact set, and (for images.json) record exactly the
    approved repository digests. No metadata secret values are read or printed.
    """
    for name in manifest.metadata_artifacts:
        path = os.path.join(backup_dir, name)
        if is_symlink(path) or not os.path.isfile(path):
            raise ToolError("E_MISSING_ARTIFACT", "Backup metadata is missing.",
                            resource=name, next_action="reject_backup")
        try:
            data = json.loads(read_bytes_nofollow(path).decode("utf-8"))
        except (OSError, UnicodeDecodeError, ValueError):
            raise ToolError("E_VERIFY_FAILED", "Backup metadata is not valid JSON.",
                            resource=name, next_action="reject_backup")
        if not isinstance(data, dict):
            raise ToolError("E_VERIFY_FAILED", "Backup metadata must be an object.",
                            resource=name, next_action="reject_backup")
        if data.get("schema_version") != 1:
            raise ToolError("E_VERIFY_FAILED", "Backup metadata has an unsupported schema version.",
                            resource=name, next_action="reject_backup")
        if "manifest_id" in data and data["manifest_id"] != manifest.manifest_id:
            raise ToolError("E_VERIFY_FAILED", "Backup metadata names a different manifest.",
                            resource=name, next_action="reject_backup")
        if "manifest_digest" in data and data["manifest_digest"] != manifest.digest:
            raise ToolError("E_VERIFY_FAILED", "Backup metadata has a different manifest digest.",
                            resource=name, next_action="reject_backup")
        if "required_artifacts" in data and list(data["required_artifacts"]) != manifest.required_artifacts():
            raise ToolError("E_VERIFY_FAILED", "Backup metadata lists a different required-artifact set.",
                            resource=name, next_action="reject_backup")
        if name == "images.json":
            if data.get("archive_images") is not False:
                raise ToolError("E_VERIFY_FAILED", "images.json does not forbid image archival.",
                                resource=name, next_action="reject_backup")
            expected = {
                container["name"]: container["image"].get("repo_digest")
                for container in manifest.containers if container.get("included")
            }
            observed = {
                item.get("container"): item.get("repository_digest")
                for item in (data.get("images") or [])
            }
            if observed != expected:
                raise ToolError("E_VERIFY_FAILED",
                                "images.json does not record the approved repository digests.",
                                resource=name, next_action="reject_backup")


def verify_directory(
    backup_dir: str,
    manifest,
    require_complete: bool = True,
    validate_archives: bool = True,
) -> VerifyResult:
    result = VerifyResult()
    if is_symlink(backup_dir) or not os.path.isdir(backup_dir):
        return result.fail(
            ToolError("E_CONTRACT", "Backup directory does not exist.",
                      resource=os.path.basename(backup_dir))
        )

    try:
        entries = parse_sums_file(os.path.join(backup_dir, SUMS_NAME))
    except ToolError as error:
        return result.fail(error)
    listed = {name: digest for digest, name in entries}
    required = required_sums_names(manifest)
    result.present = required

    # Exact hash set: no missing artifact, no arbitrary listed extra.
    for name in required:
        if name not in listed:
            result.missing.append(name)
    if sorted(listed) != required:
        for name in listed:
            if name not in required:
                result.extra.append(name)
    if result.missing:
        return result.fail(
            ToolError("E_MISSING_ARTIFACT", "A required artifact is not covered by SHA256SUMS.",
                      resource=result.missing[0], next_action="reject_backup")
        )
    if result.extra:
        return result.fail(
            ToolError("E_VERIFY_FAILED", "SHA256SUMS covers an unrequired entry.",
                      resource=result.extra[0], next_action="reject_backup")
        )

    for name in required:
        path = os.path.join(backup_dir, name)
        if is_symlink(path) or not os.path.isfile(path):
            result.missing.append(name)
            continue
        try:
            actual = sha256_file(path, nofollow=True)
        except OSError:
            return result.fail(ToolError("E_VERIFY_FAILED", "Artifact could not be read.",
                                         resource=name, next_action="reject_backup"))
        result.total_bytes += os.path.getsize(path)
        if actual != listed[name]:
            result.mismatched.append(name)
        result.checked.append({"artifact": name, "sha256": actual})
    if result.missing:
        return result.fail(
            ToolError("E_MISSING_ARTIFACT", "An artifact listed in SHA256SUMS is missing.",
                      resource=result.missing[0], next_action="reject_backup")
        )
    if result.mismatched:
        return result.fail(
            ToolError("E_HASH_MISMATCH", "An artifact hash does not match SHA256SUMS.",
                      resource=result.mismatched[0], next_action="reject_backup")
        )

    try:
        # The directory must contain exactly the required set plus the marker;
        # dotfiles and ``.tmp-*`` are NOT silently ignored.
        allowed_names = set(required) | ALLOWED_EXTRA
        for name in sorted(os.listdir(backup_dir)):
            if name in allowed_names:
                continue
            result.extra.append(name)
        if result.extra:
            raise ToolError("E_VERIFY_FAILED",
                            "Backup directory contains files not covered by SHA256SUMS.",
                            resource=result.extra[0], next_action="review_backup")
        _check_report(backup_dir, manifest)
        _check_metadata(backup_dir, manifest)
        if require_complete:
            complete = os.path.join(backup_dir, COMPLETE_NAME)
            if is_symlink(complete) or not os.path.isfile(complete) or os.path.getsize(complete) == 0:
                raise ToolError("E_VERIFY_FAILED",
                                "COMPLETE marker is absent; the copy is partial.",
                                resource=COMPLETE_NAME, next_action="inspect_source_job")
        if validate_archives:
            for _digest, name in entries:
                if not name.endswith(".tar"):
                    continue
                roots = _declared_includes(manifest, name)
                report = archive_adapter.validate_tar(os.path.join(backup_dir, name), roots=roots)
                _check_membership(manifest, name, report)
                result.checked.append(
                    {"artifact": name, "members": len(report.members), "tar": "safe"}
                )
    except ToolError as error:
        return result.fail(error)

    return result
