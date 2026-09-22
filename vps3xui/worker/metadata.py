"""Versioned backup metadata (``images.json`` and ``backup.json``).

Metadata never contains secret values: image references/digests, the manifest
identity, exclusions and the recorded source operation state only.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .. import TOOL_VERSION


def build_images_json(manifest, captured_at: str) -> Dict[str, Any]:
    images: List[Dict[str, Any]] = []
    for container in manifest.containers:
        if not container.get("included"):
            continue
        images.append(
            {
                "container": container["name"],
                "compose_project": container["compose_project"],
                "service": container["service"],
                "repository_digest": container["image"].get("repo_digest"),
                "image_reference": container["image"].get("reference"),
            }
        )
    return {
        "schema_version": 1,
        "captured_at": captured_at,
        "archive_images": False,
        "policy": manifest.data["images"]["policy"],
        "images": images,
    }


def build_backup_json(
    manifest,
    backup_id: str,
    initial_state: Dict[str, Any],
    created_at: str,
    platform_info: Dict[str, str],
) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "backup_id": backup_id,
        "tool_version": TOOL_VERSION,
        "manifest_id": manifest.manifest_id,
        "manifest_digest": manifest.digest,
        "created_at": created_at,
        "platform": platform_info,
        "required_artifacts": manifest.required_artifacts(),
        "exclusions": list(manifest.data["exclusions"]),
        "reference_only_artifacts": manifest.reference_only_artifacts(),
        "source_operation": {"state": "copy_complete"},
        "original_containers": initial_state.get("stop_containers"),
    }
