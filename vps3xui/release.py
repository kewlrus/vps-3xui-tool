"""Build the pinned release archive delivered to the host.

The release contains the runtime package, the schema/config, the entry-point
wrappers and the approved manifest. It is written with fixed metadata so the
same inputs produce the same digest, and the digest is verified on delivery.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import tarfile
from typing import List, Optional

from . import TOOL_VERSION
from .manifest import REPO_ROOT

RELEASE_MANIFEST_NAME = "manifest.json"
RELEASE_VERSION_FILE = "RELEASE"

PACKAGE_FILES = [
    "__init__.py",
    "cli.py",
    "coordination.py",
    "errors.py",
    "hostops.py",
    "inventory.py",
    "jobs.py",
    "jsonschema_lite.py",
    "manifest.py",
    "plan.py",
    "probe.py",
    "remote_ops.py",
    "remote_verify.py",
    "release.py",
    "util.py",
    "verify.py",
    "backup.py",
]

ADAPTER_FILES = ["__init__.py", "ssh.py", "archive.py", "docker.py", "systemd.py"]
WORKER_FILES = [
    "__init__.py",
    "jobctx.py",
    "failure_journal.py",
    "backup_worker.py",
    "finalizer.py",
    "metadata.py",
    "system.py",
]
BIN_FILES = ["vps3xui-worker", "vps3xui-finalizer"]
CONFIG_FILES = ["manifest.schema.json"]


def _candidate_paths() -> List[str]:
    paths = []
    for name in PACKAGE_FILES:
        candidate = os.path.join(REPO_ROOT, "vps3xui", name)
        if os.path.isfile(candidate):
            paths.append(candidate)
    for name in ADAPTER_FILES:
        candidate = os.path.join(REPO_ROOT, "vps3xui", "adapters", name)
        if os.path.isfile(candidate):
            paths.append(candidate)
    for name in WORKER_FILES:
        candidate = os.path.join(REPO_ROOT, "vps3xui", "worker", name)
        if os.path.isfile(candidate):
            paths.append(candidate)
    for name in BIN_FILES:
        candidate = os.path.join(REPO_ROOT, "bin", name)
        if os.path.isfile(candidate):
            paths.append(candidate)
    for name in CONFIG_FILES:
        candidate = os.path.join(REPO_ROOT, "config", name)
        if os.path.isfile(candidate):
            paths.append(candidate)
    return paths


def build_release_archive(manifest, extra_files: Optional[List[str]] = None) -> bytes:
    raw = io.BytesIO()
    # Deterministic gzip: fixed mtime and no embedded filename, so identical
    # inputs always produce identical bytes (and therefore one digest).
    with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path in _candidate_paths() + list(extra_files or []):
                arcname = os.path.relpath(path, REPO_ROOT)
                info = archive.gettarinfo(path, arcname=arcname)
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                info.mtime = 0
                info.mode = 0o644
                if arcname.startswith("bin/"):
                    info.mode = 0o755
                with open(path, "rb") as handle:
                    archive.addfile(info, handle)
            import json

            payload = (
                json.dumps(manifest.data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
            ).encode("utf-8")
            info = tarfile.TarInfo(RELEASE_MANIFEST_NAME)
            info.size = len(payload)
            info.mode = 0o600
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))
            version = ("%s\n" % TOOL_VERSION).encode("utf-8")
            info = tarfile.TarInfo(RELEASE_VERSION_FILE)
            info.size = len(version)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(version))
    return raw.getvalue()


def release_archive_digest(archive: bytes) -> str:
    return hashlib.sha256(archive).hexdigest()


def content_addressed_release_dir(version: str, digest: str) -> str:
    """Immutable, content-addressed release path (never reused/replaced)."""
    return "/opt/vps3xui/releases/%s-%s" % (version, digest[:16])


def archive_file_hashes(archive: bytes) -> dict:
    """Map arcname -> sha256 for every regular file in a release archive."""
    result = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as tar:
        for member in tar:
            if not member.isfile():
                continue
            handle = tar.extractfile(member)
            digest = hashlib.sha256()
            if handle is not None:
                while True:
                    block = handle.read(1024 * 1024)
                    if not block:
                        break
                    digest.update(block)
            result[member.name] = digest.hexdigest()
    return result
