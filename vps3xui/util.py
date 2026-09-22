"""Small shared primitives: safe identifiers, safe relative paths, atomic
durable writes, hashing and canonical JSON. Python 3.9+, standard library only.

The helpers here are deliberately conservative about the filesystem:

* directories are created one component at a time and never through a symlink;
* existing directories are not chmodded (that used to silently re-mode the
  repository root when a caller wrote ``./plan.json``);
* critical writes are exclusive, no-follow and fsync-failures are surfaced;
* reads that feed trust decisions use ``O_NOFOLLOW``.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import tempfile
from typing import Any, Iterable, List, Optional

from .errors import ToolError

# The small filesystem primitives live in ``coordination`` so the identical
# reviewed code is used in-package and when remote_ops is shipped standalone.
from .coordination import (  # noqa: E402  (re-exported shared primitives)
    DEFAULT_DIR_MODE,
    DEFAULT_FILE_MODE,
    atomic_write_bytes,
    bounded,
    create_exclusive,
    ensure_dir,
    is_symlink,
    owned_by_current_user,
    read_bytes_nofollow,
    require_private_dir,
    validate_id,
)

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

DEFAULT_DIR_MODE = 0o700
DEFAULT_FILE_MODE = 0o600

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)





def canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def json_digest(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj)).hexdigest()


def write_json(path: str, obj: Any, mode: int = DEFAULT_FILE_MODE) -> None:
    data = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    atomic_write_bytes(path, data, mode=mode)



def read_json(path: str, nofollow: bool = True) -> Any:
    if nofollow:
        return json.loads(read_bytes_nofollow(path).decode("utf-8"))
    with open(path, "rb") as handle:
        return json.loads(handle.read().decode("utf-8"))


def sha256_file(path: str, chunk_size: int = 1024 * 1024, nofollow: bool = False) -> str:
    digest = hashlib.sha256()
    if nofollow:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW)
        try:
            while True:
                block = os.read(fd, chunk_size)
                if not block:
                    break
                digest.update(block)
        finally:
            os.close(fd)
        return digest.hexdigest()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_is_symlink(path: str) -> bool:
    return is_symlink(path)



def dedupe(items: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def canonical_relpath(value: str) -> str:
    """Collapse ``//`` and ``./`` and reject traversal/absolute/NUL.

    Returns the canonical relative path (no leading ``./``, no empty parts).
    Unlike :func:`safe_relative_path` this also normalises, so ``a//./b`` and
    ``a/b`` compare equal.
    """
    if not isinstance(value, str) or value == "" or "\x00" in value:
        raise ToolError("E_UNSAFE_PATH", "Invalid path.", resource=str(value)[:80])
    if value.startswith("/") or value.startswith("\\"):
        raise ToolError("E_UNSAFE_PATH", "Absolute path rejected.", resource=value)
    if re.match(r"^[A-Za-z]:", value):
        raise ToolError("E_UNSAFE_PATH", "Drive-qualified path rejected.", resource=value)
    parts = []
    for part in value.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise ToolError("E_UNSAFE_PATH", "Path escapes its root.", resource=value)
        parts.append(part)
    if not parts:
        raise ToolError("E_UNSAFE_PATH", "Empty canonical path.", resource=value)
    return "/".join(parts)


def safe_relative_path(value: str, what: str = "path") -> str:
    """Validate a relative, non-escaping path for archive/sums membership.

    Kept as the legacy entry point; it shares :func:`canonical_relpath` rules
    but returns the original spelling so callers that need the literal name
    (for example a SHA256SUMS entry) keep it.
    """
    if not isinstance(value, str) or value == "":
        raise ToolError("E_UNSAFE_PATH", "Empty %s." % what, resource=what)
    if "\x00" in value:
        raise ToolError("E_UNSAFE_PATH", "NUL in %s." % what, resource=what)
    canonical_relpath(value)
    return value


def normalize_relpath(value: str) -> str:
    """Collapse ``./`` prefixes without allowing traversal."""
    while value.startswith("./"):
        value = value[2:]
    return value


def safe_tar_member(value: str, what: str = "path") -> str:
    """Validate a token that will be passed to GNU tar as a file-list entry.

    A leading ``-`` or an embedded ``=`` could be interpreted as an option
    (``--checkpoint-action=exec=...``); absolute/``..`` paths or NUL bytes are
    always refused. The caller must additionally pass ``--`` before the list.
    """
    if value in (".", "./"):
        return value
    if not isinstance(value, str) or value == "" or "\x00" in value:
        raise ToolError("E_UNSAFE_PATH", "Invalid %s for tar." % what, resource=str(value)[:80])
    if value.startswith("-") or value.startswith("\\") or value.startswith("/"):
        raise ToolError("E_UNSAFE_PATH", "%s may not start with '-' or a path separator." % what,
                        resource=value)
    if "=" in value or "\n" in value:
        raise ToolError("E_UNSAFE_PATH", "%s contains a disallowed character." % what, resource=value)
    canonical_relpath(value.lstrip("./"))
    return value
