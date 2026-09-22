"""Archive creation, strict validation and safe extraction.

Validation builds a bounded canonical member/link graph *before* any
extraction. It rejects traversal, absolute paths, duplicates, device/special
files, setuid/setgid bits, unsupported types and dangerous PAX records, and it
resolves symlink chains so an escaping or cyclic link is refused. Legitimate
Let's Encrypt relative links (``live/x -> ../../archive/x/...``) are kept, and
links must resolve inside the declared tree, not merely the archive root.

Extraction (``safe_extract``) prefers GNU tar so numeric ownership and ACL/xattr
metadata survive; the Python fallback still applies validated numeric ownership
and extended attributes where the platform supports it.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tarfile
from typing import Any, Dict, List, Optional, Tuple

from ..errors import ToolError

DEFAULT_MAX_MEMBERS = 500000
DEFAULT_MAX_TOTAL_BYTES = 200 * 1024 * 1024 * 1024
_MAX_LINK_DEPTH = 40

_DANGEROUS_XATTR_PREFIXES = ("security.", "trusted.", "system.")
_ALLOWED_XATTRS = ("security.selinux",)
# PAX keys that tarfile handles itself or that we accept as inert metadata.
_ALLOWED_PAX_KEYS = {
    "path", "linkpath", "size", "uid", "gid", "uname", "gname", "mtime",
    "atime", "ctime",
}
_ALLOWED_PAX_PREFIXES = ("SCHILY.xattr.", "SCHILY.acl.", "LIBARCHIVE.xattr.", "LIBARCHIVE.acl.")

_TEXT_TYPES = {
    tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE,
}
_DIRECTORY_TYPES = {tarfile.DIRTYPE}
_REGULAR_TYPES = {tarfile.REGTYPE, tarfile.AREGTYPE}
_SYMLINK_TYPES = {tarfile.SYMTYPE}
_HARDLINK_TYPES = {tarfile.LNKTYPE}
# GNU long-name/long-link pseudo members carry only metadata and are resolved
# into the following member by tarfile before it is handed to us.
_GNU_META_TYPES = {b"L", b"K"}


class TarReport(object):
    def __init__(self, members: List[Dict[str, Any]], total_size: int):
        self.members = members
        self.total_size = total_size

    def to_object(self) -> Dict[str, Any]:
        return {"member_count": len(self.members), "total_size": self.total_size}


def _fail(message: str, resource: Optional[str] = None) -> None:
    raise ToolError("E_UNSAFE_ARCHIVE", message, resource=resource, next_action="reject_archive")


def _check_xattrs(member: tarfile.TarInfo) -> None:
    for key in (member.pax_headers or {}):
        attr = None
        for prefix in ("SCHILY.xattr.", "LIBARCHIVE.xattr."):
            if key.startswith(prefix):
                attr = key[len(prefix):]
                break
        if attr is None:
            continue
        if attr in _ALLOWED_XATTRS:
            continue
        for prefix in _DANGEROUS_XATTR_PREFIXES:
            if attr.startswith(prefix):
                _fail("Archive member carries a disallowed extended attribute.", member.name)
        if key.startswith("LIBARCHIVE.xattr."):
            # LIBARCHIVE xattrs are only ever accepted for the reviewed allowlist.
            _fail("Archive member carries an unsupported LIBARCHIVE extended attribute.", member.name)


def _check_pax(member: tarfile.TarInfo) -> None:
    for key in (member.pax_headers or {}):
        if key in _ALLOWED_PAX_KEYS:
            continue
        if key.startswith("GNU.sparse.") or key == "GNU.sparse.major":
            _fail("Archive member uses an unsupported sparse record.", member.name)
        if any(key.startswith(prefix) for prefix in _ALLOWED_PAX_PREFIXES):
            continue
        _fail("Archive member carries an unsupported PAX header.", member.name)


def canonical_relpath(name: str) -> str:
    """Collapse ``//``, ``./`` and reject traversal/absolute/NUL."""
    if not isinstance(name, str) or "\x00" in name:
        _fail("Archive member name is invalid.")
    if name.startswith("/") or name.startswith("\\"):
        _fail("Archive contains an absolute member path.", name)
    if len(name) > 4096:
        _fail("Archive member path is too long.")
    parts = []
    for part in name.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            _fail("Archive member path escapes its root.", name)
        parts.append(part)
    return "/".join(parts)


def _resolve_link(member_name: str, linkname: str, roots: Optional[List[str]],
                  nodes: Optional[Dict[str, Dict[str, Any]]] = None) -> str:
    """Resolve a link target component-by-component.

    Symlink components are expanded *before* ``..`` is normalised, so
    ``b -> a/x`` where ``a`` is itself a link to ``../outside`` is refused
    instead of being textually collapsed into a safe-looking path.
    """
    if linkname.startswith("/") or linkname.startswith("\\"):
        _fail("Archive contains an absolute link target.", member_name)
    resolved: List[str] = [part for part in os.path.dirname(member_name).split("/") if part]
    stack = [part for part in linkname.split("/")]
    seen = set()
    depth = 0
    while stack:
        part = stack.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            if not resolved:
                _fail("Archive link target escapes the extraction root.", member_name)
            resolved.pop()
            continue
        resolved.append(part)
        current = "/".join(resolved)
        node = nodes.get(current) if nodes else None
        if node is not None and node["type"] == "symlink":
            if current in seen or depth > _MAX_LINK_DEPTH:
                _fail("Archive contains a symlink cycle.", member_name)
            seen.add(current)
            depth += 1
            resolved.pop()
            stack = [tok for tok in node["linkname"].split("/")] + stack
    joined = "/".join(resolved)
    if joined == ".." or joined.startswith("../") or os.path.isabs(joined):
        _fail("Archive link target escapes the extraction root.", member_name)
    if roots and joined:
        if not any(joined == root or joined.startswith(root + "/") for root in roots):
            _fail("Archive link target leaves the declared tree.", member_name)
    return joined


def _normalize_root(root: str) -> str:
    return canonical_relpath(root) if root not in ("", ".") else ""


def validate_tar(
    path: str,
    max_members: int = DEFAULT_MAX_MEMBERS,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    roots: Optional[List[str]] = None,
) -> TarReport:
    """Build and check the canonical member/link graph of a tar archive."""
    if not os.path.isfile(path) or os.path.islink(path):
        raise ToolError("E_MISSING_ARTIFACT", "Archive file is missing.",
                        resource=os.path.basename(path))
    decl_roots = [_normalize_root(root) for root in (roots or [])]
    decl_roots = [root for root in decl_roots if root]

    members: List[Dict[str, Any]] = []
    nodes: Dict[str, Dict[str, Any]] = {}
    total_size = 0
    try:
        with tarfile.open(path, "r:*") as archive:
            for member in archive:
                if len(nodes) >= max_members:
                    _fail("Archive has too many members.", os.path.basename(path))
                if member.type in _GNU_META_TYPES:
                    continue
                name = canonical_relpath(member.name)
                _check_xattrs(member)
                _check_pax(member)
                if member.type not in _TEXT_TYPES:
                    _fail("Archive contains an unsupported member type.", member.name)
                is_meta = (
                    member.type == tarfile.DIRTYPE
                    and (member.name.endswith("/") or name in decl_roots or name == "")
                )
                if member.type == tarfile.DIRTYPE and name == "":
                    # A bare root entry is allowed but is still validated: it
                    # must not carry setuid/setgid bits or a payload, and its
                    # metadata is never applied to the extraction root.
                    if member.mode & (stat.S_ISUID | stat.S_ISGID):
                        _fail("Archive root entry has setuid/setgid bits.", member.name)
                    if member.size:
                        _fail("Archive root entry declares a payload.", member.name)
                    continue
                if name == "":
                    _fail("Archive contains an empty member name.", member.name)
                if name in nodes:
                    _fail("Archive contains a duplicate member.", name)
                mode = member.mode
                if mode & (stat.S_ISUID | stat.S_ISGID):
                    _fail("Archive member has setuid/setgid bits.", name)
                nodes[name] = {
                    "type": "dir" if member.type in _DIRECTORY_TYPES else
                            "symlink" if member.type in _SYMLINK_TYPES else
                            "hardlink" if member.type in _HARDLINK_TYPES else "file",
                    "linkname": member.linkname,
                    "size": member.size,
                    "mode": mode,
                    "uid": member.uid,
                    "gid": member.gid,
                }
                if member.type in _REGULAR_TYPES:
                    total_size += member.size
                    if total_size > max_total_bytes:
                        _fail("Archive exceeds the maximum uncompressed size.", os.path.basename(path))

            # Resolve symlink/hardlink targets against the canonical graph.
            for name, info in sorted(nodes.items()):
                if info["type"] == "symlink":
                    info["resolved"] = _resolve_link(name, info["linkname"], decl_roots, nodes)
                elif info["type"] == "hardlink":
                    target = _normalize_link_target(info["linkname"])
                    _resolve_link(name, info["linkname"], decl_roots, nodes)
                    node = nodes.get(target)
                    if node is None:
                        _fail("Archive hard link points to an unknown member.", name)
                    if node["type"] != "file":
                        _fail("Archive hard link must point to a regular file.", name)
                    info["resolved"] = target

            # No member may be written through a symlink ancestor.
            for name in nodes:
                parent = os.path.dirname(name)
                while parent:
                    if parent in nodes and nodes[parent]["type"] == "symlink":
                        _fail("Archive writes through a symlink ancestor.", name)
                    parent = os.path.dirname(parent)

            for name, info in nodes.items():
                members.append({
                    "name": name,
                    "type": info["type"],
                    "size": info["size"],
                    "mode": info["mode"],
                })
    except tarfile.TarError:
        raise ToolError("E_UNSAFE_ARCHIVE", "Archive cannot be parsed as a tar file.",
                        resource=os.path.basename(path), next_action="reject_archive")
    return TarReport(members, total_size)


def _normalize_link_target(linkname: str) -> str:
    return canonical_relpath(linkname)


def _gnu_tar_available() -> bool:
    try:
        proc = subprocess.run(["tar", "--version"], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0 and b"GNU tar" in proc.stdout


def safe_extract(tar_path: str, dest_dir: str, roots: Optional[List[str]] = None) -> TarReport:
    """Validate, then extract into a fresh private directory (no symlinks followed)."""
    from .. import coordination as coord

    report = validate_tar(tar_path, roots=roots)
    dest_dir = os.path.abspath(dest_dir)
    if os.path.islink(dest_dir):
        _fail("Extraction destination is a symlink.", os.path.basename(dest_dir))
    if os.path.exists(dest_dir) and os.listdir(dest_dir):
        raise ToolError("E_PRECONDITION", "Extraction directory is not empty.",
                        resource=os.path.basename(dest_dir), next_action="use_fresh_directory")
    unsafe = coord.symlink_ancestors(os.path.join(dest_dir, ".probe"))
    if unsafe:
        _fail("Extraction destination has a symlink component.",
              os.path.basename(unsafe[0]))
    os.makedirs(dest_dir, mode=0o700, exist_ok=True)
    if _gnu_tar_available():
        argv = [
            "tar", "--numeric-owner", "--same-owner", "--acls", "--xattrs",
            "--no-overwrite-dir", "-xpf", tar_path, "-C", dest_dir,
        ]
        proc = subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3600)
        if proc.returncode != 0:
            raise ToolError("E_UNSAFE_ARCHIVE", "GNU tar could not extract the archive safely.",
                            resource=os.path.basename(tar_path), next_action="reject_archive")
        return report
    return _python_extract(tar_path, dest_dir, roots=roots)


def _python_extract(tar_path: str, dest_dir: str, roots: Optional[List[str]] = None) -> TarReport:
    report = validate_tar(tar_path, roots=roots)
    root = os.path.realpath(dest_dir)
    hardlinks: List[Tuple[str, str]] = []
    with tarfile.open(tar_path, "r:*") as archive:
        for member in archive:
            if member.type in _GNU_META_TYPES:
                continue
            name = canonical_relpath(member.name)
            if name == "":
                continue
            target = os.path.realpath(os.path.join(root, name))
            if target != root and not target.startswith(root + os.sep):
                _fail("Extraction target escapes the destination directory.", name)
            parent = os.path.dirname(target)
            current = parent
            while os.path.realpath(current) != root and current.startswith(root):
                if os.path.islink(current):
                    _fail("Extraction would write through an existing symlink.", name)
                current = os.path.dirname(current)
            if member.islnk():
                # Hard links are materialised after all regular files so a
                # forward hard link (target later in the stream) still works.
                hardlinks.append((name, canonical_relpath(member.linkname)))
                continue
            _extract_one(archive, member, root, name)
        for name, source_name in hardlinks:
            out = os.path.join(root, name)
            source = os.path.join(root, source_name)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            if os.path.lexists(out):
                os.unlink(out)
            if not os.path.isfile(source) or os.path.islink(source):
                _fail("Archive hard link target was not extracted.", name)
            os.link(source, out)
    return report


def _extract_one(archive: tarfile.TarFile, member: tarfile.TarInfo, root: str, name: str) -> None:
    out = os.path.join(root, name)
    if member.isdir():
        os.makedirs(out, mode=member.mode or 0o755, exist_ok=True)
    elif member.issym():
        os.makedirs(os.path.dirname(out), exist_ok=True)
        if os.path.lexists(out):
            os.unlink(out)
        os.symlink(member.linkname, out)
    elif member.islnk():
        source = os.path.join(root, canonical_relpath(member.linkname))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        if os.path.lexists(out):
            os.unlink(out)
        if os.path.lexists(source):
            os.link(source, out)
    else:
        os.makedirs(os.path.dirname(out), exist_ok=True)
        handle = archive.extractfile(member)
        data = handle.read() if handle is not None else b""
        with open(out, "wb") as target:
            target.write(data)
    _apply_metadata(member, out)


def _apply_metadata(member: tarfile.TarInfo, path: str) -> None:
    """Apply numeric ownership, mode and extended attributes *strictly*.

    The Python fallback is only used when GNU tar is unavailable. It must never
    claim to preserve metadata it cannot apply: a required mode, ownership or
    declared xattr/ACL that cannot be reproduced is a hard failure, not a
    silent success. Metadata that already matches is left untouched.
    """
    info = os.lstat(path)
    if not os.path.islink(path):
        if stat.S_IMODE(info.st_mode) != (member.mode & 0o7777):
            try:
                os.chmod(path, member.mode & 0o7777)
            except OSError:
                _fail("Extracted member mode could not be applied.", member.name)
    if info.st_uid != member.uid or info.st_gid != member.gid:
        if not hasattr(os, "chown"):
            _fail("Numeric ownership cannot be preserved without os.chown.", member.name)
        try:
            os.chown(path, member.uid, member.gid, follow_symlinks=False)
        except (OSError, NotImplementedError):
            _fail("Numeric ownership could not be preserved.", member.name)
    headers = member.pax_headers or {}
    if any(key.startswith(("SCHILY.acl.", "LIBARCHIVE.acl.")) for key in headers):
        _fail("ACLs cannot be preserved without GNU tar.", member.name)
    for key, value in headers.items():
        if not key.startswith("SCHILY.xattr."):
            continue
        attr = key[len("SCHILY.xattr."):]
        if hasattr(os, "getxattr"):
            try:
                if os.getxattr(path, attr, follow_symlinks=False) == value.encode("utf-8"):
                    continue
            except OSError:
                pass
        if not hasattr(os, "setxattr"):
            _fail("Extended attributes cannot be preserved on this platform.", member.name)
        try:
            os.setxattr(path, attr, value.encode("utf-8"), follow_symlinks=False)
        except (OSError, NotImplementedError):
            _fail("Extended attribute could not be preserved.", member.name)


def create_tar(dest_path: str, sources: List[str], root: str = "/") -> None:
    """Create an uncompressed tar for fixtures and synthetic tests."""
    os.makedirs(os.path.dirname(os.path.abspath(dest_path)), mode=0o700, exist_ok=True)
    with tarfile.open(dest_path, "w", format=tarfile.PAX_FORMAT) as archive:
        for source in sources:
            archive.add(os.path.join(root, source.lstrip("/")), arcname=source.lstrip("/"))


def copy_dir_into(src: str, dest: str) -> None:
    shutil.copytree(src, dest, symlinks=True)
