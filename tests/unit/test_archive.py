import io
import os
import tarfile
import tempfile
import unittest
from unittest import mock

import support
from vps3xui.adapters import archive as archive_adapter
from vps3xui.errors import ToolError


def file_member(name, content=b"data", mode=0o644, pax=None, uid=None, gid=None):
    info = tarfile.TarInfo(name)
    info.size = len(content)
    info.mode = mode
    info.uid = os.geteuid() if uid is None else uid
    info.gid = os.getegid() if gid is None else gid
    if pax:
        info.pax_headers = dict(pax)
    return info, content


def symlink_member(name, target):
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    info.uid = os.geteuid()
    info.gid = os.getegid()
    return info, b""


def hardlink_member(name, target):
    info = tarfile.TarInfo(name)
    info.type = tarfile.LNKTYPE
    info.linkname = target
    return info, b""


def special_member(name, kind):
    info = tarfile.TarInfo(name)
    info.type = kind
    if kind in (tarfile.CHRTYPE, tarfile.BLKTYPE):
        info.devmajor = 1
        info.devminor = 3
    return info, b""


def write_tar(path, members):
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
        for info, payload in members:
            archive.addfile(info, io.BytesIO(payload))


def dir_member(name, mode=0o755, uid=None):
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = mode
    info.uid = os.geteuid() if uid is None else uid
    info.gid = os.getegid()
    return info, b""



class ArchiveValidationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="archive-")

    def _path(self, name="a.tar"):
        return os.path.join(self.tmp, name)

    def test_plain_archive_is_accepted(self):
        write_tar(self._path(), [file_member("etc/app/config.yml", b"a: 1")])
        report = archive_adapter.validate_tar(self._path())
        self.assertEqual(len(report.members), 1)
        self.assertEqual(report.members[0]["type"], "file")

    def test_absolute_member_path_rejected(self):
        write_tar(self._path(), [file_member("/etc/passwd")])
        with self.assertRaises(ToolError) as caught:
            archive_adapter.validate_tar(self._path())
        self.assertEqual(caught.exception.code, "E_UNSAFE_ARCHIVE")

    def test_traversal_member_rejected(self):
        write_tar(self._path(), [file_member("../evil")])
        with self.assertRaises(ToolError):
            archive_adapter.validate_tar(self._path())

    def test_duplicate_member_rejected(self):
        write_tar(self._path(), [file_member("a", b"1"), file_member("a", b"2")])
        with self.assertRaises(ToolError):
            archive_adapter.validate_tar(self._path())

    def test_device_and_fifo_rejected(self):
        for kind in (tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                path = self._path("special.tar")
                write_tar(path, [special_member("dev/x", kind)])
                with self.assertRaises(ToolError):
                    archive_adapter.validate_tar(path)
                os.unlink(path)

    def test_setuid_rejected(self):
        write_tar(self._path(), [file_member("bin/tool", b"x", mode=0o4755)])
        with self.assertRaises(ToolError):
            archive_adapter.validate_tar(self._path())

    def test_symlink_escape_rejected(self):
        write_tar(self._path(), [symlink_member("etc/link", "../../etc/passwd")])
        with self.assertRaises(ToolError):
            archive_adapter.validate_tar(self._path())

    def test_absolute_symlink_rejected(self):
        write_tar(self._path(), [symlink_member("etc/link", "/etc/passwd")])
        with self.assertRaises(ToolError):
            archive_adapter.validate_tar(self._path())

    def test_legitimate_letsencrypt_relative_link_accepted(self):
        write_tar(self._path(), [
            file_member("etc/letsencrypt/archive/kewlsub.duckdns.org/cert1.pem", b"cert"),
            symlink_member(
                "etc/letsencrypt/live/kewlsub.duckdns.org/cert.pem",
                "../../archive/kewlsub.duckdns.org/cert1.pem",
            ),
        ])
        report = archive_adapter.validate_tar(self._path())
        self.assertEqual(len(report.members), 2)

    def test_symlink_ancestor_write_rejected(self):
        write_tar(self._path(), [
            file_member("etc/letsencrypt/archive/x/cert.pem", b"cert"),
            symlink_member("etc/letsencrypt/live/x", "../../archive/x"),
            file_member("etc/letsencrypt/live/x/evil.pem", b"evil"),
        ])
        with self.assertRaises(ToolError):
            archive_adapter.validate_tar(self._path())

    def test_hardlink_to_unknown_member_rejected(self):
        write_tar(self._path(), [hardlink_member("a", "missing")])
        with self.assertRaises(ToolError):
            archive_adapter.validate_tar(self._path())

    def test_pax_capability_rejected(self):
        write_tar(self._path(), [
            file_member("bin/tool", b"x", pax={"SCHILY.xattr.security.capability": "AAAA"}),
        ])
        with self.assertRaises(ToolError):
            archive_adapter.validate_tar(self._path())

    def test_user_xattr_is_allowed(self):
        write_tar(self._path(), [
            file_member("data/file", b"x", pax={"SCHILY.xattr.user.comment": "ok"}),
        ])
        report = archive_adapter.validate_tar(self._path())
        self.assertEqual(len(report.members), 1)

    def test_truncated_archive_is_rejected(self):
        path = self._path("trunc.tar")
        with open(path, "wb") as handle:
            handle.write(b"not a tar file at all")
        with self.assertRaises(ToolError):
            archive_adapter.validate_tar(path)

    def test_safe_extract_into_fresh_directory(self):
        path = self._path("ok.tar")
        write_tar(path, [file_member("etc/app/config.yml", b"a: 1")])
        dest = os.path.join(self.tmp, "out")
        report = archive_adapter.safe_extract(path, dest)
        self.assertEqual(len(report.members), 1)
        with open(os.path.join(dest, "etc/app/config.yml"), "rb") as handle:
            self.assertEqual(handle.read(), b"a: 1")

    def test_safe_extract_refuses_non_empty_destination(self):
        path = self._path("ok2.tar")
        write_tar(path, [file_member("a", b"1")])
        dest = os.path.join(self.tmp, "busy")
        os.makedirs(dest)
        with open(os.path.join(dest, "existing"), "w") as handle:
            handle.write("keep")
        with self.assertRaises(ToolError) as caught:
            archive_adapter.safe_extract(path, dest)
        self.assertEqual(caught.exception.code, "E_PRECONDITION")


class ArchiveGraphTest(unittest.TestCase):
    """REVIEW-2 item 10: component-wise symlink resolution and metadata."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="archive-graph-")

    def _path(self, name="a.tar"):
        return os.path.join(self.tmp, name)

    def test_symlink_component_escape_is_rejected(self):
        # ``escape`` -> ../outside (escaping), then ``escape/x`` must not be
        # textually collapsed into a safe-looking path.
        write_tar(self._path(), [
            symlink_member("escape", "../outside"),
            file_member("escape/x", b"data"),
        ])
        with self.assertRaises(ToolError) as caught:
            archive_adapter.validate_tar(self._path())
        self.assertEqual(caught.exception.code, "E_UNSAFE_ARCHIVE")

    def test_symlink_component_resolution_inside_tree_is_allowed(self):
        # ``other`` points through ``alias`` (a symlink). Component-wise
        # expansion resolves ``alias/file`` to ``real/file`` inside the tree.
        write_tar(self._path(), [
            symlink_member("alias", "real"),
            file_member("real/file", b"data"),
            symlink_member("other", "alias/file"),
        ])
        report = archive_adapter.validate_tar(self._path())
        self.assertEqual(len(report.members), 3)

    def test_libarchive_dangerous_xattr_is_rejected(self):
        write_tar(self._path(), [
            file_member("data/file", b"x", pax={"LIBARCHIVE.xattr.security.capability": "AAAA"}),
        ])
        with self.assertRaises(ToolError):
            archive_adapter.validate_tar(self._path())

    def test_root_directory_entry_with_setuid_is_rejected(self):
        write_tar(self._path(), [dir_member(".", mode=0o4755)])
        with self.assertRaises(ToolError):
            archive_adapter.validate_tar(self._path())

    def test_root_directory_entry_is_accepted_and_ignored(self):
        write_tar(self._path(), [dir_member(".", mode=0o750), file_member("a", b"1")])
        report = archive_adapter.validate_tar(self._path())
        self.assertEqual(len(report.members), 1)

    def test_safe_extract_refuses_a_symlinked_destination(self):
        path = self._path("d.tar")
        write_tar(path, [file_member("a", b"1")])
        victim = os.path.join(self.tmp, "victim")
        os.makedirs(victim)
        link = os.path.join(self.tmp, "dest-link")
        os.symlink(victim, link)
        with self.assertRaises(ToolError) as caught:
            archive_adapter.safe_extract(path, link)
        self.assertEqual(caught.exception.code, "E_UNSAFE_ARCHIVE")

    def test_forward_hardlink_extracts_python_fallback(self):
        path = self._path("hl.tar")
        info, content = file_member("b", b"payload")
        write_tar(path, [hardlink_member("a", "b"), (info, content)])
        dest = os.path.join(self.tmp, "hl-out")
        with mock.patch.object(archive_adapter, "_gnu_tar_available", lambda: False):
            archive_adapter.safe_extract(path, dest)
        self.assertTrue(os.path.isfile(os.path.join(dest, "a")))
        with open(os.path.join(dest, "a"), "rb") as handle:
            self.assertEqual(handle.read(), b"payload")

    def test_python_fallback_fails_on_unpreservable_ownership(self):
        path = self._path("own.tar")
        write_tar(path, [file_member("a", b"1", uid=os.geteuid() + 123456)])
        dest = os.path.join(self.tmp, "own-out")
        with mock.patch.object(archive_adapter, "_gnu_tar_available", lambda: False):
            with self.assertRaises(ToolError) as caught:
                archive_adapter.safe_extract(path, dest)
        self.assertEqual(caught.exception.code, "E_UNSAFE_ARCHIVE")


if __name__ == "__main__":
    unittest.main()
