import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest

import support
from vps3xui.release import build_release_archive


class ReleaseArchiveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="release-")
        self.manifest = support.approved_manifest(self.tmp)

    def _names(self, blob):
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
            return {member.name: member for member in archive.getmembers()}

    def test_release_contains_package_wrappers_and_manifest(self):
        blob = build_release_archive(self.manifest)
        names = self._names(blob)
        for expected in [
            "vps3xui/verify.py",
            "vps3xui/remote_ops.py",
            "vps3xui/worker/backup_worker.py",
            "vps3xui/adapters/archive.py",
            "config/manifest.schema.json",
            "bin/vps3xui-worker",
            "bin/vps3xui-finalizer",
            "manifest.json",
            "RELEASE",
        ]:
            self.assertIn(expected, names, expected)

    def test_wrappers_are_executable_in_the_archive(self):
        names = self._names(build_release_archive(self.manifest))
        self.assertTrue(names["bin/vps3xui-worker"].mode & 0o111)
        self.assertTrue(names["bin/vps3xui-finalizer"].mode & 0o111)

    def test_embedded_manifest_matches(self):
        blob = build_release_archive(self.manifest)
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
            payload = archive.extractfile("manifest.json").read().decode("utf-8")
        self.assertEqual(json.loads(payload), self.manifest.data)

    def test_archive_digest_is_stable_for_same_inputs(self):
        first = build_release_archive(self.manifest)
        second = build_release_archive(self.manifest)
        self.assertEqual(hashlib.sha256(first).hexdigest(), hashlib.sha256(second).hexdigest())

    def test_every_released_module_compiles(self):
        blob = build_release_archive(self.manifest)
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
            for member in archive.getmembers():
                if not member.name.endswith(".py"):
                    continue
                source = archive.extractfile(member).read()
                compile(source, member.name, "exec")


if __name__ == "__main__":
    unittest.main()
