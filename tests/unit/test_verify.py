import os
import shutil
import tarfile
import tempfile
import unittest

import support
from vps3xui.adapters import archive as archive_adapter
from vps3xui.errors import ToolError
from vps3xui.verify import build_sums, parse_sums_text, required_sums_names, verify_directory


class VerifyCompleteBackupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="verify-")
        self.manifest, self.backup_dir, self.report, self.system = support.complete_backup(self.tmp)
        self.assertTrue(self.report["state"], "succeeded")

    def test_complete_backup_verifies(self):
        result = verify_directory(self.backup_dir, self.manifest, require_complete=True)
        self.assertTrue(result.ok, result.error.to_error_object() if result.error else None)
        self.assertEqual(result.missing, [])
        self.assertEqual(result.mismatched, [])
        self.assertEqual(result.extra, [])

    def _rewrite_manifest_json(self, name, mutate):
        import json
        path = os.path.join(self.backup_dir, name)
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        mutate(data)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
        sums = build_sums(self.backup_dir, required_sums_names(self.manifest))
        with open(os.path.join(self.backup_dir, "SHA256SUMS"), "wb") as handle:
            handle.write(sums)

    def test_metadata_schema_version_is_checked(self):
        self._rewrite_manifest_json("backup.json", lambda d: d.update(schema_version=99))
        result = verify_directory(self.backup_dir, self.manifest)
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "E_VERIFY_FAILED")

    def test_metadata_manifest_identity_is_checked(self):
        self._rewrite_manifest_json("backup.json", lambda d: d.update(manifest_id="other"))
        result = verify_directory(self.backup_dir, self.manifest)
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "E_VERIFY_FAILED")

    def test_images_metadata_digest_is_checked(self):
        self._rewrite_manifest_json(
            "images.json",
            lambda d: d["images"][0].update(repository_digest="sha256:" + "0" * 64),
        )
        result = verify_directory(self.backup_dir, self.manifest)
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "E_VERIFY_FAILED")

    def test_missing_required_artifact(self):
        os.unlink(os.path.join(self.backup_dir, "binds.tar"))
        result = verify_directory(self.backup_dir, self.manifest)
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "E_MISSING_ARTIFACT")

    def test_required_artifact_not_covered_by_sums(self):
        sums_path = os.path.join(self.backup_dir, "SHA256SUMS")
        with open(sums_path, "r", encoding="utf-8") as handle:
            lines = [line for line in handle if not line.rstrip("\n").endswith("  ufw-meta.txt")]
        with open(sums_path, "w", encoding="utf-8") as handle:
            handle.writelines(lines)
        result = verify_directory(self.backup_dir, self.manifest)
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "E_MISSING_ARTIFACT")
        self.assertIn("ufw-meta.txt", result.missing)

    def test_hash_mismatch(self):
        target = os.path.join(self.backup_dir, "ufw-status.txt")
        with open(target, "ab") as handle:
            handle.write(b"tampered\n")
        result = verify_directory(self.backup_dir, self.manifest)
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "E_HASH_MISMATCH")

    def test_extra_file_is_rejected(self):
        with open(os.path.join(self.backup_dir, "extra.bin"), "wb") as handle:
            handle.write(b"x")
        result = verify_directory(self.backup_dir, self.manifest)
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "E_VERIFY_FAILED")

    def test_missing_complete_marker_is_partial(self):
        os.unlink(os.path.join(self.backup_dir, "COMPLETE"))
        result = verify_directory(self.backup_dir, self.manifest, require_complete=True)
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "E_VERIFY_FAILED")

    def test_missing_sums_file(self):
        os.unlink(os.path.join(self.backup_dir, "SHA256SUMS"))
        result = verify_directory(self.backup_dir, self.manifest)
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "E_MISSING_ARTIFACT")

    def test_unsafe_tar_member_rejected_even_with_matching_hash(self):
        # Replace binds.tar with an archive containing traversal, then refresh sums.
        import io

        bad = os.path.join(self.backup_dir, "binds.tar")
        with tarfile.open(bad, "w") as archive:
            info = tarfile.TarInfo("../escape")
            payload = b"evil"
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        with open(os.path.join(self.backup_dir, "SHA256SUMS"), "wb") as handle:
            handle.write(build_sums(self.backup_dir, required_sums_names(self.manifest)))
        result = verify_directory(self.backup_dir, self.manifest, validate_archives=True)
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "E_UNSAFE_ARCHIVE")

    def test_members_outside_declared_includes_rejected(self):
        bad = os.path.join(self.backup_dir, "binds.tar")
        with tarfile.open(bad, "w") as archive:
            import io

            info = tarfile.TarInfo("etc/shadow")
            payload = b"root:x:0:0"
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        with open(os.path.join(self.backup_dir, "SHA256SUMS"), "wb") as handle:
            handle.write(build_sums(self.backup_dir, required_sums_names(self.manifest)))
        result = verify_directory(self.backup_dir, self.manifest, validate_archives=True)
        self.assertFalse(result.ok)
        self.assertEqual(result.error.code, "E_UNSAFE_ARCHIVE")

    def test_letsencrypt_link_membership_is_preserved(self):
        report = archive_adapter.validate_tar(os.path.join(self.backup_dir, "binds.tar"))
        kinds = {(member["name"], member["type"]) for member in report.members}
        cert_link = (
            "etc/letsencrypt/live/kewlsub.duckdns.org/cert.pem",
            "symlink",
        )
        self.assertIn(cert_link, kinds)


class SumsParsingTest(unittest.TestCase):
    def test_malformed_line_rejected(self):
        with self.assertRaises(ToolError) as caught:
            parse_sums_text("not-a-hash  file\n")
        self.assertEqual(caught.exception.code, "E_SUMS_INVALID")

    def test_duplicate_entry_rejected(self):
        line = "%s  a\n" % ("0" * 64)
        with self.assertRaises(ToolError):
            parse_sums_text(line + line)

    def test_sums_must_not_cover_itself(self):
        with self.assertRaises(ToolError):
            parse_sums_text("%s  SHA256SUMS\n" % ("0" * 64))

    def test_traversal_entry_rejected(self):
        with self.assertRaises(ToolError):
            parse_sums_text("%s  ../escape\n" % ("0" * 64))

    def test_binary_marker_accepted(self):
        entries = parse_sums_text("%s *binds.tar\n" % ("a" * 64))
        self.assertEqual(entries, [("a" * 64, "binds.tar")])


if __name__ == "__main__":
    unittest.main()
