"""F2: the first-failure journal is written once and never overwritten.

The worker persists its first cause to ``failure.json`` before it can write
``report.json``. A rerun -- even one whose durable state was lost back to
``accepted`` -- must not overwrite, replace or erase existing evidence,
whatever shape it has: valid, malformed, empty, unreadable, non-regular,
symlinked or written for another job. The independent finalizer reads the same
shared classification, so both sides agree on the first cause and a corrupt
present journal yields a curated, content-free diagnostic instead of its raw
bytes. Only a truly absent file permits a first creation.

Every host effect goes through the synthetic system; no Docker, systemd, SSH
or production data is touched.
"""

import json
import os
import stat
import subprocess
import sys
import unittest
from unittest import mock

import support
from vps3xui.errors import ToolError
from vps3xui.inventory import Inventory
from vps3xui.plan import build_plan
from vps3xui.release import build_release_archive
from vps3xui.worker import failure_journal, finalizer
from vps3xui.worker.backup_worker import BackupWorker
from vps3xui.worker.jobctx import FAILURE_FILE, JobContext, REPORT_FILE, STATE_FILE

SUCCESS_RESULT = {"SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": "0"}
SIGNAL_RESULT = {"SERVICE_RESULT": "signal", "EXIT_CODE": "killed", "EXIT_STATUS": "9"}
CANARY = "JOURNAL_CANARY_FIRST_CAUSE"
CopyFailure = "synthetic copy failure"


def seeded_job(tmp, job_id):
    manifest = support.approved_manifest(tmp)
    inventory = Inventory.from_probe(support.synthetic_probe())
    plan = build_plan(manifest, inventory, support.HOST_KEY)
    job_dir = os.path.join(tmp, "jobs", job_id)
    backup_dir = os.path.join(tmp, "backups", job_id)
    support.seed_job(job_dir, {
        "schema_version": 1,
        "request_id": job_id,
        "job_id": job_id,
        "manifest_id": manifest.manifest_id,
        "plan_digest": plan["identity"],
        "machine_id": support.MACHINE_ID,
        "host_key_fingerprint": support.HOST_KEY,
        "backup_dir": backup_dir,
        "stop_containers": plan["stop_containers"],
        "leave_stopped": plan["leave_stopped"],
        "required_bytes_estimate": 5_000_000_000,
    }, plan, manifest)
    system = support.SyntheticSystem(manifest, os.path.join(tmp, "system-1", job_id))
    return manifest, system, job_dir, backup_dir


def fresh_system(manifest, tmp, job_id):
    return support.SyntheticSystem(manifest, os.path.join(tmp, "system-2", job_id))


def journal_bytes(job_dir):
    with open(os.path.join(job_dir, FAILURE_FILE), "rb") as handle:
        return handle.read()


def journal_fingerprint(job_dir):
    info = os.lstat(os.path.join(job_dir, FAILURE_FILE))
    return (info.st_ino, info.st_size, journal_bytes(job_dir))


def stat_is_fifo(path):
    return stat.S_ISFIFO(os.lstat(path).st_mode)


def write_journal(job_dir, payload, mode=0o600):
    if isinstance(payload, bytes):
        blob = payload
    else:
        blob = (json.dumps(payload) + "\n").encode("utf-8")
    path = os.path.join(job_dir, FAILURE_FILE)
    with open(path, "wb") as handle:
        handle.write(blob)
    os.chmod(path, mode)
    return blob


def drop_state(job_dir):
    """Model a rerun whose durable state unexpectedly reads back ``accepted``."""
    path = os.path.join(job_dir, STATE_FILE)
    if os.path.exists(path):
        os.unlink(path)


class WorkerJournalPreservationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = support.temp_state_dir("f2-journal-")

    def _assert_no_restart(self, system):
        self.assertEqual(system.stopped_ids, [])
        self.assertEqual(system.copy_calls, [])

    def test_corrupt_journal_blocks_a_rerun_and_survives_byte_for_byte(self):
        manifest, system, job_dir, backup_dir = seeded_job(self.tmp, "req-f2-corrupt")
        drop_state(job_dir)
        canary_blob = ('{"code": "E_EXECUTION", "message": "%s"' % CANARY).encode("utf-8")
        write_journal(job_dir, canary_blob)
        before = journal_fingerprint(job_dir)

        rerun_system = fresh_system(manifest, self.tmp, "req-f2-corrupt")
        report = BackupWorker(rerun_system, job_dir, manifest).run()

        self.assertEqual(journal_fingerprint(job_dir), before)
        self._assert_no_restart(rerun_system)
        self.assertEqual(report["state"], "interrupted")
        failure = report["original_failure"]
        self.assertEqual(failure["code"], "E_EXECUTION")
        self.assertEqual(failure["resource"], FAILURE_FILE)
        self.assertEqual(failure["detail"]["reason"], "failure_journal_malformed")
        self.assertNotIn(CANARY, json.dumps(report, sort_keys=True))
        with open(os.path.join(job_dir, "events.log"), "rb") as handle:
            self.assertNotIn(CANARY.encode(), handle.read())
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))

    def test_empty_journal_is_malformed_and_preserved(self):
        manifest, system, job_dir, backup_dir = seeded_job(self.tmp, "req-f2-empty")
        drop_state(job_dir)
        write_journal(job_dir, b"")
        before = journal_fingerprint(job_dir)

        rerun_system = fresh_system(manifest, self.tmp, "req-f2-empty")
        report = BackupWorker(rerun_system, job_dir, manifest).run()

        self.assertEqual(journal_fingerprint(job_dir), before)
        self._assert_no_restart(rerun_system)
        self.assertEqual(report["original_failure"]["detail"]["reason"],
                         "failure_journal_malformed")

    def test_valid_first_cause_takes_precedence_over_the_rerun(self):
        manifest, system, job_dir, backup_dir = seeded_job(self.tmp, "req-f2-valid")
        system.faults["copy_fail"] = True
        first = BackupWorker(system, job_dir, manifest).run()
        self.assertEqual(first["original_failure"]["code"], "E_EXECUTION")
        persisted = support.read_json_file(os.path.join(job_dir, FAILURE_FILE))
        self.assertEqual(persisted["job_id"], "req-f2-valid")
        self.assertEqual(persisted["schema_version"], 1)
        drop_state(job_dir)
        before = journal_fingerprint(job_dir)

        rerun_system = fresh_system(manifest, self.tmp, "req-f2-valid")
        report = BackupWorker(rerun_system, job_dir, manifest).run()

        self.assertEqual(journal_fingerprint(job_dir), before)
        self._assert_no_restart(rerun_system)
        self.assertEqual(report["state"], "interrupted")
        self.assertEqual(report["original_failure"],
                         {"code": "E_EXECUTION", "message": CopyFailure, "resource": None})

    def test_legacy_minimal_journal_is_still_accepted(self):
        manifest, system, job_dir, backup_dir = seeded_job(self.tmp, "req-f2-legacy")
        drop_state(job_dir)
        write_journal(job_dir, {"code": "E_PRECONDITION", "message": "legacy cause",
                                "resource": "disk"})
        before = journal_fingerprint(job_dir)

        rerun_system = fresh_system(manifest, self.tmp, "req-f2-legacy")
        report = BackupWorker(rerun_system, job_dir, manifest).run()

        self.assertEqual(journal_fingerprint(job_dir), before)
        self._assert_no_restart(rerun_system)
        self.assertEqual(report["original_failure"],
                         {"code": "E_PRECONDITION", "message": "legacy cause", "resource": "disk"})

    def test_wrong_job_journal_fails_closed(self):
        manifest, system, job_dir, backup_dir = seeded_job(self.tmp, "req-f2-wrongjob")
        drop_state(job_dir)
        write_journal(job_dir, {"schema_version": 1, "job_id": "req-somebody-else",
                                "code": "E_PRECONDITION", "message": CANARY,
                                "resource": "disk"})
        before = journal_fingerprint(job_dir)

        rerun_system = fresh_system(manifest, self.tmp, "req-f2-wrongjob")
        report = BackupWorker(rerun_system, job_dir, manifest).run()

        self.assertEqual(journal_fingerprint(job_dir), before)
        self._assert_no_restart(rerun_system)
        failure = report["original_failure"]
        self.assertEqual(failure["detail"]["reason"], "failure_journal_job_mismatch")
        self.assertNotIn(CANARY, json.dumps(report, sort_keys=True))

    def test_unsupported_schema_fails_closed(self):
        manifest, system, job_dir, backup_dir = seeded_job(self.tmp, "req-f2-schema")
        drop_state(job_dir)
        write_journal(job_dir, {"schema_version": 99, "job_id": "req-f2-schema",
                                "code": "E_EXECUTION", "message": CANARY})
        before = journal_fingerprint(job_dir)

        rerun_system = fresh_system(manifest, self.tmp, "req-f2-schema")
        report = BackupWorker(rerun_system, job_dir, manifest).run()

        self.assertEqual(journal_fingerprint(job_dir), before)
        self._assert_no_restart(rerun_system)
        self.assertEqual(report["original_failure"]["detail"]["reason"],
                         "failure_journal_unsupported")

    def test_symlink_journal_is_preserved_and_its_target_untouched(self):
        manifest, system, job_dir, backup_dir = seeded_job(self.tmp, "req-f2-symlink")
        drop_state(job_dir)
        target = os.path.join(self.tmp, "outside-target.json")
        with open(target, "wb") as handle:
            handle.write(CANARY.encode())
        os.symlink(target, os.path.join(job_dir, FAILURE_FILE))
        before = os.lstat(os.path.join(job_dir, FAILURE_FILE))

        rerun_system = fresh_system(manifest, self.tmp, "req-f2-symlink")
        report = BackupWorker(rerun_system, job_dir, manifest).run()

        after = os.lstat(os.path.join(job_dir, FAILURE_FILE))
        self.assertTrue(os.path.islink(os.path.join(job_dir, FAILURE_FILE)))
        self.assertEqual((before.st_ino, before.st_mode), (after.st_ino, after.st_mode))
        with open(target, "rb") as handle:
            self.assertEqual(handle.read(), CANARY.encode())
        self._assert_no_restart(rerun_system)
        self.assertEqual(report["original_failure"]["detail"]["reason"],
                         "failure_journal_unreadable")
        self.assertNotIn(CANARY, json.dumps(report, sort_keys=True))

    def test_nonregular_journal_is_preserved(self):
        manifest, system, job_dir, backup_dir = seeded_job(self.tmp, "req-f2-dir")
        drop_state(job_dir)
        path = os.path.join(job_dir, FAILURE_FILE)
        os.mkdir(path, 0o700)

        rerun_system = fresh_system(manifest, self.tmp, "req-f2-dir")
        report = BackupWorker(rerun_system, job_dir, manifest).run()

        self.assertTrue(os.path.isdir(path))
        self._assert_no_restart(rerun_system)
        self.assertEqual(report["original_failure"]["detail"]["reason"],
                         "failure_journal_unreadable")

    def test_unreadable_journal_is_preserved(self):
        manifest, system, job_dir, backup_dir = seeded_job(self.tmp, "req-f2-perm")
        drop_state(job_dir)
        blob = write_journal(job_dir, {"code": "E_EXECUTION", "message": CANARY})
        path = os.path.join(job_dir, FAILURE_FILE)
        inode = os.lstat(path).st_ino
        os.chmod(path, 0o000)
        try:
            rerun_system = fresh_system(manifest, self.tmp, "req-f2-perm")
            report = BackupWorker(rerun_system, job_dir, manifest).run()
            self._assert_no_restart(rerun_system)
            self.assertEqual(report["original_failure"]["detail"]["reason"],
                             "failure_journal_unreadable")
            self.assertNotIn(CANARY, json.dumps(report, sort_keys=True))
        finally:
            os.chmod(path, 0o600)
        self.assertEqual(os.lstat(path).st_ino, inode)
        self.assertEqual(journal_bytes(job_dir), blob)

    def test_oversized_journal_blocks_a_rerun_and_survives(self):
        manifest, system, job_dir, backup_dir = seeded_job(self.tmp, "req-f2-big")
        drop_state(job_dir)
        blob = (json.dumps({"schema_version": 1, "job_id": "req-f2-big",
                            "code": "E_EXECUTION", "message": CANARY + "A" * 70000}) + "\n"
                ).encode("utf-8")
        self.assertGreater(len(blob), failure_journal.MAX_JOURNAL_BYTES)
        write_journal(job_dir, blob)
        before = journal_fingerprint(job_dir)

        rerun_system = fresh_system(manifest, self.tmp, "req-f2-big")
        report = BackupWorker(rerun_system, job_dir, manifest).run()

        self.assertEqual(journal_fingerprint(job_dir), before)
        self._assert_no_restart(rerun_system)
        self.assertEqual(report["original_failure"]["detail"]["reason"],
                         "failure_journal_oversized")
        self.assertNotIn(CANARY, json.dumps(report, sort_keys=True))


class JournalSafeReadTest(unittest.TestCase):
    """The shared reader must never block, over-read or leak raw bytes."""

    def setUp(self):
        self.tmp = support.temp_state_dir("f2-saferead-")
        self.job_dir = os.path.join(self.tmp, "jobs", "req-f2-read")
        os.makedirs(self.job_dir, mode=0o700)
        self.path = os.path.join(self.job_dir, FAILURE_FILE)

    def _content_free(self, state):
        self.assertEqual(state["status"], failure_journal.INVALID)
        self.assertIsNone(state["failure"])
        self.assertNotIn(CANARY, json.dumps(state, sort_keys=True))

    def test_fifo_journal_is_rejected_without_blocking(self):
        os.mkfifo(self.path, 0o600)
        script = (
            "import json, sys\n"
            "from vps3xui.worker import failure_journal\n"
            "print(json.dumps(failure_journal.read_state(sys.argv[1], sys.argv[2])))\n"
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [os.path.join(support.REPO_ROOT, "tests"), support.REPO_ROOT])
        # A subprocess with a hard timeout proves the read cannot hang: a FIFO
        # would block forever if the path were opened before being classified.
        done = subprocess.run([sys.executable, "-c", script, self.job_dir, "req-f2-read"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=20, env=env)
        self.assertEqual(done.returncode, 0, done.stderr.decode("utf-8", "replace"))
        state = json.loads(done.stdout.decode("utf-8").strip().splitlines()[-1])
        self.assertEqual(state["status"], failure_journal.INVALID)
        self.assertEqual(state["reason"], failure_journal.UNREADABLE)
        self.assertTrue(stat_is_fifo(self.path))

    def test_symlink_journal_is_invalid_and_content_free(self):
        target = os.path.join(self.tmp, "outside.json")
        with open(target, "wb") as handle:
            handle.write(CANARY.encode())
        os.symlink(target, self.path)
        self._content_free(failure_journal.read_state(self.job_dir, "req-f2-read"))
        self.assertTrue(os.path.islink(self.path))
        with open(target, "rb") as handle:
            self.assertEqual(handle.read(), CANARY.encode())

    def test_nonregular_journal_is_invalid(self):
        os.mkdir(self.path, 0o700)
        self._content_free(failure_journal.read_state(self.job_dir, "req-f2-read"))
        self.assertTrue(os.path.isdir(self.path))

    def test_oversized_journal_is_invalid_and_not_read(self):
        write_journal(self.job_dir, CANARY.encode() + b"A" * (failure_journal.MAX_JOURNAL_BYTES + 1))
        state = failure_journal.read_state(self.job_dir, "req-f2-read")
        self._content_free(state)
        self.assertEqual(state["reason"], failure_journal.OVERSIZED)

    def test_stat_permission_error_is_invalid_not_absent(self):
        with mock.patch("os.lstat", side_effect=PermissionError(13, "Permission denied")):
            state = failure_journal.read_state(self.job_dir, "req-f2-read")
        self._content_free(state)
        self.assertEqual(state["reason"], failure_journal.UNREADABLE)

    def test_journal_replaced_between_stat_and_open_is_invalid(self):
        write_journal(self.job_dir, {"code": "E_EXECUTION", "message": CANARY})
        other = os.path.join(self.tmp, "other.json")
        with open(other, "wb") as handle:
            handle.write(b'{"code": "E_EXECUTION", "message": "replacement"}')
        real_open = os.open

        def swapped(_path, flags, *args, **kwargs):
            return real_open(other, flags, *args, **kwargs)

        with mock.patch("os.open", side_effect=swapped):
            state = failure_journal.read_state(self.job_dir, "req-f2-read")
        self._content_free(state)
        self.assertEqual(state["reason"], failure_journal.UNREADABLE)


class FailureJournalRecordTest(unittest.TestCase):
    def setUp(self):
        self.tmp = support.temp_state_dir("f2-record-")
        self.job_dir = os.path.join(self.tmp, "jobs", "req-f2-record")
        os.makedirs(self.job_dir, mode=0o700)

    def test_first_record_carries_provenance_and_wins(self):
        self.assertTrue(failure_journal.record(self.job_dir, code="E_EXECUTION",
                                               message="boom", job_id="req-f2-record"))
        persisted = support.read_json_file(os.path.join(self.job_dir, FAILURE_FILE))
        self.assertEqual(persisted["schema_version"], 1)
        self.assertEqual(persisted["job_id"], "req-f2-record")
        self.assertEqual(persisted["code"], "E_EXECUTION")

    def test_second_record_never_touches_the_first(self):
        failure_journal.record(self.job_dir, code="E_EXECUTION", message="first",
                               job_id="req-f2-record")
        before = journal_fingerprint(self.job_dir)
        self.assertFalse(failure_journal.record(self.job_dir, code="E_RECOVERY_REQUIRED",
                                                message="second", job_id="req-f2-record"))
        self.assertEqual(journal_fingerprint(self.job_dir), before)
        self.assertEqual(support.read_json_file(os.path.join(self.job_dir, FAILURE_FILE))["code"],
                         "E_EXECUTION")

    def test_competing_creator_wins_and_the_worker_adopts_it(self):
        manifest, system, seeded_dir, backup_dir = seeded_job(self.tmp, "req-f2-race")
        worker = BackupWorker(system, seeded_dir, manifest)
        competing = (json.dumps({"schema_version": 1, "job_id": "req-f2-race",
                                 "code": "E_CONFLICT", "message": "competing first cause"}) + "\n"
                     ).encode("utf-8")
        path = os.path.join(seeded_dir, FAILURE_FILE)

        def race(_path, _mode=0o600):
            with open(path, "wb") as handle:
                handle.write(competing)
            raise ToolError("E_PRECONDITION", "Refusing to clobber an existing path.")

        with mock.patch.object(failure_journal, "create_exclusive", side_effect=race):
            worker._record_failure("E_EXECUTION", "worker cause")

        self.assertEqual(worker.original_failure,
                         {"code": "E_CONFLICT", "message": "competing first cause",
                          "resource": None})
        self.assertEqual(journal_bytes(seeded_dir), competing)

    def test_failed_creation_keeps_the_in_memory_cause(self):
        manifest, system, seeded_dir, backup_dir = seeded_job(self.tmp, "req-f2-nocreate")
        worker = BackupWorker(system, seeded_dir, manifest)
        failure = ToolError("E_STATE_WRITE_FAILED", "State file could not be written durably.")
        with mock.patch.object(failure_journal, "create_exclusive", side_effect=failure):
            worker._record_failure("E_EXECUTION", "in-memory cause", resource="copy")
        self.assertFalse(os.path.exists(os.path.join(seeded_dir, FAILURE_FILE)))
        self.assertEqual(worker.original_failure,
                         {"code": "E_EXECUTION", "message": "in-memory cause", "resource": "copy"})

    def test_serialization_failure_leaves_nothing_behind(self):
        with self.assertRaises(ToolError):
            failure_journal.record(self.job_dir, code="E_EXECUTION", message=object())
        self.assertFalse(os.path.exists(os.path.join(self.job_dir, FAILURE_FILE)))

    def test_fsync_failure_keeps_the_written_bytes(self):
        with mock.patch("os.fsync", side_effect=OSError("fsync failed")):
            with self.assertRaises(OSError):
                failure_journal.record(self.job_dir, code="E_EXECUTION", message="written",
                                       job_id="req-f2-record")
        persisted = support.read_json_file(os.path.join(self.job_dir, FAILURE_FILE))
        self.assertEqual(persisted["code"], "E_EXECUTION")
        self.assertEqual(persisted["message"], "written")

    def test_read_state_distinguishes_absent_valid_and_invalid(self):
        self.assertEqual(failure_journal.read_state(self.job_dir)["status"],
                         failure_journal.ABSENT)
        write_journal(self.job_dir, {"code": "E_EXECUTION", "message": "legacy"})
        state = failure_journal.read_state(self.job_dir, "req-f2-record")
        self.assertEqual(state["status"], failure_journal.VALID)
        self.assertEqual(state["failure"]["code"], "E_EXECUTION")
        write_journal(self.job_dir, {"code": "E_EXECUTION", "job_id": "req-other"})
        state = failure_journal.read_state(self.job_dir, "req-f2-record")
        self.assertEqual(state["status"], failure_journal.INVALID)
        self.assertEqual(state["reason"], failure_journal.JOB_MISMATCH)

    def test_absent_journal_returns_the_fallback(self):
        fallback = {"code": "E_EXECUTION", "message": "fallback", "resource": None}
        state = failure_journal.read_state(self.job_dir)
        self.assertEqual(failure_journal.reported_failure(state, fallback), fallback)


class WorkerFinalizerAgreementTest(unittest.TestCase):
    def setUp(self):
        self.tmp = support.temp_state_dir("f2-agree-")

    def test_first_cause_survives_a_rerun_and_an_independent_finalizer(self):
        manifest, system, job_dir, backup_dir = seeded_job(self.tmp, "req-f2-agree")
        system.faults["copy_fail"] = True
        BackupWorker(system, job_dir, manifest).run()
        persisted = support.read_json_file(os.path.join(job_dir, FAILURE_FILE))
        drop_state(job_dir)
        before = journal_fingerprint(job_dir)

        rerun_system = fresh_system(manifest, self.tmp, "req-f2-agree")
        rerun = BackupWorker(rerun_system, job_dir, manifest).run()
        self.assertEqual(rerun["original_failure"],
                         {"code": "E_EXECUTION", "message": CopyFailure, "resource": None})

        result = finalizer.recover(job_dir, rerun_system, manifest,
                                   service_result=dict(SIGNAL_RESULT))
        report = JobContext(job_dir).read_json(REPORT_FILE)
        self.assertEqual(result["state"], "failed")
        self.assertEqual(report["original_failure"],
                         {"code": "E_EXECUTION", "message": CopyFailure, "resource": None})
        self.assertEqual(report["original_failure"]["code"], persisted["code"])
        self.assertEqual(journal_fingerprint(job_dir), before)
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))

    def test_worker_and_finalizer_report_the_same_corrupt_diagnostic(self):
        manifest, system, job_dir, backup_dir = seeded_job(self.tmp, "req-f2-diag")
        drop_state(job_dir)
        write_journal(job_dir, ('{"code": "E_EXECUTION", "message": "%s"' % CANARY).encode())
        before = journal_fingerprint(job_dir)

        rerun_system = fresh_system(manifest, self.tmp, "req-f2-diag")
        rerun = BackupWorker(rerun_system, job_dir, manifest).run()
        result = finalizer.recover(job_dir, rerun_system, manifest,
                                   service_result=dict(SIGNAL_RESULT))
        report = JobContext(job_dir).read_json(REPORT_FILE)

        self.assertEqual(rerun["original_failure"], report["original_failure"])
        self.assertEqual(report["original_failure"]["detail"]["reason"],
                         "failure_journal_malformed")
        self.assertEqual(journal_fingerprint(job_dir), before)
        self.assertNotIn(CANARY, json.dumps(result, sort_keys=True))
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))

    def test_untouched_missing_journal_still_reaches_success(self):
        manifest, system, job_dir, backup_dir = seeded_job(self.tmp, "req-f2-clean")
        BackupWorker(system, job_dir, manifest).run()
        self.assertFalse(os.path.exists(os.path.join(job_dir, FAILURE_FILE)))
        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        self.assertEqual(result["state"], "succeeded")
        self.assertTrue(os.path.isfile(os.path.join(backup_dir, "COMPLETE")))

    def test_finalizer_fails_closed_on_a_wrong_job_journal(self):
        manifest, system, job_dir, backup_dir = seeded_job(self.tmp, "req-f2-finaljob")
        BackupWorker(system, job_dir, manifest).run()
        write_journal(job_dir, {"schema_version": 1, "job_id": "req-somebody-else",
                                "code": "E_EXECUTION", "message": CANARY})
        before = journal_fingerprint(job_dir)

        result = finalizer.recover(job_dir, system, manifest,
                                   service_result=dict(SUCCESS_RESULT))
        report = JobContext(job_dir).read_json(REPORT_FILE)
        self.assertEqual(result["state"], "failed")
        self.assertEqual(report["original_failure"]["detail"]["reason"],
                         "failure_journal_job_mismatch")
        self.assertEqual(journal_fingerprint(job_dir), before)
        self.assertNotIn(CANARY, json.dumps(report, sort_keys=True))
        self.assertFalse(os.path.exists(os.path.join(backup_dir, "COMPLETE")))


class ReleaseArchiveTest(unittest.TestCase):
    def test_release_archive_ships_the_failure_journal_module(self):
        import io
        import tarfile

        tmp = support.temp_state_dir("f2-release-")
        blob = build_release_archive(support.approved_manifest(tmp))
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
            names = {member.name for member in archive.getmembers()}
        self.assertIn("vps3xui/worker/failure_journal.py", names)


if __name__ == "__main__":
    unittest.main()
