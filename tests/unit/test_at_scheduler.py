"""Pending ``at``/batch jobs must block a P0 backup conservatively.

The shipped probe reports only bounded ``at`` queue facts (tool presence,
per-spool directory state and a job count). These tests run the real
``probe_at`` helper against a remapped temporary spool tree and a faked command
boundary, then drive the real ``compare``/``build_plan``/``verify_plan`` and
worker-preflight code. No real ``atq``/``at``/``atd`` ever runs and no host
spool directory is read.
"""

import contextlib
import json
import os
import shutil
import sys
import tempfile
import unittest

import support
from vps3xui import probe as probe_module
from vps3xui.errors import ToolError
from vps3xui.inventory import Inventory, compare
from vps3xui.plan import build_plan, verify_plan
from vps3xui.worker.backup_worker import BackupWorker

ATJOBS = "/var/spool/cron/atjobs"
ATSPOOL = "/var/spool/cron/atspool"
ATDIR = "/var/spool/at"
ATJOBS_NESTED = "/var/spool/at/jobs"
ATOUT = "/var/spool/at/spool"

ABSENT_QUEUE = {
    "tooling": {"at": None, "atq": None},
    "state": "absent",
    "atq": {"present": False, "observed": False, "count": None},
    "directories": [],
}


def _host_path(root, path):
    return os.path.join(root, path.lstrip("/"))


def _mkdir(root, path):
    os.makedirs(_host_path(root, path), exist_ok=True)


def _write_job(root, directory, name, body="true\n"):
    target = os.path.join(_host_path(root, directory), name)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(body)
    return target


def _snapshot(path):
    entries = []
    for name in sorted(os.listdir(path)):
        with open(os.path.join(path, name), "rb") as handle:
            entries.append((name, handle.read()))
    return entries


@contextlib.contextmanager
def remapped_at_probe(root, *, which=None, lines_run=None, listdir=None):
    """Run ``probe_at`` against ``root`` with a faked command boundary.

    Every absolute path the probe looks up is remapped under ``root`` so the
    real host spool is never touched; ``shutil.which`` and the bounded ``atq``
    helper (the command boundary) are replaced so no process is ever started.
    """
    real_lstat = os.lstat
    real_listdir = os.listdir
    real_which = probe_module.shutil.which
    real_lines = probe_module._run_bounded_lines

    def remap(path):
        if isinstance(path, (str, os.PathLike)):
            text = os.fspath(path)
            if text.startswith("/"):
                return _host_path(root, text)
        return path

    def lstat_remap(path, *args, **kwargs):
        return real_lstat(remap(path), *args, **kwargs)

    def listdir_remap(path=".", *args, **kwargs):
        if listdir is not None:
            return listdir(path, *args, **kwargs)
        return real_listdir(remap(path), *args, **kwargs)

    probe_module.shutil.which = lambda name: (which or {}).get(name)
    probe_module._run_bounded_lines = (
        lines_run if lines_run is not None
        else (lambda argv, timeout, max_bytes, max_lines: (127, 0, False)))
    os.lstat = lstat_remap
    os.listdir = listdir_remap
    try:
        yield
    finally:
        os.lstat = real_lstat
        os.listdir = real_listdir
        probe_module.shutil.which = real_which
        probe_module._run_bounded_lines = real_lines


def _probe_at(root, **kwargs):
    errors = []
    with remapped_at_probe(root, **kwargs):
        facts = probe_module.probe_at(errors)
    return facts, errors


class ProbeAtDiscoveryTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="at-spool-")
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_absent_installation_is_supported(self):
        facts, errors = _probe_at(self.root)
        self.assertEqual(facts["state"], "absent")
        self.assertEqual(facts["directories"], [])
        self.assertEqual(errors, [])

    def test_empty_spool_is_supported(self):
        _mkdir(self.root, ATJOBS)
        facts, errors = _probe_at(self.root)
        self.assertEqual(facts["state"], "empty")
        self.assertEqual(errors, [])
        self.assertEqual(facts["directories"],
                         [{"path": ATJOBS, "state": "empty", "jobs": 0}])

    def test_at_installed_without_usable_queue_is_unknown(self):
        # ``at`` exists but neither ``atq`` nor a recognised spool is
        # inspectable: the queue must not read as absent/empty.
        facts, errors = _probe_at(self.root, which={"at": "/usr/bin/at"})
        self.assertEqual(facts["state"], "unknown")
        self.assertEqual(facts["directories"], [])
        self.assertIn("at_queue_unknown", errors)

    def test_at_installed_with_empty_spool_is_supported(self):
        _mkdir(self.root, ATJOBS)
        facts, errors = _probe_at(self.root, which={"at": "/usr/bin/at"})
        self.assertEqual(facts["state"], "empty")
        self.assertEqual(errors, [])

    def test_simple_queued_job_is_occupied(self):
        _write_job(self.root, ATJOBS, "a0000101")
        facts, errors = _probe_at(self.root)
        self.assertEqual(facts["state"], "occupied")
        self.assertEqual(errors, [])
        self.assertEqual([entry["jobs"] for entry in facts["directories"]], [1])

    def test_wrapper_body_is_never_read_and_still_blocks(self):
        # A wrapper/indirection with no literal "certbot" text still blocks:
        # only the queued file's presence is used, never its body.
        _write_job(self.root, ATJOBS, "b0000202",
                   body="#!/bin/sh\nexec $HOME/lib/renew.sh\n")
        facts, errors = _probe_at(self.root)
        self.assertEqual(facts["state"], "occupied")
        blob = json.dumps(facts)
        self.assertNotIn("b0000202", blob)
        self.assertNotIn("renew.sh", blob)

    def test_all_documented_spool_variants_are_observed(self):
        _write_job(self.root, ATJOBS, "a0000101")
        _write_job(self.root, ATDIR, "a0000102")
        _write_job(self.root, ATJOBS_NESTED, "a0000103")
        # Known output/metadata directories must neither count nor error.
        _mkdir(self.root, ATOUT)
        _mkdir(self.root, ATSPOOL)
        facts, errors = _probe_at(self.root)
        self.assertEqual(facts["state"], "occupied")
        self.assertEqual(errors, [])
        counts = {entry["path"]: entry["jobs"] for entry in facts["directories"]}
        self.assertEqual(counts[ATJOBS], 1)
        self.assertEqual(counts[ATDIR], 1)          # nested jobs/spool skipped
        self.assertEqual(counts[ATJOBS_NESTED], 1)

    def test_metadata_only_spool_is_empty(self):
        _mkdir(self.root, ATDIR)
        _mkdir(self.root, ATOUT)
        _mkdir(self.root, ATSPOOL)
        facts, errors = _probe_at(self.root)
        self.assertEqual(facts["state"], "empty")
        self.assertEqual(errors, [])

    def test_control_file_only_spool_is_empty(self):
        _write_job(self.root, ATJOBS, ".SEQ", body="1\n")
        facts, errors = _probe_at(self.root)
        self.assertEqual(facts["state"], "empty")
        self.assertEqual(errors, [])
        self.assertEqual([entry["jobs"] for entry in facts["directories"]], [0])
        self.assertNotIn(".SEQ", json.dumps(facts))

    def test_control_file_symlink_is_unknown(self):
        _mkdir(self.root, ATJOBS)
        _write_job(self.root, ATDIR, "real")
        os.symlink(_host_path(self.root, ATDIR) + "/real",
                   os.path.join(_host_path(self.root, ATJOBS), ".SEQ"))
        facts, errors = _probe_at(self.root)
        self.assertEqual(facts["state"], "unknown")
        self.assertIn("at_queue_unknown", errors)

    def test_control_file_directory_is_unknown(self):
        _mkdir(self.root, ATJOBS)
        os.makedirs(os.path.join(_host_path(self.root, ATJOBS), ".SEQ"))
        facts, errors = _probe_at(self.root)
        self.assertEqual(facts["state"], "unknown")
        self.assertIn("at_queue_unknown", errors)

    def test_oversized_spool_is_unknown(self):
        _write_job(self.root, ATJOBS, "a1")
        _write_job(self.root, ATJOBS, "a2")
        _write_job(self.root, ATJOBS, "a3")
        original = probe_module.AT_SPOOL_MAX_ENTRIES
        probe_module.AT_SPOOL_MAX_ENTRIES = 2
        try:
            facts, errors = _probe_at(self.root)
        finally:
            probe_module.AT_SPOOL_MAX_ENTRIES = original
        self.assertEqual(facts["state"], "unknown")
        self.assertIn("at_queue_unknown", errors)

    def test_unreadable_spool_is_incomplete(self):
        _write_job(self.root, ATJOBS, "a0000101")

        def listdir(path=".", *args, **kwargs):
            if os.fspath(path) == ATJOBS:
                raise PermissionError("denied")
            return []

        facts, errors = _probe_at(self.root, listdir=listdir)
        self.assertEqual(facts["state"], "unknown")
        self.assertIn("at_queue_unreadable", errors)

    def test_nonregular_spool_path_is_incomplete(self):
        target = _host_path(self.root, ATDIR)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("not a directory\n")
        facts, errors = _probe_at(self.root)
        self.assertEqual(facts["state"], "unknown")
        self.assertIn("at_queue_unknown", errors)

    def test_symlinked_spool_path_is_incomplete(self):
        _mkdir(self.root, ATSPOOL)
        link = _host_path(self.root, ATJOBS)
        os.makedirs(os.path.dirname(link), exist_ok=True)
        os.symlink(_host_path(self.root, ATSPOOL), link)
        facts, errors = _probe_at(self.root)
        self.assertEqual(facts["state"], "unknown")
        self.assertIn("at_queue_unknown", errors)

    def test_unknown_entry_inside_spool_is_incomplete(self):
        _mkdir(self.root, ATJOBS)
        os.symlink(_host_path(self.root, ATJOBS),
                   os.path.join(_host_path(self.root, ATJOBS), "sneaky"))
        facts, errors = _probe_at(self.root)
        self.assertEqual(facts["state"], "unknown")
        self.assertIn("at_queue_unknown", errors)

    def test_atq_reporting_jobs_is_occupied(self):
        lines_run = lambda argv, timeout, max_bytes, max_lines: (0, 2, False)
        facts, errors = _probe_at(self.root, which={"atq": "/usr/bin/atq"},
                                  lines_run=lines_run)
        self.assertEqual(facts["state"], "occupied")
        self.assertEqual(facts["atq"]["count"], 2)
        self.assertEqual(errors, [])

    def test_atq_failure_is_incomplete(self):
        lines_run = lambda argv, timeout, max_bytes, max_lines: (1, 0, False)
        facts, errors = _probe_at(self.root, which={"atq": "/usr/bin/atq"},
                                  lines_run=lines_run)
        self.assertEqual(facts["state"], "unknown")
        self.assertIn("at_queue_unreadable", errors)

    def test_atq_overflow_is_incomplete(self):
        lines_run = lambda argv, timeout, max_bytes, max_lines: (127, 0, True)
        facts, errors = _probe_at(self.root, which={"atq": "/usr/bin/atq"},
                                  lines_run=lines_run)
        self.assertEqual(facts["state"], "unknown")
        self.assertIn("at_queue_unknown", errors)

    def test_atq_facts_retain_only_a_count(self):
        lines_run = lambda argv, timeout, max_bytes, max_lines: (0, 1, False)
        facts, errors = _probe_at(self.root, which={"atq": "/usr/bin/atq"},
                                  lines_run=lines_run)
        self.assertEqual(set(facts["atq"]), {"present", "observed", "count"})
        self.assertIsInstance(facts["atq"]["count"], int)

    def test_probe_does_not_mutate_or_leak_the_spool(self):
        canary = "CANARY-JOB-BODY"
        _write_job(self.root, ATJOBS, "a0000101",
                   body="#!/bin/sh\n%s\n" % canary)
        before = _snapshot(_host_path(self.root, ATJOBS))
        facts, errors = _probe_at(self.root)
        after = _snapshot(_host_path(self.root, ATJOBS))
        self.assertEqual(before, after)
        self.assertNotIn(canary, json.dumps(facts))
        self.assertEqual(facts["state"], "occupied")


class BoundedAtqCaptureTest(unittest.TestCase):
    """The bounded ``atq`` helper must cap bytes, lines and time."""

    def _run(self, code, timeout=10, max_bytes=64 * 1024, max_lines=100):
        return probe_module._run_bounded_lines(
            [sys.executable, "-c", code], timeout, max_bytes, max_lines)

    def test_counts_nonblank_lines_and_discards_output(self):
        self.assertEqual(self._run("import sys; sys.stdout.write('a\\n\\nb\\n')"),
                         (0, 2, False))

    def test_byte_overflow_is_reported(self):
        code, count, overflow = self._run(
            "import sys; sys.stdout.write('x' * 4096)", max_bytes=1024)
        self.assertTrue(overflow)

    def test_line_overflow_is_reported(self):
        code, count, overflow = self._run(
            "import sys; sys.stdout.write('a\\nb\\nc\\nd\\n')", max_lines=2)
        self.assertTrue(overflow)

    def test_timeout_is_bounded(self):
        self.assertEqual(self._run("import time; time.sleep(30)", timeout=1),
                         (127, 0, False))


class AtQueueCompareTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="at-compare-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.manifest = support.approved_manifest(self.tmp)

    def _report(self, **overrides):
        return compare(self.manifest,
                       Inventory.from_probe(support.synthetic_probe(**overrides)))

    def _codes(self, report):
        return [item.code for item in report.blocking]

    def _resources(self, report):
        return [item.resource for item in report.blocking]

    def test_default_empty_queue_is_supported(self):
        self.assertTrue(self._report().ok)

    def test_missing_queue_fact_blocks(self):
        probe = support.synthetic_probe()
        probe.pop("at_queue")
        report = compare(self.manifest, Inventory.from_probe(probe))
        self.assertIn("E_PROBE_INCOMPLETE", self._codes(report))
        self.assertIn("at_queue", self._resources(report))

    def test_non_dict_queue_fact_blocks(self):
        report = self._report(at_queue="not-a-mapping")
        self.assertIn("E_PROBE_INCOMPLETE", self._codes(report))

    def test_pending_job_in_spool_is_conflict(self):
        at_queue = {
            "tooling": {"at": "/usr/bin/at", "atq": "/usr/bin/atq"},
            "state": "occupied",
            "atq": {"present": True, "observed": True, "count": 1},
            "directories": [{"path": ATJOBS, "state": "occupied", "jobs": 1}],
        }
        report = self._report(at_queue=at_queue)
        self.assertIn("E_CONFLICT", self._codes(report))
        self.assertIn("at:%s" % ATJOBS, self._resources(report))

    def test_atq_count_without_spool_is_conflict(self):
        at_queue = {
            "tooling": {"at": None, "atq": "/usr/bin/atq"},
            "state": "occupied",
            "atq": {"present": True, "observed": True, "count": 3},
            "directories": [],
        }
        report = self._report(at_queue=at_queue)
        self.assertIn("E_CONFLICT", self._codes(report))
        self.assertIn("at:queue", self._resources(report))

    def test_unknown_state_without_error_token_blocks(self):
        at_queue = {
            "tooling": {"at": None, "atq": None},
            "state": "unknown",
            "atq": {"present": False, "observed": False, "count": None},
            "directories": [{"path": ATDIR, "state": "unknown", "jobs": None}],
        }
        report = self._report(at_queue=at_queue)   # no error token supplied
        self.assertIn("E_PROBE_INCOMPLETE", self._codes(report))

    def test_unobserved_atq_blocks(self):
        at_queue = {
            "tooling": {"at": "/usr/bin/at", "atq": "/usr/bin/atq"},
            "state": "empty",
            "atq": {"present": True, "observed": False, "count": None},
            "directories": [],
        }
        report = self._report(at_queue=at_queue)
        self.assertIn("E_PROBE_INCOMPLETE", self._codes(report))

    def test_empty_state_without_evidence_blocks(self):
        at_queue = {
            "tooling": {"at": None, "atq": None},
            "state": "empty",
            "atq": {"present": False, "observed": False, "count": None},
            "directories": [],
        }
        report = self._report(at_queue=at_queue)
        self.assertIn("E_PROBE_INCOMPLETE", self._codes(report))

    def test_malformed_section_blocks_without_traceback(self):
        report = self._report(at_queue={"state": "empty"})
        self.assertIn("E_PROBE_INCOMPLETE", self._codes(report))

    def test_unrecognised_state_blocks(self):
        at_queue = {
            "tooling": {"at": None, "atq": None},
            "state": "banana",
            "atq": {"present": False, "observed": False, "count": None},
            "directories": [],
        }
        report = self._report(at_queue=at_queue)
        self.assertIn("E_PROBE_INCOMPLETE", self._codes(report))

    def test_malformed_directory_entry_blocks(self):
        at_queue = {
            "tooling": {"at": None, "atq": None},
            "state": "empty",
            "atq": {"present": False, "observed": False, "count": None},
            "directories": [{"path": ATJOBS}],
        }
        report = self._report(at_queue=at_queue)
        self.assertIn("E_PROBE_INCOMPLETE", self._codes(report))

    def test_mislabelled_count_is_conflict(self):
        # State says empty but a spool reports a positive count: occupied wins.
        at_queue = {
            "tooling": {"at": None, "atq": None},
            "state": "empty",
            "atq": {"present": False, "observed": False, "count": None},
            "directories": [{"path": ATJOBS, "state": "empty", "jobs": 2}],
        }
        report = self._report(at_queue=at_queue)
        self.assertIn("E_CONFLICT", self._codes(report))
        self.assertIn("at:%s" % ATJOBS, self._resources(report))

    def test_mislabelled_atq_count_is_conflict(self):
        at_queue = {
            "tooling": {"at": None, "atq": "/usr/bin/atq"},
            "state": "empty",
            "atq": {"present": True, "observed": True, "count": 2},
            "directories": [],
        }
        report = self._report(at_queue=at_queue)
        self.assertIn("E_CONFLICT", self._codes(report))
        self.assertIn("at:queue", self._resources(report))

    def test_occupied_state_without_evidence_is_conflict(self):
        at_queue = {
            "tooling": {"at": None, "atq": None},
            "state": "occupied",
            "atq": {"present": False, "observed": False, "count": None},
            "directories": [],
        }
        report = self._report(at_queue=at_queue)
        self.assertIn("E_CONFLICT", self._codes(report))
        self.assertIn("at:queue", self._resources(report))

    def test_absent_state_with_observed_facts_blocks(self):
        at_queue = {
            "tooling": {"at": "/usr/bin/at", "atq": "/usr/bin/atq"},
            "state": "absent",
            "atq": {"present": False, "observed": False, "count": None},
            "directories": [],
        }
        report = self._report(at_queue=at_queue)
        self.assertIn("E_PROBE_INCOMPLETE", self._codes(report))


class AtQueuePlanStalenessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="at-plan-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.manifest = support.approved_manifest(self.tmp)

    def test_new_empty_spool_stales_a_plan(self):
        inventory0 = Inventory.from_probe(support.synthetic_probe(at_queue=ABSENT_QUEUE))
        plan = build_plan(self.manifest, inventory0, support.HOST_KEY)
        inventory1 = Inventory.from_probe(support.synthetic_probe(at_queue={
            "tooling": {"at": "/usr/bin/at", "atq": "/usr/bin/atq"},
            "state": "empty",
            "atq": {"present": True, "observed": True, "count": 0},
            "directories": [{"path": ATJOBS, "state": "empty", "jobs": 0}],
        }))
        with self.assertRaises(ToolError) as caught:
            verify_plan(plan, self.manifest, inventory1, support.HOST_KEY)
        self.assertEqual(caught.exception.code, "E_PLAN_STALE")

    def test_job_added_after_plan_blocks_worker_preflight(self):
        inventory0 = Inventory.from_probe(support.synthetic_probe(at_queue=ABSENT_QUEUE))
        plan = build_plan(self.manifest, inventory0, support.HOST_KEY)
        job_dir = os.path.join(self.tmp, "jobs", "req-at-1")
        backup_dir = os.path.join(self.tmp, "backups", "req-at-1")
        support.seed_job(job_dir, {
            "schema_version": 1,
            "request_id": "req-at-1",
            "job_id": "req-at-1",
            "manifest_id": self.manifest.manifest_id,
            "plan_digest": plan["identity"],
            "machine_id": support.MACHINE_ID,
            "host_key_fingerprint": support.HOST_KEY,
            "backup_dir": backup_dir,
            "stop_containers": plan["stop_containers"],
            "leave_stopped": plan["leave_stopped"],
            "required_bytes_estimate": 5_000_000_000,
        }, plan, self.manifest)
        system = support.SyntheticSystem(self.manifest, os.path.join(self.tmp, "system"))
        later = Inventory.from_probe(support.synthetic_probe(at_queue={
            "tooling": {"at": "/usr/bin/at", "atq": "/usr/bin/atq"},
            "state": "occupied",
            "atq": {"present": True, "observed": True, "count": 1},
            "directories": [{"path": ATJOBS, "state": "occupied", "jobs": 1}],
        }))
        worker = BackupWorker(system, job_dir, self.manifest, probe=lambda spec: later)
        with self.assertRaises(ToolError) as caught:
            worker._preflight()
        self.assertIn(caught.exception.code, ("E_CONFLICT", "E_PLAN_STALE"))
        self.assertFalse(worker.changes_started)


if __name__ == "__main__":
    unittest.main()
