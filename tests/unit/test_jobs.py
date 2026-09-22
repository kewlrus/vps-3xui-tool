import tempfile
import unittest

import support
from vps3xui.errors import ToolError
from vps3xui.jobs import JobStore


class JobStoreTest(unittest.TestCase):
    def setUp(self):
        self.store = JobStore(tempfile.mkdtemp(prefix="jobs-"))

    def test_idempotent_registration_same_plan(self):
        first = self.store.register_request("req-1", "digest-a", "manifest-1", "vps-3xui")
        second = self.store.register_request("req-1", "digest-a", "manifest-1", "vps-3xui")
        self.assertEqual(first["request_id"], second["request_id"])
        self.assertEqual(first["registered_at"], second["registered_at"])

    def test_same_id_different_plan_conflicts(self):
        self.store.register_request("req-1", "digest-a", "manifest-1", "vps-3xui")
        with self.assertRaises(ToolError) as caught:
            self.store.register_request("req-1", "digest-b", "manifest-1", "vps-3xui")
        self.assertEqual(caught.exception.code, "E_REQUEST_ID_CONFLICT")

    def test_same_id_different_manifest_conflicts(self):
        self.store.register_request("req-1", "digest-a", "manifest-1", "vps-3xui")
        with self.assertRaises(ToolError):
            self.store.register_request("req-1", "digest-a", "manifest-2", "vps-3xui")

    def test_unsafe_request_id_rejected(self):
        with self.assertRaises(ToolError) as caught:
            self.store.register_request("../escape", "d", "m", "vps-3xui")
        self.assertEqual(caught.exception.code, "E_UNSAFE_ID")

    def test_incomplete_job_blocks_new_work(self):
        self.store.register_request("req-1", "digest-a", "manifest-1", "vps-3xui")
        with self.assertRaises(ToolError) as caught:
            self.store.assert_no_blocking_work()
        self.assertEqual(caught.exception.code, "E_JOB_INCOMPLETE")

    def test_terminal_jobs_do_not_block(self):
        self.store.register_request("req-1", "digest-a", "manifest-1", "vps-3xui")
        self.store.update_request("req-1", state="succeeded")
        self.store.assert_no_blocking_work()
        self.assertEqual(self.store.blocking_requests(), [])

    def test_failed_job_does_not_block_but_recovery_required_does(self):
        self.store.register_request("req-1", "d", "m", "vps-3xui")
        self.store.update_request("req-1", state="failed")
        self.store.assert_no_blocking_work()
        self.store.update_request("req-1", state="recovery_required")
        with self.assertRaises(ToolError):
            self.store.assert_no_blocking_work()

    def test_lock_is_exclusive(self):
        with self.store.lock():
            with self.assertRaises(ToolError) as caught:
                with self.store.lock():
                    pass
        self.assertEqual(caught.exception.code, "E_LOCKED")
        # After release the lock can be taken again.
        with self.store.lock():
            pass

    def test_locked_error_is_not_leaked_as_other_code(self):
        with self.store.lock():
            self.assertEqual(self.store.blocking_requests(), [])


if __name__ == "__main__":
    unittest.main()
