"""The small host interface used by the core CLI.

Two implementations exist: ``adapters.ssh.RemoteHostOps`` (real OpenSSH) and
``tests.support.SyntheticHost`` (in-process, used by the test suite). Core
logic never calls subprocess directly, which is what makes the fault tests
meaningful rather than a mock of the code under test.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .inventory import Inventory


class HostOps(object):
    alias = ""  # type: str

    def fingerprint(self) -> str:
        """Verified SSH host key fingerprint (SHA256:...)."""
        raise NotImplementedError

    def probe(self, spec: Optional[Dict[str, Any]] = None, timeout: int = 90) -> Inventory:
        """Run the shipped read-only probe with a manifest-derived spec."""
        raise NotImplementedError

    def read_json_file(self, remote_path: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    def path_exists(self, remote_path: str) -> bool:
        raise NotImplementedError

    def list_dir(self, remote_path: str) -> List[str]:
        raise NotImplementedError

    def write_file(self, remote_path: str, data: bytes, mode: int = 0o600) -> None:
        raise NotImplementedError

    def ensure_release(self, release_dir: str, archive: bytes) -> str:
        """Deliver and verify the pinned release; return its sha256."""
        raise NotImplementedError

    def launch_backup(self, unit_name: str, release_dir: str, job_dir: str,
                      runtime_max_seconds: int, timeout_stop_seconds: int) -> None:
        raise NotImplementedError

    def launch_recover(self, unit_name: str, release_dir: str, job_dir: str) -> None:
        raise NotImplementedError

    def remote_verify(self, release_dir: str, backup_dir: str, manifest_path: str) -> Dict[str, Any]:
        """Run the pinned verifier on the host and return its JSON result."""
        raise NotImplementedError

    def reserve_and_launch(self, root: str, job_dir: str, request_payload: Dict[str, Any],
                           plan_payload: Dict[str, Any], launch: Dict[str, Any]) -> Dict[str, Any]:
        """Atomically reserve a job under the host stack lock and launch it.

        Must refuse while another job is still blocking, write the immutable
        request/plan, launch the unit, and be idempotent for a repeated request
        id. Returns the remote coordination result object.
        """
        raise NotImplementedError

    def remote_job_status(self, root: str, job_id: str) -> Dict[str, Any]:
        """Durable, reconciled remote job status (authoritative)."""
        raise NotImplementedError

    def remote_recover(self, root: str, job_id: str) -> Dict[str, Any]:
        """Launch the fixed recover unit for an owned job under the stack lock."""
        raise NotImplementedError

    def host_context(self) -> Dict[str, Any]:
        """Resolved connection identity bound into the plan (host/port/user/key)."""
        return {"ssh_alias": self.alias}

    def fetch_file(self, remote_path: str, local_path: str) -> None:
        raise NotImplementedError
