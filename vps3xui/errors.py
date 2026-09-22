"""Stable error codes and exit-code classes for the P0 CLI.

Exit codes stay in small groups so a caller can branch on broad meaning:

* 0  success
* 2  contract/usage error (bad arguments, malformed manifest/plan/state)
* 3  precondition or conflict (drift, stale plan, idempotency conflict, lock)
* 4  execution error (remote command, unsupported environment, host failure)
* 5  verification failure (missing/corrupt artifact, unsafe archive)

The tool never returns raw child stderr, environment dumps, HTTP bodies or
traceback text in diagnostics. Error messages are curated strings.
"""

from __future__ import annotations

from typing import Optional

EXIT_OK = 0
EXIT_CONTRACT = 2
EXIT_PRECONDITION = 3
EXIT_EXECUTION = 4
EXIT_VERIFY = 5


class ExitClass(object):
    CONTRACT = "contract"
    PRECONDITION = "precondition"
    EXECUTION = "execution"
    VERIFY = "verify"


# code -> (exit code, exit class)
ERROR_CODES = {
    # contract / usage
    "E_CONTRACT": (EXIT_CONTRACT, ExitClass.CONTRACT),
    "E_MANIFEST_INVALID": (EXIT_CONTRACT, ExitClass.CONTRACT),
    "E_MANIFEST_NOT_APPROVED": (EXIT_CONTRACT, ExitClass.CONTRACT),
    "E_PLAN_INVALID": (EXIT_CONTRACT, ExitClass.CONTRACT),
    "E_UNSAFE_PATH": (EXIT_CONTRACT, ExitClass.CONTRACT),
    "E_UNSAFE_ID": (EXIT_CONTRACT, ExitClass.CONTRACT),
    "E_NOT_IMPLEMENTED": (EXIT_CONTRACT, ExitClass.CONTRACT),
    # precondition / conflict
    "E_INVENTORY_DRIFT": (EXIT_PRECONDITION, ExitClass.PRECONDITION),
    "E_MANIFEST_PENDING_APPROVAL": (EXIT_PRECONDITION, ExitClass.PRECONDITION),
    "E_REQUEST_ID_CONFLICT": (EXIT_PRECONDITION, ExitClass.PRECONDITION),
    "E_JOB_INCOMPLETE": (EXIT_PRECONDITION, ExitClass.PRECONDITION),
    "E_JOB_NOT_FOUND": (EXIT_PRECONDITION, ExitClass.PRECONDITION),
    "E_PLAN_STALE": (EXIT_PRECONDITION, ExitClass.PRECONDITION),
    "E_PLAN_EXPIRED": (EXIT_PRECONDITION, ExitClass.PRECONDITION),
    "E_HOST_KEY_UNKNOWN": (EXIT_PRECONDITION, ExitClass.PRECONDITION),
    "E_HOST_IDENTITY_MISMATCH": (EXIT_PRECONDITION, ExitClass.PRECONDITION),
    "E_LOCKED": (EXIT_PRECONDITION, ExitClass.PRECONDITION),
    "E_PRECONDITION": (EXIT_PRECONDITION, ExitClass.PRECONDITION),
    "E_CONFLICT": (EXIT_PRECONDITION, ExitClass.PRECONDITION),
    "E_PROBE_INCOMPLETE": (EXIT_PRECONDITION, ExitClass.PRECONDITION),
    "E_TRUST_MISMATCH": (EXIT_PRECONDITION, ExitClass.PRECONDITION),
    "E_NOT_OWNED": (EXIT_PRECONDITION, ExitClass.PRECONDITION),
    "E_UNIT_BUSY": (EXIT_PRECONDITION, ExitClass.PRECONDITION),
    "E_INTERRUPTED": (EXIT_PRECONDITION, ExitClass.PRECONDITION),
    # execution
    "E_EXECUTION": (EXIT_EXECUTION, ExitClass.EXECUTION),
    "E_UNSUPPORTED": (EXIT_EXECUTION, ExitClass.EXECUTION),
    "E_IMAGE_NOT_RESTORABLE": (EXIT_EXECUTION, ExitClass.EXECUTION),
    "E_RUNTIME_MISSING": (EXIT_EXECUTION, ExitClass.EXECUTION),
    "E_STATE_WRITE_FAILED": (EXIT_EXECUTION, ExitClass.EXECUTION),
    "E_RECOVERY_REQUIRED": (EXIT_EXECUTION, ExitClass.EXECUTION),
    # verification
    "E_VERIFY_FAILED": (EXIT_VERIFY, ExitClass.VERIFY),
    "E_MISSING_ARTIFACT": (EXIT_VERIFY, ExitClass.VERIFY),
    "E_HASH_MISMATCH": (EXIT_VERIFY, ExitClass.VERIFY),
    "E_UNSAFE_ARCHIVE": (EXIT_VERIFY, ExitClass.VERIFY),
    "E_SUMS_INVALID": (EXIT_VERIFY, ExitClass.VERIFY),
}


def exit_code_for(code: str) -> int:
    return ERROR_CODES.get(code, (EXIT_EXECUTION, ExitClass.EXECUTION))[0]


def exit_class_for(code: str) -> str:
    return ERROR_CODES.get(code, (EXIT_EXECUTION, ExitClass.EXECUTION))[1]


class ToolError(Exception):
    """A curated, safe error that maps to a stable code and exit class."""

    def __init__(
        self,
        code: str,
        message: str,
        resource: Optional[str] = None,
        next_action: Optional[str] = None,
    ):
        super(ToolError, self).__init__(message)
        self.code = code
        self.message = message
        self.resource = resource
        self.next_action = next_action

    @property
    def exit_code(self) -> int:
        return exit_code_for(self.code)

    def to_error_object(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "resource": self.resource,
            "next_action": self.next_action,
        }
