"""Command-line contract for the P0 tool.

Every command supports ``--json`` (a single result object on stdout) and maps
failures to stable ``error.code`` values with grouped exit codes. Diagnostics
are curated and bounded; raw child stderr, environment data and exception text
are never emitted.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, Callable, Dict, List, Optional

from . import TOOL_VERSION
from . import backup as backup_ops
from . import manifest as manifest_module
from .adapters.ssh import RemoteHostOps
from .errors import ToolError, exit_code_for
from .inventory import compare, probe_spec
from .plan import (
    DEFAULT_RUNTIME_MAX_SECONDS,
    DEFAULT_TIMEOUT_STOP_SECONDS,
    DEFAULT_TTL_SECONDS,
)
from .util import validate_id
HostFactory = Callable[[str], Any]


def _default_host_factory(alias: str):
    return RemoteHostOps(alias)


def _parser() -> argparse.ArgumentParser:
    parser = _ToolArgumentParser(
        prog="vps3xui",
        description="Inspect, plan and back up the vps-3xui Docker stack (P0).",
    )
    parser.add_argument("--version", action="version", version="vps3xui %s" % TOOL_VERSION)
    sub = parser.add_subparsers(dest="command", required=True)

    inspect = sub.add_parser("inspect", help="read-only inventory and drift check")
    inspect.add_argument("--host", required=True)
    inspect.add_argument("--manifest", dest="manifest_path")
    inspect.add_argument("--json", action="store_true")

    backup = sub.add_parser("backup", help="plan, start, verify and fetch a backup")
    backup_sub = backup.add_subparsers(dest="backup_command", required=True)

    plan = backup_sub.add_parser("plan", help="build an expiring machine-bound plan")
    plan.add_argument("--host", required=True)
    plan.add_argument("--manifest", dest="manifest_path", required=True)
    plan.add_argument("--out", required=True)
    plan.add_argument("--ttl-minutes", type=int, default=DEFAULT_TTL_SECONDS // 60)
    plan.add_argument("--runtime-max-seconds", type=int, default=DEFAULT_RUNTIME_MAX_SECONDS)
    plan.add_argument("--timeout-stop-seconds", type=int, default=DEFAULT_TIMEOUT_STOP_SECONDS)
    plan.add_argument("--json", action="store_true")

    start = backup_sub.add_parser("start", help="register and launch the autonomous backup")
    start.add_argument("--host", required=True)
    start.add_argument("--manifest", dest="manifest_path", required=True)
    start.add_argument("--plan", dest="plan_path", required=True)
    start.add_argument("--request-id", required=True)
    start.add_argument("--apply", action="store_true")
    start.add_argument("--state-dir", default=None)
    start.add_argument("--json", action="store_true")

    verify = backup_sub.add_parser("verify", help="verify a source job or a fetched copy")
    verify.add_argument("--host")
    verify.add_argument("--job")
    verify.add_argument("--directory")
    verify.add_argument("--manifest", dest="manifest_path", required=True)
    verify.add_argument("--state-dir", default=None)
    verify.add_argument("--json", action="store_true")

    fetch = backup_sub.add_parser("fetch", help="fetch a secret copy to a destination directory")
    fetch.add_argument("--host", required=True)
    fetch.add_argument("--manifest", dest="manifest_path", required=True)
    fetch.add_argument("--job", required=True)
    fetch.add_argument("--destination", required=True)
    fetch.add_argument("--state-dir", default=None)
    fetch.add_argument("--apply", action="store_true")
    fetch.add_argument("--json", action="store_true")

    job = sub.add_parser("job", help="read job state or recover a job")
    job_sub = job.add_subparsers(dest="job_command", required=True)

    status = job_sub.add_parser("status", help="read durable job state")
    status.add_argument("job_id")
    status.add_argument("--host", required=True)
    status.add_argument("--state-dir", default=None)
    status.add_argument("--json", action="store_true")

    recover = job_sub.add_parser("recover", help="run the independent recovery for a job")
    recover.add_argument("--host", required=True)
    recover.add_argument("--job", required=True)
    recover.add_argument("--state-dir", default=None)
    recover.add_argument("--wait-seconds", type=int, default=30)
    recover.add_argument("--apply", action="store_true")
    recover.add_argument("--json", action="store_true")

    return parser


def _emit(result: Dict[str, Any], as_json: bool) -> None:
    if as_json:
        json.dump(result, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
        return
    state = result.get("state")
    sys.stdout.write("state: %s\n" % state)
    for key in (
        "manifest_id",
        "plan_path",
        "job_id",
        "request_id",
        "backup_dir",
        "destination",
        "unit_name",
        "expires_at",
        "approved",
        "evidence",
    ):
        if result.get(key) is not None:
            sys.stdout.write("%s: %s\n" % (key, result[key]))
    if result.get("stop_containers"):
        sys.stdout.write("stop_containers: %s\n" % ", ".join(result["stop_containers"]))
    if result.get("warnings"):
        for item in result["warnings"]:
            sys.stdout.write("warning: %s (%s)\n" % (item["code"], item.get("resource")))
    error = result.get("error")
    if error:
        sys.stdout.write("error: %s: %s\n" % (error.get("code"), error.get("message")))


def _emit_error(error: ToolError, as_json: bool, command: Optional[str] = None) -> None:
    if as_json:
        json.dump(
            {
                "schema_version": 1,
                "command": command,
                "state": "blocked",
                "operation_complete": False,
                "error": error.to_error_object(),
            },
            sys.stdout,
            sort_keys=True,
        )
        sys.stdout.write("\n")
    else:
        sys.stderr.write("error: %s: %s\n" % (error.code, error.message))


def _load_manifest(path: Optional[str]):
    if not path:
        raise ToolError(
            "E_CONTRACT",
            "This command requires --manifest.",
            resource="manifest",
            next_action="pass_manifest",
        )
    return manifest_module.load(path)


def dispatch(args: argparse.Namespace, host_factory: HostFactory = _default_host_factory) -> Dict[str, Any]:
    if args.command == "inspect":
        manifest = _load_manifest(args.manifest_path)
        host = host_factory(args.host)
        inventory = host.probe(probe_spec(manifest))
        drift = compare(manifest, inventory)
        return {
            "schema_version": 1,
            "command": "inspect",
            "state": "ok" if drift.ok else "blocked",
            "operation_complete": drift.ok,
            "approved": manifest.approved,
            "manifest_id": manifest.manifest_id,
            "host": {
                "ssh_alias": manifest.ssh_alias,
                "machine_id": inventory.machine_id,
                "os": inventory.os,
                "arch": inventory.arch,
            },
            "inventory": inventory.to_object(),
            "drift": drift.to_object(),
            "error": None if drift.ok else drift.first_blocking_error().to_error_object(),
        }

    if args.command == "backup" and args.backup_command == "plan":
        manifest = _load_manifest(args.manifest_path)
        host = host_factory(args.host)
        plan, drift, _inventory, _fingerprint = backup_ops.run_plan(
            host,
            manifest,
            args.ttl_minutes * 60,
            runtime_max_seconds=args.runtime_max_seconds,
            timeout_stop_seconds=args.timeout_stop_seconds,
        )
        backup_ops.write_plan(plan, args.out)
        return backup_ops.plan_result(plan, args.out, drift)

    if args.command == "backup" and args.backup_command == "start":
        manifest = _load_manifest(args.manifest_path)
        host = host_factory(args.host)
        return backup_ops.run_start(
            host,
            manifest,
            args.plan_path,
            args.request_id,
            args.state_dir,
            args.apply,
        )

    if args.command == "backup" and args.backup_command == "verify":
        manifest = _load_manifest(args.manifest_path)
        if args.job:
            validate_id(args.job, "job_id")
        if args.directory:
            return backup_ops.run_verify_directory(manifest, args.directory)
        if not args.host or not args.job:
            raise ToolError(
                "E_CONTRACT",
                "backup verify needs either --directory or both --host and --job.",
                resource="verify",
                next_action="fix_arguments",
            )
        host = host_factory(args.host)
        return backup_ops.run_verify_job(host, manifest, args.job, args.state_dir)

    if args.command == "backup" and args.backup_command == "fetch":
        manifest = _load_manifest(args.manifest_path)
        validate_id(args.job, "job_id")
        host = host_factory(args.host)
        return backup_ops.run_fetch(
            host, manifest, args.job, args.destination, args.state_dir, args.apply
        )

    if args.command == "job" and args.job_command == "status":
        validate_id(args.job_id, "job_id")
        host = host_factory(args.host)
        return backup_ops.run_status(host, args.job_id, args.state_dir)

    if args.command == "job" and args.job_command == "recover":
        validate_id(args.job, "job_id")
        host = host_factory(args.host)
        return backup_ops.run_recover(
            host, args.job, args.state_dir, args.apply, wait_seconds=args.wait_seconds
        )

    raise ToolError("E_CONTRACT", "Unsupported command.", resource=args.command)


class _ToolArgumentParser(argparse.ArgumentParser):
    """argparse variant that raises ToolError instead of printing/exiting."""

    def error(self, message):  # noqa: D401 - argparse hook
        # Never reflect arbitrary argument text (which can be a secret or a
        # hostile string); echo only a sanitized option token when present.
        detail = ""
        match = re.search(r"--?[A-Za-z][A-Za-z0-9-]*", message or "")
        if match:
            detail = " (%s)" % match.group(0)
        raise ToolError(
            "E_CONTRACT",
            "Invalid command line%s." % detail,
            resource="cli",
            next_action="check_help",
        )


def _safe_message(message: str) -> str:
    """Bound and strip anything that could reflect arbitrary input."""
    text = " ".join(str(message).split())
    return text[:200]


def _parse_args(argv: Optional[List[str]]):
    parser = _parser()
    try:
        return parser.parse_args(argv)
    except SystemExit as exc:  # --help/--version request a clean exit
        raise _CleanExit(int(exc.code or 0))


class _CleanExit(Exception):
    def __init__(self, code: int):
        super(_CleanExit, self).__init__("clean exit")
        self.code = code


def _wants_json(argv: Optional[List[str]]) -> bool:
    tokens = list(sys.argv[1:] if argv is None else argv)
    return "--json" in tokens


def _command_name(args: Optional[argparse.Namespace]) -> Optional[str]:
    if args is None:
        return None
    parts = [getattr(args, "command", None)]
    for extra in ("backup_command", "job_command"):
        value = getattr(args, extra, None)
        if value:
            parts.append(value)
    parts = [part for part in parts if part]
    return ".".join(parts) if parts else None


def main(argv: Optional[List[str]] = None, host_factory: HostFactory = _default_host_factory) -> int:
    as_json = _wants_json(argv)
    args = None
    try:
        args = _parse_args(argv)
        as_json = bool(getattr(args, "json", False)) or as_json
        result = dispatch(args, host_factory=host_factory)
    except _CleanExit as clean:
        return clean.code
    except ToolError as error:
        _emit_error(error, as_json, _command_name(args))
        return error.exit_code
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        # A boundary failure must never emit a traceback or reflected input.
        error = ToolError(
            "E_EXECUTION",
            "The command failed at its boundary (%s)." % type(exc).__name__,
            resource=_command_name(args),
            next_action="retry_or_inspect",
        )
        _emit_error(error, as_json, _command_name(args))
        return error.exit_code
    except Exception as exc:  # noqa: BLE001 - never leak a traceback
        error = ToolError(
            "E_EXECUTION",
            "Unexpected failure (%s)." % type(exc).__name__,
            resource=_command_name(args),
            next_action="retry_or_inspect",
        )
        _emit_error(error, as_json, _command_name(args))
        return error.exit_code
    _emit(result, getattr(args, "json", False) or as_json)
    if result.get("error") and not result.get("operation_complete"):
        code = (result.get("error") or {}).get("code")
        return exit_code_for(code) if code else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
