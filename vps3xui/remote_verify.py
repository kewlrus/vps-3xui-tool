"""Pinned-module entry for verifying a backup directory on the host.

Run as ``python3 -m vps3xui.remote_verify --directory DIR --manifest FILE`` from
the delivered release, so the host uses exactly the same verification code as
the local CLI. It never prints file contents, only the verification summary.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import manifest as manifest_module
from .errors import ToolError, exit_code_for
from .verify import verify_directory


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="vps3xui.remote_verify")
    parser.add_argument("--directory", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args(argv)
    try:
        manifest = manifest_module.load(args.manifest)
        result = verify_directory(args.directory, manifest, require_complete=True)
        json.dump(result.to_object(), sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
        if not result.ok and result.error is not None:
            return exit_code_for(result.error.code)
        return 0
    except ToolError as error:
        json.dump({"ok": False, "error": error.to_error_object()}, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
        return error.exit_code


if __name__ == "__main__":
    sys.exit(main())
