#!/usr/bin/env python3
"""Portable part of the vps3xui restore drill.

Runs locally with synthetic fixtures only (no VM, no Docker, no network). It
builds a complete synthetic backup, verifies it portably, extracts it into
separate fresh destinations and asserts the drill properties that do not need a
real Docker/systemd host:

* a complete copy verifies and a partial copy does not;
* named volume archives restore into their own destinations;
* the two declared Fail2ban destinations do not merge;
* restored secret files keep mode 0600;
* the Let's Encrypt relative link stays inside the tree;
* UFW reference archives are never applied;
* a worker killed mid-copy leaves no COMPLETE marker and the finalizer never
  declares success; the recorded containers are restarted;
* GNU tar metadata (mode and numeric owner) round-trips when GNU tar exists.

The full VM-only part (real Docker volumes, create-stopped container, bounded
systemd worker/finalizer with SIGKILL/timeout/transport loss) lives in
``vm-restore-drill.sh`` and reports NOT RUN without a disposable Linux host.

Exit codes: 0 all portable checks passed; 1 a check failed; 3 not run (missing
dependencies such as the test harness).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (os.path.join(REPO_ROOT, "tests"), REPO_ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)


def _fail_environment(message: str) -> int:
    sys.stderr.write("NOT RUN: %s\n" % message)
    return 3


try:
    import support  # noqa: E402  (tests/support.py)
    from vps3xui.util import read_json  # noqa: E402
    from vps3xui.verify import verify_directory  # noqa: E402
    from vps3xui.worker import finalizer  # noqa: E402
    from vps3xui.worker.backup_worker import BackupWorker  # noqa: E402
    from vps3xui.worker.jobctx import (  # noqa: E402
        REQUEST_FILE,
        STATE_FILE,
        JobContext,
    )
except Exception as error:  # noqa: BLE001 - report a bounded NOT RUN reason
    raise SystemExit(_fail_environment("the Python tool/harness is unavailable (%s)" % type(error).__name__))


FAILURES = []
CHECKS = []


def check(label: str, ok: bool, detail: str = "") -> None:
    CHECKS.append(label)
    if ok:
        print("  - PASS %s%s" % (label, (" (%s)" % detail) if detail else ""))
    else:
        FAILURES.append(label)
        print("  - FAIL %s%s" % (label, (" (%s)" % detail) if detail else ""))


def _extract(archive: str, destination: str) -> None:
    os.makedirs(destination, mode=0o700, exist_ok=True)
    with tarfile.open(archive, "r:*") as handle:
        handle.extractall(destination)


def _find_basename(root: str, name: str):
    for base, _dirs, files in os.walk(root):
        if name in files:
            return os.path.join(base, name)
    return None


def _run_killed_backup(tmp: str):
    from vps3xui.inventory import Inventory
    from vps3xui.plan import build_plan

    manifest = support.approved_manifest(tmp)
    inventory = Inventory.from_probe(support.synthetic_probe())
    plan = build_plan(manifest, inventory, support.HOST_KEY)
    job_dir = os.path.join(tmp, "jobs", "req-kill-1")
    backup_dir = os.path.join(tmp, "backups", "req-kill-1")
    support.seed_job(job_dir, {
        "schema_version": 1,
        "request_id": "req-kill-1",
        "job_id": "req-kill-1",
        "manifest_id": manifest.manifest_id,
        "plan_digest": plan["identity"],
        "machine_id": support.MACHINE_ID,
        "host_key_fingerprint": support.HOST_KEY,
        "backup_dir": backup_dir,
        "stop_containers": plan["stop_containers"],
        "leave_stopped": plan["leave_stopped"],
        "required_bytes_estimate": 5_000_000_000,
    }, plan, manifest)
    system = support.SyntheticSystem(manifest, os.path.join(tmp, "system"),
                                     faults={"kill_during_copy": True})
    worker = BackupWorker(system, job_dir, manifest)
    try:
        worker.run()
    except support.KillWorker:
        pass
    # ExecStopPost equivalent: the independent finalizer always runs.
    finalizer.recover(job_dir, system, manifest)
    report = read_json(os.path.join(job_dir, "report.json")) or {}
    return manifest, backup_dir, report, system


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="vps3xui-portable-")
    print("portable restore drill: building a synthetic complete backup")
    manifest, backup_dir, report, _system = support.complete_backup(tmp)
    check("synthetic backup reached succeeded", report.get("state") == "succeeded",
          str(report.get("state")))
    result = verify_directory(backup_dir, manifest, require_complete=True)
    check("complete copy verifies portably", result.ok,
          result.error.message if result.error else "")

    # A partial copy (COMPLETE removed) must not verify.
    partial = os.path.join(tmp, "partial")
    shutil.copytree(backup_dir, partial)
    os.unlink(os.path.join(partial, "COMPLETE"))
    partial_result = verify_directory(partial, manifest, require_complete=True)
    check("partial copy is rejected", not partial_result.ok)

    targets = os.path.join(tmp, "restore")
    os.makedirs(targets, mode=0o700)

    # Named volume archives restore into their own destinations.
    volumes_ok = True
    for volume in manifest.volumes:
        dest = os.path.join(targets, "volumes", volume["name"])
        _extract(os.path.join(backup_dir, volume["artifact"]), dest)
        if not os.listdir(dest):
            volumes_ok = False
    check("named volume archives restore into separate destinations", volumes_ok)

    # The two declared Fail2ban destinations must not merge.
    layer_dirs = {}
    for layer in manifest.writable_layers:
        dest = os.path.join(targets, "layers", layer["container"] + layer["path"].replace("/", "_"))
        _extract(os.path.join(backup_dir, layer["artifact"]), dest)
        layer_dirs[layer["path"]] = dest
    check("Fail2ban config/data restore into separate destinations",
          layer_dirs.get("/etc/fail2ban") != layer_dirs.get("/var/lib/fail2ban"))

    # Restored secret files keep 0600.
    auth = _find_basename(os.path.join(targets, "volumes", "llmproxy_chatgpt_auth"), "auth.json")
    if auth is None:
        check("restored chatgpt auth file is present", False, "auth.json not found")
    else:
        mode = oct(os.stat(auth).st_mode & 0o777)
        check("restored chatgpt auth file is mode 0600", mode == "0o600", mode)

    # Let's Encrypt relative link stays inside the tree.
    certbot_root = os.path.join(targets, "letsencrypt")
    _extract(os.path.join(backup_dir, "binds.tar"), certbot_root)
    live = os.path.join(certbot_root, "etc/letsencrypt/live/kewlsub.duckdns.org/cert.pem")
    link_ok = False
    if os.path.islink(live):
        resolved = os.path.realpath(live)
        link_ok = resolved.startswith(os.path.realpath(certbot_root) + os.sep)
    check("Let's Encrypt relative link resolves inside the tree", link_ok)

    # UFW reference archives are never applied.
    ufw_applied = os.path.exists(os.path.join(certbot_root, "etc/ufw"))
    check("UFW reference archive was not applied", not ufw_applied)

    # Bounded worker: SIGKILL mid-copy leaves no COMPLETE and never succeeds.
    kill_tmp = tempfile.mkdtemp(prefix="vps3xui-portable-kill-")
    manifest2, backup2, report2, system2 = _run_killed_backup(kill_tmp)
    check("SIGKILL mid-copy leaves no COMPLETE marker",
          not os.path.exists(os.path.join(backup2, "COMPLETE")))
    check("finalizer never declares success after SIGKILL",
          report2.get("state") != "succeeded", str(report2.get("state")))
    recorded_ids = [item["id"] for item in
                    (read_json(os.path.join(kill_tmp, "jobs", "req-kill-1", "initial-state.json"))
                     or {}).get("stop_containers", [])]
    check("recorded containers were restarted one id at a time",
          system2.start_batches == [[cid] for cid in recorded_ids]
          and set(system2.started_ids) >= set(recorded_ids))

    # GNU tar metadata round-trip (only when GNU tar is available).
    gnu = subprocess.run(["tar", "--version"], capture_output=True)
    if b"GNU tar" in gnu.stdout:
        source = os.path.join(tmp, "meta-src")
        os.makedirs(source)
        path = os.path.join(source, "secret.bin")
        with open(path, "wb") as handle:
            handle.write(b"x")
        os.chmod(path, 0o600)
        arc = os.path.join(tmp, "meta.tar")
        subprocess.run(["tar", "--numeric-owner", "-cpf", arc, "-C", source, "secret.bin"],
                       check=True)
        dest = os.path.join(tmp, "meta-out")
        os.makedirs(dest)
        subprocess.run(["tar", "--numeric-owner", "-xpf", arc, "-C", dest], check=True)
        mode = oct(os.stat(os.path.join(dest, "secret.bin")).st_mode & 0o777)
        check("GNU tar round-trips mode 0600", mode == "0o600", mode)
    else:
        print("  - NOT RUN GNU tar metadata round-trip (GNU tar unavailable locally)")

    print("portable drill: %d checks, %d failures" % (len(CHECKS), len(FAILURES)))
    if FAILURES:
        for label in FAILURES:
            sys.stderr.write("FAIL: %s\n" % label)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
