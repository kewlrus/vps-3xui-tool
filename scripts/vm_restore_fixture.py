#!/usr/bin/env python3
"""Self-contained synthetic fixture for the VM restore drill.

This module builds *only* disposable, uniquely named fixture resources; it never
touches the real production volume/container/unit names, never pulls an image
and never reads a real backup. It has these modes:

``--plan``
    Print the fixture plan as JSON (names, files, manifest) without touching the
    host. Used by the local test suite to prove the fixture is unique, synthetic
    and consistent with the approved manifest contract.

``--create``
    Create the fixture on an explicitly disposable Linux host: fixture files at
    their real absolute paths, one real named Docker volume, one create-started
    fixture container using an already-present test image (``--pull=never``),
    then run the shipped read-only probe and build a real plan from it. Prints a
    JSON object with the job directory and resource names.

``--cleanup``
    Remove *only* the resources ``--create`` recorded in its durable ownership
    ledger: files and directories by filesystem identity (device/inode plus
    content digest), Docker objects by container ID and drill labels, systemd
    units only by the exact names this drill recorded. A missing ledger, a
    creation refusal or any identity that no longer matches leaves the resource
    untouched.

``--reserve-unit``
    Record the intent to launch a transient unit (name + per-run token) *before*
    ``systemd-run`` runs, so a crash between the launch and the confirmation
    still leaves cleanup able to find that exact unit - or to prove it absent -
    without touching a same-named unit that does not carry the token.

``--record-unit``
    Confirm a launched transient unit and pin its systemd ``InvocationID`` in an
    existing ledger. It refuses to invent a ledger.

Ownership rules enforced here:

* the ledger is written durably (fsync + rename) after every mutation and an
  existing ledger path is never overwritten; when the ledger cannot be written
  nothing is created and no unrelated resource is ever removed;
* only directories this run actually created are recorded, so pre-existing
  directories keep their mode and are never chmod-ed;
* a partial creation failure removes exactly the already-recorded objects;
* cleanup never falls back to the ``--plan`` file list, so a refusal can never
  delete a pre-existing host path, unit or Docker object;
* only an explicit systemd answer is acted on: a proven absence is tolerated, a
  token mismatch or a foreign ``FragmentPath`` is refused, and an error or
  unknown state aborts cleanup with every recorded resource and the ledger kept
  intact;
* a unit file this run installed is unlinked only after the unit systemd loaded
  from exactly that file is stopped and verified inactive, because the worker or
  the finalizer may have activated it.

The drill script (``vm-restore-drill.sh``) drives the worker/finalizer against
this fixture and performs the assertions. This module never asserts success.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import stat
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

HOOK_COMMAND = "/usr/local/sbin/certbot-http01-guard --fixture"
SYSTEMD_UNITS = ("certbot-http01-cleanup.service", "certbot-http01-cleanup.timer")
PREFIX = "vps3xui-drill"
# Every Docker object this fixture creates carries these labels; the exact IDs
# and creation times are additionally recorded in the ledger.
LABEL_MARKER = "com.vps3xui.drill"
LABEL_ID = "com.vps3xui.drill.id"
LABEL_PREFIX = "com.vps3xui.drill.prefix"
# Per-run random ownership token: recorded in the ledger and in every Docker
# label, so a raced-in foreign object can never be mistaken for ours.
LABEL_TOKEN = "com.vps3xui.drill.token"
LEDGER_SCHEMA_VERSION = 1
SYSTEMD_SYSTEM_DIR = "/etc/systemd/system"
# Vendored Certbot trigger units live *below* the runtime directory in the
# systemd unit load path, so the worker's reversible ``mask --runtime`` (which
# writes into ``/run/systemd/system``) actually shadows the unit file. If the
# trigger files lived in ``/etc/systemd/system`` they would outrank the runtime
# mask, the worker would correctly fail closed on the ineffective mask, and the
# success drill could never reach ``copying``. The cleanup units and the Certbot
# drop-in stay under ``SYSTEMD_SYSTEM_DIR`` per the reviewed manifest contract.
SYSTEMD_VENDOR_DIR = "/usr/lib/systemd/system"
# Unit directories this fixture records ownership in and may remove files from
# (``/etc`` plus the vendor locations). This is the fixture's supported
# ownership set, not the complete systemd load path; it is used only for unit
# file ownership during cleanup and to decide when removing a recorded file
# requires a ``daemon-reload``.
SYSTEMD_UNIT_DIRS = (SYSTEMD_SYSTEM_DIR, "/lib/systemd/system", SYSTEMD_VENDOR_DIR)
# The reviewed manifest contract permits writable layers only for the literal
# production container name (``APPROVED_WRITABLE_LAYERS`` in manifest.py). The
# drill therefore creates a second, synthetic Fail2ban container with that
# exact name on a disposable host, after refusing to run when a production
# stack or that container already exists. It is owned by the same per-run token
# and full container id in the R1 ledger as every other fixture object.
FAIL2BAN_CONTAINER = "3xui_app"
PRODUCTION_CONTAINER_NAMES = (
    "3xui_app", "llmproxy", "llmproxy_caddy_data", "llmproxy_caddy_config",
    "caddy", "litellm", "telemt", "llmproxy_chatgpt_auth",
)
FAIL2BAN_CONFIG_PATH = "/etc/fail2ban"
# The reviewed worker calls RealSystem.backup_root() (require_private_dir) before
# copying, which would create this path outside the ownership ledger. The fixture
# creates and records it first and refuses a pre-existing one, so the worker never
# chmods unowned state and cleanup can still remove only what this run made.
BACKUP_ROOT = "/var/backups/vps3xui"
FAIL2BAN_DATA_PATH = "/var/lib/fail2ban"
# The exact synthetic bytes seeded into the Fail2ban writable layers. The same
# constants drive both the ``docker cp`` seed and the restore comparison, so the
# drill checks the restored files against the values it actually seeded.
FAIL2BAN_CONFIG_SEED = "synthetic drill jail; never production\n"
FAIL2BAN_FILTER_SEED = "[Definition]\nfailregex = ^drill\n"
FAIL2BAN_DATA_SEED = "synthetic drill fail2ban database\n"
# Marker the drill puts in a transient unit's Description so the fixture can
# prove, later, that the unit it is about to stop is the one it launched.
UNIT_TOKEN_PREFIX = "vps3xui-drill-unit-token="
UNIT_STOP_WAIT_SECONDS = 15.0
UNIT_STOP_POLL_SECONDS = 0.5
# ActiveState values that mean "something is still running"; only these may be
# stopped. Anything else that is not an explicit inactive/failed state is an
# unknown outcome: cleanup then aborts without touching any resource.
UNIT_ACTIVE_STATES = ("active", "activating", "deactivating", "reloading")
UNIT_INACTIVE_STATES = ("inactive", "failed")
# Direct (non-drop-in) unit files the fixture may have installed itself.
UNIT_FILE_SUFFIXES = (".service", ".timer", ".socket", ".path", ".mount", ".target",
                     ".swap", ".slice", ".device")
# Exact units the fixture installs files for. Any of them already present (from a
# vendor unit file or a runtime unit) is a conflict, never something to override.
FIXTURE_UNIT_NAMES = tuple(SYSTEMD_UNITS) + ("certbot.service", "certbot.timer")
# Host directories the reviewed probe/plan needs to exist. They are created and
# recorded like every other fixture directory, so cleanup removes them again only
# when this run created them and they are still empty.
REQUIRED_HOST_DIRS = ("/var/backups",)


def _fail(message: str):
    sys.stderr.write("FAIL: %s\n" % message)
    raise SystemExit(1)


def sanitize_identifier(value: str) -> str:
    cleaned = "".join(ch for ch in value if ch.isalnum() or ch in "-.")
    cleaned = cleaned.strip(".-")
    if not cleaned:
        _fail("the drill identifier must contain letters or digits")
    return cleaned[:32]


def fixture_identity(identifier: str) -> Dict[str, str]:
    ident = sanitize_identifier(identifier)
    prefix = "%s-%s" % (PREFIX, ident)
    return {
        "id": ident,
        "prefix": prefix,
        "drill_dir": "/var/lib/%s" % prefix,
        "compose_dir": "/opt/%s" % prefix,
        "compose_project": prefix,
        "compose_service": "app",
        "volume": prefix + "-data",
        "container": prefix + "-app",
        "idle_container": prefix + "-idle",
        "fail2ban_container": FAIL2BAN_CONTAINER,
        "fail2ban_compose_project": prefix + "-fail2ban",
        "fail2ban_config_artifact": prefix + "-fail2ban-config.tar",
        "fail2ban_data_artifact": prefix + "-fail2ban-data.tar",
        "restored_container": prefix + "-restored",
        "worker_unit": prefix + "-worker",
        "finalizer_unit": prefix + "-finalizer",
        "lineage": prefix + ".example.invalid",
        "job_dir": "/var/lib/%s/jobs/%s" % (prefix, prefix),
    }


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def compose_file(content_image: str) -> str:
    return (
        "services:\n"
        "  app:\n"
        "    image: %s\n"
        "    restart: unless-stopped\n"
        "    volumes:\n"
        "      - data:/data\n"
        "volumes:\n"
        "  data:\n"
        "    driver: local\n" % content_image
    )


def renewal_file() -> str:
    return (
        "# synthetic vps3xui drill lineage; never a real certificate\n"
        "authenticator = standalone\n"
        "pre_hook = %s\n"
        "post_hook = %s\n"
        "renew_hook = %s\n" % (HOOK_COMMAND, HOOK_COMMAND, HOOK_COMMAND)
    )


def fixture_files(names: Dict[str, str], image: str) -> List[Dict[str, Any]]:
    """Every fixture file: (path, bytes, mode). Guard helper is 0755."""
    prefix = names["prefix"]
    files = [
        {"path": names["compose_dir"] + "/docker-compose.yaml",
         "content": compose_file(image), "mode": 0o644},
        {"path": names["compose_dir"] + "/app.env",
         "content": "FIXTURE_ONLY=1\n", "mode": 0o600},
        {"path": "/etc/letsencrypt/renewal/%s.conf" % names["lineage"],
         "content": renewal_file(), "mode": 0o600},
        {"path": "/etc/letsencrypt/archive/%s/cert.pem" % names["lineage"],
         "content": "# synthetic drill certificate; never a real certificate\n",
         "mode": 0o644},
        {"path": "/etc/letsencrypt/archive/%s/privkey.pem" % names["lineage"],
         "content": "# synthetic drill private key; never a real key\n", "mode": 0o600},
        {"path": "/usr/local/sbin/certbot-http01-guard",
         "content": "#!/bin/sh\n# synthetic drill guard; does nothing\nexit 0\n", "mode": 0o755},
        {"path": "/etc/certbot-http01-guard.enabled",
         "content": "fixture\n", "mode": 0o644},
        {"path": "/etc/systemd/system/%s" % SYSTEMD_UNITS[0],
         "content": "[Unit]\nDescription=vps3xui drill cleanup (fixture)\n[Service]\nType=oneshot\nExecStart=/bin/true\n",
         "mode": 0o644},
        {"path": "/etc/systemd/system/%s" % SYSTEMD_UNITS[1],
         "content": "[Unit]\nDescription=vps3xui drill cleanup timer (fixture)\n[Timer]\nOnUnitActiveSec=30\n",
         "mode": 0o644},
        # Stub Certbot trigger units: the reviewed worker snapshots, stops,
        # runtime-masks and restores the exact original unit-file state, so the
        # disposable host must expose real (fixture) unit files for that path.
        # They are installed in the *vendor* directory so the worker's runtime
        # mask in ``/run/systemd/system`` is not shadowed by an ``/etc`` file.
        {"path": SYSTEMD_VENDOR_DIR + "/certbot.service",
         "content": "[Unit]\nDescription=vps3xui drill certbot stub (fixture)\n"
                    "[Service]\nType=oneshot\nExecStart=/bin/true\n",
         "mode": 0o644},
        {"path": SYSTEMD_VENDOR_DIR + "/certbot.timer",
         "content": "[Unit]\nDescription=vps3xui drill certbot timer stub (fixture)\n"
                    "[Timer]\nOnCalendar=daily\n\n[Install]\nWantedBy=timers.target\n",
         "mode": 0o644},
        {"path": "/etc/systemd/system/certbot.service.d/http01-cleanup.conf",
         "content": "[Service]\nEnvironment=VPS3XUI_DRILL=%s\n" % prefix, "mode": 0o644},
        {"path": "/etc/ufw/fixture.conf",
         "content": "# synthetic ufw reference; never applied\n", "mode": 0o644},
        {"path": "/etc/default/ufw",
         "content": "# synthetic ufw defaults; never applied\n", "mode": 0o644},
    ]
    return files


def fixture_symlinks(names: Dict[str, str]) -> List[Dict[str, str]]:
    """The reviewed Let's Encrypt relative links, synthetic only.

    ``live/<lineage>/cert.pem`` points at ``../../archive/<lineage>/cert.pem``
    relative to the live directory, exactly the shape the archive adapter must
    preserve. They are emitted as real symlinks so the VM backup/restore path is
    not tested with a regular-file substitute.
    """
    live = "/etc/letsencrypt/live/%s" % names["lineage"]
    archive = "../../archive/%s" % names["lineage"]
    return [
        {"path": live + "/cert.pem", "target": archive + "/cert.pem"},
        {"path": live + "/privkey.pem", "target": archive + "/privkey.pem"},
    ]


def fixture_dirs(names: Dict[str, str]) -> List[str]:
    return [
        names["compose_dir"],
        names["drill_dir"],
        "/etc/letsencrypt/renewal",
        "/etc/letsencrypt/archive/%s" % names["lineage"],
        "/etc/letsencrypt/live/%s" % names["lineage"],
        "/etc/systemd/system/certbot.service.d",
        "/etc/letsencrypt/renewal-hooks/pre",
        "/etc/letsencrypt/renewal-hooks/post",
        "/etc/letsencrypt/renewal-hooks/deploy",
        "/var/lib/certbot-http01-guard",
        "/etc/ufw",
        BACKUP_ROOT,
    ]


def restore_expectations(names: Dict[str, str], image: str,
                         resources: Dict[str, Any]) -> Dict[str, Any]:
    """Exact values the restore step must observe in the restored artifacts.

    Derived from the same seed data the fixture wrote, so a restore comparison is
    against the seeded source values rather than hard-coded test constants.
    """
    files = {item["path"]: item for item in fixture_files(names, image)}
    metadata = resources["metadata"]
    expected = []
    for path in (metadata["path"], names["compose_dir"] + "/docker-compose.yaml"):
        item = files[path]
        entry = {
            "path": path,
            "sha256": _sha256_bytes(item["content"].encode("utf-8")),
            "mode": "%04o" % item["mode"],
            "uid": 0,
            "gid": 0,
        }
        if path == metadata["path"]:
            entry.update({
                "uid": metadata["uid"],
                "gid": metadata["gid"],
                "mode": metadata["mode"],
                "acl": "user:%d:rwx" % metadata["acl_user"],
                "xattr_name": metadata["xattr"],
                "xattr_value": "drill",
            })
        expected.append(entry)
    # The worker copies the Fail2ban writable layers out with ``docker cp -a``
    # and the drill copies them back in the same way, so the numeric owner and
    # mode must survive both directions. The seed files are created by this
    # root-only fixture, so their owner is root:root by construction.
    fail2ban = [
        {"path": FAIL2BAN_CONFIG_PATH + "/jail.local",
         "sha256": _sha256_bytes(FAIL2BAN_CONFIG_SEED.encode("utf-8")),
         "mode": "0640", "uid": 0, "gid": 0, "contains": "synthetic drill jail"},
        {"path": FAIL2BAN_CONFIG_PATH + "/filter.d/drill.conf",
         "sha256": _sha256_bytes(FAIL2BAN_FILTER_SEED.encode("utf-8")),
         "mode": "0640", "uid": 0, "gid": 0, "contains": "failregex"},
        {"path": FAIL2BAN_DATA_PATH + "/db.sqlite",
         "sha256": _sha256_bytes(FAIL2BAN_DATA_SEED.encode("utf-8")),
         "mode": "0600", "uid": 0, "gid": 0, "contains": "synthetic drill fail2ban database"},
    ]
    return {
        "bind_files": expected,
        "links": fixture_symlinks(names),
        "volume": {"name": names["volume"], "path": "fixture.txt",
                   "content": "fixture-data\n"},
        "fail2ban": {"files": fail2ban,
                     "config_path": FAIL2BAN_CONFIG_PATH,
                     "data_path": FAIL2BAN_DATA_PATH},
    }


def trusted_alias_pins(host: Host, names: Dict[str, str], image: str) -> List[Dict[str, str]]:
    """Exact extra trust pins for vendor-alias paths the host actually exposes.

    On a usrmerge host ``/lib`` is a symlink to ``usr/lib``, so the installed
    vendor trigger is readable both at ``/usr/lib/systemd/system/<unit>`` and at
    ``/lib/systemd/system/<unit>``. The shipped ``probe_cron`` scans both
    directories and reports both paths, and ``compare`` requires a pin for every
    observed path, so the drill would otherwise fail closed on an unpinned alias.

    A ``/lib`` pin is returned only when that path resolves to the *very same*
    file this run installed: identical device+inode (``os.stat``, symlink-aware)
    and the expected content digest. A distinct or foreign ``/lib`` file is never
    granted trust, and ``compare`` then blocks it (fail closed). A distinct
    ``/lib`` tree with no certbot files yields no alias pin. The fixture never
    creates a ``/lib`` copy and never records the pre-existing alias in the
    ownership ledger.
    """
    expected = {item["path"]: _sha256_bytes(item["content"].encode("utf-8"))
                for item in fixture_files(names, image)}
    pins: List[Dict[str, str]] = []
    for unit in ("certbot.service", "certbot.timer"):
        canonical = SYSTEMD_VENDOR_DIR + "/" + unit
        alias = "/lib/systemd/system/" + unit
        digest = expected.get(canonical)
        if not digest or not host.lexists(canonical) or not host.lexists(alias):
            continue
        try:
            canonical_stat = os.stat(host.local(canonical))
            alias_stat = os.stat(host.local(alias))
        except OSError:
            continue
        if (canonical_stat.st_dev, canonical_stat.st_ino) != (
                alias_stat.st_dev, alias_stat.st_ino):
            continue
        try:
            with open(host.local(alias), "rb") as handle:
                actual = hashlib.sha256(handle.read()).hexdigest()
        except OSError:
            continue
        if actual != digest:
            continue
        pins.append({"path": alias, "sha256": digest})
    return pins


def build_manifest(names: Dict[str, str], image: str, volume_mountpoint: str,
                   files: List[Dict[str, Any]],
                   extra_trusted: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
    """Manifest data for the fixture, identical in shape to production.

    ``extra_trusted`` carries runtime-only pins (the usrmerge ``/lib`` alias of
    the installed vendor triggers) that cannot be represented in the offline
    ``--plan`` baseline. They are content-only and never change the required
    trust set.
    """
    if "@sha256:" not in image:
        _fail("the drill image must be a complete repo@sha256:... reference")
    reference = image.split("@", 1)[0]
    by_path = {item["path"]: item for item in files}
    trusted = []
    for path in (
        "/usr/local/sbin/certbot-http01-guard",
        "/etc/certbot-http01-guard.enabled",
        "/etc/systemd/system/%s" % SYSTEMD_UNITS[0],
        "/etc/systemd/system/%s" % SYSTEMD_UNITS[1],
        SYSTEMD_VENDOR_DIR + "/certbot.service",
        SYSTEMD_VENDOR_DIR + "/certbot.timer",
        "/etc/systemd/system/certbot.service.d/http01-cleanup.conf",
        "/etc/letsencrypt/renewal/%s.conf" % names["lineage"],
    ):
        item = {"path": path, "sha256": _sha256_bytes(by_path[path]["content"].encode("utf-8"))}
        if path == "/usr/local/sbin/certbot-http01-guard":
            item.update({"mode": "0755", "uid": 0, "gid": 0})
        trusted.append(item)
    known = {item["path"] for item in trusted}
    for item in extra_trusted or ():
        path = item.get("path")
        digest = item.get("sha256")
        if not path or not digest or path in known:
            continue
        trusted.append({"path": path, "sha256": digest})
        known.add(path)
    renewal_name = "%s.conf" % names["lineage"]
    hook_pins = {
        "%s:%s" % (renewal_name, key): _sha256_text(HOOK_COMMAND)
        for key in ("pre_hook", "post_hook", "renew_hook")
    }
    return {
        "schema_version": 1,
        "manifest_id": "%s-manifest" % names["prefix"],
        "approved": True,
        "approval_note": "Disposable synthetic drill fixture; never the production inventory.",
        "source": {
            "ssh_alias": names["prefix"],
            "expected_machine_id": None,
            "expected_host_key_fingerprint": None,
        },
        "compose_projects": [
            {
                "project": names["compose_project"],
                "working_dir": names["compose_dir"],
                "files": [names["compose_dir"] + "/docker-compose.yaml"],
                "services": [names["compose_service"]],
            }
        ],
        "containers": [
            {
                "name": names["container"],
                "compose_project": names["compose_project"],
                "service": names["compose_service"],
                "expected_state": "running",
                "included": True,
                "restart_order": 10,
                "image": {
                    "reference": reference,
                    "repo_digest": image,
                    "source": "registry",
                    "restorable": True,
                },
                "mounts": [
                    {
                        "type": "volume",
                        "name": names["volume"],
                        "source": volume_mountpoint,
                        "destination": "/data",
                        "rw": True,
                    }
                ],
            },
            {
                # Synthetic Fail2ban writable-layer holder. The reviewed
                # manifest contract currently accepts these two paths only for
                # the literal ``3xui_app`` container, so the drill uses that
                # name after a production-resource refusal check. It carries no
                # host mounts; its writable layer is seeded below with
                # ``docker cp`` and copied out by the worker with ``docker cp``.
                "name": names["fail2ban_container"],
                "compose_project": names["fail2ban_compose_project"],
                "service": "fail2ban",
                "expected_state": "running",
                "included": True,
                "restart_order": 20,
                "image": {
                    "reference": reference,
                    "repo_digest": image,
                    "source": "registry",
                    "restorable": True,
                },
                "mounts": [],
            },
            {
                # A synthetic container that is created but never started.
                # It is declared expected_state "stopped" so the plan records
                # it in leave_stopped and the drill can assert it stays stopped
                # with a stable id across every scenario.
                "name": names["idle_container"],
                "compose_project": names["compose_project"],
                "service": "idle",
                "expected_state": "exited",
                "included": True,
                "restart_order": 30,
                "image": {
                    "reference": reference,
                    "repo_digest": image,
                    "source": "registry",
                    "restorable": True,
                },
                "mounts": [],
            },
        ],
        "volumes": [
            {
                "name": names["volume"],
                "driver": "local",
                "options": {},
                "artifact": "%s-data.tar" % names["prefix"],
                "sensitive": True,
            }
        ],
        "bind_trees": [
            {
                "artifact": "%s-binds.tar" % names["prefix"],
                "root": "/",
                "includes": [
                    "opt/%s/docker-compose.yaml" % names["prefix"],
                    "opt/%s/app.env" % names["prefix"],
                    "etc/letsencrypt",
                ],
                "sensitive": True,
            }
        ],
        "writable_layers": [
            {
                "container": names["fail2ban_container"],
                "path": FAIL2BAN_CONFIG_PATH,
                "artifact": names["fail2ban_config_artifact"],
                "sensitive": False,
            },
            {
                "container": names["fail2ban_container"],
                "path": FAIL2BAN_DATA_PATH,
                "artifact": names["fail2ban_data_artifact"],
                "sensitive": True,
            },
        ],
        "reference_artifacts": [
            {
                "artifacts": ["%s-ufw.tar" % names["prefix"]],
                "source": "/etc/ufw",
                "note": "Fixture reference only; never applied.",
                "never_apply": True,
            }
        ],
        "metadata_artifacts": ["images.json", "backup.json"],
        "trusted_files": trusted,
        "exclusions": ["docker_data_root", "docker_images", "certbot_runtime_lease"],
        "images": {
            "archive_images": False,
            "policy": "Never archive images; the fixture image is preloaded on the drill host.",
        },
        "certbot": {
            "lineage": names["lineage"],
            "guard_path": "/usr/local/sbin/certbot-http01-guard",
            "guard_enabled_path": "/etc/certbot-http01-guard.enabled",
            "cleanup_service": SYSTEMD_UNITS[0],
            "cleanup_timer": SYSTEMD_UNITS[1],
            "dropin": "/etc/systemd/system/certbot.service.d/http01-cleanup.conf",
            "service_unit": "certbot.service",
            "timer_unit": "certbot.timer",
            "lease_path": "/var/lib/certbot-http01-guard/lease.json",
            "artifact": "%s-certbot.tar" % names["prefix"],
            "max_lease_seconds": 900,
            "cleanup_interval_seconds": 30,
            "permitted_hooks": ["pre_hook", "post_hook", "renew_hook"],
            "hook_fingerprints": hook_pins,
            "renewal_hook_dirs": [
                "/etc/letsencrypt/renewal-hooks/pre",
                "/etc/letsencrypt/renewal-hooks/post",
                "/etc/letsencrypt/renewal-hooks/deploy",
            ],
        },
        "ufw": {
            "reference_only": True,
            "paths": ["/etc/ufw", "/etc/default/ufw"],
            "never_apply": True,
        },
    }


def plan_object(identifier: str, image: str,
                volume_mountpoint: Optional[str] = None) -> Dict[str, Any]:
    names = fixture_identity(identifier)
    files = fixture_files(names, image)
    mountpoint = volume_mountpoint or ("/var/lib/docker/volumes/%s/_data" % names["volume"])
    manifest = build_manifest(names, image, mountpoint, files)
    return {
        "names": names,
        "manifest": manifest,
        "dirs": fixture_dirs(names),
        "symlinks": fixture_symlinks(names),
        "files": [
            {
                "path": item["path"],
                "mode": "%04o" % item["mode"],
                "sha256": _sha256_bytes(item["content"].encode("utf-8")),
                "content_b64": base64.b64encode(item["content"].encode("utf-8")).decode("ascii"),
            }
            for item in files
        ],
        "hook_command": HOOK_COMMAND,
        "systemd_units": list(SYSTEMD_UNITS),
        "required_host_dirs": list(REQUIRED_HOST_DIRS),
        "required_tools": ["tar", "setfacl", "getfacl", "setfattr", "getfattr"],
        "safety": {
            "confirm": "disposable",
            "fail2ban_container_name": FAIL2BAN_CONTAINER,
            "production_container_refusal": list(PRODUCTION_CONTAINER_NAMES),
            "reason": ("the reviewed writable-layer contract names the Fail2ban "
                       "container literally; the fixture refuses to run if any "
                       "production container name already exists"),
        },
    }


# ---------------------------------------------------------------------------
# Host seam: every mutation goes through one object so the local test suite can
# drive the real create/cleanup logic against a temporary root and fake
# Docker/systemd commands, without touching a real host.
# ---------------------------------------------------------------------------


def _run(argv: List[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout)


def _stderr(result: subprocess.CompletedProcess) -> str:
    return result.stderr.decode("utf-8", "replace").strip()


def _stdout_text(result: subprocess.CompletedProcess) -> str:
    return result.stdout.decode("utf-8", "replace").strip()


class Host(object):
    """One seam for every host mutation the fixture performs.

    Production uses ``root='/'`` plus the real ``docker``/``systemctl`` binaries.
    Tests pass a temporary ``root`` and a fake ``runner`` so that no real host
    path, container, volume or unit is ever touched.
    """

    def __init__(self, root: str = os.sep, platform: Optional[str] = None,
                 euid: Optional[int] = None, runner=None):
        self.root = os.path.abspath(root)
        self._platform = sys.platform if platform is None else platform
        self._euid = os.geteuid() if euid is None else euid
        self._runner = runner or _run

    def is_linux(self) -> bool:
        return self._platform.startswith("linux")

    def is_root(self) -> bool:
        return self._euid == 0

    def local(self, path: str) -> str:
        if self.root == os.sep:
            return path
        return os.path.join(self.root, path.lstrip(os.sep))

    def lexists(self, path: str) -> bool:
        return os.path.lexists(self.local(path))

    def lstat(self, path: str):
        return os.lstat(self.local(path))

    def isdir(self, path: str) -> bool:
        return os.path.isdir(self.local(path))

    def mkdir(self, path: str, mode: int) -> None:
        os.mkdir(self.local(path), mode)

    def write_exclusive(self, path: str, content: str, mode: int) -> None:
        target = self.local(path)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(target, flags, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content.encode("utf-8"))
        os.chmod(target, mode)

    def unlink(self, path: str) -> None:
        os.unlink(self.local(path))

    def symlink(self, target: str, path: str) -> None:
        os.symlink(target, self.local(path))

    def chown(self, path: str, uid: int, gid: int) -> None:
        os.chown(self.local(path), uid, gid)

    def rmdir(self, path: str) -> None:
        os.rmdir(self.local(path))

    def read_text(self, path: str) -> str:
        with open(self.local(path), "r", encoding="utf-8") as handle:
            return handle.read()

    def fsync_dir(self, path: str) -> None:
        fd = os.open(self.local(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def remove_tree(self, path: str) -> None:
        """Remove a recorded tree without ever following a symlink."""
        self._remove_tree_path(self.local(path))

    def _remove_tree_path(self, target: str) -> None:
        if os.path.islink(target) or not os.path.isdir(target):
            os.unlink(target)
            return
        with os.scandir(target) as entries:
            children = [entry.path for entry in entries]
        for child in children:
            if os.path.islink(child) or not os.path.isdir(child):
                os.unlink(child)
            else:
                self._remove_tree_path(child)
        os.rmdir(target)

    def run(self, argv: List[str], timeout: int = 120) -> subprocess.CompletedProcess:
        return self._runner(argv, timeout)


def _docker_lookup(host: Host, argv: List[str]):
    """Return ``(state, info)`` for a Docker object.

    ``state`` is ``"present"`` (with the parsed object), ``"absent"`` when Docker
    confirms the object does not exist, or ``"error"`` for anything else. The
    distinction matters: only a confirmed absence may drop a ledger entry, while
    a Docker failure must retain it for a later retry.
    """
    try:
        result = host.run(argv)
    except Exception:
        return "error", None
    if result.returncode == 0:
        try:
            value = json.loads(_stdout_text(result))
        except ValueError:
            return "error", None
        if isinstance(value, dict):
            return "present", value
        return "error", None
    message = _stderr(result).lower()
    if "no such" in message or "not found" in message:
        return "absent", None
    return "error", None


# ---------------------------------------------------------------------------
# Durable ownership ledger
# ---------------------------------------------------------------------------


class LedgerError(Exception):
    """The ledger path is occupied by something that is not a valid ledger."""


LEDGER_LIST_FIELDS = ("files", "links", "dirs", "trees", "volumes", "containers", "units")


def _file_identity(path: str, info: os.stat_result) -> Dict[str, Any]:
    return {"path": path, "dev": info.st_dev, "ino": info.st_ino}


class Ledger(object):
    """Durable record of the resources this fixture actually created.

    Cleanup reads *only* this file, so a creation refusal can never remove a
    pre-existing path, unit or Docker object. The ledger is published with
    ``O_EXCL`` (never overwriting an existing one) and then rewritten through a
    unique exclusive temporary file plus an ownership check on the previous
    inode, so a raced replacement is refused instead of clobbered. A crash can
    leak at most the single resource whose entry was being written, and a leaked
    resource is never deleted by a later run.
    """

    def __init__(self, path: str, host: Host, identifier: str, prefix: str,
                 token: Optional[str] = None):
        self.path = path
        self._host = host
        self.token = token or secrets.token_hex(16)
        self._published = None
        self._data = {
            "schema_version": LEDGER_SCHEMA_VERSION,
            "identifier": identifier,
            "prefix": prefix,
            "token": self.token,
            "files": [],
            "links": [],
            "dirs": [],
            "trees": [],
            "volumes": [],
            "containers": [],
            "units": [],
        }

    @classmethod
    def open_existing(cls, path: str, host: Host) -> Optional["Ledger"]:
        data = read_ledger(host, path)
        if data is None:
            return None
        ledger = cls(path, host, data.get("identifier", ""), data.get("prefix", ""),
                     token=data.get("token"))
        ledger._data = data
        info = host.lstat(path)
        ledger._published = (info.st_dev, info.st_ino)
        return ledger

    @property
    def data(self) -> Dict[str, Any]:
        return self._data

    def _encode(self) -> bytes:
        return json.dumps(self._data, indent=2, sort_keys=True).encode("utf-8")

    def _parent(self):
        parent_host = os.path.dirname(self.path) or os.sep
        parent = self._host.local(parent_host)
        if not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        return parent_host

    def begin(self) -> None:
        """Publish the ledger exclusively; never overwrite an existing one.

        A durable publication that fails half way is rolled back: a ledger file
        this call just created is unlinked again, so a crash cannot leave a
        zero-length ledger that makes every later run refuse to start.
        """
        target = self._host.local(self.path)
        parent_host = self._parent()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(target, flags, 0o600)
        except FileExistsError:
            _fail("refusing to overwrite an existing ownership ledger: %s" % self.path)
        info = os.fstat(fd)
        self._published = (info.st_dev, info.st_ino)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(self._encode())
                handle.flush()
                os.fsync(handle.fileno())
            self._host.fsync_dir(parent_host)
        except BaseException:
            self._unpublish()
            raise

    def _unpublish(self) -> None:
        """Remove the ledger file only while it is still the one we published."""
        if self._published is None:
            return
        target = self._host.local(self.path)
        try:
            info = os.lstat(target)
        except OSError:
            return
        if (info.st_dev, info.st_ino) != self._published:
            return
        try:
            os.unlink(target)
        except OSError:
            return
        self._published = None

    def _check_published(self, target: str) -> None:
        try:
            info = os.lstat(target)
        except OSError:
            raise LedgerError("the ownership ledger disappeared: %s" % self.path)
        if not stat.S_ISREG(info.st_mode):
            raise LedgerError("the ownership ledger is not a regular file: %s" % self.path)
        if self._published is not None and (info.st_dev, info.st_ino) != self._published:
            raise LedgerError("the ownership ledger was replaced: %s" % self.path)

    def _write(self) -> None:
        target = self._host.local(self.path)
        parent_host = self._parent()
        self._check_published(target)
        tmp = "%s.tmp-%s" % (target, secrets.token_hex(8))
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(tmp, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(self._encode())
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, target)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        info = os.lstat(target)
        self._published = (info.st_dev, info.st_ino)
        self._host.fsync_dir(parent_host)

    def write(self) -> None:
        self._write()

    def _append(self, key: str, record: Dict[str, Any]) -> None:
        self._data[key].append(record)
        self._write()

    def add_file(self, path: str, info: os.stat_result, digest: str) -> None:
        record = _file_identity(path, info)
        record["sha256"] = digest
        record["mode"] = "%04o" % stat.S_IMODE(info.st_mode)
        self._append("files", record)

    def add_link(self, path: str, info: os.stat_result, target: str) -> None:
        record = _file_identity(path, info)
        record["target"] = target
        self._append("links", record)

    def add_dir(self, path: str, info: os.stat_result) -> None:
        self._append("dirs", _file_identity(path, info))

    def add_tree(self, path: str, info: os.stat_result) -> None:
        self._append("trees", _file_identity(path, info))

    def add_volume(self, record: Dict[str, Any]) -> None:
        self._append("volumes", record)

    def add_container(self, record: Dict[str, Any]) -> None:
        self._append("containers", record)

    def add_unit(self, record: Dict[str, Any]) -> None:
        self._append("units", record)


def read_ledger(host: Host, path: str) -> Optional[Dict[str, Any]]:
    """Return the validated ledger, ``None`` if absent, else raise LedgerError."""
    try:
        info = host.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise LedgerError("the ownership ledger is not a regular file: %s" % path)
    try:
        data = json.loads(host.read_text(path))
    except (OSError, ValueError):
        raise LedgerError("the ownership ledger could not be read: %s" % path)
    _validate_ledger(data, path)
    return data


def _validate_ledger(data: Any, path: str) -> None:
    if not isinstance(data, dict) or data.get("schema_version") != LEDGER_SCHEMA_VERSION:
        raise LedgerError("the ownership ledger has an unsupported schema: %s" % path)
    if not isinstance(data.get("token"), str) or not data["token"]:
        raise LedgerError("the ownership ledger has no ownership token: %s" % path)
    for field in LEDGER_LIST_FIELDS:
        records = data.get(field, [])
        if not isinstance(records, list):
            raise LedgerError("the ownership ledger field %s is not a list" % field)
        for record in records:
            if not isinstance(record, dict):
                raise LedgerError("the ownership ledger field %s has a bad record" % field)
            if not (record.get("path") or record.get("name")):
                raise LedgerError("the ownership ledger field %s has a record without an identity" % field)


# ---------------------------------------------------------------------------
# Creation
# ---------------------------------------------------------------------------


def drill_labels(names: Dict[str, str], token: str) -> Dict[str, str]:
    return {LABEL_MARKER: "1", LABEL_ID: names["id"], LABEL_PREFIX: names["prefix"],
            LABEL_TOKEN: token}


def _make_dir_chain(host: Host, ledger: Ledger, directory: str) -> None:
    """Create every missing level of ``directory``, recording only our own.

    A pre-existing directory is never chmod-ed or recorded, so cleanup cannot
    remove it or change its mode.
    """
    current = os.sep
    for part in [item for item in directory.split(os.sep) if item]:
        current = os.path.join(current, part)
        if host.isdir(current):
            continue
        if host.lexists(current):
            _fail("refusing to replace a non-directory path: %s" % current)
        try:
            host.mkdir(current, 0o755)
        except FileExistsError:
            continue
        ledger.add_dir(current, host.lstat(current))


def _create_files(host: Host, ledger: Ledger, files: List[Dict[str, Any]]) -> None:
    for item in files:
        _make_dir_chain(host, ledger, os.path.dirname(item["path"]))
        try:
            host.write_exclusive(item["path"], item["content"], item["mode"])
        except FileExistsError:
            _fail("refusing to overwrite existing path: %s" % item["path"])
        info = host.lstat(item["path"])
        ledger.add_file(item["path"], info, _sha256_bytes(item["content"].encode("utf-8")))


def _create_links(host: Host, ledger: Ledger, links: List[Dict[str, str]]) -> None:
    for item in links:
        _make_dir_chain(host, ledger, os.path.dirname(item["path"]))
        try:
            host.symlink(item["target"], item["path"])
        except FileExistsError:
            _fail("refusing to overwrite existing path: %s" % item["path"])
        ledger.add_link(item["path"], host.lstat(item["path"]), item["target"])


def _apply_required_metadata(host: Host, names: Dict[str, str],
                             ledger: Ledger) -> Dict[str, Any]:
    """Apply the numeric owner/mode/ACL/xattr values the VM drill must restore.

    The reviewed worker tar uses ``--numeric-owner --acls --xattrs``. Missing
    tooling or a filesystem that cannot hold ACL/xattrs is a hard failure; the
    drill must never report an all-pass result with those checks skipped.
    """
    target = names["compose_dir"] + "/app.env"
    numeric_uid, numeric_gid = 4242, 4343
    try:
        host.chown(target, numeric_uid, numeric_gid)
    except OSError as exc:
        _fail("could not apply the numeric-owner fixture: %s" % exc)
    commands = [
        (["setfacl", "-m", "u:%d:rwx" % numeric_uid, target],
         "setfacl is required for the ACL round-trip"),
        (["setfattr", "-n", "user.vps3xui", "-v", "drill", target],
         "setfattr is required for the xattr round-trip"),
    ]
    for argv, message in commands:
        result = host.run(argv)
        if result.returncode != 0:
            _fail("%s" % message)
    info = host.lstat(target)
    return {
        "path": target,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": "%04o" % stat.S_IMODE(info.st_mode),
        "acl_user": numeric_uid,
        "xattr": "user.vps3xui",
    }


def _write_seed_files(host: Host, ledger: Ledger,
                      files: List[Dict[str, Any]]) -> None:
    _create_files(host, ledger, files)


def _create_fail2ban_container(host: Host, ledger: Ledger, names: Dict[str, str],
                               image: str) -> Dict[str, Any]:
    """Create the synthetic Fail2ban writable-layer container and seed it.

    The container carries the production name required by
    ``APPROVED_WRITABLE_LAYERS`` but is otherwise a disposable, token-labelled
    fixture. ``--pull=never`` is mandatory; the preloaded test image must also
    provide a shell so the no-op sleep command can run.
    """
    labels = {
        "com.docker.compose.project": names["fail2ban_compose_project"],
        "com.docker.compose.service": "fail2ban",
    }
    labels.update(drill_labels(names, ledger.token))
    argv = ["docker", "create", "--pull=never", "--name", names["fail2ban_container"]]
    for key, value in labels.items():
        argv.extend(["--label", "%s=%s" % (key, value)])
    argv.extend([image, "sh", "-c", "while true; do sleep 60; done"])
    result = host.run(argv)
    if result.returncode != 0:
        _fail("docker create failed for the Fail2ban container: %s" % _stderr(result))
    created_id = _stdout_text(result)
    state, info = _docker_lookup(host, ["docker", "inspect", "--format", "{{json .}}",
                                        names["fail2ban_container"]])
    if state != "present" or not _id_matches(created_id, info.get("Id")):
        _fail("docker inspect did not confirm the Fail2ban container")
    record = {
        "name": names["fail2ban_container"],
        "id": info.get("Id"),
        "labels": labels,
        "prefix": names["prefix"],
        "identifier": names["id"],
    }
    ledger.add_container(record)

    config_seed = names["drill_dir"] + "/seed/etc/fail2ban"
    data_seed = names["drill_dir"] + "/seed/var/lib/fail2ban"
    _write_seed_files(host, ledger, [
        {"path": config_seed + "/jail.local",
         "content": FAIL2BAN_CONFIG_SEED, "mode": 0o640},
        {"path": config_seed + "/filter.d/drill.conf",
         "content": FAIL2BAN_FILTER_SEED, "mode": 0o640},
        {"path": data_seed + "/db.sqlite",
         "content": FAIL2BAN_DATA_SEED, "mode": 0o600},
    ])
    for seed, destination in ((config_seed, "/etc/"), (data_seed, "/var/lib/")):
        copied = host.run(["docker", "cp", "-a", seed, "%s:%s" % (names["fail2ban_container"], destination)])
        if copied.returncode != 0:
            _fail("docker cp could not seed the Fail2ban writable layer: %s" % _stderr(copied))
    started = host.run(["docker", "start", names["fail2ban_container"]])
    if started.returncode != 0:
        _fail("docker start failed for the Fail2ban container: %s" % _stderr(started))
    return record


def _create_volume(host: Host, ledger: Ledger, names: Dict[str, str]) -> Dict[str, Any]:
    """Create the volume and prove ownership before anything is written to it.

    ``docker volume create`` is idempotent: on an existing volume it succeeds
    without applying our labels. The per-run token label is therefore the only
    ownership evidence; there is deliberately no unlabelled fallback.
    """
    labels = drill_labels(names, ledger.token)
    argv = ["docker", "volume", "create"]
    for key, value in labels.items():
        argv.extend(["--label", "%s=%s" % (key, value)])
    argv.append(names["volume"])
    result = host.run(argv)
    if result.returncode != 0:
        _fail("docker volume create failed: %s" % _stderr(result))
    state, info = _docker_lookup(host, ["docker", "volume", "inspect", "--format",
                                        "{{json .}}", names["volume"]])
    if state != "present":
        _fail("docker volume inspect did not confirm the created fixture volume")
    record = {
        "name": names["volume"],
        "driver": info.get("Driver"),
        "created_at": info.get("CreatedAt"),
        "labels": labels,
    }
    if not _volume_owned(record, info):
        # Either the create raced with a foreign volume of the same name, or the
        # labels/creation time did not come back. Nothing may be seeded into an
        # object this run cannot prove it owns.
        _fail("refusing to use a volume without this run's ownership labels: %s"
              % names["volume"])
    ledger.add_volume(record)
    return info


def _id_matches(recorded: Optional[str], actual: Optional[str]) -> bool:
    if not recorded or not actual:
        return False
    return (recorded == actual or actual.startswith(recorded)
            or recorded.startswith(actual))


def _create_container(host: Host, ledger: Ledger, names: Dict[str, str],
                      image: str) -> Dict[str, Any]:
    labels = {
        "com.docker.compose.project": names["compose_project"],
        "com.docker.compose.service": names["compose_service"],
    }
    labels.update(drill_labels(names, ledger.token))
    argv = ["docker", "create", "--pull=never", "--name", names["container"]]
    for key, value in labels.items():
        argv.extend(["--label", "%s=%s" % (key, value)])
    argv.extend(["-v", "%s:/data" % names["volume"], image,
                 "sh", "-c", "while true; do sleep 60; done"])
    result = host.run(argv)
    if result.returncode != 0:
        _fail("docker create failed: %s" % _stderr(result))
    created_id = _stdout_text(result)
    state, info = _docker_lookup(host, ["docker", "inspect", "--format", "{{json .}}",
                                        names["container"]])
    if state != "present" or not _id_matches(created_id, info.get("Id")):
        _fail("docker inspect did not confirm the created fixture container")
    record = {
        "name": names["container"],
        "id": info.get("Id"),
        "labels": labels,
        "prefix": names["prefix"],
        "identifier": names["id"],
    }
    ledger.add_container(record)
    return record


def _create_idle_container(host: Host, ledger: Ledger, names: Dict[str, str],
                           image: str) -> Dict[str, Any]:
    """Create a stopped, included fixture container the worker must never start."""
    labels = {
        "com.docker.compose.project": names["compose_project"],
        "com.docker.compose.service": "idle",
    }
    labels.update(drill_labels(names, ledger.token))
    argv = ["docker", "create", "--pull=never", "--name", names["idle_container"]]
    for key, value in labels.items():
        argv.extend(["--label", "%s=%s" % (key, value)])
    argv.extend([image, "sh", "-c", "while true; do sleep 60; done"])
    result = host.run(argv)
    if result.returncode != 0:
        _fail("docker create failed for the idle fixture container: %s" % _stderr(result))
    created_id = _stdout_text(result)
    state, info = _docker_lookup(host, ["docker", "inspect", "--format", "{{json .}}",
                                        names["idle_container"]])
    if state != "present" or not _id_matches(created_id, info.get("Id")):
        _fail("docker inspect did not confirm the idle fixture container")
    record = {
        "name": names["idle_container"],
        "id": info.get("Id"),
        "labels": labels,
        "prefix": names["prefix"],
        "identifier": names["id"],
    }
    ledger.add_container(record)
    return record


def _resources_exist(host: Host, names: Dict[str, str]) -> List[str]:
    existing = []
    state, _ = _docker_lookup(host, ["docker", "volume", "inspect", "--format", "{{json .}}",
                                     names["volume"]])
    if state == "present":
        existing.append("volume:" + names["volume"])
    state, _ = _docker_lookup(host, ["docker", "inspect", "--format", "{{json .}}",
                                     names["container"]])
    if state == "present":
        existing.append("container:" + names["container"])
    state, _ = _docker_lookup(host, ["docker", "inspect", "--format", "{{json .}}",
                                     names["idle_container"]])
    if state == "present":
        existing.append("container:" + names["idle_container"])
    return existing


def _unit_present(host: Host, name: str) -> bool:
    """Any installed (vendor) or loaded/runtime unit with this exact name."""
    for argv in (
        ["systemctl", "list-unit-files", name, "--no-legend", "--plain"],
        ["systemctl", "list-units", name, "--all", "--no-legend", "--plain"],
    ):
        result = host.run(argv)
        if result.returncode == 0 and _stdout_text(result):
            return True
    return False


UNIT_SHOW_PROPERTIES = ("LoadState", "ActiveState", "SubState", "Description",
                        "InvocationID", "FragmentPath")


def _unit_lookup(host: Host, name: str):
    """Return ``(state, properties)`` for a systemd unit.

    ``state`` is ``"present"`` (systemd answered with properties), ``"absent"``
    when systemd proves the unit is not known (``LoadState=not-found`` or an
    explicit "could not be found" error), or ``"error"`` for anything else - a
    bus failure, a timeout or unreadable output. The distinction is essential:
    only a proven absence may drop a ledger entry or be treated as "stopped",
    while an error must abort cleanup without mutating anything.
    """
    if not name:
        return "error", None
    argv = ["systemctl", "show"]
    for key in UNIT_SHOW_PROPERTIES:
        argv.extend(["-p", key])
    argv.append(name)
    try:
        result = host.run(argv)
    except Exception:
        return "error", None
    if result.returncode != 0:
        message = _stderr(result).lower()
        if "could not be found" in message or ("not found" in message and "unit" in message):
            return "absent", None
        return "error", None
    properties: Dict[str, str] = {}
    for line in _stdout_text(result).splitlines():
        key, _, value = line.partition("=")
        properties[key.strip()] = value.strip()
    load_state = properties.get("LoadState")
    if load_state == "not-found":
        return "absent", properties
    if not load_state:
        return "error", properties
    return "present", properties


def unit_runtime_state(unit: str, host: Host) -> str:
    """Public ``"running"``/``"stopped"``/``"absent"``/``"unknown"`` for a unit.

    Reuses the R1 lookup semantics: a systemd bus failure or unreadable output is
    ``"unknown"`` and must never be read as inactive by the harness.
    """
    return _unit_running(host, unit)


def _unit_running(host: Host, name: str) -> str:
    """``"running"``, ``"stopped"``, ``"absent"`` or ``"unknown"``."""
    state, properties = _unit_lookup(host, name)
    if state == "error":
        return "unknown"
    if state == "absent":
        return "absent"
    active = (properties or {}).get("ActiveState") or ""
    if active in UNIT_INACTIVE_STATES:
        return "stopped"
    if active in UNIT_ACTIVE_STATES:
        return "running"
    return "unknown"


def container_runtime_state(name: str, host: Host) -> str:
    """Public ``"running"``/``"stopped"``/``"absent"``/``"unknown"`` for a container.

    Distinguishes a Docker-confirmed absence and a Docker/bus failure from a
    container Docker proved is stopped. A failed or timed-out ``docker inspect``
    is ``"unknown"`` and must never be read as "the container is stopped".
    """
    if not name:
        return "unknown"
    state, info = _docker_lookup(host, ["docker", "inspect", "--format", "{{json .}}",
                                        name])
    if state == "absent":
        return "absent"
    if state == "error":
        return "unknown"
    runtime = (info or {}).get("State") or {}
    return "running" if runtime.get("Running") else "stopped"


def container_identity(name: str, host: Host) -> str:
    """Return the full container id, or ``""`` when it cannot be proven."""
    if not name:
        return ""
    state, info = _docker_lookup(host, ["docker", "inspect", "--format", "{{json .}}",
                                        name])
    if state != "present":
        return ""
    return (info or {}).get("Id") or ""


def _refuse_existing(host: Host, names: Dict[str, str], image: str) -> None:
    existing = _resources_exist(host, names)
    if existing:
        _fail("refusing to reuse existing fixture resources: %s" % ", ".join(existing))
    production = []
    for name in PRODUCTION_CONTAINER_NAMES:
        state, _ = _docker_lookup(host, ["docker", "inspect", "--format", "{{json .}}", name])
        if state == "present":
            production.append(name)
    if production:
        _fail("refusing to run on a host with production-like containers: %s"
              % ", ".join(sorted(production)))
    unit_result = host.run(["systemctl", "list-unit-files", "%s*" % names["prefix"],
                            "--no-legend", "--plain"])
    if unit_result.returncode == 0 and _stdout_text(unit_result):
        _fail("refusing to reuse existing fixture systemd units: %s" % names["prefix"])
    # The cleanup/certbot units are shared, non-prefixed names: a vendor unit file
    # or a runtime unit would be silently overridden by the fixture file, so any
    # exact match is a conflict.
    for unit in FIXTURE_UNIT_NAMES:
        if _unit_present(host, unit):
            _fail("refusing to reuse an existing systemd unit: %s" % unit)
    for item in fixture_files(names, image):
        if host.lexists(item["path"]):
            _fail("refusing to overwrite existing path: %s" % item["path"])
    if host.lexists(BACKUP_ROOT):
        _fail("refusing to reuse an existing backup root: %s" % BACKUP_ROOT)


def create_resources(host: Host, names: Dict[str, str], image: str,
                     ledger: Ledger) -> Dict[str, Any]:
    """Create the files, directories, volume and container; record each one."""
    for directory in REQUIRED_HOST_DIRS:
        _make_dir_chain(host, ledger, directory)
    for directory in fixture_dirs(names):
        _make_dir_chain(host, ledger, directory)
    _create_files(host, ledger, fixture_files(names, image))
    _create_links(host, ledger, fixture_symlinks(names))
    metadata = _apply_required_metadata(host, names, ledger)

    reload_result = host.run(["systemctl", "daemon-reload"])
    if reload_result.returncode != 0:
        _fail("systemctl daemon-reload failed for the fixture units")

    volume_info = _create_volume(host, ledger, names)

    seeded = host.run(["docker", "run", "--rm", "--pull=never",
                       "-v", "%s:/data" % names["volume"], image,
                       "sh", "-c", "printf 'fixture-data\\n' > /data/fixture.txt"])
    if seeded.returncode != 0:
        _fail("failed to seed the fixture volume: %s" % _stderr(seeded))

    container = _create_container(host, ledger, names, image)
    fail2ban_container = _create_fail2ban_container(host, ledger, names, image)
    idle_container = _create_idle_container(host, ledger, names, image)
    started = host.run(["docker", "start", names["container"]])
    if started.returncode != 0:
        _fail("docker start failed: %s" % _stderr(started))

    mountpoint = volume_info.get("Mountpoint") or (
        "/var/lib/docker/volumes/%s/_data" % names["volume"])
    return {"names": names, "volume": volume_info, "container": container,
            "fail2ban_container": fail2ban_container, "idle_container": idle_container,
            "metadata": metadata, "mountpoint": mountpoint,
            "restore_expectations": restore_expectations(
                names, image, {"metadata": metadata})}


def seed_job(host: Host, ledger: Ledger, names: Dict[str, str], image: str,
             release_dir: str, mountpoint: str,
             job_dir: str, probe=None) -> Dict[str, Any]:
    """Run the shipped read-only probe and build a fresh real plan for ``job_dir``.

    Every job gets its own probe/compare/build_plan pass against the *current*
    fixture, so the plan's inventory digest matches what the worker's preflight
    will observe. This is required because a later job inherits the restore
    target the drill created for an earlier job, and unit states also change; a
    plan cloned from the template would be rejected as ``E_PLAN_STALE``.
    """
    from vps3xui import manifest as manifest_module
    from vps3xui.inventory import compare, probe_spec
    from vps3xui.plan import build_plan
    from vps3xui.util import write_json
    from vps3xui import coordination as coord
    from vps3xui.worker.system import run_local_probe

    manifest_data = build_manifest(names, image, mountpoint, fixture_files(names, image),
                                   extra_trusted=trusted_alias_pins(host, names, image))
    manifest = manifest_module.from_object(manifest_data)

    # Production always runs the shipped read-only probe. The local test suite
    # injects a faithful, in-process observation so the real compare/build_plan
    # (and the worker preflight that consumes this plan) can be exercised
    # without a Linux host; the drill host itself never injects a probe.
    probe = probe or run_local_probe
    inventory = probe(probe_spec(manifest))
    report = compare(manifest, inventory)
    if not report.ok:
        _fail("the disposable host does not match the fixture manifest: %s"
              % json.dumps(report.to_object(), sort_keys=True))

    host_key = "SHA256:fixture-drill-host-key"
    plan = build_plan(manifest, inventory, host_key)

    _make_dir_chain(host, ledger, os.path.dirname(job_dir))
    try:
        os.mkdir(host.local(job_dir), 0o700)
    except FileExistsError:
        _fail("refusing to reuse an existing job directory: %s" % job_dir)
    ledger.add_tree(job_dir, host.lstat(job_dir))

    local_job_dir = host.local(job_dir)
    backup_dir = os.path.join(job_dir, "backup")
    coord.replace_json(os.path.join(local_job_dir, coord.RESERVATION_FILE), {
        "schema_version": coord.RESERVATION_SCHEMA_VERSION,
        "job_id": os.path.basename(job_dir),
        "plan_digest": plan["identity"],
        "manifest_id": manifest.manifest_id,
    })
    coord.replace_json(os.path.join(local_job_dir, coord.REQUEST_FILE), {
        "schema_version": 1,
        "request_id": os.path.basename(job_dir),
        "job_id": os.path.basename(job_dir),
        "manifest_id": manifest.manifest_id,
        "plan_digest": plan["identity"],
        "machine_id": inventory.machine_id,
        "host_key_fingerprint": host_key,
        "backup_dir": backup_dir,
        "stop_containers": plan["stop_containers"],
        "leave_stopped": plan["leave_stopped"],
        "required_bytes_estimate": plan["space"]["required_bytes_estimate"],
    })
    coord.replace_json(os.path.join(local_job_dir, coord.PLAN_FILE), plan)
    coord.replace_json(os.path.join(local_job_dir, coord.MANIFEST_FILE), manifest_data)
    write_json(os.path.join(local_job_dir, "fixture.json"), {
        "names": names, "manifest_id": manifest.manifest_id,
        "release_dir": release_dir, "backup_dir": backup_dir,
    })
    return {
        "names": names,
        "job_dir": job_dir,
        "backup_dir": backup_dir,
        "manifest_id": manifest.manifest_id,
        "volume_mountpoint": mountpoint,
        "token": ledger.token,
        "plan": plan,
    }


def create_job(host: Host, names: Dict[str, str], image: str, release_dir: str,
               ledger: Ledger, resources: Dict[str, Any], probe=None) -> Dict[str, Any]:
    """Run the shipped read-only probe and seed the template job directory.

    The returned mapping carries the ledger's per-run ownership ``token`` so the
    harness can confirm it against the ledger before it labels a launched unit.
    """
    result = seed_job(host, ledger, names, image, release_dir,
                      resources["mountpoint"], names["job_dir"], probe=probe)
    result["container_id"] = resources["container"]["id"]
    result["idle_container"] = resources["idle_container"]
    result["restore_expectations"] = resources["restore_expectations"]
    return result


def create(identifier: str, image: str, release_dir: str, ledger_path: str,
           host: Optional[Host] = None) -> Dict[str, Any]:
    host = host or Host()
    if not host.is_linux():
        _fail("the fixture can only be created on a disposable Linux host")
    if not host.is_root():
        _fail("the fixture must be created as root on a disposable host")
    return create_fixture(identifier, image, release_dir, ledger_path, host)


def create_fixture(identifier: str, image: str, release_dir: str, ledger_path: str,
                   host: Host, probe=None) -> Dict[str, Any]:
    """Refuse an occupied fixture, then create it under a durable ledger."""
    names = fixture_identity(identifier)
    # Read-only refusal runs before the ledger exists, so a refusal can never
    # leave a plan-based deletion path behind.
    _refuse_existing(host, names, image)
    ledger = Ledger(ledger_path, host, names["id"], names["prefix"])
    ledger.begin()
    previous_umask = os.umask(0o077)
    try:
        resources = create_resources(host, names, image, ledger)
        result = create_job(host, names, image, release_dir, ledger, resources,
                            probe=probe)
        result["token"] = ledger.token
        return result
    except BaseException:
        # A partial creation removes exactly the recorded objects.
        cleanup_fixture(ledger_path, host)
        raise
    finally:
        os.umask(previous_umask)


def _open_owned_ledger(ledger_path: str, host: Host) -> Ledger:
    try:
        ledger = Ledger.open_existing(ledger_path, host)
    except LedgerError as exc:
        _fail("refusing to extend the fixture ledger: %s" % exc)
    if ledger is None:
        _fail("refusing to extend a missing fixture ledger: %s" % ledger_path)
    return ledger


def create_owned_dir(ledger_path: str, path: str, host: Host) -> None:
    """Create and ledger-record an empty restore destination directory."""
    ledger = _open_owned_ledger(ledger_path, host)
    if host.lexists(path):
        _fail("refusing to reuse an existing restore destination: %s" % path)
    _make_dir_chain(host, ledger, path)


def create_owned_tree(ledger_path: str, path: str, host: Host) -> None:
    """Create a ledger-owned directory whose later contents are disposable.

    Cleanup removes recorded trees recursively through the same identity-checked
    routine used for job directories. This is the correct ownership record for
    extraction destinations, copy barriers and other directories the drill will
    populate with unrecorded transient files.
    """
    ledger = _open_owned_ledger(ledger_path, host)
    if host.lexists(path):
        _fail("refusing to reuse an existing restore tree: %s" % path)
    _make_dir_chain(host, ledger, path)
    ledger.add_tree(path, host.lstat(path))


def write_owned_file(ledger_path: str, path: str, content: str, mode: int,
                     host: Host) -> None:
    """Create and ledger-record a regular file (used for the copy-barrier shim)."""
    ledger = _open_owned_ledger(ledger_path, host)
    _make_dir_chain(host, ledger, os.path.dirname(path))
    try:
        host.write_exclusive(path, content, mode)
    except FileExistsError:
        _fail("refusing to overwrite an existing fixture file: %s" % path)
    ledger.add_file(path, host.lstat(path), _sha256_bytes(content.encode("utf-8")))


def create_owned_container(ledger_path: str, name: str, image: str, host: Host,
                           compose_project: str = "vps3xui-drill-restore",
                           service: str = "restore") -> Dict[str, Any]:
    """Create a stopped, token-labelled, ledger-owned container.

    Used for the Fail2ban restore target: the drill copies the two actual
    ``docker cp`` archives into this container and must prove it stays stopped.
    """
    ledger = _open_owned_ledger(ledger_path, host)
    prefix = ledger.data.get("prefix") or ""
    if not name.startswith(prefix + "-"):
        _fail("refusing to create a container outside the drill prefix: %s" % name)
    state, _ = _docker_lookup(host, ["docker", "inspect", "--format", "{{json .}}", name])
    if state == "present":
        _fail("refusing to reuse an existing restore container: %s" % name)
    labels = {
        "com.docker.compose.project": compose_project,
        "com.docker.compose.service": service,
    }
    labels.update({LABEL_MARKER: "1", LABEL_ID: ledger.data.get("identifier") or "",
                   LABEL_PREFIX: prefix, LABEL_TOKEN: ledger.token})
    argv = ["docker", "create", "--pull=never", "--name", name]
    for key, value in labels.items():
        argv.extend(["--label", "%s=%s" % (key, value)])
    argv.extend([image, "sh", "-c", "while true; do sleep 60; done"])
    result = host.run(argv)
    if result.returncode != 0:
        _fail("docker create failed for the restore container: %s" % _stderr(result))
    created_id = _stdout_text(result)
    state, info = _docker_lookup(host, ["docker", "inspect", "--format", "{{json .}}", name])
    if state != "present" or not _id_matches(created_id, info.get("Id")):
        _fail("docker inspect did not confirm the restore container")
    record = {"name": name, "id": info.get("Id"), "labels": labels,
              "prefix": prefix, "identifier": ledger.data.get("identifier")}
    ledger.add_container(record)
    return record


def create_owned_job(ledger_path: str, job_id: str, template_job_dir: str,
                     image: str, release_dir: str, mountpoint: str,
                     names: Dict[str, str], host: Host,
                     probe=None) -> Dict[str, Any]:
    """Create an independent, ledger-owned job with a fresh real probe + plan.

    The plan is rebuilt now against the stabilized fixture (which already
    includes any restore target), so request/reservation digests, the stop/leave
    sets and the inventory digest all match the worker's own preflight instead of
    the template plan that a changed inventory would reject as ``E_PLAN_STALE``.
    """
    from vps3xui import coordination as coord

    ledger = _open_owned_ledger(ledger_path, host)
    coord.validate_id(job_id, "job_id")
    jobs_root = os.path.dirname(template_job_dir)
    new_job_dir = os.path.join(jobs_root, job_id)
    if host.lexists(new_job_dir):
        _fail("refusing to reuse an existing drill job: %s" % new_job_dir)
    return seed_job(host, ledger, names, image, release_dir, mountpoint, new_job_dir,
                    probe=probe)


# ---------------------------------------------------------------------------
# Ownership-checked cleanup
# ---------------------------------------------------------------------------


def _try_run(host: Host, argv: List[str]) -> bool:
    try:
        return host.run(argv).returncode == 0
    except Exception:
        return False


def _verify_regular(host: Host, record: Dict[str, Any]) -> str:
    """``"absent"``, ``"owned"`` or ``"blocked"`` for a recorded file."""
    path = record.get("path")
    if not path:
        return "blocked"
    try:
        info = host.lstat(path)
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "blocked"
    if not stat.S_ISREG(info.st_mode):
        return "blocked"
    if info.st_dev != record.get("dev") or info.st_ino != record.get("ino"):
        return "blocked"
    digest = record.get("sha256")
    if digest:
        try:
            with open(host.local(path), "rb") as handle:
                actual = hashlib.sha256(handle.read()).hexdigest()
        except OSError:
            return "blocked"
        if actual != digest:
            return "blocked"
    return "owned"


def _verify_link(host: Host, record: Dict[str, Any]) -> str:
    """``"absent"``, ``"owned"`` or ``"blocked"`` for a recorded symlink."""
    path = record.get("path")
    if not path:
        return "blocked"
    try:
        info = host.lstat(path)
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "blocked"
    if not stat.S_ISLNK(info.st_mode):
        return "blocked"
    if info.st_dev != record.get("dev") or info.st_ino != record.get("ino"):
        return "blocked"
    try:
        target = os.readlink(host.local(path))
    except OSError:
        return "blocked"
    if target != record.get("target"):
        return "blocked"
    return "owned"


def _verify_directory(host: Host, record: Dict[str, Any]) -> str:
    """``"absent"``, ``"owned"`` or ``"blocked"`` for a recorded directory."""
    path = record.get("path")
    if not path:
        return "blocked"
    try:
        info = host.lstat(path)
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "blocked"
    if not stat.S_ISDIR(info.st_mode):
        return "blocked"
    if info.st_dev != record.get("dev") or info.st_ino != record.get("ino"):
        return "blocked"
    return "owned"


def _unit_state(host: Host, record: Dict[str, Any]) -> str:
    """``"absent"``, ``"owned"``, ``"blocked"`` or ``"unknown"`` for a unit.

    Ownership is the exact launch token the drill wrote into the unit's
    Description (plus, when recorded, its systemd InvocationID). A unit that
    merely shares our prefix is never treated as ours. A systemd query that
    fails for any reason other than a proven absence is ``"unknown"``: the
    caller must then abort cleanup instead of guessing.
    """
    name = record.get("name") or ""
    if not name or not record.get("token"):
        return "unknown"
    state, properties = _unit_lookup(host, name)
    if state == "error":
        return "unknown"
    if state == "absent":
        return "absent"
    if (properties or {}).get("LoadState") != "loaded":
        # masked, bad-setting, ... - not a unit this run can reason about.
        return "unknown"
    if properties.get("Description") != UNIT_TOKEN_PREFIX + record["token"]:
        return "blocked"
    recorded_invocation = record.get("invocation_id")
    current = properties.get("InvocationID")
    if recorded_invocation and current and current != recorded_invocation:
        return "blocked"
    return "owned"


def _stop_unit(host: Host, record: Dict[str, Any], wait_seconds: float) -> str:
    """Stop an owned unit; ``"stopped"``, ``"absent"``, ``"blocked"`` or ``"unknown"``.

    A failed ``is-active``/show query is never read as "it stopped": only an
    explicit inactive/failed state (or a proven absence) counts, and an
    unknown outcome aborts cleanup.
    """
    name = record["name"]
    running = _unit_running(host, name)
    if running == "unknown":
        return "unknown"
    if running == "absent":
        return "absent"
    if running == "running":
        try:
            stop_result = host.run(["systemctl", "stop", name])
        except Exception:
            return "unknown"
        if stop_result.returncode != 0:
            return "unknown"
    deadline = time.time() + max(wait_seconds, 0.0)
    while True:
        running = _unit_running(host, name)
        if running == "unknown":
            return "unknown"
        if running in ("stopped", "absent"):
            _try_run(host, ["systemctl", "reset-failed", name])
            return "stopped"
        if time.time() >= deadline:
            return "blocked"
        time.sleep(UNIT_STOP_POLL_SECONDS)


def is_unit_file_path(path: str) -> bool:
    """True when ``path`` is a direct unit file in a supported unit directory."""
    directory, _, name = path.rpartition("/")
    return directory in SYSTEMD_UNIT_DIRS and name.endswith(UNIT_FILE_SUFFIXES)


def _unit_file_name(path: str) -> Optional[str]:
    """The unit a recorded unit file defines, or ``None`` for anything else."""
    if not is_unit_file_path(path):
        return None
    return path.rpartition("/")[2]


def _needs_daemon_reload(path: str) -> bool:
    """True when removing ``path`` changes the loaded unit tree."""
    return any(path == directory or path.startswith(directory + "/")
               for directory in SYSTEMD_UNIT_DIRS)


def _prepare_unit_file_removal(host: Host, path: str, unit: str,
                               wait_seconds: float) -> str:
    """``"ready"``, ``"blocked"`` or ``"unknown"`` before unlinking a unit file.

    A unit file this run installed may have been activated by the worker or the
    finalizer. Its file identity alone therefore proves nothing about the
    runtime unit: the loaded unit must have this exact file as its
    ``FragmentPath`` (that is the ownership proof), and it must be stopped and
    verified inactive before the file is unlinked. A same-named unit loaded from
    another file is never ours and is refused; a state systemd cannot answer is
    ``"unknown"`` and aborts cleanup.
    """
    state, properties = _unit_lookup(host, unit)
    if state == "error":
        return "unknown"
    if state == "absent":
        return "ready"
    load_state = (properties or {}).get("LoadState") or ""
    if load_state == "not-found":
        return "ready"
    if load_state != "loaded":
        return "unknown"
    if (properties or {}).get("FragmentPath") != path:
        return "blocked"
    stopped = _stop_unit(host, {"name": unit}, wait_seconds)
    if stopped == "unknown":
        return "unknown"
    if stopped == "blocked":
        return "blocked"
    return "ready"


def _container_owned(record: Dict[str, Any], info: Dict[str, Any]) -> bool:
    if (info.get("Name") or "").lstrip("/") != record.get("name"):
        return False
    # The full inspected ID must be exactly the ID we recorded: a name rebound to
    # another container is not ours.
    if not record.get("id") or info.get("Id") != record["id"]:
        return False
    labels = (info.get("Config") or {}).get("Labels") or {}
    recorded_labels = record.get("labels") or {}
    if not recorded_labels:
        return False
    for key, value in recorded_labels.items():
        if labels.get(key) != value:
            return False
    return True


def _volume_owned(record: Dict[str, Any], info: Dict[str, Any]) -> bool:
    if info.get("Name") != record.get("name"):
        return False
    # A non-empty creation time plus every recorded label (including the per-run
    # token) is the ownership evidence; there is no name-only fallback.
    if not record.get("created_at") or info.get("CreatedAt") != record["created_at"]:
        return False
    labels = info.get("Labels") or {}
    recorded_labels = record.get("labels") or {}
    if not recorded_labels:
        return False
    for key, value in recorded_labels.items():
        if labels.get(key) != value:
            return False
    return True


def _retain_ledger(host: Host, ledger_path: str, data: Dict[str, Any],
                   remaining: Dict[str, List[Dict[str, Any]]]) -> bool:
    """Rewrite the ledger with only the entries that still need removal."""
    merged = dict(data)
    for field in LEDGER_LIST_FIELDS:
        merged[field] = list(remaining.get(field, []))
    try:
        ledger = Ledger.open_existing(ledger_path, host)
    except LedgerError:
        return False
    if ledger is None:
        return False
    ledger._data = merged
    try:
        ledger.write()
    except (OSError, LedgerError):
        return False
    return True


def _abort_cleanup(host: Host, ledger_path: str, data: Dict[str, Any],
                   result: Dict[str, Any], reason: str) -> Dict[str, Any]:
    """Abort cleanup after an unknown outcome, preserving every resource.

    Nothing else is touched and the ledger is rewritten with *all* entries still
    recorded, so a retry starts from the complete state and already-removed
    objects are simply reported as absent.
    """
    result["blocked"].append(reason)
    remaining = {field: list(data.get(field, [])) for field in LEDGER_LIST_FIELDS}
    if not _retain_ledger(host, ledger_path, data, remaining):
        result["blocked"].append("ledger:retain")
    result["incomplete"] = True
    return result


def cleanup_fixture(ledger_path: str, host: Host,
                    stop_wait_seconds: Optional[float] = None) -> Dict[str, Any]:
    """Remove only the resources the ledger records as created by this fixture.

    Every step re-checks ownership (filesystem device/inode + digest, Docker full
    ID/labels/token, systemd launch token) and refuses anything that no longer
    matches. A missing ledger removes nothing; an unusable ledger is refused
    outright. Recorded units are stopped first, and when any recorded object
    cannot be removed the ledger is retained with the remaining entries and the
    result is marked ``incomplete`` so a retry can finish the job. Objects that
    are already gone are tolerated.
    """
    wait = UNIT_STOP_WAIT_SECONDS if stop_wait_seconds is None else stop_wait_seconds
    result: Dict[str, Any] = {"removed": [], "absent": [], "blocked": [],
                              "incomplete": False, "ledger": ledger_path}
    try:
        data = read_ledger(host, ledger_path)
    except LedgerError as exc:
        result["blocked"].append("ledger:%s" % exc)
        result["incomplete"] = True
        return result
    if data is None:
        result["absent"].append("ledger")
        return result

    remaining: Dict[str, List[Dict[str, Any]]] = {field: [] for field in LEDGER_LIST_FIELDS}
    reload_needed = False

    # Owned transient units first: a unit that is still running may own the job
    # files. If one cannot be proven ours and stopped, retain everything.
    units_blocked = False
    for record in data.get("units", []):
        name = record.get("name") or ""
        state = _unit_state(host, record)
        if state == "unknown":
            return _abort_cleanup(host, ledger_path, data, result,
                                  "unit:%s (unknown runtime state)" % name)
        if state == "absent":
            result["absent"].append("unit:%s" % name)
            continue
        if state == "blocked":
            result["blocked"].append("unit:%s" % name)
            remaining["units"].append(record)
            units_blocked = True
            continue
        stop_state = _stop_unit(host, record, wait)
        if stop_state == "unknown":
            return _abort_cleanup(host, ledger_path, data, result,
                                  "unit:%s (unknown stop outcome)" % name)
        if stop_state == "blocked":
            result["blocked"].append("unit:%s" % name)
            remaining["units"].append(record)
            units_blocked = True
            continue
        result["removed"].append("unit:%s" % name)

    if units_blocked:
        for field in ("containers", "volumes", "files", "links", "trees", "dirs"):
            remaining[field] = list(data.get(field, []))
        result["incomplete"] = True
        if not _retain_ledger(host, ledger_path, data, remaining):
            result["blocked"].append("ledger:retain")
        return result

    # Preflight every recorded unit file: the worker or the finalizer may have
    # activated one of them, so their runtime state must be *known* before
    # anything else is removed. An unknown systemd answer aborts cleanup with
    # every resource and the ledger intact.
    for record in data.get("files", []):
        path = record.get("path") or ""
        unit = _unit_file_name(path)
        if unit is None or _verify_regular(host, record) != "owned":
            continue
        state, properties = _unit_lookup(host, unit)
        load_state = (properties or {}).get("LoadState") or ""
        if state == "error" or (state == "present" and load_state not in ("loaded",
                                                                         "not-found")):
            return _abort_cleanup(host, ledger_path, data, result,
                                  "file:%s (unknown unit %s state)" % (path, unit))

    # Containers: verify the exact full recorded ID, then remove by that ID.
    for record in data.get("containers", []):
        name = record.get("name") or ""
        state, info = _docker_lookup(host, ["docker", "inspect", "--format",
                                            "{{json .}}", name])
        if state == "absent":
            result["absent"].append("container:%s" % name)
            continue
        if state != "present" or not _container_owned(record, info):
            result["blocked"].append("container:%s" % name)
            remaining["containers"].append(record)
            continue
        if _try_run(host, ["docker", "rm", "-f", info["Id"]]):
            result["removed"].append("container:%s" % name)
        else:
            result["blocked"].append("container:%s" % name)
            remaining["containers"].append(record)

    # Volumes: Docker removes volumes by name only, so identity is re-verified
    # immediately before the removal.
    for record in data.get("volumes", []):
        name = record.get("name") or ""
        state, info = _docker_lookup(host, ["docker", "volume", "inspect", "--format",
                                            "{{json .}}", name])
        if state == "absent":
            result["absent"].append("volume:%s" % name)
            continue
        if state != "present" or not _volume_owned(record, info):
            result["blocked"].append("volume:%s" % name)
            remaining["volumes"].append(record)
            continue
        if _try_run(host, ["docker", "volume", "rm", name]):
            result["removed"].append("volume:%s" % name)
        else:
            result["blocked"].append("volume:%s" % name)
            remaining["volumes"].append(record)

    for record in data.get("files", []):
        path = record.get("path") or ""
        state = _verify_regular(host, record)
        if state == "absent":
            result["absent"].append("file:%s" % path)
            continue
        if state != "owned":
            result["blocked"].append("file:%s" % path)
            remaining["files"].append(record)
            continue
        unit = _unit_file_name(path)
        if unit is not None:
            # This run installed the unit file; the worker or the finalizer may
            # have activated it. Stop the unit that systemd loaded from exactly
            # this file and verify it is inactive before unlinking the file.
            decision = _prepare_unit_file_removal(host, path, unit, wait)
            if decision == "unknown":
                return _abort_cleanup(
                    host, ledger_path, data, result,
                    "file:%s (unknown unit %s state)" % (path, unit))
            if decision == "blocked":
                result["blocked"].append("file:%s" % path)
                remaining["files"].append(record)
                continue
        try:
            host.unlink(path)
        except FileNotFoundError:
            result["absent"].append("file:%s" % path)
            continue
        except OSError:
            result["blocked"].append("file:%s" % path)
            remaining["files"].append(record)
            continue
        result["removed"].append("file:%s" % path)
        if _needs_daemon_reload(path):
            reload_needed = True

    for record in data.get("links", []):
        path = record.get("path") or ""
        state = _verify_link(host, record)
        if state == "absent":
            result["absent"].append("link:%s" % path)
            continue
        if state != "owned":
            result["blocked"].append("link:%s" % path)
            remaining["links"].append(record)
            continue
        try:
            host.unlink(path)
        except FileNotFoundError:
            result["absent"].append("link:%s" % path)
            continue
        except OSError:
            result["blocked"].append("link:%s" % path)
            remaining["links"].append(record)
            continue
        result["removed"].append("link:%s" % path)

    for record in data.get("trees", []):
        path = record.get("path") or ""
        state = _verify_directory(host, record)
        if state == "absent":
            result["absent"].append("tree:%s" % path)
            continue
        if state != "owned":
            result["blocked"].append("tree:%s" % path)
            remaining["trees"].append(record)
            continue
        try:
            host.remove_tree(path)
        except FileNotFoundError:
            result["absent"].append("tree:%s" % path)
            continue
        except OSError:
            result["blocked"].append("tree:%s" % path)
            remaining["trees"].append(record)
            continue
        result["removed"].append("tree:%s" % path)

    directories = sorted(data.get("dirs", []),
                         key=lambda item: item.get("path", "").count(os.sep),
                         reverse=True)
    for record in directories:
        path = record.get("path") or ""
        state = _verify_directory(host, record)
        if state == "absent":
            result["absent"].append("dir:%s" % path)
            continue
        if state != "owned":
            result["blocked"].append("dir:%s" % path)
            remaining["dirs"].append(record)
            continue
        try:
            host.rmdir(path)
        except FileNotFoundError:
            result["absent"].append("dir:%s" % path)
            continue
        except OSError:
            result["blocked"].append("dir:%s" % path)
            remaining["dirs"].append(record)
            continue
        result["removed"].append("dir:%s" % path)
        if _needs_daemon_reload(path):
            reload_needed = True

    if reload_needed:
        _try_run(host, ["systemctl", "daemon-reload"])

    result["incomplete"] = bool(result["blocked"])
    if result["incomplete"]:
        if not _retain_ledger(host, ledger_path, data, remaining):
            result["blocked"].append("ledger:retain")
        result["incomplete"] = True
        return result

    # Everything recorded is gone: remove the ledger itself, last, and only while
    # the exact path still holds a regular file.
    try:
        ledger_info = host.lstat(ledger_path)
    except OSError:
        ledger_info = None
    if ledger_info is not None and stat.S_ISREG(ledger_info.st_mode):
        try:
            host.unlink(ledger_path)
        except OSError:
            result["blocked"].append("ledger:remove")
            result["incomplete"] = True
        else:
            result["removed"].append("ledger")
    return result


def _open_ledger_for_unit(ledger_path: str, unit: str, host: Host) -> "Ledger":
    try:
        ledger = Ledger.open_existing(ledger_path, host)
    except LedgerError as exc:
        _fail("refusing to record unit %s: %s" % (unit, exc))
    if ledger is None:
        _fail("refusing to record unit %s: no ownership ledger is present" % unit)
    prefix = ledger.data.get("prefix") or ""
    if not unit or "/" in unit or not unit.startswith(prefix + "-"):
        _fail("refusing to record a unit outside the drill prefix: %s" % unit)
    return ledger


def reserve_unit(ledger_path: str, unit: str, host: Host) -> None:
    """Record the intent to launch ``unit`` *before* ``systemd-run`` runs.

    The entry carries the ledger's per-run token, so cleanup can later find the
    unit by its Description token (or prove it absent) even when the process
    dies between the launch and the confirmation - without ever touching a
    same-named unit that does not carry the token.
    """
    ledger = _open_ledger_for_unit(ledger_path, unit, host)
    token = ledger.data.get("token") or ""
    if not token:
        _fail("refusing to reserve unit %s: the ledger has no ownership token" % unit)
    for entry in ledger.data.get("units", []):
        if entry.get("name") == unit:
            _fail("refusing to reserve unit %s: it is already recorded" % unit)
    ledger.add_unit({"name": unit, "token": token, "invocation_id": None})


def record_unit(ledger_path: str, unit: str, host: Host) -> None:
    """Confirm a launched transient unit and record its invocation ID."""
    ledger = _open_ledger_for_unit(ledger_path, unit, host)
    state, properties = _unit_lookup(host, unit)
    if state == "error":
        _fail("refusing to record unit %s: systemd could not report its state" % unit)
    if state == "absent":
        _fail("refusing to record unit %s: systemd does not know this unit" % unit)
    token = ledger.data.get("token") or ""
    if properties.get("Description") != UNIT_TOKEN_PREFIX + token:
        _fail("refusing to record unit %s: launch token mismatch" % unit)
    record = {"name": unit, "token": token,
              "invocation_id": properties.get("InvocationID")}
    entries = ledger.data.get("units", [])
    for index, entry in enumerate(entries):
        if entry.get("name") == unit:
            entries[index] = record
            ledger.write()
            return
    ledger.add_unit(record)


def confirm_unit(ledger_path: str, unit: str, host: Host) -> None:
    """Confirm a just-launched transient unit, tolerating a proven early exit.

    ``systemd-run --collect`` unloads a unit as soon as it finishes. A short
    synthetic job can therefore be gone before the launch receipt is written,
    even though ``systemd-run`` proved it started. In that case the unit is
    recorded as ``collected`` (no invocation id); cleanup later proves it absent
    and touches nothing. A still-loaded unit must still carry our exact launch
    token, and an unreadable bus state is refused.
    """
    ledger = _open_ledger_for_unit(ledger_path, unit, host)
    state, properties = _unit_lookup(host, unit)
    if state == "error":
        _fail("refusing to confirm unit %s: systemd could not report its state" % unit)
    token = ledger.data.get("token") or ""
    if state == "absent":
        record: Dict[str, Any] = {"name": unit, "token": token,
                                  "invocation_id": None, "collected": True}
    else:
        if properties.get("Description") != UNIT_TOKEN_PREFIX + token:
            _fail("refusing to confirm unit %s: launch token mismatch" % unit)
        record = {"name": unit, "token": token,
                  "invocation_id": properties.get("InvocationID")}
    entries = ledger.data.get("units", [])
    for index, entry in enumerate(entries):
        if entry.get("name") == unit:
            entries[index] = record
            ledger.write()
            return
    ledger.add_unit(record)


def ledger_token(ledger_path: str, host: Host) -> str:
    """Return the validated per-run ownership token from an existing ledger."""
    try:
        ledger = Ledger.open_existing(ledger_path, host)
    except LedgerError as exc:
        _fail("refusing to read the ownership token: %s" % exc)
    if ledger is None:
        _fail("refusing to read the ownership token: no ownership ledger: %s"
              % ledger_path)
    token = ledger.data.get("token") or ""
    if not token:
        _fail("refusing to read the ownership token: the ledger has no token")
    return token


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="vm_restore_fixture")
    parser.add_argument("--identifier",
                        help="unique drill identifier (letters/digits/dash); "
                             "required for --plan and --create")
    parser.add_argument("--image", default=os.environ.get("VPS3XUI_DRILL_IMAGE"),
                        help="preloaded repo@sha256:... test image")
    parser.add_argument("--release-dir", default=os.environ.get("VPS3XUI_DRILL_RELEASE"),
                        help="release directory holding the vps3xui package")
    parser.add_argument("--ledger", default=os.environ.get("VPS3XUI_DRILL_LEDGER"),
                        help="durable ownership ledger path (required to create or clean)")
    parser.add_argument("--plan", action="store_true", help="print the fixture plan only")
    parser.add_argument("--create", action="store_true", help="create the fixture on this host")
    parser.add_argument("--cleanup", action="store_true",
                        help="remove only the resources recorded in --ledger")
    parser.add_argument("--record-unit", metavar="UNIT",
                        help="record a drill-launched transient unit in --ledger")
    parser.add_argument("--reserve-unit", metavar="UNIT",
                        help="reserve a transient unit in --ledger before launching it")
    parser.add_argument("--create-dir", metavar="PATH",
                        help="create and ledger-record a restore destination directory")
    parser.add_argument("--create-tree", metavar="PATH",
                        help="create and ledger-record a disposable restore tree")
    parser.add_argument("--write-file", metavar="PATH",
                        help="create and ledger-record a file; content comes from stdin")
    parser.add_argument("--create-restore-container", metavar="NAME",
                        help="create a stopped, ledger-owned restore container")
    parser.add_argument("--create-job", metavar="JOB_ID",
                        help="clone the fixture job into a new independent ledger-owned job")
    parser.add_argument("--template-job", default=None,
                        help="template job for --create-job")
    parser.add_argument("--mountpoint", default=None,
                        help="real volume mountpoint for --create-job")
    parser.add_argument("--root", default=os.sep, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    modes = [args.plan, args.create, args.cleanup, bool(args.record_unit),
             bool(args.reserve_unit), bool(args.create_dir), bool(args.create_tree),
             bool(args.write_file),
             bool(args.create_restore_container), bool(args.create_job)]
    if sum(1 for item in modes if item) != 1:
        _fail("choose exactly one of --plan, --create, --cleanup, --record-unit "
              "or --reserve-unit, --create-dir, --write-file, "
              "--create-tree, "
              "--create-restore-container, --create-job")
    host = Host(root=args.root)
    if args.plan:
        if not args.identifier:
            _fail("--plan requires --identifier")
        image = args.image or "fixture.local/app@sha256:" + "0" * 64
        json.dump(plan_object(args.identifier, image), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    if args.cleanup:
        if not args.ledger:
            _fail("--cleanup requires --ledger")
        result = cleanup_fixture(args.ledger, host)
        if result.get("incomplete"):
            _fail("incomplete cleanup; the ownership ledger was retained: %s"
                  % args.ledger)
        return 0
    if args.reserve_unit:
        if not args.ledger:
            _fail("--reserve-unit requires --ledger")
        reserve_unit(args.ledger, args.reserve_unit, host)
        return 0
    if args.record_unit:
        if not args.ledger:
            _fail("--record-unit requires --ledger")
        record_unit(args.ledger, args.record_unit, host)
        return 0
    if args.create_dir:
        if not args.ledger:
            _fail("--create-dir requires --ledger")
        create_owned_dir(args.ledger, args.create_dir, host)
        return 0
    if args.create_tree:
        if not args.ledger:
            _fail("--create-tree requires --ledger")
        create_owned_tree(args.ledger, args.create_tree, host)
        return 0
    if args.write_file:
        if not args.ledger:
            _fail("--write-file requires --ledger")
        content = sys.stdin.read()
        write_owned_file(args.ledger, args.write_file, content, 0o755, host)
        return 0
    if args.create_restore_container:
        if not args.ledger or not args.image:
            _fail("--create-restore-container requires --ledger and --image")
        create_owned_container(args.ledger, args.create_restore_container, args.image, host)
        return 0
    if args.create_job:
        if not args.ledger or not args.template_job or not args.image or not args.mountpoint:
            _fail("--create-job requires --ledger, --template-job, --image and --mountpoint")
        try:
            ledger = Ledger.open_existing(args.ledger, host)
        except LedgerError as exc:
            _fail("--create-job could not read the ledger: %s" % exc)
        if ledger is None:
            _fail("--create-job requires an existing ownership ledger")
        names = fixture_identity(ledger.data.get("identifier") or "")
        result = create_owned_job(args.ledger, args.create_job, args.template_job,
                                  args.image, args.release_dir or REPO_ROOT,
                                  args.mountpoint, names, host)
        json.dump(result, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    if not args.ledger:
        _fail("--create requires --ledger (the durable ownership ledger)")
    if not args.identifier:
        _fail("--create requires --identifier")
    if not args.image:
        _fail("--image (or VPS3XUI_DRILL_IMAGE) is required to create the fixture")
    result = create(args.identifier, args.image, args.release_dir or REPO_ROOT,
                    args.ledger, host)
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
