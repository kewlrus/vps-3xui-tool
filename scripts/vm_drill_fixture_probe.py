#!/usr/bin/env python3
"""Faithful synthetic probe observation for the disposable drill fixture.

The real restore drill always runs the shipped read-only probe
(``vps3xui/probe.py``) on the disposable host. This module exists only so the
*local* test suite can drive the real ``compare``, ``build_plan`` and
``BackupWorker`` preflight code against the exact fixture
``scripts/vm_restore_fixture.py`` creates, without a Linux host and without
pretending that a probe ran.

Everything here is derived from the generated fixture manifest and the exact
fixture file contents (``fixture_files``/``fixture_symlinks``), so a plan built
from this observation matches what the worker's own preflight recomputes. The
Certbot cron observation is never fabricated: local tests pass the output of the
real ``probe_cron`` reading the synthetic fixture unit files (see
``cron_observation``).
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, List, Optional

import vm_restore_fixture as fixture

PROBE_VERSION = 3
SYSTEMD_VERSION = "systemd 255 (255.4-1ubuntu8.4)"
DOCKER_VERSION = "27.1.1"
COMPOSE_VERSION = "2.29.1"
PYTHON_VERSION = "3.12.3"
FREE_BYTES = 40_000_000_000


def machine_id(names: Dict[str, str]) -> str:
    return hashlib.sha256(("vps3xui-drill-machine:" + names["prefix"]).encode("utf-8")).hexdigest()[:32]


def _trusted_fingerprints(names: Dict[str, str], image: str,
                          alias_pins: Optional[List[Dict[str, str]]] = None) -> Dict[str, str]:
    digests: Dict[str, str] = {}
    for item in fixture.fixture_files(names, image):
        digests[item["path"]] = hashlib.sha256(item["content"].encode("utf-8")).hexdigest()
    # Runtime-only vendor-alias pins (usrmerge /lib) derived by the fixture from
    # the very same installed file; the observation mirrors that shape.
    for item in alias_pins or ():
        digests[item["path"]] = item["sha256"]
    return digests


def _renewal_fingerprints(names: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    digest = hashlib.sha256(fixture.HOOK_COMMAND.encode("utf-8")).hexdigest()
    return {"%s.conf" % names["lineage"]: {"pre_hook": digest, "post_hook": digest,
                                           "renew_hook": digest}}


def cron_observation(root: str, *, extra_unit: Optional[str] = None) -> List[Dict[str, str]]:
    """Run the **real** ``probe_cron`` against synthetic, remapped host content.

    ``root`` must contain a synthetic systemd tree (``etc/systemd/system`` and/or
    the vendor directories). The shipped ``probe.probe_cron`` body is executed
    unchanged; only the absolute path lookups are remapped into ``root`` so no
    real host directory is read. The returned entries carry the canonical
    absolute unit paths and the real content digests, exactly as the probe would
    report.
    """
    import builtins
    from vps3xui import probe

    real_listdir = os.listdir
    real_isfile = os.path.isfile
    real_open = builtins.open
    prefix = root.rstrip("/") + "/"

    def remap(path):
        if isinstance(path, (str, os.PathLike)):
            text = os.fspath(path)
            if text.startswith("/"):
                return prefix + text.lstrip("/")
        return path

    def listdir(path="."):
        return real_listdir(remap(path))

    def isfile(path):
        return real_isfile(remap(path))

    def open_remap(path, *args, **kwargs):
        return real_open(remap(path), *args, **kwargs)

    os.listdir = listdir
    os.path.isfile = isfile
    builtins.open = open_remap
    try:
        if extra_unit:
            target = os.path.join(root, "etc/systemd/system", extra_unit)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with real_open(target, "w", encoding="utf-8") as handle:
                handle.write("[Unit]\nDescription=certbot renamed unit\n")
        return probe.probe_cron([])
    finally:
        os.listdir = real_listdir
        os.path.isfile = real_isfile
        builtins.open = real_open


def write_unit_files(root: str, names: Dict[str, str], image: str,
                     overrides: Optional[Dict[str, str]] = None) -> None:
    """Materialise the fixture's real systemd unit files under ``root``.

    ``probe_cron`` reads immediate ``.service``/``.timer`` files in every unit
    directory (``/etc/systemd/system`` and the vendor directories); nested
    drop-ins are written too so the tree matches the disposable host, where the
    real probe would also scan the top level.
    """
    overrides = overrides or {}
    for item in fixture.fixture_files(names, image):
        path = item["path"]
        if not any(path.startswith(directory + "/")
                   for directory in fixture.SYSTEMD_UNIT_DIRS):
            continue
        target = os.path.join(root, path.lstrip("/"))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(overrides.get(path, item["content"]))


# systemd's unit load path, highest precedence first. ``systemctl mask --runtime``
# writes a ``/dev/null`` symlink into ``/run/systemd/system``; that mask is only
# effective when no higher-precedence unit file of the same name exists. This is
# the exact fact the fixture placement must satisfy: vendor units (``/usr/lib``)
# are shadowed by the runtime mask, ``/etc`` units are not.
UNIT_LOAD_PATH = (
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/local/lib/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
)


def unit_fragment_path(root: str, unit: str) -> Optional[str]:
    """The winning fragment for ``unit`` under ``root``, or ``None`` if absent.

    Models the systemd load path (/etc > /run > /usr/local/lib > /lib >
    /usr/lib); the first existing fragment wins. A test can materialise the
    runtime mask (``/run/systemd/system/<unit> -> /dev/null``) and then ask which
    fragment systemd would actually load, instead of assuming every mask takes
    effect.
    """
    for directory in UNIT_LOAD_PATH:
        candidate = os.path.join(root, directory.lstrip("/"), unit)
        if os.path.lexists(candidate):
            return directory + "/" + unit
    return None


def runtime_mask_is_effective(root: str, unit: str) -> bool:
    """True when ``systemctl mask --runtime <unit>`` would actually mask it.

    The runtime mask is written to ``/run/systemd/system``; it is ineffective
    when an ``/etc/systemd/system`` unit file of the same name outranks it.
    """
    for directory in UNIT_LOAD_PATH:
        if directory == "/run/systemd/system":
            # Nothing with higher precedence exists, so the runtime mask wins.
            return True
        if os.path.lexists(os.path.join(root, directory.lstrip("/"), unit)):
            return False
    return True


def fixture_probe(names: Dict[str, str], image: str, mountpoint: str,
                  restored: Optional[Dict[str, Any]] = None,
                  cron_certbot: Optional[List[Any]] = None,
                  unit_states: Optional[Dict[str, Dict[str, str]]] = None,
                  errors: Optional[List[str]] = None,
                  at_queue: Optional[Dict[str, Any]] = None,
                  alias_pins: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
    """A probe-shaped observation that the generated fixture manifest accepts."""
    reference = image.split("@", 1)[0]
    if at_queue is None:
        # The disposable fixture host has no ``at`` package installed; the
        # resulting queue fact is the supported "absent" state.
        at_queue = {
            "tooling": {"at": None, "atq": None},
            "state": "absent",
            "atq": {"present": False, "observed": False, "count": None},
            "directories": [],
        }
    containers: List[Dict[str, Any]] = [
        {
            "id": "id-drill-app-0001", "name": names["container"],
            "image": reference, "image_id": "sha256:drill-app",
            "repo_digests": [image], "running": True, "status": "running",
            "restart_policy": "unless-stopped", "network_mode": "bridge",
            "compose_project": names["compose_project"],
            "compose_service": names["compose_service"],
            "mounts": [
                {"type": "volume", "name": names["volume"], "source": mountpoint,
                 "destination": "/data", "rw": True, "driver": "local", "mode": ""}
            ],
        },
        {
            "id": "id-drill-fail2ban-0002", "name": names["fail2ban_container"],
            "image": reference, "image_id": "sha256:drill-fail2ban",
            "repo_digests": [image], "running": True, "status": "running",
            "restart_policy": "unless-stopped", "network_mode": "bridge",
            "compose_project": names["fail2ban_compose_project"],
            "compose_service": "fail2ban", "mounts": [],
        },
        {
            "id": "id-drill-idle-0003", "name": names["idle_container"],
            "image": reference, "image_id": "sha256:drill-idle",
            "repo_digests": [image], "running": False, "status": "exited",
            "restart_policy": "no", "network_mode": "bridge",
            "compose_project": names["compose_project"],
            "compose_service": "idle", "mounts": [],
        },
    ]
    if restored is not None:
        containers.append({
            "id": restored["id"], "name": restored["name"], "image": reference,
            "image_id": "sha256:drill-restored", "repo_digests": [image],
            "running": False, "status": "created", "restart_policy": "no",
            "network_mode": "bridge",
            "compose_project": "vps3xui-drill-restore",
            "compose_service": "restore", "mounts": [],
        })

    base_units = {
        "certbot.service": {"load_state": "loaded", "active_state": "inactive",
                            "unit_file_state": "enabled"},
        "certbot.timer": {"load_state": "loaded", "active_state": "active",
                          "unit_file_state": "enabled"},
        fixture.SYSTEMD_UNITS[0]: {"load_state": "loaded", "active_state": "inactive",
                                   "unit_file_state": "enabled"},
        fixture.SYSTEMD_UNITS[1]: {"load_state": "loaded", "active_state": "active",
                                   "unit_file_state": "enabled"},
    }
    units = dict(base_units)
    for unit, state in (unit_states or {}).items():
        units[unit] = state

    paths: Dict[str, Any] = {}
    for path, kind, size in (
        (names["compose_dir"] + "/docker-compose.yaml", "file", 1024),
        (names["compose_dir"] + "/app.env", "file", 64),
        ("/etc/letsencrypt", "dir", 300_000),
        ("/etc/ufw", "dir", 65_536),
        ("/etc/default/ufw", "file", 2048),
        ("/usr/local/sbin/certbot-http01-guard", "file", 4096),
        (mountpoint, "dir", 131_072),
    ):
        paths[path] = {"exists": True, "is_symlink": False, "kind": kind,
                       "size_bytes": size}
    paths[fixture_labels_lease(names)] = {"exists": False, "is_symlink": False,
                                          "kind": None, "size_bytes": 0}

    renewal_name = "%s.conf" % names["lineage"]
    return {
        "probe_version": PROBE_VERSION,
        "machine_id": machine_id(names),
        "os": {"id": "ubuntu", "version_id": "24.04"},
        "arch": "x86_64",
        "python": PYTHON_VERSION,
        "errors": list(errors or []),
        "docker": {"present": True, "version": DOCKER_VERSION,
                   "compose_version": COMPOSE_VERSION, "root_dir": "/var/lib/docker"},
        "containers": containers,
        "volumes": [{"name": names["volume"], "driver": "local", "options": {},
                     "mountpoint": mountpoint, "scope": "local"}],
        "systemd": {"present": True, "version": SYSTEMD_VERSION, "units": units,
                    "unit_files": list(fixture.SYSTEMD_UNITS) + ["certbot.service", "certbot.timer"]},
        "tar": {"present": True, "gnu": True, "version": "tar (GNU tar) 1.35"},
        "certbot": {
            "present": True, "binary": "/usr/bin/certbot",
            "renewal_files": [renewal_name],
            "renewal_hooks": {renewal_name: {"pre_hook": True, "post_hook": True,
                                             "renew_hook": True, "authenticator": "standalone"}},
            "guard_present": True, "guard_enabled": True,
            "lease_present": False, "lease_age_seconds": None,
            "renewal_hook_fingerprints": _renewal_fingerprints(names),
            "renewal_hook_dirs": {path: {} for path in fixture_hook_dirs()},
        },
        "trusted_fingerprints": _trusted_fingerprints(names, image, alias_pins),
        "trusted_modes": {
            "/usr/local/sbin/certbot-http01-guard": {"mode": "0755", "uid": 0,
                                                     "gid": 0, "is_symlink": False},
        },
        "cron_certbot": list(cron_certbot or []),
        "at_queue": at_queue,
        "compose": {names["compose_project"]: {"valid": True, "state": "valid",
                                               "services": [names["compose_service"]]}},
        "ufw": {"present": True, "version": "ufw 0.36.2", "active": True,
                "status_available": True},
        "paths": paths,
        "writable_layer": {
            "%s:%s" % (names["fail2ban_container"], fixture.FAIL2BAN_CONFIG_PATH):
                {"exists": True, "size_bytes": 65_536},
            "%s:%s" % (names["fail2ban_container"], fixture.FAIL2BAN_DATA_PATH):
                {"exists": True, "size_bytes": 131_072},
        },
        "space": {
            "/": {"total_bytes": 80_000_000_000, "free_bytes": FREE_BYTES},
            "/var/backups": {"total_bytes": 80_000_000_000, "free_bytes": FREE_BYTES},
            "/var/lib/docker": {"total_bytes": 80_000_000_000, "free_bytes": FREE_BYTES},
        },
    }


def fixture_labels_lease(names: Dict[str, str]) -> str:
    return "/var/lib/certbot-http01-guard/lease.json"


def fixture_hook_dirs() -> List[str]:
    return ["/etc/letsencrypt/renewal-hooks/pre",
            "/etc/letsencrypt/renewal-hooks/post",
            "/etc/letsencrypt/renewal-hooks/deploy"]


if __name__ == "__main__":  # pragma: no cover - manual inspection helper
    import json
    identity = fixture.fixture_identity("fixture-probe")
    print(json.dumps(fixture_probe(identity, "fixture.local/app@sha256:" + "0" * 64,
                                   "/var/lib/docker/volumes/%s/_data" % identity["volume"]),
                     indent=2, sort_keys=True))
