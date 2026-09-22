"""Synthetic host/system harness for the test suite.

The point of this harness is to exercise the real parsing, plan, job, worker
and verification code paths with a controllable in-process host — no SSH, no
Docker, no real VPS, no real secrets. Secret canaries placed here must never
appear in CLI output or logs.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import uuid
from typing import Any, Dict, List, Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from vps3xui import TOOL_VERSION
from vps3xui import coordination as coord
from vps3xui import manifest as manifest_module
from vps3xui.adapters import archive as archive_adapter
from vps3xui.errors import ToolError
from vps3xui.hostops import HostOps
from vps3xui.inventory import Inventory
from vps3xui.plan import build_plan
from vps3xui.util import ensure_dir, sha256_hex
from vps3xui.worker import finalizer
from vps3xui.worker.backup_worker import BackupWorker
from vps3xui.worker.jobctx import JobContext
from vps3xui.worker.metadata import build_backup_json, build_images_json

SECRET_CANARY = "CANARY-liteLLM-master-key-9f2c"
ENV_CANARY = "CANARY-duckdns-token-7711"
DB_CANARY = "CANARY-panel-client-secret-4400"

MACHINE_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
HOST_KEY = "SHA256:0123456789abcdefghijklmnopqrstuvwxyzABCDEF"

# The ExecStopPost unit metadata a healthy systemd unit reports. Synthetic
# callers that expect a legitimate success must pass this explicitly; the
# production finalizer never invents it, so a caller that omits it models
# missing unit evidence and must not reach COMPLETE.
UNIT_SUCCESS_RESULT = {"SERVICE_RESULT": "success", "EXIT_CODE": "exited", "EXIT_STATUS": "0"}

# Synthetic trust contract shared by the fake probe and approved manifests.
# The full required trust set: guard helper + marker, the tool's cleanup units,
# the Certbot drop-in and the lineage renewal file. The privileged guard helper
# also carries machine-bound permission pins (mode/uid/gid).
TRUSTED_FILES = [
    {"path": "/usr/local/sbin/certbot-http01-guard", "sha256": "b" * 64,
     "mode": "0755", "uid": 0, "gid": 0},
    {"path": "/etc/certbot-http01-guard.enabled", "sha256": "c" * 64},
    {"path": "/etc/systemd/system/certbot-http01-cleanup.service", "sha256": "1" * 64},
    {"path": "/etc/systemd/system/certbot-http01-cleanup.timer", "sha256": "2" * 64},
    {"path": "/etc/systemd/system/certbot.service.d/http01-cleanup.conf", "sha256": "3" * 64},
    {"path": "/etc/letsencrypt/renewal/kewlsub.duckdns.org.conf", "sha256": "4" * 64},
]
TRUSTED_MODES = {
    "/usr/local/sbin/certbot-http01-guard": {"mode": "0755", "uid": 0, "gid": 0,
                                             "is_symlink": False},
}
HOOK_FINGERPRINTS = {
    "kewlsub.duckdns.org.conf:pre_hook": "a" * 64,
    "kewlsub.duckdns.org.conf:post_hook": "d" * 64,
    "kewlsub.duckdns.org.conf:renew_hook": "e" * 64,
}
RENEWAL_HOOK_DIRS = [
    "/etc/letsencrypt/renewal-hooks/pre",
    "/etc/letsencrypt/renewal-hooks/post",
    "/etc/letsencrypt/renewal-hooks/deploy",
]


class KillWorker(BaseException):
    """Simulates SIGKILL / RuntimeMaxSec termination of the worker process."""


def example_data() -> Dict[str, Any]:
    import json

    with open(manifest_module.EXAMPLE_MANIFEST_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def synthetic_probe(**overrides: Any) -> Dict[str, Any]:
    containers = [
        {
            "id": "id-litellm-0001",
            "name": "litellm",
            "image": "ghcr.io/berriai/litellm:1.101.0",
            "image_id": "sha256:litellm",
            "repo_digests": [
                "ghcr.io/berriai/litellm@sha256:32c04b00bc1a720e6d5eeb56a7e72f4e1e7d1e538e779c59b990cbddfd5e27da"
            ],
            "running": True,
            "status": "running",
            "restart_policy": "unless-stopped",
            "network_mode": "llmproxy_backend",
            "compose_project": "llmproxy",
            "compose_service": "litellm",
            "mounts": [
                {"type": "bind", "name": None, "source": "/opt/llmproxy/litellm-config.yaml",
                 "destination": "/app/config.yaml", "rw": False, "driver": None, "mode": ""},
                {"type": "volume", "name": "llmproxy_chatgpt_auth", "source": "/var/lib/docker/volumes/llmproxy_chatgpt_auth/_data",
                 "destination": "/var/lib/litellm/chatgpt", "rw": True, "driver": "local", "mode": ""},
            ],
        },
        {
            "id": "id-caddy-0002",
            "name": "caddy",
            "image": "caddy:2",
            "image_id": "sha256:caddy",
            "repo_digests": [
                "caddy@sha256:df7f1c2fb114453b951de51a98efc010db1655a92c2e86be6706714e2417a78d"
            ],
            "running": True,
            "status": "running",
            "restart_policy": "unless-stopped",
            "network_mode": "llmproxy_backend",
            "compose_project": "llmproxy",
            "compose_service": "caddy",
            "mounts": [
                {"type": "bind", "name": None, "source": "/opt/llmproxy/caddy/Caddyfile",
                 "destination": "/etc/caddy/Caddyfile", "rw": False, "driver": None, "mode": ""},
                {"type": "volume", "name": "llmproxy_caddy_data", "source": "/var/lib/docker/volumes/llmproxy_caddy_data/_data",
                 "destination": "/data", "rw": True, "driver": "local", "mode": ""},
                {"type": "volume", "name": "llmproxy_caddy_config", "source": "/var/lib/docker/volumes/llmproxy_caddy_config/_data",
                 "destination": "/config", "rw": True, "driver": "local", "mode": ""},
            ],
        },
        {
            "id": "id-3xui-0003",
            "name": "3xui_app",
            "image": "ghcr.io/mhsanaei/3x-ui:v3.7.0",
            "image_id": "sha256:3xui",
            "repo_digests": [
                "ghcr.io/mhsanaei/3x-ui@sha256:3b3131f1876e6bf35063a9ec4dd1c594e4525180bfc2e1c477dcc8a3c9550ca1"
            ],
            "running": True,
            "status": "running",
            "restart_policy": "unless-stopped",
            "network_mode": "host",
            "compose_project": "panel",
            "compose_service": "3xui",
            "mounts": [
                {"type": "bind", "name": None, "source": "/root/panel/db",
                 "destination": "/etc/x-ui", "rw": True, "driver": None, "mode": ""},
                {"type": "bind", "name": None, "source": "/etc/letsencrypt",
                 "destination": "/etc/letsencrypt", "rw": False, "driver": None, "mode": ""},
            ],
        },
        {
            "id": "id-telemt-0004",
            "name": "telemt",
            "image": "unknown/telemt",
            "image_id": "sha256:telemt",
            "repo_digests": [],
            "running": False,
            "status": "exited",
            "restart_policy": "no",
            "network_mode": "host",
            "compose_project": "telemt",
            "compose_service": "telemt",
            "mounts": [],
        },
    ]
    volumes = [
        {"name": "llmproxy_chatgpt_auth", "driver": "local", "options": {},
         "mountpoint": "/var/lib/docker/volumes/llmproxy_chatgpt_auth/_data", "scope": "local"},
        {"name": "llmproxy_caddy_data", "driver": "local", "options": {},
         "mountpoint": "/var/lib/docker/volumes/llmproxy_caddy_data/_data", "scope": "local"},
        {"name": "llmproxy_caddy_config", "driver": "local", "options": {},
         "mountpoint": "/var/lib/docker/volumes/llmproxy_caddy_config/_data", "scope": "local"},
    ]
    units = {
        "certbot.service": {"load_state": "loaded", "active_state": "inactive", "unit_file_state": "enabled"},
        "certbot.timer": {"load_state": "loaded", "active_state": "active", "unit_file_state": "enabled"},
        "certbot-http01-cleanup.service": {"load_state": "loaded", "active_state": "inactive", "unit_file_state": "enabled"},
        "certbot-http01-cleanup.timer": {"load_state": "loaded", "active_state": "active", "unit_file_state": "enabled"},
    }
    paths = {
        "/opt/llmproxy/docker-compose.yaml": {"exists": True, "is_symlink": False, "kind": "file", "size_bytes": 1024},
        "/opt/llmproxy/litellm-config.yaml": {"exists": True, "is_symlink": False, "kind": "file", "size_bytes": 2048},
        "/opt/llmproxy/.env": {"exists": True, "is_symlink": False, "kind": "file", "size_bytes": 512},
        "/opt/llmproxy/caddy/Caddyfile": {"exists": True, "is_symlink": False, "kind": "file", "size_bytes": 512},
        "/root/panel/compose.yml": {"exists": True, "is_symlink": False, "kind": "file", "size_bytes": 700},
        "/root/panel/db": {"exists": True, "is_symlink": False, "kind": "dir", "size_bytes": 5_000_000},
        "/etc/letsencrypt": {"exists": True, "is_symlink": False, "kind": "dir", "size_bytes": 300_000},
        "/etc/letsencrypt/live": {"exists": True, "is_symlink": False, "kind": "dir", "size_bytes": 4096},
        "/etc/letsencrypt/archive": {"exists": True, "is_symlink": False, "kind": "dir", "size_bytes": 200_000},
        "/etc/certbot-http01-guard.enabled": {"exists": True, "is_symlink": False, "kind": "file", "size_bytes": 33},
        "/usr/local/sbin/certbot-http01-guard": {"exists": True, "is_symlink": False, "kind": "file", "size_bytes": 4096},
        "/var/lib/certbot-http01-guard": {"exists": True, "is_symlink": False, "kind": "dir", "size_bytes": 4096},
        "/etc/ufw": {"exists": True, "is_symlink": False, "kind": "dir", "size_bytes": 65536},
        "/etc/default/ufw": {"exists": True, "is_symlink": False, "kind": "file", "size_bytes": 2048},
        "/etc/machine-id": {"exists": True, "is_symlink": False, "kind": "file", "size_bytes": 33},
    }
    data: Dict[str, Any] = {
        "probe_version": 3,
        "machine_id": MACHINE_ID,
        "os": {"id": "ubuntu", "version_id": "24.04"},
        "arch": "x86_64",
        "python": "3.12.3",
        "errors": [],
        "docker": {"present": True, "version": "27.1.1", "compose_version": "2.29.1",
                   "root_dir": "/var/lib/docker"},
        "containers": containers,
        "volumes": volumes,
        "systemd": {
            "present": True,
            "version": "systemd 255 (255.4-1ubuntu8.4)",
            "units": units,
            "unit_files": ["certbot.service", "certbot.timer",
                           "certbot-http01-cleanup.service", "certbot-http01-cleanup.timer"],
        },
        "tar": {"present": True, "gnu": True, "version": "tar (GNU tar) 1.35"},
        "certbot": {
            "present": True,
            "binary": "/usr/bin/certbot",
            "renewal_files": ["kewlsub.duckdns.org.conf"],
            "renewal_hooks": {
                "kewlsub.duckdns.org.conf": {
                    "pre_hook": True, "post_hook": True, "renew_hook": True,
                    "authenticator": "standalone",
                }
            },
            "guard_present": True,
            "guard_enabled": True,
            "lease_present": False,
            "lease_age_seconds": None,
            "renewal_hook_fingerprints": {
                "kewlsub.duckdns.org.conf": {
                    "pre_hook": HOOK_FINGERPRINTS["kewlsub.duckdns.org.conf:pre_hook"],
                    "post_hook": HOOK_FINGERPRINTS["kewlsub.duckdns.org.conf:post_hook"],
                    "renew_hook": HOOK_FINGERPRINTS["kewlsub.duckdns.org.conf:renew_hook"],
                }
            },
            "renewal_hook_dirs": {path: {} for path in RENEWAL_HOOK_DIRS},
        },
        "trusted_fingerprints": {item["path"]: item["sha256"] for item in TRUSTED_FILES},
        "trusted_modes": copy.deepcopy(TRUSTED_MODES),
        "cron_certbot": [],
        "at_queue": {
            "tooling": {"at": "/usr/bin/at", "atq": "/usr/bin/atq"},
            "state": "empty",
            "atq": {"present": True, "observed": True, "count": 0},
            "directories": [
                {"path": "/var/spool/cron/atjobs", "state": "empty", "jobs": 0},
            ],
        },
        "compose": {
            "llmproxy": {"valid": True, "state": "valid"},
            "panel": {"valid": True, "state": "valid"},
        },
        "ufw": {"present": True, "version": "ufw 0.36.2", "active": True, "status_available": True},
        "paths": paths,
        "writable_layer": {
            "3xui_app:/etc/fail2ban": {"exists": True, "size_bytes": 65536},
            "3xui_app:/var/lib/fail2ban": {"exists": True, "size_bytes": 131072},
        },
        "space": {
            "/": {"total_bytes": 80_000_000_000, "free_bytes": 40_000_000_000},
            "/var/backups": {"total_bytes": 80_000_000_000, "free_bytes": 40_000_000_000},
            "/var/lib/docker": {"total_bytes": 80_000_000_000, "free_bytes": 40_000_000_000},
        },
    }
    for key, value in overrides.items():
        data[key] = value
    return data


def approved_manifest(tmpdir: str, **overrides: Any):
    import json

    data = manifest_module.load(manifest_module.EXAMPLE_MANIFEST_PATH).data
    data = copy.deepcopy(data)
    data["approved"] = True
    data["trusted_files"] = copy.deepcopy(TRUSTED_FILES)
    data["certbot"]["hook_fingerprints"] = dict(HOOK_FINGERPRINTS)
    data["certbot"]["renewal_hook_dirs"] = list(RENEWAL_HOOK_DIRS)
    data["approval_note"] = "synthetic test manifest"
    data["source"]["expected_machine_id"] = MACHINE_ID
    data["source"]["expected_host_key_fingerprint"] = HOST_KEY
    data["pending_approval"] = []
    data.update(overrides)
    path = os.path.join(tmpdir, "manifest.json")
    ensure_dir(tmpdir, 0o700)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
    return manifest_module.load(path)


class SyntheticSystem(object):
    """In-process SystemOps used by BackupWorker/finalizer tests."""

    def __init__(self, manifest, root: str, faults: Optional[Dict[str, bool]] = None,
                 probe: Optional[Dict[str, Any]] = None):
        self.manifest = manifest
        self.root = root
        self.faults = dict(faults or {})
        self.probe_data = copy.deepcopy(probe or synthetic_probe())
        self.machine = MACHINE_ID
        self.lease_active = False
        self.renewal_active = False
        self.masked_runtime = False
        self.units = {
            "certbot.service": {"load_state": "loaded", "active_state": "inactive", "unit_file_state": "enabled"},
            "certbot.timer": {"load_state": "loaded", "active_state": "active", "unit_file_state": "enabled"},
            "certbot-http01-cleanup.service": {"load_state": "loaded", "active_state": "inactive", "unit_file_state": "enabled"},
            "certbot-http01-cleanup.timer": {"load_state": "loaded", "active_state": "active", "unit_file_state": "enabled"},
        }
        self.containers: Dict[str, Dict[str, Any]] = {
            "litellm": {"id": "id-litellm-0001", "running": True},
            "caddy": {"id": "id-caddy-0002", "running": True},
            "3xui_app": {"id": "id-3xui-0003", "running": True},
            "telemt": {"id": "id-telemt-0004", "running": False},
        }
        self.copy_calls: List[str] = []
        self.stopped_ids: List[str] = []
        self.started_ids: List[str] = []
        self.stop_batches: List[List[str]] = []
        self.start_batches: List[List[str]] = []
        self.host_root = os.path.join(root, "host")
        self.backup_root_path = os.path.join(root, "backups")
        self.volume_mounts = {
            "llmproxy_chatgpt_auth": os.path.join(root, "volumes", "llmproxy_chatgpt_auth"),
            "llmproxy_caddy_data": os.path.join(root, "volumes", "llmproxy_caddy_data"),
            "llmproxy_caddy_config": os.path.join(root, "volumes", "llmproxy_caddy_config"),
        }
        ensure_dir(self.host_root, 0o700)
        ensure_dir(self.backup_root_path, 0o700)
        self._populate()

    # -- fixtures ---------------------------------------------------------
    def _write(self, relative: str, content: bytes, mode: int = 0o600) -> None:
        path = os.path.join(self.host_root, relative)
        ensure_dir(os.path.dirname(path), 0o700)
        with open(path, "wb") as handle:
            handle.write(content)
        os.chmod(path, mode)

    def _populate(self) -> None:
        self._write("opt/llmproxy/docker-compose.yaml", b"services:\n  litellm:\n    image: litellm\n")
        self._write("opt/llmproxy/litellm-config.yaml", b"general_settings:\n  master_key: os.environ/LITELLM_MASTER_KEY\n")
        self._write("opt/llmproxy/.env", ("LITELLM_MASTER_KEY=%s\nDUCKDNS_TOKEN=%s\n" % (SECRET_CANARY, ENV_CANARY)).encode())
        self._write("opt/llmproxy/caddy/Caddyfile", b"kewlllm.duckdns.org {\n  reverse_proxy litellm:4000\n}\n")
        self._write("root/panel/compose.yml", b"services:\n  3xui:\n    image: 3x-ui\n")
        os.makedirs(os.path.join(self.host_root, "root/panel/db"), mode=0o700, exist_ok=True)
        self._write("root/panel/db/x-ui.db", ("sqlite:%s\n" % DB_CANARY).encode(), mode=0o600)
        archive_dir = os.path.join(self.host_root, "etc/letsencrypt/archive/kewlsub.duckdns.org")
        ensure_dir(archive_dir, 0o700)
        with open(os.path.join(archive_dir, "cert1.pem"), "wb") as handle:
            handle.write(b"-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n")
        live_dir = os.path.join(self.host_root, "etc/letsencrypt/live/kewlsub.duckdns.org")
        ensure_dir(live_dir, 0o700)
        os.symlink("../../archive/kewlsub.duckdns.org/cert1.pem", os.path.join(live_dir, "cert.pem"))
        for name, path in self.volume_mounts.items():
            ensure_dir(path, 0o700)
            self._secret_file(path, name)

    def _secret_file(self, path: str, name: str) -> None:
        if name == "llmproxy_chatgpt_auth":
            ensure_dir(os.path.join(path, "chatgpt"), 0o700)
            with open(os.path.join(path, "chatgpt", "auth.json"), "wb") as handle:
                handle.write(('{"tokens":"%s"}\n' % SECRET_CANARY).encode())
            os.chmod(os.path.join(path, "chatgpt", "auth.json"), 0o600)
        else:
            with open(os.path.join(path, "state.bin"), "wb") as handle:
                handle.write(b"state")

    def writable_layer_dir(self, container: str, path: str) -> str:
        directory = os.path.join(self.root, "writable", container, path.strip("/"))
        ensure_dir(directory, 0o700)
        with open(os.path.join(directory, "data.db"), "wb") as handle:
            handle.write(b"fail2ban-state")
        return directory

    # -- SystemOps --------------------------------------------------------
    def probe(self, spec=None, timeout: int = 90):
        return Inventory.from_probe(copy.deepcopy(self.probe_data))

    def machine_id(self) -> str:
        return self.machine

    def backup_root(self) -> str:
        ensure_dir(self.backup_root_path, 0o700)
        return self.backup_root_path

    def container_states(self, names):
        return {
            name: (dict(self.containers[name]) if name in self.containers else None)
            for name in names
        }

    def running_container_names(self):
        return [name for name, fact in self.containers.items() if fact["running"]]

    def stop_containers(self, ids):
        ids = list(ids)
        self.stop_batches.append(ids)
        if self.faults.get("stop_fail"):
            raise ToolError("E_EXECUTION", "synthetic stop failure")
        for name, fact in self.containers.items():
            if fact["id"] in ids:
                fact["running"] = False
                self.stopped_ids.append(fact["id"])

    def start_containers(self, ids):
        ids = list(ids)
        self.start_batches.append(ids)
        self.started_ids.extend(ids)
        if self.faults.get("start_fail"):
            raise ToolError("E_EXECUTION", "synthetic start failure")
        for name, fact in self.containers.items():
            if fact["id"] in ids:
                fact["running"] = True

    def free_bytes(self, path: str) -> int:
        return 1_000_000 if self.faults.get("low_space") else 40_000_000_000

    def fsync_paths(self, manifest) -> None:
        if self.faults.get("fsync_fail"):
            raise ToolError("E_STATE_WRITE_FAILED", "synthetic fsync failure")

    def certbot_state(self, manifest):
        return {"units": copy.deepcopy(self.units)}

    def disable_certbot_triggers(self, manifest) -> None:
        if self.renewal_active or self.lease_active:
            raise ToolError("E_PRECONDITION", "synthetic active certbot trigger")
        self.masked_runtime = True
        self.units["certbot.timer"]["active_state"] = "inactive"
        if self.faults.get("renewal_race"):
            self.renewal_active = True

    def restore_certbot_triggers(self, state, manifest) -> None:
        if self.faults.get("certbot_restore_fail"):
            raise ToolError("E_EXECUTION", "synthetic certbot restore failure")
        original = (state or {}).get("units") or {}
        service = original.get("certbot.service") or {}
        if service.get("active_state") == "inactive" and self.units["certbot.service"]["active_state"] == "active":
            raise ToolError("E_CONFLICT", "synthetic certbot service unexpectedly active")
        self.masked_runtime = False
        self.units = copy.deepcopy(original or self.units)

    def certbot_renewal_active(self, manifest) -> bool:
        return self.renewal_active

    def check_lease(self, manifest) -> bool:
        return self.lease_active

    def _tar(self, dest_path: str, cwd: str, names: List[str]) -> str:
        ensure_dir(os.path.dirname(dest_path), 0o700)
        with tarfile.open(dest_path, "w", format=tarfile.PAX_FORMAT) as archive:
            for name in names:
                archive.add(os.path.join(cwd, name), arcname=name)
        return dest_path

    def copy_bind_tree(self, dest_dir, tree):
        if self.faults.get("copy_fail"):
            raise ToolError("E_EXECUTION", "synthetic copy failure")
        if self.faults.get("kill_during_copy"):
            raise KillWorker("simulated SIGKILL during copy")
        self.copy_calls.append(tree["artifact"])
        return self._tar(
            os.path.join(dest_dir, tree["artifact"]), self.host_root, list(tree["includes"])
        )

    def copy_volume(self, dest_dir, volume):
        self.copy_calls.append(volume["artifact"])
        mountpoint = self.volume_mounts[volume["name"]]
        return self._tar(os.path.join(dest_dir, volume["artifact"]), mountpoint, ["."])

    def copy_writable_layer(self, dest_dir, layer, container_id=None):
        self.copy_calls.append(layer["artifact"])
        directory = self.writable_layer_dir(layer["container"], layer["path"])
        return self._tar(os.path.join(dest_dir, layer["artifact"]), directory, ["."])

    def copy_certbot_automation(self, dest_dir, manifest):
        certbot = manifest.certbot
        self.copy_calls.append(certbot["artifact"])
        guard_dir = os.path.join(self.root, "certbot", "usr/local/sbin")
        ensure_dir(guard_dir, 0o700)
        with open(os.path.join(guard_dir, "certbot-http01-guard"), "wb") as handle:
            handle.write(b"#!/bin/sh\n# synthetic guard\n")
        os.chmod(os.path.join(guard_dir, "certbot-http01-guard"), 0o755)
        return self._tar(os.path.join(dest_dir, certbot["artifact"]), self.root, ["certbot"])

    def copy_reference_artifacts(self, dest_dir, manifest):
        produced = []
        ufw_dir = os.path.join(self.root, "ufw", "etc/ufw")
        ensure_dir(ufw_dir, 0o700)
        with open(os.path.join(ufw_dir, "before.rules"), "wb") as handle:
            handle.write(b"# synthetic ufw rules; never applied\n")
        for reference in manifest.reference_artifacts:
            for name in reference["artifacts"]:
                if name.endswith(".tar"):
                    produced.append(self._tar(os.path.join(dest_dir, name), self.root, ["ufw"]))
                else:
                    path = os.path.join(dest_dir, name)
                    with open(path, "wb") as handle:
                        handle.write(b"# reference only; not applied\n")
                    os.chmod(path, 0o600)
                    produced.append(path)
        return produced

    def write_metadata(self, dest_dir, manifest, initial_state):
        from vps3xui.util import write_json
        from vps3xui.worker.jobctx import now_iso

        write_json(os.path.join(dest_dir, "images.json"), build_images_json(manifest, now_iso()), mode=0o600)
        write_json(
            os.path.join(dest_dir, "backup.json"),
            build_backup_json(manifest, os.path.basename(dest_dir), initial_state, now_iso(),
                              {"system": "Linux", "machine": "x86_64"}),
            mode=0o600,
        )
        if self.faults.get("metadata_fail"):
            raise ToolError("E_EXECUTION", "synthetic metadata failure")
        if self.faults.get("drop_metadata"):
            os.unlink(os.path.join(dest_dir, "images.json"))

    def validate_archive(self, path):
        return archive_adapter.validate_tar(path).to_object()


class SyntheticHost(HostOps):
    """In-process HostOps that runs the real worker against SyntheticSystem."""

    def __init__(self, manifest, root: Optional[str] = None, probe: Optional[Dict[str, Any]] = None,
                 faults: Optional[Dict[str, bool]] = None):
        self.manifest = manifest
        self.alias = manifest.ssh_alias
        self.root = root or tempfile.mkdtemp(prefix="vps3xui-host-")
        self.remote_root = os.path.join(self.root, "remote")
        ensure_dir(self.remote_root, 0o700)
        self.probe_data = probe or synthetic_probe()
        self.faults = dict(faults or {})
        self.releases: Dict[str, bytes] = {}
        self.systems: Dict[str, SyntheticSystem] = {}
        self.launches: List[Dict[str, Any]] = []
        self.fake_bin = os.path.join(self.root, "fakebin")
        self.launch_log = os.path.join(self.root, "launch.log")
        install_fake_systemd_run(self.fake_bin, self.launch_log)

    @contextlib.contextmanager
    def _fake_path(self):
        old = os.environ.get("PATH", "")
        os.environ["PATH"] = self.fake_bin + os.pathsep + old
        os.environ["VPS3XUI_FAKE_LAUNCH_LOG"] = self.launch_log
        try:
            yield
        finally:
            os.environ["PATH"] = old
            os.environ.pop("VPS3XUI_FAKE_LAUNCH_LOG", None)

    def launch_calls(self):
        return read_launch_log(self.launch_log)

    def _local(self, remote_path: str) -> str:
        return os.path.join(self.remote_root, remote_path.lstrip("/"))

    def fingerprint(self) -> str:
        return HOST_KEY

    def probe(self, spec=None, timeout: int = 90):
        return Inventory.from_probe(copy.deepcopy(self.probe_data))

    def read_json_file(self, remote_path):
        path = self._local(remote_path)
        if not os.path.isfile(path):
            return None
        import json

        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
        # The worker harness rewrites request paths into this sandbox; a real
        # host keeps the immutable request, so report the host-side paths.
        if isinstance(value, dict):
            prefix = self.remote_root.rstrip("/") + "/"
            for key in ("backup_dir", "release_dir"):
                item = value.get(key)
                if isinstance(item, str) and item.startswith(prefix):
                    value[key] = "/" + item[len(prefix):]
        return value

    def path_exists(self, remote_path: str) -> bool:
        return os.path.exists(self._local(remote_path))

    def list_dir(self, remote_path: str) -> List[str]:
        directory = self._local(remote_path)
        if not os.path.isdir(directory):
            return []
        return sorted(os.listdir(directory))

    def write_file(self, remote_path, data, mode=0o600):
        path = self._local(remote_path)
        ensure_dir(os.path.dirname(path), 0o700)
        with open(path, "wb") as handle:
            handle.write(data)
        os.chmod(path, mode)

    def ensure_release(self, release_dir, archive):
        from vps3xui.release import archive_file_hashes

        digest = sha256_hex(archive)
        directory = self._local(release_dir)
        marker = os.path.join(directory, ".digest")
        if os.path.isdir(directory):
            if os.path.isfile(marker):
                with open(marker, "r", encoding="utf-8") as handle:
                    if handle.read().strip() == digest:
                        self.releases[release_dir] = archive
                        return digest
            raise ToolError("E_EXECUTION", "Existing release differs; refusing to replace.",
                            resource=os.path.basename(release_dir))
        ensure_dir(directory, 0o700)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as tar:
            tar.extractall(directory)
            names = [m.name for m in tar.getmembers()]
        os.makedirs(os.path.join(directory, "bin"), exist_ok=True)
        for name in names:
            path = os.path.join(directory, name)
            if name.startswith("bin/") and os.path.isfile(path):
                os.chmod(path, 0o755)
            elif os.path.isfile(path):
                os.chmod(path, 0o644)
        with open(os.path.join(directory, "RELEASE"), "w", encoding="utf-8") as handle:
            handle.write("%s\n" % TOOL_VERSION)
        _write_marker(directory, ".digest", digest)
        _write_marker(directory, ".files", json.dumps(archive_file_hashes(archive), sort_keys=True))
        self.releases[release_dir] = archive
        return digest

    def reserve_and_launch(self, root, job_dir, request_payload, plan_payload, launch):
        import base64
        from vps3xui import remote_ops

        local_root = self._local(root)
        job_id = request_payload.get("job_id")
        # Rewrite the host-side launch paths into this sandbox so the reviewed
        # coordination module records and launches against the same tree.
        launch = dict(launch)
        for key in ("release_dir", "job_dir"):
            if isinstance(launch.get(key), str):
                launch[key] = self._local(launch[key])
        token = base64.b64encode(
            json.dumps({"job_id": job_id, "request": request_payload,
                        "plan": plan_payload, "launch": launch}).encode("utf-8")
        ).decode("ascii")
        # The real reviewed coordination module runs with a fake ``systemd-run``
        # on PATH, so an actual launch is asserted rather than a no-op.
        with self._fake_path():
            obj, code = remote_ops.cmd_reserve_and_launch(local_root, token)
        if code != 0:
            error = obj.get("error") or {}
            raise ToolError(error.get("code") or "E_EXECUTION",
                            error.get("message") or "remote reservation failed",
                            resource=error.get("resource"), next_action=error.get("next_action"))
        if obj.get("reserved"):
            self.launches.append({
                "unit": launch.get("unit_name"), "job": job_id,
                "release": launch.get("release_dir"),
                "runtime": launch.get("runtime_max_seconds"),
                "stop": launch.get("timeout_stop_seconds"),
            })
            self._run_worker(job_id, local_root)
        return obj

    def remote_job_status(self, root, job_id):
        from vps3xui import remote_ops

        obj, code = remote_ops.cmd_status(self._local(root), job_id)
        return obj

    def _run_worker(self, job_id: str, local_root: str) -> None:
        system = self._system(job_id)
        local_job = os.path.join(local_root, "jobs", job_id)
        # Rewrite remote absolute paths to this sandbox so the real worker code
        # runs unmodified against in-process paths.
        request_path = os.path.join(local_job, "request.json")
        with open(request_path, "r", encoding="utf-8") as handle:
            request = json.load(handle)
        request["backup_dir"] = self._local(request["backup_dir"])
        request["release_dir"] = self._local(request["release_dir"])
        with open(request_path, "w", encoding="utf-8") as handle:
            json.dump(request, handle, indent=2, sort_keys=True)
        worker = BackupWorker(system, local_job, self.manifest)
        report = None
        try:
            report = worker.run()
        except KillWorker:
            pass
        # ExecStopPost equivalent: the independent finalizer always runs. The
        # unit metadata is supplied only when the worker exited 0 with a copied
        # job; a kill or a failed run passes none, so success needs evidence.
        unit_result = dict(UNIT_SUCCESS_RESULT) if (report or {}).get("state") == "copied" else None
        finalizer.recover(local_job, system, self.manifest, service_result=unit_result)

    def _system(self, job_id: str, faults: Optional[Dict[str, bool]] = None) -> SyntheticSystem:
        if job_id not in self.systems:
            system_root = os.path.join(self.root, "system", job_id)
            ensure_dir(system_root, 0o700)
            self.systems[job_id] = SyntheticSystem(self.manifest, system_root, faults=self.faults,
                                                   probe=self.probe_data)
        if faults:
            self.systems[job_id].faults.update(faults)
        return self.systems[job_id]

    def launch_backup(self, unit_name, release_dir, job_dir, runtime_max_seconds, timeout_stop_seconds):
        import json

        job_id = os.path.basename(job_dir.rstrip("/"))
        self.launches.append({"unit": unit_name, "job": job_id, "release": release_dir,
                              "runtime": runtime_max_seconds, "stop": timeout_stop_seconds})
        system = self._system(job_id)
        local_job = self._local(job_dir)
        # Rewrite remote absolute paths to this sandbox so the real worker code
        # runs unmodified against in-process paths.
        request_path = os.path.join(local_job, "request.json")
        with open(request_path, "r", encoding="utf-8") as handle:
            request = json.load(handle)
        request["backup_dir"] = self._local(request["backup_dir"])
        request["release_dir"] = self._local(request["release_dir"])
        with open(request_path, "w", encoding="utf-8") as handle:
            json.dump(request, handle, indent=2, sort_keys=True)
        worker = BackupWorker(system, local_job, self.manifest)
        try:
            worker.run()
        except KillWorker:
            # ExecStopPost equivalent: the independent finalizer still runs.
            finalizer.recover(local_job, system, self.manifest)

    def launch_recover(self, unit_name, release_dir, job_dir):
        job_id = os.path.basename(job_dir.rstrip("/"))
        system = self._system(job_id)
        system.faults = {}
        finalizer.recover(self._local(job_dir), system, self.manifest)

    def remote_recover(self, root, job_id):
        from vps3xui import remote_ops

        local_root = self._local(root)
        job_path = self._local(os.path.join(root, "jobs", job_id))
        with self._fake_path():
            obj, code = remote_ops.cmd_recover(local_root, job_id)
        if code != 0:
            error = obj.get("error") or {}
            raise ToolError(error.get("code") or "E_EXECUTION",
                            error.get("message") or "remote recovery failed",
                            resource=error.get("resource"), next_action=error.get("next_action"))
        # The recover unit runs the independent finalizer on the host.
        system = self._system(job_id)
        system.faults = {}
        finalizer.recover(job_path, system, self.manifest, explicit=True)
        return obj

    def remote_verify(self, release_dir, backup_dir, manifest_path):
        from vps3xui.verify import verify_directory

        result = verify_directory(self._local(backup_dir), self.manifest, require_complete=True)
        return result.to_object()

    def fetch_file(self, remote_path, local_path):
        source = self._local(remote_path)
        if not os.path.isfile(source):
            raise ToolError("E_MISSING_ARTIFACT", "Remote artifact is missing.",
                            resource=os.path.basename(remote_path))
        shutil.copyfile(source, local_path)


def seed_job(job_dir: str, request: Dict[str, Any], plan: Optional[Dict[str, Any]] = None,
             manifest=None) -> Dict[str, Any]:
    """Create a job directory with the durable reservation the workers require.

    Mirrors exactly what ``remote_ops`` writes: an immutable ``reservation.json``
    plus ``request.json`` (and ``plan.json``/``manifest.json``) so the worker and
    finalizer can assert ownership and re-verify the reviewed plan.
    """
    ensure_dir(job_dir, 0o700)
    job_id = os.path.basename(job_dir.rstrip("/"))
    payload = dict(request)
    payload.setdefault("job_id", job_id)
    if plan is not None:
        payload.setdefault("plan_digest", plan.get("identity"))
    if manifest is not None:
        payload.setdefault("manifest_id", manifest.manifest_id)
    coord.replace_json(os.path.join(job_dir, coord.RESERVATION_FILE), {
        "schema_version": coord.RESERVATION_SCHEMA_VERSION,
        "job_id": job_id,
        "plan_digest": payload.get("plan_digest"),
        "manifest_id": payload.get("manifest_id"),
    })
    coord.replace_json(os.path.join(job_dir, coord.REQUEST_FILE), payload)
    if plan is not None:
        coord.replace_json(os.path.join(job_dir, coord.PLAN_FILE), plan)
    if manifest is not None:
        coord.replace_json(os.path.join(job_dir, coord.MANIFEST_FILE), manifest.data)
    return payload


FAKE_SYSTEMD_RUN = """#!/bin/sh
{
  printf '%s\n' "$0"
  for a in "$@"; do printf '%s\n' "$a"; done
  printf '%s\n' '---END---'
} >> "$VPS3XUI_FAKE_LAUNCH_LOG"
exit "${VPS3XUI_FAKE_SYSTEMD_RC:-0}"
"""


def install_fake_systemd_run(directory: str, log_path: str) -> str:
    """Install a fake ``systemd-run`` binary that records its argv."""
    ensure_dir(directory, 0o700)
    binary = os.path.join(directory, "systemd-run")
    with open(binary, "w", encoding="utf-8") as handle:
        handle.write(FAKE_SYSTEMD_RUN)
    os.chmod(binary, 0o755)
    return log_path


def read_launch_log(log_path: str) -> List[List[str]]:
    """Parse the fake ``systemd-run`` log into a list of argv lists."""
    if not os.path.isfile(log_path):
        return []
    calls: List[List[str]] = []
    current: List[str] = []
    with open(log_path, "r", encoding="utf-8") as handle:
        for line in handle.read().splitlines():
            if line == "---END---":
                calls.append(current)
                current = []
            else:
                current.append(line)
    if current:
        calls.append(current)
    return calls


def temp_state_dir(prefix: str = "vps3xui-state-") -> str:
    return tempfile.mkdtemp(prefix=prefix)


def new_request_id() -> str:
    return "req-" + uuid.uuid4().hex[:12]


def _write_marker(directory: str, name: str, text: str) -> None:
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o600)


def read_json_file(path: str):
    import json

    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def complete_backup(tmp, faults=None):
    """Run the real worker against a synthetic system and return the copy."""
    from vps3xui.inventory import Inventory as _Inventory
    from vps3xui.plan import build_plan as _build_plan
    from vps3xui.worker.backup_worker import BackupWorker
    from vps3xui.worker.jobctx import REPORT_FILE

    manifest = approved_manifest(tmp)
    inventory = _Inventory.from_probe(synthetic_probe())
    plan = _build_plan(manifest, inventory, HOST_KEY)
    job_dir = os.path.join(tmp, "jobs", "req-verify-1")
    backup_dir = os.path.join(tmp, "backups", "req-verify-1")
    seed_job(job_dir, {
        "schema_version": 1,
        "request_id": "req-verify-1",
        "job_id": "req-verify-1",
        "manifest_id": manifest.manifest_id,
        "plan_digest": plan["identity"],
        "machine_id": MACHINE_ID,
        "host_key_fingerprint": HOST_KEY,
        "backup_dir": backup_dir,
        "stop_containers": plan["stop_containers"],
        "leave_stopped": plan["leave_stopped"],
        "required_bytes_estimate": 5_000_000_000,
    }, plan, manifest)
    system = SyntheticSystem(manifest, os.path.join(tmp, "system"), faults=faults)
    worker = BackupWorker(system, job_dir, manifest)
    report = worker.run()
    # ExecStopPost equivalent: the finalizer publishes success last, using the
    # unit metadata a real clean exit would report.
    unit_result = dict(UNIT_SUCCESS_RESULT) if (report or {}).get("state") == "copied" else None
    finalizer.recover(job_dir, system, manifest, service_result=unit_result)
    from vps3xui.util import read_json
    report = read_json(os.path.join(job_dir, REPORT_FILE))
    return manifest, backup_dir, report, system
