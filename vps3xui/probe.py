#!/usr/bin/env python3
"""Fixed, read-only inventory probe, shipped and executed over stdin.

It runs on the source host as ``python3 - <base64-spec>`` with this exact file
content on stdin. The *code* is fixed and reviewed; only validated JSON *data*
(the base64 argv token) varies, and that data is limited to paths, unit names
and Compose project directories supplied by the manifest. The probe performs
no writes, installs nothing, starts/stops nothing, and never emits environment
values, secret file contents, raw ``docker inspect`` output or child stderr.

Output is a single JSON object on stdout with ``probe_version`` 3. Every
section is best-effort: an unavailable section is reported as a bounded token
in ``errors`` instead of guessing. Callers must fail closed on those tokens.

Requires Python 3.8+ on the host; the caller reports E_RUNTIME_MISSING if the
interpreter is absent.
"""

import base64
import hashlib
import json
import os
import select
import shutil
import stat
import subprocess
import sys
import time

PROBE_VERSION = 3

DEFAULT_PATHS = [
    "/opt/llmproxy",
    "/opt/llmproxy/.env",
    "/opt/llmproxy/docker-compose.yaml",
    "/opt/llmproxy/litellm-config.yaml",
    "/opt/llmproxy/caddy/Caddyfile",
    "/root/panel",
    "/root/panel/compose.yml",
    "/root/panel/db",
    "/etc/letsencrypt",
    "/etc/letsencrypt/live",
    "/etc/letsencrypt/archive",
    "/etc/certbot-http01-guard.enabled",
    "/usr/local/sbin/certbot-http01-guard",
    "/var/lib/certbot-http01-guard",
    "/etc/ufw",
    "/etc/default/ufw",
    "/etc/machine-id",
]

DEFAULT_UNITS = [
    "certbot.service",
    "certbot.timer",
    "certbot-http01-cleanup.service",
    "certbot-http01-cleanup.timer",
]

DEFAULT_WRITABLE_LAYERS = [
    {"container": "3xui_app", "path": "/etc/fail2ban"},
    {"container": "3xui_app", "path": "/var/lib/fail2ban"},
]

DEFAULT_COMPOSE_PROJECTS = [
    {"project": "llmproxy", "working_dir": "/opt/llmproxy",
     "files": ["/opt/llmproxy/docker-compose.yaml"]},
    {"project": "panel", "working_dir": "/root/panel", "files": ["/root/panel/compose.yml"]},
]

DEFAULT_BACKUP_ROOT = "/var/backups"

# Recognised Linux ``at``/batch spool layouts. Queued job files live directly
# in the job directories; auxiliary directories hold per-job output/metadata
# (or a nested job directory) and are never read or counted as jobs.
AT_JOB_SPOOL_DIRS = (
    "/var/spool/cron/atjobs",  # Debian/Ubuntu job spool
    "/var/spool/at",           # RHEL/CentOS/SUSE job spool
    "/var/spool/at/jobs",      # explicit nested job spool
)
AT_AUX_SPOOL_DIRS = (
    "/var/spool/cron/atspool",  # Debian/Ubuntu job output
    "/var/spool/at/spool",      # RHEL job output
    "/var/spool/at/jobs",       # nested job spool seen from /var/spool/at
)
# Only documented implementation control files may sit in an otherwise empty
# job spool. They are recognised by exact basename and skipped only when they
# are a valid regular non-symlink file; any other type named like one stays
# unknown. Job files are never recognised (or skipped) by their name.
AT_CONTROL_FILES = (".SEQ",)
# Hard bounds so a hostile or runaway spool/`atq` cannot exhaust memory or
# hide evidence: exceeding either bound makes the queue unknown, never empty.
AT_SPOOL_MAX_ENTRIES = 4096
ATQ_MAX_BYTES = 256 * 1024
ATQ_MAX_LINES = 4096
ATQ_TIMEOUT_SECONDS = 15


def _spec():
    """Decode the validated spec from argv[1], or return an empty mapping."""
    if len(sys.argv) < 2 or not sys.argv[1]:
        return {}
    try:
        raw = base64.b64decode(sys.argv[1].encode("ascii"), validate=True)
    except (ValueError, TypeError):
        return {}
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def _str_list(value, fallback):
    if not isinstance(value, list):
        return list(fallback)
    out = []
    for item in value:
        if isinstance(item, str) and item:
            out.append(item)
    return out


def _run(argv, timeout=20, cwd=None, env=None):
    """Run a command, returning (exit_code, stdout_text). stderr is discarded."""
    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            cwd=cwd,
            env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return 127, ""
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


def _run_json_lines(argv, timeout=20, cwd=None, env=None):
    code, out = _run(argv, timeout=timeout, cwd=cwd, env=env)
    if code != 0:
        return None
    items = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except ValueError:
            continue
    return items


def _run_json(argv, timeout=20):
    code, out = _run(argv, timeout=timeout)
    if code != 0 or not out.strip():
        return None
    try:
        return json.loads(out)
    except ValueError:
        return None


def _walk_size(path):
    total = 0
    files = 0
    try:
        if os.path.isfile(path) and not os.path.islink(path):
            return os.path.getsize(path), 1
        if os.path.islink(path):
            return 0, 0
        for root, dirs, names in os.walk(path):
            for name in names:
                full = os.path.join(root, name)
                try:
                    if os.path.islink(full):
                        continue
                    total += os.lstat(full).st_size
                    files += 1
                except OSError:
                    continue
    except OSError:
        return None, 0
    return total, files


def _space(path):
    """Free space of the filesystem holding ``path``.

    If the exact path does not exist yet, walk up to the nearest existing
    ancestor so a not-yet-created backup root is still measured honestly.
    """
    probe = path
    while probe and not os.path.exists(probe):
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    try:
        st = os.statvfs(probe or path)
    except OSError:
        return None
    return {"total_bytes": st.f_frsize * st.f_blocks,
            "free_bytes": st.f_frsize * st.f_bavail}


def _sha256_file(path):
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            while True:
                block = handle.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


def probe_os():
    info = {"id": None, "version_id": None}
    try:
        with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if "=" not in line:
                    continue
                key, _, value = line.strip().partition("=")
                value = value.strip().strip('"')
                if key == "ID":
                    info["id"] = value
                elif key == "VERSION_ID":
                    info["version_id"] = value
    except OSError:
        pass
    return info


def probe_config_fingerprints(spec):
    """Private fingerprints of configuration inputs, so edits stale a plan.

    These are hashes only; the probe never emits file contents. They are kept
    out of the user-facing ``inspect`` summary but included in the structural
    inventory digest.
    """
    result = {}
    for path in _str_list(spec.get("config_files"), []):
        result[path] = _sha256_file(path)
    return result


def probe_trusted_fingerprints(spec):
    """Private sha256 of the manifest's trusted files (never file contents)."""
    result = {}
    for path in _str_list(spec.get("trusted_files"), []):
        result[path] = _sha256_file(path)
    return result


def probe_trusted_modes(spec):
    """Private permission facts (mode/uid/gid) of the manifest's trusted files.

    A content hash alone cannot prove that a privileged helper is still owned by
    root and not world-writable. Only the numeric facts are emitted.
    """
    result = {}
    for path in _str_list(spec.get("trusted_files"), []):
        try:
            info = os.lstat(path)
        except OSError:
            continue
        result[path] = {
            "mode": "%04o" % (info.st_mode & 0o7777),
            "uid": info.st_uid,
            "gid": info.st_gid,
            "is_symlink": os.path.islink(path),
        }
    return result


def probe_containers(errors):
    if not shutil.which("docker"):
        errors.append("docker_missing")
        return None, []
    listed = _run_json_lines(
        ["docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}"]
    )
    if listed is None:
        errors.append("docker_ps_failed")
        return None, []
    containers = []
    for entry in listed:
        ident = entry.get("ID")
        if not ident:
            continue
        raw = _run_json(["docker", "inspect", ident], timeout=30)
        if not raw:
            errors.append("docker_inspect_failed")
            continue
        try:
            item = raw[0]
        except (IndexError, TypeError):
            errors.append("docker_inspect_failed")
            continue
        state = item.get("State", {}) or {}
        config = item.get("Config", {}) or {}
        host_config = item.get("HostConfig", {}) or {}
        labels = config.get("Labels", {}) or {}
        image_id = item.get("Image")
        repo_digests = []
        if image_id:
            digests = _run_json(
                ["docker", "image", "inspect", image_id, "--format", "{{json .RepoDigests}}"]
            )
            if isinstance(digests, list):
                repo_digests = [str(item) for item in digests if isinstance(item, str)]
        mounts = []
        for mount in item.get("Mounts", []) or []:
            mounts.append(
                {
                    "type": mount.get("Type"),
                    "name": mount.get("Name"),
                    "source": mount.get("Source"),
                    "destination": mount.get("Destination"),
                    "rw": bool(mount.get("RW")),
                    "driver": mount.get("Driver"),
                    "mode": mount.get("Mode"),
                }
            )
        containers.append(
            {
                "id": ident,
                "name": (item.get("Name") or entry.get("Names") or "").lstrip("/"),
                "image": config.get("Image") or entry.get("Image"),
                "image_id": image_id,
                "repo_digests": repo_digests,
                "running": bool(state.get("Running")),
                "status": state.get("Status") or entry.get("State"),
                "restart_policy": (host_config.get("RestartPolicy") or {}).get("Name"),
                "network_mode": host_config.get("NetworkMode"),
                "compose_project": labels.get("com.docker.compose.project"),
                "compose_service": labels.get("com.docker.compose.service"),
                "mounts": mounts,
            }
        )
    return listed, containers


def probe_volumes(errors):
    if not shutil.which("docker"):
        return []
    listed = _run_json_lines(["docker", "volume", "ls", "--format", "{{json .}}"])
    if listed is None:
        errors.append("docker_volume_ls_failed")
        return []
    volumes = []
    for entry in listed:
        name = entry.get("Name")
        if not name:
            continue
        raw = _run_json(["docker", "volume", "inspect", name])
        if not raw:
            errors.append("docker_volume_inspect_failed")
            continue
        item = raw[0]
        volumes.append(
            {
                "name": name,
                "driver": item.get("Driver"),
                "options": item.get("Options") or {},
                "mountpoint": item.get("Mountpoint"),
                "scope": item.get("Scope"),
            }
        )
    return volumes


def probe_systemd(errors, units_to_probe):
    if not shutil.which("systemctl"):
        errors.append("systemctl_missing")
        return {"present": False, "units": {}, "unit_files": [], "version": None}
    version = None
    code, out = _run(["systemctl", "--version"], timeout=15)
    if code == 0 and out:
        version = out.splitlines()[0].strip() or None
    units = {}
    for unit in units_to_probe:
        code, out = _run(
            ["systemctl", "show", unit, "-p", "LoadState,ActiveState,UnitFileState"]
        )
        if code != 0:
            continue
        fields = {}
        for line in out.splitlines():
            key, _, value = line.partition("=")
            fields[key] = value
        units[unit] = {
            "load_state": fields.get("LoadState"),
            "active_state": fields.get("ActiveState"),
            "unit_file_state": fields.get("UnitFileState"),
        }
    unit_files = []
    code, out = _run(
        ["systemctl", "list-unit-files", "--plain", "--no-legend", "certbot*"]
    )
    if code == 0:
        for line in out.splitlines():
            parts = line.split()
            if parts:
                unit_files.append(parts[0])
    return {"present": True, "units": units, "unit_files": unit_files, "version": version}


def probe_certbot(errors, spec):
    guard_path = spec.get("guard_path") or "/usr/local/sbin/certbot-http01-guard"
    guard_enabled = spec.get("guard_enabled_path") or "/etc/certbot-http01-guard.enabled"
    lease_path = spec.get("lease_path") or "/var/lib/certbot-http01-guard/lease.json"
    info = {
        "present": False,
        "binary": None,
        "renewal_dir": "/etc/letsencrypt/renewal",
        "renewal_files": [],
        "renewal_hooks": {},
        "renewal_hook_fingerprints": {},
        "renewal_hook_dirs": {},
        "guard_path": guard_path,
        "guard_present": os.path.exists(guard_path),
        "guard_enabled_path": guard_enabled,
        "guard_enabled": os.path.exists(guard_enabled),
        "lease_path": lease_path,
        "lease_present": os.path.exists(lease_path),
        "lease_age_seconds": None,
    }
    binary = shutil.which("certbot")
    if binary:
        info["present"] = True
        info["binary"] = binary
    renewal_dir = spec.get("renewal_dir") or "/etc/letsencrypt/renewal"
    try:
        names = sorted(os.listdir(renewal_dir))
    except OSError:
        names = []
    for name in names:
        if not name.endswith(".conf"):
            continue
        info["renewal_files"].append(name)
        hooks = {}
        hook_fingerprints = {}
        try:
            with open(os.path.join(renewal_dir, name), "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip()
                    if key in ("pre_hook", "post_hook", "renew_hook", "deploy_hook"):
                        hooks[key] = bool(value)
                        if value:
                            hook_fingerprints[key] = hashlib.sha256(value.encode("utf-8")).hexdigest()
                    elif key == "authenticator":
                        hooks["authenticator"] = value
        except OSError:
            errors.append("renewal_read_failed")
        info["renewal_hooks"][name] = hooks
        info["renewal_hook_fingerprints"][name] = hook_fingerprints
    for directory in _str_list(spec.get("renewal_hook_dirs"), []):
        entries = {}
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            names = []
        for entry_name in names:
            full = os.path.join(directory, entry_name)
            entries[entry_name] = _sha256_file(full)
        info["renewal_hook_dirs"][directory] = entries
    if info["lease_present"]:
        try:
            age = int(max(0, __import__("time").time() - os.path.getmtime(lease_path)))
            info["lease_age_seconds"] = age
        except OSError:
            pass
    return info


def probe_cron(errors):
    """Content-based Certbot scheduler detection.

    A renamed cron file or systemd timer is caught by reading its contents, not
    by trusting the filename. User crontabs are included: a per-user scheduler
    is exactly the kind of out-of-band renewal this design must refuse.
    """
    found = {}

    def _scan_file(path):
        try:
            with open(path, "rb") as handle:
                blob = handle.read(256 * 1024)
        except OSError:
            return
        if b"certbot" not in blob.lower():
            return
        digest = hashlib.sha256(blob).hexdigest()
        found[path] = {"path": path, "sha256": digest, "source": "cron"}

    cron_files = ["/etc/crontab"]
    for directory in ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
                      "/etc/cron.weekly", "/etc/cron.monthly"):
        try:
            cron_files.extend(os.path.join(directory, name) for name in sorted(os.listdir(directory)))
        except OSError:
            continue
    for directory in ("/var/spool/cron/crontabs", "/var/spool/cron"):
        try:
            cron_files.extend(os.path.join(directory, name) for name in sorted(os.listdir(directory)))
        except OSError:
            continue
    for path in cron_files:
        if os.path.isfile(path):
            _scan_file(path)

    for directory in ("/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system"):
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        for name in names:
            if not (name.endswith(".timer") or name.endswith(".service")):
                continue
            path = os.path.join(directory, name)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "rb") as handle:
                    blob = handle.read(256 * 1024)
            except OSError:
                continue
            if b"certbot" not in blob.lower():
                continue
            found[path] = {"path": path, "sha256": hashlib.sha256(blob).hexdigest(),
                           "source": "systemd"}
    return [found[key] for key in sorted(found)]


def _run_bounded_lines(argv, timeout, max_bytes, max_lines):
    """Run a read-only command under a hard stdout and time bound.

    Returns ``(exit_code, line_count, overflow)``. Only the count of non-blank
    lines is kept; the raw output is discarded and never more than ``max_bytes``
    is buffered. ``overflow`` is True when the command produced more than
    ``max_bytes`` of stdout or more than ``max_lines`` non-blank lines; in that
    case the command is terminated and the queue must be treated as unknown.
    """
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return 127, 0, False
    stream = proc.stdout
    try:
        fd = stream.fileno()
        deadline = time.monotonic() + max(1, int(timeout))
        chunks = []
        total = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                proc.wait()
                return 127, 0, False
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                proc.kill()
                proc.wait()
                return 127, 0, False
            block = os.read(fd, 65536)
            if not block:
                break
            total += len(block)
            if total > max_bytes:
                proc.kill()
                proc.wait()
                return 127, 0, True
            chunks.append(block)
        try:
            code = proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return 127, 0, False
        lines = [line for line in b"".join(chunks).splitlines() if line.strip()]
        if len(lines) > max_lines:
            return code, 0, True
        return code, len(lines), False
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _at_dir_facts(path, errors):
    """Bounded read-only observation of one ``at`` job spool directory.

    ``None`` means the path is absent, so an ``at`` installation that is not
    present stays supported. Only regular, non-symlink files count as queued
    jobs. An unreadable or non-directory path, an over-large directory, or any
    unexpected entry that could hide a job is reported as a bounded error token
    instead of being silently ignored. No job file is ever opened and the
    directory scan is capped at ``AT_SPOOL_MAX_ENTRIES``.
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        errors.append("at_queue_unreadable")
        return {"path": path, "state": "unknown", "jobs": None}
    if not stat.S_ISDIR(info.st_mode):
        errors.append("at_queue_unknown")
        return {"path": path, "state": "unknown", "jobs": None}
    try:
        names = sorted(os.listdir(path))
    except OSError:
        errors.append("at_queue_unreadable")
        return {"path": path, "state": "unknown", "jobs": None}
    if len(names) > AT_SPOOL_MAX_ENTRIES:
        errors.append("at_queue_unknown")
        return {"path": path, "state": "unknown", "jobs": None}
    jobs = 0
    unknown = False
    for name in names:
        full = os.path.join(path, name)
        if full in AT_AUX_SPOOL_DIRS:
            continue
        try:
            entry = os.lstat(full)
        except OSError:
            unknown = True
            continue
        if name in AT_CONTROL_FILES:
            # A documented control file (e.g. ``.SEQ``) may remain in an empty
            # spool. It is skipped only as a valid regular non-symlink file; a
            # symlink or other type named ``.SEQ`` stays unknown.
            if not stat.S_ISREG(entry.st_mode):
                unknown = True
            continue
        if stat.S_ISREG(entry.st_mode):
            jobs += 1
        else:
            unknown = True
    if unknown:
        errors.append("at_queue_unknown")
        return {"path": path, "state": "unknown", "jobs": None}
    return {"path": path, "state": "occupied" if jobs else "empty", "jobs": jobs}


def probe_at(errors):
    """Read-only detection of queued ``at``/batch jobs.

    P0 refuses to copy while *any* pending ``at`` job exists: its shell body or
    a wrapper may invoke Certbot and the tool has no general shell analyzer.
    Only bounded evidence is emitted - tool presence, per-spool directory state
    and a job count. Job bodies, environment and raw ``atq`` output are never
    read or printed. An unreadable or unrecognised queue/spool, or an installed
    ``at`` whose queue cannot be inspected at all, is a probe error token, so it
    blocks as incomplete evidence rather than as an empty queue.
    """
    at_binary = shutil.which("at")
    atq_binary = shutil.which("atq")
    directories = []
    for path in AT_JOB_SPOOL_DIRS:
        entry = _at_dir_facts(path, errors)
        if entry is not None:
            directories.append(entry)
    occupied = any(entry["state"] == "occupied" for entry in directories)
    unknown = any(entry["state"] == "unknown" for entry in directories)
    atq = {"present": bool(atq_binary), "observed": False, "count": None}
    if atq_binary:
        code, line_count, overflow = _run_bounded_lines(
            [atq_binary], ATQ_TIMEOUT_SECONDS, ATQ_MAX_BYTES, ATQ_MAX_LINES
        )
        if overflow:
            errors.append("at_queue_unknown")
            unknown = True
        elif code == 0:
            # Only the count of queued lines is kept; raw ``atq`` output is
            # discarded so no job text can leak into the inventory.
            atq["observed"] = True
            atq["count"] = line_count
            if line_count:
                occupied = True
        else:
            errors.append("at_queue_unreadable")
            unknown = True
    recognized_spool = bool(directories)
    if unknown:
        state = "unknown"
    elif occupied:
        state = "occupied"
    elif not at_binary and not atq["present"] and not recognized_spool:
        state = "absent"
    elif at_binary and not atq["observed"] and not recognized_spool:
        # ``at`` is installed but neither ``atq`` nor a recognised spool could
        # be inspected: the queue cannot be ruled out, so this is not "absent".
        errors.append("at_queue_unknown")
        state = "unknown"
    else:
        state = "empty"
    return {
        "tooling": {"at": at_binary, "atq": atq_binary},
        "state": state,
        "atq": atq,
        "directories": directories,
    }


def probe_tar(errors):
    """GNU tar availability/version: metadata preservation depends on it."""
    tar_binary = shutil.which("tar")
    if not tar_binary:
        errors.append("tar_missing")
        return {"present": False, "gnu": False, "version": None}
    code, out = _run(["tar", "--version"], timeout=15)
    if code != 0:
        errors.append("tar_version_unavailable")
        return {"present": True, "gnu": False, "version": None}
    first = (out.splitlines() or [""])[0].strip()
    return {"present": True, "gnu": "GNU tar" in out, "version": first or None}


def probe_ufw(errors):
    info = {"present": bool(shutil.which("ufw")), "version": None, "active": None,
            "status_available": False}
    if not info["present"]:
        return info
    code, out = _run(["ufw", "version"], timeout=15)
    if code == 0:
        info["version"] = out.strip().splitlines()[0] if out.strip() else None
    code, out = _run(["ufw", "status"], timeout=15)
    if code == 0 and out.strip():
        info["status_available"] = True
        first = out.strip().splitlines()[0].lower()
        info["active"] = "active" in first and "inactive" not in first
    return info


def probe_paths(paths):
    result = {}
    for path in paths:
        entry = {"exists": os.path.exists(path), "is_symlink": os.path.islink(path)}
        if entry["exists"] and not entry["is_symlink"]:
            if os.path.isdir(path):
                size, files = _walk_size(path)
                entry["kind"] = "dir"
                entry["size_bytes"] = size
                entry["file_count"] = files
            else:
                entry["kind"] = "file"
                try:
                    entry["size_bytes"] = os.path.getsize(path)
                except OSError:
                    entry["size_bytes"] = None
                entry["file_count"] = 1
        result[path] = entry
    return result


def probe_writable_layer(containers, errors, layers):
    running = {c["name"]: c for c in containers if c.get("running")}
    result = {}
    for layer in layers:
        container = layer.get("container")
        path = layer.get("path")
        if not container or not path or container not in running:
            continue
        key = "%s:%s" % (container, path)
        code, out = _run(["docker", "exec", container, "du", "-sb", path], timeout=30)
        if code != 0 or not out.strip():
            result[key] = {"exists": False, "size_bytes": None}
            continue
        try:
            size = int(out.split()[0])
        except (ValueError, IndexError):
            size = None
        result[key] = {"exists": True, "size_bytes": size}
    return result


def probe_compose(errors, spec):
    """Safe validation only: ``config`` never prints expanded values here.

    ``--quiet`` validates the file; ``--services`` prints service names only.
    Both run with the project working directory as the real cwd and PWD so a
    relative path override resolves exactly as Compose would at deploy time.
    """
    if not shutil.which("docker"):
        return {}
    result = {}
    for item in spec.get("compose_projects") or DEFAULT_COMPOSE_PROJECTS:
        project = item.get("project")
        working_dir = item.get("working_dir")
        files = _str_list(item.get("files"), [])
        if not project or not working_dir or not files:
            continue
        base = ["docker", "compose", "-p", project, "--project-directory", working_dir]
        for path in files:
            base += ["-f", path]
        env = dict(os.environ)
        env["PWD"] = working_dir
        code, _out = _run(base + ["config", "--quiet"], timeout=60,
                          cwd=working_dir, env=env)
        entry = {"valid": code == 0, "state": "valid" if code == 0 else "config_invalid",
                 "services": []}
        if code == 0:
            scode, sout = _run(base + ["config", "--services"], timeout=60,
                               cwd=working_dir, env=env)
            if scode == 0:
                entry["services"] = sorted({line.strip() for line in sout.splitlines() if line.strip()})
        result[project] = entry
    return result


def _space_paths(spec, docker_root, volumes, paths):
    candidates = ["/", spec.get("backup_root") or DEFAULT_BACKUP_ROOT,
                  docker_root or "/var/lib/docker"]
    for volume in volumes:
        if volume.get("mountpoint"):
            candidates.append(volume["mountpoint"])
    for path in _str_list(spec.get("space_paths"), []):
        candidates.append(path)
    for path, entry in paths.items():
        if entry.get("exists") and entry.get("kind") == "dir":
            candidates.append(path)
    seen = []
    for path in candidates:
        if path and path not in seen:
            seen.append(path)
    return {path: _space(path) for path in seen}


def main():
    spec = _spec()
    errors = []
    result = {
        "probe_version": PROBE_VERSION,
        "machine_id": None,
        "os": probe_os(),
        "arch": os.uname().machine if hasattr(os, "uname") else None,
        "python": "%d.%d.%d" % sys.version_info[:3],
        "errors": errors,
    }
    try:
        with open("/etc/machine-id", "r", encoding="utf-8", errors="replace") as handle:
            result["machine_id"] = handle.read().strip() or None
        if not result["machine_id"]:
            errors.append("machine_id_empty")
    except OSError:
        errors.append("machine_id_unreadable")
    result["config_fingerprints"] = probe_config_fingerprints(spec)
    result["trusted_fingerprints"] = probe_trusted_fingerprints(spec)
    result["trusted_modes"] = probe_trusted_modes(spec)
    result["docker"] = {
        "present": bool(shutil.which("docker")),
        "version": None,
        "compose_version": None,
        "root_dir": None,
    }
    if result["docker"]["present"]:
        code, out = _run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=15)
        if code == 0:
            result["docker"]["version"] = out.strip() or None
        code, out = _run(["docker", "compose", "version", "--short"], timeout=15)
        if code == 0:
            result["docker"]["compose_version"] = out.strip() or None
        info = _run_json(["docker", "info", "--format", "{{json .DockerRootDir}}"], timeout=20)
        if isinstance(info, str):
            result["docker"]["root_dir"] = info
    _listed, containers = probe_containers(errors)
    units = _str_list(spec.get("units"), DEFAULT_UNITS)
    result["containers"] = containers
    result["volumes"] = probe_volumes(errors)
    extra_paths = [v.get("mountpoint") for v in result["volumes"] if v.get("mountpoint")]
    result["systemd"] = probe_systemd(errors, units)
    result["tar"] = probe_tar(errors)
    result["certbot"] = probe_certbot(errors, spec)
    result["cron_certbot"] = probe_cron(errors)
    result["at_queue"] = probe_at(errors)
    result["ufw"] = probe_ufw(errors)
    probe_path_list = _str_list(spec.get("paths"), DEFAULT_PATHS)
    for extra in extra_paths:
        if extra not in probe_path_list:
            probe_path_list.append(extra)
    result["paths"] = probe_paths(probe_path_list)
    result["writable_layer"] = probe_writable_layer(
        containers, errors, spec.get("writable_layers") or DEFAULT_WRITABLE_LAYERS
    )
    result["compose"] = probe_compose(errors, spec)
    result["space"] = _space_paths(
        spec, result["docker"].get("root_dir"), result["volumes"], result["paths"]
    )
    json.dump(result, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
