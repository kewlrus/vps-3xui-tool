"""Strict OpenSSH transport.

Security properties required by the design and enforced here:

* the alias is a validated identifier, never interpolated as a shell string;
* ``StrictHostKeyChecking=yes`` and ``BatchMode=yes`` are always set;
* multiplexing is disabled (``ControlMaster=no``, ``ControlPath=none``);
* ``UpdateHostKeys=no`` so the pinned host key cannot be silently rotated;
* the resolved host key fingerprint is read from local ``known_hosts`` and is
  part of host identity; an unknown host key is ``E_HOST_KEY_UNKNOWN``;
* child stderr is captured but only its length and digest are retained, so raw
  remote output never reaches diagnostics.
"""

from __future__ import annotations

import atexit
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from typing import Dict, List, Optional, Sequence

from ..errors import ToolError
from ..util import bounded

_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

SSH_OPTIONS = [
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes",
    "-o", "UpdateHostKeys=no",
    "-o", "ControlMaster=no",
    "-o", "ControlPath=none",
    "-o", "ControlPersist=no",
    "-o", "PreferredAuthentications=publickey",
    "-o", "PasswordAuthentication=no",
    "-o", "KbdInteractiveAuthentication=no",
]


class CommandResult(object):
    def __init__(self, exit_code: int, stdout: bytes, stderr: bytes):
        self.exit_code = exit_code
        self.stdout = stdout
        self._stderr = stderr
        self.stderr_len = len(stderr)
        self.stderr_digest = hashlib.sha256(stderr).hexdigest() if stderr else ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    def text(self, limit: int = 4 * 1024 * 1024) -> str:
        return self.stdout[:limit].decode("utf-8", "replace")

    def safe_summary(self) -> str:
        """A bounded summary with no raw remote text."""
        return "exit=%d stderr_bytes=%d" % (self.exit_code, self.stderr_len)


def validate_alias(alias: str) -> str:
    if not isinstance(alias, str) or not _ALIAS_RE.match(alias):
        raise ToolError(
            "E_CONTRACT",
            "SSH alias must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}.",
            resource="ssh_alias",
            next_action="pass_valid_alias",
        )
    return alias


PREFERRED_KEY_TYPES = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
)


def _option_present(value) -> bool:
    """``ssh -G`` prints 'none' for unset options; honour that as absence."""
    if value is None:
        return False
    text = str(value).strip()
    return text not in ("", "none", "None")


def _parse_known_hosts_line(raw: str, source: str):
    parts = raw.split()
    if len(parts) < 3:
        return None
    marker = ""
    if parts[0].startswith("@"):
        marker = parts[0][1:]
        parts = parts[1:]
    if len(parts) < 3:
        return None
    _hosts, keytype, key = parts[0], parts[1], parts[2]
    return {"marker": marker, "keytype": keytype, "key": key,
            "line": raw.strip(), "source": source}


def _select_key(parsed, alias: str):
    """Pick exactly one trusted key per algorithm; refuse revoked/CA/ambiguous."""
    if any(item["marker"] == "revoked" for item in parsed):
        raise ToolError("E_HOST_KEY_UNKNOWN",
                        "The pinned host key is marked revoked in known_hosts.",
                        resource=alias, next_action="pin_host_key")
    if any(item["marker"] == "cert-authority" for item in parsed):
        raise ToolError("E_UNSUPPORTED",
                        "The host is pinned through a CA key, which cannot be bound exactly.",
                        resource=alias, next_action="pin_host_key")
    by_type = {}
    for item in parsed:
        by_type.setdefault(item["keytype"], []).append(item)
    for keytype in PREFERRED_KEY_TYPES:
        entries = by_type.get(keytype) or []
        distinct = {item["key"] for item in entries}
        if len(distinct) > 1:
            raise ToolError("E_UNSUPPORTED",
                            "Multiple different %s keys are pinned for this host." % keytype,
                            resource=alias, next_action="remove_stale_host_key")
        if len(distinct) == 1:
            return entries[0]
    for keytype in sorted(by_type):
        entries = by_type[keytype]
        distinct = {item["key"] for item in entries}
        if len(distinct) > 1:
            raise ToolError("E_UNSUPPORTED",
                            "Multiple different %s keys are pinned for this host." % keytype,
                            resource=alias, next_action="remove_stale_host_key")
        return entries[0]
    return None


def _fingerprint_of(key_b64: str) -> Optional[str]:
    """OpenSSH SHA256 fingerprint of a base64 host-key blob (no padding)."""
    import base64 as _b64
    import hashlib as _hashlib

    try:
        blob = _b64.b64decode(key_b64, validate=True)
    except (ValueError, TypeError):
        return None
    digest = _hashlib.sha256(blob).digest()
    return "SHA256:" + _b64.b64encode(digest).decode("ascii").rstrip("=")


class SshTransport(object):
    def __init__(self, alias: str, connect_timeout: int = 10, ssh_binary: str = "ssh"):
        self.alias = validate_alias(alias)
        self.connect_timeout = int(connect_timeout)
        self.ssh_binary = ssh_binary
        self._resolved: Optional[Dict[str, str]] = None
        self._pin: Optional[Dict[str, str]] = None
        self._pin_dir: Optional[str] = None

    # -- host identity ----------------------------------------------------
    def resolve(self) -> Dict[str, str]:
        """Resolve the alias locally via ``ssh -G`` (no network access)."""
        if self._resolved is not None:
            return self._resolved
        try:
            proc = subprocess.run(
                [self.ssh_binary, "-G", self.alias],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            raise ToolError(
                "E_EXECUTION",
                "Cannot resolve SSH alias locally.",
                resource=self.alias,
                next_action="check_ssh_config",
            )
        if proc.returncode != 0:
            raise ToolError(
                "E_CONTRACT",
                "SSH alias is not defined in the local SSH configuration.",
                resource=self.alias,
                next_action="define_alias",
            )
        resolved: Dict[str, str] = {}
        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            key, _, value = line.partition(" ")
            if key and value and key not in resolved:
                resolved[key] = value
        self._resolved = resolved
        return resolved

    def fingerprint(self) -> str:
        """HostOps-compatible alias for the pinned host key fingerprint."""
        return self.host_key_pin()["fingerprint"]

    def host_key_fingerprint(self) -> str:
        return self.fingerprint()

    def host_key_pin(self) -> Dict[str, str]:
        """The exact trusted host key this transport is bound to.

        Resolution is local (``ssh -G`` + ``ssh-keygen -F``); no TOFU, no
        ``ssh-keyscan``, no network. The selected key is copied into a private
        temporary ``known_hosts`` file that this transport passes to *every*
        ``ssh`` invocation, together with the pinned algorithm and the resolved
        hostname/port. A revoked key, a CA key, an ambiguous same-algorithm pair
        or an unsupported complex configuration is refused instead of being
        pretended verified.
        """
        if self._pin is not None:
            return self._pin
        resolved = self.resolve()
        for key in ("proxycommand", "proxyjump", "hostkeyalias", "knownhostscommand"):
            if _option_present(resolved.get(key)):
                raise ToolError(
                    "E_UNSUPPORTED",
                    "The SSH configuration uses %s, which cannot be bound to a pinned host key." % key,
                    resource=self.alias,
                    next_action="simplify_ssh_config",
                )
        hostname = resolved.get("hostname")
        if not _option_present(hostname):
            raise ToolError("E_HOST_KEY_UNKNOWN", "SSH alias has no hostname.", resource=self.alias)
        port = resolved.get("port") if _option_present(resolved.get("port")) else "22"
        lookup = hostname if port == "22" else "[%s]:%s" % (hostname, port)
        candidates = []
        known_hosts = resolved.get("userknownhostsfile")
        if _option_present(known_hosts):
            candidates.extend(tok for tok in known_hosts.split() if _option_present(tok))
        candidates.append(os.path.expanduser("~/.ssh/known_hosts"))

        selected = None
        for path in candidates:
            if not path or not os.path.isfile(path):
                continue
            parsed = self._known_hosts_keys(lookup, path)
            if not parsed:
                continue
            selected = _select_key(parsed, self.alias)
            break
        if selected is None:
            raise ToolError(
                "E_HOST_KEY_UNKNOWN",
                "No trusted host key is pinned for this alias in known_hosts.",
                resource=self.alias,
                next_action="pin_host_key",
            )
        fingerprint = _fingerprint_of(selected["key"])
        if fingerprint is None:
            raise ToolError("E_HOST_KEY_UNKNOWN", "The pinned host key could not be fingerprinted.",
                            resource=self.alias, next_action="pin_host_key")
        pin_dir = tempfile.mkdtemp(prefix="vps3xui-known-hosts-")
        os.chmod(pin_dir, 0o700)
        pin_file = os.path.join(pin_dir, "known_hosts")
        with open(pin_file, "w", encoding="utf-8") as handle:
            handle.write(selected["line"] + "\n")
        os.chmod(pin_file, 0o600)
        atexit.register(self.close)
        self._pin_dir = pin_dir
        self._pin = {
            "file": pin_file,
            "known_hosts_source": selected["source"],
            "keytype": selected["keytype"],
            "key": selected["key"],
            "fingerprint": fingerprint,
            "hostname": hostname,
            "port": port,
            "user": resolved.get("user") if _option_present(resolved.get("user")) else "",
        }
        return self._pin

    def close(self) -> None:
        """Remove the private pinned known_hosts file (explicit transport lifecycle)."""
        if self._pin_dir:
            shutil.rmtree(self._pin_dir, ignore_errors=True)
            self._pin_dir = None

    def __del__(self):  # pragma: no cover - best effort
        try:
            self.close()
        except Exception:
            pass

    @staticmethod
    def _known_hosts_keys(lookup: str, path: str):
        """Return parsed keys for ``lookup`` from one known_hosts file."""
        try:
            proc = subprocess.run(
                ["ssh-keygen", "-F", lookup, "-f", path],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            return []
        if proc.returncode != 0:
            return []
        parsed = []
        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            if line.startswith("#") or not line.strip():
                continue
            entry = _parse_known_hosts_line(line, path)
            if entry is not None:
                parsed.append(entry)
        return parsed

    # -- command execution ------------------------------------------------
    def _base_argv(self) -> List[str]:
        pin = self.host_key_pin()
        return (
            [
                self.ssh_binary,
                "-o", "ConnectTimeout=%d" % self.connect_timeout,
            ]
            + SSH_OPTIONS
            + [
                "-o", "Hostname=%s" % pin["hostname"],
                "-o", "Port=%s" % pin["port"],
                "-o", "UserKnownHostsFile=%s" % pin["file"],
                "-o", "GlobalKnownHostsFile=/dev/null",
                "-o", "HostKeyAlgorithms=%s" % pin["keytype"],
            ]
            + ([ "-o", "User=%s" % pin["user"]] if pin.get("user") else [])
            + [self.alias]
        )

    def run(
        self,
        argv: Sequence[str],
        stdin_bytes: Optional[bytes] = None,
        timeout: int = 60,
        max_stdout: int = 8 * 1024 * 1024,
    ) -> CommandResult:
        if not argv:
            raise ToolError("E_CONTRACT", "Remote command is empty.")
        for token in argv:
            if not isinstance(token, str) or "\x00" in token:
                raise ToolError("E_CONTRACT", "Remote command token is invalid.")
        command = " ".join(_shell_quote(token) for token in argv)
        return self.run_raw(command, stdin_bytes=stdin_bytes, timeout=timeout, max_stdout=max_stdout)

    def run_raw(
        self,
        command: str,
        stdin_bytes: Optional[bytes] = None,
        timeout: int = 60,
        max_stdout: int = 8 * 1024 * 1024,
    ) -> CommandResult:
        full = self._base_argv() + [command]
        try:
            proc = subprocess.run(
                full,
                input=stdin_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise ToolError(
                "E_EXECUTION",
                "Remote command timed out.",
                resource=self.alias,
                next_action="retry_or_inspect",
            )
        except OSError:
            raise ToolError(
                "E_EXECUTION",
                "Cannot launch the local ssh client.",
                resource=self.alias,
                next_action="check_ssh_client",
            )
        return CommandResult(
            proc.returncode,
            proc.stdout[:max_stdout],
            proc.stderr[:4096],
        )

    def fetch_to(self, remote_path: str, local_path: str, timeout: int = 3600) -> CommandResult:
        """Stream a remote file to a local path without printing it."""
        full = self._base_argv() + ["cat -- %s" % _shell_quote(remote_path)]
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(local_path, flags, 0o600)
        except OSError as exc:
            raise ToolError("E_PRECONDITION",
                            "Refusing to write the fetched file (exists, symlink or unwritable).",
                            resource=os.path.basename(local_path), next_action="use_fresh_destination")
        try:
            with os.fdopen(fd, "wb") as handle:
                proc = subprocess.run(
                    full,
                    stdout=handle,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                )
        except subprocess.TimeoutExpired:
            raise ToolError(
                "E_EXECUTION",
                "Remote fetch timed out.",
                resource=os.path.basename(remote_path),
                next_action="retry_fetch",
            )
        except OSError:
            raise ToolError(
                "E_EXECUTION",
                "Cannot write fetched file.",
                resource=os.path.basename(local_path),
                next_action="check_destination",
            )
        return CommandResult(proc.returncode, b"", proc.stderr[:4096])


def _shell_quote(token: str) -> str:
    return "'" + token.replace("'", "'\\''") + "'"


def remote_quote(token: str) -> str:
    """Public helper for building a single remote argument safely."""
    return _shell_quote(token)


def safe_remote_error(result: CommandResult, what: str) -> ToolError:
    return ToolError(
        "E_EXECUTION",
        "%s failed (%s)." % (what, bounded(result.safe_summary(), 120)),
        next_action="inspect_remote_state",
    )


def _probe_bytes() -> bytes:
    here = os.path.dirname(os.path.abspath(__file__))
    probe_path = os.path.join(os.path.dirname(here), "probe.py")
    with open(probe_path, "rb") as handle:
        return handle.read()


_VERIFY_RELEASE_SNIPPET = (
    "import hashlib,json,os,sys\n"
    "root=sys.argv[1]\n"
    "want=json.load(sys.stdin)\n"
    "bad=[]\n"
    "for name,digest in want.items():\n"
    "    p=os.path.join(root,name)\n"
    "    if os.path.islink(p) or not os.path.isfile(p):\n"
    "        bad.append(name); continue\n"
    "    h=hashlib.sha256(open(p,'rb').read()).hexdigest()\n"
    "    if h!=digest: bad.append(name)\n"
    "sys.exit(1 if bad else 0)\n"
)

# Verify the received archive bytes before extraction.
_HASH_SNIPPET = (
    "import hashlib,sys\n"
    "sys.exit(0 if hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest()==sys.argv[2] else 1)\n"
)

# Atomic directory publish (no -T, which is not portable to BSD tar/mv hosts).
_RENAME_SNIPPET = (
    "import os,sys\n"
    "os.rename(sys.argv[1],sys.argv[2])\n"
)


def _remote_ops_bytes() -> bytes:
    """The fixed remote coordination program, shipped over stdin.

    ``vps3xui.coordination`` (the shared, stdlib-only lock/reservation
    primitives) is concatenated ahead of ``remote_ops`` so the reviewed code path
    has no package import and no separate install step.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    package = os.path.dirname(here)
    with open(os.path.join(package, "coordination.py"), "rb") as handle:
        coordination = handle.read()
    with open(os.path.join(package, "remote_ops.py"), "rb") as handle:
        ops = handle.read().replace(b"from __future__ import annotations\n", b"", 1)
    return coordination + b"\n" + ops


class RemoteHostOps(SshTransport):
    """Real host operations over OpenSSH, implementing the HostOps interface."""

    def probe(self, spec=None, timeout: int = 90):
        import base64
        import json

        from ..inventory import Inventory

        check = self.run_raw("command -v python3 >/dev/null 2>&1", timeout=30)
        if not check.ok:
            raise ToolError(
                "E_RUNTIME_MISSING",
                "The host has no python3 interpreter for the read-only probe.",
                resource=self.alias,
                next_action="install_runtime_or_use_manual_probe",
            )
        command = "python3 -"
        if spec is not None:
            token = base64.b64encode(
                json.dumps(spec, sort_keys=True).encode("utf-8")
            ).decode("ascii")
            command = "python3 - %s" % remote_quote(token)
        result = self.run_raw(command, stdin_bytes=_probe_bytes(), timeout=timeout)
        if not result.ok:
            raise safe_remote_error(result, "read-only probe")
        try:
            import json

            data = json.loads(result.text())
        except ValueError:
            raise ToolError(
                "E_UNSUPPORTED",
                "Probe returned data that is not a JSON object.",
                resource=self.alias,
                next_action="check_host_runtime",
            )
        return Inventory.from_probe(data)

    def read_json_file(self, remote_path: str):
        quoted = remote_quote(remote_path)
        result = self.run_raw("test -f %s && cat -- %s" % (quoted, quoted), timeout=60)
        if result.exit_code != 0:
            return None
        try:
            import json

            return json.loads(result.text())
        except ValueError:
            raise ToolError(
                "E_EXECUTION",
                "Remote job file is not valid JSON.",
                resource=os.path.basename(remote_path),
                next_action="inspect_remote_state",
            )

    def path_exists(self, remote_path: str) -> bool:
        return self.run_raw("test -e %s" % remote_quote(remote_path), timeout=30).ok

    def list_dir(self, remote_path: str) -> List[str]:
        result = self.run_raw("ls -1 -- %s 2>/dev/null || true" % remote_quote(remote_path), timeout=30)
        if not result.ok:
            return []
        return [line for line in result.text(1 << 20).splitlines() if line.strip()]

    def write_file(self, remote_path: str, data: bytes, mode: int = 0o600) -> None:
        directory = os.path.dirname(remote_path)
        # Unique temp per attempt: a shared name lets two concurrent writers
        # clobber each other's payload before the rename.
        temp = os.path.join(directory, ".tmp-vps3xui-%s" % os.urandom(6).hex())
        command = (
            "set -e; umask 077; mkdir -p %s; cat > %s; chmod %o %s; mv -f %s %s; sync"
            % (
                remote_quote(directory),
                remote_quote(temp),
                mode,
                remote_quote(temp),
                remote_quote(temp),
                remote_quote(remote_path),
            )
        )
        result = self.run_raw(command, stdin_bytes=data, timeout=300)
        if not result.ok:
            raise safe_remote_error(result, "write remote file")

    def ensure_release(self, release_dir: str, archive: bytes) -> str:
        import json

        from ..release import archive_file_hashes

        expected = hashlib.sha256(archive).hexdigest()
        marker = os.path.join(release_dir, ".digest")
        files_marker = os.path.join(release_dir, ".files")
        file_map = archive_file_hashes(archive)

        # Reuse only a release whose receipt matches the expected bytes.
        check = self.run_raw(
            "test -d %s && cat -- %s 2>/dev/null" % (remote_quote(release_dir), remote_quote(marker)),
            timeout=30,
        )
        if check.ok and check.text(4096).strip() == expected:
            verify = self.run_raw(
                "env PYTHONPATH=%s python3 -c %s %s"
                % (
                    remote_quote(release_dir),
                    _shell_quote(_VERIFY_RELEASE_SNIPPET),
                    remote_quote(release_dir),
                ),
                stdin_bytes=json.dumps(file_map).encode("utf-8"),
                timeout=300,
            )
            if verify.ok:
                return expected
            raise ToolError(
                "E_EXECUTION",
                "An existing pinned release does not match its recorded contents.",
                resource=os.path.basename(release_dir),
                next_action="inspect_release",
            )
        if self.run_raw("test -e %s" % remote_quote(release_dir), timeout=30).ok:
            raise ToolError(
                "E_EXECUTION",
                "A release path exists with different contents; refusing to replace it.",
                resource=os.path.basename(release_dir),
                next_action="inspect_release",
            )

        # Unique temp per attempt; publish atomically with no-replace so two
        # concurrent identical installs cannot clobber each other.
        suffix = os.urandom(6).hex()
        tmp_dir = "%s.tmp-%s" % (release_dir, suffix)
        tar_tmp = "%s.tar.tmp-%s" % (release_dir, suffix)
        self.write_file(tar_tmp, archive, mode=0o600)
        install = (
            "set -e; umask 077; "
            "trap 'rm -rf %(tmp)s %(tar)s' EXIT; "
            "test ! -e %(dir)s || { echo exists >&2; exit 3; }; "
            "test ! -e %(tmp)s || { echo exists >&2; exit 3; }; "
            "python3 -c %(hash)s %(tar)s %(digest)s; "
            "mkdir -p %(tmp)s; "
            "tar -xpf %(tar)s -C %(tmp)s; rm -f %(tar)s; "
            "printf '%%s' %(digest)s > %(tmp)s/.digest; "
            "cat > %(tmp)s/.files; "
            "env PYTHONPATH=%(tmp)s python3 -c %(verify)s %(tmp)s < %(tmp)s/.files; "
            "chmod -R a-w %(tmp)s; "
            "test ! -e %(dir)s || { echo exists >&2; exit 3; }; "
            # Atomic, portable no-replace publish: os.rename fails rather than
            # moving into a concurrently created directory.
            "python3 -c %(rename)s %(tmp)s %(dir)s; "
            "chmod 600 %(marker)s %(files)s"
            % {
                "tmp": remote_quote(tmp_dir),
                "tar": remote_quote(tar_tmp),
                "dir": remote_quote(release_dir),
                "digest": remote_quote(expected),
                "hash": _shell_quote(_HASH_SNIPPET),
                "verify": _shell_quote(_VERIFY_RELEASE_SNIPPET),
                "marker": remote_quote(marker),
                "files": remote_quote(files_marker),
                "rename": _shell_quote(_RENAME_SNIPPET),
            }
        )
        result = self.run_raw(
            install,
            stdin_bytes=json.dumps(file_map).encode("utf-8"),
            timeout=600,
        )
        if not result.ok:
            raise safe_remote_error(result, "deliver pinned release")
        return expected

    def launch_backup(self, unit_name: str, release_dir: str, job_dir: str,
                      runtime_max_seconds: int, timeout_stop_seconds: int) -> None:
        worker = os.path.join(release_dir, "bin", "vps3xui-worker")
        finalizer = os.path.join(release_dir, "bin", "vps3xui-finalizer")
        argv = [
            "systemd-run",
            "--unit=%s" % unit_name,
            "--property=Type=exec",
            "--property=RuntimeMaxSec=%d" % int(runtime_max_seconds),
            "--property=TimeoutStopSec=%d" % int(timeout_stop_seconds),
            "--property=KillMode=control-group",
            "--property=ExecStopPost=%s %s" % (finalizer, _shell_quote(job_dir)),
            "--property=StandardOutput=journal",
            "--property=StandardError=journal",
            worker,
            job_dir,
        ]
        result = self.run(argv, timeout=60)
        if not result.ok:
            raise safe_remote_error(result, "systemd-run backup unit")

    def launch_recover(self, unit_name: str, release_dir: str, job_dir: str) -> None:
        finalizer = os.path.join(release_dir, "bin", "vps3xui-finalizer")
        argv = [
            "systemd-run",
            "--no-block",
            "--unit=%s" % unit_name,
            "--property=Type=oneshot",
            "--property=RuntimeMaxSec=900",
            "--property=KillMode=control-group",
            "--property=StandardOutput=journal",
            "--property=StandardError=journal",
            finalizer,
            "--recover",
            job_dir,
        ]
        result = self.run(argv, timeout=60)
        if not result.ok:
            raise safe_remote_error(result, "systemd-run recover unit")

    def remote_verify(self, release_dir: str, backup_dir: str, manifest_path: str) -> dict:
        import json

        command = (
            "env PYTHONPATH=%s python3 -m vps3xui.remote_verify "
            "--directory %s --manifest %s"
        ) % (
            remote_quote(release_dir),
            remote_quote(backup_dir),
            remote_quote(manifest_path),
        )
        result = self.run_raw(command, timeout=1800)
        if not result.ok and not result.text(1 << 20).strip():
            raise safe_remote_error(result, "remote verification")
        try:
            return json.loads(result.text())
        except ValueError:
            raise ToolError(
                "E_EXECUTION",
                "Remote verification returned data that is not JSON.",
                resource=os.path.basename(backup_dir),
                next_action="inspect_remote_state",
            )

    def fetch_file(self, remote_path: str, local_path: str) -> None:
        result = self.fetch_to(remote_path, local_path)
        if not result.ok:
            raise safe_remote_error(result, "fetch remote artifact")

    def host_context(self) -> Dict[str, str]:
        """Resolved connection context bound into the plan identity."""
        pin = self.host_key_pin()
        return {
            "ssh_alias": self.alias,
            "hostname": pin["hostname"],
            "port": pin["port"],
            "user": pin.get("user") or "",
            "host_key_fingerprint": pin["fingerprint"],
        }

    def remote_recover(self, root: str, job_id: str) -> dict:
        """Launch the fixed recover unit for an owned job, under the stack lock."""
        return self._run_remote_ops(root, ["recover", job_id], timeout=300)

    # -- remote stack coordination ---------------------------------------
    def _run_remote_ops(self, root: str, command: List[str], stdin_bytes: bytes = b"",
                        timeout: int = 120) -> dict:
        import json

        check = self.run_raw("command -v python3 >/dev/null 2>&1", timeout=30)
        if not check.ok:
            raise ToolError(
                "E_RUNTIME_MISSING",
                "The host has no python3 interpreter for remote coordination.",
                resource=self.alias,
                next_action="install_runtime",
            )
        argv = ["python3", "-", remote_quote(root)] + [remote_quote(tok) for tok in command]
        result = self.run_raw(" ".join(argv), stdin_bytes=_remote_ops_bytes(), timeout=timeout)
        # The JSON payload (if any) travels as a base64 argv token so the
        # shipped source on stdin stays exactly the reviewed module.
        if not result.ok and not result.text(1 << 20).strip():
            raise safe_remote_error(result, "remote coordination")
        try:
            return json.loads(result.text())
        except ValueError:
            raise ToolError(
                "E_EXECUTION",
                "Remote coordination returned data that is not JSON.",
                resource=os.path.basename(root),
                next_action="inspect_remote_state",
            )

    def reserve_and_launch(self, root: str, job_dir: str, request_payload: dict,
                           plan_payload: dict, launch: dict) -> dict:
        import json

        payload = {
            "job_id": request_payload.get("job_id"),
            "request": request_payload,
            "plan": plan_payload,
            "launch": launch,
        }
        import base64 as _b64

        token = _b64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        result = self._run_remote_ops(
            root, ["reserve-and-launch", token], b"", timeout=300
        )
        if not result.get("ok"):
            error = result.get("error") or {}
            raise ToolError(
                error.get("code") or "E_EXECUTION",
                error.get("message") or "Remote reservation failed.",
                resource=error.get("resource"),
                next_action=error.get("next_action"),
            )
        return result

    def remote_job_status(self, root: str, job_id: str) -> dict:
        result = self._run_remote_ops(root, ["status", job_id], timeout=60)
        return result
