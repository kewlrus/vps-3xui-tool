"""Ownership-driven create/cleanup tests for the VM restore fixture (R1).

These tests drive the real ``scripts/vm_restore_fixture.py`` create and cleanup
code through a fake host: filesystem operations are confined to a temporary root
and every Docker/systemd command is answered in-process with real Docker
semantics (``docker volume create`` is idempotent, ``docker inspect`` reports a
missing object, ``systemctl show`` exposes unit properties). No real path,
container, volume or unit is touched.

Covered R1 contract: refusal and partial creation failure preserve pre-existing
files, directories, Docker objects and units; cleanup removes only what this run
recorded and can still prove it owns (full Docker ID, labels plus per-run token,
filesystem dev/inode plus digest, systemd launch token); an incomplete cleanup
retains the ledger and reports nonzero so a retry can finish; a ledger that is
present but unusable is refused; and no unit is stopped, reset or unmasked
without proven ownership.
"""

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FIXTURE = os.path.join(REPO_ROOT, "scripts", "vm_restore_fixture.py")
DRILL = os.path.join(REPO_ROOT, "scripts", "vm-restore-drill.sh")
SCRIPTS = os.path.join(REPO_ROOT, "scripts")
IMAGE = "fixture.local/app@sha256:" + "0" * 64

for _path in (SCRIPTS, os.path.join(REPO_ROOT, "tests"), REPO_ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

_spec = importlib.util.spec_from_file_location("vm_restore_fixture_under_test", FIXTURE)
fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fixture)

import vm_drill  # noqa: E402
import vm_drill_fixture_probe as probe_helper  # noqa: E402
from vps3xui.inventory import Inventory  # noqa: E402


def completed(argv, returncode=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


def parse_labels(argv):
    labels = {}
    index = 0
    while index < len(argv):
        if argv[index] == "--label" and index + 1 < len(argv):
            key, _, value = argv[index + 1].partition("=")
            labels[key] = value
            index += 2
            continue
        index += 1
    return labels


class FakeHost(fixture.Host):
    """Temporary-root filesystem plus in-process Docker/systemd fakes."""

    def __init__(self, root, volumes=None, containers=None, units=None,
                 failures=None, race_volume=False, drop_volume_labels=False,
                 empty_volume_created_at=False, refuse_stop=False,
                 unit_query_errors=None, stop_errors=None):
        super().__init__(root=root, platform="linux", euid=0)
        self.calls = []
        self.volumes = {name: dict(info) for name, info in (volumes or {}).items()}
        self.containers = {name: dict(info) for name, info in (containers or {}).items()}
        self.units = {name: dict(info) for name, info in (units or {}).items()}
        self.failures = dict(failures or {})
        self.race_volume = race_volume
        self.drop_volume_labels = drop_volume_labels
        self.empty_volume_created_at = empty_volume_created_at
        self.refuse_stop = refuse_stop
        # Simulated systemd bus failures: `systemctl show`/`stop` fail for these
        # units without answering anything about their state.
        self.unit_query_errors = set(unit_query_errors or ())
        self.stop_errors = set(stop_errors or ())
        # Snapshot of whether a unit's own file still existed when it was stopped.
        self.stop_snapshot = {}
        self.create_seen = False
        self._sequence = 0

    def add_unit(self, name, token, active=False, invocation="invocation-1",
                 description=None, fragment_path=None, load_state="loaded",
                 sub_state=None):
        self.units[name] = {
            "LoadState": load_state,
            "ActiveState": "active" if active else "inactive",
            "SubState": sub_state or ("running" if active else "dead"),
            "Description": (fixture.UNIT_TOKEN_PREFIX + token
                            if description is None else description),
            "InvocationID": invocation,
            "FragmentPath": ("/etc/systemd/system/%s" % name
                             if fragment_path is None else fragment_path),
        }

    def run(self, argv, timeout=120):
        argv = list(argv)
        self.calls.append(argv)
        for key, code in self.failures.items():
            if tuple(argv[:len(key)]) == tuple(key):
                return completed(argv, code, b"", b"injected failure")
        return self._dispatch(argv)

    def chown(self, path, uid, gid):
        # The fake host has no privilege to change numeric ownership in the
        # temporary root. The VM drill applies the real call; local tests only
        # record that the fixture requested it.
        self.calls.append(["chown", "%d:%d" % (uid, gid), path])

    def _dispatch(self, argv):
        if argv[:3] == ["docker", "volume", "create"]:
            self.create_seen = True
            name = argv[-1]
            if name not in self.volumes:
                # Real `docker volume create` is idempotent: an existing volume
                # keeps its metadata and the command still succeeds.
                labels = None if self.drop_volume_labels else (parse_labels(argv[3:-1]) or None)
                created_at = "" if self.empty_volume_created_at else "2026-09-22T00:00:00Z"
                self.volumes[name] = {
                    "Name": name,
                    "Driver": "local",
                    "CreatedAt": created_at,
                    "Labels": labels,
                    "Mountpoint": "/var/lib/docker/volumes/%s/_data" % name,
                }
            return completed(argv, 0, (name + "\n").encode(), b"")
        if argv[:3] == ["docker", "volume", "inspect"]:
            name = argv[-1]
            if self.race_volume and not self.create_seen:
                return completed(argv, 1, b"", b"Error: No such volume: " + name.encode())
            info = self.volumes.get(name)
            if info is None:
                return completed(argv, 1, b"", b"Error: No such volume: " + name.encode())
            return completed(argv, 0, _json(info).encode(), b"")
        if argv[:3] == ["docker", "volume", "rm"]:
            name = argv[-1]
            if name not in self.volumes:
                return completed(argv, 1, b"", b"Error: No such volume: " + name.encode())
            del self.volumes[name]
            return completed(argv, 0, (name + "\n").encode(), b"")
        if argv[:3] == ["docker", "container", "inspect"]:
            name = argv[-1]
            return completed(argv, 0 if name in self.containers else 1, b"[]", b"")
        if argv[:2] == ["docker", "inspect"]:
            name = argv[-1]
            info = self.containers.get(name)
            if info is None:
                return completed(argv, 1, b"", b"Error: No such object: " + name.encode())
            return completed(argv, 0, _json(info).encode(), b"")
        if argv[:2] == ["docker", "create"]:
            name = argv[argv.index("--name") + 1]
            labels = parse_labels(argv)
            self._sequence += 1
            container_id = "%064x" % self._sequence
            self.containers[name] = {
                "Id": container_id,
                "Name": "/" + name,
                "Config": {"Labels": labels},
            }
            return completed(argv, 0, (container_id + "\n").encode(), b"")
        if argv[:2] == ["docker", "start"]:
            return completed(argv, 0, (argv[-1] + "\n").encode(), b"")
        if argv[:2] == ["docker", "rm"]:
            # Real Docker accepts either a name or a full/abbreviated ID.
            target = argv[-1]
            if target not in self.containers:
                for name, info in list(self.containers.items()):
                    if info.get("Id", "").startswith(target):
                        target = name
                        break
            if target not in self.containers:
                return completed(argv, 1, b"", b"Error: No such container: " + target.encode())
            del self.containers[target]
            return completed(argv, 0, (target + "\n").encode(), b"")
        if argv[:2] == ["docker", "run"]:
            return completed(argv, 0, b"", b"")
        if argv[:2] == ["docker", "cp"]:
            return completed(argv, 0, b"", b"")
        if argv[:2] == ["systemctl", "list-unit-files"]:
            return self._list_units(argv, argv[2])
        if argv[:2] == ["systemctl", "list-units"]:
            return self._list_units(argv, argv[2])
        if argv[:2] == ["systemctl", "show"]:
            name = argv[-1]
            if name in self.unit_query_errors:
                return completed(argv, 1, b"",
                                 b"Failed to connect to bus: No such file or directory")
            properties = self.units.get(name)
            if properties is None:
                return completed(argv, 1, b"", b"Unit %s could not be found." % name.encode())
            keys = []
            index = 2
            while index < len(argv) - 1:
                if argv[index] == "-p":
                    keys.append(argv[index + 1])
                    index += 2
                    continue
                index += 1
            if not keys:
                keys = list(properties)
            body = "".join("%s=%s\n" % (key, properties.get(key, "")) for key in keys)
            return completed(argv, 0, body.encode(), b"")
        if argv[:2] == ["systemctl", "is-active"]:
            name = argv[-1]
            properties = self.units.get(name)
            if properties is not None and properties.get("ActiveState") == "active":
                return completed(argv, 0, b"active\n", b"")
            return completed(argv, 3, b"inactive\n", b"")
        if argv[:2] == ["systemctl", "stop"]:
            name = argv[-1]
            if name in self.stop_errors:
                return completed(argv, 1, b"",
                                 b"Failed to connect to bus: No such file or directory")
            fragment = (self.units.get(name) or {}).get("FragmentPath")
            self.stop_snapshot[name] = self.lexists(
                fragment or ("/etc/systemd/system/%s" % name))
            if not self.refuse_stop and name in self.units:
                self.units[name]["ActiveState"] = "inactive"
            return completed(argv, 0, b"", b"")
        if argv[:1] == ["systemctl"]:
            return completed(argv, 0, b"", b"")
        if argv[:1] == ["setfacl"] or argv[:1] == ["setfattr"]:
            return completed(argv, 0, b"", b"")
        return completed(argv, 1, b"", b"unexpected command")

    def _list_units(self, argv, pattern):
        if pattern.endswith("*"):
            matches = sorted(name for name in self.units if name.startswith(pattern[:-1]))
        else:
            matches = [pattern] if pattern in self.units else []
        body = "".join(name + "\n" for name in matches).encode()
        return completed(argv, 0, body, b"")


class FailingLedgerHost(FakeHost):
    """Fake host whose durable ledger write fails after N fsyncs."""

    def __init__(self, root, fail_after, **kwargs):
        super().__init__(root, **kwargs)
        self.fail_after = fail_after
        self.fsyncs = 0

    def fsync_dir(self, path):
        self.fsyncs += 1
        if self.fsyncs > self.fail_after:
            raise OSError("simulated ledger fsync failure")
        return super().fsync_dir(path)


def _json(value):
    return json.dumps(value)


def destructive_calls(host):
    """Every Docker/systemd call that could remove or reset a resource."""
    destructive = []
    for call in host.calls:
        if call[:2] == ["docker", "rm"]:
            destructive.append(call)
        elif call[:3] == ["docker", "volume", "rm"]:
            destructive.append(call)
        if call[:1] == ["systemctl"] and call[1:2] in (["stop"], ["reset-failed"], ["unmask"]):
            destructive.append(call)
    return destructive


class FixtureCleanupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.host = FakeHost(self.tmp.name)
        self.names = fixture.fixture_identity("t1")
        self.ledger = "/var/lib/%s.ledger.json" % self.names["prefix"]
        self.token = None

    def write(self, path, content, mode=0o600):
        target = self.host.local(path)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(target, mode)

    def read(self, path):
        with open(self.host.local(path), "r", encoding="utf-8") as handle:
            return handle.read()

    def create_all(self, host=None):
        host = host or self.host
        ledger = fixture.Ledger(self.ledger, host, self.names["id"], self.names["prefix"])
        ledger.begin()
        self.token = ledger.token
        return fixture.create_resources(host, self.names, IMAGE, ledger)

    def cleanup(self, host=None, **kwargs):
        kwargs.setdefault("stop_wait_seconds", 0)
        return fixture.cleanup_fixture(self.ledger, host or self.host, **kwargs)

    def destructive(self):
        return destructive_calls(self.host)

    # -- refusal -----------------------------------------------------------

    def test_refusal_never_deletes_a_preexisting_path(self):
        sentinel = "/etc/default/ufw"
        self.write(sentinel, "preexisting-sentinel\n", 0o644)
        with self.assertRaises(SystemExit):
            fixture.create_fixture("t1", IMAGE, self.tmp.name, self.ledger, self.host)
        self.assertFalse(self.host.lexists(self.ledger))
        self.assertEqual(self.read(sentinel), "preexisting-sentinel\n")
        result = self.cleanup()
        self.assertEqual(result["removed"], [])
        self.assertEqual(self.read(sentinel), "preexisting-sentinel\n")
        self.assertEqual(self.destructive(), [])

    def test_refusal_preserves_a_preexisting_docker_volume(self):
        self.host.volumes[self.names["volume"]] = {
            "Name": self.names["volume"], "CreatedAt": "other", "Labels": {"foreign": "1"},
        }
        with self.assertRaises(SystemExit):
            fixture.create_fixture("t1", IMAGE, self.tmp.name, self.ledger, self.host)
        self.assertIn(self.names["volume"], self.host.volumes)
        self.assertEqual(self.host.volumes[self.names["volume"]]["Labels"], {"foreign": "1"})
        self.assertEqual(self.destructive(), [])

    def test_refusal_on_preexisting_vendor_unit(self):
        self.host.add_unit("certbot.service", "vendor", description="vendor certbot")
        with self.assertRaises(SystemExit):
            fixture.create_fixture("t1", IMAGE, self.tmp.name, self.ledger, self.host)
        self.assertFalse(self.host.lexists(fixture.SYSTEMD_VENDOR_DIR + "/certbot.service"))
        self.assertFalse(self.host.lexists("/etc/systemd/system/certbot.service"))
        self.assertFalse(self.host.lexists(self.ledger))
        self.assertEqual(self.destructive(), [])

    def test_refusal_never_overwrites_a_preexisting_vendor_unit_file(self):
        # F6: the fixture installs the Certbot triggers in the vendor directory,
        # so a pre-existing vendor file there is a conflict, never something to
        # overwrite (the real host's own certbot.service may live there).
        vendor = fixture.SYSTEMD_VENDOR_DIR + "/certbot.service"
        self.write(vendor, "# vendor certbot unit; never ours\n", 0o644)
        with self.assertRaises(SystemExit):
            fixture.create_fixture("t1", IMAGE, self.tmp.name, self.ledger, self.host)
        self.assertEqual(self.read(vendor), "# vendor certbot unit; never ours\n")
        self.assertFalse(self.host.lexists(self.ledger))
        self.assertEqual(self.destructive(), [])

    def test_refusal_on_preexisting_cleanup_unit(self):
        self.host.add_unit(fixture.SYSTEMD_UNITS[1], "vendor", description="vendor timer")
        with self.assertRaises(SystemExit):
            fixture.create_fixture("t1", IMAGE, self.tmp.name, self.ledger, self.host)
        self.assertFalse(self.host.lexists("/etc/systemd/system/%s" % fixture.SYSTEMD_UNITS[1]))
        self.assertFalse(self.host.lexists(self.ledger))

    # -- partial failure ---------------------------------------------------

    def test_partial_creation_failure_cleans_only_owned_objects(self):
        self.host.failures[("docker", "create")] = 125
        preexisting_dir = "/etc/letsencrypt"
        os.makedirs(self.host.local(preexisting_dir), exist_ok=True)
        os.chmod(self.host.local(preexisting_dir), 0o750)
        self.write(preexisting_dir + "/keep.conf", "keep\n", 0o600)

        with self.assertRaises(SystemExit):
            fixture.create_fixture("t1", IMAGE, self.tmp.name, self.ledger, self.host)

        self.assertTrue(self.host.isdir(preexisting_dir))
        self.assertEqual(stat.S_IMODE(self.host.lstat(preexisting_dir).st_mode), 0o750)
        self.assertEqual(self.read(preexisting_dir + "/keep.conf"), "keep\n")
        for path in ("/etc/default/ufw", fixture.SYSTEMD_VENDOR_DIR + "/certbot.service",
                     fixture.SYSTEMD_VENDOR_DIR + "/certbot.timer",
                     "/etc/certbot-http01-guard.enabled",
                     self.names["compose_dir"] + "/app.env"):
            self.assertFalse(self.host.lexists(path), path)
        self.assertFalse(self.host.lexists(self.ledger))
        self.assertNotIn(self.names["volume"], self.host.volumes)
        self.assertNotIn(self.names["container"], self.host.containers)
        self.assertIn(["docker", "volume", "rm", self.names["volume"]], self.host.calls)

    def test_ledger_publication_failure_creates_nothing(self):
        host = FailingLedgerHost(self.tmp.name, fail_after=0)
        with self.assertRaises(OSError):
            fixture.create_fixture("t1", IMAGE, self.tmp.name, self.ledger, host)
        self.assertFalse(host.lexists(self.ledger))
        self.assertFalse(host.lexists("/etc/default/ufw"))
        self.assertEqual(destructive_calls(host), [])

    def test_ledger_write_failure_mid_creation_never_deletes_unowned(self):
        host = FailingLedgerHost(self.tmp.name, fail_after=1)
        sentinel = "/etc/letsencrypt/keep.conf"
        self.write(sentinel, "keep\n", 0o600)
        with self.assertRaises(OSError):
            fixture.create_fixture("t1", IMAGE, self.tmp.name, self.ledger, host)
        self.assertEqual(self.read(sentinel), "keep\n")
        self.assertEqual(destructive_calls(host), [])
        self.assertEqual([c for c in host.calls if c[:3] == ["docker", "volume", "create"]], [])

    def test_existing_ledger_is_never_overwritten(self):
        self.write(self.ledger, '{"schema_version": 1, "prefix": "t1"}\n', 0o600)
        with self.assertRaises(SystemExit):
            fixture.create_fixture("t1", IMAGE, self.tmp.name, self.ledger, self.host)
        self.assertEqual(self.read(self.ledger), '{"schema_version": 1, "prefix": "t1"}\n')
        self.assertFalse(self.host.lexists("/etc/default/ufw"))

    def test_foreign_ledger_replacement_is_not_clobbered(self):
        ledger = fixture.Ledger(self.ledger, self.host, self.names["id"], self.names["prefix"])
        ledger.begin()
        os.unlink(self.host.local(self.ledger))
        self.write(self.ledger, "foreign ledger\n", 0o600)
        with self.assertRaises(fixture.LedgerError):
            ledger.add_unit({"name": self.names["worker_unit"], "token": ledger.token})
        self.assertEqual(self.read(self.ledger), "foreign ledger\n")

    # -- volume ownership --------------------------------------------------

    def test_raced_in_foreign_volume_is_refused_and_preserved(self):
        self.host.volumes[self.names["volume"]] = {
            "Name": self.names["volume"], "Driver": "local",
            "CreatedAt": "2020-01-01T00:00:00Z", "Labels": {"foreign": "1"},
            "Mountpoint": "/var/lib/docker/volumes/%s/_data" % self.names["volume"],
        }
        self.host.race_volume = True  # hidden from the pre-check, present at create
        with self.assertRaises(SystemExit):
            fixture.create_fixture("t1", IMAGE, self.tmp.name, self.ledger, self.host)
        foreign = self.host.volumes[self.names["volume"]]
        self.assertEqual(foreign["Labels"], {"foreign": "1"})
        self.assertEqual(foreign["CreatedAt"], "2020-01-01T00:00:00Z")
        self.assertNotIn(["docker", "volume", "rm", self.names["volume"]], self.host.calls)
        self.assertEqual([c for c in self.host.calls if c[:2] == ["docker", "run"]], [])

    def test_volume_without_labels_is_refused_before_seeding(self):
        self.host.drop_volume_labels = True
        with self.assertRaises(SystemExit):
            fixture.create_fixture("t1", IMAGE, self.tmp.name, self.ledger, self.host)
        self.assertEqual([c for c in self.host.calls if c[:2] == ["docker", "run"]], [])
        self.assertEqual(self.destructive(), [])

    def test_volume_without_creation_time_is_refused_before_seeding(self):
        self.host.empty_volume_created_at = True
        with self.assertRaises(SystemExit):
            fixture.create_fixture("t1", IMAGE, self.tmp.name, self.ledger, self.host)
        self.assertEqual([c for c in self.host.calls if c[:2] == ["docker", "run"]], [])

    def test_volume_labels_carry_a_unique_token(self):
        self.create_all()
        labels = self.host.volumes[self.names["volume"]]["Labels"]
        self.assertEqual(labels[fixture.LABEL_TOKEN], self.token)
        self.assertTrue(self.token)

    # -- identity races ----------------------------------------------------

    def test_cleanup_refuses_a_replaced_file_and_retains_the_ledger(self):
        self.create_all()
        target = self.names["compose_dir"] + "/app.env"
        os.unlink(self.host.local(target))
        self.write(target, "foreign-replacement\n", 0o600)
        result = self.cleanup()
        self.assertEqual(self.read(target), "foreign-replacement\n")
        self.assertIn("file:%s" % target, result["blocked"])
        self.assertTrue(result["incomplete"])
        self.assertTrue(self.host.lexists(self.ledger))
        self.assertFalse(self.host.lexists(self.names["compose_dir"] + "/docker-compose.yaml"))

    def test_cleanup_refuses_a_foreign_container(self):
        self.create_all()
        self.host.containers[self.names["container"]]["Id"] = "f" * 64
        result = self.cleanup()
        self.assertIn(self.names["container"], self.host.containers)
        self.assertIn("container:%s" % self.names["container"], result["blocked"])
        self.assertTrue(result["incomplete"])
        self.assertNotIn(["docker", "rm", "-f", self.names["container"]], self.host.calls)

    def test_cleanup_refuses_a_recreated_volume(self):
        self.create_all()
        self.host.volumes[self.names["volume"]]["CreatedAt"] = "someone-else"
        result = self.cleanup()
        self.assertIn(self.names["volume"], self.host.volumes)
        self.assertIn("volume:%s" % self.names["volume"], result["blocked"])
        self.assertNotIn(["docker", "volume", "rm", self.names["volume"]], self.host.calls)

    def test_cleanup_leaves_a_recorded_directory_that_is_no_longer_empty(self):
        self.create_all()
        foreign = "/etc/letsencrypt/renewal/foreign.conf"
        self.write(foreign, "foreign\n", 0o600)
        result = self.cleanup()
        self.assertEqual(self.read(foreign), "foreign\n")
        self.assertTrue(self.host.isdir("/etc/letsencrypt/renewal"))
        self.assertIn("dir:/etc/letsencrypt/renewal", result["blocked"])
        self.assertTrue(result["incomplete"])
        self.assertTrue(self.host.lexists(self.ledger))

    # -- successful cleanup ------------------------------------------------

    def test_cleanup_removes_verified_objects_only(self):
        self.create_all()
        container_id = self.host.containers[self.names["container"]]["Id"]
        result = self.cleanup()
        self.assertFalse(result["incomplete"], result)
        self.assertNotIn(self.names["container"], self.host.containers)
        self.assertNotIn(self.names["volume"], self.host.volumes)
        self.assertIn(["docker", "rm", "-f", container_id], self.host.calls)
        self.assertNotIn(["docker", "rm", "-f", self.names["container"]], self.host.calls)
        self.assertFalse(self.host.lexists(self.ledger))
        self.assertFalse(self.host.lexists(self.names["compose_dir"]))
        self.assertFalse(self.host.lexists(self.names["drill_dir"]))

    def test_cleanup_stops_only_owned_units_and_never_unmasks(self):
        self.create_all()
        self.host.add_unit(self.names["worker_unit"], self.token, active=True)
        fixture.record_unit(self.ledger, self.names["worker_unit"], self.host)
        result = self.cleanup()
        self.assertFalse(result["incomplete"], result)
        self.assertIn(["systemctl", "stop", self.names["worker_unit"]], self.host.calls)
        self.assertIn(["systemctl", "reset-failed", self.names["worker_unit"]], self.host.calls)
        self.assertFalse([c for c in self.host.calls if c[1:2] == ["unmask"]])
        for call in self.host.calls:
            if call[:1] == ["systemctl"] and call[1:2] in (["stop"], ["reset-failed"], ["unmask"]):
                self.assertEqual(call[-1], self.names["worker_unit"], call)

    def test_owned_unit_stop_failure_retains_everything(self):
        self.create_all()
        self.host.add_unit(self.names["worker_unit"], self.token, active=True)
        fixture.record_unit(self.ledger, self.names["worker_unit"], self.host)
        self.host.refuse_stop = True
        result = self.cleanup()
        self.assertTrue(result["incomplete"])
        self.assertIn("unit:%s" % self.names["worker_unit"], result["blocked"])
        self.assertTrue(self.host.lexists(self.ledger))
        self.assertIn(self.names["container"], self.host.containers)
        self.assertTrue(self.host.lexists(self.names["compose_dir"] + "/app.env"))

    def test_unit_token_mismatch_is_never_stopped(self):
        self.create_all()
        self.host.add_unit(self.names["worker_unit"], "another-token", active=True)
        ledger = fixture.Ledger.open_existing(self.ledger, self.host)
        ledger.add_unit({"name": self.names["worker_unit"], "token": self.token})
        result = self.cleanup()
        self.assertTrue(result["incomplete"])
        self.assertNotIn(["systemctl", "stop", self.names["worker_unit"]], self.host.calls)
        self.assertTrue(self.host.lexists(self.ledger))

    def test_absent_recorded_unit_is_tolerated(self):
        self.create_all()
        ledger = fixture.Ledger.open_existing(self.ledger, self.host)
        ledger.add_unit({"name": self.names["worker_unit"], "token": self.token})
        result = self.cleanup()
        self.assertFalse(result["incomplete"], result)
        self.assertIn("unit:%s" % self.names["worker_unit"], result["absent"])
        self.assertFalse(self.host.lexists(self.ledger))

    # -- unknown systemd outcomes -----------------------------------------

    def test_unknown_unit_state_aborts_and_preserves_everything(self):
        self.create_all()
        self.host.add_unit(self.names["worker_unit"], self.token, active=True)
        fixture.record_unit(self.ledger, self.names["worker_unit"], self.host)
        self.host.unit_query_errors.add(self.names["worker_unit"])
        result = self.cleanup()
        self.assertTrue(result["incomplete"])
        self.assertTrue([item for item in result["blocked"] if "unknown runtime state" in item],
                        result["blocked"])
        # Nothing else may be touched while a unit state is unknown.
        self.assertIn(self.names["container"], self.host.containers)
        self.assertIn(self.names["volume"], self.host.volumes)
        self.assertTrue(self.host.lexists(self.names["compose_dir"] + "/app.env"))
        self.assertTrue(self.host.lexists(self.ledger))
        self.assertEqual(self.destructive(), [])
        # The retained ledger keeps every entry, so a retry starts complete.
        retained = json.loads(self.read(self.ledger))
        self.assertEqual([item["name"] for item in retained["containers"]],
                         [self.names["container"], self.names["fail2ban_container"],
                          self.names["idle_container"]])
        self.assertEqual([item["name"] for item in retained["volumes"]],
                         [self.names["volume"]])
        self.assertIn(self.names["compose_dir"] + "/app.env",
                      [item["path"] for item in retained["files"]])

    def test_unit_stop_bus_failure_is_never_read_as_stopped(self):
        self.create_all()
        self.host.add_unit(self.names["worker_unit"], self.token, active=True)
        fixture.record_unit(self.ledger, self.names["worker_unit"], self.host)
        self.host.stop_errors.add(self.names["worker_unit"])
        result = self.cleanup()
        self.assertTrue(result["incomplete"])
        self.assertTrue([item for item in result["blocked"] if "unknown stop outcome" in item],
                        result["blocked"])
        self.assertNotIn(["systemctl", "reset-failed", self.names["worker_unit"]],
                         self.host.calls)
        self.assertIn(self.names["container"], self.host.containers)
        self.assertIn(self.names["volume"], self.host.volumes)
        self.assertTrue(self.host.lexists(self.ledger))
        # Only the one failed stop attempt happened: nothing was removed.
        self.assertEqual([call for call in self.destructive()
                          if call[:2] != ["systemctl", "stop"]], [])

    def test_unknown_fixture_unit_state_aborts_before_any_removal(self):
        self.create_all()
        self.host.add_unit(fixture.SYSTEMD_UNITS[0], "", active=False,
                           description="vps3xui drill cleanup (fixture)")
        self.host.unit_query_errors.add(fixture.SYSTEMD_UNITS[0])
        result = self.cleanup()
        self.assertTrue(result["incomplete"])
        self.assertTrue([item for item in result["blocked"] if "unknown unit" in item],
                        result["blocked"])
        self.assertIn(self.names["container"], self.host.containers)
        self.assertIn(self.names["volume"], self.host.volumes)
        self.assertTrue(self.host.lexists("/etc/systemd/system/%s" % fixture.SYSTEMD_UNITS[0]))
        self.assertTrue(self.host.lexists(self.ledger))
        # The unit-file preflight runs before any removal: even the first fixture
        # file is still in place.
        self.assertTrue(self.host.lexists(self.names["compose_dir"] + "/docker-compose.yaml"))
        self.assertEqual([call for call in self.host.calls
                          if call[:2] in (["docker", "rm"],)
                          or call[:3] == ["docker", "volume", "rm"]], [])

    def test_masked_fixture_unit_state_aborts_before_any_removal(self):
        self.create_all()
        self.host.add_unit(fixture.SYSTEMD_UNITS[0], "", description="vps3xui drill cleanup",
                           fragment_path="/dev/null", load_state="masked")
        result = self.cleanup()
        self.assertTrue(result["incomplete"])
        self.assertIn(self.names["container"], self.host.containers)
        self.assertTrue(self.host.lexists(self.ledger))

    # -- fixture unit files activated by the worker/finalizer ---------------

    def test_activated_fixture_unit_is_stopped_before_its_file_is_unlinked(self):
        self.create_all()
        unit = fixture.SYSTEMD_UNITS[0]
        self.host.add_unit(unit, "", active=True,
                           description="vps3xui drill cleanup (fixture)")
        result = self.cleanup()
        self.assertFalse(result["incomplete"], result)
        self.assertIn(["systemctl", "stop", unit], self.host.calls)
        # The unit was still defined by our file when it was stopped, and the
        # file is gone afterwards, so nothing can be left running from it.
        self.assertTrue(self.host.stop_snapshot[unit])
        self.assertFalse(self.host.lexists("/etc/systemd/system/%s" % unit))
        self.assertFalse(self.host.lexists(self.ledger))

    def test_timer_unit_is_stopped_before_its_file_is_unlinked(self):
        self.create_all()
        unit = fixture.SYSTEMD_UNITS[1]
        self.host.add_unit(unit, "", active=True,
                           description="vps3xui drill cleanup timer (fixture)")
        result = self.cleanup()
        self.assertFalse(result["incomplete"], result)
        self.assertIn(["systemctl", "stop", unit], self.host.calls)
        self.assertTrue(self.host.stop_snapshot[unit])
        self.assertFalse(self.host.lexists("/etc/systemd/system/%s" % unit))

    def test_foreign_same_named_unit_is_never_stopped_and_blocks_its_file(self):
        self.create_all()
        unit = fixture.SYSTEMD_UNITS[1]
        self.host.add_unit(unit, "", active=True, description="vendor timer",
                           fragment_path="/usr/lib/systemd/system/%s" % unit)
        result = self.cleanup()
        self.assertTrue(result["incomplete"])
        self.assertNotIn(["systemctl", "stop", unit], self.host.calls)
        self.assertTrue(self.host.lexists("/etc/systemd/system/%s" % unit))
        self.assertIn("file:/etc/systemd/system/%s" % unit, result["blocked"])
        self.assertTrue(self.host.lexists(self.ledger))
        retained = json.loads(self.read(self.ledger))
        self.assertIn("/etc/systemd/system/%s" % unit,
                      [item["path"] for item in retained["files"]])

    def test_owned_unit_file_is_unlinked_when_no_unit_is_loaded(self):
        self.create_all()
        result = self.cleanup()
        self.assertFalse(result["incomplete"], result)
        self.assertFalse(self.host.lexists("/etc/systemd/system/%s" % fixture.SYSTEMD_UNITS[0]))
        self.assertEqual([c for c in self.host.calls if c[1:2] == ["stop"]], [])

    # -- vendored Certbot triggers (F6) ------------------------------------

    def test_vendored_trigger_is_stopped_before_its_file_is_unlinked(self):
        self.create_all()
        unit = "certbot.service"
        path = fixture.SYSTEMD_VENDOR_DIR + "/" + unit
        self.host.add_unit(unit, "", active=True,
                           description="vps3xui drill certbot stub (fixture)",
                           fragment_path=path)
        result = self.cleanup()
        self.assertFalse(result["incomplete"], result)
        self.assertIn(["systemctl", "stop", unit], self.host.calls)
        # The unit was still defined by the vendor file when it was stopped, and
        # removing it refreshes the loaded unit tree.
        self.assertTrue(self.host.stop_snapshot[unit])
        self.assertFalse(self.host.lexists(path))
        self.assertIn(["systemctl", "daemon-reload"], self.host.calls)
        self.assertFalse(self.host.lexists(self.ledger))

    def test_vendored_trigger_file_is_unlinked_when_no_unit_is_loaded(self):
        self.create_all()
        path = fixture.SYSTEMD_VENDOR_DIR + "/certbot.timer"
        result = self.cleanup()
        self.assertFalse(result["incomplete"], result)
        self.assertFalse(self.host.lexists(path))
        self.assertIn(["systemctl", "daemon-reload"], self.host.calls)
        self.assertEqual([c for c in self.host.calls if c[1:2] == ["stop"]], [])

    def test_vendored_trigger_with_foreign_fragment_path_blocks_its_file(self):
        self.create_all()
        unit = "certbot.timer"
        path = fixture.SYSTEMD_VENDOR_DIR + "/" + unit
        self.host.add_unit(unit, "", active=True, description="vendor timer",
                           fragment_path="/etc/systemd/system/%s" % unit)
        result = self.cleanup()
        self.assertTrue(result["incomplete"])
        self.assertNotIn(["systemctl", "stop", unit], self.host.calls)
        self.assertTrue(self.host.lexists(path))
        self.assertIn("file:%s" % path, result["blocked"])
        self.assertTrue(self.host.lexists(self.ledger))
        retained = json.loads(self.read(self.ledger))
        self.assertIn(path, [item["path"] for item in retained["files"]])

    def test_cleanup_preserves_a_preexisting_usrmerge_lib_symlink(self):
        # A usrmerge host exposes /lib -> usr/lib before the fixture runs. The
        # fixture never creates or records that alias; cleanup removes only the
        # canonical owned vendor files and leaves the pre-existing symlink.
        os.symlink("usr/lib", self.host.local("/lib"))
        self.create_all()
        ledger = json.loads(self.read(self.ledger))
        for field in fixture.LEDGER_LIST_FIELDS:
            for item in ledger.get(field, []):
                identity = item.get("path") or item.get("name") or ""
                self.assertFalse(identity.startswith("/lib"), item)
        result = self.cleanup()
        self.assertFalse(result["incomplete"], result)
        self.assertTrue(os.path.islink(self.host.local("/lib")))
        self.assertFalse(self.host.lexists(fixture.SYSTEMD_VENDOR_DIR + "/certbot.service"))
        self.assertFalse(self.host.lexists(fixture.SYSTEMD_VENDOR_DIR + "/certbot.timer"))
        self.assertFalse(self.host.lexists(self.ledger))

    # -- reserved transient units ------------------------------------------

    def test_reserved_unit_is_stopped_when_the_confirmation_never_ran(self):
        self.create_all()
        fixture.reserve_unit(self.ledger, self.names["worker_unit"], self.host)
        # The launch happened, but --record-unit never ran: the reservation alone
        # is enough to find and stop exactly this unit.
        self.host.add_unit(self.names["worker_unit"], self.token, active=True)
        result = self.cleanup()
        self.assertFalse(result["incomplete"], result)
        self.assertIn(["systemctl", "stop", self.names["worker_unit"]], self.host.calls)
        self.assertFalse(self.host.lexists(self.ledger))

    def test_reserved_unit_that_was_never_launched_is_tolerated(self):
        self.create_all()
        fixture.reserve_unit(self.ledger, self.names["worker_unit"], self.host)
        result = self.cleanup()
        self.assertFalse(result["incomplete"], result)
        self.assertIn("unit:%s" % self.names["worker_unit"], result["absent"])
        self.assertNotIn(["systemctl", "stop", self.names["worker_unit"]], self.host.calls)
        self.assertFalse(self.host.lexists(self.ledger))

    def test_reserved_unit_with_a_foreign_token_is_never_stopped(self):
        self.create_all()
        fixture.reserve_unit(self.ledger, self.names["worker_unit"], self.host)
        self.host.add_unit(self.names["worker_unit"], "someone-else", active=True)
        result = self.cleanup()
        self.assertTrue(result["incomplete"])
        self.assertNotIn(["systemctl", "stop", self.names["worker_unit"]], self.host.calls)
        self.assertTrue(self.host.lexists(self.ledger))
        self.assertIn(self.names["container"], self.host.containers)

    def test_reserve_unit_refuses_outside_the_prefix_or_twice(self):
        self.create_all()
        with self.assertRaises(SystemExit):
            fixture.reserve_unit(self.ledger, "certbot-http01-cleanup.timer", self.host)
        fixture.reserve_unit(self.ledger, self.names["worker_unit"], self.host)
        with self.assertRaises(SystemExit):
            fixture.reserve_unit(self.ledger, self.names["worker_unit"], self.host)
        retained = json.loads(self.read(self.ledger))
        self.assertEqual([entry["name"] for entry in retained["units"]],
                         [self.names["worker_unit"]])
        self.assertEqual(retained["units"][0]["token"], self.token)
        self.assertIsNone(retained["units"][0]["invocation_id"])

    def test_record_unit_updates_the_reservation_without_duplicating_it(self):
        self.create_all()
        fixture.reserve_unit(self.ledger, self.names["worker_unit"], self.host)
        self.host.add_unit(self.names["worker_unit"], self.token)
        fixture.record_unit(self.ledger, self.names["worker_unit"], self.host)
        retained = json.loads(self.read(self.ledger))
        self.assertEqual(len(retained["units"]), 1)
        self.assertEqual(retained["units"][0]["invocation_id"], "invocation-1")

    # -- R9 restore ownership extensions ----------------------------------

    def test_r9_restore_tree_and_container_are_ledger_owned(self):
        self.create_all()
        restore_tree = self.names["drill_dir"] + "/restore-tree"
        fixture.create_owned_tree(self.ledger, restore_tree, self.host)
        transient = self.host.local(restore_tree + "/extracted/config.ini")
        os.makedirs(os.path.dirname(transient), exist_ok=True)
        self.write(restore_tree + "/extracted/config.ini", "config\n", 0o600)
        restored = fixture.create_owned_container(
            self.ledger, self.names["restored_container"], IMAGE, self.host)
        result = self.cleanup()
        self.assertFalse(result["incomplete"], result)
        self.assertFalse(self.host.lexists(restore_tree))
        self.assertNotIn(restored["name"], self.host.containers)
        self.assertIn("container:%s" % restored["name"], result["removed"])

    def test_r9_restore_tree_refuses_a_preexisting_sentinel(self):
        self.create_all()
        restore_tree = self.names["drill_dir"] + "/restore-tree"
        self.write(restore_tree + "/sentinel", "keep\n", 0o600)
        with self.assertRaises(SystemExit):
            fixture.create_owned_tree(self.ledger, restore_tree, self.host)
        self.assertEqual(self.read(restore_tree + "/sentinel"), "keep\n")

    def test_r9_restore_container_refuses_an_existing_name(self):
        self.create_all()
        foreign = self.names["restored_container"]
        self.host.containers[foreign] = {
            "Id": "f" * 64, "Name": "/" + foreign,
            "Config": {"Labels": {"foreign": "1"}},
        }
        with self.assertRaises(SystemExit):
            fixture.create_owned_container(self.ledger, foreign, IMAGE, self.host)
        self.assertEqual(self.host.containers[foreign]["Config"]["Labels"],
                         {"foreign": "1"})

    # -- ledger retention and retry ----------------------------------------

    def test_incomplete_cleanup_retains_a_trimmed_ledger_and_can_be_retried(self):
        self.create_all()
        foreign = "/etc/letsencrypt/renewal/foreign.conf"
        self.write(foreign, "foreign\n", 0o600)
        first = self.cleanup()
        self.assertTrue(first["incomplete"])
        self.assertTrue(self.host.lexists(self.ledger))
        retained = json.loads(self.read(self.ledger))
        # The blocked directory and every ancestor this run created stay in the
        # retained ledger: they are removed only once the foreign file is gone.
        self.assertEqual([item["path"] for item in retained["dirs"]],
                         ["/etc/letsencrypt/renewal", "/etc/letsencrypt", "/etc"])
        self.assertEqual(retained["files"], [])
        self.assertEqual(retained["containers"], [])
        self.assertEqual(retained["volumes"], [])
        self.assertEqual(self.read(foreign), "foreign\n")
        os.unlink(self.host.local(foreign))
        second = self.cleanup()
        self.assertFalse(second["incomplete"], second)
        self.assertFalse(self.host.lexists(self.ledger))
        self.assertFalse(self.host.lexists("/etc/letsencrypt"))
        self.assertFalse(self.host.lexists("/etc"))

    def test_already_removed_objects_are_tolerated(self):
        self.create_all()
        os.unlink(self.host.local(self.names["compose_dir"] + "/app.env"))
        del self.host.volumes[self.names["volume"]]
        del self.host.containers[self.names["container"]]
        result = self.cleanup()
        self.assertFalse(result["incomplete"], result)
        self.assertIn("file:%s" % (self.names["compose_dir"] + "/app.env"), result["absent"])
        self.assertIn("volume:%s" % self.names["volume"], result["absent"])
        self.assertIn("container:%s" % self.names["container"], result["absent"])

    def test_cleanup_removes_no_leftover_temporary_files(self):
        self.create_all()
        self.cleanup()
        directory = os.path.dirname(self.host.local(self.ledger))
        leftovers = [name for name in os.listdir(directory) if ".tmp-" in name]
        self.assertEqual(leftovers, [])

    def test_cleanup_without_a_ledger_is_a_no_op(self):
        result = self.cleanup()
        self.assertEqual(result["removed"], [])
        self.assertFalse(result["incomplete"])
        self.assertEqual(self.host.calls, [])

    def test_symlinked_ledger_is_refused(self):
        self.write("/tmp/elsewhere.json", '{"schema_version": 1}\n', 0o600)
        target = self.host.local(self.ledger)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        os.symlink(self.host.local("/tmp/elsewhere.json"), target)
        result = self.cleanup()
        self.assertTrue(result["incomplete"])
        self.assertTrue([item for item in result["blocked"] if item.startswith("ledger:")])
        self.assertEqual(self.host.calls, [])

    def test_corrupt_ledger_is_refused(self):
        self.write(self.ledger, "not json\n", 0o600)
        result = self.cleanup()
        self.assertTrue(result["incomplete"])
        self.assertEqual(self.host.calls, [])

    def test_bad_schema_or_records_are_refused(self):
        self.write(self.ledger, json.dumps({"schema_version": 99}) + "\n", 0o600)
        self.assertTrue(self.cleanup()["incomplete"])
        self.write(self.ledger, json.dumps({
            "schema_version": fixture.LEDGER_SCHEMA_VERSION, "token": "t",
            "files": "not-a-list",
        }) + "\n", 0o600)
        self.assertTrue(self.cleanup()["incomplete"])

    def test_record_unit_refuses_unowned_or_unknown_units(self):
        with self.assertRaises(SystemExit):
            fixture.record_unit(self.ledger, self.names["worker_unit"], self.host)
        self.create_all()
        with self.assertRaises(SystemExit):
            fixture.record_unit(self.ledger, "certbot-http01-cleanup.timer", self.host)
        with self.assertRaises(SystemExit):
            fixture.record_unit(self.ledger, self.names["worker_unit"], self.host)
        self.host.add_unit(self.names["worker_unit"], "another-token")
        with self.assertRaises(SystemExit):
            fixture.record_unit(self.ledger, self.names["worker_unit"], self.host)
        self.host.add_unit(self.names["worker_unit"], self.token)
        fixture.record_unit(self.ledger, self.names["worker_unit"], self.host)
        retained = json.loads(self.read(self.ledger))
        self.assertEqual(retained["units"][0]["token"], self.token)
        self.assertEqual(retained["units"][0]["invocation_id"], "invocation-1")


class DrillLaunchTokenTest(unittest.TestCase):
    """R9-A: the launch token comes from the validated ledger, not a stale map.

    Drives the *real* fixture ``create_job`` output into the *real* Driver
    ``_reserve_and_launch``/``systemd_run_argv`` (fake Docker/systemd only), so
    the unit Description the drill writes is proven to match the ledger token
    that ``confirm_unit`` checks.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.host = FakeHost(self.tmp.name)
        self.names = fixture.fixture_identity("t1")
        self.ledger = "/var/lib/%s.ledger.json" % self.names["prefix"]
        self.ledger_obj = fixture.Ledger(self.ledger, self.host, self.names["id"],
                                         self.names["prefix"])
        self.ledger_obj.begin()
        self.token = self.ledger_obj.token
        self.resources = fixture.create_resources(self.host, self.names, IMAGE,
                                                  self.ledger_obj)
        inventory = Inventory.from_probe(probe_helper.fixture_probe(
            self.names, IMAGE, self.resources["mountpoint"]))
        self.job = fixture.create_job(self.host, self.names, IMAGE, REPO_ROOT,
                                      self.ledger_obj, self.resources,
                                      probe=lambda spec: inventory)

    def _driver(self, description_token=None, stale_info_token=None):
        evidence = os.path.join(self.tmp.name, "evidence")
        os.makedirs(evidence, exist_ok=True)
        driver = vm_drill.Driver(REPO_ROOT, self.tmp.name, IMAGE, self.names["id"],
                                 self.ledger, evidence)
        driver.host = self.host
        driver.evidence_dir = evidence
        driver.fixture_info = dict(self.job)
        if stale_info_token is not None:
            driver.fixture_info["token"] = stale_info_token
        captured = []

        def fake_run(argv, **kwargs):
            captured.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        driver.run = fake_run
        return driver, captured

    def test_create_job_returns_the_ledger_token(self):
        self.assertEqual(self.job["token"], self.token)
        self.assertEqual(fixture.ledger_token(self.ledger, self.host), self.token)

    def test_launch_uses_the_validated_ledger_token(self):
        unit = self.names["prefix"] + "-worker"
        self.host.add_unit(unit, self.token)
        driver, captured = self._driver(stale_info_token="stale-in-memory-token")
        driver._reserve_and_launch(self.job["job_dir"], unit, 30, 90, None)
        argv = captured[-1]
        description = next(item for item in argv
                           if item.startswith("--property=Description="))
        self.assertEqual(description,
                         "--property=Description=" + fixture.UNIT_TOKEN_PREFIX + self.token)
        self.assertNotIn("stale-in-memory-token", " ".join(argv))
        retained = json.loads(self.read(self.ledger))
        self.assertEqual(retained["units"][0]["token"], self.token)
        self.assertEqual(retained["units"][0]["invocation_id"], "invocation-1")

    def test_launch_refuses_a_unit_with_a_foreign_token(self):
        unit = self.names["prefix"] + "-worker"
        self.host.add_unit(unit, "foreign-token")
        driver, _captured = self._driver()
        with self.assertRaises(SystemExit):
            driver._reserve_and_launch(self.job["job_dir"], unit, 30, 90, None)

    def test_confirm_unit_tolerates_a_collected_short_unit(self):
        unit = self.names["prefix"] + "-worker"
        # systemd-run --collect unloaded the unit before the receipt: systemd
        # proves it absent, and the confirmed launch is recorded as collected.
        fixture.reserve_unit(self.ledger, unit, self.host)
        fixture.confirm_unit(self.ledger, unit, self.host)
        retained = json.loads(self.read(self.ledger))
        entry = [item for item in retained["units"] if item["name"] == unit][0]
        self.assertTrue(entry.get("collected"))
        self.assertIsNone(entry["invocation_id"])
        self.assertEqual(entry["token"], self.token)

    def read(self, path):
        with open(self.host.local(path), "r", encoding="utf-8") as handle:
            return handle.read()


class DrillCleanupWiringTest(unittest.TestCase):
    def test_drill_cleanup_uses_the_ledger_and_never_the_plan(self):
        with open(DRILL, "r", encoding="utf-8") as handle:
            script = handle.read()
        self.assertIn("--cleanup --ledger", script)
        self.assertNotIn("plan[\"files\"]", script)
        self.assertNotIn("docker rm -f", script)
        self.assertNotIn("docker volume rm", script)
        self.assertNotIn("unmask", script)
        self.assertNotIn('"/dev/null || true"', script)
        harness_path = os.path.join(REPO_ROOT, "scripts", "vm_drill.py")
        with open(harness_path, "r", encoding="utf-8") as handle:
            harness = handle.read()
        self.assertIn("fixture.UNIT_TOKEN_PREFIX", harness)
        self.assertIn("fixture.reserve_unit", harness)
        self.assertIn("systemd_run_argv", harness)
        self.assertIn("fixture.confirm_unit", harness)

    def test_fixture_has_no_unlabelled_volume_fallback_or_unmask(self):
        with open(FIXTURE, "r", encoding="utf-8") as handle:
            source = handle.read()
        self.assertNotIn("unmask", source)
        self.assertNotIn('"volume", "create", names["volume"]', source)


class DrillCleanupTrapTest(unittest.TestCase):
    """The drill's real EXIT trap text must fail a successful run when cleanup is
    incomplete, and must never turn a failed run into a success."""

    @staticmethod
    def cleanup_function():
        with open(DRILL, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        try:
            start = lines.index("cleanup() {")
        except ValueError:
            raise AssertionError("the drill has no cleanup() trap function")
        for end in range(start + 1, len(lines)):
            if lines[end] == "}":
                return "\n".join(lines[start:end + 1])
        raise AssertionError("the drill's cleanup() function is unterminated")

    def run_trap(self, cleanup_exit, drill_exit=0):
        directory = tempfile.mkdtemp(prefix="drill-trap-")
        self.addCleanup(shutil.rmtree, directory, True)
        ledger = os.path.join(directory, "drill.ledger.json")
        with open(ledger, "w", encoding="utf-8") as handle:
            handle.write("{}\n")
        harness = (
            "set -euo pipefail\n"
            "ledger=\"$1\"\n"
            "fixture_py=\"$2\"\n"
            "python3() { return %d; }\n"
            "eval \"$3\"\n"
            "trap cleanup EXIT\n"
            "exit %d\n" % (cleanup_exit, drill_exit)
        )
        return subprocess.run(["bash", "-c", harness, "--", ledger, FIXTURE,
                               self.cleanup_function()], capture_output=True)

    def test_incomplete_cleanup_fails_an_otherwise_successful_drill(self):
        result = self.run_trap(cleanup_exit=1, drill_exit=0)
        self.assertEqual(result.returncode, 4, result.stderr.decode())
        self.assertIn(b"INCOMPLETE", result.stderr)

    def test_incomplete_cleanup_never_turns_a_failure_into_success(self):
        result = self.run_trap(cleanup_exit=1, drill_exit=1)
        self.assertEqual(result.returncode, 1, result.stderr.decode())
        self.assertIn(b"INCOMPLETE", result.stderr)

    def test_complete_cleanup_keeps_the_success_exit(self):
        result = self.run_trap(cleanup_exit=0, drill_exit=0)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertNotIn(b"INCOMPLETE", result.stderr)

    def test_drill_reserves_the_unit_before_launching_it(self):
        harness_path = os.path.join(REPO_ROOT, "scripts", "vm_drill.py")
        with open(harness_path, "r", encoding="utf-8") as handle:
            script = handle.read()
        reserve = script.index("fixture.reserve_unit")
        launch = script.index("self.run(argv)", reserve)
        record = script.index("fixture.confirm_unit", launch)
        self.assertLess(reserve, launch, "the unit must be reserved before the launch")
        self.assertLess(launch, record, "the launch must precede the confirmation")

    def test_cleanup_trap_reports_the_fixture_output_and_a_retry(self):
        result = self.run_trap(cleanup_exit=1, drill_exit=0)
        self.assertIn(b"retry:", result.stderr)
        self.assertIn(b"the ownership ledger was retained", result.stderr)


class FixtureCliContractTest(unittest.TestCase):
    """The drill invokes cleanup with only a ledger; keep that CLI shape valid."""

    def run_cli(self, *args):
        return subprocess.run([sys.executable, FIXTURE, *args],
                              capture_output=True, cwd=REPO_ROOT)

    def temporary_ledger_dir(self):
        directory = tempfile.mkdtemp(prefix="drill-ledger-")
        self.addCleanup(shutil.rmtree, directory, True)
        return directory

    def missing_ledger(self):
        return os.path.join(self.temporary_ledger_dir(), "absent.ledger.json")

    def test_cleanup_with_only_a_ledger_is_a_quiet_no_op(self):
        result = self.run_cli("--cleanup", "--ledger", self.missing_ledger())
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_cleanup_reports_nonzero_for_an_unusable_ledger(self):
        path = os.path.join(self.temporary_ledger_dir(), "bad.ledger.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("not json\n")
        result = self.run_cli("--cleanup", "--ledger", path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"retained", result.stderr)

    def test_cleanup_requires_a_ledger(self):
        result = self.run_cli("--cleanup")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"--ledger", result.stderr)

    def test_create_requires_a_ledger(self):
        result = self.run_cli("--create", "--identifier", "t1", "--image", IMAGE)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"--ledger", result.stderr)

    def test_plan_requires_an_identifier(self):
        result = self.run_cli("--plan")
        self.assertNotEqual(result.returncode, 0)

    def test_record_unit_requires_a_ledger(self):
        result = self.run_cli("--record-unit", "vps3xui-drill-t1-worker",
                              "--ledger", self.missing_ledger())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"ledger", result.stderr)

    def test_reserve_unit_requires_a_ledger(self):
        result = self.run_cli("--reserve-unit", "vps3xui-drill-t1-worker")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"--ledger", result.stderr)

    def test_reserve_unit_without_a_ledger_file_is_refused(self):
        result = self.run_cli("--reserve-unit", "vps3xui-drill-t1-worker",
                              "--ledger", self.missing_ledger())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"no ownership ledger is present", result.stderr)


if __name__ == "__main__":
    unittest.main()
