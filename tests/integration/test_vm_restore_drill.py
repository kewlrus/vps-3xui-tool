"""Integration guards for the isolated VM restore drill.

The full drill requires a disposable Linux VM/container, which is not available
in this workspace. These tests verify that the harness exists, is syntactically
valid, is executable, builds a synthetic (non-production) fixture, and fails
closed with a documented NOT RUN result when no isolated target is provided.
P0 must not be called production-ready until the drill itself passes on a
disposable host and the run is recorded.
"""

import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DRILL = os.path.join(REPO_ROOT, "scripts", "vm-restore-drill.sh")
EMERGENCY = os.path.join(REPO_ROOT, "scripts", "emergency-recover.sh")
PORTABLE = os.path.join(REPO_ROOT, "scripts", "portable_restore_drill.py")
FIXTURE = os.path.join(REPO_ROOT, "scripts", "vm_restore_fixture.py")
SCRIPTS = os.path.join(REPO_ROOT, "scripts")
for _path in (SCRIPTS, os.path.join(REPO_ROOT, "tests"), REPO_ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import support  # noqa: E402
import vm_drill_fixture_probe as probe_helper  # noqa: E402
import vm_restore_fixture as fixture_module  # noqa: E402
from vps3xui import coordination as coord  # noqa: E402
from vps3xui import manifest as manifest_module  # noqa: E402
from vps3xui.errors import ToolError  # noqa: E402
from vps3xui.inventory import Inventory, compare, probe_spec  # noqa: E402
from vps3xui.plan import build_plan, verify_plan  # noqa: E402
from vps3xui.worker import finalizer  # noqa: E402
from vps3xui.worker.backup_worker import BackupWorker  # noqa: E402

IMAGE = "fixture.local/app@sha256:" + "0" * 64
HOST_KEY = "SHA256:fixture-drill-host-key"


def _env(**overrides):
    env = dict(os.environ)
    for key in ("VPS3XUI_DRILL_ROOT", "VPS3XUI_DRILL_IMAGE",
                "VPS3XUI_DRILL_CONFIRM", "VPS3XUI_DRILL_ID"):
        env.pop(key, None)
    env.update(overrides)
    return env


def _marked_root():
    root = tempfile.mkdtemp(prefix="drill-root-")
    with open(os.path.join(root, ".vps3xui-drill"), "w", encoding="utf-8") as handle:
        handle.write("disposable\n")
    return root


class VmRestoreDrillTest(unittest.TestCase):
    def test_drill_script_exists_and_is_executable(self):
        self.assertTrue(os.path.isfile(DRILL), DRILL)
        self.assertTrue(os.access(DRILL, os.X_OK), "drill must be executable")
        self.assertTrue(os.path.isfile(FIXTURE), FIXTURE)

    def test_emergency_recover_exists_and_is_executable(self):
        self.assertTrue(os.path.isfile(EMERGENCY), EMERGENCY)
        self.assertTrue(os.access(EMERGENCY, os.X_OK))

    def test_scripts_are_valid_bash_and_fixture_compiles(self):
        for script in (DRILL, EMERGENCY):
            result = subprocess.run(["bash", "-n", script], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        result = subprocess.run([sys.executable, "-m", "py_compile", FIXTURE],
                                capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_portable_drill_passes_locally(self):
        result = subprocess.run([sys.executable, PORTABLE], capture_output=True, cwd=REPO_ROOT)
        self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())
        self.assertIn(b"0 failures", result.stdout)

    def test_drill_reports_not_run_without_isolated_target(self):
        result = subprocess.run(["bash", DRILL], capture_output=True, env=_env())
        self.assertEqual(result.returncode, 3)
        self.assertIn(b"NOT RUN", result.stdout)
        self.assertIn(b"production-ready", result.stdout)

    def test_drill_refuses_slash_as_root(self):
        result = subprocess.run(["bash", DRILL], capture_output=True,
                                env=_env(VPS3XUI_DRILL_ROOT="/"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"refusing", result.stderr)

    def test_drill_refuses_system_directory_root(self):
        result = subprocess.run(["bash", DRILL], capture_output=True,
                                env=_env(VPS3XUI_DRILL_ROOT="/etc"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"refusing", result.stderr)

    def test_drill_refuses_relative_root(self):
        result = subprocess.run(["bash", DRILL], capture_output=True,
                                env=_env(VPS3XUI_DRILL_ROOT="relative/path"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"absolute", result.stderr)

    def test_drill_requires_disposable_marker(self):
        root = tempfile.mkdtemp(prefix="drill-root-")
        result = subprocess.run(["bash", DRILL], capture_output=True,
                                env=_env(VPS3XUI_DRILL_ROOT=root))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"disposable", result.stderr)

    def test_drill_refuses_non_empty_root(self):
        root = _marked_root()
        with open(os.path.join(root, "leftover"), "w", encoding="utf-8") as handle:
            handle.write("x\n")
        result = subprocess.run(["bash", DRILL], capture_output=True,
                                env=_env(VPS3XUI_DRILL_ROOT=root))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"not empty", result.stderr)

    def test_drill_requires_explicit_confirmation(self):
        root = _marked_root()
        result = subprocess.run(["bash", DRILL], capture_output=True,
                                env=_env(VPS3XUI_DRILL_ROOT=root,
                                         VPS3XUI_DRILL_IMAGE="fixture.local/app@sha256:" + "0" * 64))
        self.assertEqual(result.returncode, 3)
        self.assertIn(b"NOT RUN", result.stdout)
        self.assertIn(b"VPS3XUI_DRILL_CONFIRM=disposable", result.stdout)

    def test_drill_never_references_production_resources(self):
        with open(DRILL, "r", encoding="utf-8") as handle:
            script = handle.read()
        self.assertNotIn("llmproxy_chatgpt_auth", script)
        self.assertNotIn("VPS3XUI_DRILL_BACKUP", script)
        self.assertNotIn("VPS3XUI_DRILL_MANIFEST", script)
        self.assertIn("vm_restore_fixture.py", script)
        with open(FIXTURE, "r", encoding="utf-8") as handle:
            fixture = handle.read()
        self.assertIn("--pull=never", fixture)
        self.assertIn("vps3xui-drill", fixture)
        self.assertIn("refusing to overwrite existing path", fixture)

    def test_emergency_recover_refuses_without_apply(self):
        job_dir = tempfile.mkdtemp(prefix="emergency-")
        result = subprocess.run(["bash", EMERGENCY, job_dir], capture_output=True)
        self.assertEqual(result.returncode, 2)

    def test_emergency_recover_refuses_without_recorded_state(self):
        job_dir = tempfile.mkdtemp(prefix="emergency-")
        result = subprocess.run(["bash", EMERGENCY, job_dir, "--apply"], capture_output=True)
        self.assertEqual(result.returncode, 3)


FAKE_PREREQS = {
    "uname": "#!/bin/sh\necho Linux\n",
    "id": "#!/bin/sh\necho 0\n",
    "docker": ("#!/bin/sh\n"
               "case \"$1 $2\" in\n"
               "  \"image inspect\") printf '[{\"RepoDigests\":[\"%s\"]}]\\n' \"$3\" ;;\n"
               "  *) exit 1 ;;\n"
               "esac\n"),
    "systemctl": "#!/bin/sh\nexit 0\n",
    "systemd-run": "#!/bin/sh\nexit 0\n",
    "setfacl": "#!/bin/sh\nexit 0\n",
    "getfacl": "#!/bin/sh\nexit 0\n",
    "setfattr": "#!/bin/sh\nexit 0\n",
    "getfattr": "#!/bin/sh\nexit 0\n",
}


def _fake_prereq_bin(root):
    """A fake requisites directory so the shell reaches the evidence-dir logic.

    ``tar`` still delegates to the real tar for extraction but advertises GNU tar
    so the wrapper's GNU-tar prerequisite passes without touching a host.
    """
    real_tar = shutil.which("tar")
    if real_tar is None:
        return None
    bin_dir = os.path.join(root, "fakebin")
    os.makedirs(bin_dir)
    for name, body in FAKE_PREREQS.items():
        path = os.path.join(bin_dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(body)
        os.chmod(path, 0o755)
    tar_path = os.path.join(bin_dir, "tar")
    with open(tar_path, "w", encoding="utf-8") as handle:
        handle.write("#!/bin/sh\n"
                     "if [ \"$1\" = \"--version\" ]; then echo 'tar (GNU tar) 1.34'; exit 0; fi\n"
                     "exec %s \"$@\"\n" % real_tar)
    os.chmod(tar_path, 0o755)
    return bin_dir


class ShellEvidenceDirTest(unittest.TestCase):
    """R9 item 1: the wrapper must never write into an existing evidence dir."""

    def setUp(self):
        if shutil.which("bash") is None:
            self.skipTest("bash is required to exercise the drill wrapper")

    def _env(self, root, evidence, bin_dir):
        env = dict(os.environ)
        env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
        env.update({"VPS3XUI_DRILL_ROOT": root,
                    "VPS3XUI_DRILL_IMAGE": IMAGE,
                    "VPS3XUI_DRILL_CONFIRM": "disposable",
                    "VPS3XUI_DRILL_EVIDENCE": evidence,
                    "VPS3XUI_DRILL_ID": "t1"})
        return env

    def test_refuses_a_preexisting_evidence_dir_without_clobbering_sentinels(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)  # avoid the /var symlink on macOS
            bin_dir = _fake_prereq_bin(tmp)
            if bin_dir is None:
                self.skipTest("no real tar available to delegate to")
            root = os.path.join(tmp, "root")
            os.makedirs(root)
            with open(os.path.join(root, ".vps3xui-drill"), "w", encoding="utf-8") as handle:
                handle.write("disposable\n")
            evidence = os.path.join(tmp, "existing-evidence")
            os.makedirs(evidence)
            sentinels = {"fixture-plan.json": "SENTINEL-PLAN\n",
                         "cleanup.log": "SENTINEL-CLEANUP\n"}
            for name, text in sentinels.items():
                with open(os.path.join(evidence, name), "w", encoding="utf-8") as handle:
                    handle.write(text)
            result = subprocess.run(["bash", DRILL], env=self._env(root, evidence, bin_dir),
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            for name, text in sentinels.items():
                with open(os.path.join(evidence, name), "r", encoding="utf-8") as handle:
                    self.assertEqual(handle.read(), text, name)
            self.assertEqual(sorted(os.listdir(evidence)), sorted(sentinels))

    def test_a_fresh_evidence_dir_is_owned_by_this_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)  # avoid the /var symlink on macOS
            bin_dir = _fake_prereq_bin(tmp)
            if bin_dir is None:
                self.skipTest("no real tar available to delegate to")
            root = os.path.join(tmp, "root")
            os.makedirs(root)
            with open(os.path.join(root, ".vps3xui-drill"), "w", encoding="utf-8") as handle:
                handle.write("disposable\n")
            evidence = os.path.join(tmp, "evidence")
            result = subprocess.run(["bash", DRILL], env=self._env(root, evidence, bin_dir),
                                    capture_output=True, text=True)
            # The harness cannot execute on this non-Linux host, but the wrapper
            # must still have created and stamped the evidence dir itself.
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(os.path.isdir(evidence))
            self.assertTrue(os.path.isfile(
                os.path.join(evidence, ".vps3xui-drill-evidence-owner")))
            self.assertTrue(os.path.isfile(os.path.join(evidence, "cleanup.log")))
            self.assertTrue(os.path.isfile(os.path.join(evidence, "fixture-plan.json")))


def _fixture_mountpoint(names):
    return "/var/lib/docker/volumes/%s/_data" % names["volume"]


class FixtureManifestTrustTest(unittest.TestCase):
    """R9-B: the fixture's real systemd unit files must be digest-pinned.

    The R4 content probe (``probe_cron``) labels any unit file containing
    ``certbot`` as ``source: systemd`` and ``compare`` refuses an unpinned
    entry, so the fixture's own ``certbot.service``/``certbot.timer`` stubs must
    be pinned or *every* job fails before it can start. These tests run the real
    ``probe_cron`` against synthetic, remapped host content and compare the
    result with the generated fixture manifest - never a fabricated cron list.
    """

    def _manifest(self, names, mountpoint):
        data = fixture_module.build_manifest(names, IMAGE, mountpoint,
                                             fixture_module.fixture_files(names, IMAGE))
        return data

    def test_real_probe_cron_observes_the_pinned_fixture_units_and_compare_accepts(self):
        names = fixture_module.fixture_identity("trust1")
        mountpoint = _fixture_mountpoint(names)
        with tempfile.TemporaryDirectory() as root:
            probe_helper.write_unit_files(root, names, IMAGE)
            cron = probe_helper.cron_observation(root)
        self.assertTrue(cron, "the real probe_cron found no Certbot scheduler content")
        paths = {(entry["path"], entry["source"]) for entry in cron}
        self.assertIn(("/usr/lib/systemd/system/certbot.service", "systemd"), paths)
        self.assertIn(("/usr/lib/systemd/system/certbot.timer", "systemd"), paths)
        manifest = manifest_module.from_object(self._manifest(names, mountpoint))
        inventory = Inventory.from_probe(
            probe_helper.fixture_probe(names, IMAGE, mountpoint, cron_certbot=cron))
        report = compare(manifest, inventory)
        self.assertTrue(report.ok, [item.to_object() for item in report.blocking])

    def test_unpinned_fixture_unit_still_blocks_the_plan(self):
        names = fixture_module.fixture_identity("trust1")
        mountpoint = _fixture_mountpoint(names)
        with tempfile.TemporaryDirectory() as root:
            probe_helper.write_unit_files(root, names, IMAGE)
            cron = probe_helper.cron_observation(root)
        data = self._manifest(names, mountpoint)
        data["trusted_files"] = [
            item for item in data["trusted_files"]
            if item["path"] not in ("/usr/lib/systemd/system/certbot.service",
                                    "/usr/lib/systemd/system/certbot.timer")
        ]
        manifest = manifest_module.from_object(data)
        inventory = Inventory.from_probe(
            probe_helper.fixture_probe(names, IMAGE, mountpoint, cron_certbot=cron))
        report = compare(manifest, inventory)
        self.assertFalse(report.ok)
        self.assertIn("E_CONFLICT",
                      [item.to_object()["code"] for item in report.blocking])

    def test_renamed_certbot_scheduler_is_refused(self):
        names = fixture_module.fixture_identity("trust1")
        mountpoint = _fixture_mountpoint(names)
        with tempfile.TemporaryDirectory() as root:
            probe_helper.write_unit_files(root, names, IMAGE)
            cron = probe_helper.cron_observation(root, extra_unit="certbot-renamed.service")
        manifest = manifest_module.from_object(self._manifest(names, mountpoint))
        inventory = Inventory.from_probe(
            probe_helper.fixture_probe(names, IMAGE, mountpoint, cron_certbot=cron))
        report = compare(manifest, inventory)
        self.assertFalse(report.ok)
        self.assertTrue(any(item.to_object()["resource"]
                            == "systemd:/etc/systemd/system/certbot-renamed.service"
                            for item in report.blocking))


class CertbotTriggerPrecedenceTest(unittest.TestCase):
    """F6: the fixture's Certbot triggers must sit below the runtime mask.

    The reviewed worker masks the trigger units with ``systemctl mask --runtime``
    (which writes ``/run/systemd/system``) and then refuses unless the effective
    ``UnitFileState`` is ``masked``/``masked-runtime``. systemd loads ``/etc``
    before ``/run`` before the vendor directories, so a fixture trigger in
    ``/etc/systemd/system`` would shadow the runtime mask and the success job
    would fail closed before ``copying``. These tests model that precedence
    directly instead of assuming every mask takes effect.
    """

    def _manifest(self, names, mountpoint):
        return fixture_module.build_manifest(names, IMAGE, mountpoint,
                                             fixture_module.fixture_files(names, IMAGE))

    def test_fixture_triggers_are_vendored_and_cleanup_units_stay_in_etc(self):
        names = fixture_module.fixture_identity("preced1")
        files = {item["path"] for item in fixture_module.fixture_files(names, IMAGE)}
        self.assertIn("/usr/lib/systemd/system/certbot.service", files)
        self.assertIn("/usr/lib/systemd/system/certbot.timer", files)
        self.assertNotIn("/etc/systemd/system/certbot.service", files)
        self.assertNotIn("/etc/systemd/system/certbot.timer", files)
        # The cleanup automation and the drop-in stay under /etc per manifest.
        for unit in fixture_module.SYSTEMD_UNITS:
            self.assertIn("/etc/systemd/system/%s" % unit, files)
        self.assertIn("/etc/systemd/system/certbot.service.d/http01-cleanup.conf", files)

    def test_trusted_pins_cover_the_vendored_triggers_exactly(self):
        names = fixture_module.fixture_identity("preced1")
        mountpoint = _fixture_mountpoint(names)
        pinned = {item["path"] for item in self._manifest(names, mountpoint)["trusted_files"]}
        self.assertIn("/usr/lib/systemd/system/certbot.service", pinned)
        self.assertIn("/usr/lib/systemd/system/certbot.timer", pinned)
        self.assertNotIn("/etc/systemd/system/certbot.service", pinned)
        self.assertNotIn("/etc/systemd/system/certbot.timer", pinned)

    def test_runtime_mask_wins_over_the_vendor_trigger(self):
        names = fixture_module.fixture_identity("preced1")
        with tempfile.TemporaryDirectory() as root:
            probe_helper.write_unit_files(root, names, IMAGE)
            run_dir = os.path.join(root, "run/systemd/system")
            os.makedirs(run_dir, exist_ok=True)
            for unit in ("certbot.service", "certbot.timer"):
                # The fixture trigger is vendored, so the mask written to /run
                # is the winning fragment and the worker's check would pass.
                self.assertTrue(probe_helper.runtime_mask_is_effective(root, unit), unit)
                os.symlink("/dev/null", os.path.join(run_dir, unit))
                self.assertEqual(probe_helper.unit_fragment_path(root, unit),
                                 "/run/systemd/system/" + unit)
                os.unlink(os.path.join(run_dir, unit))

    def test_etc_override_shadows_the_runtime_mask(self):
        names = fixture_module.fixture_identity("preced1")
        with tempfile.TemporaryDirectory() as root:
            probe_helper.write_unit_files(root, names, IMAGE)
            run_dir = os.path.join(root, "run/systemd/system")
            etc_dir = os.path.join(root, "etc/systemd/system")
            os.makedirs(run_dir, exist_ok=True)
            os.makedirs(etc_dir, exist_ok=True)
            os.symlink("/dev/null", os.path.join(run_dir, "certbot.timer"))
            with open(os.path.join(etc_dir, "certbot.timer"), "w", encoding="utf-8") as handle:
                handle.write("[Unit]\nDescription=certbot local override\n")
            # /etc outranks /run: the runtime mask is ineffective and systemd
            # keeps loading the local override, so the worker must fail closed.
            self.assertFalse(probe_helper.runtime_mask_is_effective(root, "certbot.timer"))
            self.assertEqual(probe_helper.unit_fragment_path(root, "certbot.timer"),
                             "/etc/systemd/system/certbot.timer")

    def test_etc_certbot_override_is_refused_by_the_plan(self):
        names = fixture_module.fixture_identity("preced1")
        mountpoint = _fixture_mountpoint(names)
        with tempfile.TemporaryDirectory() as root:
            probe_helper.write_unit_files(root, names, IMAGE)
            override = os.path.join(root, "etc/systemd/system/certbot.timer")
            os.makedirs(os.path.dirname(override), exist_ok=True)
            with open(override, "w", encoding="utf-8") as handle:
                handle.write("[Unit]\nDescription=certbot local override\n")
            cron = probe_helper.cron_observation(root)
        manifest = manifest_module.from_object(self._manifest(names, mountpoint))
        inventory = Inventory.from_probe(
            probe_helper.fixture_probe(names, IMAGE, mountpoint, cron_certbot=cron))
        report = compare(manifest, inventory)
        self.assertFalse(report.ok)
        self.assertTrue(any(item.to_object()["resource"]
                            == "systemd:/etc/systemd/system/certbot.timer"
                            for item in report.blocking))


class VendorAliasTrustTest(unittest.TestCase):
    """F6 correction: the usrmerge ``/lib -> usr/lib`` alias must not block.

    On a usrmerge host the installed vendor trigger is readable both at
    ``/usr/lib/systemd/system/<unit>`` and at ``/lib/systemd/system/<unit>``, and
    the shipped ``probe_cron`` reports both paths. The fixture derives an *exact*
    extra pin for the alias only when it resolves to the very same file this run
    installed; a distinct or foreign ``/lib`` file is never trusted and the plan
    fails closed.
    """

    def _host(self, root):
        return fixture_module.Host(root=root, platform="linux", euid=0)

    def _manifest(self, names, alias_pins=None):
        return manifest_module.from_object(fixture_module.build_manifest(
            names, IMAGE, _fixture_mountpoint(names),
            fixture_module.fixture_files(names, IMAGE), extra_trusted=alias_pins))

    def _inventory(self, names, root, alias_pins=None):
        cron = probe_helper.cron_observation(root)
        observation = probe_helper.fixture_probe(
            names, IMAGE, _fixture_mountpoint(names), cron_certbot=cron,
            alias_pins=alias_pins)
        return Inventory.from_probe(observation), cron

    def test_usrmerge_alias_is_pinned_and_the_plan_builds(self):
        names = fixture_module.fixture_identity("alias1")
        with tempfile.TemporaryDirectory() as root:
            probe_helper.write_unit_files(root, names, IMAGE)
            os.symlink("usr/lib", os.path.join(root, "lib"))
            alias = fixture_module.trusted_alias_pins(self._host(root), names, IMAGE)
            self.assertEqual({item["path"] for item in alias},
                             {"/lib/systemd/system/certbot.service",
                              "/lib/systemd/system/certbot.timer"})
            manifest = self._manifest(names, alias)
            pinned = set(manifest.trusted_file_paths())
            self.assertTrue({item["path"] for item in alias} <= pinned)
            inventory, cron = self._inventory(names, root, alias)
            observed = {entry["path"] for entry in cron}
            self.assertIn("/usr/lib/systemd/system/certbot.timer", observed)
            self.assertIn("/lib/systemd/system/certbot.timer", observed)
            report = compare(manifest, inventory)
            self.assertTrue(report.ok, [item.to_object() for item in report.blocking])
            plan = build_plan(manifest, inventory, HOST_KEY)
            self.assertTrue(plan["identity"])

    def test_seed_job_writes_the_runtime_alias_pins(self):
        names = fixture_module.fixture_identity("alias2")
        tmp = tempfile.mkdtemp(prefix="drill-alias-")
        self.addCleanup(shutil.rmtree, tmp, True)
        probe_helper.write_unit_files(tmp, names, IMAGE)
        os.symlink("usr/lib", os.path.join(tmp, "lib"))
        host = self._host(tmp)
        ledger = fixture_module.Ledger("/var/lib/%s.ledger.json" % names["prefix"], host,
                                       names["id"], names["prefix"])
        ledger.begin()
        alias = fixture_module.trusted_alias_pins(host, names, IMAGE)
        inventory, _cron = self._inventory(names, tmp, alias)
        fixture_module.seed_job(host, ledger, names, IMAGE, REPO_ROOT,
                                _fixture_mountpoint(names), names["job_dir"],
                                probe=lambda spec: inventory)
        written = manifest_module.load(
            host.local(os.path.join(names["job_dir"], "manifest.json")))
        pinned = set(written.trusted_file_paths())
        self.assertIn("/lib/systemd/system/certbot.service", pinned)
        self.assertIn("/lib/systemd/system/certbot.timer", pinned)

    def test_distinct_lib_copy_is_not_trusted_and_blocks(self):
        names = fixture_module.fixture_identity("alias3")
        with tempfile.TemporaryDirectory() as root:
            probe_helper.write_unit_files(root, names, IMAGE)
            # /lib/systemd/system is a *distinct* directory holding a byte copy
            # with a different inode: not the file this run installed.
            lib_dir = os.path.join(root, "lib/systemd/system")
            os.makedirs(lib_dir)
            shutil.copyfile(os.path.join(root, "usr/lib/systemd/system/certbot.timer"),
                            os.path.join(lib_dir, "certbot.timer"))
            self.assertEqual(
                fixture_module.trusted_alias_pins(self._host(root), names, IMAGE), [])
            manifest = self._manifest(names)
            self.assertNotIn("/lib/systemd/system/certbot.timer",
                             set(manifest.trusted_file_paths()))
            inventory, cron = self._inventory(names, root)
            self.assertIn("/lib/systemd/system/certbot.timer",
                          {entry["path"] for entry in cron})
            report = compare(manifest, inventory)
            self.assertFalse(report.ok)
            self.assertTrue(any(item.to_object()["resource"]
                                == "systemd:/lib/systemd/system/certbot.timer"
                                for item in report.blocking))

    def test_foreign_symlinked_lib_unit_is_not_trusted(self):
        names = fixture_module.fixture_identity("alias4")
        with tempfile.TemporaryDirectory() as root:
            probe_helper.write_unit_files(root, names, IMAGE)
            foreign = os.path.join(root, "srv/foreign-certbot.timer")
            os.makedirs(os.path.dirname(foreign))
            with open(foreign, "w", encoding="utf-8") as handle:
                handle.write("[Unit]\nDescription=foreign certbot scheduler\n")
            os.makedirs(os.path.join(root, "lib/systemd/system"))
            os.symlink(foreign, os.path.join(root, "lib/systemd/system/certbot.timer"))
            self.assertEqual(
                fixture_module.trusted_alias_pins(self._host(root), names, IMAGE), [])
            manifest = self._manifest(names)
            inventory, cron = self._inventory(names, root)
            self.assertIn("/lib/systemd/system/certbot.timer",
                          {entry["path"] for entry in cron})
            report = compare(manifest, inventory)
            self.assertFalse(report.ok)
            self.assertNotIn("/lib/systemd/system/certbot.timer",
                             set(manifest.trusted_file_paths()))

    def test_tampered_lib_alias_content_is_not_trusted(self):
        names = fixture_module.fixture_identity("alias5")
        with tempfile.TemporaryDirectory() as root:
            probe_helper.write_unit_files(root, names, IMAGE)
            lib_dir = os.path.join(root, "lib/systemd/system")
            os.makedirs(lib_dir)
            with open(os.path.join(lib_dir, "certbot.timer"), "w",
                      encoding="utf-8") as handle:
                handle.write("[Unit]\nDescription=tampered certbot alias\n")
            self.assertEqual(
                fixture_module.trusted_alias_pins(self._host(root), names, IMAGE), [])
            manifest = self._manifest(names)
            self.assertNotIn("/lib/systemd/system/certbot.timer",
                             set(manifest.trusted_file_paths()))
            inventory, cron = self._inventory(names, root)
            self.assertIn("/lib/systemd/system/certbot.timer",
                          {entry["path"] for entry in cron})
            report = compare(manifest, inventory)
            self.assertFalse(report.ok)


class PlanFreshnessAcrossLifecycleTest(unittest.TestCase):
    """R9-C: every drill job must re-probe and rebuild its own real plan.

    A plan cloned from the template job goes stale as soon as the drill creates
    its restored container (or a unit state changes), because
    ``inventory_structural_digest`` covers every container. This drives the real
    ``seed_job``/``create_owned_job``, the real coordinator lock and the real
    ``BackupWorker`` preflight across a sequential lifecycle, so a cloned plan
    would raise ``E_PLAN_STALE`` from the real ``verify_plan``.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="drill-plan-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.names = fixture_module.fixture_identity("plan1")
        self.image = IMAGE
        self.mountpoint = _fixture_mountpoint(self.names)
        self.host = fixture_module.Host(root=self.tmp, platform="linux", euid=0)
        self.ledger_path = "/var/lib/%s.ledger.json" % self.names["prefix"]
        self.ledger = fixture_module.Ledger(self.ledger_path, self.host,
                                            self.names["id"], self.names["prefix"])
        self.ledger.begin()
        self._systems = 0
        data = fixture_module.build_manifest(self.names, self.image, self.mountpoint,
                                             fixture_module.fixture_files(self.names, self.image))
        self.manifest = manifest_module.from_object(data)

    def _inventory(self, restored=None, unit_states=None):
        observation = probe_helper.fixture_probe(self.names, self.image, self.mountpoint,
                                                 restored=restored,
                                                 unit_states=unit_states)
        return Inventory.from_probe(observation)

    def _system(self, inventory):
        self._systems += 1
        system = support.SyntheticSystem(self.manifest,
                                         os.path.join(self.tmp, "system-%d" % self._systems))
        system.machine = inventory.machine_id
        system.containers = {
            name: {"id": item.get("id"), "running": bool(item.get("running"))}
            for name, item in inventory.containers.items()
        }
        system.lease_active = False
        return system

    def _preflight(self, job_dir, inventory):
        local_job = self.host.local(job_dir)
        job_id = os.path.basename(local_job)
        root = coord.root_for_job_dir(local_job)
        coord.assert_owned(root, job_id)
        worker = BackupWorker(self._system(inventory), local_job, self.manifest,
                              probe=lambda spec: inventory)
        with coord.stack_lock(root, wait_seconds=0):
            coord.assert_owned(root, job_id)
            coord.assert_no_blocking(root, ignoring=job_id)
            worker._preflight()
        return worker

    def _finalize(self, job_dir, inventory):
        finalizer.recover(self.host.local(job_dir), self._system(inventory),
                          self.manifest, service_result=None, explicit=False)

    def test_sequential_jobs_rebuild_plans_and_accept_the_changed_host(self):
        inventory0 = self._inventory()
        template = fixture_module.seed_job(self.host, self.ledger, self.names,
                                           self.image, REPO_ROOT, self.mountpoint,
                                           self.names["job_dir"],
                                           probe=lambda spec: inventory0)
        self._preflight(self.names["job_dir"], inventory0)
        self._finalize(self.names["job_dir"], inventory0)

        # The drill's successful restore creates a new stopped container that is
        # absent from the template plan: the old cloned plan is now stale.
        restored = {"id": "d" * 64, "name": self.names["restored_container"]}
        inventory1 = self._inventory(restored=restored)
        with self.assertRaises(ToolError) as caught:
            verify_plan(template["plan"], self.manifest, inventory1, HOST_KEY)
        self.assertEqual(caught.exception.code, "E_PLAN_STALE")

        second = fixture_module.create_owned_job(
            self.ledger_path, "%s-kill" % self.names["id"], self.names["job_dir"],
            self.image, REPO_ROOT, self.mountpoint, self.names, self.host,
            probe=lambda spec: inventory1)
        self.assertNotEqual(second["plan"]["identity"], template["plan"]["identity"])
        request = json.loads(self.host.read_text(
            os.path.join(second["job_dir"], "request.json")))
        reservation = json.loads(self.host.read_text(
            os.path.join(second["job_dir"], "reservation.json")))
        self.assertEqual(request["plan_digest"], second["plan"]["identity"])
        self.assertEqual(reservation["plan_digest"], second["plan"]["identity"])
        self.assertEqual(request["stop_containers"], second["plan"]["stop_containers"])
        self._preflight(second["job_dir"], inventory1)
        self._finalize(second["job_dir"], inventory1)

        # A later unit-state change must likewise force a fresh plan.
        inventory2 = self._inventory(restored=restored, unit_states={
            "certbot.timer": {"load_state": "loaded", "active_state": "inactive",
                              "unit_file_state": "disabled"}})
        with self.assertRaises(ToolError) as caught:
            verify_plan(second["plan"], self.manifest, inventory2, HOST_KEY)
        self.assertEqual(caught.exception.code, "E_PLAN_STALE")
        third = fixture_module.create_owned_job(
            self.ledger_path, "%s-timeout" % self.names["id"], self.names["job_dir"],
            self.image, REPO_ROOT, self.mountpoint, self.names, self.host,
            probe=lambda spec: inventory2)
        self._preflight(third["job_dir"], inventory2)

    def test_create_owned_job_refuses_to_reuse_an_existing_job(self):
        inventory = self._inventory()
        fixture_module.seed_job(self.host, self.ledger, self.names, self.image,
                                REPO_ROOT, self.mountpoint, self.names["job_dir"],
                                probe=lambda spec: inventory)
        with self.assertRaises(SystemExit):
            fixture_module.create_owned_job(
                self.ledger_path, os.path.basename(self.names["job_dir"]),
                self.names["job_dir"], self.image, REPO_ROOT, self.mountpoint,
                self.names, self.host, probe=lambda spec: inventory)


if __name__ == "__main__":
    unittest.main()
