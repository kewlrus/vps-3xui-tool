#!/usr/bin/env bash
# Isolated, self-contained restore drill for a vps3xui P0 backup.
#
# The *portable* part (synthetic fixtures, no Docker/systemd/network) always runs
# locally via scripts/portable_restore_drill.py. The *VM* part needs an explicitly
# disposable Linux host; it creates its own synthetic fixture through
# scripts/vm_restore_fixture.py and drives the real shipped entrypoints through
# scripts/vm_drill.py.
#
# The VM part is deliberately fail-closed:
#   * unique vps3xui-drill-<id> fixture volume/unit/job paths, one synthetic
#     Fail2ban writable-layer container with the literal reviewed name, and a
#     refusal to run when any production-like container already exists;
#   * one preloaded test image supplied by the operator, always used with
#     --pull=never (no downloads, no production image, no OAuth/secrets);
#   * the actual shipped bin/vps3xui-worker and bin/vps3xui-finalizer argv, with
#     the ExecStopPost command line escaped for systemd;
#   * independent synthetic jobs for success+restore, SIGKILL during copying,
#     actual RuntimeMaxSec expiry during copying, and loss of the submitting
#     parent while the worker stays managed by systemd;
#   * restoration of the successful worker's actual archives into ledger-owned
#     isolated destinations, including the two real docker-cp Fail2ban artifacts
#     into a created-stopped container, and a never-applied UFW reference.
#
# Required environment for the VM part:
#   VPS3XUI_DRILL_ROOT      disposable scratch root, absolute, empty, not a
#                           system directory, marked with .vps3xui-drill
#   VPS3XUI_DRILL_IMAGE     preloaded non-production test image, complete
#                           repo@sha256:... ref with a matching RepoDigest
#   VPS3XUI_DRILL_CONFIRM   must be exactly "disposable"
#
# Optional:
#   VPS3XUI_DRILL_ID        unique fixture identifier (defaults to <epoch>-<pid>)
#   VPS3XUI_DRILL_RELEASE   release dir with the vps3xui package (defaults to the
#                           repository root next to this script)
#   VPS3XUI_DRILL_EVIDENCE  evidence dir (defaults to <drill root>/evidence;
#                           it must be a genuinely new path - the wrapper creates
#                           it exclusively and never writes into an existing dir)
#   VPS3XUI_DRILL_WAIT      seconds to wait for a copying barrier (default 180)
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }
note() { echo "  - $*"; }
here="$(cd "$(dirname "$0")" && pwd)"
release_dir="${VPS3XUI_DRILL_RELEASE:-$(cd "$here/.." && pwd)}"
fixture_py="$here/vm_restore_fixture.py"
drill_py="$here/vm_drill.py"

# --- portable part: always runnable, no VM required -------------------------
echo "restore drill: portable checks (no VM required)"
[ -f "$fixture_py" ] || fail "the fixture generator is missing: $fixture_py"
[ -f "$drill_py" ] || fail "the VM harness is missing: $drill_py"
[ -f "$here/portable_restore_drill.py" ] || fail "the portable drill is missing"
PYTHONPATH="$release_dir" python3 "$here/portable_restore_drill.py" || \
  fail "portable restore drill failed"

# --- disposable-root guards run before any NOT RUN decision -----------------
drill_root="${VPS3XUI_DRILL_ROOT:-}"
if [ -n "$drill_root" ]; then
  [ "$drill_root" != "/" ] || fail "refusing to use / as the drill root"
  case "$drill_root" in
    /opt|/etc|/var|/root|/home|/usr|/boot|/bin|/sbin|/lib|/lib64|/proc|/sys|/dev)
      fail "refusing to use a system directory as the drill root: $drill_root" ;;
  esac
  case "$drill_root" in
    /*) ;;
    *) fail "the drill root must be an absolute path" ;;
  esac
  [ -d "$drill_root" ] || fail "drill root does not exist: $drill_root"
  [ -f "$drill_root/.vps3xui-drill" ] || \
    fail "drill root is not marked disposable (.vps3xui-drill marker missing)"
  leftovers="$(ls -A "$drill_root" 2>/dev/null | grep -v '^\.vps3xui-drill$' || true)"
  [ -z "$leftovers" ] || fail "drill root is not empty; use a fresh disposable root"
fi

# --- VM prerequisites: report NOT RUN, never a pass -------------------------
missing=()
[ -n "$drill_root" ] || missing+=("VPS3XUI_DRILL_ROOT")
[ -n "${VPS3XUI_DRILL_IMAGE:-}" ] || missing+=("VPS3XUI_DRILL_IMAGE")
[ "${VPS3XUI_DRILL_CONFIRM:-}" = "disposable" ] || missing+=("VPS3XUI_DRILL_CONFIRM=disposable")
if [ "${#missing[@]}" -gt 0 ] || [ "$(uname -s)" != "Linux" ]; then
  echo "NOT RUN: the VM part of the restore drill requires an explicitly disposable Linux host."
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "         missing: ${missing[*]}"
  else
    echo "         this host is $(uname -s), not Linux"
  fi
  echo "         It also requires GNU tar, Docker with the Compose plugin, systemd, root,"
  echo "         setfacl/getfacl, setfattr/getfattr and a preloaded test image supplied with"
  echo "         VPS3XUI_DRILL_IMAGE. P0 is not production-ready until this drill passes and"
  echo "         its run is recorded."
  exit 3
fi

[ "$(id -u)" = "0" ] || fail "the VM drill must run as root on the disposable host"
for tool in docker systemd-run systemctl python3 tar setfacl getfacl setfattr getfattr; do
  command -v "$tool" >/dev/null || fail "$tool is required on the disposable host"
done
tar --version | grep -q 'GNU tar' || fail "GNU tar is required"

image="$VPS3XUI_DRILL_IMAGE"
case "$image" in
  *@sha256:*) ;;
  *) fail "VPS3XUI_DRILL_IMAGE must be a complete repo@sha256:... reference" ;;
esac
docker image inspect "$image" >/dev/null 2>&1 || \
  fail "the test image is not preloaded locally; this drill never pulls images"
python3 - "$image" <<'PY' || fail "the preloaded image must have a matching repo digest"
import json, subprocess, sys
image = sys.argv[1]
out = subprocess.run(["docker", "image", "inspect", image],
                     stdout=subprocess.PIPE).stdout.decode("utf-8")
info = json.loads(out)[0]
if image not in (info.get("RepoDigests") or []):
    sys.stderr.write("image %s has no matching RepoDigest\n" % image)
    raise SystemExit(1)
PY
case "$image" in
  *llmproxy*|*3x-ui*|*3xui*|*litellm*)
    fail "refusing to use what looks like a production image: $image" ;;
esac

drill_id="${VPS3XUI_DRILL_ID:-$(date +%s)-$$}"
plan_json="$(PYTHONPATH="$release_dir" python3 "$fixture_py" --plan \
  --identifier "$drill_id" --image "$image")" || \
  fail "the synthetic fixture plan could not be built"
prefix="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["names"]["prefix"])' \
  "$plan_json")"
ledger="$drill_root/$prefix.ledger.json"

evidence_dir="${VPS3XUI_DRILL_EVIDENCE:-$drill_root/evidence}"
case "$evidence_dir" in
  /*) ;;
  *) fail "VPS3XUI_DRILL_EVIDENCE must be an absolute path" ;;
esac

# Create the evidence directory *exclusively* and stamp this run's owner marker
# BEFORE anything is written into it. A pre-existing directory, a symlinked
# ancestor, or a path overlapping a prospective fixture/drill-owned tree is
# refused here, so no earlier fixture-plan.json/cleanup.log can be clobbered.
if ! evidence_marker="$(PYTHONPATH="$release_dir" python3 "$drill_py" --prepare-evidence \
      --evidence-dir "$evidence_dir" --drill-root "$drill_root" \
      --identifier "$drill_id" --image "$image" --ledger "$ledger")"; then
  fail "the evidence dir must be a genuinely new directory (refusal above)"
fi
export VPS3XUI_DRILL_EVIDENCE_MARKER="$evidence_marker"
evidence_owned=1

cleanup() {
  local status=$?
  local output=""
  # The fixture records every resource it actually created in a durable ledger
  # and removes only those, after re-checking filesystem identity, digests,
  # Docker full ids/labels/tokens and systemd launch tokens. Evidence is stored
  # outside the ledger-owned trees and is never removed by this cleanup.
  if [ -f "$ledger" ]; then
    if ! output="$(python3 "$fixture_py" --cleanup --ledger "$ledger" 2>&1)"; then
      echo "INCOMPLETE: fixture cleanup could not remove every owned resource;" >&2
      echo "            the ownership ledger was retained at $ledger" >&2
      if [ -n "$output" ]; then
        echo "            $output" >&2
      fi
      echo "            retry: python3 $fixture_py --cleanup --ledger $ledger" >&2
      if [ "$status" -eq 0 ]; then
        status=4
      fi
    fi
  fi
  # Only write cleanup.log when THIS run created the evidence directory; a
  # refusal before the exclusive mkdir must never touch an existing directory.
  if [ "${evidence_owned:-0}" = "1" ] && [ -n "${evidence_dir:-}" ]; then
    printf '%s\n' "$output" > "$evidence_dir/cleanup.log" 2>/dev/null || true
  fi
  exit "$status"
}
trap cleanup EXIT

echo "restore drill: starting the VM harness for $prefix"
printf '%s\n' "$plan_json" > "$evidence_dir/fixture-plan.json"
PYTHONPATH="$release_dir${PYTHONPATH:+:$PYTHONPATH}" \
VPS3XUI_DRILL_WAIT="${VPS3XUI_DRILL_WAIT:-180}" \
python3 "$drill_py" \
  --release-dir "$release_dir" \
  --drill-root "$drill_root" \
  --image "$image" \
  --identifier "$drill_id" \
  --ledger "$ledger" \
  --evidence-dir "$evidence_dir"

echo
echo "restore drill complete: VM checks passed"
echo "evidence retained at $evidence_dir"
echo "record this run in docs/agent-work/p0/worker-report.md"
exit 0
