#!/usr/bin/env bash
# Emergency recovery helper for a vps3xui backup job.
#
# Manual fallback ONLY. The preferred path is `vps3xui job recover`, which runs
# the pinned, idempotent finalizer. This script exists so an operator with
# independent SSH access can restore the recorded containers if systemd or the
# tool is unavailable. It never publishes COMPLETE and never starts a container
# that was not recorded as originally running.
#
# Usage: emergency-recover.sh JOB_DIR --apply
set -euo pipefail

usage() {
  echo "usage: $0 JOB_DIR --apply" >&2
  exit 2
}

[ "$#" -ge 1 ] || usage
job_dir="$1"
shift
apply=0
for arg in "$@"; do
  case "$arg" in
    --apply) apply=1 ;;
    *) usage ;;
  esac
done

if [ "$apply" -ne 1 ]; then
  echo "refusing to act without --apply" >&2
  exit 2
fi

state_file="$job_dir/initial-state.json"
if [ ! -f "$state_file" ]; then
  echo "no recorded original state in $job_dir; nothing safe to do" >&2
  exit 3
fi

python3 - "$state_file" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    state = json.load(handle)

recorded = state.get("stop_containers") or []
if not recorded:
    print("no containers were recorded as originally running")
else:
    print("containers to restore (in manifest order):")
    for item in recorded:
        print("  %s %s" % (item.get("name"), item.get("id")))
    print(" ".join(item["id"] for item in recorded if item.get("id")))
PY

ids=$(python3 - "$state_file" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    state = json.load(handle)
print(" ".join(item["id"] for item in (state.get("stop_containers") or []) if item.get("id")))
PY
)

if [ -n "$ids" ]; then
  # shellcheck disable=SC2086
  docker start $ids
fi

certbot_state=$(python3 - "$state_file" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    state = json.load(handle)
print("yes" if state.get("certbot") is not None else "no")
PY
)

if [ "$certbot_state" = "yes" ]; then
  echo "Certbot trigger state was recorded; restore it with 'vps3xui job recover' on the host."
fi

echo "emergency recovery attempted; verify with 'vps3xui job status' and 'backup verify'"
