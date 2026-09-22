# P0 functionality audit

Date: 2026-09-23. Requested by the user after reading handoff.md.

Verdict: the P0 command surface is implemented and local checks pass after
correcting the fetch destination defect found during this audit. Overall P0
acceptance remains open: the real Linux restore drill has not run. No production
access, deployment, package installation or credential changes were performed.

## Finding corrected

`backup fetch` resolved the destination with `realpath()` before checking for a
symlink. This erased the evidence needed by both its explicit check and
`require_private_dir`, allowing a fetch to write to a redirected location and
change that directory's permissions. Existing tests did not cover the CLI path.

The destination now retains its components through validation (`abspath`), so
the existing no-symlink directory helper can reject unsafe ancestors as well as
the final component. The regression test covers an existing directory link, a
dangling link, a link with a trailing slash and a symlinked ancestor. It checks
refusal, untouched target contents/permissions and absence of partial artifacts.
All four cases failed before the fix and pass after it.

Implementation: `vps3xui/backup.py:run_fetch`.
Regression: `tests/unit/test_cli_flow.py:test_fetch_refuses_symlink_destinations_before_writing`.
Before-fix evidence: `evidence/audit-fetch-before.log`.

## Contract coverage

Scope: design sections 3-9 and P0 in section 14; the original P0 execution
contract, F1-F7 reports, current source and executable local tests were checked.

| P0 requirement | Implementation and local evidence | Status |
| --- | --- | --- |
| Read-only inspect, strict inventory, drift and trust checks | cli, probe, inventory, manifest; inventory/probe/manifest/SSH tests | Implemented; local PASS |
| Expiring source plan bound to host, manifest and inventory | plan, backup.run_plan; plan tests and worker preflight tests | Implemented; local PASS |
| Durable request IDs, retry, conflict and exclusive stack ownership | jobs, coordination, remote_ops; jobs/remote_ops/launch/lock-handoff tests | Implemented; local PASS |
| Autonomous bounded backup and independent finalizer/recover | backup_worker, finalizer, systemd launcher; worker/finalizer tests | Implemented; local PASS; real Linux pending |
| Certbot lease/race/scheduler protection and exact source recovery | inventory, probe, worker/system; at-scheduler, worker and recovery tests | Implemented; local PASS; production trust unapproved |
| Exact artifacts, metadata, sums, safe archives and honest COMPLETE | verify, archive, metadata, completion reconciliation; archive/verify/completion tests | Implemented; local PASS |
| Source and portable verify, including a fresh client | backup.run_verify_job/run_verify_directory; CLI and 19 fresh-client tests | Implemented; local PASS |
| Controlled fetch into a protected destination | backup.run_fetch; CLI flow, file safety and new symlink regression | Implemented; local PASS after correction |
| One-object JSON, safe errors and secret canaries | cli/errors and adapter boundaries; CLI/adapter/worker tests | Implemented; local PASS |
| Isolated restore procedure and failure scenarios | portable_restore_drill, vm_drill and owned fixture/cleanup harness | Procedure implemented; portable PASS; Linux NOT RUN |

P1 restore prepare/stage/activate, DNS cutover, retention and boot recovery are
outside this P0 contract. They are not missing P0 commands.

## Verification

Python 3.9, standard library; `PYTHONPATH=tests:.` and
`PYTHONPYCACHEPREFIX=/private/tmp/vps3xui-audit-pycache` for Python checks.

- Baseline: `python3 -m unittest discover -s tests` passed 580 tests.
- Final tree: the same command passed 581 tests, exit 0 (27.104s).
  Evidence: `evidence/audit-unit-tests.log`.
- New regression alone passes after the fix; four subcases failed before it.
- `python3 scripts/portable_restore_drill.py`: 11 checks PASS, zero failures;
  GNU tar metadata round-trip NOT RUN because GNU tar is unavailable locally.
- `python3 docs/agent-work/p0/evidence/resume_probes.py`: R2-R8 all PASS.
- `python3 -m compileall -q vps3xui bin tests scripts`: PASS after the code fix.
- `bin/vps3xui --help`: PASS. This entrypoint is a shell wrapper, not a Python file.
- Tracked whitespace check excluding `.DS_Store`: PASS.

The standalone portable/probe runs preceded the fetch-only correction; the final
full suite includes the portable drill and all existing regression tests.

## Remaining acceptance limit

The design requires actual restoration on an isolated Linux host. Local fake
adapters and portable extraction do not establish real systemd timeout/SIGKILL/
transport-loss recovery, Docker restoration or GNU tar UID/GID/ACL/xattr behavior.
The user has no disposable host; do not substitute production or request it again.
Production inventory and approval of actual guard/hook fingerprints remain a
separate readiness task. The production example manifest stays unapproved.

No further local functionality gap was identified within this audit's scope.
