# vps3xui P0 handoff

## Current state

2026-09-23: F7 was completed and accepted after the user's instruction to continue.
**F1-F7 accepted locally. P0 local functionality is complete.**
**Real Linux restore drill is NOT RUN; overall P0 acceptance remains open.**
The user confirms no disposable Linux host is available. Do not ask again or use
the production VPS as a substitute. No worker is running.

Current audit: [FUNCTIONALITY-AUDIT.md](docs/agent-work/p0/FUNCTIONALITY-AUDIT.md).
The independent 2026-09-23 audit found and fixed a fetch destination symlink
bypass; a new regression covers four path variants. Final suite: 581 tests PASS.
Prior F1-F7 review: [COMPLETION-FINAL-REVIEW.md](docs/agent-work/p0/COMPLETION-FINAL-REVIEW.md).
Plan: [COMPLETION-PLAN.md](docs/agent-work/p0/COMPLETION-PLAN.md).
Checkpoint: [CHECKPOINT.md](docs/agent-work/p0/CHECKPOINT.md).
FINAL-REVIEW.md and RESUME-FINAL-REVIEW.md are historical.

## Accepted work

Earlier continuation: R1-R8 corrections plus R9 local harness code accepted.
This continuation used one native Flash worker per task, sequentially; root
reviewed actual changes before assigning the next task.

- F1: bounded at queue/spool discovery, conservative queued/unknown evidence
  refusal, plan/preflight drift protection. Root targeted check: 42 tests PASS.
- F2: durable first-write-only failure journal, bounded nonblocking reads,
  preservation of corrupt/foreign/symlink evidence on rerun. Root: 29 tests PASS.
- F3: consistent source success gates; contradictory COMPLETE revocation only
  after identity/path validation; retryable fsync and binding failures retained.
  Root: 29 tests PASS after two material review correction cycles.
- F4: contract audit identified F5, F6 and F7. Same-request-id retry after a
  submission failure is intentional safe behavior, not a missing feature.
- F5: positive durable no-effects evidence, bound to job/request/plan, makes
  caught preflight failures terminal without mutating host services. Ambiguous
  or corrupt evidence remains blocked. Root: 32 tests PASS.
- F6: Certbot fixture triggers moved to vendor units so runtime masking works;
  cleanup recognizes vendor files and reloads systemd safely. After one review
  correction, usrmerge aliases receive exact pins only for the same device/inode
  and expected content; /lib is never created, owned or removed. Accepted.
- F7: `backup verify --host --job` works from an empty client state. Paths come
  from the host's immutable request, validated for identity, live host key,
  manifest id/digest, digest-derived release path and fixed backup path. The
  success gate still runs first, and a disagreeing local record refuses. Root
  implemented it directly (no deepseek_coder worker type was available). Accepted.

Worker reports: docs/agent-work/p0/corrections/F1.md through F6.md, with audit in
F4-AUDIT.md. Last worker: /root/f6_fixture_precedence, completed and accepted.
Routing static_only: deepseek_coder / deepseek-v4.1-flash / high, inherited
LiteLLM. Upstream inference metadata was not independently available.

## F7 checks (before the independent audit)

- Full suite: 580 tests PASS, exit 0.
- compileall: PASS; tracked diff whitespace check excluding .DS_Store: PASS.
- Portable restore drill: 11 checks PASS, zero failures; GNU tar portion NOT RUN.
- R2-R8 regression probes: PASS.
- No-VM wrapper: expected exit 3, NOT RUN.
- Original design and references/apps.md unchanged against continuation baseline.

Evidence: docs/agent-work/p0/evidence/f7-*. Report: corrections/F7.md.

## What remains (external only, needs a new instruction)

Linux acceptance requires an explicitly approved disposable host with
systemd/Docker/GNU tar, ACL/xattr tools and a preloaded synthetic image@sha256.
Follow references/recovery.md and retain drill and cleanup evidence. Production
inventory and real trusted guard/hook approval are a separate task. The example
production manifest remains unapproved. No local P0 code task is open.

## Workspace and preservation

- Repo /Users/kewlrus/projects/skills/vps-3xui; branch main.
- HEAD 633ac3e2f90441ac6ced5842b21a7cef4efc20a3 unchanged.
- Implementation and reports are largely untracked; git diff alone is incomplete.
  Preserve all dirty/untracked work, .codegraph and .gitignore; ignore .DS_Store.
- Initial current continuation: /private/tmp/vps3xui-p0-completion-baseline.
- Per-task snapshots: /private/tmp/vps3xui-before-f3, -before-f5, -before-f6, -before-f7.
- No staging, commits, resets, pushes, deployment, settings/credentials changes
  or production access. No P1 restore CLI work.
- Python 3.9, standard library only; use PYTHONPYCACHEPREFIX under /private/tmp
  and PYTHONPATH=tests:. for tests.
