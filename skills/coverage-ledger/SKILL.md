---
name: coverage-ledger
description: Track what a source audit has covered, what it missed, and why. Use when creating or updating coverage units during a VulnForge research task.
---

# Coverage Ledger

## Purpose

A coverage ledger proves which surfaces, trust boundaries, subsystems, and attack
classes were audited. An architecture summary or agent count is not evidence;
only `reviewed_paths` and `local_checks` count.

## When to create a unit

Create one coverage unit for each material combination of:

- **surface**: an external input entry point (file, function, route, message type)
- **boundary**: the trust boundary or security control at that surface
- **subsystem**: the repository directory or package containing it
- **attack_class**: the vulnerability category being checked

Use canonical source references (file path + exported scope or line) for each
dimension. Do not use human-readable labels as references.

## Status rules

| Status | Precondition | Meaning |
|---|---|---|
| `planned` | No owner, no evidence | Seeded, not yet assigned |
| `in_progress` | Owner set, no evidence | Assigned to a reviewer |
| `covered` | Owner + reviewed_paths + local_checks | Reviewed with no candidate found |
| `candidate` | Owner + evidence + fingerprints | Reviewed and linked to finding(s) |
| `blocked` | Owner + partial evidence + unresolved reason | Cannot complete due to missing information |
| `deferred` / `out_of_scope` / `not_applicable` | No evidence + unresolved reason | Explicit gap, never counts as covered |

Never mark a unit `covered` without recording reviewed paths and checks.
Never count `deferred` or `blocked` as coverage in reports.

## Bidirectional linking

When a unit becomes `candidate`, call `link_finding_to_coverage` with the finding's
fingerprint. This writes `coverage_id` back onto the finding, making the relationship
bidirectional. Use `coverage_orphans` to detect candidate units whose fingerprints
do not exist in the finding store.

## Multi-run discipline

Do not carry a previous run's `covered` status into a new run automatically.
Check whether the relevant source has changed (compare revisions). If changed,
create a new `planned` unit for revalidation.
