---
name: scan-triage
description: Triage raw static-analysis results into hypothesis findings with deduplication. Use after semgrep_scan or similar tools return multiple results.
---

# Scan Triage

## Purpose

Turn raw scanner output into structured, deduplicated hypothesis findings.
Scanner results are leads, not vulnerabilities. Every result must be reviewed
before promotion to `candidate`.

## Workflow

1. **Import**: call `import_scan_results` with the raw scan output. It groups
   results by `(path, check_id)` and generates stable fingerprints.
2. **Verify grouping**: a single finding may contain multiple evidence items
   (multiple lines in the same function). If two results are in different
   functions or represent different root causes, they should be separate findings.
3. **Review each hypothesis**:
   - Read the source at the reported location and surrounding context
   - Trace the data flow from entry to sink
   - Check whether the condition is reachable from an external input
4. **Promote or reject**:
   - Reachable with real boundary violation → `candidate`, link to coverage
   - Unreachable, false positive, or defense-in-depth → `rejected` with reason
   - Cannot determine due to missing info → `needs_validation` with blocked_reason
5. **Update coverage**: mark the corresponding coverage unit as `candidate`,
   `covered`, or `blocked` depending on review outcome.

## Grouping rules

| Situation | Action |
|---|---|
| Same file, same function, same check_id | One finding with multiple evidence items |
| Same file, different functions, same check_id | Separate findings |
| Same function, different check_ids | Separate findings (different vulnerability classes) |
| Same root cause reported by different tools | One finding, list both tools in evidence |

## Common false-positive patterns

- Dangerous API call with no attacker-controlled input
- Missing length check that is enforced upstream
- Defense-in-depth suggestion (Layer A prevents it; absence of Layer B is hardening)
- Resource "leak" in error path that the process exits immediately after
- Integer overflow that requires values beyond the input size limit

## Output discipline

Never set severity on a hypothesis or needs_validation finding. Only confirmed
findings receive severity, and severity must reflect demonstrated impact, not
scanner confidence.
