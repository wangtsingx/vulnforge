---
name: vuln-research
description: Plan an evidence-driven security review of an authorized local Linux C/C++ source tree.
---

# Vuln Research

## Mission
Coordinate source review for (1) known-vulnerability variants and (2) previously unknown defects.

## Required inputs
- Registered project ID
- Exact source revision
- Authorized review scope
- Optional CVE or patch references

## Workflow
1. Record project identity, revision, build context, and scope.
2. Inventory source files and major components.
3. Review relevant historical CVEs and security patches when supplied.
4. Identify external input boundaries and sensitive operations.
5. Run configured static analysis.
6. Inspect candidate code with surrounding context.
7. Create findings only when source evidence supports a specific hypothesis.
8. State missing evidence and validation steps.
9. Produce a report separating facts, inferences, and unknowns.

## Finding rules
- A dangerous API call alone is not a vulnerability.
- A static-analysis alert alone is not a confirmed vulnerability.
- A crash alone does not establish security impact.
- Every source claim must include repository revision, file, function (if known), and line range.
- Never claim a CVE, exploitability, or severity without supporting evidence.

## Output
Return a concise research plan, candidate findings, evidence references, confidence rationale,
verification status, and remediation ideas.
