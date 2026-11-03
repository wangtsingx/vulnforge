---
name: security-report
description: Generate a structured security research report from validated findings and evidence.
---

# Security Report

## Workflow

1. Collect all findings for the target project using `findings_list`.
2. Load full details for each finding with `get_finding`.
3. Organize findings by severity and status:
   - Confirmed: reproducible with clear security impact.
   - Candidate: source evidence supports a hypothesis but verification is incomplete.
   - Rejected: evidence disproved the hypothesis.
4. For each finding, include:
   - Finding ID and title
   - CWE classification (if known)
   - Source location (file, function, line range)
   - Evidence references
   - Data flow description
   - Trigger conditions
   - Verification status and limitations
   - Remediation recommendation
5. Separate clearly:
   - Facts (source code, tool output, reproducible results)
   - Inferences (data flow, reachability, impact analysis)
   - Unknowns (missing evidence, untested paths)
6. Call `generate_report` to produce the Markdown output.
7. State that static-analysis findings and crashes require human confirmation before being treated as vulnerabilities.

## Constraints

- Never claim a 0-day or confirmed vulnerability without reproducible evidence.
- Severity must be justified by attack prerequisites and impact, not by tool output.
- Include the exact source revision analyzed.
