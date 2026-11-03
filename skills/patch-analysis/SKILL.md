---
name: patch-analysis
description: Analyze security patches and derive reusable root-cause patterns for variant hunting.
---

# Patch Analysis

1. Identify the exact repository, parent revision, fixed revision, and affected files.
2. Read the full patch and relevant surrounding functions.
3. Describe the violated security invariant before describing the code change.
4. Identify input sources, trust boundaries, and affected sinks.
5. Explain why the old code was unsafe and why the new code addresses the issue.
6. Extract a generalized pattern that does not depend only on function names.
7. Search for structurally similar code and compare whether the same invariant is enforced.
8. Record false-positive conditions and evidence still required.

Do not assume every similar code fragment is vulnerable. Preserve upstream and vendor revision distinctions.
