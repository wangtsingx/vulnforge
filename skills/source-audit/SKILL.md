---
name: source-audit
description: Audit C/C++ source for input validation, memory safety, integer, and resource-lifecycle defects.
---

# Source Audit

1. Start from externally reachable inputs: network parsers, file parsers, configuration, IPC, and privileged interfaces.
2. Trace data from source to sensitive operations such as allocation, copy, indexing, parsing, and authorization decisions.
3. Check length units, integer conversions, arithmetic overflow, bounds checks, and error paths.
4. Review ownership, cleanup, aliasing, and object lifetime.
5. Consider state-machine and concurrency invariants where relevant.
6. Use static-analysis output as leads, not conclusions.
7. For each candidate, capture exact source lines and explain the missing or insufficient invariant.
8. Recommend a safe validation test and a minimal remediation.

Do not infer attacker reachability merely because a function accepts a pointer or integer.
