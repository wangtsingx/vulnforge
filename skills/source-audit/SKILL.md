---
name: source-audit
description: Universal source audit method for any language — input boundaries, data flow, validation, and lifecycle.
---

# Universal Source Audit

This skill defines the language-agnostic core of source auditing. Use the
language-specific audit skill (go-audit, rust-audit, python-audit, etc.) for
language-specific patterns on top of this foundation.

## Phase 1: Attack Surface

1. Identify all external input entry points:
   - Network protocol parsers (HTTP, WebSocket, gRPC, raw sockets)
   - File parsers (configuration, uploads, plugins)
   - IPC endpoints (pipes, shared memory, message queues)
   - CLI arguments and environment variables
   - Database and cache reads used in security decisions

2. For each entry point, classify:
   - Who controls the input (anonymous user, authenticated user, admin, internal service)?
   - What encoding or serialization is applied?
   - What is the maximum input size?

## Phase 2: Data Flow

1. Trace input from source to sink:
   - Identify each transformation (decode, parse, normalize, validate)
   - Note where trust level changes (from untrusted to trusted)
   - Identify missing validation between source and sink

2. Common sink categories:
   - Memory allocation and copy
   - File and path operations
   - Command or query execution
   - Deserialization
   - Authentication and authorization decisions
   - Cryptographic operations

## Phase 3: Invariant Analysis

1. For each source-to-sink path, ask:
   - What security invariant must hold at the sink?
   - Is that invariant enforced?
   - Can it be bypassed by encoding, truncation, type conversion, or race?
   - Is the enforcement on all paths, or only on the happy path?

2. Common invariant violations:
   - Length checked in one unit but used in another (bytes vs characters)
   - Integer overflow before bounds check
   - Path normalized but not confined to base directory
   - Input validated before decode but used after decode
   - Authorization checked once but not on retry or redirect

## Phase 4: Candidate Findings

1. For each candidate, record:
   - Exact file, function, and line range
   - Input source and data flow
   - Missing or insufficient invariant
   - Trigger conditions and prerequisites
   - Potential security impact
   - False-positive conditions
   - Recommended validation test

2. Use the project's language-specific audit skill for detailed patterns.

## Constraints

- A dangerous API call alone is not a vulnerability.
- Static analysis output is a lead, not a conclusion.
- Do not assume reachability without tracing the data flow.
- Separate confirmed facts from inferences and hypotheses.
