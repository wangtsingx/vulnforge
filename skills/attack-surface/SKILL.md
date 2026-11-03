---
name: attack-surface
description: Identify external input boundaries, trust boundaries, and sensitive operations in a C/C++ source tree.
---

# Attack Surface Analysis

## Workflow

1. Identify all external input entry points:
   - Network protocol parsers (socket reads, packet handlers, HTTP request processing)
   - File parsers (configuration, uploaded content, plugin loading)
   - IPC endpoints (pipes, shared memory, D-Bus, sockets)
   - Privileged interfaces (setuid binaries, kernel syscall interfaces)
   - Environment variables and command-line arguments for elevated processes

2. For each entry point, trace the data flow to sensitive operations:
   - Memory allocation and copy (`malloc`, `memcpy`, `strcpy`, `snprintf`)
   - Indexing and pointer arithmetic
   - File and path operations
   - Authentication and authorization decisions
   - Privilege transitions

3. Identify trust boundaries:
   - Where does untrusted data first enter the process?
   - Where is it validated, sanitized, or length-checked?
   - Can validation be bypassed by encoding, truncation, or integer conversion?

4. Record for each surface:
   - File and line range
   - Input source type
   - Data flow path
   - Current validation and its limitations
   - Potential bypass conditions

## Constraints

- Presence of a dangerous API alone does not imply reachability.
- Document the exact data flow from source to sink.
- Separate confirmed attack surface from speculative paths.
