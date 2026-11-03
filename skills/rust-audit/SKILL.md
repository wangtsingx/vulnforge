---
name: rust-audit
description: Audit Rust source for unsafe block, panic injection, integer cast, and command injection defects.
---

# Rust Source Audit

## Workflow

1. Identify external input entry points:
   - HTTP framework handlers (Actix, Axum, Rocket, Warp)
   - CLI argument parsing (clap, structopt)
   - File and configuration parsers (serde, nom)
   - Network listeners and IPC channels

2. Focus on `unsafe` blocks:
   - `unsafe { ... }`: What memory safety invariant must the caller maintain?
   - `std::mem::transmute`: Is the type reinterpretation valid?
   - FFI calls: Are C strings null-terminated? Are buffers properly sized?
   - Raw pointer dereference: Is the pointer valid, aligned, and non-null?

3. Check panic paths:
   - `.unwrap()` and `.expect()`: Can they be reached with untrusted input?
   - Array indexing: Can it panic with out-of-bounds?
   - Integer overflow: Is `overflow-checks` enabled in release builds?
   - `panic!()` calls: Are they reachable from external input?

4. Check integer casts:
   - `as usize`, `as u32`, `as i32`: Can truncation or sign change cause issues?
   - Prefer `TryFrom` or `checked_*` arithmetic for untrusted values.

5. Check command and path operations:
   - `Command::new(...).args(...)`: Are arguments user-controlled?
   - `File::open`, `fs::read_to_string`: Is the path built from user input?

6. Check concurrency:
   - `Arc<Mutex<T>>`: Is the lock held across `.await` points?
   - `RefCell` in multi-threaded context: Can it panic at runtime?
   - `Send`/`Sync` bounds: Are they correct for shared state?

7. For each candidate, capture:
   - File, function, and line range
   - Unsafe invariant or missing validation
   - Input source and data flow
   - Trigger conditions

## Constraints

- Rust's ownership model prevents most memory errors but not logic or injection flaws.
- `unsafe` code is not automatically vulnerable; it requires invariant analysis.
- Panics are denial-of-service vectors in server contexts but not memory corruption.
