# Ghidra-rs Codex Instructions

## Project Objectives
- Port Ghidra from Java to Rust.
- Support Python scripts and plugins written in Python, Rust, and WASM.
- Preserve 1-to-1 functional parity with the original Java source where appropriate.
- Maintain high test coverage and reliability for all ported behavior.
- Use `egui` for the UI, with native and WASM support.

## Repository Structure
- `orig_src/`: Original Ghidra Java source. Treat this as the source of truth for parity work.
- `ghidra-rs/`: Main Rust crate.
- `scripts/`: Project maintenance and source comparison scripts.
- `todo.md`: Porting progress and priority tracking.

## Current Porting State
- Core workspace and crate setup are present.
- The Rust crate already includes framework, utility, generic, program model, database, scripting, and UI shell modules.
- `todo.md` tracks completed and pending areas. Read it before selecting new work.
- The remaining high-level areas include ProgramDB, disassembler, decompiler, docking UI, and plugin loaders.

## Coding Standards
- Write idiomatic Rust using standard naming, ownership, error handling, and safety conventions.
- Keep behavior aligned with the Java source unless there is a clear Rust-specific reason to adapt it.
- Document public APIs with Rustdoc.
- Keep changes scoped to the porting task or bug being handled.
- Do not introduce placeholder implementations, stubbed behavior, or `TODO` comments without explicit user approval.
- Do not mark work complete unless the Rust code is implemented, tested, and compared against its Java counterpart.

## Choosing What To Port Next
1. Read `todo.md` to identify incomplete modules and current project priorities.
2. Inspect `orig_src/` for the matching Java source and nearby dependencies.
3. Use `scripts/sync_check.py` to find low-dependency Java files or inspect a candidate file:
   - `python scripts/sync_check.py --root orig_src`
   - `python scripts/sync_check.py --root orig_src --check-deps <JavaFileNameOrPath>`
   - `python scripts/sync_check.py --root orig_src --utility-only`
4. Prefer files whose dependencies are already ported, small enough to verify, and aligned with the next unchecked item in `todo.md`.
5. Before porting a module, confirm whether its Java dependencies are already represented in Rust. Port required prerequisites first, or ask the user before adding mocks.
6. After completing a port, update `todo.md` only when the implementation and tests are both complete.

## Porting Workflow
1. Identify the Java file or module in `orig_src/`.
2. Compare the Java API, behavior, edge cases, and tests if present.
3. Resolve dependencies by using existing Rust modules or porting prerequisites.
4. Implement the Rust equivalent in the appropriate module under `ghidra-rs/src`.
5. Add focused unit tests for the ported behavior, including edge cases from the Java implementation.
6. Run the relevant test target first, then run the broader workspace tests when feasible.
7. Update `todo.md` to reflect completed, verified work.

## Testing Requirements
- Every ported module must include unit tests or integration tests that exercise the expected behavior.
- Tests should cover Java parity, boundary cases, serialization formats, error paths, and concurrency behavior when applicable.
- Prefer narrow tests close to the module for small ports and broader integration tests for cross-module behavior.
- Run `cargo test --workspace` before declaring the code ready when the environment supports it.
- The project uses a PyO3 release that supports the current Python 3.14 development environment. Prefer upgrading PyO3 over pinning local development to an older Python version unless compatibility requirements change.
- Report any test command that could not be run or any environment issue that prevents a full test pass.

## Review Checklist
- The Rust code maps clearly to the Java source and preserves important semantics.
- Public APIs have Rustdoc where appropriate.
- New code has tests and those tests pass locally.
- `todo.md` is updated only for completed work.
- No placeholders, stubs, or unapproved `TODO` comments were added.
- Existing user changes in the working tree were not reverted or overwritten.
