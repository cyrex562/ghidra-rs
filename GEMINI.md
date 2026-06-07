# Ghidra-rs Project Instructions

## Objectives
- Port Ghidra from Java to Rust.
- Support Python scripts and plugins (Python, Rust, WASM).
- Maintain 1-to-1 functional parity with the original Java source where appropriate.
- Ensure high test coverage and reliability.
- UI Framework: **egui** (Native + WASM support).

## Coding Standards
- **Idiomatic Rust:** Follow standard Rust conventions (naming, safety, performance).
- **Parity Tracking:** Every ported file must be documented and verified against its Java counterpart.
- **Testing:** Unit tests must accompany every ported module.
- **Documentation:** Use Rustdoc for all public APIs.

## Porting Workflow
1. **Identify Module:** Choose a Java file/module from `orig_src`.
2. **Resolve Dependencies:** Ensure all prerequisites are ported or mocked.
3. **Port Code:** Translate Java logic to Rust syntax and idiomatic patterns.
4. **Verify:** Write unit tests to match original intent and edge cases.
5. **Update Todo:** Mark the file as completed in `todo.md`.

## Project Structure
- `orig_src/`: Original Java source code.
- `ghidra-rs/`: Main crate for the project.
- `crates/`: Supporting crates (as needed).
- `scripts/`: Project maintenance and sync scripts.
- `todo.md`: Tracking progress of the port.
