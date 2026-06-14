# Ghidra-rs Codex Instructions

## Project Objectives

- Port Ghidra from Java to Rust.
- Support Python scripts and plugins written in Python, Rust, and WASM.
- Preserve 1-to-1 functional parity with the original Java source where appropriate.
- Maintain high test coverage and reliability for all ported behavior.
- Use `egui` for the UI, with native and WASM support.

## Autonomous Operation (READ FIRST)

You run **unattended**, working **one GitHub issue per invocation**. Optimize for correct,
small, reviewable increments — not speed. You cannot ask the user a question mid-run, so
when you would otherwise need approval, you **park** (see below) instead of guessing.

### The loop (per run)

1. You are given one issue labeled `ready`. Read it fully, including its Constraints.
2. Create a feature branch off `integration`: `port/<issue#>-<slug>`.
3. Port only what the issue specifies, into the module given by the map below.
4. Add tests; run `cargo test` (see Testing Requirements). Do not proceed on failure.
5. Update `PORT_MANIFEST.tsv`: set each ported class's `status` column TODO -> DONE, and
   commit that change on the feature branch alongside the code.
6. When acceptance criteria are met: merge the feature branch into `integration`, push
   `integration`, label the issue `review`, and comment a 2–3 line summary (what changed,
   branch name, test result).
7. Never touch `main`. Never open, push, or merge anything into `main`.

### Branch rules

- Base every branch on `integration`, never on `main`. The human merges `integration -> main`.
- One issue = one feature branch. Never bundle unrelated issues.
- Rebase only onto `integration` (this lane controls it), never onto `main`.

### STOP and park (label `needs-attention`, comment your question) when:

- A decision is required outside the issue's stated Constraints.
- You would need to add a stub, placeholder, or `TODO` (these need user approval you cannot
  get while unattended — so park instead of stubbing).
- A change would alter a public Rust API already used by other modules.
- A new dependency, data format, or schema change is required.
- A Java package's top-level area is **not in the map table** below (do not invent a module).
- A file would need to be deleted — **never delete files**; park instead.
- The issue turns out to be primarily Swing UI (see UI rule) — park with the `ui` label.
- The spec is genuinely ambiguous and a wrong guess wastes real work.
  When you park: leave the branch as-is, post a comment stating what is blocking, the exact
  decision you need, and what you tried. Then stop.

### Risk tiers (from the issue's "Risk tier" field)

- `low` → reversible/local: proceed, and log any assumption you made as an issue comment.
- `high` → park rather than assume.

### UI / Swing rule

Swing→egui is a redesign, not a mechanical port. Issues labeled `ui` / `needs-design` are
**out of scope for autonomous runs** — do not pick them, and if an assigned issue turns out
to be mostly Swing UI, park it with the `ui` label.

### Never

Delete files; force-push; push to or merge into `main`; `git reset --hard` a shared branch;
rewrite published history; weaken, skip, or delete tests to make a build pass; add
unapproved stubs/placeholders/`TODO`s; revert or overwrite uncommitted user changes.

## Repository Structure

- `orig_src/`: Original Ghidra Java source. Treat this as the source of truth for parity work.
- `ghidra-rs/`: Main Rust crate.
- `scripts/`: Project maintenance and dependency/parity scripts (`sync_check.py`).
- `PORT_MANIFEST.tsv`: **The single source of truth for porting status.** TAB-separated:
  `<java_path>\t<status>\t<package>`. Status is `TODO` or `DONE`. You update it (step 5 above).
- `todo.md`: Optional human-readable summary, generated from the manifest. Not authoritative.

## Current Porting State

- Core workspace and crate setup are present.
- The Rust crate already includes framework, utility, generic, program model, database, and
  scripting modules. The UI shell exists but Swing→egui work is human-directed (see UI rule).
- `PORT_MANIFEST.tsv` tracks completed and pending classes. It is authoritative.
- Remaining high-level areas include ProgramDB, disassembler, decompiler, docking UI, and
  plugin loaders — most are high-dependency and surface later under `--port-order`.

## Coding Standards

- Write idiomatic Rust using standard naming, ownership, error handling, and safety conventions.
- Keep behavior aligned with the Java source unless there is a clear Rust-specific reason to adapt.
- Document public APIs with Rustdoc.
- Keep changes scoped to the porting task or bug being handled.
- Do not introduce placeholder implementations, stubbed behavior, or `TODO` comments without
  explicit user approval — while unattended, that means **park** instead.
- Do not mark work complete unless the Rust code is implemented, tested, and compared against
  its Java counterpart.

## Choosing What To Port Next

1. Get the current frontier — TODO files ordered by fewest **remaining (unported)** deps:
    - `python scripts/sync_check.py --root orig_src --manifest PORT_MANIFEST.tsv --port-order`
    - A `0` in the first column means every dependency is already ported (safe, no stubbing).
2. Take the issue you were assigned; confirm it corresponds to a low-remaining-dep file.
3. Inspect `orig_src/` for the matching Java source and its dependencies:
    - `python scripts/sync_check.py --root orig_src --check-deps <JavaFileNameOrPath>`
4. Before porting, confirm its Java dependencies are already represented in Rust. If a
   prerequisite is unported, **park** (do not add mocks) — the frontier ordering should
   prevent this, so a missing prereq means the manifest is stale or the issue is mis-ordered.
5. After completing a port, set the manifest rows to DONE (only when implementation and tests
   are both complete and verified against the Java source).

## Porting Workflow

1. Identify the Java file or module in `orig_src/`.
2. Compare the Java API, behavior, edge cases, and tests if present.
3. Resolve dependencies using existing Rust modules; if a prerequisite is unported, park.
4. Implement the Rust equivalent in the module given by the map below, under `ghidra-rs/src`.
5. Add focused unit tests for the ported behavior, including edge cases from the Java source.
6. Run the relevant test target first, then the broader workspace tests when feasible.
7. Set the ported classes' `PORT_MANIFEST.tsv` rows to DONE; commit on the feature branch.

## Testing Requirements

- Every ported module must include unit or integration tests exercising expected behavior.
- Cover Java parity, boundary cases, serialization formats, error paths, and concurrency when applicable.
- Prefer narrow tests near the module for small ports; broader integration tests for cross-module behavior.
- Run `cargo test --workspace` before declaring code ready when the environment supports it.
- The project uses a PyO3 release compatible with the Python 3.14 dev environment. Prefer
  upgrading PyO3 over pinning to an older Python unless compatibility requires otherwise.
- Report any test command that could not be run, or any environment issue that prevents a
  full test pass — do not silently skip.

## Review Checklist (your own, before labeling `review`)

- The Rust code maps clearly to the Java source and preserves important semantics.
- Public APIs have Rustdoc where appropriate.
- New code has tests and those tests pass locally.
- `PORT_MANIFEST.tsv` is updated to DONE only for completed, verified work.
- No placeholders, stubs, or unapproved `TODO`s were added.
- Work happened on a `port/<issue#>-<slug>` branch off `integration`; `main` was untouched.
- No files were deleted; uncommitted user changes were not reverted or overwritten.

## Target layout — ONE curated crate, not a 1:1 mirror

All ported code lives in the single `ghidra-rs` crate under `ghidra-rs/src/`. The Rust
module tree is an idiomatic reorganization of Ghidra's Java packages. MATCH the existing
tree; do not reproduce Java's package structure verbatim.

### Placement rule

1. Find the Java package: strip `orig_src/<module>/src/<sourceset>/java/` from the source
   path. e.g. `.../java/mobiledevices/dmg/btree/BTreeTypes.java` → `mobiledevices.dmg.btree`.
2. Map the TOP-LEVEL area using this table:

    | Java top-level                                                      | Rust module (src/) |
    | ------------------------------------------------------------------- | ------------------ |
    | ghidra.framework.\*                                                 | framework/         |
    | ghidra.program.\*                                                   | program/           |
    | ghidra.util.\*                                                      | util/              |
    | generic._ , ghidra.generic._                                        | generic/           |
    | ghidra.app.script.\* , jython, plugin loaders                       | script/            |
    | ghidra.app.util.bin.format.\* (COFF, ELF, MachO, PE, DWARF, PDB, …) | format/            |
    | GPL filesystem modules (mobiledevices.dmg.\*, ext4, squashfs, …)    | filesystem/        |
    | ghidra.app.util.demangler.\*                                        | demangler/         |

3. Within that area, mirror the remaining package path in snake_case; convert the class to a
   snake_case file (`BTreeTypes` → `b_tree_types.rs`); ensure each dir has a wired `mod.rs`.
4. If a module already covers this code, EXTEND it — never create a parallel one. Read
   sibling files first and match their conventions.
5. Scripting: Jython/Python ports target `script/python.rs` (this crate uses pyo3, not
   Jython); WASM targets `script/wasm.rs`.

### If the area is NOT in the table above → STOP and park (needs-attention).

Do NOT invent a new top-level module. Comment asking which top-level module the new area
belongs under. Once answered, the table grows and porting resumes.
