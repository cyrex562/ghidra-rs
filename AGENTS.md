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
- You're about to reach for `Rc<RefCell<_>>`, `Arc<Mutex<_>>`, or `Box<dyn Trait>` on a
  **shared/graph type** (referenced from many places, mutated over its lifetime — e.g. it
  appears high in `SEAM.tsv`'s fan-in ranking) and no established ownership pattern exists
  for it yet in `OWNERSHIP_MIGRATION.md` or in an already-remediated sibling type. Park
  instead of picking a pattern ad hoc — that's exactly how the current
  `Rc<RefCell>`/`Arc<Mutex>`/`Box<dyn>`/`.clone()` inconsistency happened (see
  `OWNERSHIP_MIGRATION.md`). Plain trait objects for genuinely open-ended extension points
  (script/plugin providers, loaders) are fine and not what this trigger is about.
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
- `OWNERSHIP_MIGRATION.md`: Convention and phased plan for replacing mechanically-translated
  Java idioms (trait-object + `Rc<RefCell>`/`Arc<Mutex>` graphs, Java-bean accessors) with
  arena+ID / enum-dispatch Rust patterns. Read before touching a high-fan-in shared type.
- `OWNERSHIP_DEBT.tsv`: File-level frontier for that migration (same shape as `SEAM.tsv`),
  generated/refreshed by `scripts/pattern_audit.py` — TAB-separated:
  `status  priority  score  fanin  class  module  path  signals`.
- `CONVENTION_QUEUE.tsv`: Type-level frontier — the decision list Phase 3 actually works from,
  generated by `scripts/debt_clusters.py` (`verdict  leverage  occurrences  fanin  type
  category  source  note`). An ownership decision is about a TYPE, not a file; deciding one
  type unblocks every file that referenced it. `SUGGEST-*` rows are inert proposals until
  promoted. `CONVENTION_FAMILIES.tsv` decides a whole naming family at once.

## Current Porting State

- Core workspace and crate setup are present.
- The Rust crate already includes framework, utility, generic, program model, database, and
  scripting modules. The UI shell exists but Swing→egui work is human-directed (see UI rule).
- `PORT_MANIFEST.tsv` tracks completed and pending classes. It is authoritative.
- Remaining high-level areas include ProgramDB, disassembler, decompiler, docking UI, and
  plugin loaders — most are high-dependency and surface later under `--port-order`.

## Diagnosing the Port (read before concluding anything about a type's shape)

The port is roughly 22% complete. **Any measurement taken from the Rust tree therefore measures
how far the port has got, not how the code should be shaped.** Every analysis tool written for
this repo has had to learn that the hard way, four times in one week:

- A proposer counted Rust implementers and recommended "small closed set -> enum" for `CodeUnit`
  (3 impls, because `Instruction` and `Data` are unported), for `Lock` (an extension point), and
  for `PrototypeModel` (one implementer literally named `Foo`).
- A trait with **no** implementers looked like a trait nobody wants; 198 of those were
  `seam_stubs.rs` placeholders waiting for their port.
- A trait whose only implementers were `Mock*`/`Stub*` looked collapsible; it meant the real
  implementers are still queued (`Namespace` had 51 mocks and zero real ones).
- A trait standing in for a concrete class looked like a shape defect; `TokenPattern`'s own doc
  comment says it is a seam "so that callers do not need to depend on its full implementation,
  which is not yet ported".

**The rule: judge shape from `orig_src` and `PORT_MANIFEST.tsv`, not from the Rust tree.** Before
concluding that a ported type is wrong, check:

1. **Is the Java class still TODO?** Then a trait standing in for it is a deliberate seam. The
   work is to port the class, not to "fix" the trait.
2. **Are the only implementers test doubles?** Then you are looking at an unfinished port.
3. **Is it declared in a `seam_stubs.rs`?** It is a placeholder by construction.
4. **What does Java actually declare it as?** `class`/`enum` with nothing extending it means a
   Rust trait is the wrong shape. `interface` with no in-tree implementers means you cannot tell
   -- it may be an extension point, or its implementers may be unported.
5. **Does the absence of a Rust type mean anything?** Usually not: constants-only Java classes
   (`SquashConstants`, `MachHeaderFlags`) correctly port to modules of `const` items with no type
   of that name at all.

### Names are not identities

The other recurring failure is matching on a *name* rather than on what the name refers to.
Three flavours have bitten, all producing confident and wrong conclusions:

- **Bare-name pairing.** `PatternExpression` is two unrelated Java classes -- the sleigh runtime
  expression and the pcodeCPort compiler's AST node. Pairing by basename reported a
  design conflict that does not exist.
- **JDK collisions.** The Rust `Lock` trait models `java.util.concurrent.locks.Lock`; `orig_src`
  holds an unrelated `ghidra.util.Lock` class. A scan of `orig_src` alone cannot see this.
- **Method-name sweeps.** `get_data_type_manager` is declared by several unrelated traits, and a
  regex for `Box<dyn [\w:]*DataTypeManager>` also matches `StandAloneDataTypeManager`. Both
  rewrote the wrong code, and both compiled.

Scope any rewrite to the *declaration* it belongs to (brace-matched `impl Trait for Type`
blocks), never to a name pattern across the crate. Wide regexes on this codebase have been wrong
every time they have been tried.

### Compiling is not evidence

Three behavioural breaks this week compiled cleanly and were caught only by running tests: a
`while it.has_next() { push(it.next()) }` rewrite that consumed two items per iteration and
dropped every other address; `unimplemented!()` bodies inserted for newly-required trait methods
that were in fact exercised; and a self-deadlock that no compile-time check could see. Run the
suite, and read what the failures say before assuming they are unrelated.

## Choosing the Rust shape (automated: `scripts/shape_rules.py`)

The most expensive defect class in this port has never been a wrong method body. It is a
*correct* method body hung off the wrong Rust construct — because that mistake is contagious.
`ghidra.trace.model.Lifespan` is declared `public sealed interface Lifespan`: a closed set over
a range of longs, which is a Rust `enum`. It was ported as `pub trait Lifespan`, and the crate
now carries **613 `dyn Lifespan`** uses written against that shape, plus doc comments in later
ports explaining which methods *could not* be default methods because `Lifespan` has no
constructible implementor. Nothing failed a build or a test. The shape decision has to be made
before the port, not audited after it.

**Do not decide the shape by hand.** Ask:

```
python3 scripts/shape_rules.py directive <path/under/orig_src>   # the rule + why, as prose
python3 scripts/shape_rules.py classify  <path/under/orig_src>   # the same, as JSON
```

`SHAPES.tsv` holds the answer for all 15,601 Java files; `shape_rules.py index` rebuilds it in
~15s. The rules read the Java declaration only — never the Rust tree, for the reasons in
"Diagnosing the Port" above.

| Rule | Java declaration | Rust shape |
|---|---|---|
| R1 | `enum` | `enum` (constant bodies become `match self`) |
| R2 | `sealed interface` / `sealed class` | `enum` — `permits` **is** the variant list |
| R3 | `record` | `struct`, accessors are field reads |
| R5 | extends/names a `Throwable` | error type: `Display` + `std::error::Error` |
| R6a | extends `Iterator`/`ListIterator`/`Enumeration` (a cursor) | implement `std::iter::Iterator` |
| R6b | extends `Iterable`/`Collection` and declares no other API | implement `std::iter::Iterator` |
| R7 | only statics, no instance state | plain module — **no type of that name** |
| R9 | open `interface` with methods | `trait` |
| R10 | `abstract class`, no in-repo subclasses | `struct` |
| R11 | `abstract class` **with instance fields** | shared-state `struct` **+** `trait` |
| R12 | `abstract class`, no instance state | `trait` |
| R13 | private ctor + static `INSTANCE` | `struct` + `OnceLock`, not a global `Arc<Mutex<_>>` |
| R14 | concrete `class` | `struct` |
| R4, R8a, R8b | annotation type; marker interface; constants-only interface | **park** — ask a human |

Three things this table is deliberate about:

- **`Iterable` is not a cursor.** It means "you can iterate me", which any collection says.
  `AddressSetView extends Iterable<AddressRange>` and declares 28 other abstract methods with
  833 `dyn AddressSetView` uses behind it; so do `Project` and `ProjectData`. Those keep their
  own shape and additionally implement `IntoIterator`. Only `Iterator`/`Enumeration` (R6a), or
  an `Iterable` with essentially no other API (R6b), *is* a sequence.

- **A cycle cut-point is not a shape.** `PORT_ORDER.tsv`'s `mode` column says whether a file sits
  on a dependency cycle — a fact about the graph, which decides *when* it is ported, not *what*
  it becomes. Break a cycle by stubbing the forward reference in `seam_stubs.rs`; never by
  turning a value type into a trait object. Conflating the two is how `Lifespan` happened.
- **Ambiguity parks.** R4/R8a/R8b cover cases the Java source genuinely does not answer (does
  anything dispatch on this marker?). `descent_night.sh` parks these *without* an LLM turn.

`shape_rules.py audit` compares shipped `pub trait`/`struct`/`enum` declarations against the
rules and writes `SHAPE_DEBT.tsv`. It excludes traits standing in for still-TODO Java classes
(those are deliberate seams) and ambiguous basenames.

## When a trait object is warranted (automated: `scripts/dyn_rules.py`)

"Don't reach for `dyn` by default" is advice without evidence, and it loses to the concrete
pressure of writing a signature. The question is answerable per type, from that type's Java
hierarchy:

```
python3 scripts/dyn_rules.py explain <TypeName>     # why this type is or is not polymorphic
python3 scripts/dyn_rules.py audit                  # rank every `dyn T` in the crate
```

`dep_context.py` already emits this per dependency into the file the porter reads, so a port
is told which of its dependencies warrant `dyn` before it writes a signature.

| | Java `T` is | verdict |
|---|---|---|
| **P1** | a class or enum — there was never an interface | **fix** — use the concrete type |
| **P2** | an interface with exactly one concrete implementer | **fix** — Java's header-file idiom, use that type |
| **P3** | an interface with 2–3 concrete implementers | **investigate** — enum if they are alternative representations, trait if independently extensible |
| **P4** | an extension point (`ExtensionPoint`/`Service`/`Plugin`/…) | **ok** |
| **P5** | an interface with 4+ concrete implementers | **ok** |
| **P0** | an interface with no implementer anywhere in `orig_src` | **unknown** — anonymous/lambda/external; there is no concrete type to collapse to, so don't guess |

Measured over the crate: **40.9% of non-std `dyn` is genuine (P5)** and 26.6% is P1+P2. The raw
count badly overstates the problem, which is why `pattern_audit.py` now exempts P4/P5 by
default (`--no-justified-dyn` restores the old behaviour). That exemption removed 37% of the
total debt score and took 158 files off the frontier that were never debt.

Three counting rules matter, and getting any of them wrong flips types between buckets:

- **Transitively.** `TraceCodeUnit`'s direct subtypes are the *interfaces* `TraceData` and
  `TraceInstruction`; a direct count says it has no implementations.
- **Concrete only.** An abstract base is not an alternative representation. Counting
  `AbstractDataType` and 11 sub-interfaces gives `DataType` 12 implementers; it has 192.
- **Excluding test doubles.** `StubProgram` makes `Program` look like a closed set of three
  when it has one real implementation. This is the same trap "Diagnosing the Port" describes
  from the Rust side, and `*Adapter` is *not* a double in this codebase.

### Small closed sets are several questions (decided 2026-08-09)

"2–3 implementers → enum" is not one answer. Classifying the 214 undecided P3 types by *what*
their implementers are, rather than how many, splits them into families with different
answers. `scripts/debt_clusters.py` applies these automatically (`suggest_by_family`).

| implementers look like | e.g. | answer |
|---|---|---|
| same concept, different **storage backing** (`*DB`, `DB*`, `InMemory*`, `Pseudo*`) | `Instruction` = InstructionDB + DBTraceInstruction + PseudoInstruction; `FunctionTag` = FunctionTagDB + InMemoryFunctionTag | **one type** — the backing is *where it was read from*, not what it is. Copy ID resolved against a snapshot, per convention 3. |
| a **null object** plus the real one (`Invalid*`, `Empty*`, `Null*`, `*Error`) | `InstructionPrototype` = InvalidPrototype + SleighInstructionPrototype | **`Option<T>`** — port the real one as the concrete type and delete the placeholder. Rust already has a way to say "no value". |
| one **wraps** another (`*Wrapper`, `*Adapter`, `*Proxy`) | `GDirectedGraph` = JungDirectedGraph + JungToGDirectedGraphAdapter | **`dyn` (or a generic)** — the wrapper genuinely has to hold something polymorphic. |
| a **base + subclass** chain | `ProgramCompilerSpec extends BasicCompilerSpec` | **composition** — the derived struct embeds the base. Java inheritance-for-reuse has no Rust translation. |
| genuinely unrelated **siblings** | `Language` = OldLanguage + SleighLanguage | **enum dispatch**, per convention 2. |

**Count implementers transitively, concrete-only, doubles excluded** — `IMPLEMENTERS.tsv`, via
`shape_rules.concrete_implementers`. Counting *direct* subtypes instead put 23 proposals in the
wrong family, including `CodeUnit` (proposed as a closed set; it has 20 concrete implementers),
`MemBuffer` (27), `AssemblySymbol` (17) and `DomainObject` (14). That is the same wrong answer
"Diagnosing the Port" records being reached from the Rust side, arrived at from a different
direction — direct subtypes stop at sub-interfaces.

A `SUGGEST-*` row is a proposal and stays re-derivable: when the evidence changes, re-run with
`--resuggest`, which resets proposals but never a promoted verdict.

### Sets too large for an enum (decided 2026-08-09)

When a Java type has more concrete implementers than an enum can carry, "too many for an enum"
is not the answer — it is the start of a three-way question. The 42 highest-leverage cases were
decided as follows, and the reasoning generalises.

| the type is | e.g. | verdict |
|---|---|---|
| a **read-only abstraction over a source**, with lazy combinators that compose at runtime | `AddressSetView` (union/intersection/difference/cached), `MemBuffer`, `ProcessorContextView` | **ACCEPT** — Rust's `io::Read`/`Index` shape; the implementations exist to be substituted |
| a **domain object with identity**, mutated over its lifetime, referenced from everywhere | `Namespace`, `Reference`, `Variable`, `CodeUnit`, `DomainObject` | **ARENA** — convention 1. `CodeUnit` is `Data`'s parent, and `Data` was already an arena type |
| a hierarchy a parser or lowering pass **builds dynamically** | `PcodeBlock`, `BlockGraph`, `AbstractMsType` (137), `IsfObject` (67) | **GRAPH** — convention 4. Not ENUM: the question is how values are *constructed*, not whether the set is closed |
| a seam where a **plugin or caller supplies** the implementation | `PcodeUseropLibrary`, `InjectPayload`, `SettingsDefinition`, `Task`, `ProgramLocation` | **ACCEPT** — implementers spread across 2–4 top-level areas |
| a **`docking.*` / Swing UI** type | `ActionContext`, `DockingActionIf`, `Navigatable` | **PARK** — the UI rule; its Rust shape depends on the undecided egui design |

Two shortcuts worth trying before deciding by hand:

- **Inherit from a decided ancestor.** `Enum`, `Composite` and `Pointer` are `DataType` kinds, so
  they are variants of the `DataType` enum rather than types with their own convention. Check the
  supertype closure against `CONVENTION_QUEUE.tsv` first.
- **Package beats name.** `SettingsDefinition` lives under `ghidra.docking.settings` and is a
  data-type settings registry, not a widget; `ActionContext` under `docking` is. The path
  discriminates where the suffix does not.

## Coding Standards

- Write idiomatic Rust using standard naming, ownership, error handling, and safety conventions.
  For shared/graph types (see `OWNERSHIP_MIGRATION.md`), that means an arena + typed `Copy` ID
  (e.g. via `slotmap`) instead of translating the Java interface straight into
  `Box<dyn Trait>` + `Rc<RefCell<_>>`/`Arc<Mutex<_>>`, and enum dispatch instead of `Box<dyn>`
  for closed Java hierarchies (a fixed, known set of implementers). Don't reach for `dyn`,
  `Rc<RefCell<_>>`, `Arc<Mutex<_>>`, or Java-bean `get_x`/`set_x` accessor pairs by default just
  because that's what the Java source did — those are fine when they're the right tool for a
  specific case (e.g. `dyn` for a genuine open-ended plugin extension point), not as the
  reflexive translation of "Java interface" or "Java field with a getter."
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
- Periodic pattern audit: `audit_night.sh` re-scans ported code with
  `scripts/pattern_audit.py` and refreshes `OWNERSHIP_DEBT.tsv`, flagging files whose
  Java-idiom smell score (dyn/Rc<RefCell>/Arc<Mutex> sprawl, clone density, get/set pairs,
  unwrap density, singleton statics) got worse since the last run — this is how ownership-
  pattern drift gets caught instead of accumulating invisibly. It doesn't block a merge by
  itself; treat a regression it reports the same as any other review feedback.

## Review Checklist (your own, before labeling `review`)

- The Rust code maps clearly to the Java source and preserves important semantics.
- Public APIs have Rustdoc where appropriate.
- New code has tests and those tests pass locally.
- `PORT_MANIFEST.tsv` is updated to DONE only for completed, verified work.
- No placeholders, stubs, or unapproved `TODO`s were added.
- No new `Rc<RefCell<_>>`/`Arc<Mutex<_>>`/`Box<dyn Trait>` was added to a shared/graph type
  without following `OWNERSHIP_MIGRATION.md`'s conventions (or parking per the trigger above
  if none is established yet for that type).
- Work happened on a `port/<issue#>-<slug>` branch off `integration`; `main` was untouched.
- No files were deleted; uncommitted user changes were not reverted or overwritten.
- Commits contain ONLY the files the task touched. The harnesses stage via `harness_add`
  (`scripts/harness_guard.sh`) rather than `git add -A`, because an unscoped add during a
  long unattended run commits whatever a human is editing into an unrelated port commit —
  which is exactly how three unrelated files landed inside `f2fa5516`.

## Target layout — ONE curated crate, not a 1:1 mirror

All ported code lives in the single `ghidra-rs` crate under `ghidra-rs/src/`. The Rust
module tree is an idiomatic reorganization of Ghidra's Java packages. MATCH the existing
tree; do not reproduce Java's package structure verbatim.

### Placement rule

1. Find the Java package: strip `orig_src/<module>/src/<sourceset>/java/` from the source
   path. e.g. `.../java/mobiledevices/dmg/btree/BTreeTypes.java` → `mobiledevices.dmg.btree`.
2. Map the package using the table below — the **LONGEST matching prefix wins**
   (the table is ordered most-specific first, so take the first row whose prefix is
   `pkg` or a `pkg.` ancestor). e.g. `ghidra.app.util.bin.format.elf` → `format/`,
   but `ghidra.app.plugin.core` → `app/`.

   This table is generated from `scripts/port_layout.tsv` — edit that file and run
   `python scripts/portlib.py gen-agents` to regenerate; the harness reads the same
   file, so the two never drift.

    | Java package prefix        | Rust module (src/) |
    | -------------------------- | ------------------ |
    | ghidra.app.util.bin.format | format/            |
    | ghidra.app.util.demangler  | demangler/         |
    | ghidra.app.script          | script/            |
    | ghidra.closedpatternmining | feature/           |
    | ghidra.machinelearning     | feature/           |
    | ghidra.bytepatterns        | feature/           |
    | ghidra.bitpatterns         | feature/           |
    | ghidra.pcodeCPort          | decompiler/        |
    | mobiledevices.dmg          | filesystem/        |
    | ghidra.framework           | framework/         |
    | ghidra.javaclass           | format/            |
    | ghidra.language            | program/           |
    | ghidra.security            | framework/         |
    | ghidra.markdown            | util/              |
    | ghidra.features            | feature/           |
    | ghidra.pyghidra            | script/            |
    | ghidra.program             | program/           |
    | ghidra.generic             | generic/           |
    | ghidra.feature             | feature/           |
    | ghidra.service             | service/           |
    | ghidra.formats             | filesystem/        |
    | ghidra.plugins             | app/               |
    | ghidra.docking             | docking/           |
    | ghidra.sleigh              | sleigh/            |
    | ghidra.dalvik              | format/            |
    | ghidra.jython              | script/            |
    | ghidra.server             | server/            |
    | ghidra.plugin              | app/               |
    | ghidra.async               | util/              |
    | ghidra.pcode               | pcode/             |
    | ghidra.trace               | trace/             |
    | ghidra.symz3               | feature/           |
    | ghidra.taint               | feature/           |
    | ghidra.graph               | graph/             |
    | ghidra.debug               | debug/             |
    | ghidra.util                | util/              |
    | ghidra.base                | util/              |
    | ghidra.file                | file/              |
    | ghidra.bsfv                | feature/           |
    | ghidra.lisa                | feature/           |
    | ghidra.app                 | app/               |
    | ghidra.xml                 | util/              |
    | ghidra.asm                 | asm/               |
    | ghidra.net                 | net/               |
    | ghidra.pty                 | pty/               |
    | ghidra.dbg                 | debug/             |
    | functioncalls              | graph/             |
    | decompiler                 | decompiler/        |
    | mdemangler                 | demangler/         |
    | foundation                 | util/              |
    | datagraph                  | graph/             |
    | resources                  | util/              |
    | utilities                  | util/              |
    | squashfs                   | filesystem/        |
    | generic                    | generic/           |
    | docking                    | docking/           |
    | utility                    | util/              |
    | sarif                      | sarif/             |
    | agent                      | debug/             |
    | ext4                       | filesystem/        |
    | util                       | util/              |
    | pdb                        | format/            |
    | gui                        | docking/           |
    | log                        | util/              |
    | db                         | framework/         |

3. Within that area, mirror the remaining package path in snake_case; convert the class to a
   snake_case file (`BTreeTypes` → `b_tree_types.rs`); ensure each dir has a wired `mod.rs`.
4. If a module already covers this code, EXTEND it — never create a parallel one. Read
   sibling files first and match their conventions.
5. Scripting: Jython/Python ports target `script/python.rs` (this crate uses pyo3, not
   Jython); WASM targets `script/wasm.rs`.

### If the package is NOT in the table above → STOP and park (needs-attention).

The table is comprehensive: areas deliberately left out (test, examples, demo
`ghidra_scripts`, dev-tooling, doclets, help) are **not** to be ported — they are
tracked in `todo.md` under "Post-Port" as native-Rust equivalents to build later.
The harness already filters these out, so you should rarely see one; if you do, park
it. Do NOT invent a new top-level module — comment asking which module the new area
belongs under; once answered, add a row to `scripts/port_layout.tsv`, regenerate this
table, and porting resumes.
