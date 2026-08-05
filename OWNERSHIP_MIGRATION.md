# Ownership & Idiom Migration Plan

## Problem

The autonomous port translates Java interfaces to Rust traits close to 1:1
(this is literally `seam_night.sh`'s job: "breaks the keystone SCC by porting
core Java interfaces to Rust TRAITS"). Java's object model — GC references,
nullable fields, shared mutable graphs, deep interface hierarchies — has no
direct Rust equivalent, so each autonomous run has been inventing its own local
workaround: `Box<dyn Trait>`, then `Rc<RefCell<_>>` or `Arc<Mutex<_>>` to share
it, then `.clone()` wherever the borrow checker complains.

`scripts/pattern_audit.py` (added by this plan) quantifies it. First run against
`ghidra-rs/src`, cross-referenced with `SEAM.tsv` fan-in:

```
priority  score   fanin  class                        path
4289.6    386.8   1009   Listing                      program/model/listing/listing.rs
2848.7    198.1   1338   Function                     program/model/listing/function.rs
2513.6    160.0   1471   DataTypeManager              program/model/data/data_type_manager.rs
1981.0     94.2   2003   DataType                     program/model/data/data_type.rs
1631.4    125.2   1203   ProgramBasedDataTypeManager  program/model/data/program_based_data_type_manager.rs
```
(`OWNERSHIP_DEBT.tsv` has the full 639-file list.)

The five highest-fan-in ported types in the crate are also its five highest
idiom-smell scores. That's not a coincidence: the classes with the most Java
callers are the ones with the richest interface surface, which is exactly where
mechanical trait translation produces the most `dyn Trait` dispatch and
`Rc`/`Arc` sharing. It also means the debt compounds — every one of the 13,856
still-TODO Java files that will eventually reference `Listing`, `Function`,
`DataTypeManager`, or `DataType` will inherit whatever ownership shape those
five files settle into.

## Target convention

Two replacements for "port Java interface -> Rust trait + `Box<dyn>` +
shared-mutable-cell", chosen per type:

**1. Arena + typed ID, for shared/graph types** (`Program`, `Listing`,
`DataTypeManager`, `Function`, `Data`, `Symbol`, and similar — types that are
referenced from many places and mutated over the object's lifetime).

- One arena owns the real data: `struct ProgramStore { functions: SlotMap<FunctionId, FunctionData>, ... }`.
- Everything else holds a small `Copy` ID (`FunctionId(u32)`), not a reference, a
  `Box<dyn Function>`, or an `Rc<RefCell<dyn Function>>`.
- Behavior that Java expressed as interface methods becomes inherent methods on
  the ID type that take `&ProgramStore` / `&mut ProgramStore`:
  `impl FunctionId { fn name(self, store: &ProgramStore) -> &str }`.
- Crate of choice: `slotmap` (generational keys, O(1) lookup/removal, `Copy`
  keys designed for exactly this pattern; `generational-arena` is an acceptable
  alternative if a dependency conflict shows up). Add under `[dependencies]` in
  `ghidra-rs/Cargo.toml` when the pilot (below) starts.
- This removes `Rc<RefCell<_>>` cycles and most `.clone()`-to-dodge-the-borrow-checker
  calls, because callers pass a `Copy` ID around instead of a reference into a
  shared cell.

**2. Enum dispatch, for closed hierarchies** (`DataType`'s concrete kinds —
`Structure`, `Union`, `Enum`, `Array`, `Pointer`, `TypeDef`, `Dynamic`, ... —
where Java's `instanceof`/interface-implementer set is fixed and known).

- `enum DataTypeKind { Structure(StructureData), Union(UnionData), Pointer(PointerData), ... }`
  instead of `Box<dyn DataType>`.
- Shared behavior via a small trait implemented on the enum (or a `match` in one
  place), not via dynamic dispatch scattered across call sites.
- Keep `dyn Trait` for the cases where it's actually the right tool: genuine
  open-ended extension points a plugin can implement (e.g. `ScriptProvider`,
  processor/loader plugins) — those are open sets by design, and `dyn` is the
  idiomatic Rust answer there. The rule isn't "no `dyn`," it's "don't reach for
  `dyn` by default because the Java source had an interface."

**When `Rc<RefCell<_>>`/`Arc<Mutex<_>>` is still fine:** genuinely
single-owner-with-callback or truly shared cross-thread mutable state that
isn't graph-shaped (e.g. a listener registry, a cache). The smell isn't the
type — it's using it as the default answer to "how do I share this Java
object" instead of a deliberate choice.

## Evaluation: `scripts/pattern_audit.py`

Heuristic (regex, no rustc AST — same tradeoff `sync_check.py` already makes)
scanner over `ghidra-rs/src`. Signals per file: `dyn Trait` count,
`Rc<RefCell<`/`Arc<Mutex<` count, `.clone()` density, Java-style
`get_x`/`set_x` accessor pairs, `.unwrap()`/`.expect()` density outside test
modules (proxy for Java checked-exception-as-panic instead of `Result`
propagation), and `static ... Lazy<Mutex<...>>` (Java singleton/manager
statics). Weighted into a `score`; cross-referenced against `SEAM.tsv` fan-in
into a `priority` so a smelly high-fan-in seam type outranks an equally smelly
leaf file.

```
python scripts/pattern_audit.py --root ghidra-rs/src --seam SEAM.tsv --out OWNERSHIP_DEBT.tsv
```

Output is `OWNERSHIP_DEBT.tsv` — same shape as `STUBS.tsv`/`SEAM.tsv`:
`status(TODO/DONE/PARK) priority score fanin class module path signals`. This
is the frontier file for remediation, exactly like `SEAM.tsv` is the frontier
for the seam harness.

Caveats to state plainly, not paper over: it's regex-based (a `dyn` inside a
comment or string counts; class-name-from-filename guessing can mismatch on
irregular names), and it ranks *candidates for review*, not confirmed defects
— a human or an agent should still read the file before deciding arena vs.
enum vs. "this `Rc<RefCell>` is actually fine here."

## Remediation

**This is a breaking change to already-`DONE`, widely-depended-on public
APIs.** `AGENTS.md` already says autonomous runs must park rather than alter a
public Rust API used by other modules — that rule is correct in general and
would otherwise fire on every file in this migration. Remediation therefore
gets its own lane, explicitly carved out of the normal one-issue-per-run rule,
rather than being picked up ad hoc by `tick2.sh`/`seam_night.sh`.

**Phase 0 — land the tooling (this change).** `pattern_audit.py`,
`OWNERSHIP_DEBT.tsv`, this doc, `AGENTS.md` pointers, and the periodic-audit
harness. No ported code changes yet. Low risk, fully additive.

**Phase 1 — pilot on one type.** Pick a mid-fan-in, self-contained type (not
`Listing` or `Function` — too central to risk the first attempt on) to prove
the arena/ID pattern compiles cleanly against real call sites and to write up
the concrete before/after as a worked example other agents (and humans) can
follow. Land it as its own reviewed PR, human-approved given the API-breaking
nature.

**Phase 2 — the top-5 seam types**, in `OWNERSHIP_DEBT.tsv` priority order
(`Listing`, `Function`, `DataTypeManager`, `DataType`,
`ProgramBasedDataTypeManager`). Each gets its own branch/PR:
`ownership/<type>-arena-migration`, off `integration`, same build-gate-then-merge
discipline as `seam_night.sh` uses for `SEAM.tsv`, but **not** run
autonomously/unattended for this phase — the fan-in is high enough that a bad
call here is expensive to unwind, so each PR gets human review before merge
even though an agent does the mechanical work. Downstream call sites broken by
the signature change are enumerated by `cargo build`'s errors — fix-forward
through them in the same PR (or as immediate stacked follow-ups) rather than
leaving `integration` red.

**Phase 3 — sweep the rest of `OWNERSHIP_DEBT.tsv`** in normal
one-issue-per-run autonomous cadence (a `remediate_ownership.sh` harness,
mirroring `seam_night.sh`'s structure, added in this change but left
`REMEDIATE_MAX=0`-equivalent / not cron-wired until Phase 2 validates the
pattern). By this phase the convention is proven and documented with real
examples, so autonomous remediation is far lower-risk than it would be today.

**Phase 4 — ongoing.** New ports must follow the convention from the start
(see `AGENTS.md` changes below), so `OWNERSHIP_DEBT.tsv` should only shrink
from here, modulo the periodic audit catching regressions (next section).

## Periodic harness step: catching new Java-isms, not just ownership

A one-time backlog sweep doesn't stop new smells from entering — `tick2.sh`
and `seam_night.sh` will keep porting thousands of remaining files, and
without a check, each is free to reinvent the same workarounds. Add a
detection-only step, cheap enough to run every batch, separate from the
(expensive, human-reviewed) remediation lane:

- **What**: `scripts/pattern_audit.py --diff-new --baseline OWNERSHIP_DEBT.tsv`
  run against files touched since the last audit snapshot. It only reports
  files whose smell score *increased* — i.e. new debt just introduced — not
  the whole backlog, so it's cheap to read after every batch.
- **Where it plugs in**: end of `tick2.sh`'s batch loop and `seam_night.sh`'s
  run (both already do a post-batch/post-merge build gate; add the audit
  right after). On regression, append the new rows to `OWNERSHIP_DEBT.tsv`
  (status `TODO`) instead of silently letting them merge — this is the fix for
  the gap noted earlier: ownership-pattern drift wasn't triggering any STOP
  condition, so it accumulated invisibly. It still doesn't block the merge (a
  human curates `OWNERSHIP_DEBT.tsv` into remediation issues), but it stops
  being invisible.
- **Standalone cadence**: `audit_night.sh` (added in this change) re-runs a
  full scan and refreshes `OWNERSHIP_DEBT.tsv` weekly, wired the same way
  `seam_night.sh` documents its own crontab line, so drift is caught even
  outside a porting batch (e.g. after manual/human commits).
- **Scope beyond ownership**: the signal set already generalizes past
  arena-vs-`Rc`. Getter/setter pairs are Java bean idiom leaking into Rust
  (should usually be a `pub` field or a single accessor, not a get/set pair).
  `.unwrap()`/`.expect()` density is Java's checked-exception-as-control-flow
  habit leaking in (should be `Result` propagation with `?`). `Lazy<Mutex<_>>`
  statics are Java singleton/manager classes leaking in (should be state owned
  by and threaded through the relevant struct). Extend `SIGNAL_WEIGHTS` in
  `pattern_audit.py` as new traps get recognized — it's a single dict, not a
  rewrite.

## `AGENTS.md` changes (applied in this change)

- Pointer to this doc from "Coding Standards".
- New STOP/park trigger: a shared/graph type with no established ownership
  pattern yet (ambiguous arena-vs-trait-object choice) — park instead of
  picking one ad hoc, the way `Rc<RefCell>` vs `Arc<Mutex>` vs `Box<dyn>` has
  been picked ad hoc so far.
- Review checklist item: new code doesn't introduce `Rc<RefCell<_>>` /
  `Arc<Mutex<_>>` / `Box<dyn Trait>` on a type already covered by
  `OWNERSHIP_DEBT.tsv`'s arena convention without following it.
- Pointer to the periodic audit step under "Testing Requirements".
