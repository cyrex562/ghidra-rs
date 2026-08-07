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
2483.6    118.1   2003   DataType                     program/model/data/data_type.rs
1640.2    119.2   1276   DataUtilities                program/model/data/data_utilities.rs
```
(`OWNERSHIP_DEBT.tsv` has the full 1,521-row list.)

Numbers above are from the committed `OWNERSHIP_DEBT.tsv` and are reproducible — re-running
the scan on an unchanged tree yields a byte-identical file. Two corrections against this
doc's first draft, which quoted a pre-comment-strip-fix run: `DataType` scores 118.1/2483.6
(not 94.2/1981.0), and the fifth-ranked row is `DataUtilities`, not
`ProgramBasedDataTypeManager` (now sixth, priority 1631.4). Phase 2's scope is "the top-N
rows of `OWNERSHIP_DEBT.tsv` at the time you start it" — read the file, don't trust this
snapshot to stay current.

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

**3. Snapshot + transaction, for DB-backed domain objects** (`program/database/*` — the
`DataTypeDB`/`FunctionDB`/`SymbolDB` family). Decided 2026-08-06.

Ghidra's DB-backed objects cache fields (`name`, `categoryPath`, …), compare a stored
`modification_count` against the cache's to decide staleness, call `refreshIfNeeded()` before
most reads, and guard the whole dance with a reentrant read/write lock. Ported faithfully, every
one of these classes drags that scaffolding along. It is not incidental: it exists *because* the
store is mutable and objects hold stale copies of it. Both bugs found on 2026-08-05 came out of
it — the `set_name` → `get_name` self-deadlock, and a cache that survived its own invalidation.
Only 5 files carry the pattern today; **345 `program/database` files are still TODO**, so the
cost of the default is almost entirely still ahead.

The replacement, which matches Ghidra's *semantics* more closely than Java's implementation
does — `DomainObject` is already transactional, with undo/redo and modification counts, i.e.
MVCC implemented by hand over DB checkpoints:

- **Read = an atomic snapshot.** `fn snapshot(&self) -> Arc<ProgramStore>`. Readers resolve
  `Copy` IDs against the snapshot they hold. There is no staleness check because a snapshot
  cannot go stale — an older version is a *consistent* version, not a wrong one.
  `needs_refreshing`/`refresh_if_needed`/`do_refresh` disappear entirely, and with them the
  read lock.
- **Write = a transaction.** `fn transaction<R>(&self, name: &str, f: impl FnOnce(&mut ProgramStore) -> R) -> R`
  takes the single-writer lock, mutates, and publishes the new version atomically at commit.
  This *is* `startTransaction`/`endTransaction`.
- **Undo/redo = a delta log.** Each transaction records the reversible changes it made; undo
  applies their inverses, redo replays them forward. This is what Ghidra already does — a
  transaction records the changed records for its checkpoint rather than duplicating the
  database.

  Retaining prior `Arc<ProgramStore>` versions instead is the obvious-looking design and is
  wrong: holding the previous version makes the writer a non-sole owner, so `Arc::make_mut`
  copies the arena on the next write, and a non-persistent map copy is O(n) in entries. Measured
  in the pilot (`equate_store.rs`, `write_cost_is_independent_of_store_size`):

  | store entries | in-place write | copying write | ratio |
  |---|---|---|---|
  | 100 | 2.9 µs | 87 µs | 30x |
  | 1,000 | 2.3 µs | 262 µs | 116x |
  | 10,000 | 3.9 µs | 2.1 ms | 536x |
  | 100,000 | 24 µs | 25 ms | 1040x |

  In-place cost is flat; the copying path is linear. At 100k entries that is 25 ms *per
  transaction*, and a real program has millions of code units — auto-analysis would never
  finish. The delta log keeps the writer the sole owner, so writes stay in place, and its memory
  is proportional to edits rather than store size.
- **`modification_count` = the version number**, and generational arena keys already give
  per-entry versioning.

*The cost that remains, and cannot be removed at this layer:* a reader holding a snapshot
across a write still forces exactly one copy — that copy is what keeps the reader's version
immutable. So a GUI holding a snapshot while analysis runs pays the right-hand column above on
every transaction. That is inherent to snapshot isolation over non-persistent maps; if it
becomes the bottleneck the answer is persistent arenas (`im`/`rpds`: O(1) clone with structural
sharing) at the cost of a dependency and slower point access. Keep arenas as per-entity `Arc`
fields either way, so a transaction only ever touches what it modifies.

*A constraint that dictates the id type:* undoing a deletion must restore the entry under the
**same** id, or every id held elsewhere dangles after an undo. `SlotMap::insert` always mints a
fresh key and has no insert-at-key, so arenas that need undo use an explicit monotonic counter —
which is what the DB record key already is. Ids are never reused, so a stale id resolves to
`None`, the same safety a generational key gives.

*Relationship to storage:* this changes the **access** model, not persistence. Commit still
writes through. `framework/db` (fully ported, 13k lines: B-trees, buffer manager, chained
buffers, recovery) becomes the reader for **legacy Ghidra-format projects** — an import/upgrade
path, exactly as Ghidra itself upgrades older project formats to the current version — rather
than the live in-memory model. ghidra-rs is therefore not bound to Java Ghidra's on-disk layout
going forward, provided the importer exists.

**4. Tagged arena graph, for AST/IR node sets** (the sleigh compiler's expression nodes, p-code
and decompiler IR, and anything else built by a parser or lowering pass). Decided 2026-08-07.

Java models these as a class hierarchy with a virtual method per operation. Translated
literally that becomes `Box<dyn Node>` everywhere, which loses exhaustiveness, makes every new
operation a change to every implementer, and cannot be snapshotted cheaply. Translated into a
*data-carrying* enum it fights back differently: recursive `Box` fields, no sub-expression
sharing, and a wide type whose largest variant sets the size of every node.

The shape that fits:

```rust
new_key_type! { pub struct ExprId; }          // Copy handle, an edge in the graph

pub enum ExprKind { Constant, TokenField, ContextField, Plus, Sub, And, Not, ... }

pub struct ExprNode {
    kind: ExprKind,
    children: [Option<ExprId>; 2],            // fixed arity -- see below
    payload: Payload,                         // only for the kinds that carry data
    location: Location,
}

pub struct ExprGraph { nodes: SlotMap<ExprId, ExprNode> }
```

Three rules that are the whole point, and are easy to lose:

- **Fixed arity, not `Vec<ExprId>`.** A data-carrying enum makes `Plus(a, b)` unable to hold
  three operands; a tag plus a growable child list gives that guarantee away and moves the error
  to runtime. Size the child array to the language (2 for sleigh expressions) and make
  constructors the only way to build a node.
- **A payload enum, not side tables.** Measured on the 30 ported `pcodeCPort/slghpatexpress`
  nodes: 12 are pure operator wrappers carrying nothing but their operands (`AndExpression`,
  `DivExpression`, `LeftShiftExpression`, ... each a single `binary` field), and only three carry
  real data -- `TokenField` (9 fields), `ContextField` (7), `OperandResolve` (5). With that
  distribution a payload enum has few variants and most nodes carry `Payload::None`; side tables
  would buy uniformity nobody needs and cost an indirection on every access.
- **One tag enum per language, never one globally.** The crate already has two `OpCode` enums,
  for p-code and for the decompiler, and that is correct: they are different languages. Sleigh
  expressions get their own. Merging unrelated node sets into one enum would undo the
  exhaustiveness this exists for.

*What it buys:* adding an operation is one function with one match instead of a method added to
32 implementers; adding a node kind is one arm, and the compiler then names every match that
must handle it; sub-expression sharing falls out of the graph, which a tree of `Box` cannot
express; and the arena composes directly with the snapshot convention above, so a whole AST
version is an `Arc` clone.

*When NOT to use it.* A small, fixed, statically-built hierarchy is better as a plain
data-carrying enum -- the sleigh **runtime**'s `PatternExpression` is exactly that (18 variants,
grammar fixed once the `.sla` is compiled, evaluated hot) and should stay as it is. Converting it
would be churn for nothing. Genuine open-ended extension points stay `dyn`.

*The two sleigh ports are the worked comparison,* and both are right: the runtime evaluates a
fixed grammar (enum), while the compiler builds an AST dynamically across 30-odd node types with
per-node encode/list-values behaviour (tagged graph). They are different Java classes in
different packages, not one concept done twice -- `scripts/stub_audit.py` reported them as a
conflict until it learned to pair by Java class rather than by bare name.

*Choosing between conventions 2 and 4:* the question is not "is the hierarchy closed" -- both of
these are closed. It is **how the values are built and how the operations grow**. Values
constructed from a fixed source, few variants, operations rarely added: data-carrying enum.
Nodes built dynamically by a parser, recursive or shared, operations added over time: tagged
arena graph.

**Ported Java locks** (decided 2026-08-06, applies across `util/database` and
`util/stream_utils`). A Java class that takes a `ReadWriteLock`/`Lock`/`Object` monitor and
wraps a delegate translates literally into a Rust struct holding `Arc<RwLock<()>>` beside a
delegate it owns by value. That lock guards *nothing*: the payload is `()`, and `&self`/`&mut
self` already provide exactly the read/write exclusion being imitated. It is also actively
misleading -- sharing such a wrapper needs `Arc<..>`, which makes every `&mut self` method
(`add`, `remove`, `clear`) unreachable, so the mutating half of the API cannot be used
concurrently at all.

The rule: **put the lock around the data, not beside it.** A synchronized collection is
`Arc<RwLock<C>>`. Reintroduce an explicit lock only when it coordinates something the type does
not own -- an external resource, or state shared with another holder of the same lock -- and
when it does, use the crate's `Lock` trait (`util/lock_hold.rs`), as
`DBSynchronizedSpliterator` does, rather than an ad-hoc `Mutex<()>`. Worked example:
`db_synchronized_collection.rs` / `db_synchronized_iterator.rs`, where the wrappers are gone
and a test mutates a shared collection from four threads -- the case the wrapper could not
serve.

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

Caveats to state plainly, not paper over: it's regex-based (class-name-from-
filename guessing can mismatch on irregular names, and it doesn't understand
string literals), and it ranks *candidates for review*, not confirmed defects
— a human or an agent should still read the file before deciding arena vs.
enum vs. "this `Rc<RefCell>` is actually fine here." One comment-related false
positive already surfaced and got fixed during the Phase 1 pilot below: the
scanner originally matched `dyn`/`Rc<RefCell<` inside doc comments too, so
`group_tree.rs`'s own module doc comment — which explains what the file
*replaces* by naming `Box<dyn Group>` and `Rc<RefCell<dyn Group>>` in prose —
scored itself as smelly (`dyn=8, rc_refcell=2`) despite containing zero real
trait-object or shared-cell usage. `scan_file` now strips `//`/`///`/`//!`
line comments before matching; `group_tree.rs` scores `0` after the fix. Kept
here as a concrete reminder that the tool's own output needs the same
skepticism as anything else it flags.

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

**Phase 1 — pilot on one type. DONE — see `group_tree.rs`.** Pick a mid-fan-in,
self-contained type (not `Listing` or `Function` — too central to risk the
first attempt on) to prove the arena/ID pattern compiles cleanly against real
call sites and to write up the concrete before/after as a worked example other
agents (and humans) can follow. Land it as its own reviewed PR, human-approved
given the API-breaking nature.

*Worked example:* `ghidra-rs/src/program/model/listing/group_tree.rs` ports
`Group`/`ProgramModule`/`ProgramFragment` — Ghidra's Program Tree, a genuine
multi-parent DAG (a fragment "may be contained in more than one module," per
`ProgramModule`'s Java doc) — to a `GroupTree` arena (`SlotMap<GroupId,
GroupNode>`) with a `GroupKind::{Module, Fragment}` enum for the closed
module-vs-fragment hierarchy. `GroupId` is a `Copy` handle; behavior lives as
methods on `GroupId` taking `&GroupTree`/`&mut GroupTree`, exactly the shape
sketched above. No `Rc<RefCell<_>>`, `Arc<Mutex<_>>`, or `Box<dyn Trait>`
appears anywhere in the real code (`pattern_audit.py` scores the file `0`
after the comment-stripping fix noted above). A test
(`fragment_can_have_multiple_parents`) builds a fragment shared by two
modules and mutates it through both — the actual multi-parent-graph case that
would otherwise reach for `Rc<RefCell<dyn Group>>` — using nothing but two
`GroupId` copies into one arena.

Deliberately scoped down from full parity to keep the pilot self-contained:
ports `Group` in full and a representative subset of `ProgramModule`/
`ProgramFragment` (tree structure, names/comments, min/max address, multi-
parent add/remove, cycle and duplicate-name rejection). Does not port child
reordering, reparenting, version-tag/tree-ID bookkeeping, the "can't remove
the tree's last fragment" invariant, or `CodeUnit`-level fragment operations
— those need `Listing`/`CodeUnit` wiring, i.e. Phase 2. The existing
`Group`/`ProgramModule`/`ProgramFragment` traits in sibling files (`group.rs`,
`program_module.rs`, `program_fragment.rs`) are untouched: this is additive,
not a replacement, so it ships with zero downstream call-site changes.
Wiring `Listing`'s `Arc<dyn ProgramFragment>`/`Arc<dyn ProgramModule>`-
returning methods to hand out `GroupId`s instead is real Phase 2 work (it
touches `Listing`, one of the top-5 types below) — this pilot deliberately
stops short of it.

*Aside, discovered while building the pilot:* `main` had drifted 2,831
commits behind `integration` (last synced at the `#3073` merge), and
`integration` — not `main` — is where `AGENTS.md`'s branch model and the
active porting harness (`tick2.sh`/`seam_night.sh`) actually operate. The
Phase 0 tooling in this doc originally landed on `main`; this pilot branch
cherry-picks it forward onto `integration` so both live where the real work
happens. Separately, `main`'s `.gitignore` still had the bare `debug` pattern
that a prior `integration` commit (`996bfe12`) had already identified and
fixed as silently untracking every `src/**/debug/` directory (`ghidra-rs/src/
debug/`, `src/app/plugin/core/debug/`, `src/format/pe/debug/`) — that fix,
and the ~124 files it recovered, are on `integration` but were never merged
back to `main`. Nothing to do here in this doc, but worth a human's attention:
`main` needs a resync from `integration` independent of this migration.

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

**Phase 3 — decide conventions per TYPE, then sweep files.** The original plan was a
file-at-a-time autonomous sweep of `OWNERSHIP_DEBT.tsv` via `remediate_ownership.sh`. Proofing
showed that unit is wrong, and the fix is a second frontier file alongside it.

An ownership decision is never about a file; it is about a *type*. The file-level frontier
re-asks the same question once per file, pays an LLM call each time, and parks each time —
observed directly: `Trace` → `DebuggerStaticMappingService` → `DebuggerTraceManagerService`
parked in sequence, all three on the same undecided `Trace` convention.
`scripts/debt_clusters.py` inverts the index into `CONVENTION_QUEUE.tsv`: for every type
reached through `dyn T`/`Rc<RefCell<T>>`/`Arc<Mutex<T>>` in a blocked file, how many distinct
files depend on that one decision. 939 blocked files rest on ~1,070 types, but the
distribution is steep — the top 20 verdicts cover 58% of the pile, the top 40 cover 64%.

Verdicts: `ACCEPT` (`dyn` is right here — a genuine open-ended extension point), `ARENA`,
`ENUM`, `ITER` (Java iterator interface → concrete Rust iterator), `STRUCT` (a trait with
0–2 implementers is usually just a type), `PARK`, and `TODO`. `ACCEPT` is what makes a
decision *do* something: `pattern_audit.py --accepted` stops counting those types, so files
whose only remaining smell is ACCEPTed types leave the frontier with no LLM call and no park.
`SUGGEST-<VERDICT>` rows are proposals and are deliberately inert — nothing downstream honours
them until `--promote`.

`CONVENTION_FAMILIES.tsv` decides a whole naming family at once, which is what keeps the queue
tractable. Decided so far: `*Iterator` → `ITER`; `*Listener`/`*Service`/`*Provider`/`*Monitor`
→ `ACCEPT`; `*Manager` → `ARENA`. Per-type verdicts always beat family rules, and a hand-made
verdict is never recomputed when the rules change.

*The measured payoff so far:* excluding idiomatic trait objects (`dyn Error`, `dyn Any`,
`dyn Fn` — 1,745 occurrences were being scored as Java-idiom debt) plus 94 `ACCEPT` verdicts
retired **161 files** from the frontier, 1,521 rows → 1,360, with zero code changes and zero
LLM calls.

*The finding that matters most:* the 939 blocked files split into **318 decidable now** and
**582 waiting on the port** — traits whose only implementers are mocks, or `seam_stubs.rs`
placeholders, i.e. the normal mid-port state. Those cannot be decided until their
implementations land. So Phase 3 is not one blockage but two, and the larger half resolves
itself as `descent_night.sh` progresses. Phase 3 should track the port, not race it.

*On trusting the proposer:* `--suggest` infers verdicts from structural evidence (is it a
trait? how many real implementers?). Its first three rule-sets were all wrong on real data and
were corrected only because the output was checked against the source: it counted mock impls
as implementers (making `Namespace` look like a 52-variant enum), read "many implementers" as
*closed* hierarchy (proposing a 94-variant enum for `MemBuffer`), and read "no implementers"
as "shouldn't be a trait" (when 198 of those are seam stubs awaiting their port). It now
declines to guess in all three cases and records the evidence instead — 311 proposals where
the naive version made 868. Treat remaining suggestions as prompts for review, not answers.

*Sequencing constraint, found by proofing the harness (2026-08-05):* the debt graph has the
same dependency structure as the port graph, so Phase 3 cannot run ahead of Phase 2. Of the
1,416 rows eligible under `MAX_FANIN=500`, **939 (66%) are convention-blocked** — their score
is dominated by `dyn`/`Rc<RefCell<_>>`/`Arc<Mutex<_>>` over some *other* core type that has no
convention yet — and only 477 (34%) are mechanically fixable (clone/unwrap/get-set density
alone). A live single-iteration run confirmed the failure mode rather than predicting it:
`DebuggerTraceManagerService` parked because its 174 `dyn`s are all over
`Trace`/`TracePlatform`/`TraceThread`/`TraceObject`/`Target`, and `Trace` itself had already
parked for the same reason, as had its sibling `DebuggerStaticMappingService`. Three files,
one undecided convention. Turned loose on the raw priority order, the harness would park most
of what it touched and burn an LLM call per park.

`MECHANICAL_ONLY=1` (default) therefore restricts unattended runs to the 34% that need no
convention decision — rows with no `Rc`/`Arc` and fewer than `DYN_BLOCK_THRESHOLD` (5) `dyn`s.
Set `MECHANICAL_ONLY=0` once Phase 2 has decided the core-type conventions; the selector then
returns to plain priority order (verified: it picks `Trace` first again).

The Phase-2-is-human-only rule is enforced in code, not just asserted here:
`remediate_ownership.sh` skips any row whose fan-in exceeds `MAX_FANIN`
(default 500), so an unattended run works the long tail and cannot pick
`Listing`/`Function`/`DataTypeManager`/`DataType`/`DataUtilities` — all of
which sit at 1,000+ fan-in. 105 of the 1,521 rows are held back by that
default; the remaining 1,416 are eligible. Raise `MAX_FANIN` deliberately,
after Phase 2 has landed by hand. (Before this guard existed, a first
`REMEDIATE_MAX=6` run went straight at `Listing` on iteration 1 — the exact
outcome the surrounding prose warned against.)

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
  outside a porting batch (e.g. after manual/human commits). The refresh must
  pass `--preserve-status`: a plain rescan writes `TODO` for every row, so an
  unqualified refresh silently wipes every `DONE`/`PARK` recorded since the
  last audit and re-opens already-handled files. With the flag, `DONE`/`PARK`
  carry over, except that a row whose score got *worse* than the snapshot is
  reopened to `TODO` and logged — a remediation that regressed should come
  back onto the frontier.
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
