# AST-Foundation Transpiler — Design & ROI Spec (#4)

Status: **proposal for decision** (build vs defer). Author: harness maintainer. Date: 2026-08-04.

## 1. Why (problem + research verdict)
The nightly LLM porter costs ~$1–4 and 3–25 min/class, and iteration count is the throughput
bottleneck. A large fraction of remaining classes are *mechanical* boilerplate that should never
touch the LLM. We already have `scripts/transpile_datatypes.py` (regex) covering ~26 of the simplest
DataTypes — but regex is a hard ceiling: it cannot reason about resolved types, so it can't scale to
other families or to classes with any semantic nuance.

Research verdict (2026-08-04, cited report): **no turnkey Java→Rust transpiler exists** and repo-level
LLM Java→Rust is only ~31–45% pass@1 (94.8% of failures are compile errors) — so blind transpilation
is out and our trait-seam + verify-first approach is correct. The recommended upgrade: drive
deterministic transpilation off a **real Java AST + symbol resolver**, emit the mechanical 80%
deterministically, and keep the LLM for the semantic 20% (ownership, inheritance shape, exceptions).

## 2. Scope & ROI (grounded)
Remaining unported in-scope classes: **7,075**. Cleanly-mechanical families:

| Family | Count | Median lines | Transpile confidence |
|---|---|---|---|
| Java `enum` | 309 | 134 | High (constants + small methods) |
| `*Exception` | 40 | 38 | Very high (→ Rust error enum/struct) |
| `*DataType` | 148 | 71 | High (regex already does ~26; AST does more) |
| small interfaces (<60 ln) | 247 | — | High (→ trait decl) |
| **subtotal** | **~744** | | |
| value-objects/records in "other" | ~100–400 (est.) | — | Medium |

**Realistic deterministic ceiling: ~600–900 classes (~9–13% of remaining).** At ~$2/class and ~8
min/class that's **~$1.2k–1.8k and ~80–120 model-hours removed** from the LLM loop, deterministically
and with generated tests — plus it takes the *most formulaic, lowest-learning-value* work off the loop
so LLM spend concentrates on the semantic 20%.

Non-goals: the semantic 20% (inheritance→trait/enum/composition choice, shared-mutable graphs →
`Rc`/`Arc`/`Weak`, exception-as-control-flow, generics variance, reflection). The transpiler **marks**
these as seams; it does not resolve them.

## 3. Architecture (three stages, decoupled by JSON)
```
Java source ──▶ [Stage 1: JVM helper]  JavaParser + JavaSymbolSolver
                     │  parse + resolve types/symbols (feed dep jars/sources via TypeSolver)
                     ▼
              resolved-AST.json  (nodes carry RESOLVED types, not just syntax)
                     │
              [Stage 2: Python emitter]  consumes JSON, per-family rules
                     │  "lower-ugly-then-refactor": emit correct-but-plain Rust
                     │  exhaustive node coverage; any unhandled node → `// TRANSPILER-UNIMPL: ...`
                     ▼
        Rust file(s) + mod.rs wiring + #[cfg(test)] + a per-class VERDICT:
              FULL  (no unimpl markers → mark DONE, LLM never sees it)
              PARTIAL (has markers → hand to LLM as a pre-filled skeleton = #2 skeleton-first)
```
- **Stage 1 (JVM helper):** small Maven/Gradle project, one entrypoint: `java -jar astdump.jar Foo.java`
  → JSON. JavaParser+SymbolSolver (Apache-2.0/LGPL) is the default (cleanest AST→JSON; keeps emission
  logic in our existing Python). Spoon (MIT, ships a `Processor` transform framework) is the
  alternative if we'd rather do transforms JVM-side.
- **Stage 2 (Python):** replaces the regex in `transpile_datatypes.py` with an AST consumer; the
  existing family logic becomes the first rule-set. Type mapper: primitives, String, collections
  (Vec/HashMap/BTreeMap/BinaryHeap; indexmap/fixedbitset for LinkedHashMap/BitSet), null→Option,
  checked-exception→Result skeleton, interface→trait, unknown in-repo type→`&dyn T`/`Box<dyn T>`.
- **Verification:** generated Rust is compiled (`cargo build --lib`) + generated tests run, in the
  MAIN checkout (worktrees can't compile until the `.gitignore debug/` defect is fixed — see §6).

## 4. Design principles (stolen from proven transpilers)
1. **Lower-ugly-then-refactor** (C2Rust): emit correct-but-non-idiomatic Rust deterministically;
   idiomatization is separate optional passes. Don't block on pretty.
2. **Exhaustive node coverage + `unimplemented` markers** (Corrode): every AST node is either handled
   or emits an explicit marker → precise FULL-vs-PARTIAL verdict, discoverable gaps.
3. **Own the semantic model** (CxGo): rules fire on *resolved types*, not text.
4. **Ownership as explicit seams** (j2objc playbook): `Rc`/`Arc`/`Weak` + reference cycles are the #1
   irreducible gap — emit annotated seams + optionally a cycle-finder; never `Arc<Mutex<_>>`-soup it.
5. **Ship a small runtime shim crate** for recurring Java-ism helpers (sharpen/j2objc precedent).

## 5. Effort estimate (phased; ~2.5–3.5 focused weeks total)
| Phase | Deliverable | Effort |
|---|---|---|
| P1 | JVM helper: JavaParser+SymbolSolver → resolved-AST JSON (+ TypeSolver wired to ghidra deps) | 2–3 d |
| P2 | Python AST-consumer framework: node walker, type mapper, FULL/PARTIAL verdict, unimpl markers | 3–4 d |
| P3 | Rule-set: `*Exception` (fast win) → enums → small interfaces → port `*DataType` regex logic onto AST | 4–6 d |
| P4 | Harness integration: pre-pass transpiles FULL classes → mark DONE/exclude; PARTIAL → skeleton to LLM (#2) | 2 d |
| P5 | Ownership seams + cycle-finder + runtime shim crate (incremental) | ongoing |
Each family after P3 is ~0.5–1 d of new rules. Toolchain adds a JVM build dependency to the repo.

## 6. Risks & dependencies
- **JVM dependency:** repo now needs a JDK + Maven to build the helper. Mitigate: check in a prebuilt
  `astdump.jar`, JVM only needed to rebuild it.
- **`.gitignore debug/` defect** (known): must be fixed first so generated code compiles in worktrees /
  clean checkouts and so validation is reliable. Small enabling fix.
- **Symbol resolution needs the dep classpath:** SymbolSolver must see referenced types; feed it the
  ghidra source tree as a SourceTypeSolver. Unresolved symbols → PARTIAL (graceful, not a crash).
- **Maintenance:** a rule engine is code to own; but far less than the alternative (LLM-porting 700+
  formulaic classes and re-reviewing them).
- **The 20% is still the 20%:** this removes volume, not the hard ownership work.

## 7. Integration with the existing harness
- New `desc_order` pre-pass (or standalone `transpile_pass.py`): for each pending class, run the
  transpiler; if verdict FULL → write Rust, wire mod.rs, `cargo build --lib` gate, mark DONE, skip LLM.
  If PARTIAL → stash the skeleton for the LLM port as pre-filled scaffold (this IS item #2).
- Fits the current model: deterministic scaffold + LLM-for-the-20%, gated by build+test (our rule).

## 8. Recommendation
Build it, staged, **but gate P1 on a spike**: first prove the JVM-helper→JSON→emitter path on the
`*Exception` family (40 classes, simplest, fast) end-to-end (compiles + tests). If the spike lands
clean, the ROI (~600–900 deterministic ports) justifies P2–P4. If the AST plumbing proves heavier than
estimated, we still have the regex transpiler for the DataType family and fall back to LLM for the rest.
**Suggested go/no-go: the P1+P3-exception spike (~3–4 days).**
