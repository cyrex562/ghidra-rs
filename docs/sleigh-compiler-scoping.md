# Sleigh Compiler Scoping — Design Spike

Status: recommendation (design-only; no source/manifest changes)
Date: 2026-07-11
Scope question: *Does ghidra-rs need to port the Sleigh spec **compiler**, or can it
consume pre-compiled `.sla` at runtime?*

---

## 1. Scope Decision (evidence)

**Decision: the runtime does NOT need the Sleigh compiler. It needs to *consume*
pre-compiled `.sla`, which it already does.** The compiler is a build-time toolchain, not
a runtime component.

Evidence, grounded in files actually read:

1. **The Rust runtime already loads compiled `.sla`.**
   `ghidra-rs/src/program/model/lang/sleigh/mod.rs` — `SleighLanguage::decode(decoder, id)`
   opens `ELEM_SLEIGH`, reads the binary attributes (`ATTRIB_VERSION`, `UNIQBASE`,
   `ALIGN`, `UNIQMASK`, `NUMSECTIONS`…), rejects `version < 4` with
   `"Unsupported .sla version: {}"`, skips the `ELEM_SOURCEFILES` block, and parses the
   address spaces + symbol table. This is a **binary/packed decoder of a compiled `.sla`**,
   not a text-grammar parser. `todo.md` (lines 119-123) marks the "SLA Loading" milestone
   — `PackedDecode`, `SleighLanguage` loader, decision tree, `resolve` — as done `[x]`.

2. **Ghidra's own runtime disassembler doesn't touch the ANTLR compiler either.**
   `orig_src/.../ghidra/app/plugin/processors/sleigh/SleighLanguage.java` imports exactly
   one symbol from the grammar package — `import ghidra.sleigh.grammar.SourceFileIndexer;`
   (line 46). No lexer, no parser, no `SleighCompile`. Ghidra runs the ANTLR compiler only
   when *building* specs from source.

3. **`.sla` is a build artifact; the repo ships only `.slaspec` source.**
   `find orig_src -name '*.sla'` → **0 files**; `-name '*.slaspec'` → **151 files**
   (e.g. `Ghidra/Processors/AARCH64/data/languages/AARCH64.slaspec`,
   `.../8085/data/languages/8085.slaspec`). `orig_src/.gitignore` line 31 is `*.sla`.
   So upstream Ghidra keeps `.slaspec` source in-tree and **compiles to `.sla` during its
   build** — the `.sla` binary is the stable ABI that the Rust runtime already reads.

4. **Project intent already treats spec/build tooling as out-of-band.**
   `AGENTS.md` (§ "areas deliberately left out … are not to be ported — tracked in
   `todo.md` under Post-Port") and `todo.md` "Future" (line 156: *"Standard file formats
   for SLA, etc."*) frame spec formats/tooling as later, native-Rust concerns rather than
   1:1 ports.

**Decisive single fact:** `SleighLanguage::decode` in
`ghidra-rs/src/program/model/lang/sleigh/mod.rs` already parses compiled `.sla` end-to-end
(version-gated binary decoder + symbol table), and the only thing Ghidra's *runtime*
imports from the grammar package is `SourceFileIndexer` — the ANTLR compiler is never on
the disassembly path.

---

## 2. Recommendation

**(A) Descope the Sleigh compiler to Post-Port / build-tooling.** Consume pre-compiled
`.sla` at runtime; obtain the `.sla` binaries by running upstream Ghidra's existing sleigh
compiler as an **external, one-time build step** over the 151 in-tree `.slaspec` files.
The `.sla` binary format (version ≥ 4) is the contract the Rust runtime already implements.

Rationale: descoping removes the single largest ANTLR-shaped blocker from the porting
frontier (see §3) for **zero runtime capability loss** — a ported disassembler needs
`.sla`, not a `.slaspec` compiler. Re-implementing an ANTLR-3 tree-grammar compiler by
hand is both high-effort and high-risk (§4) for a capability that only matters when
authoring *new* processor specs.

**Carve-outs that must still be ported regardless of this decision** (§5): the
runtime-facing, hand-written helpers `SourceFileIndexer` and
`HashMapPreprocessorDefinitionsAdapter`.

**Guardrail:** keep the ANTLR-coupled compiler classes in `PORT_PARKED.tsv` (already done)
so the nightly porter stops thrashing on the missing generated `BaseLexer`/`DisplayLexer`/
`SemanticLexer` prerequisites.

---

## 3. Cluster Inventory (what descoping removes)

Counts from `PORT_MANIFEST.tsv` (status column) and the grammar/`pcodeCPort` trees.

### 3a. `ghidra/sleigh/grammar` package — 31 files (19 DONE, 12 TODO)
The 19 DONE are hand-portable, ANTLR-runtime-independent helpers already ported into
`ghidra-rs/src/sleigh/grammar/` (e.g. `ANTLRUtil`, `LexerMultiplexer`, `Location`,
`SleighToken`, `BaseRecognizerOverride`, `RadixBigInteger`, `TokenExtractor`).
The **12 TODO** are the ANTLR-coupled / compiler-driver / test classes:

| TODO file | nature |
|---|---|
| `SleighLexer.java`, `AbstractSleighParser.java`, `AbstractSleighCompiler.java`, `SleighParserRun.java`, `SleighEchoRun.java` | generated/ANTLR-coupled — **parked**, descoped |
| `SleighPreprocessor.java` | preprocessor (modal-lex driver) — descoped w/ compiler |
| `SourceFileIndexer.java`, `HashMapPreprocessorDefinitionsAdapter.java` | **still port** (see §5) |
| `BooleanExpressionTest.java`, `BooleanExpressionDefTest.java`, `SleighPreprocessorTest.java`, `SourceFileIndexerTest.java` | tests — Post-Port |

### 3b. `pcodeCPort` package (C-sleigh backend behind the grammar) — 147 files (29 DONE, 118 TODO)
This is the C++ sleigh library ported to Java: the compiler's symbol table, pattern
algebra, equations, and templates (`SleighCompile`, `SleighBase`, `SymbolTable`,
`SubtableSymbol`, `Constructor`, `PatternExpression`/`*Equation`/`*Pattern`,
`ConstTpl`/`OpTpl`/`VarnodeTpl`, `PcodeCompile`, `SemanticEnvironment`, `MacroBuilder`…).
The brief's ~74 heaviest grammar importers live here. **118 TODO** classes — the bulk of
the current frontier in this subtree — are compiler-side and drop off if descoped. A
handful of DONE files are shared/runtime primitives already landed (`OpCode`, `spacetype`,
`Utils`, `PatternBlock`, `ErrorWarningReporter`, `DirectoryVisitor`, plus
`ghidra-rs/src/decompiler/slgh_compile/` helpers).

**Frontier removed by descoping: ~12 grammar TODO + ~118 `pcodeCPort` TODO ≈ 130 TODO
classes** (minus the two §5 carve-outs), plus the ~1.8k-LOC ANTLR-3 tree grammar and its
build prerequisites.

> Caveat on the `pcodeCPort` count: not every one of the 118 is *purely* compiler-only —
> some symbol/template types (`FixedHandle`, `ConstTpl`, `VarnodeData`) also model runtime
> concepts. If a decompiler port later needs those *data* structures, port the structs
> without the ANTLR-fed *builder* logic. Descoping targets the **compiler driver +
> grammar**, not necessarily every leaf data type.

---

## 4. Porting Method (contingency, if (A) is rejected or `.sla` supply is impractical)

Hand-porting the ANTLR-*generated* Java is the wrong move (those `.java` are build
products, which is exactly why the port parked on missing `BaseLexer`/`DisplayLexer`/
`SemanticLexer`). Two real options:

### Option 1 — `antlr4rust` (retarget the `.g` grammars to Rust). **Not viable as-is.**
- The grammars are **ANTLR 3**, and two of them are **tree grammars**:
  `SleighCompiler.g` (`tree grammar`, 1833 LOC, `ASTLabelType=CommonTree`,
  `tokenVocab=SleighLexer`) and `SleighEcho.g` (`tree grammar`, 498 LOC).
  `SleighParser.g` uses `output=AST` and `import DisplayParser, SemanticParser`.
- **ANTLR 4 dropped tree grammars entirely** (replaced by listeners/visitors), and
  `antlr4rust` targets ANTLR 4. So this is *not* a mechanical retarget: you would first
  rewrite all 12 grammars from ANTLR-3-with-tree-passes into ANTLR-4 parse-tree +
  visitors, then re-express every embedded Java action in Rust. The lexer is also
  **modal/multiplexed** (`LexerMultiplexer`, `SleighPreprocessor`) because, per the
  package `README.txt`, "ANTLRv3 does not support modal lexing natively" — ANTLR4's lexer
  modes help but don't map 1:1 to the existing multiplex hack.

### Option 2 — Rewrite native in Rust (**recommended if forced to port**).
- **Lexer:** `logos` (fast, declarative), with an explicit mode/multiplex layer replacing
  `LexerMultiplexer` + a small preprocessor pass replacing `SleighPreprocessor` /
  `HashMapPreprocessorDefinitionsAdapter`.
- **Parser:** `chumsky` (ergonomic error recovery, good for a hand-shaped AST) or
  `LALRPOP`. Build a first-class Rust AST instead of ANTLR `CommonTree`.
- **Tree passes:** re-implement `SleighCompiler.g` / `SleighEcho.g` as ordinary Rust AST
  walks that drive the `pcodeCPort` symbol/pattern/template backend — which is *already
  partly ported* (`ghidra-rs/src/decompiler/slgh_compile/`,
  `ghidra-rs/src/decompiler/slghsymbol/`).

**Effort: L–XL (multi-week, single focused engineer).**
Drivers: ~4,000 grammar LOC across 12 files (SleighCompiler.g alone ~1,833 with ~1,000+
action-bearing lines); modal-lex + preprocessor semantics; ~74-118 backend classes the
tree passes call into. This is a *language-implementation project*, not a translation.

**Top risks:** (1) embedded-action semantics in the tree grammar are subtle and
undocumented — behavioral parity with the C/Java sleigh is hard to verify; (2) the
modal-lex / multiplexer hack has no clean Rust analogue; (3) exact `.sla` byte-output
parity is required or every processor spec must be re-validated; (4) it re-couples the
port to a component the runtime never calls, expanding the frontier by ~130 classes for no
disassembly capability.

---

## 5. Port-Regardless Carve-outs
Independent of the compiler decision, these hand-written, portable classes belong in the
port and should stay TODO (not parked):
- **`SourceFileIndexer.java`** — imported directly by the **runtime**
  `SleighLanguage.java`; the Rust decoder already *skips* the `ELEM_SOURCEFILES` block, so
  full fidelity (source-file line attribution in diagnostics) needs this ported.
- **`HashMapPreprocessorDefinitionsAdapter.java`** — small, ANTLR-independent map adapter;
  cheap to port and useful if any preprocessing is later needed.

---

## 6. Concrete Next Steps
1. **Adopt (A).** Record in `todo.md` "Post-Port": *"Sleigh spec compiler
   (`ghidra.sleigh.grammar` ANTLR-3 + `pcodeCPort` slgh_compile) — build-time tooling;
   runtime consumes pre-compiled `.sla`."*
2. **Keep the ANTLR-coupled grammar + `pcodeCPort` compiler classes parked** (already in
   `PORT_PARKED.tsv`) so the nightly porter stops thrashing.
3. **Un-park / keep TODO the two §5 carve-outs** (`SourceFileIndexer`,
   `HashMapPreprocessorDefinitionsAdapter`) and port them as ordinary Rust.
4. **Establish a `.sla` supply**: run upstream Ghidra's sleigh compiler over the 151
   in-tree `.slaspec` once, and ship/generate the `.sla` alongside the Rust build (they
   are the ABI `SleighLanguage::decode` already reads). Add a `docs`/build note describing
   this external step. Add a couple of committed `.sla` fixtures for runtime tests.
5. **Revisit only if** authoring *new* processor specs in-tree becomes a goal — then take
   Option 2 (native Rust rewrite), not antlr4rust.
