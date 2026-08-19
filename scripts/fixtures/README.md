# SLA fixture generation (separate task)

Tooling to produce **golden `.sla` fixtures** for validating the in-port Sleigh
spec compiler. This is deliberately decoupled from the port: the ghidra-rs runtime
only *consumes* pre-compiled `.sla`, so these fixtures exist to check the future
in-port compiler (`.slaspec` → `.sla`) for parity against upstream Ghidra.

## Why this is needed
The repo ships **zero `.sla`** (they're build artifacts). The round-trip harness
needs a reference to diff against, and there is no locally-installed Ghidra to
generate one. These scripts download an official Ghidra release and run its sleigh
compiler over a curated set of in-tree `.slaspec`.

## Usage
```bash
scripts/fixtures/setup_ghidra.sh        # downloads Ghidra -> tools/ghidra-dist/ (gitignored)
scripts/fixtures/gen_sla_fixtures.sh    # compiles specs -> ghidra-rs/tests/fixtures/sla/
```
Prereqs: `curl`, `unzip`, and a **JDK 21+** (for Ghidra 11.x). Pin a specific
release with `GHIDRA_ZIP_URL=<...ghidra_*_PUBLIC_*.zip> scripts/fixtures/setup_ghidra.sh`.

## Outputs
- `tools/ghidra-dist/` — the Ghidra install (gitignored, ~1GB).
- `ghidra-rs/tests/fixtures/sla/*.sla` — golden fixtures (committed; small).
  `.slaspec` inputs stay in `orig_src/` (present locally, gitignored like all Java source).

## Round-trip harness (once the front-end exists)
`.slaspec` → in-port compiler → `.sla` → existing Rust decoder
(`ghidra-rs/src/program/model/lang/sleigh`) → model, compared byte/semantically
against the golden `.sla` here. Record the exact Ghidra version used so parity is
reproducible (SLA format is version-gated; the Rust decoder requires version ≥ 4).
