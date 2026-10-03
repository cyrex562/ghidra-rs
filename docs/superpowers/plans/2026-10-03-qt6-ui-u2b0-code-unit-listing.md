# Qt6 UI — U2b-0 Code-Unit Listing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans.

**Goal:** A `ListingViewModel` over code units and labels, the step between the byte-per-row `MemoryListing` and U2b's `FormatManager`/`FieldFactory` port.
- An instruction is one row spanning its length: address, its bytes, mnemonic and operands.
- Undefined bytes stay one row each (`??`).
- Each label gets its own row above the code unit at its address (Ghidra's Label field sits above the code unit).

`--open` uses it immediately with the ELF's symbols as labels. Instructions plug in when C2 lands.

**Architecture:**
- `ghidra-ui-model::code_unit_listing`:
  - **Inputs:** `CodeUnitListing::new(bits, blocks: Vec<MemoryBlockSnapshot>, instructions: Vec<InstructionSnapshot{start, len, mnemonic, operands}>, labels: Vec<LabelSnapshot{address, name}>)`.
  - **Row index space:** precomputed segments (a label row, an instruction row, or a run of undefined bytes). Each segment knows its first row; lookups binary-search them. The memory cost is linear in segments, not bytes.
  - **Trait:** implements `ListingViewModel` unchanged: rows/hit_test/move_cursor/goto/address_text/cursor_x/field_text.
  - **Goto:** `goto(address)` goes to the first row at that address, its label if it has one. An address inside an instruction goes to that instruction's row.
- **Fields:**
  - Address, Bytes (space-separated hex, clipped by the field like Ghidra's), Mnemonic, Operands (instruction text; `NNh` for undefined).
  - A label row has one field at the Bytes column with the label name.
  - Undefined rows render exactly as `MemoryListing`, which is regression-tested.
- **`program_import`:** builds a `CodeUnitListing` with labels from the imported symbols. The demo uses it when `--open` is given.

## Review Focus
1. An address inside an instruction: `goto` lands on the instruction row and `address_text` is its start.
2. Several labels at one address: one row each, primary first, then by name. The order is stable.
3. An instruction crossing a block gap or end is clamped to its block. No panic on a bad snapshot.
4. Row counts and index ↔ address mapping at block boundaries; empty memory.
5. `rows()` latency over a 1M-row listing: binary search, never a linear walk.
