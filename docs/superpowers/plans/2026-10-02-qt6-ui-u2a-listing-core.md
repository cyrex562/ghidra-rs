# Qt6 UI — U2a Listing Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a custom-painted Qt `ListingView` that scrolls a program's whole address space through a Rust listing view-model. In this plan the rows come from memory: undefined bytes are shown as Ghidra shows them. Rows are laid out in Rust from renderer-supplied font metrics.

**Architecture:** Three toolkit-neutral pieces sit in `ghidra-rs`:

| Piece | What it is |
|---|---|
| fieldpanel core: `Field`, `TextField`, `FieldElement`, `Layout`, `FieldLocation` | ports from `docking.widgets.fieldpanel` |
| `AddressIndexMap` | BigInteger index ↔ address over an `AddressSetView` |
| `FontMetrics` | char width per style, ascent, descent |

**`ghidra-ui-model`** defines a `ListingViewModel` trait:
- `layouts_for_range(top_index, viewport_px) -> Vec<FieldRow>` (positioned `StyledRun`s)
- `hit_test`
- cursor movement
- `goto`

**`MemoryListing`** implements the trait over `Memory`, with one row per undefined byte. Its row format matches Ghidra's default for undefined data: `address`, `bytes`, `??`, `NNh`.

**`ghidra-qt`** adds `ListingView : QAbstractScrollArea`. It paints the returned runs, keeps a scaled scrollbar over the index space, and forwards keys and clicks as intents.

**What waits for U2b:** the real `FieldFactory`/`FormatManager` port, with instructions, labels and comments, needs C2 (`InstructionDB`/`CodeManager`).

**Spec:** `docs/superpowers/specs/2026-10-01-qt6-ui-design.md` §5.

## Global Constraints

- Layout math is Rust-only. C++ supplies `FontMetrics` once at startup and again when the font changes. It paints only what `layouts_for_range` returns.
- Every UI-path call reads from a snapshot and must take under 8 ms. Provide a `cargo test` latency test over a 1,000,000-byte block.
- Address-space scrolling must work over 64-bit spaces: the index type is `u128` (Java uses `BigInteger`).
- Guardrails: `CARGO_BUILD_JOBS=4`, no builds under /tmp, row-scoped TSV staging, verify the index before committing, and use `.superpowers/tools/wt_test.sh` while sibling WIP breaks the shared tree.

## Review Focus

1. **Scrolling past the last address, or above the first.** Clamp; never panic, never wrap.
2. **Address sets with gaps** (non-contiguous blocks): indices stay dense and the gap is not rendered as rows.
3. **Huge address spaces** (blocks near `0xffff_ffff_ffff_0000`): no overflow in index math (`u128`).
4. **A font change while scrolled:** the layout is recomputed and the top address stays put.
5. **Hit-testing past the end of a row, or between fields:** snaps to the nearest valid field column, as Java's `FieldLocation` does.

---

### Task 1: Field-panel core (`FontMetrics`, `FieldElement`, `TextField`)

**Files:** `ghidra-rs/src/docking/widgets/fieldpanel/{font_metrics.rs, field_element.rs, text_field.rs}` (add `mod` entries).

**Interfaces:**
- `FontMetrics { char_width: [u16; 3] /*plain, bold, italic*/, ascent, descent, leading }`, with `string_width(&str, style)`.
- `FieldElement`, a port of `TextFieldElement` + `AttributedString`: text plus color id plus style, with `width(&FontMetrics)`.
- `TextField`, a port of `SimpleTextField`/`ClippingTextField` for one row:
  - `new(elements, start_x, width, metrics)`
  - `num_cols(row)`, `x(row, col)`, `col(row, x)`, `text()`
  - `is_valid(row, col)`
  - clipping with an ellipsis exactly as `ClippingTextField` does.

**Tests (Java-derived):**
- `x`/`col` round trips;
- clipping at a narrow width shows the `…` element with the right column count;
- `col` for an x past the end snaps to the last column.

### Task 2: `Layout` (`SingleRowLayout`/`RowLayout`) + `FieldLocation` + hit-testing

**Files:** `ghidra-rs/src/docking/widgets/fieldpanel/{layout.rs, field_location.rs}`.

**Interfaces:**
- `Layout`: ordered fields, `height()`, `field_index_at(x)`, `cursor_location(x, y) -> FieldLocation`.
- `FieldLocation { index: u128, field_num, row, col }`.

**Tests:**
- an x between fields snaps to the nearest field;
- `cursor_location` on the right edge gives the last column (Review Focus 5).

### Task 3: `AddressIndexMap`

**Files:** `ghidra-rs/src/app/util/viewer/util/address_index_map.rs`.

**Interfaces:** a port of `ghidra.app.util.viewer.util.AddressIndexMap`, with `u128` indices:
- `new(addresses: &dyn AddressSetView)`
- `index_count() -> u128`
- `address(index) -> Option<Address>`
- `index(address) -> Option<u128>`
- `index_after`/`index_before`

**Tests:**
- gaps between blocks give dense indices;
- an address in a gap has no index;
- a block near the top of a 64-bit space doesn't overflow;
- the boundary indices `0` and `count-1` (Review Focus 2 and 3).

### Task 4: `ListingViewModel` + `MemoryListing` (ghidra-ui-model)

**Files:** `ghidra-ui-model/src/listing.rs`.

**Interfaces:**
- `FieldRow { index: u128, y: i32, height: i32, runs: Vec<PositionedRun{ x, text, color_id, bold }> }`.
- `CursorPos { index: u128, field: u32, col: u32 }`.
- `trait ListingViewModel`:
  - `set_metrics(FontMetrics)`
  - `index_count() -> u128`
  - `rows(top: u128, viewport_px: i32) -> Vec<FieldRow>`
  - `hit_test(index, x) -> CursorPos`
  - `move_cursor(CursorPos, Move::{Up, Down, Left, Right, PageUp, PageDown, Home, End}) -> CursorPos`
  - `goto(address: u64) -> Option<u128>`
  - `address_text(index) -> String`
- `MemoryListing`, an implementation over a `Memory` snapshot. Each undefined byte is one row with four fields:
  - Address `"00401000"` (zero-padded hex to the address size);
  - Bytes `"55"`;
  - Mnemonic `"??"`;
  - Operand `"55h"`.

  Column widths come from the metrics.
- `ViewModelBox::Listing(Box<dyn ListingViewModel>)`.

**Tests:**
- row text for a known byte sequence;
- scrolling clamps at both ends (Review Focus 1);
- a `goto` into a gap returns `None`;
- a latency test: `rows()` over a 1M-byte block, 100 random tops, each under 8 ms (debug build: under 40 ms, documented as `cfg(debug_assertions)`);
- a metrics change keeps the row at `top` (Review Focus 4).

### Task 5: Bridge + C++ `ListingView`

**Files:** `ghidra-qt/src/bridge.rs` (listing fns), `ghidra-qt/cpp/views/listing_view.{h,cpp}`, `views.cpp` (kind 4), `build.rs`.

**Bridge functions:**
- `listing_set_metrics(pid, MetricsInfo)`
- `listing_index_count(pid) -> String` (u128 as decimal)
- `listing_rows(pid, top: &str, viewport: i32) -> Vec<RowInfo>`
- `listing_hit(pid, index: &str, x) -> CursorInfo`
- `listing_move(pid, CursorInfo, dir: u8) -> CursorInfo`
- `listing_goto(pid, address: u64) -> String` (empty if none)

**C++:**
- `ListingView` paints runs and the cursor and selection backgrounds.
- The scrollbar maps 0..1,000,000 linearly onto the `u128` index space, as Java's `IndexedScrollPane` does.
- Keys go to `listing_move` before the Rust action dispatch; that is the field-panel focus behaviour.

**Smoke tests:**
- `--dump-listing <n>` prints the first n rows' text;
- a screenshot shows listing rows.

### Task 6: Demo program in the Qt shell

**Files:** `ghidra-ui-model/src/demo_tool.rs`.

Add a "Listing" provider (`ProviderViewKind::Listing`, CENTER/STACK) backed by `MemoryListing`. Use a real ProgramDB built by the core track's ELF loader if it's available. Otherwise use a synthetic `MemoryMapDB` with two blocks and a gap.

**Smoke test:** `--dump-listing 3` shows the first three undefined-byte rows of the first block.

## Milestone note

U2b ports `FormatManager` and the core `FieldFactory`s (Address, Bytes, Mnemonic, Operand, Label, EOL/Plate comments) over real code units once C2 lands. It then replaces `MemoryListing` and adds the golden-text parity test against stock-Ghidra output (spec §6).
