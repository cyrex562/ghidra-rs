# Qt6 UI — U2c Listing Navigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the spec §5 "M1 scope" listing interactions that need no code units: cursor, keyboard navigation, selection, word-under-cursor highlight, Go To address, and back/forward history. All of them work over `MemoryListing`.

**Architecture:**
- All listing view state moves into a Rust `ListingController`: top, cursor, selection anchor, selection, highlight word, history, and a pending "reveal cursor" flag. The controller owns the `ListingViewModel`.
- `ViewModelBox::Listing` holds a `ListingHandle` (`Arc<Mutex<ListingController>>`). Actions get a clone of the handle. Lock order is always session, then controller.
- C++ sends intents: key, click, wheel, scrollbar value and resize. It paints a `ListingFrame` pulled from Rust that carries rows, cursor/selection/highlight rectangles and the scrollbar state. U2a's U2a-era bridge functions (`listing_hit`/`move`/`scroll`/...) are replaced.
- Go To needs a text prompt. A generic prompt primitive is added: Rust posts `UiEvent::Prompt`, C++ shows `QInputDialog`, and the reply goes to `prompt_reply(id, text?)`. Rust runs the handler the action registered.

**Tech Stack:** Rust (`ghidra-rs`, `ghidra-ui-model`), cxx bridge, Qt6 Widgets.

**Spec:** `docs/superpowers/specs/2026-10-01-qt6-ui-design.md` §3 (bridge rules), §5 (M1 scope).

## Global Constraints

- No domain logic in C++. C++ maps Qt events to intents and paints frames.
- Every UI-path call reads a snapshot and takes under 8 ms.
- Rust never calls C++. Every `extern "Rust"` function goes through `guard()`, with its parsing done inside the closure.
- Guardrails:
  - `CARGO_BUILD_JOBS=4`;
  - no builds under /tmp;
  - wt_test.sh syncs only the files this plan touches, never whole `ghidra-rs/src`, because sibling WIP lives there;
  - stage paths explicitly and check `git diff --cached --name-only` before committing.

## Java parity notes (sources read)

- **`HistoryList`** (inner class of NavigationHistoryPlugin.java:453):
  - Adding a location truncates the entries after the current one.
  - A location equal to the last entry replaces it.
  - The list is capped at the maximum (default 30) by dropping the oldest.
  - The current position is always the last entry after an add.
- **`previous()`** first adds the navigatable's current location, but only if there is no next entry. It then steps back.
- **GoTo** (`GoToService`) records the from-location and then the to-location.
- **Go To key binding:** `G` ("Go To Address/Label").
- **Previous/Next Location:** Alt-Left / Alt-Right.
- **Cursor text highlight:** triggered by the middle mouse button by default. It highlights every occurrence of the word under the cursor in visible fields.
- **Shift+cursor keys and shift-click** extend the selection from an anchor.

## Review Focus

1. **Back right after a goto**, before any other move, returns to the pre-goto location. Forward then returns to the goto target.
2. **History capped at 30:** the oldest entry is dropped and the current index stays valid.
3. **Selection across a gap** between blocks: indices are dense, so the selection is contiguous in index space. Shift-End and Shift-Home must not overflow.
4. **A Go To prompt for a bad address or an address in a gap** gives a status message. The cursor and history stay unchanged.
5. **A prompt reply for an unknown or already-answered id** is an error, not a panic, and the handler never runs twice.

---

### Task 1: `HistoryList<T>` port

**Files:** `ghidra-rs/src/app/plugin/core/navigation/history_list.rs` (plus the `mod` entries).

**Interfaces:**
- `HistoryList<T: PartialEq + Clone>::new(max)`
- `add(T)`
- `has_next()`, `has_previous()`
- `next() -> Option<T>`, `previous() -> Option<T>`
- `current() -> Option<&T>`
- `len()`
- `set_max(n)`
- `previous_locations()`, `next_locations()`

**Tests** (from the Java semantics):
- truncates forward entries on add;
- an equal last entry is replaced, not duplicated;
- the cap drops the oldest;
- next and previous at the ends return None.

### Task 2: `IndexSelection`

**Files:** `ghidra-ui-model/src/listing_selection.rs`.

A sorted, merged set of inclusive `u128` ranges. This is `FieldSelection` at whole-layout granularity; the listing selects whole code units.

**Interfaces:**
- `clear()`
- `set_range(a, b)` (order-insensitive)
- `contains(i)`
- `ranges()`
- `is_empty()`

**Tests:**
- order-insensitive ranges;
- `u128::MAX` bounds;
- contains on the edges.

### Task 3: `ListingController`

**Files:** `ghidra-ui-model/src/listing_controller.rs`.

**Interfaces:**
- `ListingHandle = Arc<Mutex<ListingController>>`, built with `ListingController::handle(model)`.
- Intents:
  - `set_metrics(FontMetrics)`
  - `set_viewport(px)`
  - `key(Move, extend: bool)`
  - `click(x, y, extend)`
  - `middle_click(x, y)` sets the highlight word, or clears it on empty.
  - `wheel(rows: i64)`
  - `set_scroll_value(i32)`
  - `goto_address(u64) -> Result<(), String>`. It records history (from, then to) and reveals the cursor.
  - `back()`, `forward()`. These follow Java `previous`: add the current location if there is no next entry.
- `frame() -> ListingFrame { top, rows: Vec<FrameRow{row: FieldRow, cursor: Option<(x,w)>, selected: bool, highlights: Vec<(x,w)>}>, scroll: (max, page_step, value), location_text }`.
- A history memento is a `CursorPos`. Equality is by index, matching Java's address-based `LocationMemento` equality closely enough for undefined bytes.
- `move_cursor` gets a field clamp (fixes deferred minor M4).

**Tests:** cover Review Focus 1–3. The frame shows the cursor rect and the selected flags. A middle click on "55" highlights every visible "55" run.

### Task 4: Prompt primitive and navigation actions

**Files:**
- `ghidra-ui-model/src/{events.rs, session.rs, demo_tool.rs}`
- `ghidra-qt/src/bridge.rs`
- `ghidra-qt/cpp/main_window.cpp` (prompt handling in the event pump)

**Interfaces:**
- `UiEvent::Prompt { id: u64, title, label, initial }`
- `UiEventQueue::prompt(title, label, initial, handler: Box<dyn FnOnce(Option<String>) -> Result<(), String> + Send>) -> u64`
- `UiSession::prompt_reply(id, Option<String>) -> Result<(), String>`. An unknown id is an error. When the handler returns Err, Rust posts a Status event.
- Demo actions on the Listing provider: "Go To..." (`G`, Navigation menu), "Previous Location" (Alt-Left) and "Next Location" (Alt-Right), all with toolbar entries.
- The Go To parser accepts `0x402000`, `402000` and `402000h`.

**Tests:**
- the prompt round trip;
- a double reply is an error;
- a bad address gives a status message and leaves the controller unchanged (Review Focus 4 and 5).

### Task 5: Bridge and C++ `ListingView` over frames

**Files:**
- `ghidra-qt/src/bridge.rs`: `listing_frame(pid, viewport) -> FrameInfo`, `listing_intent(pid, IntentInfo)`, `prompt_reply`.
- `ghidra-qt/cpp/views/listing_view.{h,cpp}`
- `app.cpp`: smoke flag `--listing-intents "<k=v;...>"`, which dumps the resulting frame.

**C++:** ListingView keeps no index state. It paints:
- the selection background;
- highlight rects;
- the cursor bar.

The status bar shows `location_text`.

**Smoke tests:**
- goto 0x402000, then back, then forward: the dumped top/cursor lines match;
- shift-down ×3 selects 4 rows.

## Milestone note

The U2b code-unit listing slots into `ListingController` unchanged, because it only implements `ListingViewModel`.
