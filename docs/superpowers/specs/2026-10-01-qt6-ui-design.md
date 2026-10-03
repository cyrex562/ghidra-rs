# Qt6 UI for ghidra-rs: design (Milestone 1)

Date: 2026-10-01 · Status: approved in conversation, pending written-spec review

## 1. Intent

Build a desktop UI for ghidra-rs that works the way Ghidra's Swing UI does, in **Qt6**. IDA Pro is the
reference for quality. This is not a port of Ghidra's appearance: users keep Ghidra's tools,
layouts, action names, keybindings and listing format, rendered in native Qt.

Decisions (user, 2026-10-01):

| Topic | Decision |
|---|---|
| Toolkit | Qt6 **Widgets** (not QML, not Tauri, not egui) |
| Language split | A thin C++17 Qt shell, with all logic and state in Rust, joined by a `cxx` bridge |
| Build | Cargo-driven: `build.rs` uses `cc` plus `qt-build-utils` (moc); Qt6 linked dynamically (LGPL) |
| Docking | Qt Advanced Docking System (ADS, LGPL-2.1), vendored |
| Pane model | Plugins stay pure Rust and describe panes through generic view-model traits. C++ has one generic widget per view kind, plus a few bespoke custom-painted widgets. |
| Bridge model | **A**: synchronous snapshot reads for visible data, an async event queue for changes, worker-thread tasks for slow work |
| WASM UI | Dropped. Desktop only (Linux, Windows, macOS). WASM stays a target for scripts and plugins. |
| Script/plugin UI | Later, through the same Rust view-model API and the standard ask* dialogs. No PySide6 in the process. |
| Look & feel | Ghidra layouts, actions and keybindings; Qt Fusion style driven by Ghidra's theme IDs; light and dark |
| Execution | Agents implement within this spec. A human review gate closes every milestone. New view kinds and UX deviations park for the human. |
| Milestone 1 | The docking framework plus the listing, showing a real imported ELF with disassembled instructions |
| Core dependency | A parallel core track. `.sla` files come from the **Rust sleigh compiler only**. |
| Listing parity reference | The human runs a stock Ghidra release once to export golden listing text |

Out of scope for this spec: everything after Milestone 1 (decompiler view, project window, symbol tree,
data type manager, graphs, debugger, version tracking). Each later milestone gets its own spec and plan.

## 2. Architecture and crates

```
ghidra-rs/          existing lib: model, program DB, analysis, plugins. NO Qt, NO egui.
ghidra-ui-model/    new lib: toolkit-neutral UI model (pure Rust, unit-tested)
ghidra-qt/          new bin: cxx bridge + C++ Qt6 Widgets shell + vendored ADS
```

- **ghidra-rs** stays toolkit-free. The remaining Java *model* classes of the docking, tool and listing
  framework are ported here as ordinary Rust, under the existing AGENTS.md rules (shape rules, DONE
  definition): `Tool`, `PluginTool`, `ComponentProvider`, `DockingAction` with its menu, toolbar, popup
  and key-binding data, `FormatManager`, `FieldFactory` and the core factories, `ProgramBigListingModel`,
  `AddressIndexMap`, and the non-visual `docking.widgets.fieldpanel` layout types. `java.awt` values use
  the toolkit-neutral `util` types (`Color`, `Font`, `KeyStroke`, `ActionTrigger`) decided 2026-10-01.
- **ghidra-ui-model** is the contract between the model and any renderer:
  - View-model traits: `TableModel` (rows, columns, sort, filter, edit), `TreeModel`, `TextModel`
    (styled lines with hyperlinks), `FormModel` (option and edit dialogs), `ListingModel` (field layouts,
    hit-testing), and `CustomView` (an escape hatch for bespoke widgets).
  - The UI session: open tools, the provider registry, the action and key-binding registry, layout
    persistence, the `UiEventQueue`, and task and progress plumbing.
  - All of it is testable with `cargo test` and no Qt.
- **ghidra-qt** is the only crate that links Qt:
  - `src/bridge.rs` holds the `cxx` bridge.
  - `cpp/` holds the C++ shell: `MainWindow`, the ADS dock manager, the generic widgets
    (`RustTableModel : QAbstractTableModel`, `RustTreeModel : QAbstractItemModel`, `StyledTextView`,
    `FormView`), and the bespoke `ListingView`.
  - `build.rs` compiles the C++ and ADS and runs moc.
  - **C++ contains no domain logic.** It renders what view-models return and forwards user intents.
- The egui and eframe dependencies and the placeholder egui `main.rs` window are removed. AGENTS.md's UI
  sections are rewritten to say Qt6, to point at this spec, and to make UI work agent-executable within
  the spec.

## 3. Bridge and threading contract

**Threads**
- **Qt main thread.** It is the only thread that touches widgets. It calls Rust synchronously for visible
  data only.
- **Rust worker pool.** It runs every `Task` (import, analysis, disassembly, decompile, search, save).
  Each task reports progress through `TaskMonitor`, which becomes progress events.
- **Domain-object edits.** Short single-transaction edits (rename, set comment) may run inline on the UI
  thread as intents. Anything else runs as a Task.

**UI-path contract**
1. UI-thread calls read from an **immutable ProgramDB snapshot** (the snapshot+transaction convention).
   They never take transaction locks and never do I/O.
2. Each call has a budget of **8 ms**. Debug builds time every bridge call and log any that exceed the
   budget. Work that could exceed it must be a Task.
3. User input reaches Rust as **intents**: `invoke_action`, `goto`, `edit_cell`, `context_menu`,
   `focus_changed`, `selection_changed`, `dispatch_key`.

**Change propagation**
- Rust has one MPSC `UiEventQueue`. Its events are `DomainChanged{object, ranges}`, `TaskProgress`,
  `TaskDone`, `ProviderAdded/Removed`, `ActionsChanged` and `LocationChanged`.
- C++ is woken by a `QSocketNotifier` on an eventfd or pipe (a posted event on Windows). It drains the
  queue on the UI thread, coalesced per frame.
  - `DomainChanged` means: take a new snapshot, then emit `dataChanged` or `layoutChanged`.
  - Progress events update the status bar and the task dialog.

**FFI shape**
- Opaque Rust handles (`UiSession`, `ProviderHandle`, `TableModelHandle`, `ListingModelHandle`, ...)
  cross to C++.
- Plain data crosses as `cxx` shared structs (`CellValue`, `StyledRun`, `FieldRow`, `ActionDesc`,
  `MenuPath`, `KeyStroke`, `Color`, `FontMetrics`).
- **Rust never calls back into C++.** The event queue is the only Rust-to-C++ channel, so there is no
  re-entrancy.
- Panics are caught at the bridge boundary. The message string is extracted when the panic is caught,
  logged, and shown as an error dialog. A panic never unwinds into C++.
- **Fallback** if snapshot reads miss the budget: a per-view row cache inside `ghidra-ui-model`.

## 4. Docking and tool framework mapping

| Ghidra (Java) | Rust model | Qt rendering |
|---|---|---|
| `PluginTool` / `FrontEndTool` / `Tool` | tool and plugin registry in `ghidra-rs` | one `MainWindow` per tool window |
| `ComponentProvider` | provider: title, icon, `WindowPosition`, window group, `ViewKind`, local actions | ADS `CDockWidget` hosting the generic widget for that `ViewKind` |
| `DockingWindowManager` / placeholders | `DockLayout`: visibility, `WindowPosition` placement intent, per-tool state | `ads::CDockManager`. TOP/BOTTOM/LEFT/RIGHT/STACK/WINDOW map to ADS areas and floating containers. |
| Tool config XML | saved with the real `SaveState`/`Element`. The ADS `saveState()` blob is embedded as one element. | `restoreState()` on open |
| `DockingAction` + Menu/ToolBar/Popup/KeyBinding data | Rust registry; `is_enabled_for_context` / `is_valid_context` evaluated in Rust | `QAction`s built from `ActionDesc`; menus and toolbars rebuilt on `ActionsChanged` or context change |
| `ActionContext` | built by the focused provider's view-model from its location and selection | C++ reports focus and selection intents |
| Key bindings (context-sensitive) | `KeyBindingsManager::dispatch_key(keystroke, focused_provider) -> handled` | keys the focused widget didn't consume are forwarded to Rust; no global `QShortcut`s |
| Options / Edit Options | ported options model | generic `FormView` + `TreeView` dialog |
| Theme (`GColor`/`GFont`/`GIcon` ids) | ported `docking/theme` + util `Color`/`Font` | `QPalette`/`QFont` mapping; light and dark |
| Status bar, tasks | task and progress events | status-bar widgets, task dialog |
| GoTo, NavigationHistory, `ProgramLocation`/`ProgramSelection` broadcast | Rust services | view intents in; `LocationChanged` events out to every view of that program |

The Rust model classes come first, with pure-Rust tests. A Rust **test tool** with dummy providers of
every `ViewKind` then drives the shell before any real plugin exists.

## 5. Listing view

**Rust side**
- Port `FormatManager` with Ghidra's default formats, `FieldFactory` and the core factories (Address,
  Bytes, Mnemonic, Operand, Label, EOL/Pre/Post/Plate comments, Data and open-data fields, separators,
  function signature), `ProgramBigListingModel`, `AddressIndexMap`, and the fieldpanel layout types
  (`Layout`, `Field`, `FieldLocation`, `RowColLocation`).
- C++ supplies a `FontMetrics` struct (per-style char width, ascent, descent, line height) on startup and
  on font change. Rust computes complete layouts in pixels. The listing is monospace by default.
- The `ListingModel` view-model:
  - `layouts_for_index_range(top_index, viewport_px) -> Vec<FieldRow>`, with positioned `StyledRun`s
    and theme colors;
  - `hit_test(index, x, y) -> FieldLocation -> ProgramLocation`;
  - cursor movement, goto and follow-reference, all in Rust.
- Scrolling runs over the BigInteger index space with a scaled scrollbar (Ghidra's `IndexedScrollPane`
  behaviour).

**C++ side**
- `ListingView : QAbstractScrollArea` paints only the visible rows (backgrounds for cursor, selection
  and highlights, then text runs) and forwards input as intents.
- The paint path allocates nothing beyond the returned rows.

**M1 scope**
- default format display; cursor; keyboard navigation; selection; highlight of the word under the
  cursor;
- goto address or label; back/forward history; click-to-follow references;
- inline edits: rename label, set comment, clear.

**Deferred** to M1.5 or later: flow arrows, marker and bookmark margins, overview bars, the field-header
format editor, hover tooltips, and structure open/close.

## 6. Milestone 1 plan shape

**Track U (UI)**
- **U0, scaffold**
  - Add the crates. Vendor ADS. Write `build.rs` (cc, moc, Qt6 link).
  - Show an empty `MainWindow` with an ADS dock manager.
  - Remove egui and eframe.
  - Add the offscreen smoke-test harness (`QT_QPA_PLATFORM=offscreen`, screenshots).
  - Update AGENTS.md.
- **U1, framework**
  - Rust: Tool, PluginTool, ComponentProvider, DockingAction, key bindings, DockLayout save/restore,
    the options model, the event queue, and task plumbing.
  - C++: the generic Table, Tree, Text and Form views; menus, toolbars and context menus; the status
    bar; the task dialog.
  - A demo test tool.
- **U2, listing**: section 5, against fixture ProgramDBs.

**Track C (core)**
- **C1:** finish the Rust sleigh compiler for the x86-64, x86, ARM and AARCH64 `.slaspec` files. Decode
  `.sla` (`SlaFormat`) and finish `SleighLanguage`.
- **C2:** InstructionDB on the designed instruction arena, `Disassembler`/`DisassembleCommand`, and
  `AbstractProgramLoader` plus the ELF import path into ProgramDB.

**Milestone 1 is done when:**
1. U0–U2 and C1–C2 have landed.
2. A real ELF imports, disassembles, and is browsable in the docked listing, with navigation and the
   inline edits working.
3. Golden-text parity holds against the human-exported stock-Ghidra listing for at least two small
   binaries (x86-64 and AARCH64 ELF).
4. The 1M-code-unit fixture scrolls with every UI-path call inside the 8 ms budget.
5. The human review gate passes (offscreen screenshots plus a manual demo checklist).

## 7. Testing

- **Pure-Rust unit tests** (inside `cargo test --lib`, no Qt) cover actions and context evaluation, key
  dispatch, DockLayout save/restore round-trips, listing layouts and hit-testing, and the field
  factories against golden text.
- **ghidra-qt offscreen smoke tests** launch, dock, undock, scroll and screenshot. They live behind
  `cargo test -p ghidra-qt` and are not part of the default suite, so the agent workflow and the OOM
  guardrails are unaffected.
- **Bridge latency test:** the 8 ms budget on the 1M-unit fixture.

## 8. Process and prerequisites

- Agents implement within this spec, at most 2 at a time, under the RESOURCE GUARDRAILS
  (`CARGO_BUILD_JOBS=4`, no builds under /tmp).
- New `ViewKind`s or UX deviations from Ghidra park for the human.
- Every milestone ends with a human review gate.
- **Human prerequisites:**
  1. Install the Qt6 dev packages (`qt6-base-dev`; also `qt6-base-private-dev` if ADS needs private headers). `cmake` is not required, because `build.rs` compiles ADS directly.
  2. Before the U2 parity test, run a stock Ghidra release once with the provided headless export
     script on the chosen test binaries and commit the output as fixtures.

## 9. Risks

- **The C1 Rust sleigh compiler is the long pole for M1.** U0–U2 proceed against fixtures in the
  meantime, so the UI is not blocked.
- **ADS behaviour may not match Ghidra's placeholder semantics exactly.** Mitigation: Rust's
  `DockLayout` owns the intent, ADS owns only geometry, and any mismatch is a documented UX deviation
  for the human gate.
- **Snapshot cost on the UI path.** Mitigation: the per-view row cache fallback (section 3).
