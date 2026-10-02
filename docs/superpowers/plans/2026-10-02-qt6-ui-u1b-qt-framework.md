# Qt6 UI — U1b Qt Framework Rendering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render the U1a framework model in the Qt shell, driven by a Rust **demo tool**. It must show docked Table/Tree/Text/Form panes placed by `WindowPosition`, menus/toolbars/popup menus built from actions (Ghidra ordering), context-sensitive key dispatch, a status bar fed by the event queue, and ADS geometry that round-trips. This closes the first human review gate (U0 + U1a + U1b).

**Architecture:**
- `ghidra-ui-model` gains a `ghidra-rs` dependency and owns a `UiSession`, which holds:
  - one `DockingTool`;
  - a registry `ProviderId → ViewModelBox` (enum of `Box<dyn TableModel>`, `TreeModel`, `TextModel`, `FormModel`);
  - the `UiEventQueue`.
- **Ordering logic is Rust.** Menu, toolbar and popup ordering, separators, and Qt-key→`KeyStroke` mapping are computed in Rust and unit-tested. C++ receives flat, pre-ordered descriptor lists and renders them.
- **The cxx bridge stays narrow.** Every `extern "Rust"` function goes through `guard()`. C++ catches `rust::Error` at **one central place**, a `bridgeCall` helper, so no exception escapes a Qt slot (U0 review M2).

**Tech Stack:** U0/U1a stack; Qt6 Widgets (`QTableView`/`QAbstractTableModel`, `QTreeView`/`QAbstractItemModel`, `QTextBrowser`, `QFormLayout`, `QSocketNotifier`), ADS `saveState`/`restoreState`.

**Spec:** `docs/superpowers/specs/2026-10-01-qt6-ui-design.md` §2–4, §7. U1a plan: `docs/superpowers/plans/2026-10-02-qt6-ui-u1a-framework-model.md`.

## Global Constraints

- C++ has no domain logic. It renders descriptor lists and forwards intents: `invoke_action`, `dispatch_key`, `focus_changed`, `sort`, `filter`, `edit`.
- The UI path does snapshot reads only. Each bridge call must run under 8 ms for the demo models.
- `ghidra-rs` stays toolkit-free. Qt-key mapping lives in `ghidra-qt/src/keys.rs` (the UI edge).
- `ghidra-qt` stays out of `default-members`. Its tests run with `cargo test -p ghidra-qt` under `QT_QPA_PLATFORM=offscreen`.
- Guardrails: `CARGO_BUILD_JOBS=4`, no build output under /tmp, row-scoped TSV staging, and verify the index before committing.

## Review Focus

1. **Two docks with the same key binding.** Ctrl-F in the Table pane runs the table's local "Find". Ctrl-F with the Tree pane focused runs the global action. Task 2, Task 5 smoke test.
2. **Menus with equal names in different groups.** They are separated and ordered exactly as Ghidra does: no-group last in the menubar, first in popups, then sub-group, then name. Task 2.
3. **Restoring geometry saved by a different set of docks.** ADS `restoreState` is fed a stale blob; the window still shows every current provider, falling back to the default placement. Task 4.
4. **A Rust panic or `Err` inside a bridge call made from a Qt slot** (sort, edit, invoke). It shows in the status bar and the app keeps running. Task 3, Task 5.
5. **Rapid event bursts while the window is hidden or minimised.** Wake bytes are drained and the queue does not grow without bound. Task 5.

---

### Task 1: `UiSession` owns a `DockingTool`, view models, and the demo tool

**Files:** Modify `ghidra-ui-model/Cargo.toml` (add `ghidra-rs = { path = "../ghidra-rs" }`), `ghidra-ui-model/src/session.rs`. Create `ghidra-ui-model/src/demo_tool.rs`.

**Interfaces:**
- **Produces `ViewModelBox`:** an enum with variants `Table(Box<dyn TableModel>)`, `Tree(Box<dyn TreeModel>)`, `Text(Box<dyn TextModel>)` and `Form(Box<dyn FormModel>)`.
- **`UiSession` provider and model access:**
  - `UiSession::new() -> UiSession`, an empty tool named `"Ghidra-rs"`.
  - `tool()` / `tool_mut()` return the `DockingTool`.
  - `add_provider(provider: Box<dyn ComponentProvider>, model: Option<ViewModelBox>, show: bool) -> ProviderId`
  - `model(id) -> Option<&ViewModelBox>`, `model_mut(id)`
  - `events() -> &UiEventQueue`, `take_wake_handle() -> Option<WakeHandle>`
  - `title()`, which keeps U0 behaviour.
- **Demo tool:** `demo_tool::build_demo_session() -> UiSession`. It has four providers:
  - "Symbols" (Table, LEFT)
  - "Program Tree" (Tree, LEFT)
  - "Decompiler" (Text, RIGHT)
  - "Options" (Form, BOTTOM)

  It registers these actions:

  | Action | Kind | Menu path | Group | Key |
  |---|---|---|---|---|
  | "Exit" | global | `["&File","E&xit"]` | `"Z"` | none |
  | "Copy" | global | `["&Edit","&Copy"]` | `"Clipboard"` | Ctrl-C |
  | "Find" | global | `["&Search","&Find..."]` | none | Ctrl-F; also a toolbar icon `icon.search` |
  | "Find in Table" | local to Symbols | popup | none | Ctrl-F |
  | "Wrap Lines" | toggle, local to Decompiler | — | — | — |

  Every action posts `UiEvent::TaskProgress`/`TaskDone` when run, and sets a status message via a new `UiEvent::Status(String)` variant, so the effect is observable in tests and on screen.
- **`UiEvent::Status(String)` change:** add the variant to `events.rs` (not coalesced), with a test.

- [ ] **Step 1: Failing tests** (`demo_tool.rs`)
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_rs::docking::action::DispatchResult;
    use ghidra_rs::util::awt::key_stroke::{vk, CTRL_DOWN_MASK};
    use ghidra_rs::util::awt::KeyStroke;

    #[test]
    fn demo_has_one_provider_per_fixed_view_kind() {
        let s = build_demo_session();
        let kinds: Vec<_> = s.tool().provider_ids()
            .map(|id| s.tool().provider(id).unwrap().state().view_kind().clone()).collect();
        for k in [ProviderViewKind::Table, ProviderViewKind::Tree, ProviderViewKind::Text, ProviderViewKind::Form] {
            assert!(kinds.contains(&k), "{k:?}");
        }
        for id in s.tool().provider_ids() {
            assert!(s.model(id).is_some(), "provider {id:?} has a model");
        }
    }

    #[test]
    fn ctrl_f_is_local_in_symbols_and_global_elsewhere() {
        let mut s = build_demo_session();
        let symbols = s.tool().find_provider("Demo", "Symbols").unwrap();
        let tree = s.tool().find_provider("Demo", "Program Tree").unwrap();
        let ctrl_f = KeyStroke::new(vk::F, CTRL_DOWN_MASK);
        let local = s.tool_mut().dispatch_key(ctrl_f, Some(symbols));
        let global = s.tool_mut().dispatch_key(ctrl_f, Some(tree));
        match (local, global) {
            (DispatchResult::Performed(a), DispatchResult::Performed(b)) => assert_ne!(a, b),
            other => panic!("{other:?}"),
        }
        let statuses: Vec<String> = s.events().drain().into_iter().filter_map(|e| match e {
            UiEvent::Status(m) => Some(m), _ => None }).collect();
        assert_eq!(statuses, vec!["Find in Table".to_string(), "Find".to_string()]);
    }
}
```

- [ ] **Step 2: Run the tests and verify they fail** with `CARGO_BUILD_JOBS=4 cargo test -p ghidra-ui-model`. **Step 3: Implement.** Actions capture a clone of the `UiEventQueue` (it is `Clone + Send + Sync`) and post `Status`. **Step 4:** tests pass, plus `cargo test -p ghidra-ui-model` overall. **Step 5:** commit `ui-model: UiSession owns DockingTool + view models; demo tool`.

---

### Task 2: Menu/toolbar/popup ordering and Qt key mapping (Rust)

**Files:** Create `ghidra-ui-model/src/menus.rs`, `ghidra-qt/src/keys.rs`.

**Interfaces:**
- **`MenuEntry` enum:**
  - `Submenu { title: String, mnemonic: Option<char>, children: Vec<MenuEntry> }`
  - `Item { action: ActionId, text: String, mnemonic: Option<char>, key_text: String, enabled: bool, checkable: bool, checked: bool }`
  - `Separator`
- **`menus::menu_bar(tool: &DockingTool, ctx: &dyn ActionContext) -> Vec<MenuEntry>`:** a port of `MenuManager`/`ManagedMenuItemComparator`.
  - Top level: submenus per first path element, ordered by the tool's menu-group map. The demo sets File → `"0"`, Edit → `"1"`, Search → `"2"`; others sort by name after those.
  - Items within a menu: sort by group with **null last**, then sub-group, then text. Insert a `Separator` whenever the group changes.
  - Enablement comes from `is_enabled_for_context(ctx)`; only `should_add_to_window(true, …)` actions are included.
- **`menus::popup(tool, provider: ProviderId, ctx) -> Vec<MenuEntry>`:** popup data for global and that provider's local actions where `is_add_to_popup(ctx)`. Groups sort **null first** (`PopupGroupComparator`), with separators as Java inserts them.
- **`menus::tool_bar(tool, ctx) -> Vec<ToolBarEntry>`:** `ToolBarEntry::{Button{action, icon, tooltip, enabled}, Separator}`, ordered by toolbar group, then sub-group, with a separator between groups.
- **`ghidra_qt::keys::qt_to_key_stroke(qt_key: i32, qt_modifiers: u32) -> Option<KeyStroke>`:**
  - Maps Qt::Key letters, digits, F1–F12, Enter/Return, Escape, Space, Delete, Backspace, Tab, Home/End, PageUp/Down and arrows to `vk`.
  - Maps the modifiers Shift 0x02000000, Ctrl 0x04000000, Alt 0x08000000 and Meta 0x10000000 to the `*_DOWN_MASK` bits.
  - Returns `None` for modifier-only presses.

- [ ] **Step 1: Failing tests** (`menus.rs` and `keys.rs`)
```rust
// menus.rs
#[test]
fn null_group_sorts_last_in_menubar_first_in_popup_with_separators() {
    let mut t = DockingTool::new("T");
    t.add_action(Box::new(menu_action("B", &["Edit", "B"], None)));
    t.add_action(Box::new(menu_action("A", &["Edit", "A"], Some("x"))));
    t.add_action(Box::new(menu_action("C", &["Edit", "C"], Some("x"))));
    let bar = menu_bar(&t, &DefaultActionContext::new());
    let MenuEntry::Submenu { children, .. } = &bar[0] else { panic!() };
    let names: Vec<String> = children.iter().map(entry_name).collect();
    assert_eq!(names, vec!["A", "C", "---", "B"]);
}

#[test]
fn equal_groups_order_by_sub_group_then_text() {
    let mut t = DockingTool::new("T");
    t.add_action(Box::new(menu_action_sub("Z", &["M", "Z"], Some("g"), Some("a"))));
    t.add_action(Box::new(menu_action_sub("A", &["M", "A"], Some("g"), Some("b"))));
    let bar = menu_bar(&t, &DefaultActionContext::new());
    let MenuEntry::Submenu { children, .. } = &bar[0] else { panic!() };
    assert_eq!(children.iter().map(entry_name).collect::<Vec<_>>(), vec!["Z", "A"]);
}

#[test]
fn nested_paths_build_submenus_and_disabled_items_are_marked() { /* ["File","Recent","a.out"] → File>Recent>a.out; disabled action → enabled=false */ }

// keys.rs
#[test]
fn ctrl_shift_g_maps_to_ghidra_stroke() {
    let ks = qt_to_key_stroke(0x47 /*Qt::Key_G*/, 0x0400_0000 | 0x0200_0000).unwrap();
    assert_eq!(ks.to_ghidra_string(), "Ctrl-Shift-G");
    assert_eq!(qt_to_key_stroke(0x0100_0030 /*Key_F1*/, 0).unwrap().to_ghidra_string(), "F1");
    assert_eq!(qt_to_key_stroke(0x0100_0021 /*Key_Control*/, 0x0400_0000), None);
}
```
Write `nested_paths_build_submenus_and_disabled_items_are_marked` in full, as its comment describes. Add `menu_action`, `menu_action_sub` and `entry_name` test helpers (`entry_name` returns `"---"` for `Separator`).

- [ ] **Steps 2–5:** RED, implement, GREEN, commit `ui-model: Ghidra menu/toolbar/popup ordering; ghidra-qt Qt key mapping`.

---

### Task 3: Bridge surface + central C++ error handling

**Files:** Modify `ghidra-qt/src/bridge.rs` and `ghidra-qt/src/main.rs` (it builds `build_demo_session()`). Create `ghidra-qt/cpp/bridge_call.h`.

**Interfaces.** All of the following are `extern "Rust"` and return `Result<…>` through `guard`. `pid` is the provider id as `u64`.
- **Providers:**
  - `session_title`
  - `provider_ids() -> Vec<u64>`
  - `provider_info(pid) -> ProviderInfo{ id, title, tab_text, kind: u8 /*0 table 1 tree 2 text 3 form 4 listing 5 custom*/, position: u8 /*WindowPosition order Top..Stack*/, visible: bool }`
- **Table:**
  - `table_column_count(pid)`, `table_column_name(pid, c)`, `table_row_count(pid)`, `table_cell(pid, r, c) -> String`
  - `table_sort(pid, c, asc)`, `table_filter(pid, text)`
  - `table_editable(pid, r, c) -> bool`, `table_edit(pid, r, c, value) -> Result<()>`
- **Tree:** `tree_root(pid) -> u64`, `tree_child_count(pid, node)`, `tree_child(pid, node, i) -> u64`, `tree_parent(pid, node) -> i64 /*-1 none*/`, `tree_label(pid, node)`.
- **Text:** `text_line_count(pid)`, `text_line(pid, i) -> Vec<RunInfo{text, color_id, bold, italic, link}>`.
- **Form:** `form_fields(pid) -> Vec<FieldInfo{key, label, kind: u8, value, choices: Vec<String>}>`, `form_set(pid, key, value) -> Result<()>`.
- **Menus and toolbar:** `menu_bar(focused_pid: i64) -> Vec<MenuItemInfo>` and `popup_menu(pid) -> Vec<MenuItemInfo>`. The menu tree is flattened depth-first: `MenuItemInfo{ depth: u32, kind: u8 /*0 submenu 1 item 2 separator*/, text, mnemonic: u32, action: u64, key_text, enabled, checkable, checked }`. `tool_bar(focused_pid) -> Vec<ToolBarInfo{ kind, action, icon, tooltip, enabled }>`.
- **Intents:**
  - `invoke_action(action: u64, focused_pid: i64)`
  - `dispatch_key(qt_key: i32, qt_mods: u32, focused_pid: i64) -> u8` (0 performed, 1 disabled, 2 ambiguous, 3 not handled)
  - `focus_changed(pid: i64)`
- **Layout and events:**
  - `layout_geometry() -> Vec<u8>`, `set_layout_geometry(bytes)`
  - `wake_fd() -> i32`, `drain_events() -> Vec<EventInfo{ kind: u8, text, task, progress, maximum }>`

C++ side:
- **`bridge_call.h`:** `template<class F> bool bridgeCall(QStatusBar*, F&&)`. It catches `rust::Error`, shows `e.what()` in the status bar for 5 s, logs to stderr, and returns false. **Every** C++ call into Rust in slots and models goes through it.

- [ ] **Step 1: Failing Rust tests** in `bridge.rs`. Call the plain Rust functions behind the bridge directly (they're ordinary `fn`s):
  - `provider_ids` returns 4 ids;
  - `table_cell` out of range returns an empty string;
  - `form_set` with a bad int returns `Err`;
  - `dispatch_key` with Qt Ctrl-F in Symbols returns 0;
  - a `table_edit` on a non-editable cell returns `Err("not editable")`.
- [ ] **Step 2: Run the tests and verify they fail. Step 3:** implement, with the session behind a `Mutex` in a `static OnceLock` per run (single UI thread; the mutex only guards against misuse). **Step 4:** green. **Step 5:** commit `ghidra-qt: bridge surface for providers/views/menus/keys/events + central bridgeCall`.

---

### Task 4: C++ generic views + ADS docks from the provider list

**Files:** Create `ghidra-qt/cpp/views/table_view.{h,cpp}` (`RustTableModel : QAbstractTableModel`, `QTableView` with sort header and a filter `QLineEdit`), `tree_view.{h,cpp}` (`RustTreeModel : QAbstractItemModel` using internalId = node id), `text_view.{h,cpp}` (`QTextBrowser` filled from runs with color/bold/italic/links), and `form_view.{h,cpp}` (`QFormLayout` of `QLineEdit`/`QSpinBox`/`QCheckBox`/`QComboBox`, committing via `form_set`). Modify `main_window.{h,cpp}`:
- create one `CDockWidget` per provider with the matching view;
- map `WindowPosition` to an ADS area: TOP → TopDockWidgetArea, BOTTOM → Bottom, LEFT → Left, RIGHT → Right, WINDOW → floating container, STACK → tab into the previous area;
- save geometry with `set_layout_geometry(m_dockManager->saveState())` on close;
- restore it on startup. If `restoreState` returns false, keep the default placement.

Update `build.rs` to moc the new headers.

- [ ] **Step 1: Failing smoke tests** (`ghidra-qt/tests/smoke.rs`):
  - `--dump-docks` (a new CLI flag) prints one line per dock: `"<title>\t<area>\t<view-kind>"`. Assert all four demo providers appear with areas Left/Left/Right/Bottom.
  - The screenshot is still 1200×800.
  - `--restore-geometry <file-with-garbage>` still dumps all four docks (Review Focus 3).
- [ ] **Step 2: Run the tests and verify they fail. Step 3:** implement. Rows are fetched lazily through the model; nothing is cached beyond Qt's own. **Step 4:** green. **Step 5:** commit `ghidra-qt: ADS docks per provider with generic Table/Tree/Text/Form views`.

---

### Task 5: Menus, toolbar, popups, key forwarding, status bar, event pump

**Files:** Modify `main_window.{h,cpp}`. Create `cpp/action_bridge.{h,cpp}` (builds the `QMenuBar`/`QToolBar`/`QMenu` from the flattened lists and rebuilds them on `ActionsChanged` or focus change), `cpp/event_pump.{h,cpp}` (a `QSocketNotifier` on `wake_fd()` that calls `drain_events()` and applies `Status` messages to the status bar and `TaskProgress`/`TaskDone` to a status-bar progress widget).

Key forwarding uses an application-level event filter. A `QKeyEvent` that the focused widget doesn't accept is passed to `dispatch_key` with the focused dock's provider id. A result of "ambiguous" opens a `QMenu` listing the candidate actions, which is Ghidra's action chooser.

- [ ] **Step 1: Failing smoke tests:**
  - `--dump-menus` prints the built `QMenuBar` tree, using `"-"` for separators and `"[x]"` for disabled items. Assert the File, Edit and Search order and the Copy shortcut text `"Ctrl+C"`.
  - `--press "Ctrl-F" --focus "Symbols" --quit-after-ms 800` posts a synthetic `QKeyEvent` to the Symbols dock. The test asserts that stderr/stdout contains the status line `"Find in Table"`; with `--focus "Program Tree"` it asserts `"Find"` (Review Focus 1).
  - `--invoke-missing-action` triggers a bridge `Err` from a slot. The test asserts the app exits 0 and prints the error to stderr (Review Focus 4).
- [ ] **Step 2: Run the tests and verify they fail. Step 3: implement. Step 4: green. Step 5:** commit `ghidra-qt: menus/toolbar/popups from Rust, key forwarding, status bar + event pump`.

---

## Milestone gate (U0 + U1a + U1b) — human review

1. **Screenshot:** `target/tmp/smoke_main_window.png` shows four docked panes.
2. **On the desktop**, with `cargo run -p ghidra-qt`:
   - menus are ordered and have mnemonics;
   - Ctrl-F behaves differently in the Symbols pane than elsewhere;
   - right-click in Symbols shows "Find in Table";
   - the table sorts and filters;
   - form edits validate;
   - layout persists across restarts;
   - undock and re-dock work on X11 and Wayland.
3. **Review the ledgers:** the U0, U1a and U1b `Ruling:` lines and deferred minors.
