# Qt6 UI — U1a Framework Model (pure Rust) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the toolkit-neutral half of Ghidra's docking framework. That means keystrokes, menu/toolbar/key-binding data, actions, component providers, the tool's action registry with context-sensitive key dispatch, layout persistence, the UI event queue, and the generic view-model traits. The U1b Qt plan then renders these with no domain logic in C++.

**Architecture:**
- **Value and framework types live in `ghidra-rs`**, per the AGENTS.md package map. Placeholders already exist for most of them in `seam_stubs.rs`; each is **promoted** to a real type and its importers are repointed.
  - `docking.*` goes to `docking/`.
  - `gui.event.MouseBinding` goes to `docking/` (`gui` maps to `docking/`).
  - `ghidra.framework.options.ActionTrigger` goes to `framework/options/`.
  - `javax.swing.KeyStroke` goes to `util::awt` (the toolkit-neutral decision of 2026-10-01).
- **The renderer contract lives in `ghidra-ui-model`:** `UiEventQueue`, `Waker`, `ViewKind`, and the `TableModel`/`TreeModel`/`TextModel`/`FormModel` traits.
- Swing-only surface is dropped from the Rust model, because the C++ shell renders instead. That covers `createButton`, `createMenuItem`, `JComponent`, `MouseEvent` and `Component` on `DockingActionIf`/`ActionContext`.

**Tech Stack:** Rust 1.96; the existing `ghidra-rs` crate (`SaveState`/`Element` for persistence); `ghidra-ui-model`; no new dependencies. The `Waker` uses `std::os::unix::net::UnixStream::pair` on Unix and a `std::sync::mpsc` notify fallback elsewhere.

**Spec:** `docs/superpowers/specs/2026-10-01-qt6-ui-design.md`, §2–4.

**How the implementation steps are written.** These classes are *ports*. Each implementation step names the Java method bodies to port, with their files under `orig_src/Ghidra/Framework/Docking/src/main/java/` (`D/` below), and gives the exact Rust signatures. **The tests are given in full** and encode the Java behaviour, so they are the contract. Follow `.claude/descent_batch_brief.md` for promote/replace of placeholders, `PORT_MANIFEST.tsv` DONE flips (Definition of DONE in AGENTS.md), and `STUBS.tsv` line removal.

## Global Constraints

- `ghidra-rs` and `ghidra-ui-model` stay toolkit-free. No Qt, egui, or `J*`/`Component`/`MouseEvent` types in any new or changed signature.
- Icons are referenced by **theme icon id** (`IconId(String)`, Ghidra's `GIcon` id such as `"icon.provider.close"`), never by image data.
- Mutually referencing types use IDs or call-time arguments, never back-pointers (decision of 2026-09-24). In particular, `MenuData`/`ToolBarData` do **not** hold their owning action. The owning `DockingAction` fires change events when its data is replaced or updated through it.
- No `Rc<RefCell<_>>`. Registries are plain owned structs mutated through `&mut self`. A tool that must be shared later uses the snapshot/`&self` + interior-mutability convention, but U1a needs none.
- Prefix every cargo command with `CARGO_BUILD_JOBS=4`. No build output under /tmp. Commit with explicit pathspecs only. `Cargo.lock` is untracked. Each commit message ends with the two trailer lines from the U0 plan.
- Run the full `cargo test --lib` (in `ghidra-rs/`) at the end of every task that touches `ghidra-rs`, because promotions repoint importers crate-wide.

## Review Focus

1. **Keystroke strings round-trip as Ghidra writes them.** `"ctrl shift G"`, `"Ctrl-Shift-G"`, `"CTRL+SHIFT+G"`-style variants and duplicated modifiers parse to the same stroke and print as `"Ctrl-Shift-G"`. Task 1.
2. **Two actions bound to the same key in different providers.** The focused provider's valid, enabled action wins. A global action fires only when no provider-local candidate is valid. An unhandled key returns `false`, so the shell can pass it on. Task 5.
3. **Saved layout from a newer or older build.** It names a provider id that no longer exists, or misses a new one. Restore keeps known providers, ignores unknown ones without error, and gives new providers their default `WindowPosition`. Task 6.
4. **Event queue flood.** Thousands of `DomainChanged` events between two UI frames. `drain()` coalesces per object and range so the shell does one refresh, and the waker is signalled at most once per drain cycle. Task 7.
5. **A key binding set to a system-reserved stroke.** `KeyBindingData::new` with `SystemActionsLevel` precedence must be rejected, as in Java. Task 2.

---

### Task 1: `KeyStroke` (util::awt), `MouseBinding`, `ActionTrigger`, `KeyBindingPrecedence`

**Files:**
- Create: `ghidra-rs/src/util/awt/key_stroke.rs` (`KeyStroke`, `KeyCode` constants, modifier masks, Java-format parse/print)
- Modify: `ghidra-rs/src/util/awt/mod.rs` (export)
- Create: `ghidra-rs/src/docking/key_binding_precedence.rs`
- Create: `ghidra-rs/src/docking/mouse_binding.rs`
- Create: `ghidra-rs/src/framework/options/action_trigger.rs`
- Modify: `ghidra-rs/src/framework/seam_stubs.rs` (delete the `KeyStroke`/`ActionTrigger` placeholders; repoint importers), and `STUBS.tsv`
- Modify: `ghidra-rs/src/docking/mod.rs`, `ghidra-rs/src/framework/options/mod.rs`

**Interfaces:**
- Produces:
  - `util::awt::KeyStroke { key_code: i32, modifiers: i32, on_key_release: bool }`, `Copy + Eq + Hash`, with:
    - `KeyStroke::new(key_code, modifiers) -> KeyStroke` (modifiers normalised to the `*_DOWN_MASK` bits, as Java does)
    - `fn key_code(self) -> i32`
    - `fn modifiers(self) -> i32`
    - `fn to_ghidra_string(self) -> String` (Java `KeyBindingUtils.parseKeyStroke(KeyStroke)`)
    - `fn parse(s: &str) -> Option<KeyStroke>` (Java `KeyBindingUtils.parseKeyStroke(String)`)
  - `util::awt::key_stroke::{SHIFT_DOWN_MASK=0x40, CTRL_DOWN_MASK=0x80, META_DOWN_MASK=0x100, ALT_DOWN_MASK=0x200}`
  - `util::awt::key_stroke::vk` module with Java `VK_*` values (letters `0x41..=0x5A`, digits `0x30..=0x39`, `F1=0x70..F12=0x7B`, `ENTER=0x0A`, `ESCAPE=0x1B`, `SPACE=0x20`, `DELETE=0x7F`, `BACK_SPACE=0x08`, `TAB=0x09`, `HOME=0x24`, `END=0x23`, `PAGE_UP=0x21`, `PAGE_DOWN=0x22`, `LEFT=0x25`, `UP=0x26`, `RIGHT=0x27`, `DOWN=0x28`, `INSERT=0x9B`, `SLASH=0x2F`, `SEMICOLON=0x3B`, `EQUALS=0x3D`, `MINUS=0x2D`, `PERIOD=0x2E`, `COMMA=0x2C`), plus `fn key_name(code) -> Option<&'static str>` and `fn key_code(name) -> Option<i32>` using Java's `KeyEvent.getKeyText`-style upper-case names (`"G"`, `"F5"`, `"ENTER"`, `"ESCAPE"`, `"SPACE"`, `"DELETE"`, `"BACK_SPACE"`, `"PAGE_UP"`, ...)
  - `docking::KeyBindingPrecedence` enum: `SystemActionsLevel, KeyListenerLevel, ActionMapLevel, DefaultLevel` (declaration order is significant: lower = higher priority)
  - `docking::MouseBinding { button: i32, modifiers: i32 }` (Java `gui.event.MouseBinding`; port `getMouseBinding(String)`/`getDisplayText`)
  - `framework::options::ActionTrigger { key_stroke: Option<KeyStroke>, mouse_binding: Option<MouseBinding> }`

- [ ] **Step 1: Write the failing tests** (`key_stroke.rs`)
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_space_and_dash_separated_forms_identically() {
        let a = KeyStroke::parse("ctrl shift G").unwrap();
        let b = KeyStroke::parse("Ctrl-Shift-G").unwrap();
        let c = KeyStroke::parse("shift-ctrl-g").unwrap();
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(a.key_code(), vk::G);
        assert_eq!(a.modifiers(), CTRL_DOWN_MASK | SHIFT_DOWN_MASK);
    }

    #[test]
    fn duplicate_modifiers_and_pressed_token_are_ignored() {
        assert_eq!(
            KeyStroke::parse("ctrl ctrl pressed G"),
            KeyStroke::parse("ctrl G")
        );
    }

    #[test]
    fn prints_in_ghidra_modifier_order() {
        // Java KeyBindingUtils.parseKeyStroke(KeyStroke): Ctrl, Alt, Shift, Meta order, '-' separator.
        let ks = KeyStroke::new(vk::G, SHIFT_DOWN_MASK | CTRL_DOWN_MASK | ALT_DOWN_MASK);
        assert_eq!(ks.to_ghidra_string(), "Ctrl-Alt-Shift-G");
        assert_eq!(KeyStroke::new(vk::F5, 0).to_ghidra_string(), "F5");
        assert_eq!(KeyStroke::new(vk::DELETE, 0).to_ghidra_string(), "DELETE");
    }

    #[test]
    fn round_trips_through_string() {
        for s in ["Ctrl-Shift-G", "F5", "Alt-ENTER", "Ctrl-SPACE", "Meta-Q"] {
            let ks = KeyStroke::parse(s).unwrap_or_else(|| panic!("parse {s}"));
            assert_eq!(ks.to_ghidra_string(), s, "{s}");
        }
    }

    #[test]
    fn blank_or_modifier_only_is_none() {
        assert_eq!(KeyStroke::parse(""), None);
        assert_eq!(KeyStroke::parse("   "), None);
        assert_eq!(KeyStroke::parse("ctrl shift"), None);
        assert_eq!(KeyStroke::parse("ctrl NOT_A_KEY"), None);
    }
}
```
Also add tests in `key_binding_precedence.rs` (`SystemActionsLevel < DefaultLevel` via `Ord`) and `mouse_binding.rs` (`MouseBinding::parse("Ctrl-Button3")` gives `button=3, modifiers=CTRL_DOWN_MASK`, and displays back as `"Ctrl-Button3"`, per `MouseBinding.getMouseBinding`/`getDisplayText`).

- [ ] **Step 2: Run the tests and verify they fail.**
Run: `cd ghidra-rs && CARGO_BUILD_JOBS=4 cargo test --lib util::awt::key_stroke docking::mouse_binding docking::key_binding_precedence`
Expected: compile errors (types missing).

- [ ] **Step 3: Implement.**
  - **Parse:** port `D/docking/actions/KeyBindingUtils.java` `parseKeyStroke(String)` (lines ~761–830). Tokenise on `-` and space, de-dup, map modifier tokens case-insensitively, drop `pressed`/`typed`/`released`. Exactly one key token must remain, resolved through `vk::key_code(upper)`; otherwise `None`.
  - **Print:** port `parseKeyStroke(KeyStroke)` (lines ~633–700). Prefix modifiers as `Ctrl-`, `Alt-`, `Shift-`, `Meta-` in that order, then the key name.
  - **Normalisation:** `KeyStroke::new` normalises the legacy masks (`SHIFT_MASK=1, CTRL_MASK=2, META_MASK=4, ALT_MASK=8`) to the `*_DOWN_MASK` bits, as `KeyBindingUtils.validateKeyStroke` does.
  - **Placeholders:** delete the `framework/seam_stubs.rs` `KeyStroke` and `ActionTrigger` placeholders. Repoint every importer (`grep -rn 'seam_stubs::{\?.*\bKeyStroke\b\|seam_stubs::{\?.*\bActionTrigger\b' ghidra-rs/src`), scoped to the import lines. Remove their `STUBS.tsv` lines.

- [ ] **Step 4: Run the tests and the full lib suite and verify they pass.**
Run: `cd ghidra-rs && CARGO_BUILD_JOBS=4 cargo test --lib util::awt docking::mouse_binding docking::key_binding_precedence` (expect all pass), then `CARGO_BUILD_JOBS=4 cargo test --lib 2>&1 | grep '^test result'` (expect `0 failed`).

- [ ] **Step 5: Flip the manifest and commit.**
Flip `docking/KeyBindingPrecedence.java`, `gui/event/MouseBinding.java` and `ghidra/framework/options/ActionTrigger.java` to DONE in `PORT_MANIFEST.tsv` if their rows exist and were TODO. Commit with message `ui-model: KeyStroke (util::awt), MouseBinding, ActionTrigger, KeyBindingPrecedence`.

---

### Task 2: `MenuData`, `ToolBarData`, `KeyBindingData`, `IconId`

**Files:**
- Create: `ghidra-rs/src/docking/action/menu_data.rs`, `tool_bar_data.rs`, `key_binding_data.rs`
- Create: `ghidra-rs/src/docking/icon_id.rs`
- Modify: `ghidra-rs/src/docking/action/mod.rs`, `ghidra-rs/src/docking/mod.rs`
- Modify: `ghidra-rs/src/docking/seam_stubs.rs` (delete the `MenuData`/`ToolBarData`/`KeyBindingData`/`KeyBindingType` placeholders where now real; repoint importers), `ghidra-rs/src/sarif/seam_stubs.rs` (its `MenuData` placeholder), `STUBS.tsv`

**Interfaces:**
- Consumes: Task 1 (`KeyStroke`, `MouseBinding`, `ActionTrigger`, `KeyBindingPrecedence`).
- Produces:
  - `docking::IconId(pub String)`
  - `docking::action::MenuData`, a `Clone + Eq` struct, with:
    - `MenuData::new(path: &[&str]) -> Result<MenuData, MenuDataError>`
    - `with_group(path, group)` / `full(path, icon: Option<IconId>, group: Option<&str>, mnemonic: Option<char>, sub_group: Option<&str>)`
    - `menu_path() -> &[String]`, `menu_path_as_string() -> String` (`"A->B"`), `menu_path_display_string()`
    - `mnemonic() -> Option<char>`, `menu_group()`, `menu_sub_group()` (returns `NO_SUBGROUP` when unset), `parent_menu_group()`, `menu_item_name()`
    - `set_menu_group`, `set_menu_sub_group`, `set_parent_menu_group(..) -> Result<(), MenuDataError>`, `set_menu_path(..) -> Result<..>`, `set_menu_item_name`, `set_mnemonic`, `clear_mnemonic`
    - statics `strip_mnemonic_amp(&str) -> String` and `mnemonic_of(&str) -> Option<char>`
  - `const NO_SUBGROUP: &str = "\u{ffff}"`
  - `docking::action::ToolBarData { icon: IconId, group: Option<String>, sub_group: String }`, with `new`, getters, and setters (sub-group `None` maps to `NO_SUBGROUP`)
  - `docking::action::KeyBindingData` with:
    - `new(KeyStroke) -> KeyBindingData`
    - `with_precedence(KeyStroke, KeyBindingPrecedence) -> Result<_, KeyBindingError>` (rejects `SystemActionsLevel`)
    - `from_mouse(MouseBinding)`, `from_trigger(ActionTrigger)`, `parse(&str) -> Result<_, KeyBindingError>`
    - `key_binding() -> Option<KeyStroke>`, `precedence()`, `mouse_binding()`, `action_trigger()`
    - `update(Option<&KeyBindingData>, Option<&ActionTrigger>) -> Option<KeyBindingData>` (Java `update`)
    - `pub(crate) system(KeyStroke)` (the system-precedence constructor)
  - `docking::action::KeyBindingType` enum `{ Unsupported, Individual, Shared }` with `supports_key_bindings()`, `is_shared()`, `is_managed()` (Java `KeyBindingType`)
  - A `MenuData` used as menubar or popup data is the same type. Java's `MenuBarData`/`PopupMenuData` subclasses existed only to fire change events through the owner, which the owning `DockingAction` now does (Task 3).

- [ ] **Step 1: Write the failing tests** (`menu_data.rs`, `key_binding_data.rs`)
```rust
// menu_data.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_path_is_rejected() {
        assert!(MenuData::new(&[]).is_err());
    }

    #[test]
    fn mnemonic_comes_from_last_element_ampersand_and_is_stripped() {
        let m = MenuData::new(&["&File", "Save &As..."]).unwrap();
        assert_eq!(m.mnemonic(), Some('A'));
        // only the LAST element is stripped (Java processMenuPath)
        assert_eq!(m.menu_path(), &["&File".to_string(), "Save As...".to_string()]);
        assert_eq!(m.menu_item_name(), "Save As...");
    }

    #[test]
    fn double_ampersand_is_a_literal() {
        assert_eq!(MenuData::strip_mnemonic_amp("Fish && Chips"), "Fish & Chips");
        assert_eq!(MenuData::mnemonic_of("Fish && Chips"), None);
        assert_eq!(MenuData::mnemonic_of("&Edit"), Some('E'));
        assert_eq!(MenuData::mnemonic_of("Trailing&"), None);
    }

    #[test]
    fn path_strings() {
        let m = MenuData::new(&["&Edit", "Copy &Special"]).unwrap();
        assert_eq!(m.menu_path_as_string(), "&Edit->Copy Special");
        assert_eq!(m.menu_path_display_string(), "Edit->Copy Special");
    }

    #[test]
    fn sub_group_defaults_to_no_subgroup() {
        let mut m = MenuData::new(&["A"]).unwrap();
        assert_eq!(m.menu_sub_group(), NO_SUBGROUP);
        m.set_menu_sub_group(Some("x"));
        assert_eq!(m.menu_sub_group(), "x");
        m.set_menu_sub_group(None);
        assert_eq!(m.menu_sub_group(), NO_SUBGROUP);
    }

    #[test]
    fn parent_group_requires_a_parent_menu() {
        let mut top = MenuData::new(&["Top"]).unwrap();
        assert!(top.set_parent_menu_group(Some("g")).is_err());
        let mut nested = MenuData::new(&["Top", "Item"]).unwrap();
        nested.set_parent_menu_group(Some("g")).unwrap();
        assert_eq!(nested.parent_menu_group(), Some("g"));
    }
}

// key_binding_data.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::awt::key_stroke::{vk, CTRL_DOWN_MASK};

    #[test]
    fn system_precedence_is_rejected_for_clients() {
        let ks = KeyStroke::new(vk::G, CTRL_DOWN_MASK);
        assert!(KeyBindingData::with_precedence(ks, KeyBindingPrecedence::SystemActionsLevel).is_err());
        assert_eq!(KeyBindingData::new(ks).precedence(), KeyBindingPrecedence::DefaultLevel);
        assert_eq!(KeyBindingData::system(ks).precedence(), KeyBindingPrecedence::SystemActionsLevel);
    }

    #[test]
    fn parse_rejects_invalid_strings() {
        assert!(KeyBindingData::parse("ctrl G").is_ok());
        assert!(KeyBindingData::parse("ctrl").is_err());
    }

    #[test]
    fn update_follows_java_semantics() {
        let ks = KeyStroke::new(vk::G, CTRL_DOWN_MASK);
        let trig = ActionTrigger { key_stroke: Some(ks), mouse_binding: None };
        assert_eq!(KeyBindingData::update(None, None), None);
        let added = KeyBindingData::update(None, Some(&trig)).unwrap();
        assert_eq!(added.key_binding(), Some(ks));
        assert_eq!(KeyBindingData::update(Some(&added), None), None);
        // same trigger: unchanged (Java returns the same instance)
        assert_eq!(KeyBindingData::update(Some(&added), Some(&trig)), Some(added.clone()));
    }
}
```

- [ ] **Step 2: Run the tests and verify they fail** (missing types).

- [ ] **Step 3: Implement.**
  - Port `D/docking/action/MenuData.java` method by method. The `firePropertyChanged` hooks are dropped (see Interfaces).
  - Port `ToolBarData.java` and `KeyBindingData.java`. `logKeyBindingWhitespaceWarning` becomes `tracing::warn!`.
  - Port `KeyBindingType.java`.
  - Promote the placeholders (delete them and repoint importers per the brief).

- [ ] **Step 4: Module tests plus the full lib suite pass.**

- [ ] **Step 5: Flip the manifest** for MenuData, MenuBarData, PopupMenuData, ToolBarData, KeyBindingData and KeyBindingType. MenuBarData and PopupMenuData are DONE because they collapse into `MenuData`; add a ledger note. Commit: `ui-model: MenuData/ToolBarData/KeyBindingData/KeyBindingType real structs`.

---

### Task 3: `DockingAction`, `ActionContext`, `DockingActionIf` reshaped

**Files:**
- Create: `ghidra-rs/src/docking/action/docking_action.rs`
- Create: `ghidra-rs/src/docking/default_action_context.rs`
- Modify: `ghidra-rs/src/docking/action/docking_action_if.rs` (toolkit-neutral trait), `toggle_docking_action_if.rs`, `multi_action_docking_action_if.rs`, `ghidra-rs/src/docking/action_context.rs`
- Modify: `ghidra-rs/src/docking/seam_stubs.rs` (remove now-unused `JButton`/`JMenuItem`/`Component`/`MouseEvent`/`PropertyChangeListener` placeholders if nothing else uses them), `STUBS.tsv`

**Interfaces:**
- Consumes: Task 2.
- Produces:
  - `docking::action::ActionId(u64)`: a `Copy` id assigned by the registry (Task 5); `ActionId::UNASSIGNED`.
  - `docking::action::ActionChange` enum `{ Enabled, MenuBarData, PopupMenuData, ToolBarData, KeyBindingData, Description }`.
  - `docking::action::DockingAction`, a struct (R11 shared state) holding:
    - `name`, `owner`, `description`, `enabled: bool`, `help_location: Option<String>`
    - `menu_bar_data: Option<MenuData>`, `popup_menu_data: Option<MenuData>`, `tool_bar_data: Option<ToolBarData>`
    - `key_binding_data: Option<KeyBindingData>`, `default_key_binding_data: Option<KeyBindingData>`, `key_binding_type: KeyBindingType`
    - `context_type: TypeId`, `supports_default_context: bool`
    - `pending_changes: Vec<ActionChange>`

    It has setters that record an `ActionChange` only when the value actually changes (Java `firePropertyChanged` with old != new), plus `take_changes(&mut self) -> Vec<ActionChange>` and `update_menu_bar_data(&mut self, f: impl FnOnce(&mut MenuData))`, which records a change only if the data changed. Likewise `update_popup_menu_data` and `update_tool_bar_data`.
  - `docking::action::ActionBehavior`, a trait: `fn action_performed(&mut self, ctx: &dyn ActionContext)`. These have Java's defaults:
    - `fn is_enabled_for_context(&self, ctx: &dyn ActionContext) -> bool { true }`
    - `fn is_valid_context(&self, ctx: &dyn ActionContext) -> bool { true }`
    - `fn is_add_to_popup(&self, ctx: &dyn ActionContext) -> bool` (Java default: `is_enabled_for_context(ctx)`)
  - `docking::action::DockingActionIf`, reshaped to `trait DockingActionIf: ActionBehavior { fn state(&self) -> &DockingAction; fn state_mut(&mut self) -> &mut DockingAction; }`, with provided accessors forwarding to `state()` (`name()`, `owner()`, `full_name()` = `"name (owner)"`, `is_enabled()`, `key_binding()`, ...). **Removed:** `create_button`, `create_menu_item`, `create_menu_component`, property-change listeners, `JButton`/`Component`.
  - `docking::ActionContext`, reshaped to a toolkit-neutral trait:
    - `fn provider(&self) -> Option<ProviderId>` (Task 4 id)
    - `fn context_object(&self) -> Option<&(dyn Any + Send + Sync)>`
    - `fn source_object(&self) -> Option<&(dyn Any + Send + Sync)>`
    - `fn event_click_modifiers(&self) -> i32`
    - `fn as_any(&self) -> &dyn Any` (enables context-type checks like Java's `instanceof`)
  - `docking::DefaultActionContext`, a struct implementing it, with builder setters.
  - `docking::action::ToggleDockingAction`: `DockingAction` plus `selected: bool`, with a `ActionChange::Selected` variant added.
  - `docking::action::is_context_applicable(action: &dyn DockingActionIf, ctx: &dyn ActionContext) -> bool`. It ports `DockingAction.isValidContext` gating: a context-type match via `ctx.as_any().type_id() == state.context_type`, or the action supports the default context, or `context_type == TypeId::of::<dyn ActionContext>`-equivalent "any". Use a sentinel `ANY_CONTEXT` `TypeId` of a private marker type.

- [ ] **Step 1: Write the failing tests** (`docking_action.rs`)
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::DefaultActionContext;

    struct Counter { state: DockingAction, hits: u32 }
    impl ActionBehavior for Counter {
        fn action_performed(&mut self, _ctx: &dyn ActionContext) { self.hits += 1; }
    }
    impl DockingActionIf for Counter {
        fn state(&self) -> &DockingAction { &self.state }
        fn state_mut(&mut self) -> &mut DockingAction { &mut self.state }
    }

    fn action() -> Counter {
        Counter { state: DockingAction::new("Rename", "LabelPlugin"), hits: 0 }
    }

    #[test]
    fn full_name_is_name_then_owner() {
        assert_eq!(action().full_name(), "Rename (LabelPlugin)");
    }

    #[test]
    fn setting_same_value_records_no_change() {
        let mut a = action();
        a.state_mut().set_enabled(true); // already enabled by default
        assert!(a.state_mut().take_changes().is_empty());
        a.state_mut().set_enabled(false);
        assert_eq!(a.state_mut().take_changes(), vec![ActionChange::Enabled]);
    }

    #[test]
    fn updating_menu_data_in_place_records_change_only_when_different() {
        let mut a = action();
        a.state_mut().set_menu_bar_data(Some(MenuData::new(&["Edit", "Rename"]).unwrap()));
        a.state_mut().take_changes();
        a.state_mut().update_menu_bar_data(|m| m.set_menu_group(Some("g")));
        assert_eq!(a.state_mut().take_changes(), vec![ActionChange::MenuBarData]);
        a.state_mut().update_menu_bar_data(|m| m.set_menu_group(Some("g")));
        assert!(a.state_mut().take_changes().is_empty());
    }

    #[test]
    fn default_popup_rule_follows_enablement() {
        let a = action();
        let ctx = DefaultActionContext::new();
        assert!(a.is_add_to_popup(&ctx));
    }

    #[test]
    fn context_type_gates_applicability() {
        struct Special;
        let mut a = action();
        a.state_mut().set_context_type(std::any::TypeId::of::<Special>(), false);
        assert!(!is_context_applicable(&a, &DefaultActionContext::new()));
        a.state_mut().set_context_type(std::any::TypeId::of::<Special>(), true);
        assert!(is_context_applicable(&a, &DefaultActionContext::new()));
    }

    #[test]
    fn performing_runs_behaviour() {
        let mut a = action();
        a.action_performed(&DefaultActionContext::new());
        assert_eq!(a.hits, 1);
    }
}
```

- [ ] **Step 2: Run the tests and verify they fail.**

- [ ] **Step 3: Implement.**
  - Port the `D/docking/action/DockingAction.java` state, getters, setters, `firePropertyChanged` (as `pending_changes`), `getFullName`, `isEnabledForContext`/`isValidContext`/`isAddToPopup` defaults, `setContextClass`, and `ToggleDockingAction.java`.
  - Reshape `docking_action_if.rs` and its two sibling traits to the toolkit-neutral form, and update their mock tests.
  - Port `DefaultActionContext.java`, minus the Swing fields.
  - Fix every crate importer of the removed methods. Use `grep -rn 'create_button\|create_menu_item\|create_menu_component' ghidra-rs/src`; scope each fix to that `impl` block.

- [ ] **Step 4: Module tests plus the full lib suite pass.**

- [ ] **Step 5: Flip the manifest** (DockingAction, ToggleDockingAction, DefaultActionContext; DockingActionIf if it has a row). Commit: `ui-model: toolkit-neutral DockingAction/ActionContext; DockingActionIf reshaped`.

---

### Task 4: `ComponentProvider` and `ViewKind`

**Files:**
- Create: `ghidra-ui-model/src/view_kind.rs` (`ViewKind` lives in the renderer contract)
- Create: `ghidra-rs/src/docking/component_provider.rs`
- Modify: `ghidra-rs/Cargo.toml`, only if `ViewKind` is needed by `ghidra-rs`. **Ruling in advance:** it is not. Instead `ComponentProvider` carries a `view_kind: ProviderViewKind` enum defined in `ghidra-rs/src/docking/` (`Table, Tree, Text, Form, Listing, Custom(String)`), and `ghidra-ui-model` maps it to its own `ViewKind`. This keeps `ghidra-rs` from depending on `ghidra-ui-model`, which would form a cycle once U1b makes `ghidra-ui-model` depend on `ghidra-rs`.
- Modify: `ghidra-rs/src/docking/seam_stubs.rs` (the `ComponentProvider` placeholder), `STUBS.tsv`

**Interfaces:**
- Consumes: Task 3 (`DockingAction`, `ActionContext`), `docking::WindowPosition` (already real).
- Produces:
  - `docking::ProviderId(u64)`, `Copy`.
  - `docking::ComponentProviderState`, a struct (R11) holding:
    - `name`, `owner`, `title`, `sub_title`, `tab_text`, `window_menu_group: Option<String>`, `window_group: String`
    - `default_position: WindowPosition`, `intra_group_position: WindowPosition`
    - `visible: bool`, `transient: bool`, `snapshot: bool`
    - `icon: Option<IconId>`, `help_location: Option<String>`, `view_kind: ProviderViewKind`
    - `local_action_names: Vec<String>`, `pending: Vec<ProviderChange>`

    Setters record a `ProviderChange { Title, SubTitle, TabText, Icon, Visible }` on change. `fn get_id(&self) -> String` returns `"<owner>.<name>"`-style ids as Java `getProviderId`/`getName` do. Check Java `ComponentProvider.getOwner()`/`getName()`; the persistence key is `name + owner`.
  - `docking::ComponentProvider`, a trait:
    - `fn state(&self) -> &ComponentProviderState`, `fn state_mut(&mut self) -> &mut ComponentProviderState`
    - `fn action_context(&self) -> Box<dyn ActionContext>` (Java `getActionContext(null)`; default: a `DefaultActionContext` with `provider = Some(id)`)
    - `fn component_shown(&mut self) {}`, `fn component_hidden(&mut self) {}`, `fn component_activated(&mut self) {}`, `fn component_deactivated(&mut self) {}`
  - `ghidra_ui_model::ViewKind`, an enum mirroring `ProviderViewKind`, with `impl From<&ProviderViewKind>`. **Defer** that `From` impl to U1b, when `ghidra-ui-model` gains the `ghidra-rs` dependency. In U1a, `ViewKind` stands alone with its unit test.

- [ ] **Step 1: Write the failing tests**
```rust
// ghidra-rs/src/docking/component_provider.rs
#[cfg(test)]
mod tests {
    use super::*;

    struct P(ComponentProviderState);
    impl ComponentProvider for P {
        fn state(&self) -> &ComponentProviderState { &self.0 }
        fn state_mut(&mut self) -> &mut ComponentProviderState { &mut self.0 }
    }

    fn provider() -> P {
        P(ComponentProviderState::new("Listing", "CodeBrowserPlugin", ProviderViewKind::Listing))
    }

    #[test]
    fn defaults_match_java() {
        let p = provider();
        assert_eq!(p.state().title(), "Listing"); // Java: title defaults to name
        assert_eq!(p.state().tab_text(), None);
        assert_eq!(p.state().default_position(), WindowPosition::Window);
        assert!(!p.state().is_visible());
    }

    #[test]
    fn title_change_is_recorded_once() {
        let mut p = provider();
        p.state_mut().set_title("Listing: a.out");
        p.state_mut().set_title("Listing: a.out");
        assert_eq!(p.state_mut().take_changes(), vec![ProviderChange::Title]);
    }

    #[test]
    fn default_action_context_names_the_provider() {
        let mut p = provider();
        p.state_mut().set_id(ProviderId(7));
        let ctx = p.action_context();
        assert_eq!(ctx.provider(), Some(ProviderId(7)));
    }
}
```
Before writing `defaults_match_java`, check Java `ComponentProvider`'s constructor defaults (`defaultWindowPosition = WindowPosition.WINDOW`, title = name) in `D/docking/ComponentProvider.java`. Adjust the expected values to the Java source if they differ, and ledger it.

`ghidra-ui-model/src/view_kind.rs` test: `ViewKind::Custom("graph".into()) != ViewKind::Table` and `ViewKind::all_fixed()` returns the 5 fixed kinds in spec order (Table, Tree, Text, Form, Listing).

- [ ] **Step 2: Run the tests and verify they fail. Step 3: implement** (port the `ComponentProvider.java` state and getters/setters; drop `getComponent`/`JComponent`, focus and Swing; promote the placeholder). **Step 4:** tests plus the full suite pass. **Step 5:** flip `docking/ComponentProvider.java` to DONE only if the Definition of DONE holds for the non-Swing API. Otherwise leave it TODO and ledger the reason, since much of it is Swing. Commit: `ui-model: ComponentProvider state/trait + ViewKind`.

---

### Task 5: `ToolActions` registry and `KeyBindingsManager` dispatch

**Files:**
- Create: `ghidra-rs/src/docking/actions/tool_actions.rs`
- Create: `ghidra-rs/src/docking/action/key_bindings_manager.rs`
- Modify: `ghidra-rs/src/docking/actions/mod.rs`, `ghidra-rs/src/docking/action/mod.rs`

**Interfaces:**
- Consumes: Tasks 1–4.
- Produces:
  - `docking::actions::ToolActions`, with:
    - `fn new() -> Self`
    - `fn add_global(&mut self, action: Box<dyn DockingActionIf>) -> ActionId`
    - `fn add_local(&mut self, provider: ProviderId, action: Box<dyn DockingActionIf>) -> ActionId`
    - `fn remove(&mut self, id: ActionId) -> Option<Box<dyn DockingActionIf>>`
    - `fn remove_provider_actions(&mut self, provider: ProviderId)`
    - `fn get(&self, id) -> Option<&dyn DockingActionIf>`, `fn get_mut(..)`
    - `fn actions_for_key(&self, ks: KeyStroke) -> Vec<ActionId>`
    - `fn global_actions(&self) -> impl Iterator<Item = ActionId>`
    - `fn local_actions(&self, p: ProviderId) -> impl Iterator<Item = ActionId>`
    - `fn set_key_binding(&mut self, id, data: Option<KeyBindingData>)` (keeps the key index in sync)
    - `fn take_all_changes(&mut self) -> Vec<(ActionId, ActionChange)>`

    `Box<dyn DockingActionIf>` is the accepted open extension point here (P5: actions are plugin-supplied).
  - `docking::action::KeyBindingsManager`, with:
    - `fn dispatch(actions: &mut ToolActions, ks: KeyStroke, focused: Option<ProviderId>, ctx_for: &dyn Fn(Option<ProviderId>) -> Box<dyn ActionContext>) -> DispatchResult`
    - `DispatchResult { Performed(ActionId), Disabled(ActionId), Ambiguous(Vec<ActionId>), NotHandled }`

    Resolution ports Java `KeyBindingsManager` + `MultipleKeyAction.getValidContextActions`:
    1. Collect candidates bound to `ks`. Precedence: lower `KeyBindingPrecedence` first.
    2. **Local pass:** candidates owned by `focused`, checked against the focused provider's context. Keep those whose `is_context_applicable && is_valid_context`.
    3. If none, **global pass:** global candidates checked against the focused (or default) context.
    4. Exactly one valid and enabled-for-context candidate gives `Performed` (run `action_performed`).
    5. One valid but disabled gives `Disabled`.
    6. More than one valid and enabled gives `Ambiguous` (the shell shows Ghidra's action-chooser dialog in U1b).
    7. None gives `NotHandled`.

- [ ] **Step 1: Write the failing tests** (`key_bindings_manager.rs`)
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::DefaultActionContext;
    use crate::util::awt::key_stroke::{vk, CTRL_DOWN_MASK};

    struct A { s: DockingAction, hits: std::rc::Rc<std::cell::Cell<u32>>, valid: bool, enabled: bool }
    impl ActionBehavior for A {
        fn action_performed(&mut self, _c: &dyn ActionContext) { self.hits.set(self.hits.get() + 1); }
        fn is_valid_context(&self, _c: &dyn ActionContext) -> bool { self.valid }
        fn is_enabled_for_context(&self, _c: &dyn ActionContext) -> bool { self.enabled }
    }
    impl DockingActionIf for A {
        fn state(&self) -> &DockingAction { &self.s }
        fn state_mut(&mut self) -> &mut DockingAction { &mut self.s }
    }
    fn act(name: &str, valid: bool, enabled: bool) -> (Box<A>, std::rc::Rc<std::cell::Cell<u32>>) {
        let hits = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut s = DockingAction::new(name, "T");
        s.set_key_binding_data(Some(KeyBindingData::new(ctrl_g())));
        (Box::new(A { s, hits: hits.clone(), valid, enabled }), hits)
    }
    fn ctrl_g() -> KeyStroke { KeyStroke::new(vk::G, CTRL_DOWN_MASK) }
    fn ctx(p: Option<ProviderId>) -> Box<dyn ActionContext> {
        Box::new(DefaultActionContext::new().with_provider(p))
    }

    #[test]
    fn focused_provider_local_action_beats_global() {
        let mut t = ToolActions::new();
        let (g, g_hits) = act("Global", true, true);
        let (l, l_hits) = act("Local", true, true);
        t.add_global(g);
        let lid = t.add_local(ProviderId(1), l);
        let r = KeyBindingsManager::dispatch(&mut t, ctrl_g(), Some(ProviderId(1)), &ctx);
        assert_eq!(r, DispatchResult::Performed(lid));
        assert_eq!((l_hits.get(), g_hits.get()), (1, 0));
    }

    #[test]
    fn global_fires_when_no_local_is_valid() {
        let mut t = ToolActions::new();
        let (g, g_hits) = act("Global", true, true);
        let (l, _) = act("Local", false, true);
        let gid = t.add_global(g);
        t.add_local(ProviderId(1), l);
        assert_eq!(
            KeyBindingsManager::dispatch(&mut t, ctrl_g(), Some(ProviderId(1)), &ctx),
            DispatchResult::Performed(gid)
        );
        assert_eq!(g_hits.get(), 1);
    }

    #[test]
    fn other_providers_local_actions_are_ignored() {
        let mut t = ToolActions::new();
        let (l, hits) = act("Local", true, true);
        t.add_local(ProviderId(2), l);
        assert_eq!(
            KeyBindingsManager::dispatch(&mut t, ctrl_g(), Some(ProviderId(1)), &ctx),
            DispatchResult::NotHandled
        );
        assert_eq!(hits.get(), 0);
    }

    #[test]
    fn valid_but_disabled_reports_disabled() {
        let mut t = ToolActions::new();
        let (g, hits) = act("Global", true, false);
        let gid = t.add_global(g);
        assert_eq!(
            KeyBindingsManager::dispatch(&mut t, ctrl_g(), None, &ctx),
            DispatchResult::Disabled(gid)
        );
        assert_eq!(hits.get(), 0);
    }

    #[test]
    fn two_valid_enabled_globals_are_ambiguous() {
        let mut t = ToolActions::new();
        let (a, _) = act("A", true, true);
        let (b, _) = act("B", true, true);
        let ia = t.add_global(a);
        let ib = t.add_global(b);
        match KeyBindingsManager::dispatch(&mut t, ctrl_g(), None, &ctx) {
            DispatchResult::Ambiguous(mut ids) => {
                ids.sort();
                assert_eq!(ids, vec![ia, ib]);
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn unbound_key_is_not_handled_and_rebinding_updates_index() {
        let mut t = ToolActions::new();
        let (a, _) = act("A", true, true);
        let id = t.add_global(a);
        let ctrl_h = KeyStroke::new(vk::H, CTRL_DOWN_MASK);
        assert_eq!(KeyBindingsManager::dispatch(&mut t, ctrl_h, None, &ctx), DispatchResult::NotHandled);
        t.set_key_binding(id, Some(KeyBindingData::new(ctrl_h)));
        assert_eq!(KeyBindingsManager::dispatch(&mut t, ctrl_h, None, &ctx), DispatchResult::Performed(id));
        assert_eq!(KeyBindingsManager::dispatch(&mut t, ctrl_g(), None, &ctx), DispatchResult::NotHandled);
    }
}
```
(`Rc<Cell>` appears in test doubles only, to observe hits. It is not part of the production API.)

- [ ] **Step 2: Run the tests and verify they fail. Step 3: implement** (port the `D/docking/action/KeyBindingsManager.java` + `MultipleKeyAction.java` resolution rules above; `ToolActions` ports the registry and key-index parts of `D/docking/actions/ToolActions.java`, but not shared-key-binding stubs or options persistence, which are deferred to U1b/M2). **Step 4:** tests plus the full suite pass. **Step 5:** commit `ui-model: ToolActions registry + context-sensitive KeyBindingsManager dispatch`. Do not flip ToolActions/KeyBindingsManager to DONE, since parts are deferred; ledger it.

---

### Task 6: `DockingTool` and `DockLayout` persistence

**Files:**
- Create: `ghidra-rs/src/docking/docking_tool.rs`
- Create: `ghidra-rs/src/docking/dock_layout.rs`

**Interfaces:**
- Consumes: Tasks 3–5; `framework::options::SaveState` (real since a3c90f4c) and `util::xml::element::Element` (canonical since 3732b858).
- Produces:
  - `docking::DockingTool`, holding `name`, `providers: BTreeMap<ProviderId, Box<dyn ComponentProvider>>`, `actions: ToolActions` and `layout: DockLayout`, with:
    - `fn add_provider(&mut self, p: Box<dyn ComponentProvider>, show: bool) -> ProviderId` (assigns the id and records the provider in the layout with its default position)
    - `fn remove_provider(&mut self, id)` (also removes its local actions)
    - `fn show_provider(&mut self, id, visible: bool)`
    - `fn provider(&self, id) -> Option<&dyn ComponentProvider>`
    - `fn find_provider(&self, owner: &str, name: &str) -> Option<ProviderId>`
    - `fn add_action`, `fn add_local_action`
    - `fn dispatch_key(&mut self, ks, focused) -> DispatchResult` (builds contexts from providers)
    - `fn save_layout(&self) -> SaveState`, `fn restore_layout(&mut self, s: &SaveState)`
  - `docking::DockLayout`, holding `entries: BTreeMap<String /*owner.name*/, LayoutEntry { visible: bool, position: WindowPosition, group: String }>` and `geometry: Option<Vec<u8>>` (the renderer's opaque blob; ADS `saveState()` in U1b). It stores and restores through `SaveState`, using keys `"PROVIDER:<owner>.<name>"` and a `"GEOMETRY"` byte array.

- [ ] **Step 1: Write the failing tests** (`docking_tool.rs`)
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::{ComponentProviderState, ProviderViewKind, WindowPosition};

    struct P(ComponentProviderState);
    impl ComponentProvider for P {
        fn state(&self) -> &ComponentProviderState { &self.0 }
        fn state_mut(&mut self) -> &mut ComponentProviderState { &mut self.0 }
    }
    fn p(name: &str, pos: WindowPosition) -> Box<dyn ComponentProvider> {
        let mut s = ComponentProviderState::new(name, "Owner", ProviderViewKind::Table);
        s.set_default_position(pos);
        Box::new(P(s))
    }

    #[test]
    fn layout_round_trips_visibility_position_and_geometry() {
        let mut t = DockingTool::new("CodeBrowser");
        let a = t.add_provider(p("A", WindowPosition::Left), true);
        let _b = t.add_provider(p("B", WindowPosition::Bottom), false);
        t.layout_mut().set_geometry(Some(vec![1, 2, 3]));
        let saved = t.save_layout();

        let mut t2 = DockingTool::new("CodeBrowser");
        let a2 = t2.add_provider(p("A", WindowPosition::Right), false); // different default
        let b2 = t2.add_provider(p("B", WindowPosition::Bottom), true);
        t2.restore_layout(&saved);
        assert!(t2.provider(a2).unwrap().state().is_visible());
        assert!(!t2.provider(b2).unwrap().state().is_visible());
        assert_eq!(t2.layout().entry("Owner.A").unwrap().position, WindowPosition::Left);
        assert_eq!(t2.layout().geometry(), Some(&[1u8, 2, 3][..]));
        let _ = a;
    }

    #[test]
    fn restore_ignores_unknown_and_defaults_new_providers() {
        let mut old = DockingTool::new("T");
        old.add_provider(p("Gone", WindowPosition::Top), true);
        let saved = old.save_layout();

        let mut t = DockingTool::new("T");
        let n = t.add_provider(p("New", WindowPosition::Right), true);
        t.restore_layout(&saved); // must not error on "Owner.Gone"
        assert!(t.provider(n).unwrap().state().is_visible());
        assert_eq!(t.layout().entry("Owner.New").unwrap().position, WindowPosition::Right);
        assert!(t.layout().entry("Owner.Gone").is_none());
    }

    #[test]
    fn removing_a_provider_removes_its_local_actions() {
        let mut t = DockingTool::new("T");
        let id = t.add_provider(p("A", WindowPosition::Left), true);
        t.add_local_action(id, Box::new(crate::docking::action::tests_support::noop_action("X")));
        assert_eq!(t.actions().local_actions(id).count(), 1);
        t.remove_provider(id);
        assert_eq!(t.actions().local_actions(id).count(), 0);
    }
}
```
Create `docking/action/tests_support.rs` as a `#[cfg(test)] pub(crate) mod` with `noop_action(name) -> impl DockingActionIf` for reuse.

- [ ] **Step 2: Run the tests and verify they fail. Step 3: implement** (the persistence key format follows Ghidra's `DockingWindowManager`/`PlaceholderManager` XML in spirit; exact Swing placeholder XML compatibility is not a goal, so ledger it). **Step 4:** tests plus the full suite pass. **Step 5:** commit `ui-model: DockingTool + DockLayout save/restore`.

---

### Task 7: `UiEventQueue` and `Waker` (ghidra-ui-model)

**Files:**
- Create: `ghidra-ui-model/src/events.rs`
- Modify: `ghidra-ui-model/src/lib.rs`

**Interfaces:**
- Produces:
  - `ghidra_ui_model::UiEvent` enum:
    - `DomainChanged { object: u64, ranges: Vec<(u64, u64)> }`
    - `TaskProgress { task: u64, message: String, progress: u64, maximum: u64 }`
    - `TaskDone { task: u64, cancelled: bool, error: Option<String> }`
    - `ProviderAdded(u64)`, `ProviderRemoved(u64)`, `ActionsChanged`, `LocationChanged { object: u64, address: u64 }`
  - `ghidra_ui_model::UiEventQueue`: `Clone + Send + Sync`, with:
    - `fn new() -> (UiEventQueue, WakeHandle)`
    - `fn post(&self, e: UiEvent)` (callable from any thread)
    - `fn drain(&self) -> Vec<UiEvent>` (UI thread), which coalesces `DomainChanged` per `object` by merging and sorting the ranges, keeps the latest `TaskProgress` per task, and keeps `ActionsChanged` once
  - `ghidra_ui_model::WakeHandle`:
    - on Unix, `fn raw_fd(&self) -> i32`, the read end of a `UnixStream::pair`; the shell wraps it in a `QSocketNotifier`
    - `fn clear(&self)` (drains pending wake bytes)
    - posting writes **one** wake byte only on the empty→non-empty transition (tracked with an `AtomicBool`), which is reset in `drain()`

- [ ] **Step 1: Write the failing tests**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_changes_coalesce_per_object() {
        let (q, _w) = UiEventQueue::new();
        for i in 0..1000u64 {
            q.post(UiEvent::DomainChanged { object: 1, ranges: vec![(i, i)] });
        }
        q.post(UiEvent::DomainChanged { object: 2, ranges: vec![(5, 9)] });
        let ev = q.drain();
        let objs: Vec<u64> = ev.iter().filter_map(|e| match e {
            UiEvent::DomainChanged { object, .. } => Some(*object), _ => None }).collect();
        assert_eq!(objs, vec![1, 2]);
        if let UiEvent::DomainChanged { ranges, .. } = &ev[0] {
            assert_eq!(ranges, &vec![(0, 999)]); // adjacent ranges merged
        } else { panic!() }
        assert!(q.drain().is_empty());
    }

    #[test]
    fn latest_progress_wins_and_actions_changed_once() {
        let (q, _w) = UiEventQueue::new();
        q.post(UiEvent::TaskProgress { task: 1, message: "a".into(), progress: 1, maximum: 10 });
        q.post(UiEvent::ActionsChanged);
        q.post(UiEvent::TaskProgress { task: 1, message: "b".into(), progress: 7, maximum: 10 });
        q.post(UiEvent::ActionsChanged);
        let ev = q.drain();
        assert_eq!(ev.iter().filter(|e| matches!(e, UiEvent::ActionsChanged)).count(), 1);
        assert!(ev.iter().any(|e| matches!(e, UiEvent::TaskProgress { progress: 7, .. })));
        assert!(!ev.iter().any(|e| matches!(e, UiEvent::TaskProgress { progress: 1, .. })));
    }

    #[cfg(unix)]
    #[test]
    fn waker_signals_once_per_drain_cycle() {
        use std::io::Read;
        use std::os::fd::FromRawFd;
        let (q, w) = UiEventQueue::new();
        for _ in 0..50 { q.post(UiEvent::ActionsChanged); }
        // exactly one wake byte available
        let mut f = unsafe { std::fs::File::from_raw_fd(libc_dup(w.raw_fd())) };
        set_nonblocking(&f);
        let mut buf = [0u8; 64];
        assert_eq!(f.read(&mut buf).unwrap_or(0), 1);
        q.drain();
        q.post(UiEvent::ActionsChanged);
        assert_eq!(f.read(&mut buf).unwrap_or(0), 1);
    }

    #[test]
    fn post_from_other_threads() {
        let (q, _w) = UiEventQueue::new();
        let hs: Vec<_> = (0..4).map(|t| { let q = q.clone(); std::thread::spawn(move || {
            for i in 0..100 { q.post(UiEvent::DomainChanged { object: t, ranges: vec![(i, i)] }); }
        })}).collect();
        for h in hs { h.join().unwrap(); }
        assert_eq!(q.drain().len(), 4);
    }
}
```
The `libc_dup`/`set_nonblocking` helpers in the waker test: implement them without a `libc` dependency, as `#[cfg(test)]` helpers in the test module. Get a second handle with `UnixStream::try_clone` on the read end, exposed via a `#[cfg(test)] fn reader_clone(&self) -> UnixStream` on `WakeHandle`, and call `set_nonblocking(true)`. Rewrite the test to use that instead of raw-fd dup. Ledger it as a plan correction (the raw-fd dup sketch above needs `libc`, which is not a dependency).

- [ ] **Step 2: Run the tests and verify they fail. Step 3: implement** (a `Mutex<Vec<UiEvent>>` queue plus `AtomicBool` pending flag plus `UnixStream` pair; coalescing in `drain`). **Step 4:** `CARGO_BUILD_JOBS=4 cargo test -p ghidra-ui-model` passes. **Step 5:** commit `ui-model: UiEventQueue with coalescing drain + fd waker`.

---

### Task 8: View-model traits (ghidra-ui-model)

**Files:**
- Create: `ghidra-ui-model/src/view_models.rs`
- Create: `ghidra-ui-model/src/demo.rs` (in-memory implementations used by the U1b demo tool and by these tests)
- Modify: `ghidra-ui-model/src/lib.rs`

**Interfaces:**
- Produces (all `Send`; methods are snapshot reads with no I/O, per spec §3):
  - `CellValue` enum: `Text(String)`, `Int(i64)`, `Address(u64)`, `Bool(bool)`, `Empty`
  - `trait TableModel`:
    - `fn column_count(&self) -> usize`, `fn column_name(&self, c: usize) -> String`
    - `fn row_count(&self) -> usize`, `fn cell(&self, row: usize, col: usize) -> CellValue`
    - `fn sort(&mut self, col: usize, ascending: bool)` (default no-op)
    - `fn set_filter(&mut self, text: &str)` (default no-op)
    - `fn is_editable(&self, row, col) -> bool { false }`
    - `fn edit(&mut self, row, col, value: &str) -> Result<(), String> { Err("not editable".into()) }`
  - `trait TreeModel`: `NodeId(u64)`, with:
    - `fn root(&self) -> NodeId`, `fn child_count(&self, n: NodeId) -> usize`, `fn child(&self, n: NodeId, i: usize) -> NodeId`
    - `fn parent(&self, n: NodeId) -> Option<NodeId>`, `fn label(&self, n: NodeId) -> String`
    - `fn icon(&self, n: NodeId) -> Option<String>` (theme icon id), `fn is_leaf(&self, n: NodeId) -> bool { self.child_count(n) == 0 }`
  - `StyledRun { text: String, color_id: Option<String> /*GColor id*/, bold: bool, italic: bool, link: Option<String> }`
  - `trait TextModel`: `fn line_count(&self) -> usize`, `fn line(&self, i: usize) -> Vec<StyledRun>`
  - `FormField { key: String, label: String, kind: FormFieldKind /*Text, Int, Bool, Choice(Vec<String>)*/, value: String }` and `trait FormModel`: `fn fields(&self) -> Vec<FormField>`, `fn set(&mut self, key: &str, value: &str) -> Result<(), String>`
  - `demo::{VecTable, StaticTree, LinesText, MapForm}`, simple in-memory implementations

- [ ] **Step 1: Write the failing tests**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo::*;

    #[test]
    fn vec_table_sorts_and_filters() {
        let mut t = VecTable::new(vec!["Name".into(), "Size".into()], vec![
            vec![CellValue::Text("b".into()), CellValue::Int(2)],
            vec![CellValue::Text("a".into()), CellValue::Int(10)],
            vec![CellValue::Text("c".into()), CellValue::Int(1)],
        ]);
        t.sort(1, true);
        assert_eq!(t.cell(0, 0), CellValue::Text("c".into()));
        t.set_filter("a");
        assert_eq!(t.row_count(), 1);
        t.set_filter("");
        assert_eq!(t.row_count(), 3);
    }

    #[test]
    fn static_tree_navigation() {
        let t = StaticTree::from_paths(&["root/a/x", "root/a/y", "root/b"]);
        let r = t.root();
        assert_eq!(t.label(r), "root");
        assert_eq!(t.child_count(r), 2);
        let a = t.child(r, 0);
        assert_eq!(t.label(a), "a");
        assert_eq!(t.child_count(a), 2);
        assert_eq!(t.parent(a), Some(r));
        assert!(t.is_leaf(t.child(r, 1)));
    }

    #[test]
    fn map_form_validates_int_fields() {
        let mut f = MapForm::new(vec![FormField::int("depth", "Depth", 3)]);
        assert!(f.set("depth", "12").is_ok());
        assert!(f.set("depth", "twelve").is_err());
        assert!(f.set("missing", "1").is_err());
        assert_eq!(f.fields()[0].value, "12");
    }

    #[test]
    fn lines_text_returns_runs() {
        let t = LinesText::new(vec!["int main() {".into(), "}".into()]);
        assert_eq!(t.line_count(), 2);
        assert_eq!(t.line(0)[0].text, "int main() {");
    }
}
```

- [ ] **Step 2: Run the tests and verify they fail. Step 3: implement. Step 4:** `CARGO_BUILD_JOBS=4 cargo test -p ghidra-ui-model` passes. **Step 5:** commit `ui-model: generic view-model traits + in-memory demo models`.

---

## Milestone note

U1a ends without a human gate: there is nothing visual yet. **U1b** (Qt rendering of all this) is the next plan. It is written after U1a lands. Its human gate covers U1a+U1b together: the demo tool with menus, toolbars, key dispatch, and table/tree/text/form panes.
