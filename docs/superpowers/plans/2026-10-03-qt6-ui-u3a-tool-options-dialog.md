# Qt6 UI — U3a Tool Options Dialog Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Edit → Tool Options opens Ghidra's options dialog over the ported `ToolOptions`.
- **Layout:**
  - Title "Options for <tool>".
  - On the left, a category tree under the root "Options".
  - On the right, the selected category's options as a form; each option's description is its tooltip.
- **Buttons:**
  - OK, Apply and Cancel.
  - "Restore Defaults", which asks for confirmation first.
- **Persistence:** values are saved with the tool configuration.

**Architecture:**
- **Dialog seam extension** (`dialogs.rs`):
  - `DialogSpec` gains optional `panes` (a tree and a form) and extra `buttons` (`ButtonSpec { key, label, confirm }`).
  - `DialogModel` gains `panes()`, returning view-model adapters, and `button(key)`.
- **Pane view models:** the session registers the pane view models under dialog-scoped ids, which sit in a reserved high range outside tool provider ids. The existing generic C++ Tree and Form widgets and the pid-keyed bridge functions then drive them unchanged.
- **Tree selection:** `TreeModel::select(node)` is new, with a default no-op. It tells the options model which category the form shows.
- **Staging:** all logic stays in `ghidra-ui-model::options_dialog`. Edits are staged per option and written on Apply/OK with the typed `ToolOptions` setters. Errors go to the dialog status line.

**Spec:** `docs/superpowers/specs/2026-10-01-qt6-ui-design.md` §4 ("Options / Edit Options: ported options model → generic FormView + TreeView dialog").

## Java parity
- `PluginTool.addOptionsAction`: "Edit Options", menu `Edit > &Tool Options`.
- `OptionsManager.editOptions`: dialog "Options for " + tool name, root node "Options". One `ToolOptions` becomes the root itself; several become children.
- `OptionsPanel`: a category tree (single selection, root expanded and selected) and the editor panel.
  - "Restore Defaults" confirms with "Restore Defaults?" / "Restore <name> to default option values and erase current settings?" and restores the selected options immediately.
- `OptionsDialog`: OK, Cancel, Apply. OK applies, then closes; Cancel discards staged edits.

## Review Focus
1. **Invalid values:** a value that fails its type (e.g. "abc" for an int) is reported in the status line. Nothing is written, and the dialog stays open on OK.
2. **Cancel:** staged edits are discarded, so reopening shows the stored values.
3. **Restore Defaults:** only the selected category's subtree is affected.
4. **Pane lifetime:** dialog-scoped view-model ids are released on close/cancel and never collide with providers.
5. **Option types the form can't edit natively** (Date, Color, Font, KeyStroke, Custom, ByteArray) are read-only, never corrupted.

## Tasks
1. `options_dialog.rs` (pure):
   - `OptionsDialogState` over named `Arc<ToolOptions>`;
   - the category tree (`TreeModel`) and the selected-category form (`FormModel` with tooltips and read-only fields);
   - stage, apply, cancel, restore defaults.
2. Dialog seam: panes and buttons in `DialogSpec`/`DialogModel`; session registration of pane view models; bridge `dialog_panes`, `dialog_button` and `tree_select`; `FormField` gains `tooltip` and `read_only`.
3. C++ `RustDialog`:
   - a split pane hosting `makeTree`/`makeForm` for the pane ids;
   - extra buttons, with a `QMessageBox` confirmation where `confirm` is set;
   - form rebuild after a tree selection or button press.
4. Demo:
   - `ToolOptions` "Tool" with "Max Goto Entries" (int, default 10), wired by a listener to `GoToAddressLabelDialog::set_max_entries` (fixes deferred minor M10);
   - the Edit → Tool Options action;
   - persistence through `ConfigState` (`ToolOptions` XML).
5. Smoke: open the dialog, set Max Goto Entries via auto-answer hooks, and verify persistence across a restart.
