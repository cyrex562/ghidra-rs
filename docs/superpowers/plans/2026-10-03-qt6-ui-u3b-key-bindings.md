# Qt6 UI — U3b Key Bindings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox syntax.

**Goal:** Key bindings become editable in Tool Options → Key Bindings, persist with the tool, and take effect immediately. This is Ghidra's model: a "Key Bindings" `ToolOptions` with one `ACTION_TRIGGER` option per action, and `ToolActions` listening to it.

**Architecture:**
- **T1, ghidra-rs `docking`:** `DockingTool` owns the key-binding `ToolOptions` (`DockingToolConstants.KEY_BINDINGS` = "Key Bindings").
  - Registering an `Individual` key-binding action registers option `"<name> (<owner>)"`: type `ActionTrigger`, default = the action's trigger, description "Key Binding for <full name>".
  - It then loads the option's value into the action (`loadKeyBindingFromOptions`).
  - Option changes reach the tool through the `ToolRequests` queue, as `SetActionTrigger(full name, trigger?)`. `apply_requests` updates every action with that full name (`ToolActions.optionsChanged`).
- **T2, `framework::options`:** port `WrappedActionTrigger`, so `ActionTrigger` values persist in the options XML (key stroke + mouse binding text).
- **T3, `ghidra-ui-model`:** the options dialog shows a table, not a form, for an options set registered with a table editor (`ToolOptions::register_options_editor`, as Java's custom `OptionsEditor`).
  - The Key Bindings table has columns Action Name | Key Binding | Owner. The Key Binding cell is editable: text like "Ctrl-F" parsed with `KeyStroke::parse`, empty to clear.
  - Edits are staged and applied on Apply/OK like the form.
  - The status line notes when the binding is already used, listing the other actions ("Key binding … is used by: …"). Ghidra allows shared bindings and shows a chooser at dispatch.
- **T4, seam and C++:**
  - `DialogSpec` gains `pane_kind` (0 = form, 1 = table) for the current selection, and `DialogModel::panes` adds a table view model.
  - `RustDialog` swaps the right pane between the generic form and table views.
- **T5, demo:** the session saves the Key Bindings options with the tool config. Smoke: rebind "Go To Address/Label" to "Ctrl-J"; after a restart, Ctrl-J opens Go To and G no longer does.

**Spec:** §4 rows "Key bindings (context-sensitive)" and "Options / Edit Options".

## Java parity
- `ToolActions.loadKeyBindingFromOptions` / `optionsChanged` / `getKeyBindingActionsIterator`: only `KeyBindingType.INDIVIDUAL` actions get options.
- `KeyBindingsPanel` columns: "Action Name", "Key Binding", "Owner" (Description hidden).
- `KeyBindingData.update`.

## Review Focus
1. Clearing a binding (empty cell) removes it, and the default is restorable with Restore Defaults.
2. An unparseable key text gives a status error, stays visible and blocks OK (as for form fields).
3. Two actions with the same full name (local actions of several providers) both follow the option.
4. Window-menu actions (`DockingWindows` owner, `Shared`/`Unsupported` binding types) never appear.
5. A saved binding for an action that registers later is applied when it registers.
