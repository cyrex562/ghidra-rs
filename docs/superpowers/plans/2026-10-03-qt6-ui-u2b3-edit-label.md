# Qt6 UI — U2b-3 Edit Label Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans.

**Goal:** Spec §5 M1 "inline edits: rename label". Java `LabelMgrPlugin` "Edit Label" (key `L`, popup "Edit Label...") opens the `AddEditDialog` titled "Edit Label at <address>" on a label row. OK renames the symbol with `SourceType.USER_DEFINED`. The listing and the Symbols pane show the new name.

**Architecture:**
- **T1, label identity:**
  - `LabelSnapshot.id: i64` and `ImportedSymbol.id: i64` (the symbol id; 0 for fixtures).
  - `CodeUnitListing` keeps header rows apart from label rows, as `SegKind::Header`.
  - `ListingViewModel::label_at(index) -> Option<(i64, String)>` returns the symbol of a label row, and defaults to `None`.
- **T2, shared Symbols table:** `SharedTable(Arc<Mutex<VecTable>>)` implements `TableModel` by delegation, plus `VecTable::update_rows(f)`. The Symbols pane uses it in program mode.
- **T3, action and dialog:**
  - "Edit Label" (owner LabelMgrPlugin, key L, popup "Edit Label...", group "Label") is enabled on the Listing when the cursor row is a label row.
  - `EditLabelDialog` (DialogModel) has title "Edit Label at <address>" and its combo is pre-filled with the name.
  - OK calls `ProgramDB::get_symbol_table().write().set_symbol_name(id, text, UserDefined)`. An error keeps the dialog open with the message as the status. An empty name gets Java's status: "Label name cannot be blank" (not checked against Java's exact text yet).
  - On success:
    - the `ListingEditor` relabels its label set and rebuilds the listing;
    - the Symbols table row gets the new name and Source "User Defined";
    - the session posts `ViewChanged` for the listing, plus `DomainChanged` for the Symbols table.

## Review Focus
1. A duplicate name in the same namespace: the status shows the core's error and nothing changes.
2. Renaming to the same name is a no-op success.
3. Header rows (`//`) are not labels: L is disabled there.
4. An offcut label row renames its own symbol, not the code unit's.
5. The cursor stays on the renamed label row after the rebuild.
