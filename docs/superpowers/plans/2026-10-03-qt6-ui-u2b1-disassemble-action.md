# Qt6 UI — U2b-1 Live Program + Disassemble Action Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox syntax.

**Goal:** The `--open` session keeps the live `ProgramDB`. Ghidra's "Disassemble" action (DisassemblerPlugin, key binding `D`, popup and Edit menu) disassembles from the listing cursor, or from the selection. The listing then re-snapshots. Cursor, scroll, selection and history are kept by address.

**Architecture:**
- **T1, `ghidra-ui-model::listing` and `listing_controller`:**
  - `ListingViewModel::address_of(index) -> Option<u64>`, the numeric form of `address_text`. It is implemented for `MemoryListing` and `CodeUnitListing`.
  - `ListingController::replace_model(model)` swaps the view-model. Java keeps `ProgramLocation`s and address-set selections, so the controller maps its index state through addresses:
    - The top row, the cursor (field 0, col 0 on the first row at the address) and the selection ranges each map to the first row at their addresses.
    - The selection's end maps to the last row at its address.
    - History mementos record the address and a model epoch. A memento from an older epoch resolves by address.
- **T2, `program_import`:**
  - `open_elf(path, dist) -> Result<(Arc<ProgramDB>, ImportedProgram), String>`. `import_elf` returns its `.1`.
  - `ImportedProgram.live: Option<LiveProgram>` wraps `Arc<ProgramDB>`. It compares by pointer, and its Debug prints only the name.
  - `snapshot_instructions(&ProgramDB, &[(start, end)])` is shared by the import and the refresh.
- **T3, `demo_tool`:**
  - With a live program, the session adds "Disassemble" (owner "DisassemblerPlugin", key `D`, Edit menu "Disassemble"). It is enabled when the context is the Listing with a cursor.
  - On perform it runs `DisassembleCommand::new(cursor address, None, true)`, or `with_start_set(selection)` when there is a selection.
  - It then rebuilds the `CodeUnitListing` from the program and calls `replace_model`. It posts `DomainChanged` for the listing, plus a status message from the command when it fails.
- **T4, smoke:** in `--open /bin/ls`, go to a known-undefined code address, press `D`, and the copied row shows an instruction mnemonic.

## Review Focus
1. `replace_model` when an address vanished. For example, a byte inside a new instruction: the cursor lands on the containing instruction row, as `goto` does. Nothing panics on an empty model.
2. Back/forward across a disassembly: an entry recorded before it lands on the same address afterwards.
3. Disassemble on a label row, or a row past the end: the cursor address is the row's code unit, and the action is a no-op outside memory.
4. A disassembly that fails (uninitialized memory): a status message and an unchanged listing.
5. Selection across rows that merge into one instruction: it stays non-empty and covers the instruction.
