# Qt6 UI — U2b-2 Follow References Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans.

**Goal:** Spec §5 M1 "click-to-follow references". Double-clicking an instruction operand that has a memory reference goes to the reference's address, with history (Java `OperandFieldMouseHandler.checkMemRefs`, one address).

**Architecture:**
- **T1, snapshot:** `InstructionSnapshot.references: Vec<OperandRef { op_index: i32, to: u64 }>`, the primary memory references per operand, taken from `ProgramDB::get_reference_store().primary_reference_from(addr, op)` for each operand.
  - The import and `ListingEditor` refreshes fill it. A cleared instruction drops its references along with it.
- **T2, model and controller:**
  - `ListingViewModel::reference_target(cursor) -> Option<u64>`, which defaults to `None`.
  - `CodeUnitListing` maps the cursor column in the Operands field to an operand index by splitting the operand text at top-level commas, ignoring commas inside `[]` and `()`. It returns that operand's reference.
  - `ListingController::activate(x, y) -> bool` places the cursor like a click, then calls `goto_address(target)` when the cursor has a target, which records history.
- **T3, seam:**
  - Bridge `listing_intent` kind 6 (activate). When it navigates, it posts `ActionsChanged` so back/forward update.
  - C++ `ListingView::mouseDoubleClickEvent` (left button) sends kind 6.

## Review Focus
1. A double-click on the mnemonic, the bytes, a label row, or an operand with no reference does nothing but place the cursor (like a click).
2. A column past the end of the operand text belongs to the last operand.
3. `x86` operand text `qword ptr [RIP + 0x2fe2]` contains no top-level comma, so it is one operand, operand 0.
4. A reference to an address outside the listing (unlisted): no move, no history entry.
5. After Clear Code Bytes the reference is gone, and a double-click there does nothing.
