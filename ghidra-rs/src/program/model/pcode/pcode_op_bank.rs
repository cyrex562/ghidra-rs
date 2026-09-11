//! Port of `ghidra.program.model.pcode.PcodeOpBank`.
//!
//! A container for [`PcodeOpAST`]s, keyed by [`SequenceNumber`] and additionally tracked on two
//! "alive"/"dead" doubly-linked lists. Used by `PcodeSyntaxTree` (not yet ported -- out of scope
//! here) to hold every pcode op in a decompiled function's syntax tree.
//!
//! ## Typing deviation: concrete `Arc<PcodeOpAST>` instead of `PcodeOp` + downcast
//!
//! Every Java method here (`destroy`, `changeOpcode`, `markAlive`, `markDead`) takes a plain
//! `PcodeOp` and immediately casts it to `PcodeOpAST` (`(PcodeOpAST) op`), relying on the runtime
//! invariant that every op a `PcodeOpBank` is ever asked to operate on was created by that same
//! bank's own `create` methods (so the cast always succeeds). This port makes that invariant
//! static instead of runtime-checked: these methods take `&Arc<PcodeOpAST>` directly, which is
//! both more precise and avoids needing a fallible-cast story `PcodeOpAST`'s existing port doesn't
//! provide.
//!
//! ## Typing deviation: `ListLinked<Object>` becomes `ListLinked<Arc<PcodeOpAST>>`
//!
//! Java's `deadList`/`aliveList` are declared `ListLinked<Object>`, but every element ever placed
//! in them (via `create`/`markAlive`/`markDead`) is a `PcodeOpAST`. This port uses
//! `ListLinked<Arc<PcodeOpAST>>` for both, which is behaviorally identical but type-safe.
//!
//! ## Deviation: `allOrdered`/`allAlive`/`allDead` return owned snapshots, not live iterators
//!
//! Java's `TreeMap.values().iterator()` (and `ListLinked`'s own iterator) are *live* views: they
//! reflect concurrent mutation of the bank (and, for the `TreeMap` case, throw
//! `ConcurrentModificationException` on most such mutations). Reproducing that fail-fast aliasing
//! behavior would require unsafe or a redesign of `ListLinked`'s cursor API; instead these methods
//! return an owned `Vec<Arc<PcodeOpAST>>` snapshot of the ops in the requested order/set at the
//! time of the call. Since `Arc<PcodeOpAST>` clones are cheap reference-count bumps (not deep
//! copies), callers still see the same underlying, still-mutable op objects.
//!
//! ## Quirk: `destroy`'s liveness guard never fires
//!
//! `destroy(PcodeOp op)` starts with `if (!op_ast.isDead()) return;` -- i.e. it silently refuses
//! to destroy an op that is not "dead". But `PcodeOpAST.bDead` is set `true` once, in the
//! constructor, and **never** has a setter anywhere in `PcodeOpAST.java` (confirmed: the only
//! writes to `bDead` in the whole file are the constructor's `bDead = true;`). `markAlive`/
//! `markDead` only move the op between `PcodeOpBank`'s alive/dead lists -- they never touch
//! `bDead`. So `isDead()` always returns `true`, and this guard is dead code: `destroy` always
//! proceeds, even for an op that was just `markAlive`'d and is sitting in the alive list. This
//! port reproduces that faithfully (see
//! [`destroy_removes_op_even_though_marked_alive`](tests::destroy_removes_op_even_though_marked_alive)),
//! rather than "fixing" the guard to actually check the alive/dead list membership.
//!
//! ## `changeOpcode`
//!
//! Java's `changeOpcode(PcodeOp op, int newopc)` calls `((PcodeOpAST) op).setOpcode(newopc)` --
//! the inherited `PcodeOp.setOpcode(int)` mutator. [`PcodeOpAST`] now exposes a real
//! `set_opcode(&self, OpCode)` (its `opcode` field became a `Cell<OpCode>` for exactly this),
//! added once `PcodeOp.java`'s own port grew real `set_opcode`/`set_input`/`set_output` mutators
//! and this bank's `change_opcode` became the concrete, well-tested follow-on that unblocked. See
//! [`change_opcode`](PcodeOpBank::change_opcode) below.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::pcode::list_linked::ListLinked;
use crate::program::model::pcode::pcode_op_ast::PcodeOpAST;
use crate::program::model::pcode::{OpCode, SequenceNumber};

/// Container for [`PcodeOpAST`]s. Port of `ghidra.program.model.pcode.PcodeOpBank`. See the
/// module docs for the typing/scope deviations from the Java source.
pub struct PcodeOpBank {
    /// All ops sorted by `SequenceNumber`. Port of the private `opTree` field.
    op_tree: RefCell<BTreeMap<SequenceNumber, Arc<PcodeOpAST>>>,
    /// List of dead ops. Port of the private `deadList` field.
    dead_list: ListLinked<Arc<PcodeOpAST>>,
    /// List of living ops. Port of the private `aliveList` field.
    alive_list: ListLinked<Arc<PcodeOpAST>>,
    /// Next unique index for a created op. Port of the private `nextUnique` field.
    next_unique: Cell<i32>,
}

impl PcodeOpBank {
    /// Port of `PcodeOpBank()`.
    pub fn new() -> Self {
        Self {
            op_tree: RefCell::new(BTreeMap::new()),
            dead_list: ListLinked::new(),
            alive_list: ListLinked::new(),
            next_unique: Cell::new(0),
        }
    }

    /// Port of `PcodeOpBank.size()`.
    pub fn size(&self) -> usize {
        self.op_tree.borrow().len()
    }

    /// Port of `PcodeOpBank.clear()`. Note this does *not* reset `next_unique`, matching Java
    /// (`clear()` never touches `nextUnique`).
    pub fn clear(&self) {
        self.op_tree.borrow_mut().clear();
        self.dead_list.clear();
        self.alive_list.clear();
    }

    /// Create a new op at instruction address `pc`, assigning it the bank's next unique index.
    ///
    /// Port of `PcodeOpBank.create(int opcode, int numinputs, Address pc)`.
    pub fn create(&self, opcode: OpCode, numinputs: usize, pc: Address) -> Arc<PcodeOpAST> {
        let uniq = self.next_unique.get();
        let op = Arc::new(PcodeOpAST::with_address(pc, uniq, opcode, numinputs));
        // Java's `nextUnique += 1` is plain `int` arithmetic, which wraps silently on overflow;
        // `wrapping_add` reproduces that rather than panicking.
        self.next_unique.set(uniq.wrapping_add(1));

        self.op_tree.borrow_mut().insert(op.get_seqnum().clone(), op.clone());
        op.set_insert_iter(Some(self.dead_list.add(op.clone())));
        op
    }

    /// Create a new op at an already-known sequence number, bumping the bank's next unique index
    /// if necessary so future [`create`](Self::create) calls don't collide with it.
    ///
    /// Port of `PcodeOpBank.create(int opcode, int numinputs, SequenceNumber sq)`.
    pub fn create_at_seqnum(&self, opcode: OpCode, numinputs: usize, sq: SequenceNumber) -> Arc<PcodeOpAST> {
        let op = Arc::new(PcodeOpAST::new(sq.clone(), opcode, numinputs));

        if sq.get_time() > self.next_unique.get() {
            self.next_unique.set(sq.get_time().wrapping_add(1));
        }

        self.op_tree.borrow_mut().insert(op.get_seqnum().clone(), op.clone());
        op.set_insert_iter(Some(self.dead_list.add(op.clone())));
        op
    }

    /// Port of `PcodeOpBank.destroy(PcodeOp op)`. See the module docs for why the `isDead()` guard
    /// never actually prevents destruction (it always returns `true`).
    pub fn destroy(&self, op: &Arc<PcodeOpAST>) {
        if !op.is_dead() {
            return;
        }
        self.op_tree.borrow_mut().remove(op.get_seqnum());
        if let Some(iter) = op.get_insert_iter() {
            self.dead_list.remove(&iter);
        }
    }

    /// Change the opcode of `op`. Port of `PcodeOpBank.changeOpcode(PcodeOp, int)`.
    pub fn change_opcode(&self, op: &Arc<PcodeOpAST>, newopc: OpCode) {
        op.set_opcode(newopc);
    }

    /// Move `op` from the dead list to the alive list.
    ///
    /// Port of `PcodeOpBank.markAlive(PcodeOp op)`.
    pub fn mark_alive(&self, op: &Arc<PcodeOpAST>) {
        if let Some(iter) = op.get_insert_iter() {
            self.dead_list.remove(&iter);
        }
        op.set_insert_iter(Some(self.alive_list.add(op.clone())));
    }

    /// Move `op` from the alive list to the dead list.
    ///
    /// Port of `PcodeOpBank.markDead(PcodeOp op)`.
    pub fn mark_dead(&self, op: &Arc<PcodeOpAST>) {
        if let Some(iter) = op.get_insert_iter() {
            self.alive_list.remove(&iter);
        }
        op.set_insert_iter(Some(self.dead_list.add(op.clone())));
    }

    /// Port of `PcodeOpBank.isEmpty()`.
    pub fn is_empty(&self) -> bool {
        self.op_tree.borrow().is_empty()
    }

    /// Find the op with the given sequence number, if any.
    ///
    /// Port of `PcodeOpBank.findOp(SequenceNumber num)`.
    pub fn find_op(&self, num: &SequenceNumber) -> Option<Arc<PcodeOpAST>> {
        self.op_tree.borrow().get(num).cloned()
    }

    /// Return all ops in `SequenceNumber` order. See the module docs for why this is an owned
    /// snapshot rather than a live iterator.
    ///
    /// Port of `PcodeOpBank.allOrdered()`.
    pub fn all_ordered(&self) -> Vec<Arc<PcodeOpAST>> {
        self.op_tree.borrow().values().cloned().collect()
    }

    /// Return all ops associated with the given instruction address, in `SequenceNumber` order.
    /// See the module docs for why this is an owned snapshot rather than a live iterator.
    ///
    /// Port of `PcodeOpBank.allOrdered(Address pc)`. Mirrors Java's `subMap(min, max)`: ops with
    /// `uniq == i32::MAX` at `pc` are excluded, since Java's `TreeMap.subMap` upper bound is
    /// exclusive.
    pub fn all_ordered_at(&self, pc: &Address) -> Vec<Arc<PcodeOpAST>> {
        let min = SequenceNumber::new(pc.clone(), 0);
        let max = SequenceNumber::new(pc.clone(), i32::MAX);
        self.op_tree.borrow().range(min..max).map(|(_, v)| v.clone()).collect()
    }

    /// Return all ops currently on the alive list, in list order. See the module docs for why
    /// this is an owned snapshot rather than a live iterator.
    ///
    /// Port of `PcodeOpBank.allAlive()`.
    pub fn all_alive(&self) -> Vec<Arc<PcodeOpAST>> {
        collect_list(&self.alive_list)
    }

    /// Return all ops currently on the dead list, in list order. See the module docs for why this
    /// is an owned snapshot rather than a live iterator.
    ///
    /// Port of `PcodeOpBank.allDead()`.
    pub fn all_dead(&self) -> Vec<Arc<PcodeOpAST>> {
        collect_list(&self.dead_list)
    }
}

impl Default for PcodeOpBank {
    fn default() -> Self {
        Self::new()
    }
}

fn collect_list(list: &ListLinked<Arc<PcodeOpAST>>) -> Vec<Arc<PcodeOpAST>> {
    let mut out = Vec::new();
    let mut cursor = list.iterator();
    while list.has_next(&cursor) {
        let v = list.next_val(&mut cursor).expect("has_next just confirmed a next element exists");
        out.push(Arc::clone(&v));
        drop(v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn new_bank_is_empty() {
        let bank = PcodeOpBank::new();
        assert!(bank.is_empty());
        assert_eq!(bank.size(), 0);
        assert!(bank.all_ordered().is_empty());
        assert!(bank.all_alive().is_empty());
        assert!(bank.all_dead().is_empty());
    }

    #[test]
    fn create_registers_op_in_tree_and_dead_list() {
        let bank = PcodeOpBank::new();
        let ram = ram_space();
        let pc = Address::new(ram, 0x1000);

        let op = bank.create(OpCode::Copy, 1, pc.clone());

        assert!(!bank.is_empty());
        assert_eq!(bank.size(), 1);
        assert_eq!(op.get_seqnum().pc, pc);
        assert_eq!(op.get_seqnum().uniq, 0);
        assert_eq!(bank.all_dead().len(), 1);
        assert!(bank.all_alive().is_empty());
        assert_eq!(bank.find_op(op.get_seqnum()).map(|o| Arc::ptr_eq(&o, &op)), Some(true));
    }

    #[test]
    fn create_assigns_increasing_uniques() {
        let bank = PcodeOpBank::new();
        let pc = Address::new(ram_space(), 0x2000);

        let op0 = bank.create(OpCode::Copy, 1, pc.clone());
        let op1 = bank.create(OpCode::Copy, 1, pc.clone());
        let op2 = bank.create(OpCode::Copy, 1, pc);

        assert_eq!(op0.get_seqnum().uniq, 0);
        assert_eq!(op1.get_seqnum().uniq, 1);
        assert_eq!(op2.get_seqnum().uniq, 2);
    }

    #[test]
    fn create_at_seqnum_bumps_next_unique_past_the_given_time() {
        let bank = PcodeOpBank::new();
        let pc = Address::new(ram_space(), 0x3000);

        // Seed the bank with an op at uniq=10 via the SequenceNumber-based constructor.
        let seeded = bank.create_at_seqnum(OpCode::Copy, 0, SequenceNumber::new(pc.clone(), 10));
        assert_eq!(seeded.get_seqnum().uniq, 10);

        // A subsequent `create` must not collide with uniq=10: nextUnique was bumped to 11.
        let next = bank.create(OpCode::Copy, 0, pc);
        assert_eq!(next.get_seqnum().uniq, 11);
    }

    #[test]
    fn create_at_seqnum_does_not_lower_next_unique_for_a_smaller_time() {
        let bank = PcodeOpBank::new();
        let pc = Address::new(ram_space(), 0x4000);

        // First, push nextUnique up to 5.
        for _ in 0..5 {
            bank.create(OpCode::Copy, 0, pc.clone());
        }
        // A seqnum-based create with a *smaller* time than nextUnique must not roll it back.
        bank.create_at_seqnum(OpCode::Copy, 0, SequenceNumber::new(pc.clone(), 1));

        let next = bank.create(OpCode::Copy, 0, pc);
        assert_eq!(next.get_seqnum().uniq, 5, "nextUnique must not have been lowered");
    }

    #[test]
    fn change_opcode_mutates_the_op_in_place() {
        let bank = PcodeOpBank::new();
        let pc = Address::new(ram_space(), 0x4500);
        let op = bank.create(OpCode::Copy, 2, pc);

        assert_eq!(op.get_opcode(), OpCode::Copy);
        bank.change_opcode(&op, OpCode::IntAdd);
        assert_eq!(op.get_opcode(), OpCode::IntAdd);

        // The op's identity/position in the bank (tree + dead list) is untouched -- Java's
        // changeOpcode only ever sets the field, nothing bank-side.
        assert_eq!(bank.size(), 1);
        assert_eq!(bank.all_dead().len(), 1);
        assert!(Arc::ptr_eq(&bank.find_op(op.get_seqnum()).unwrap(), &op));
    }

    #[test]
    fn mark_alive_then_mark_dead_moves_between_lists() {
        let bank = PcodeOpBank::new();
        let pc = Address::new(ram_space(), 0x5000);
        let op = bank.create(OpCode::Copy, 0, pc);

        assert_eq!(bank.all_dead().len(), 1);
        assert!(bank.all_alive().is_empty());

        bank.mark_alive(&op);
        assert!(bank.all_dead().is_empty());
        assert_eq!(bank.all_alive().len(), 1);
        assert!(Arc::ptr_eq(&bank.all_alive()[0], &op));

        bank.mark_dead(&op);
        assert_eq!(bank.all_dead().len(), 1);
        assert!(bank.all_alive().is_empty());
    }

    #[test]
    fn destroy_removes_op_from_tree_and_dead_list() {
        let bank = PcodeOpBank::new();
        let pc = Address::new(ram_space(), 0x6000);
        let op = bank.create(OpCode::Copy, 0, pc);

        bank.destroy(&op);

        assert!(bank.is_empty());
        assert!(bank.all_dead().is_empty());
        assert!(bank.find_op(op.get_seqnum()).is_none());
    }

    /// Documents the real Java quirk described in the module docs: `PcodeOpAST.isDead()` always
    /// returns `true` (its backing field is set once in the constructor and never has a setter),
    /// so `destroy`'s `if (!isDead()) return;` guard can never actually refuse to destroy an op --
    /// not even one that was just `markAlive`'d and is sitting in the "alive" list.
    #[test]
    fn destroy_removes_op_even_though_marked_alive() {
        let bank = PcodeOpBank::new();
        let pc = Address::new(ram_space(), 0x7000);
        let op = bank.create(OpCode::Copy, 0, pc);
        bank.mark_alive(&op);

        // The op is logically "alive" by list membership, yet `is_dead()` still reports true.
        assert!(op.is_dead(), "PcodeOpAST.isDead() never changes after construction");

        bank.destroy(&op);

        assert!(bank.is_empty(), "destroy proceeds regardless of alive/dead list membership");
        assert!(bank.find_op(op.get_seqnum()).is_none());
    }

    #[test]
    fn all_ordered_returns_ops_sorted_by_sequence_number() {
        let bank = PcodeOpBank::new();
        let ram = ram_space();
        let low = Address::new(ram.clone(), 0x1000);
        let high = Address::new(ram, 0x2000);

        let op_high = bank.create(OpCode::Copy, 0, high.clone());
        let op_low = bank.create(OpCode::Copy, 0, low.clone());

        let ordered = bank.all_ordered();
        assert_eq!(ordered.len(), 2);
        assert!(Arc::ptr_eq(&ordered[0], &op_low), "lower address must sort first");
        assert!(Arc::ptr_eq(&ordered[1], &op_high));
    }

    #[test]
    fn all_ordered_at_filters_to_a_single_instruction_address() {
        let bank = PcodeOpBank::new();
        let ram = ram_space();
        let addr_a = Address::new(ram.clone(), 0x1000);
        let addr_b = Address::new(ram, 0x2000);

        let a0 = bank.create(OpCode::Copy, 0, addr_a.clone());
        let a1 = bank.create(OpCode::Copy, 0, addr_a.clone());
        let _b0 = bank.create(OpCode::Copy, 0, addr_b);

        let at_a = bank.all_ordered_at(&addr_a);
        assert_eq!(at_a.len(), 2);
        assert!(Arc::ptr_eq(&at_a[0], &a0));
        assert!(Arc::ptr_eq(&at_a[1], &a1));
    }

    #[test]
    fn clear_empties_tree_and_both_lists_but_keeps_next_unique() {
        let bank = PcodeOpBank::new();
        let pc = Address::new(ram_space(), 0x8000);
        bank.create(OpCode::Copy, 0, pc.clone());
        bank.create(OpCode::Copy, 0, pc.clone());

        bank.clear();

        assert!(bank.is_empty());
        assert!(bank.all_dead().is_empty());
        assert!(bank.all_alive().is_empty());

        // nextUnique is untouched by clear() in Java -- the next op continues from uniq=2, not 0.
        let op = bank.create(OpCode::Copy, 0, pc);
        assert_eq!(op.get_seqnum().uniq, 2);
    }
}
