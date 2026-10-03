//! Port of `ghidra.program.model.pcode.VarnodeAST`.
//!
//! This type of Varnode is a node in an Abstract Syntax Tree. It keeps track of its defining
//! `PcodeOp` (in-edge, [`def`](VarnodeAST::get_def)) and the `PcodeOp`s which use it (out-edges,
//! [`descend`](VarnodeAST::get_descendants)). It is the concrete runtime subtype
//! `PcodeSyntaxTree` (not yet ported) actually creates and hands out -- the direct analog, for
//! varnodes, of [`PcodeOpAST`](crate::program::model::pcode::pcode_op_ast::PcodeOpAST) for
//! p-code ops.
//!
//! ## Composition, not duplication: a `base: Varnode` field
//!
//! Java's `VarnodeAST extends Varnode`, overriding roughly a dozen accessors (`isFree`,
//! `isInput`, `isPersistent`, `isAddrTied`, `isUnaffected`, `getDef`, `getDescendants`,
//! `getLoneDescend`, `hasNoDescend`, `getPCAddress`, `getHigh`, `getMergeGroup`) while inheriting
//! everything else (`getAddress`, `getSize`, `getOffset`, `getSpace`, `isConstant`, `encodeRaw`,
//! ...) unchanged from the base class. Since [`Varnode`] in this crate is already a real,
//! complete port (see `mod.rs`'s history -- it was itself completed earlier this session), this
//! struct **composes** a `base: Varnode` field for the address/size state and every
//! inherited-unchanged method, rather than duplicating that logic (contrast with
//! [`PcodeOpAST`](crate::program::model::pcode::pcode_op_ast::PcodeOpAST), which duplicates
//! `PcodeOp`'s seqnum/opcode/inputs/output fields because `PcodeOp`'s own struct shape --
//! fully-populated `Vec<Varnode>`, no incremental "null slot" building -- could not represent
//! `PcodeOpAST`'s needs at all). Here, delegation is both possible and strictly better: it reuses
//! `Varnode`'s already-tested `is_constant`/`is_unique`/`is_register`/`is_address`/`is_hash`/
//! `encode_raw`/`contains`/`intersects`/`to_string_with_language` for free, with zero risk of the
//! two copies drifting apart.
//!
//! ## Typing deviation: `def`/`descend` hold `Arc<PcodeOpAST>`, not `PcodeOp`
//!
//! Java declares `private PcodeOp def` and `private LinkedList<PcodeOp> descend`, but every
//! real value ever stored there (via `setDef`/`addDescendant`, called only from
//! `PcodeSyntaxTree`/`VarnodeBank`) is actually a `PcodeOpAST` -- the base `PcodeOp` alone cannot
//! even represent the incremental `setInput`/`setOutput` mutation `descendReplace` performs.
//! Matching [`PcodeOpBank`](crate::program::model::pcode::pcode_op_bank::PcodeOpBank)'s
//! established "concrete `Arc<...>` instead of the Java base type + runtime downcast" deviation,
//! this port types `def`/`descend` as `Arc<PcodeOpAST>` directly.
//!
//! ## Ripple: `PcodeOpAST.inputs`/`output` grew from `Varnode` to `Arc<VarnodeAST>`
//!
//! [`VarnodeAST::descend_replace`] (the port of `descendReplace`) needs `op.getOutput() == this`
//! (Java reference-identity comparison) and needs to overwrite `op`'s input slots with real
//! `VarnodeAST` identities via `op.setInput(...)`. That was only possible once
//! `pcode_op_ast.rs`'s `inputs`/`output` fields were changed from the crate's plain `Varnode`
//! value type to `Option<Arc<VarnodeAST>>` (and gained real `set_input`/`set_output` mutators,
//! matching the inherited `PcodeOp.setInput`/`setOutput`). This is the one change made to
//! `pcode_op_ast.rs` for this port; see that file's module docs for the full rationale (a `grep`
//! confirmed no other code in the crate depended on the old `Varnode`-typed accessors).
//!
//! ## Quirk: this class's `compareTo`-adjacent `equals`/`hashCode` are deliberately unusual
//!
//! The Java doc comment directly above `equals` explains why: "for a given location and size,
//! there can be only one varnode defined by input and only one defined by a PcodeOp with a given
//! SequenceNumber. But there can be multiple Varnodes of the same location and size, which are
//! all free. Thus in the free case, the equals method must compare the uniqId" -- i.e. `equals`
//! only falls back to `uniqId` when *both* varnodes are free; a free and a non-free varnode (or
//! two non-free varnodes with different defining ops) are never equal regardless of `uniqId`.
//! [`hashCode`] is just `uniqId`. Both are ported as real `PartialEq`/`Eq`/`Hash` impls below.
//!
//! ## Quirk: `Ord` (the port of `VarnodeBank.LocComparator`) is a *different* relation than `equals`
//!
//! [`VarnodeBank`](crate::program::model::pcode::varnode_bank::VarnodeBank)'s `locTree` is a
//! `TreeSet<VarnodeAST>` constructed with an explicit `Comparator` (`LocComparator`), which is
//! the classic Java pattern the `TreeSet`/`TreeMap` Javadoc explicitly warns is "inconsistent
//! with equals" if the comparator and `equals` can disagree -- and here they *do* structurally
//! differ (the comparator never even calls `isFree()`/`equals()`; it infers "free" implicitly
//! from `!isInput() && getDef() == null`), even though in every real call path the two invariants
//! stay in lockstep by construction. This port reproduces the same two-relations split: `Ord`/
//! `PartialOrd` below port `LocComparator` (and back
//! [`VarnodeBank`](crate::program::model::pcode::varnode_bank::VarnodeBank)'s `BTreeSet`
//! ordering/dedup), while `PartialEq`/`Eq`/`Hash` port `equals`/`hashCode` and are used
//! explicitly wherever Java calls `.equals(...)` (i.e. inside `VarnodeBank.xref`). Faithfully
//! keeping them separate rather than "fixing" `Ord` to agree with `PartialEq` (which would
//! silently change `VarnodeBank`'s tree-search behavior away from real Ghidra's).

use crate::program::model::address::{special_address::SpecialAddress, Address};
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::pcode_op_ast::PcodeOpAST;
use crate::program::model::pcode::{HighVariable, Varnode};
use std::cell::{Cell, RefCell};
use std::cmp::Ordering;
use std::io;
use std::sync::Arc;

/// A node in the decompiler's abstract syntax tree. Port of
/// `ghidra.program.model.pcode.VarnodeAST`. See the module docs for the composition strategy and
/// the real Java quirks reproduced here (in particular the `Ord` vs. `PartialEq` split).
pub struct VarnodeAST {
    /// Address/size state, and every inherited-unoverridden `Varnode` method. Port of the
    /// implicit superclass state (`Varnode`'s own `address`/`size` fields).
    base: Varnode,
    /// Port of the private `bInput` field.
    b_input: Cell<bool>,
    /// Port of the private `bAddrTied` field.
    b_addr_tied: Cell<bool>,
    /// Port of the private `bPersistent` field.
    b_persistent: Cell<bool>,
    /// Port of the private `bUnaffected` field.
    b_unaffected: Cell<bool>,
    /// Port of the private `bFree` field.
    b_free: Cell<bool>,
    /// Unique id for distinguishing otherwise-identical varnodes. Port of the private `uniqId`
    /// field.
    uniq_id: i32,
    /// Forced merge group within this varnode's high. Port of the private `mergegroup` field.
    mergegroup: Cell<i16>,
    /// High-level variable this varnode is an instance of. Port of the private `high` field.
    high: RefCell<Option<Arc<dyn HighVariable>>>,
    /// Operation which defines this varnode (in-edge). Port of the private `def` field. See the
    /// module docs for the `Arc<PcodeOpAST>` typing.
    def: RefCell<Option<Arc<PcodeOpAST>>>,
    /// Operations which use this varnode (out-edges). Port of the private `descend`
    /// (`LinkedList<PcodeOp>`) field. See the module docs for the `Arc<PcodeOpAST>` typing;
    /// `Vec` stands in for Java's `LinkedList` since every real usage here only ever appends,
    /// removes-by-identity, or iterates from the front.
    descend: RefCell<Vec<Arc<PcodeOpAST>>>,
}

impl VarnodeAST {
    /// Port of `VarnodeAST(Address a, int sz, int id)`.
    pub fn new(a: Address, sz: i32, id: i32) -> Self {
        Self {
            base: Varnode::new(a, sz),
            b_input: Cell::new(false),
            b_addr_tied: Cell::new(false),
            b_persistent: Cell::new(false),
            b_unaffected: Cell::new(false),
            b_free: Cell::new(true),
            uniq_id: id,
            mergegroup: Cell::new(0),
            high: RefCell::new(None),
            def: RefCell::new(None),
            descend: RefCell::new(Vec::new()),
        }
    }

    // ---- Inherited from `Varnode`, unoverridden by Java's `VarnodeAST`: delegate to `base`. ----

    /// Port of the inherited `Varnode.getAddress()`.
    pub fn get_address(&self) -> &Address {
        self.base.get_address()
    }

    /// Port of the inherited `Varnode.getSize()`.
    pub fn get_size(&self) -> i32 {
        self.base.get_size()
    }

    /// Port of the inherited `Varnode.getOffset()`.
    pub fn get_offset(&self) -> i64 {
        self.base.get_offset()
    }

    /// Port of the inherited `Varnode.getSpace()` (returns the space id, matching real Java's
    /// `int getSpace()`).
    pub fn get_space_id(&self) -> i32 {
        self.base.get_space_id()
    }

    /// Port of the inherited `Varnode.isConstant()`.
    pub fn is_constant(&self) -> bool {
        self.base.is_constant()
    }

    /// Port of the inherited `Varnode.isUnique()`.
    pub fn is_unique(&self) -> bool {
        self.base.is_unique()
    }

    /// Port of the inherited `Varnode.isRegister()`.
    pub fn is_register(&self) -> bool {
        self.base.is_register()
    }

    /// Port of the inherited `Varnode.isAddress()`.
    pub fn is_address(&self) -> bool {
        self.base.is_address()
    }

    /// Port of the inherited `Varnode.isHash()`.
    pub fn is_hash(&self) -> bool {
        self.base.is_hash()
    }

    /// Port of the inherited `Varnode.encodeRaw(Encoder)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    pub fn encode_raw(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        self.base.encode_raw(encoder)
    }

    /// Borrow the underlying "free" [`Varnode`] value (address + size only), for callers that
    /// need to interoperate with APIs still typed in terms of the base [`Varnode`].
    pub fn as_varnode(&self) -> &Varnode {
        &self.base
    }

    // ---- Overridden by Java's `VarnodeAST`. ----

    /// Port of `VarnodeAST.isFree()`.
    pub fn is_free(&self) -> bool {
        self.b_free.get()
    }

    /// Port of `VarnodeAST.isInput()`.
    pub fn is_input(&self) -> bool {
        self.b_input.get()
    }

    /// Port of `VarnodeAST.isPersistent()`.
    pub fn is_persistent(&self) -> bool {
        self.b_persistent.get()
    }

    /// Port of `VarnodeAST.isAddrTied()`.
    pub fn is_addr_tied(&self) -> bool {
        self.b_addr_tied.get()
    }

    /// Port of `VarnodeAST.isUnaffected()`.
    pub fn is_unaffected(&self) -> bool {
        self.b_unaffected.get()
    }

    /// Port of `VarnodeAST.getDef()`.
    pub fn get_def(&self) -> Option<Arc<PcodeOpAST>> {
        self.def.borrow().clone()
    }

    /// Port of `VarnodeAST.getDescendants()`. Java returns a live `Iterator<PcodeOp>`; this
    /// returns an owned snapshot (matching the deviation already established by
    /// [`PcodeOpBank`](crate::program::model::pcode::pcode_op_bank::PcodeOpBank)'s
    /// `all_ordered`/`all_alive`/`all_dead` -- see that module's docs for why a live, aliasing
    /// iterator isn't a good fit for this crate's `RefCell`-based interior mutability).
    pub fn get_descendants(&self) -> std::vec::IntoIter<Arc<PcodeOpAST>> {
        self.descend.borrow().clone().into_iter()
    }

    /// Port of `VarnodeAST.getLoneDescend()`.
    pub fn get_lone_descend(&self) -> Option<Arc<PcodeOpAST>> {
        let descend = self.descend.borrow();
        if descend.len() != 1 {
            return None;
        }
        descend.first().cloned()
    }

    /// Port of `VarnodeAST.hasNoDescend()`.
    pub fn has_no_descend(&self) -> bool {
        self.descend.borrow().is_empty()
    }

    /// Port of `VarnodeAST.getPCAddress()`.
    pub fn get_pc_address(&self) -> Address {
        if self.b_input.get() {
            return SpecialAddress::no_address();
        }
        if let Some(def) = self.def.borrow().as_ref() {
            return def.get_seqnum().get_target().clone();
        }
        let descend = self.descend.borrow();
        if descend.len() == 1 {
            return descend[0].get_seqnum().get_target().clone();
        }
        SpecialAddress::no_address()
    }

    /// Port of `VarnodeAST.getHigh()`.
    pub fn get_high(&self) -> Option<Arc<dyn HighVariable>> {
        self.high.borrow().clone()
    }

    /// Port of `VarnodeAST.getUniqueId()`.
    pub fn get_unique_id(&self) -> i32 {
        self.uniq_id
    }

    /// Port of `VarnodeAST.getMergeGroup()`.
    pub fn get_merge_group(&self) -> i16 {
        self.mergegroup.get()
    }

    // ---- Mutators. ----

    /// Port of `VarnodeAST.setAddrtied(boolean)`.
    pub fn set_addrtied(&self, val: bool) {
        self.b_addr_tied.set(val);
    }

    /// Port of `VarnodeAST.setInput(boolean)`.
    pub fn set_input(&self, val: bool) {
        self.b_input.set(val);
        self.b_free.set(false);
        *self.def.borrow_mut() = None;
    }

    /// Port of `VarnodeAST.setPersistent(boolean)`.
    pub fn set_persistent(&self, val: bool) {
        self.b_persistent.set(val);
    }

    /// Port of `VarnodeAST.setUnaffected(boolean)`.
    pub fn set_unaffected(&self, val: bool) {
        self.b_unaffected.set(val);
    }

    /// Port of `VarnodeAST.setFree(boolean)`.
    pub fn set_free(&self, val: bool) {
        self.b_free.set(val);
    }

    /// Port of `VarnodeAST.setDef(PcodeOp)`. Only clears `bFree`/`bInput` when `op` is `Some`,
    /// matching Java's `if (op != null) { bFree = false; bInput = false; }` guard.
    pub fn set_def(&self, op: Option<Arc<PcodeOpAST>>) {
        let is_some = op.is_some();
        *self.def.borrow_mut() = op;
        if is_some {
            self.b_free.set(false);
            self.b_input.set(false);
        }
    }

    /// Port of `VarnodeAST.setMergeGroup(short)`.
    pub fn set_merge_group(&self, val: i16) {
        self.mergegroup.set(val);
    }

    /// Port of `VarnodeAST.setHigh(HighVariable)`.
    pub fn set_high(&self, hi: Option<Arc<dyn HighVariable>>) {
        *self.high.borrow_mut() = hi;
    }

    /// Port of `VarnodeAST.addDescendant(PcodeOp)`.
    pub fn add_descendant(&self, op: Arc<PcodeOpAST>) {
        self.descend.borrow_mut().push(op);
    }

    /// Port of `VarnodeAST.removeDescendant(PcodeOp)`. Removes every element identical to `op`
    /// (by `Arc` pointer identity, matching Java's `==` inside a loop with no `break`) rather
    /// than only the first match.
    pub fn remove_descendant(&self, op: &Arc<PcodeOpAST>) {
        self.descend.borrow_mut().retain(|o| !Arc::ptr_eq(o, op));
    }

    /// Replace all of `vn`'s references with `this`. Port of `VarnodeAST.descendReplace(VarnodeAST)`.
    ///
    /// Takes an explicit `this: &Arc<VarnodeAST>` (rather than a `&self` receiver) since the body
    /// needs `this`'s own `Arc` identity -- to compare against `op.getOutput()` by reference and
    /// to hand a clone to `op.setInput(this, i)` -- which a plain `&self` receiver cannot provide
    /// in safe Rust. Called as `VarnodeAST::descend_replace(&oldvn, &vn)`, mirroring Java's
    /// `oldvn.descendReplace(vn)`.
    pub fn descend_replace(this: &Arc<VarnodeAST>, vn: &Arc<VarnodeAST>) {
        // Java iterates `vn.descend` directly via a `ListIterator`, removing entries in place as
        // it goes (safe under Java's iterator-aware `remove()`). Snapshotting first avoids a
        // `RefCell` double-borrow when `remove_descendant` below re-borrows `vn.descend` mutably.
        let snapshot: Vec<Arc<PcodeOpAST>> = vn.descend.borrow().clone();
        for op in snapshot {
            if let Some(out) = op.get_output() {
                if Arc::ptr_eq(&out, this) {
                    continue; // Cannot be input to your own definition.
                }
            }
            let num = op.num_inputs();
            for i in 0..num {
                // Find reference to vn.
                if let Some(input_i) = op.get_input(i) {
                    if Arc::ptr_eq(&input_i, vn) {
                        vn.remove_descendant(&op);
                        op.set_input(None, i);
                        this.add_descendant(op.clone());
                        op.set_input(Some(this.clone()), i);
                        break;
                    }
                }
            }
        }
    }
}

impl std::fmt::Debug for VarnodeAST {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VarnodeAST")
            .field("base", &self.base)
            .field("uniq_id", &self.uniq_id)
            .field("is_free", &self.is_free())
            .field("is_input", &self.is_input())
            .finish()
    }
}

/// Port of `VarnodeBank.LocComparator.compare(VarnodeAST, VarnodeAST)`: compare by location,
/// size, then definition. This is `VarnodeAST`'s own [`Ord`] below, and also backs
/// [`LocComparator`](crate::program::model::pcode::varnode_bank::LocComparator) -- see the module
/// docs for why this is deliberately a *different* relation than [`PartialEq`]/equals.
pub(crate) fn loc_compare(v1: &VarnodeAST, v2: &VarnodeAST) -> Ordering {
    let cmp = v1.get_address().cmp(v2.get_address());
    if cmp != Ordering::Equal {
        return cmp;
    }
    if v1.get_size() != v2.get_size() {
        return if v1.get_size() < v2.get_size() { Ordering::Less } else { Ordering::Greater };
    }
    if v1.is_input() {
        return if v2.is_input() { Ordering::Equal } else { Ordering::Less };
    }
    if v2.is_input() {
        return Ordering::Greater;
    }
    if let Some(d1) = v1.get_def() {
        return match v2.get_def() {
            None => Ordering::Less,
            Some(d2) => d1.get_seqnum().cmp(d2.get_seqnum()),
        };
    }
    if v2.get_def().is_some() {
        return Ordering::Greater;
    }
    // Reaching this point guarantees both Varnodes are free.
    if v1.uniq_id == v2.uniq_id {
        Ordering::Equal
    } else if v1.uniq_id < v2.uniq_id {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// Port of `VarnodeBank.DefComparator.compare(VarnodeAST, VarnodeAST)`: compare by definition,
/// then location and size. Dead code in real Ghidra too: `VarnodeBank`'s `defTree` field (the
/// only thing that would ever use this comparator) is entirely commented out in
/// `VarnodeBank.java` (`// private TreeSet defTree;` and every line that would populate it). Kept
/// here, unused, purely for completeness of the port -- see
/// [`DefComparator`](crate::program::model::pcode::varnode_bank::DefComparator).
pub(crate) fn def_compare(v1: &VarnodeAST, v2: &VarnodeAST) -> Ordering {
    if v1.is_input() {
        if !v2.is_input() {
            return Ordering::Less;
        }
    } else if let Some(d1) = v1.get_def() {
        if v2.is_input() {
            return Ordering::Greater;
        }
        if v2.is_free() {
            return Ordering::Less;
        }
        if let Some(d2) = v2.get_def() {
            let comp = d1.get_seqnum().cmp(d2.get_seqnum());
            if comp != Ordering::Equal {
                return comp;
            }
        }
    }
    let comp = v1.get_address().cmp(v2.get_address());
    if comp != Ordering::Equal {
        return comp;
    }
    if v1.get_size() != v2.get_size() {
        return if v1.get_size() < v2.get_size() { Ordering::Less } else { Ordering::Greater };
    }
    if v1.is_free() {
        // Both Varnodes must be free, compare uniqId.
        if v1.uniq_id == v2.uniq_id {
            return Ordering::Equal;
        }
        return if v1.uniq_id < v2.uniq_id { Ordering::Less } else { Ordering::Greater };
    }
    Ordering::Equal
}

impl Ord for VarnodeAST {
    fn cmp(&self, other: &Self) -> Ordering {
        loc_compare(self, other)
    }
}

impl PartialOrd for VarnodeAST {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for VarnodeAST {
    /// Port of `VarnodeAST.equals(Object)`. See the module docs for why this deliberately differs
    /// from [`Ord`]/`LocComparator`.
    fn eq(&self, other: &Self) -> bool {
        if std::ptr::eq(self, other) {
            return true;
        }
        if self.get_offset() != other.get_offset()
            || self.get_size() != other.get_size()
            || self.get_space_id() != other.get_space_id()
        {
            return false;
        }
        if self.is_free() {
            if other.is_free() {
                return self.uniq_id == other.uniq_id;
            }
            return false;
        } else if other.is_free() {
            return false;
        }
        if self.is_input() != other.is_input() {
            return false;
        }
        if let Some(def) = self.def.borrow().as_ref() {
            return match other.def.borrow().as_ref() {
                Some(other_def) => def.get_seqnum() == other_def.get_seqnum(),
                None => false,
            };
        }
        true
    }
}

impl Eq for VarnodeAST {}

impl std::hash::Hash for VarnodeAST {
    /// Port of `VarnodeAST.hashCode()`.
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.uniq_id.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::OpCode;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    fn op_ast(pc: Address, uq: i32) -> Arc<PcodeOpAST> {
        Arc::new(PcodeOpAST::with_address(pc, uq, OpCode::Copy, 2))
    }

    #[test]
    fn new_starts_free_with_no_def_and_no_descendants() {
        let vn = VarnodeAST::new(addr(0x100), 4, 7);

        assert!(vn.is_free());
        assert!(!vn.is_input());
        assert!(!vn.is_persistent());
        assert!(!vn.is_addr_tied());
        assert!(!vn.is_unaffected());
        assert!(vn.get_def().is_none());
        assert!(vn.has_no_descend());
        assert!(vn.get_lone_descend().is_none());
        assert_eq!(vn.get_descendants().count(), 0);
        assert_eq!(vn.get_unique_id(), 7);
        assert_eq!(vn.get_merge_group(), 0);
        assert!(vn.get_high().is_none());
        assert_eq!(vn.get_address(), &addr(0x100));
        assert_eq!(vn.get_size(), 4);
    }

    #[test]
    fn set_input_clears_free_and_def() {
        let vn = VarnodeAST::new(addr(0x200), 4, 0);
        let op = op_ast(addr(0x1000), 0);
        vn.set_def(Some(op));
        assert!(!vn.is_free());
        assert!(vn.get_def().is_some());

        vn.set_input(true);
        assert!(vn.is_input());
        assert!(!vn.is_free(), "setInput(true) clears bFree too, per Java");
        assert!(vn.get_def().is_none(), "setInput(true) clears def too, per Java");
    }

    #[test]
    fn set_def_only_clears_free_and_input_when_some() {
        let vn = VarnodeAST::new(addr(0x300), 4, 0);

        // Setting a null def (matching Java's `setDef(null)` inside `makeFree`) must NOT force
        // bFree/bInput false -- only a non-null def does that.
        vn.set_def(None);
        assert!(vn.is_free(), "setDef(None) must not clear bFree");

        let op = op_ast(addr(0x1000), 0);
        vn.set_def(Some(op.clone()));
        assert!(!vn.is_free());
        assert!(!vn.is_input());
        assert!(Arc::ptr_eq(&vn.get_def().unwrap(), &op));
    }

    #[test]
    fn get_pc_address_prefers_input_then_def_then_lone_descendant() {
        let vn = VarnodeAST::new(addr(0x400), 4, 0);
        // Free, no def, no descendants: NO_ADDRESS.
        assert_eq!(vn.get_pc_address(), SpecialAddress::no_address());

        // One descendant, no def: that descendant's target address.
        let op1 = op_ast(addr(0x1000), 0);
        vn.add_descendant(op1.clone());
        assert_eq!(vn.get_pc_address(), *op1.get_seqnum().get_target());

        // A def takes priority over a lone descendant.
        let def_op = op_ast(addr(0x2000), 0);
        vn.set_def(Some(def_op.clone()));
        assert_eq!(vn.get_pc_address(), *def_op.get_seqnum().get_target());

        // isInput() takes priority over everything, including a real def.
        vn.set_input(true); // also clears def, but let's check the isInput short-circuit itself
        assert_eq!(vn.get_pc_address(), SpecialAddress::no_address());
    }

    #[test]
    fn get_pc_address_with_multiple_descendants_and_no_def_is_no_address() {
        let vn = VarnodeAST::new(addr(0x500), 4, 0);
        vn.add_descendant(op_ast(addr(0x1000), 0));
        vn.add_descendant(op_ast(addr(0x1004), 0));
        assert_eq!(vn.get_pc_address(), SpecialAddress::no_address());
    }

    #[test]
    fn get_lone_descend_only_when_exactly_one() {
        let vn = VarnodeAST::new(addr(0x600), 4, 0);
        assert!(vn.get_lone_descend().is_none());

        let op1 = op_ast(addr(0x1000), 0);
        vn.add_descendant(op1.clone());
        assert!(Arc::ptr_eq(&vn.get_lone_descend().unwrap(), &op1));

        vn.add_descendant(op_ast(addr(0x1004), 0));
        assert!(vn.get_lone_descend().is_none());
    }

    #[test]
    fn add_and_remove_descendant_round_trip() {
        let vn = VarnodeAST::new(addr(0x700), 4, 0);
        let op1 = op_ast(addr(0x1000), 0);
        let op2 = op_ast(addr(0x1004), 0);
        vn.add_descendant(op1.clone());
        vn.add_descendant(op2.clone());
        assert_eq!(vn.get_descendants().count(), 2);

        vn.remove_descendant(&op1);
        let remaining: Vec<_> = vn.get_descendants().collect();
        assert_eq!(remaining.len(), 1);
        assert!(Arc::ptr_eq(&remaining[0], &op2));
    }

    /// Two free varnodes at the same location/size are equal only if `uniqId` matches -- the
    /// documented reason `VarnodeAST` overrides `equals` at all.
    #[test]
    fn equals_free_varnodes_compare_by_unique_id() {
        let a = VarnodeAST::new(addr(0x800), 4, 1);
        let b = VarnodeAST::new(addr(0x800), 4, 1);
        let c = VarnodeAST::new(addr(0x800), 4, 2);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// A free varnode is never equal to a non-free varnode at the same location/size.
    #[test]
    fn equals_free_never_equals_non_free() {
        let free = VarnodeAST::new(addr(0x900), 4, 5);
        let input = VarnodeAST::new(addr(0x900), 4, 5);
        input.set_input(true);

        assert_ne!(free, input);
        assert_ne!(input, free);
    }

    /// Two input varnodes at the same location/size are equal (both have `def == null`, both
    /// `isInput() == true`), regardless of `uniqId`.
    #[test]
    fn equals_two_input_varnodes_at_same_location_are_equal() {
        let a = VarnodeAST::new(addr(0xa00), 4, 1);
        a.set_input(true);
        let b = VarnodeAST::new(addr(0xa00), 4, 99);
        b.set_input(true);

        assert_eq!(a, b);
    }

    /// Two defined (non-input, non-free) varnodes at the same location/size are equal only if
    /// their defining ops have the same `SequenceNumber`.
    #[test]
    fn equals_defined_varnodes_compare_by_def_seqnum() {
        let a = VarnodeAST::new(addr(0xb00), 4, 1);
        a.set_def(Some(op_ast(addr(0x1000), 0)));
        let b = VarnodeAST::new(addr(0xb00), 4, 2);
        b.set_def(Some(op_ast(addr(0x1000), 0)));
        let c = VarnodeAST::new(addr(0xb00), 4, 3);
        c.set_def(Some(op_ast(addr(0x2000), 0)));

        assert_eq!(a, b, "same def seqnum => equal, regardless of uniqId");
        assert_ne!(a, c, "different def seqnum => not equal");
    }

    /// `hashCode` is just `uniqId` -- two varnodes with the same `uniqId` hash equal even if
    /// nothing else about them matches (mirroring the Java override exactly).
    #[test]
    fn hash_is_just_unique_id() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let a = VarnodeAST::new(addr(0xc00), 4, 42);
        let b = VarnodeAST::new(addr(0xd00), 8, 42);

        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    /// `Ord` (the `LocComparator` port) orders primarily by address, then size.
    #[test]
    fn ord_sorts_by_address_then_size() {
        let low = VarnodeAST::new(addr(0x100), 4, 0);
        let high = VarnodeAST::new(addr(0x200), 4, 0);
        assert_eq!(low.cmp(&high), Ordering::Less);

        let small = VarnodeAST::new(addr(0x100), 2, 0);
        let big = VarnodeAST::new(addr(0x100), 4, 0);
        assert_eq!(small.cmp(&big), Ordering::Less);
    }

    /// Input varnodes sort before non-input varnodes at the same address/size, and two input
    /// varnodes at the same address/size are `Ordering::Equal` under `LocComparator` -- even
    /// though nothing else about them (e.g. `uniqId`) was compared. This is the concrete
    /// "TreeSet can hold only one input varnode per location" invariant `VarnodeBank` relies on.
    #[test]
    fn ord_input_varnodes_group_together_ahead_of_non_input() {
        let input = VarnodeAST::new(addr(0x300), 4, 1);
        input.set_input(true);
        let defined = VarnodeAST::new(addr(0x300), 4, 2);
        defined.set_def(Some(op_ast(addr(0x1000), 0)));

        assert_eq!(input.cmp(&defined), Ordering::Less);

        let input2 = VarnodeAST::new(addr(0x300), 4, 99);
        input2.set_input(true);
        assert_eq!(input.cmp(&input2), Ordering::Equal, "two inputs at the same loc/size are Ord-equal");
    }

    /// A defined varnode sorts before a free varnode at the same address/size, and two defined
    /// varnodes sort by their def's `SequenceNumber`.
    #[test]
    fn ord_defined_before_free_and_by_seqnum() {
        let free = VarnodeAST::new(addr(0x400), 4, 0);
        let defined = VarnodeAST::new(addr(0x400), 4, 0);
        defined.set_def(Some(op_ast(addr(0x1000), 0)));
        assert_eq!(defined.cmp(&free), Ordering::Less);
        assert_eq!(free.cmp(&defined), Ordering::Greater);

        let earlier = VarnodeAST::new(addr(0x400), 4, 0);
        earlier.set_def(Some(op_ast(addr(0x1000), 0)));
        let later = VarnodeAST::new(addr(0x400), 4, 0);
        later.set_def(Some(op_ast(addr(0x2000), 0)));
        assert_eq!(earlier.cmp(&later), Ordering::Less);
    }

    /// Two free varnodes at the same address/size break ties by `uniqId` under `Ord` -- the same
    /// tie-break `PartialEq` uses, so this one case is consistent between the two relations.
    #[test]
    fn ord_free_varnodes_break_ties_by_unique_id() {
        let a = VarnodeAST::new(addr(0x500), 4, 3);
        let b = VarnodeAST::new(addr(0x500), 4, 7);
        assert_eq!(a.cmp(&b), Ordering::Less);
        assert_eq!(b.cmp(&a), Ordering::Greater);

        let c = VarnodeAST::new(addr(0x500), 4, 3);
        assert_eq!(a.cmp(&c), Ordering::Equal);
    }

    /// `descendReplace`: every op that referenced `vn` as an input now references `this` instead,
    /// and `this` gained those ops as its own descendants.
    #[test]
    fn descend_replace_relinks_consumers_from_old_to_new() {
        let this_vn: Arc<VarnodeAST> = Arc::new(VarnodeAST::new(addr(0x600), 4, 1));
        let vn: Arc<VarnodeAST> = Arc::new(VarnodeAST::new(addr(0x600), 4, 2));

        let consumer = op_ast(addr(0x1000), 0);
        consumer.set_input(Some(vn.clone()), 0);
        vn.add_descendant(consumer.clone());

        VarnodeAST::descend_replace(&this_vn, &vn);

        // The consumer's input slot 0 now points at `this_vn`, not `vn`.
        assert!(Arc::ptr_eq(&consumer.get_input(0).unwrap(), &this_vn));
        // `this_vn` gained the consumer as a descendant; `vn` lost it.
        assert!(vn.has_no_descend());
        let this_descend: Vec<_> = this_vn.get_descendants().collect();
        assert_eq!(this_descend.len(), 1);
        assert!(Arc::ptr_eq(&this_descend[0], &consumer));
    }

    /// `descendReplace` skips an op if `vn` is that op's own *output* (an op can't take its own
    /// result as an input) -- ported from `if (op.getOutput() == this) continue;`. Note the Java
    /// check compares against `this` (the receiver doing the replacing), which in our port is the
    /// first `descend_replace` argument.
    #[test]
    fn descend_replace_skips_op_that_defines_this() {
        let this_vn: Arc<VarnodeAST> = Arc::new(VarnodeAST::new(addr(0x700), 4, 1));
        let vn: Arc<VarnodeAST> = Arc::new(VarnodeAST::new(addr(0x700), 4, 2));

        // `defining_op` has `this_vn` as its output, and also (unrealistically, but exercising
        // the guard) lists `vn` as one of its own descendants.
        let defining_op = op_ast(addr(0x1000), 0);
        defining_op.set_output(Some(this_vn.clone()));
        vn.add_descendant(defining_op.clone());

        VarnodeAST::descend_replace(&this_vn, &vn);

        // Nothing was relinked: the op defining `this_vn` was skipped by the `continue`.
        assert!(!vn.has_no_descend(), "the op was skipped, not removed from vn's descendants");
        assert!(this_vn.has_no_descend(), "this_vn gained no new descendants");
    }
}
