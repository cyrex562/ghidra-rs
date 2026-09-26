//! Port of `ghidra.program.model.pcode.VarnodeBank`.
//!
//! Container class for [`VarnodeAST`]s -- the varnode-flavored counterpart to
//! [`PcodeOpBank`](crate::program::model::pcode::pcode_op_bank::PcodeOpBank), keyed/ordered by
//! location rather than sequence number.
//!
//! ## Collection choice: `BTreeSet<Arc<VarnodeAST>>` keyed by `VarnodeAST`'s own `Ord`
//!
//! Java's `locTree` is a `TreeSet<VarnodeAST>` constructed with an explicit `Comparator`
//! (`LocComparator`). Rust's `BTreeSet<T>` is generic over `T: Ord` rather than accepting an
//! injected comparator object, so this port makes [`VarnodeAST`]'s own [`Ord`] impl *be*
//! `LocComparator`'s logic (see `varnode_ast.rs`'s module docs) and stores `Arc<VarnodeAST>`
//! directly -- `Arc<T>: Ord` delegates to `T::cmp`, so `BTreeSet<Arc<VarnodeAST>>` orders/dedups
//! exactly as `locTree` does. [`LocComparator`]/[`DefComparator`] below are still ported as
//! zero-sized wrapper types purely for structural fidelity with Java's named nested classes; real
//! code should just rely on `Ord`.
//!
//! ## Quirk: `create()` never merges/dedups -- only `setInput`/`setDef` do (via `xref`)
//!
//! Java's `create(int, Address, int)` builds a new `VarnodeAST` and inserts it into `locTree`
//! unconditionally -- it never calls `xref` (the merge-or-insert helper) the way `setInput`/
//! `setDef` do. So `VarnodeBank` can genuinely hold multiple *free* varnodes at the same
//! location/size simultaneously (that's exactly the scenario the `LocComparator`/`equals` doc
//! comments on `VarnodeAST` describe: "there can be multiple Varnodes of the same location and
//! size, which are all free"). Only marking a varnode as an input or giving it a def (both of
//! which route through `xref`) can trigger a merge with an existing equal entry. Faithfully
//! reproduced: [`create`](VarnodeBank::create) never merges either.
//!
//! ## Quirk: `defTree` (and `DefComparator`) are dead code in real Ghidra
//!
//! Every line that would declare/populate/clear a second `TreeSet` sorted by `DefComparator` is
//! commented out in `VarnodeBank.java` (`// private TreeSet defTree;`, `// defTree = new
//! TreeSet(new DefComparator());`, etc.) -- only `locTree` is ever live. This port has no
//! `def_tree` field at all (there would be nothing meaningful to test), but still ports
//! [`DefComparator`]'s comparison logic in `varnode_ast::def_compare` for completeness, matching
//! this crate's established practice of preserving even genuinely-dead real Java code paths
//! rather than silently dropping them.
//!
//! ## Quirk: `locRange(Address, Address)`'s upper search bound is *not* marked as an input
//!
//! `locRange(Address min, Address max)` builds `searchvn2 = new VarnodeAST(max,
//! Integer.MAX_VALUE, 0)` but -- unlike every sibling overload (`locRange(AddressSpace)`,
//! `locRange(Address)`, `locRange(int, Address)`, `find`, `findInput`), which all call
//! `setInput(true)` on their search keys -- never calls `setInput(true)` on `searchvn2` here. The
//! upper bound therefore sorts as a *free* varnode (tie-broken by `uniqId == 0`) rather than an
//! input one, which changes exactly where it falls relative to real free/input varnodes of the
//! same address that happen to have `uniqId == 0` at the boundary. Faithfully reproduced in
//! [`loc_range_between`](VarnodeBank::loc_range_between) rather than "fixing" it to match the
//! other overloads.

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::pcode::pcode_op_ast::PcodeOpAST;
use crate::program::model::pcode::varnode_ast::{def_compare, loc_compare, VarnodeAST};
use crate::program::model::pcode::OpCode;

/// Port of the inner class `VarnodeBank.LocComparator`: compares by location, size, then
/// definition. See the module docs for why `BTreeSet<Arc<VarnodeAST>>` doesn't need to hold an
/// instance of this directly (it uses `VarnodeAST`'s own `Ord`, backed by the same logic).
#[derive(Debug, Default, Clone, Copy)]
pub struct LocComparator;

impl LocComparator {
    /// Port of `LocComparator.compare(VarnodeAST, VarnodeAST)`.
    pub fn compare(&self, v1: &VarnodeAST, v2: &VarnodeAST) -> Ordering {
        loc_compare(v1, v2)
    }
}

/// Port of the inner class `VarnodeBank.DefComparator`: compares by definition, then location and
/// size. Dead code in real Ghidra -- see the module docs.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefComparator;

impl DefComparator {
    /// Port of `DefComparator.compare(VarnodeAST, VarnodeAST)`.
    pub fn compare(&self, v1: &VarnodeAST, v2: &VarnodeAST) -> Ordering {
        def_compare(v1, v2)
    }
}

/// Container class for [`VarnodeAST`]s. Port of `ghidra.program.model.pcode.VarnodeBank`. See the
/// module docs for the `BTreeSet`-vs-`TreeSet(Comparator)` collection-choice deviation and the
/// real Java quirks reproduced here.
pub struct VarnodeBank {
    /// Varnodes sorted by location. Port of the private `locTree` field.
    loc_tree: RefCell<BTreeSet<Arc<VarnodeAST>>>,
}

impl VarnodeBank {
    /// Port of `VarnodeBank()`.
    pub fn new() -> Self {
        Self { loc_tree: RefCell::new(BTreeSet::new()) }
    }

    /// Port of `VarnodeBank.clear()`.
    pub fn clear(&self) {
        self.loc_tree.borrow_mut().clear();
    }

    /// Port of `VarnodeBank.size()`.
    pub fn size(&self) -> usize {
        self.loc_tree.borrow().len()
    }

    /// Port of `VarnodeBank.isEmpty()`.
    pub fn is_empty(&self) -> bool {
        self.loc_tree.borrow().is_empty()
    }

    /// Create a new (free) varnode at `addr`/`s` with the given unique id, and insert it into the
    /// bank. Port of `VarnodeBank.create(int, Address, int)`. See the module docs: this never
    /// merges with an existing equal entry, unlike `setInput`/`setDef`.
    pub fn create(&self, s: i32, addr: Address, id: i32) -> Arc<VarnodeAST> {
        let vn = Arc::new(VarnodeAST::new(addr, s, id));
        self.loc_tree.borrow_mut().insert(vn.clone());
        vn
    }

    /// Port of `VarnodeBank.destroy(Varnode)`.
    pub fn destroy(&self, vn: &Arc<VarnodeAST>) {
        self.loc_tree.borrow_mut().remove(vn);
    }

    /// Merge `vn` into the bank: if an existing entry is `equals()`-equal to it, redirect that
    /// existing entry's descendants to absorb `vn`'s and return the existing entry (discarding
    /// `vn`); otherwise insert `vn` fresh and return it. Port of the private
    /// `VarnodeBank.xref(VarnodeAST)`.
    fn xref(&self, vn: Arc<VarnodeAST>) -> Arc<VarnodeAST> {
        // Port of `locTree.tailSet(vn)`: everything ordered at-or-after `vn` under `LocComparator`
        // (i.e. `VarnodeAST`'s own `Ord`).
        let candidate = self.loc_tree.borrow().range(vn.clone()..).next().cloned();
        if let Some(oldvn) = candidate {
            if oldvn == vn {
                // Port of `oldvn.equals(vn)`: note this is `VarnodeAST`'s `PartialEq` (real
                // `equals()` semantics), a different relation than the `Ord`/`LocComparator`
                // membership test just above -- see `varnode_ast.rs`'s module docs.
                VarnodeAST::descend_replace(&oldvn, &vn);
                return oldvn;
            }
        }
        self.loc_tree.borrow_mut().insert(vn.clone());
        vn
    }

    /// Port of `VarnodeBank.makeFree(Varnode)`.
    pub fn make_free(&self, vn: &Arc<VarnodeAST>) {
        self.loc_tree.borrow_mut().remove(vn);
        vn.set_def(None);
        vn.set_input(false);
        vn.set_free(true);
        self.loc_tree.borrow_mut().insert(vn.clone());
    }

    /// Mark `vn` as an input varnode, merging it with an existing equal entry if one exists.
    /// Returns `None` if `vn` is not free, or is a constant -- matching Java's two early-return
    /// guards. Port of `VarnodeBank.setInput(Varnode)`.
    pub fn set_input(&self, vn: &Arc<VarnodeAST>) -> Option<Arc<VarnodeAST>> {
        if !vn.is_free() {
            return None;
        }
        if vn.is_constant() {
            return None;
        }
        self.loc_tree.borrow_mut().remove(vn);
        vn.set_input(true);
        Some(self.xref(vn.clone()))
    }

    /// Give `vn` a defining `op`, merging it with an existing equal entry if one exists. Returns
    /// `None` if `vn` is not free, or is a constant. Port of `VarnodeBank.setDef(Varnode,
    /// PcodeOp)`.
    pub fn set_def(&self, vn: &Arc<VarnodeAST>, op: Arc<PcodeOpAST>) -> Option<Arc<VarnodeAST>> {
        if !vn.is_free() {
            return None;
        }
        if vn.is_constant() {
            return None;
        }
        self.loc_tree.borrow_mut().remove(vn);
        vn.set_def(Some(op));
        Some(self.xref(vn.clone()))
    }

    /// Every varnode in the bank, in location order. Port of `VarnodeBank.locRange()`. Java
    /// returns a live `Iterator<VarnodeAST>`; this returns an owned snapshot, matching the
    /// deviation already established by
    /// [`PcodeOpBank`](crate::program::model::pcode::pcode_op_bank::PcodeOpBank) (see that
    /// module's docs).
    pub fn loc_range(&self) -> Vec<Arc<VarnodeAST>> {
        self.loc_tree.borrow().iter().cloned().collect()
    }

    /// Every varnode in the bank within `spaceid`, in location order. Port of
    /// `VarnodeBank.locRange(AddressSpace)`.
    pub fn loc_range_in_space(&self, spaceid: &Arc<AddressSpace>) -> Vec<Arc<VarnodeAST>> {
        let searchvn1 = Arc::new(VarnodeAST::new(spaceid.min_address(), 0, 0));
        searchvn1.set_input(true);
        let searchvn2 = Arc::new(VarnodeAST::new(spaceid.max_address(), i32::MAX, 0));
        self.loc_tree.borrow().range(searchvn1..searchvn2).cloned().collect()
    }

    /// Every varnode in the bank at exactly `addr` (any size), in location order. Port of
    /// `VarnodeBank.locRange(Address)`.
    ///
    /// # Panics
    /// Real Java's `addr.add(1)` throws an unchecked `AddressOutOfBoundsException` if `addr` is
    /// already at the top of its space; this port panics for the same input, matching that.
    pub fn loc_range_at(&self, addr: &Address) -> Vec<Arc<VarnodeAST>> {
        let searchvn1 = Arc::new(VarnodeAST::new(addr.clone(), 0, 0));
        searchvn1.set_input(true);
        let next_addr = addr
            .add(1)
            .expect("VarnodeBank.locRange(Address): addr.add(1) overflowed, matching real Java's AddressOutOfBoundsException");
        let searchvn2 = Arc::new(VarnodeAST::new(next_addr, 0, 0));
        searchvn2.set_input(true);
        self.loc_tree.borrow().range(searchvn1..searchvn2).cloned().collect()
    }

    /// Every varnode in the bank with an address in `[min, max)`, in location order. Port of
    /// `VarnodeBank.locRange(Address, Address)`. See the module docs: unlike every other
    /// `locRange`/`find*` overload, the upper search bound here is **not** marked as an input
    /// varnode -- faithfully reproduced.
    pub fn loc_range_between(&self, min: &Address, max: &Address) -> Vec<Arc<VarnodeAST>> {
        let searchvn1 = Arc::new(VarnodeAST::new(min.clone(), 0, 0));
        searchvn1.set_input(true);
        let searchvn2 = Arc::new(VarnodeAST::new(max.clone(), i32::MAX, 0));
        self.loc_tree.borrow().range(searchvn1..searchvn2).cloned().collect()
    }

    /// Every varnode in the bank at exactly `addr` with size `sz`, in location order. Port of
    /// `VarnodeBank.locRange(int, Address)`.
    pub fn loc_range_sized(&self, sz: i32, addr: &Address) -> Vec<Arc<VarnodeAST>> {
        let searchvn1 = Arc::new(VarnodeAST::new(addr.clone(), sz, 0));
        searchvn1.set_input(true);
        let searchvn2 = Arc::new(VarnodeAST::new(addr.clone(), sz + 1, 0));
        searchvn2.set_input(true);
        self.loc_tree.borrow().range(searchvn1..searchvn2).cloned().collect()
    }

    /// Find the varnode of size `sz` at `addr` defined by the `PcodeOp` at instruction address
    /// `pc` with the given `uniq` (pass `-1` to match any `uniq` at that `pc`). Port of
    /// `VarnodeBank.find(int, Address, Address, int)`.
    pub fn find(&self, sz: i32, addr: &Address, pc: Address, uniq: i32) -> Option<Arc<VarnodeAST>> {
        let searchvn = Arc::new(VarnodeAST::new(addr.clone(), sz, 0));
        let uq = if uniq == -1 { 0 } else { uniq };
        let op: Arc<PcodeOpAST> = Arc::new(PcodeOpAST::with_address(pc.clone(), uq, OpCode::Copy, 0));
        searchvn.set_def(Some(op));

        let tree = self.loc_tree.borrow();
        for vn in tree.range(searchvn..) {
            if vn.get_size() != sz {
                break;
            }
            if vn.get_address() != addr {
                break;
            }
            if let Some(op2) = vn.get_def() {
                if op2.get_seqnum().get_target() == &pc
                    && (uniq == -1 || op2.get_seqnum().get_time() == uniq)
                {
                    return Some(vn.clone());
                }
            }
        }
        None
    }

    /// Find the input varnode of size `sz` at `addr`, if one exists. Port of
    /// `VarnodeBank.findInput(int, Address)`.
    pub fn find_input(&self, sz: i32, addr: &Address) -> Option<Arc<VarnodeAST>> {
        let searchvn = Arc::new(VarnodeAST::new(addr.clone(), sz, 0));
        searchvn.set_input(true);
        let tree = self.loc_tree.borrow();
        let vn = tree.range(searchvn..).next()?;
        if vn.is_input() && vn.get_size() == sz && vn.get_address() == addr {
            return Some(vn.clone());
        }
        None
    }
}

impl Default for VarnodeBank {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1)
    }

    fn addr_in(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    #[test]
    fn new_bank_is_empty() {
        let bank = VarnodeBank::new();
        assert!(bank.is_empty());
        assert_eq!(bank.size(), 0);
        assert!(bank.loc_range().is_empty());
    }

    #[test]
    fn create_inserts_without_merging_even_at_same_location() {
        let bank = VarnodeBank::new();
        let ram = ram_space();
        let a = addr_in(&ram, 0x100);

        let vn1 = bank.create(4, a.clone(), 1);
        let vn2 = bank.create(4, a, 2);

        // Both free varnodes at the same location/size coexist -- create() never merges.
        assert_eq!(bank.size(), 2);
        assert!(!Arc::ptr_eq(&vn1, &vn2));
    }

    #[test]
    fn destroy_removes_from_bank() {
        let bank = VarnodeBank::new();
        let ram = ram_space();
        let vn = bank.create(4, addr_in(&ram, 0x100), 1);

        bank.destroy(&vn);
        assert!(bank.is_empty());
    }

    /// The second call to `set_input` at the same location merges into the varnode the first call
    /// already installed as the tree's input entry, returning that existing entry (not the second
    /// varnode) and leaving only one entry in the bank -- exercising the real `xref` merge path.
    #[test]
    fn set_input_merges_second_call_at_same_location_into_first() {
        let bank = VarnodeBank::new();
        let ram = ram_space();
        let a = addr_in(&ram, 0x200);
        let vn1 = bank.create(4, a.clone(), 1);
        let vn2 = bank.create(4, a, 2);

        let merged1 = bank.set_input(&vn1).expect("vn1 is free and non-constant");
        assert!(Arc::ptr_eq(&merged1, &vn1), "first call installs vn1 itself as the input entry");
        assert_eq!(bank.size(), 2, "vn2 (still free) is untouched so far");

        let merged2 = bank.set_input(&vn2).expect("vn2 is free and non-constant");
        assert!(
            Arc::ptr_eq(&merged2, &vn1),
            "second call at the same location merges into the existing input varnode, not vn2"
        );
        assert_eq!(bank.size(), 1, "vn2 was merged away, not left as a second tree entry");
    }

    /// `set_input` on a non-free varnode is a no-op that returns `None`.
    #[test]
    fn set_input_on_non_free_varnode_returns_none() {
        let bank = VarnodeBank::new();
        let ram = ram_space();
        let vn = bank.create(4, addr_in(&ram, 0x300), 1);
        bank.set_input(&vn).unwrap();

        // vn is no longer free (isInput() == true now); a second direct call must refuse.
        assert!(bank.set_input(&vn).is_none());
    }

    /// `set_def` merges two free varnodes at the same location whose defining ops share a
    /// `SequenceNumber`, exercising the def-based branch of both `LocComparator` and `equals`.
    #[test]
    fn set_def_merges_varnodes_sharing_a_def_sequence_number() {
        let bank = VarnodeBank::new();
        let ram = ram_space();
        let a = addr_in(&ram, 0x400);
        let vn1 = bank.create(4, a.clone(), 1);
        let vn2 = bank.create(4, a, 2);

        let pc = addr_in(&ram, 0x1000);
        let op1: Arc<PcodeOpAST> = Arc::new(PcodeOpAST::with_address(pc.clone(), 0, OpCode::Copy, 0));
        let op2: Arc<PcodeOpAST> = Arc::new(PcodeOpAST::with_address(pc, 0, OpCode::Copy, 0));

        let merged1 = bank.set_def(&vn1, op1).unwrap();
        assert!(Arc::ptr_eq(&merged1, &vn1));

        let merged2 = bank.set_def(&vn2, op2).unwrap();
        assert!(
            Arc::ptr_eq(&merged2, &vn1),
            "vn2's def has the same SequenceNumber as vn1's, so it merges into vn1"
        );
        assert_eq!(bank.size(), 1);
    }

    #[test]
    fn make_free_returns_varnode_to_free_state() {
        let bank = VarnodeBank::new();
        let ram = ram_space();
        let a = addr_in(&ram, 0x500);
        let vn = bank.create(4, a.clone(), 1);
        let vn = bank.set_input(&vn).unwrap();
        assert!(vn.is_input());

        bank.make_free(&vn);
        assert!(vn.is_free());
        assert!(!vn.is_input());
        assert!(vn.get_def().is_none());
        assert_eq!(bank.size(), 1, "make_free doesn't remove the varnode from the bank");
        assert!(bank.find_input(4, &a).is_none(), "no longer registered as an input varnode");
    }

    #[test]
    fn loc_range_returns_everything_in_address_order() {
        let bank = VarnodeBank::new();
        let ram = ram_space();
        let high = bank.create(4, addr_in(&ram, 0x2000), 1);
        let low = bank.create(4, addr_in(&ram, 0x1000), 2);

        let all = bank.loc_range();
        assert_eq!(all.len(), 2);
        assert!(Arc::ptr_eq(&all[0], &low), "lower address sorts first");
        assert!(Arc::ptr_eq(&all[1], &high));
    }

    #[test]
    fn loc_range_at_filters_to_a_single_address() {
        let bank = VarnodeBank::new();
        let ram = ram_space();
        let a = addr_in(&ram, 0x3000);
        let b = addr_in(&ram, 0x4000);
        let at_a = bank.create(4, a.clone(), 1);
        let _at_b = bank.create(4, b, 2);

        let results = bank.loc_range_at(&a);
        assert_eq!(results.len(), 1);
        assert!(Arc::ptr_eq(&results[0], &at_a));
    }

    #[test]
    fn loc_range_sized_filters_to_address_and_size() {
        let bank = VarnodeBank::new();
        let ram = ram_space();
        let a = addr_in(&ram, 0x5000);
        let four = bank.create(4, a.clone(), 1);
        let _eight = bank.create(8, a.clone(), 2);

        let results = bank.loc_range_sized(4, &a);
        assert_eq!(results.len(), 1);
        assert!(Arc::ptr_eq(&results[0], &four));
    }

    #[test]
    fn loc_range_between_filters_to_a_half_open_address_range() {
        let bank = VarnodeBank::new();
        let ram = ram_space();
        let inside = bank.create(4, addr_in(&ram, 0x1500), 1);
        let _before = bank.create(4, addr_in(&ram, 0x500), 2);
        let _after = bank.create(4, addr_in(&ram, 0x3000), 3);

        let results = bank.loc_range_between(&addr_in(&ram, 0x1000), &addr_in(&ram, 0x2000));
        assert_eq!(results.len(), 1);
        assert!(Arc::ptr_eq(&results[0], &inside));
    }

    #[test]
    fn loc_range_in_space_filters_across_multiple_spaces() {
        let bank = VarnodeBank::new();
        let ram = ram_space();
        let reg = register_space();
        let vn_ram = bank.create(4, addr_in(&ram, 0x100), 1);
        let _vn_reg = bank.create(4, addr_in(&reg, 0x10), 2);

        let ram_only = bank.loc_range_in_space(&ram);
        assert_eq!(ram_only.len(), 1);
        assert!(Arc::ptr_eq(&ram_only[0], &vn_ram));
    }

    #[test]
    fn find_locates_varnode_by_def_pc_and_uniq() {
        let bank = VarnodeBank::new();
        let ram = ram_space();
        let a = addr_in(&ram, 0x6000);
        let vn = bank.create(4, a.clone(), 1);
        let pc = addr_in(&ram, 0x1000);
        let op: Arc<PcodeOpAST> = Arc::new(PcodeOpAST::with_address(pc.clone(), 3, OpCode::IntAdd, 0));
        let vn = bank.set_def(&vn, op).unwrap();

        let found = bank.find(4, &a, pc.clone(), 3).expect("must find the varnode by its def's pc/uniq");
        assert!(Arc::ptr_eq(&found, &vn));

        // uniq == -1 matches any uniq at that pc.
        let found_any = bank.find(4, &a, pc.clone(), -1).expect("uniq=-1 must match any uniq at pc");
        assert!(Arc::ptr_eq(&found_any, &vn));

        // A different uniq at the same pc must not match.
        assert!(bank.find(4, &a, pc, 4).is_none());
    }

    #[test]
    fn find_input_locates_registered_input_varnode() {
        let bank = VarnodeBank::new();
        let ram = ram_space();
        let a = addr_in(&ram, 0x7000);
        let vn = bank.create(4, a.clone(), 1);
        let vn = bank.set_input(&vn).unwrap();

        let found = bank.find_input(4, &a).expect("must find the registered input varnode");
        assert!(Arc::ptr_eq(&found, &vn));

        // Wrong size at the same address must not match.
        assert!(bank.find_input(8, &a).is_none());
    }

    #[test]
    fn find_input_returns_none_when_nothing_registered() {
        let bank = VarnodeBank::new();
        let ram = ram_space();
        assert!(bank.find_input(4, &addr_in(&ram, 0x8000)).is_none());
    }

    #[test]
    fn loc_comparator_and_def_comparator_wrapper_types_delegate_correctly() {
        let ram = ram_space();
        let a = VarnodeAST::new(addr_in(&ram, 0x100), 4, 1);
        let b = VarnodeAST::new(addr_in(&ram, 0x200), 4, 2);

        assert_eq!(LocComparator.compare(&a, &b), a.cmp(&b));
        // Neither `a` nor `b` is an input or has a def, so `def_compare` falls straight through
        // to comparing addresses.
        assert_eq!(DefComparator.compare(&a, &b), a.get_address().cmp(b.get_address()));
    }
}
