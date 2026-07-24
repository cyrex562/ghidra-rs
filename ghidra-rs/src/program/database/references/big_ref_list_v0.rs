//! Port of `ghidra.program.database.references.BigRefListV0`.
//!
//! `BigRefListV0` is the concrete, one-record-per-reference [`RefList`] implementation used for a
//! single address's reference list once it has grown too large for the byte-packed
//! [`RefListV0`](crate::program::database::references::RefListV0) encoding (per
//! `RefList.checkRefListSize`'s `BIG_REFLIST_THRESHOLD` promotion). Each reference gets its own row
//! in a dedicated per-address `Table` (`"[From]BigRefList_" + hex(key)`) instead of being packed
//! into one blob, trading per-row storage overhead for cheaper incremental inserts/removals at
//! scale.
//!
//! This class was selected as a dependency-cycle cut-point, so it is ported here as a trait rather
//! than a concrete struct. `BigRefListV0`'s abstract-method overrides are inherited from
//! `RefList` (the same base class `RefListV0` implements): `addRef`/`getAllRefs`/`getNumRefs`/
//! `hasReference`/`getPrimaryRef`/`getRef`/`getRefs`/`isEmpty`/`getReferenceLevel`/`removeAll`/
//! `removeRef`/`setPrimary`/`setSymbolID`/`updateRefType`, all declared on the [`RefList`]
//! supertrait. This trait only adds the package-private bulk-insert helpers
//! `addRefs(ReferenceIterator)` and `addRefs(Reference[])` (both overloads exist here, unlike
//! `RefListV0` which only has the array form) used by the `RefList.checkRefListSize` promotion
//! path and by `ToAdapter`/`FromAdapter` upgrade paths.
//!
//! Not ported here: the two static factory methods (`createNew`/`createExisting`), the private
//! constructors, the private per-row table helpers (`appendRef`/`getRef(DBRecord)`/
//! `getTableName`/`updateRecord`/`findHighestRefLevel`/`getRefLevel`) and the nested `RefIterator`
//! class, since those describe *how* this concrete one-row-per-reference table layout implements
//! the contract rather than the dynamic-dispatch surface other in-package classes call through —
//! the same convention `RefListV0` already uses for its own byte-codec helpers. `checkRefListSize`
//! is also not ported: `BigRefListV0`'s override is a trivial no-op (`return this;`, since a
//! `BigRefListV0` is already as big as it gets), and the real logic lives on `RefList`'s own
//! still-unported default method (see `ref_list.rs`'s module docs for why).
//!
//! `RefList` is now ported (see `ref_list.rs`), so this trait declares it as a supertrait,
//! mirroring the Java `BigRefListV0 extends RefList` relationship and reusing the same supertrait
//! `RefListV0` already extends.

use std::io;
use std::sync::Arc;

use crate::program::database::references::RefList;
use crate::program::model::symbol::{Reference, ReferenceIterator};

/// The one-row-per-reference list for a single address (either outgoing "from" references or
/// incoming "to" references, depending on how the owning adapter constructed it), used once the
/// address's reference count outgrows the packed
/// [`RefListV0`](crate::program::database::references::RefListV0) encoding.
///
/// Port of `ghidra.program.database.references.BigRefListV0`. See the module docs for what was
/// intentionally left out (the static factories, the private per-row table helpers, the nested
/// iterator class, and `checkRefListSize`).
pub trait BigRefListV0: RefList {
    /// Appends every reference produced by `ref_iter` in one pass. Stands in for
    /// `BigRefListV0.addRefs(ReferenceIterator)`, used by the `RefList.checkRefListSize`
    /// promotion path to bulk-copy an existing list's references into a newly promoted
    /// `BigRefListV0`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn add_refs_from_iter(&mut self, ref_iter: &mut dyn ReferenceIterator) -> io::Result<()>;

    /// Appends a batch of existing references in one pass. Stands in for
    /// `BigRefListV0.addRefs(Reference[])`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn add_refs(&mut self, refs: &[Arc<dyn Reference>]) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::db_object::{DbObject, DbObjectState};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{RefType, ReferenceIteratorAdapter, SourceType};

    struct MockReference {
        from: Address,
        to: Address,
        op_index: i32,
        ref_type: RefType,
        source: SourceType,
        is_primary: bool,
        symbol_id: i64,
    }

    impl Reference for MockReference {
        fn from_address(&self) -> Address {
            self.from.clone()
        }

        fn to_address(&self) -> Address {
            self.to.clone()
        }

        fn is_primary(&self) -> bool {
            self.is_primary
        }

        fn symbol_id(&self) -> i64 {
            self.symbol_id
        }

        fn reference_type(&self) -> RefType {
            self.ref_type
        }

        fn operand_index(&self) -> i32 {
            self.op_index
        }

        fn is_mnemonic_reference(&self) -> bool {
            false
        }

        fn is_operand_reference(&self) -> bool {
            true
        }

        fn is_stack_reference(&self) -> bool {
            false
        }

        fn is_external_reference(&self) -> bool {
            false
        }

        fn is_entry_point_reference(&self) -> bool {
            false
        }

        fn is_memory_reference(&self) -> bool {
            true
        }

        fn is_register_reference(&self) -> bool {
            false
        }

        fn is_offset_reference(&self) -> bool {
            false
        }

        fn is_shifted_reference(&self) -> bool {
            false
        }

        fn source(&self) -> SourceType {
            self.source
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    /// A tiny in-memory stand-in for the real one-row-per-reference table storage, just enough to
    /// prove the trait is object-safe and behaves like the Java class for the mutation/query pairs
    /// that matter (including the `ReferenceIterator`-driven bulk insert `RefListV0` doesn't have).
    struct MockBigRefListV0 {
        state: DbObjectState,
        refs: Vec<Arc<dyn Reference>>,
        ref_level: i8,
    }

    impl MockBigRefListV0 {
        fn new() -> Self {
            MockBigRefListV0 {
                state: DbObjectState::new(0),
                refs: Vec::new(),
                ref_level: -1,
            }
        }
    }

    impl DbObject for MockBigRefListV0 {
        fn state(&self) -> &DbObjectState {
            &self.state
        }

        fn refresh(&self, _record: Option<&crate::framework::db::DBRecord>) -> bool {
            true
        }
    }

    impl RefList for MockBigRefListV0 {
        fn add_ref(
            &mut self,
            from_addr: &Address,
            to_addr: &Address,
            ref_type: RefType,
            op_index: i32,
            symbol_id: i64,
            is_primary: bool,
            source: SourceType,
            _is_offset: bool,
            _is_shift: bool,
            _offset_or_shift: i64,
        ) -> io::Result<()> {
            self.refs.push(Arc::new(MockReference {
                from: from_addr.clone(),
                to: to_addr.clone(),
                op_index,
                ref_type,
                source,
                is_primary,
                symbol_id,
            }));
            Ok(())
        }

        fn get_all_refs(&self) -> Vec<Arc<dyn Reference>> {
            self.refs.clone()
        }

        fn get_num_refs(&self) -> i32 {
            self.refs.len() as i32
        }

        fn has_reference(&self, op_index: i32) -> bool {
            self.refs.iter().any(|r| r.operand_index() == op_index)
        }

        fn get_primary_ref(&self, op_index: i32) -> Option<Arc<dyn Reference>> {
            self.refs
                .iter()
                .find(|r| r.is_primary() && r.operand_index() == op_index)
                .cloned()
        }

        fn get_ref(&self, ref_address: &Address, op_index: i32) -> Option<Arc<dyn Reference>> {
            self.refs
                .iter()
                .find(|r| r.operand_index() == op_index && &r.to_address() == ref_address)
                .cloned()
        }

        fn get_refs(&self) -> Box<dyn ReferenceIterator> {
            Box::new(ReferenceIteratorAdapter::new(self.refs.clone()))
        }

        fn is_empty(&self) -> bool {
            self.refs.is_empty()
        }

        fn get_reference_level(&self) -> i8 {
            self.ref_level
        }

        fn remove_all(&mut self) -> io::Result<()> {
            self.refs.clear();
            self.ref_level = -1;
            Ok(())
        }

        fn remove_ref(&mut self, delete_addr: &Address, op_index: i32) -> io::Result<bool> {
            let before = self.refs.len();
            self.refs
                .retain(|r| !(r.operand_index() == op_index && &r.to_address() == delete_addr));
            Ok(self.refs.len() != before)
        }

        fn set_primary(&mut self, reference: &dyn Reference, is_primary: bool) -> io::Result<bool> {
            for r in &mut self.refs {
                if r.operand_index() == reference.operand_index()
                    && r.to_address() == reference.to_address()
                {
                    if r.is_primary() == is_primary {
                        return Ok(false);
                    }
                    *r = Arc::new(MockReference {
                        from: r.from_address(),
                        to: r.to_address(),
                        op_index: r.operand_index(),
                        ref_type: r.reference_type(),
                        source: r.source(),
                        is_primary,
                        symbol_id: r.symbol_id(),
                    });
                    return Ok(true);
                }
            }
            Ok(false)
        }

        fn set_symbol_id(&mut self, reference: &dyn Reference, symbol_id: i64) -> io::Result<bool> {
            for r in &mut self.refs {
                if r.operand_index() == reference.operand_index()
                    && r.to_address() == reference.to_address()
                {
                    *r = Arc::new(MockReference {
                        from: r.from_address(),
                        to: r.to_address(),
                        op_index: r.operand_index(),
                        ref_type: r.reference_type(),
                        source: r.source(),
                        is_primary: r.is_primary(),
                        symbol_id,
                    });
                    return Ok(true);
                }
            }
            Ok(false)
        }

        fn update_ref_type(
            &mut self,
            change_addr: &Address,
            op_index: i32,
            ref_type: RefType,
        ) -> io::Result<()> {
            for r in &mut self.refs {
                if r.operand_index() == op_index && &r.to_address() == change_addr {
                    *r = Arc::new(MockReference {
                        from: r.from_address(),
                        to: r.to_address(),
                        op_index: r.operand_index(),
                        ref_type,
                        source: r.source(),
                        is_primary: r.is_primary(),
                        symbol_id: r.symbol_id(),
                    });
                }
            }
            Ok(())
        }
    }

    impl BigRefListV0 for MockBigRefListV0 {
        fn add_refs_from_iter(&mut self, ref_iter: &mut dyn ReferenceIterator) -> io::Result<()> {
            while let Some(r) = ref_iter.next_reference() {
                self.refs.push(r);
            }
            Ok(())
        }

        fn add_refs(&mut self, refs: &[Arc<dyn Reference>]) -> io::Result<()> {
            self.refs.extend(refs.iter().cloned());
            Ok(())
        }
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    #[test]
    fn add_and_remove_ref_round_trip() {
        let mut list = MockBigRefListV0::new();
        let from = addr(0x1000);
        let to = addr(0x2000);

        list.add_ref(
            &from,
            &to,
            RefType::Data,
            0,
            -1,
            true,
            SourceType::UserDefined,
            false,
            false,
            0,
        )
        .unwrap();

        assert_eq!(list.get_num_refs(), 1);
        assert!(!list.is_empty());
        assert!(list.has_reference(0));
        assert!(list.get_ref(&to, 0).is_some());
        assert!(list.get_primary_ref(0).is_some());

        assert!(list.remove_ref(&to, 0).unwrap());
        assert_eq!(list.get_num_refs(), 0);
        assert!(list.is_empty());
        assert!(!list.remove_ref(&to, 0).unwrap());
    }

    #[test]
    fn add_refs_from_iter_bulk_copies_a_promoted_lists_references() {
        // Mirrors `RefList.checkRefListSize`'s `refList.addRefs(getRefs())` promotion call, which
        // is the only real Java call site for this overload.
        let mut source = MockBigRefListV0::new();
        let from = addr(0x1000);
        for i in 0..3 {
            source
                .add_ref(
                    &from,
                    &addr(0x2000 + i),
                    RefType::Data,
                    i as i32,
                    -1,
                    false,
                    SourceType::Analysis,
                    false,
                    false,
                    0,
                )
                .unwrap();
        }

        let mut promoted = MockBigRefListV0::new();
        let mut iter = source.get_refs();
        promoted.add_refs_from_iter(iter.as_mut()).unwrap();

        assert_eq!(promoted.get_num_refs(), 3);
        for i in 0..3 {
            assert!(promoted.get_ref(&addr(0x2000 + i), i as i32).is_some());
        }
    }

    #[test]
    fn set_primary_reports_whether_it_changed() {
        let mut list = MockBigRefListV0::new();
        let from = addr(0x1000);
        let to = addr(0x2000);
        list.add_ref(
            &from,
            &to,
            RefType::Data,
            1,
            -1,
            false,
            SourceType::Analysis,
            false,
            false,
            0,
        )
        .unwrap();

        let current = list.get_ref(&to, 1).unwrap();
        assert!(list.set_primary(current.as_ref(), true).unwrap());
        let updated = list.get_ref(&to, 1).unwrap();
        assert!(updated.is_primary());

        // Setting to the same value again should report no change.
        assert!(!list.set_primary(updated.as_ref(), true).unwrap());
    }

    #[test]
    fn object_safety_via_trait_object() {
        let mut list: Box<dyn BigRefListV0> = Box::new(MockBigRefListV0::new());
        let from = addr(0x10);
        let to = addr(0x20);
        list.add_ref(
            &from,
            &to,
            RefType::UnconditionalCall,
            0,
            42,
            true,
            SourceType::Imported,
            false,
            false,
            0,
        )
        .unwrap();
        assert_eq!(list.get_num_refs(), 1);

        let mut iter = list.get_refs();
        assert!(iter.has_next());
        let r = iter.next_reference().unwrap();
        assert_eq!(r.symbol_id(), 42);
        assert!(!iter.has_next());

        list.remove_all().unwrap();
        assert!(list.is_empty());
    }
}
