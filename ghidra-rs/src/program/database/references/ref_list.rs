//! Port of `ghidra.program.database.references.RefList`.
//!
//! `RefList` is the abstract base class for a single address's stored reference list (either the
//! "from" list of outgoing references or the "to" list of incoming references, depending on how
//! the owning adapter constructed it). It was selected as a dependency-cycle cut-point, so it is
//! ported here as a trait rather than a concrete struct/base class. Its fourteen abstract
//! instance methods map directly to trait methods: `addRef`/`updateRefType`/`getRef`/
//! `removeRef`/`isEmpty`/`setPrimary`/`getRefs`/`getAllRefs`/`getNumRefs`/`getPrimaryRef`/
//! `removeAll`/`setSymbolID`/`hasReference`/`getReferenceLevel`. Both
//! [`RefListV0`](crate::program::database::references::RefListV0) and
//! [`BigRefListV0`](crate::program::database::references::BigRefListV0) already declared this
//! same set of methods themselves (since they were written before `RefList` was ported and the
//! only stand-in was an empty placeholder trait); they now declare `RefList` as a supertrait and
//! only add the members Java actually declares beyond it (`addRefs`/`addRefs(ReferenceIterator)`),
//! matching the Java `extends RefList` relationship and avoiding an ambiguous duplicate method
//! name on any type implementing both traits.
//!
//! `RefList extends DbObject` in Java, so this trait declares [`DbObject`] as a supertrait.
//!
//! Not ported here: the protected constructor and its `address`/`adapter`/`addrMap`/`program`/
//! `isFrom` fields (Rust traits carry no state; a concrete implementor would hold these as
//! fields and expose whatever subset of them its own API needs, the same convention already used
//! for `RecordAdapter` and other fieldless trait ports), the `protected static DataConverter
//! converter` field (an implementation detail of the not-yet-ported private byte-encoding
//! helpers, mirroring why `RefListV0`/`BigRefListV0` also leave those out), and the
//! `checkRefListSize(DbCache<RefList>, int)` default method. `checkRefListSize` needs the
//! unported `address`/`adapter`/`addrMap`/`program`/`isFrom` fields plus
//! `BigRefListV0::createNew`, whose static factory is itself explicitly not ported (see
//! `big_ref_list_v0.rs`'s module docs) — deferred until a concrete `RefList` implementor exists
//! to hang the real promotion logic off of. `BIG_REFLIST_THRESHOLD`, the public constant that
//! method compares against, is ported below since it carries no such dependency.

use std::io;
use std::sync::Arc;

use crate::program::database::db_object::DbObject;
use crate::program::model::address::Address;
use crate::program::model::symbol::{RefType, Reference, ReferenceIterator, SourceType};

/// Number of references a list may hold before [`RefList::checkRefListSize`]'s (not yet ported)
/// promotion logic would transition it to a `BigRefListV0`. Mirrors
/// `RefList.BIG_REFLIST_THRESHOLD`.
pub const BIG_REFLIST_THRESHOLD: i32 = 1700;

/// The stored reference list for a single address (either outgoing "from" references or incoming
/// "to" references, depending on how the owning adapter constructed it).
///
/// Port of `ghidra.program.database.references.RefList`. See the module docs for what was
/// intentionally left out (the protected fields/constructor and `checkRefListSize`).
pub trait RefList: DbObject {
    /// Appends a single new reference. Stands in for
    /// `RefList.addRef(Address, Address, RefType, int, long, boolean, SourceType, boolean,
    /// boolean, long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    #[allow(clippy::too_many_arguments)]
    fn add_ref(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        ref_type: RefType,
        op_index: i32,
        symbol_id: i64,
        is_primary: bool,
        source: SourceType,
        is_offset: bool,
        is_shift: bool,
        offset_or_shift: i64,
    ) -> io::Result<()>;

    /// Changes the reference type of the reference to/from `addr` at `op_index`. Stands in for
    /// `RefList.updateRefType(Address, int, RefType)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn update_ref_type(&mut self, addr: &Address, op_index: i32, ref_type: RefType) -> io::Result<()>;

    /// Returns the reference to/from `address` (depending on list direction) at `op_index`, if
    /// any. Stands in for `RefList.getRef(Address, int)`.
    fn get_ref(&self, address: &Address, op_index: i32) -> Option<Arc<dyn Reference>>;

    /// Removes the reference to/from `addr` at `op_index`, if present, returning whether one was
    /// removed. Stands in for `RefList.removeRef(Address, int)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn remove_ref(&mut self, addr: &Address, op_index: i32) -> io::Result<bool>;

    /// Returns true if this list holds no references. Stands in for `RefList.isEmpty()`.
    fn is_empty(&self) -> bool;

    /// Sets or clears `reference`'s primary flag, returning whether a change was made (`false`
    /// when `is_primary` already matched). Stands in for `RefList.setPrimary(Reference,
    /// boolean)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn set_primary(&mut self, reference: &dyn Reference, is_primary: bool) -> io::Result<bool>;

    /// Returns an iterator over every reference in this list. Stands in for `RefList.getRefs()`.
    fn get_refs(&self) -> Box<dyn ReferenceIterator>;

    /// Returns every reference currently stored in this list. Stands in for
    /// `RefList.getAllRefs()`.
    fn get_all_refs(&self) -> Vec<Arc<dyn Reference>>;

    /// Returns the number of references stored in this list. Stands in for
    /// `RefList.getNumRefs()`.
    fn get_num_refs(&self) -> i32;

    /// Returns the primary reference for `op_index`, if any. Stands in for
    /// `RefList.getPrimaryRef(int)`.
    fn get_primary_ref(&self, op_index: i32) -> Option<Arc<dyn Reference>>;

    /// Empties this list, discarding all references. Stands in for `RefList.removeAll()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn remove_all(&mut self) -> io::Result<()>;

    /// Sets `reference`'s associated symbol ID, returning whether a change was made. Stands in
    /// for `RefList.setSymbolID(Reference, long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn set_symbol_id(&mut self, reference: &dyn Reference, symbol_id: i64) -> io::Result<bool>;

    /// Returns true if the specified `op_index` has a corresponding reference. NOTE: this is
    /// only of value for the "from" lists. Stands in for `RefList.hasReference(int)`.
    fn has_reference(&self, op_index: i32) -> bool;

    /// Returns this list's cached reference level (used to prioritize which reference wins a
    /// symbol's primary label). Stands in for `RefList.getReferenceLevel()`.
    fn get_reference_level(&self) -> i8;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::db_object::DbObjectState;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

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

    /// A tiny in-memory stand-in proving the trait is object-safe and behaves like the Java class
    /// for the mutation/query pairs that matter.
    struct MockRefList {
        state: DbObjectState,
        refs: Vec<Arc<dyn Reference>>,
        ref_level: i8,
    }

    impl MockRefList {
        fn new(key: i64) -> Self {
            MockRefList {
                state: DbObjectState::new(key),
                refs: Vec::new(),
                ref_level: -1,
            }
        }
    }

    impl DbObject for MockRefList {
        fn state(&self) -> &DbObjectState {
            &self.state
        }

        fn refresh(&self, _record: Option<&crate::framework::db::DBRecord>) -> bool {
            true
        }
    }

    impl RefList for MockRefList {
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

        fn update_ref_type(
            &mut self,
            addr: &Address,
            op_index: i32,
            ref_type: RefType,
        ) -> io::Result<()> {
            for r in &mut self.refs {
                if r.operand_index() == op_index && &r.to_address() == addr {
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

        fn get_ref(&self, address: &Address, op_index: i32) -> Option<Arc<dyn Reference>> {
            self.refs
                .iter()
                .find(|r| r.operand_index() == op_index && &r.to_address() == address)
                .cloned()
        }

        fn remove_ref(&mut self, addr: &Address, op_index: i32) -> io::Result<bool> {
            let before = self.refs.len();
            self.refs
                .retain(|r| !(r.operand_index() == op_index && &r.to_address() == addr));
            Ok(self.refs.len() != before)
        }

        fn is_empty(&self) -> bool {
            self.refs.is_empty()
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

        fn get_refs(&self) -> Box<dyn ReferenceIterator> {
            Box::new(crate::program::model::symbol::ReferenceIteratorAdapter::new(
                self.refs.clone(),
            ))
        }

        fn get_all_refs(&self) -> Vec<Arc<dyn Reference>> {
            self.refs.clone()
        }

        fn get_num_refs(&self) -> i32 {
            self.refs.len() as i32
        }

        fn get_primary_ref(&self, op_index: i32) -> Option<Arc<dyn Reference>> {
            self.refs
                .iter()
                .find(|r| r.is_primary() && r.operand_index() == op_index)
                .cloned()
        }

        fn remove_all(&mut self) -> io::Result<()> {
            self.refs.clear();
            self.ref_level = -1;
            Ok(())
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

        fn has_reference(&self, op_index: i32) -> bool {
            self.refs.iter().any(|r| r.operand_index() == op_index)
        }

        fn get_reference_level(&self) -> i8 {
            self.ref_level
        }
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    #[test]
    fn object_safety_via_trait_object() {
        let mut list: Box<dyn RefList> = Box::new(MockRefList::new(1));
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
        assert!(!list.is_empty());
        assert!(list.has_reference(0));

        let mut iter = list.get_refs();
        assert!(iter.has_next());
        let r = iter.next_reference().unwrap();
        assert_eq!(r.symbol_id(), 42);
        assert!(!iter.has_next());

        assert!(list.remove_ref(&to, 0).unwrap());
        assert!(list.is_empty());
        assert!(!list.remove_ref(&to, 0).unwrap());
    }

    #[test]
    fn set_primary_and_symbol_id_report_whether_they_changed() {
        let mut list = MockRefList::new(1);
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

        assert!(list.set_symbol_id(updated.as_ref(), 99).unwrap());
        assert_eq!(list.get_ref(&to, 1).unwrap().symbol_id(), 99);
    }

    #[test]
    fn db_object_supertrait_is_usable_through_the_trait_object() {
        let list: Box<dyn RefList> = Box::new(MockRefList::new(7));
        assert_eq!(list.get_key(), 7);
        assert!(list.is_valid());
    }
}
