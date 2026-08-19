//! Port of `ghidra.program.database.references.RefListV0`.
//!
//! `RefListV0` is the concrete, byte-packed [`RefList`] implementation used for a single address's
//! reference list (either the "from" list of outgoing references or the "to" list of incoming
//! references, per its `isFrom` flag) before it grows large enough to be promoted to a
//! `BigRefListV0`. It stores every reference for that address as a run of variable-length encoded
//! records in one `byte[]` blob, re-encoding/re-decoding on every mutation and lookup.
//!
//! This class was selected as a dependency-cycle cut-point, so it is ported here as a trait rather
//! than a concrete struct. `RefListV0`'s abstract-method overrides are inherited from `RefList`
//! (`addRef`/`getAllRefs`/`getNumRefs`/`hasReference`/`getPrimaryRef`/`getRef`/`getRefs`/
//! `isEmpty`/`getReferenceLevel`/`removeAll`/`removeRef`/`setPrimary`/`setSymbolID`/
//! `updateRefType`, all declared on the [`RefList`] supertrait), so this trait only adds the
//! package-private bulk-insert helper `addRefs(Reference[])` used by `ToAdapter`/`FromAdapter`
//! upgrade paths and by `RefList.checkRefListSize` when promoting to a `BigRefListV0`.
//!
//! Not ported here: the three static factory methods (`createTemporary`/`createNew`/
//! `instantiateExisting`), the private constructors, and the private byte-encoding helpers
//! (`appendRef`/`encode`/`decode`/`updateRecord`/`findHighestRefLevel`/`getRefLevel`/`putLong`/
//! `getLong`) and the nested `RefIterator` class, since those describe *how* one concrete on-disk
//! byte layout implements the contract rather than the dynamic-dispatch surface other in-package
//! classes call through. The package-private `getData()` accessor is also left out: its own doc
//! comment calls it "a little kludgey", and its only callers are the `ToAdapter`/`FromAdapter`
//! static `upgrade(...)` migration paths, which are themselves not yet ported (see
//! `to_adapter.rs`'s module docs for the same convention).
//!
//! `RefList` is now ported (see `ref_list.rs`), so this trait declares it as a supertrait,
//! mirroring the Java `RefListV0 extends RefList` relationship.

use std::io;
use std::sync::Arc;

use crate::program::database::references::RefList;
use crate::program::model::symbol::Reference;

/// The packed reference list for a single address (either outgoing "from" references or incoming
/// "to" references, depending on how the owning adapter constructed it).
///
/// Port of `ghidra.program.database.references.RefListV0`. See the module docs for what was
/// intentionally left out (the static factories, the private byte-codec, and the nested
/// iterator class).
pub trait RefListV0: RefList {
    /// Appends a batch of existing references in one pass. Stands in for
    /// `RefListV0.addRefs(Reference[])`.
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
    use crate::program::model::symbol::{RefType, ReferenceIterator, SourceType};

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

    /// A tiny in-memory stand-in for the real byte-packed storage, just enough to prove the trait
    /// is object-safe and behaves like the Java class for the mutation/query pairs that matter.
    struct MockRefListV0 {
        state: DbObjectState,
        refs: Vec<Arc<dyn Reference>>,
        ref_level: i8,
    }

    impl MockRefListV0 {
        fn new() -> Self {
            MockRefListV0 {
                state: DbObjectState::new(0),
                refs: Vec::new(),
                ref_level: -1,
            }
        }
    }

    impl DbObject for MockRefListV0 {
        fn state(&self) -> &DbObjectState {
            &self.state
        }

        fn refresh(&self, _record: Option<&crate::framework::db::DBRecord>) -> bool {
            true
        }
    }

    impl RefList for MockRefListV0 {
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
            Box::new(crate::program::model::symbol::ReferenceIteratorAdapter::new(
                self.refs.clone(),
            ))
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

    impl RefListV0 for MockRefListV0 {
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
        let mut list = MockRefListV0::new();
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
    fn set_primary_reports_whether_it_changed() {
        let mut list = MockRefListV0::new();
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
        let mut list: Box<dyn RefListV0> = Box::new(MockRefListV0::new());
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
                let r = iter.next().unwrap();
        assert_eq!(r.symbol_id(), 42);
        assert!(iter.next().is_none());

        list.remove_all().unwrap();
        assert!(list.is_empty());
    }
}
