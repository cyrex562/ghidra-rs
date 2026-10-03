//! [`ReferenceManager`] over a [`ReferenceStore`]: what `ProgramDB.getReferenceManager()` hands
//! out, so code written against the trait (`PseudoInstruction`'s references, `CodeUnitFormat`,
//! `SymbolUtilities`) sees the program's stored references.
//!
//! The store holds memory references only (default and user ones, see the module docs of
//! [`reference_store`](super)). The trait's other kinds of references are not stored yet:
//! adding a stack, register, offset, shifted or external reference, associating a symbol, or
//! retyping a reference panics with a message naming the missing piece rather than silently
//! dropping the reference; the read side answers as Java does for a program that has none of
//! them (no external references, no referenced variables).

use std::sync::Arc;

use super::{ReferenceRecord, ReferenceStore};
use crate::program::model::address::{Address, AddressSetView, BoxedAddressIterator};
use crate::program::model::lang::Register;
use crate::program::model::listing::Variable;
use crate::program::model::symbol::reference_iterator::{EmptyReferenceIterator, ReferenceIteratorAdapter};
use crate::program::model::symbol::reference_manager::AddExternalReferenceError;
use crate::program::model::symbol::{
    ExternalLocation, Namespace, RefType, Reference, ReferenceIterator, ReferenceManager, SourceType, Symbol,
};
use crate::program::model::symbol::symbol_utilities::{DAT_LEVEL, EXT_LEVEL, LAB_LEVEL, SUB_LEVEL, UNK_LEVEL};
use crate::util::exception::InvalidInputException;

fn shared(records: Vec<ReferenceRecord>) -> Vec<Arc<dyn Reference>> {
    records.into_iter().map(|r| Arc::new(r) as Arc<dyn Reference>).collect()
}

fn unsupported(what: &str) -> ! {
    panic!("ReferenceStore does not store {what} yet (memory references only)")
}

/// Port of `RefListV0.getRefLevel(RefType)`: the dynamic-label level a reference of `ref_type`
/// gives its destination.
pub fn reference_level_of(ref_type: RefType) -> i8 {
    let level = if ref_type == RefType::ExternalRef {
        EXT_LEVEL
    } else if ref_type.is_call() {
        SUB_LEVEL
    } else if ref_type.is_data() || ref_type.is_indirect() {
        DAT_LEVEL
    } else if ref_type.is_flow() {
        LAB_LEVEL
    } else {
        UNK_LEVEL
    };
    level as i8
}

impl ReferenceStore {
    /// The highest dynamic-label level of the references to `to` (`ReferenceManager
    /// .getReferenceLevel`), or `None` when nothing references it. Java answers `UNK_LEVEL` for
    /// an unreferenced address; [`ReferenceManager::get_reference_level`] does too.
    pub fn reference_level(&self, to: &Address) -> Option<i8> {
        self.references_to(to).iter().map(|r| reference_level_of(r.reference_type())).max()
    }

    fn record_of(&self, reference: &dyn Reference) -> Option<&ReferenceRecord> {
        self.reference(&reference.from_address(), &reference.to_address(), reference.operand_index())
    }

    fn addresses(keys: Vec<Address>, start: &Address, forward: bool) -> BoxedAddressIterator {
        let mut keys: Vec<Address> =
            keys.into_iter().filter(|a| if forward { a >= start } else { a <= start }).collect();
        if !forward {
            keys.reverse();
        }
        Box::new(keys.into_iter())
    }

    fn addresses_in(keys: Vec<Address>, set: Option<&dyn AddressSetView>, forward: bool) -> BoxedAddressIterator {
        let mut keys: Vec<Address> = keys.into_iter().filter(|a| set.is_none_or(|s| s.contains(a))).collect();
        if !forward {
            keys.reverse();
        }
        Box::new(keys.into_iter())
    }

    fn all_sources(&self) -> Vec<Address> {
        self.from.keys().cloned().collect()
    }

    fn all_destinations(&self) -> Vec<Address> {
        self.to.keys().cloned().collect()
    }
}

impl ReferenceManager for ReferenceStore {
    /// Adds a memory reference like `reference`; other kinds panic (see the module docs).
    fn add_reference(&mut self, reference: Arc<dyn Reference>) -> Arc<dyn Reference> {
        if !reference.is_memory_reference() || reference.is_offset_reference() || reference.is_shifted_reference() {
            unsupported("non-memory, offset or shifted references");
        }
        let added = ReferenceManager::add_memory_reference(
            self,
            reference.from_address(),
            reference.to_address(),
            reference.reference_type(),
            reference.source(),
            reference.operand_index(),
        );
        if reference.is_primary() {
            if let Some(id) = self.reference(&reference.from_address(), &reference.to_address(), reference.operand_index()).map(|r| r.id()) {
                ReferenceStore::set_primary(self, id, true);
            }
        }
        added
    }

    fn add_stack_reference(&mut self, _: Address, _: i32, _: i32, _: RefType, _: SourceType) -> Arc<dyn Reference> {
        unsupported("stack references")
    }

    fn add_register_reference(&mut self, _: Address, _: i32, _: &Register, _: RefType, _: SourceType) -> Arc<dyn Reference> {
        unsupported("register references")
    }

    /// # Panics
    /// When the store rejects the reference (Java's `IllegalArgumentException`).
    fn add_memory_reference(
        &mut self,
        from_addr: Address,
        to_addr: Address,
        ref_type: RefType,
        source: SourceType,
        op_index: i32,
    ) -> Arc<dyn Reference> {
        match ReferenceStore::add_memory_reference(self, from_addr, to_addr, ref_type, source, op_index) {
            Ok(record) => Arc::new(record),
            Err(e) => panic!("{e}"),
        }
    }

    fn add_offset_mem_reference(&mut self, _: Address, _: Address, _: bool, _: i64, _: RefType, _: SourceType, _: i32) -> Arc<dyn Reference> {
        unsupported("offset references")
    }

    fn add_shifted_mem_reference(&mut self, _: Address, _: Address, _: i32, _: RefType, _: SourceType, _: i32) -> Arc<dyn Reference> {
        unsupported("shifted references")
    }

    fn add_external_reference(
        &mut self,
        _: Address,
        _: &str,
        _: Option<&str>,
        _: Option<Address>,
        _: SourceType,
        _: i32,
        _: RefType,
    ) -> Result<Arc<dyn Reference>, AddExternalReferenceError> {
        unsupported("external references")
    }

    fn add_external_reference_in_namespace(
        &mut self,
        _: Address,
        _: Arc<dyn Namespace>,
        _: Option<&str>,
        _: Option<Address>,
        _: SourceType,
        _: i32,
        _: RefType,
    ) -> Result<Arc<dyn Reference>, AddExternalReferenceError> {
        unsupported("external references")
    }

    fn add_external_reference_for_location(
        &mut self,
        _: Address,
        _: i32,
        _: Arc<dyn ExternalLocation>,
        _: SourceType,
        _: RefType,
    ) -> Result<Arc<dyn Reference>, InvalidInputException> {
        unsupported("external references")
    }

    fn remove_all_references_from_range(&mut self, begin_addr: Address, end_addr: Address) {
        ReferenceStore::remove_all_references_from_range(self, &begin_addr, &end_addr);
    }

    fn remove_all_references_from(&mut self, from_addr: Address) {
        ReferenceStore::remove_all_references_from(self, &from_addr);
    }

    fn remove_all_references_to(&mut self, to_addr: Address) {
        for record in self.references_to(&to_addr) {
            self.delete(record.id());
        }
    }

    /// No variables are stored, so nothing references one.
    fn get_references_to_variable(&self, _var: &dyn Variable) -> Vec<Arc<dyn Reference>> {
        Vec::new()
    }

    /// No variables are stored.
    fn get_referenced_variable(&self, _reference: &dyn Reference) -> Option<Box<dyn Variable>> {
        None
    }

    fn set_primary(&mut self, reference: Arc<dyn Reference>, is_primary: bool) {
        if let Some(id) = self.record_of(reference.as_ref()).map(|r| r.id()) {
            ReferenceStore::set_primary(self, id, is_primary);
        }
    }

    fn has_flow_references_from(&self, addr: Address) -> bool {
        !self.flow_references_from(&addr).is_empty()
    }

    fn get_flow_references_from(&self, addr: Address) -> Vec<Arc<dyn Reference>> {
        shared(self.flow_references_from(&addr))
    }

    fn get_external_references(&self) -> Box<dyn ReferenceIterator> {
        Box::new(EmptyReferenceIterator)
    }

    fn get_references_to(&self, addr: Address) -> Box<dyn ReferenceIterator> {
        Box::new(ReferenceIteratorAdapter::new(shared(self.references_to(&addr))))
    }

    /// Every reference from `start_addr` on, by from address then in the order added.
    fn get_reference_iterator(&self, start_addr: Address) -> Box<dyn ReferenceIterator> {
        let records: Vec<ReferenceRecord> = self
            .all_sources()
            .into_iter()
            .filter(|a| *a >= start_addr)
            .flat_map(|a| self.references_from(&a))
            .collect();
        Box::new(ReferenceIteratorAdapter::new(shared(records)))
    }

    fn get_reference(&self, from_addr: Address, to_addr: Address, op_index: i32) -> Option<Arc<dyn Reference>> {
        self.reference(&from_addr, &to_addr, op_index).map(|r| Arc::new(r.clone()) as Arc<dyn Reference>)
    }

    fn get_references_from(&self, addr: Address) -> Vec<Arc<dyn Reference>> {
        shared(self.references_from(&addr))
    }

    fn get_references_from_operand(&self, from_addr: Address, op_index: i32) -> Vec<Arc<dyn Reference>> {
        shared(self.references_from_operand(&from_addr, op_index))
    }

    fn has_references_from_operand(&self, from_addr: Address, op_index: i32) -> bool {
        !self.references_from_operand(&from_addr, op_index).is_empty()
    }

    fn has_references_from(&self, from_addr: Address) -> bool {
        ReferenceStore::has_references_from(self, &from_addr)
    }

    fn get_primary_reference_from(&self, addr: Address, op_index: i32) -> Option<Arc<dyn Reference>> {
        self.primary_reference_from(&addr, op_index).map(|r| Arc::new(r) as Arc<dyn Reference>)
    }

    fn get_reference_source_iterator(&self, start_addr: Address, forward: bool) -> BoxedAddressIterator {
        Self::addresses(self.all_sources(), &start_addr, forward)
    }

    fn get_reference_source_iterator_in_set(&self, addr_set: Option<&dyn AddressSetView>, forward: bool) -> BoxedAddressIterator {
        Self::addresses_in(self.all_sources(), addr_set, forward)
    }

    fn get_reference_destination_iterator(&self, start_addr: Address, forward: bool) -> BoxedAddressIterator {
        Self::addresses(self.all_destinations(), &start_addr, forward)
    }

    fn get_reference_destination_iterator_in_set(&self, addr_set: Option<&dyn AddressSetView>, forward: bool) -> BoxedAddressIterator {
        Self::addresses_in(self.all_destinations(), addr_set, forward)
    }

    fn get_reference_count_to(&self, to_addr: Address) -> i32 {
        self.reference_count_to(&to_addr) as i32
    }

    fn get_reference_count_from(&self, from_addr: Address) -> i32 {
        self.reference_count_from(&from_addr) as i32
    }

    fn get_reference_destination_count(&self) -> i32 {
        self.to.len() as i32
    }

    fn get_reference_source_count(&self) -> i32 {
        self.from.len() as i32
    }

    fn has_references_to(&self, to_addr: Address) -> bool {
        ReferenceStore::has_references_to(self, &to_addr)
    }

    fn update_ref_type(&mut self, _reference: Arc<dyn Reference>, _ref_type: RefType) -> Arc<dyn Reference> {
        unsupported("reference type updates")
    }

    fn set_association(&mut self, _symbol: Arc<dyn Symbol>, _reference: Arc<dyn Reference>) {
        unsupported("symbol associations")
    }

    fn remove_association(&mut self, _reference: Arc<dyn Reference>) {
        unsupported("symbol associations")
    }

    fn delete(&mut self, reference: Arc<dyn Reference>) {
        if let Some(id) = self.record_of(reference.as_ref()).map(|r| r.id()) {
            ReferenceStore::delete(self, id);
        }
    }

    fn get_reference_level(&self, to_addr: Address) -> i8 {
        self.reference_level(&to_addr).unwrap_or(UNK_LEVEL as i8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        Address::new(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1), offset)
    }

    fn store_with(refs: &[(i64, i64, RefType, i32)]) -> ReferenceStore {
        let mut store = ReferenceStore::new();
        for &(from, to, ref_type, op) in refs {
            ReferenceStore::add_memory_reference(&mut store, addr(from), addr(to), ref_type, SourceType::Default, op)
                .unwrap();
        }
        store
    }

    #[test]
    fn the_trait_reads_the_stores_references() {
        let store = store_with(&[(0x10, 0x100, RefType::Read, 0), (0x10, 0x200, RefType::UnconditionalCall, -1)]);
        let manager: &dyn ReferenceManager = &store;
        let primary = manager.get_primary_reference_from(addr(0x10), 0).unwrap();
        assert_eq!((primary.to_address(), primary.reference_type()), (addr(0x100), RefType::Read));
        assert_eq!(manager.get_references_from(addr(0x10)).len(), 2);
        assert_eq!(manager.get_flow_references_from(addr(0x10))[0].to_address(), addr(0x200));
        assert_eq!(manager.get_references_to(addr(0x100)).count(), 1);
        assert!(manager.has_references_to(addr(0x200)));
        assert!(!manager.has_references_to(addr(0x300)));
        assert_eq!(manager.get_reference_destination_iterator(addr(0), true).collect::<Vec<_>>(), vec![addr(0x100), addr(0x200)]);
        assert_eq!(manager.get_reference_source_iterator(addr(0x20), false).collect::<Vec<_>>(), vec![addr(0x10)]);
        assert!(manager.get_referenced_variable(primary.as_ref()).is_none());
    }

    #[test]
    fn reference_level_is_the_highest_level_of_the_references_to() {
        let store = store_with(&[
            (0x10, 0x100, RefType::Read, 0),
            (0x20, 0x100, RefType::ConditionalJump, -1),
            (0x30, 0x200, RefType::Data, 0),
            (0x40, 0x300, RefType::UnconditionalCall, -1),
        ]);
        assert_eq!(store.reference_level(&addr(0x100)), Some(LAB_LEVEL as i8));
        assert_eq!(store.reference_level(&addr(0x200)), Some(DAT_LEVEL as i8));
        assert_eq!(store.reference_level(&addr(0x300)), Some(SUB_LEVEL as i8));
        assert_eq!(store.reference_level(&addr(0x400)), None);
        assert_eq!(ReferenceManager::get_reference_level(&store, addr(0x400)), UNK_LEVEL as i8);
    }

    #[test]
    fn the_trait_mutates_the_store() {
        let mut store = store_with(&[(0x10, 0x100, RefType::Read, 0), (0x20, 0x100, RefType::Read, 0)]);
        let manager: &mut dyn ReferenceManager = &mut store;
        let added = manager.add_memory_reference(addr(0x10), addr(0x180), RefType::Read, SourceType::UserDefined, 0);
        assert!(!added.is_primary());
        manager.set_primary(added.clone(), true);
        assert_eq!(manager.get_primary_reference_from(addr(0x10), 0).unwrap().to_address(), addr(0x180));
        manager.delete(added);
        assert_eq!(manager.get_reference_count_from(addr(0x10)), 1);
        manager.remove_all_references_to(addr(0x100));
        assert!(!manager.has_references_to(addr(0x100)));
        assert_eq!(manager.get_reference_source_count(), 0);
    }
}
