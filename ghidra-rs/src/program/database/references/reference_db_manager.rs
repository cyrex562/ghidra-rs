//! Port of `ghidra.program.database.references.ReferenceDBManager` as a trait (cycle cut-point).
//!
//! The Java class is a concrete `ReferenceManager`/`ManagerDB`/`ErrorHandler` implementation that
//! directly wires together `SymbolManager`, `ProgramDB`, and `ExternalManagerDB`: `SymbolManager`
//! calls `symbolAdded`/`symbolRemoved` on its reference manager whenever a symbol changes, while
//! `ReferenceDBManager` calls back into the symbol manager (`getSymbol`, `getSymbols`,
//! `findVariableStorageAddress`) to resolve variable references. That mutual dependency is the
//! `ReferenceDBManager` <-> [`SymbolManagerDb`](crate::program::database::symbol::SymbolManagerDb)
//! cycle this port cuts.
//!
//! `ReferenceDbManager` captures the class's own public surface -- the parts not already covered
//! by the already-ported [`ReferenceManager`] and [`ManagerDB`] interfaces it implements -- so a
//! concrete DB-backed implementor can be added later without reintroducing the cycle. Method names
//! mirror the corresponding `ReferenceDBManager` Java methods (`snake_case`d). Left out: the
//! constructor (`DBHandle`/`AddressMap`/`OpenMode`/`Lock`/`TaskMonitor` wiring and the old stack
//! reference/namespace-address upgrade path), which is an implementation detail of whichever
//! concrete DB-backed type is added later, not part of the callable API other managers depend on.

use std::io;

use thiserror::Error;

use crate::program::database::ManagerDB;
use crate::program::model::address::{Address, AddressIterator};
use crate::program::model::symbol::{ReferenceManager, Symbol};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Error produced by [`ReferenceDbManager::move_references_to`], mirroring the Java method's
/// `throws CancelledException, IOException`.
#[derive(Debug, Error)]
pub enum MoveReferencesToError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Reference manager implementation for the database.
///
/// Port of `ghidra.program.database.references.ReferenceDBManager`. See the module docs for what
/// was intentionally left out (the constructor and old-format upgrade path).
pub trait ReferenceDbManager: ReferenceManager + ManagerDB {
    /// Notification that a symbol is about to be removed. Stands in for
    /// `ReferenceDBManager.symbolRemoved(Symbol)`.
    fn symbol_removed(&mut self, symbol: &dyn Symbol);

    /// Notification that a symbol has been added. Stands in for
    /// `ReferenceDBManager.symbolAdded(Symbol)`.
    fn symbol_added(&mut self, symbol: &dyn Symbol);

    /// Move all references that have `old_to_addr` as their "to" address so they instead point at
    /// `new_to_addr`. Any symbol binding will be discarded since these are intended for memory
    /// label references only. Stands in for
    /// `ReferenceDBManager.moveReferencesTo(Address, Address, TaskMonitor)`.
    ///
    /// # Returns
    /// The number of references updated.
    fn move_references_to(
        &mut self,
        old_to_addr: Address,
        new_to_addr: Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<i32, MoveReferencesToError>;

    /// Get an address iterator over references that are external entry memory references. Stands
    /// in for `ReferenceDBManager.getExternalEntryIterator()`.
    fn get_external_entry_iterator(&self) -> Box<dyn AddressIterator>;

    /// Return whether the address is an external entry point. Stands in for
    /// `ReferenceDBManager.isExternalEntryPoint(Address)`.
    fn is_external_entry_point(&self, to_addr: Address) -> bool;

    /// Create a memory reference to the given address to mark it as an external entry point.
    /// Stands in for `ReferenceDBManager.addExternalEntryPointRef(Address)`.
    ///
    /// # Panics
    /// Implementations should reject a non-memory address, mirroring Java's
    /// `IllegalArgumentException`.
    fn add_external_entry_point_ref(&mut self, to_addr: Address);

    /// Removes the external entry point at the given address. Stands in for
    /// `ReferenceDBManager.removeExternalEntryPoint(Address)`.
    fn remove_external_entry_point(&mut self, addr: Address);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressIteratorAdapter, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Variable;
    use crate::program::model::symbol::{
        AddExternalReferenceError, ExternalLocation, Namespace, RefType, Reference,
        ReferenceIterator, SourceType,
    };
    use crate::program::model::symbol::mem_reference_impl::MemReferenceImpl;
    use crate::util::exception::InvalidInputException;
    use std::collections::HashSet;
    use std::sync::Arc;

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram(), offset)
    }

    /// Mock implementing enough of `ReferenceManager`/`ManagerDB`/`ReferenceDbManager` against a
    /// flat reference list to exercise real `move_references_to`/external-entry-point behavior;
    /// unrelated `ReferenceManager` methods are left as inert stubs (mirroring the existing
    /// `MockReferenceManager` in `reference_manager.rs`'s tests), matching how
    /// `SymbolManagerDb`'s mock isn't a full DB-backed implementation either.
    struct MockRefDbManager {
        refs: Vec<Arc<dyn Reference>>,
        external_entries: HashSet<i64>,
        symbol_events: Vec<String>,
    }

    impl MockRefDbManager {
        fn new() -> Self {
            MockRefDbManager {
                refs: Vec::new(),
                external_entries: HashSet::new(),
                symbol_events: Vec::new(),
            }
        }
    }

    impl ReferenceManager for MockRefDbManager {
        fn add_reference(&mut self, reference: Arc<dyn Reference>) -> Arc<dyn Reference> {
            self.refs.push(reference.clone());
            reference
        }

        fn add_stack_reference(
            &mut self,
            _from_addr: Address,
            _op_index: i32,
            _stack_offset: i32,
            _ref_type: RefType,
            _source: SourceType,
        ) -> Arc<dyn Reference> {
            unimplemented!()
        }

        fn add_register_reference(
            &mut self,
            _from_addr: Address,
            _op_index: i32,
            _register: &crate::program::model::lang::Register,
            _ref_type: RefType,
            _source: SourceType,
        ) -> Arc<dyn Reference> {
            unimplemented!()
        }

        fn add_memory_reference(
            &mut self,
            from_addr: Address,
            to_addr: Address,
            ref_type: RefType,
            source: SourceType,
            op_index: i32,
        ) -> Arc<dyn Reference> {
            let reference: Arc<dyn Reference> = Arc::new(MemReferenceImpl::new(
                from_addr, to_addr, ref_type, source, op_index, false,
            ));
            self.refs.push(reference.clone());
            reference
        }

        fn add_offset_mem_reference(
            &mut self,
            _from_addr: Address,
            _to_addr: Address,
            _to_addr_is_base: bool,
            _offset: i64,
            _ref_type: RefType,
            _source: SourceType,
            _op_index: i32,
        ) -> Arc<dyn Reference> {
            unimplemented!()
        }

        fn add_shifted_mem_reference(
            &mut self,
            _from_addr: Address,
            _to_addr: Address,
            _shift_value: i32,
            _ref_type: RefType,
            _source: SourceType,
            _op_index: i32,
        ) -> Arc<dyn Reference> {
            unimplemented!()
        }

        fn add_external_reference(
            &mut self,
            _from_addr: Address,
            _library_name: &str,
            _ext_label: Option<&str>,
            _ext_addr: Option<Address>,
            _source: SourceType,
            _op_index: i32,
            _ref_type: RefType,
        ) -> Result<Arc<dyn Reference>, AddExternalReferenceError> {
            unimplemented!()
        }

        fn add_external_reference_in_namespace(
            &mut self,
            _from_addr: Address,
            _ext_namespace: Arc<dyn Namespace>,
            _ext_label: Option<&str>,
            _ext_addr: Option<Address>,
            _source: SourceType,
            _op_index: i32,
            _ref_type: RefType,
        ) -> Result<Arc<dyn Reference>, AddExternalReferenceError> {
            unimplemented!()
        }

        fn add_external_reference_for_location(
            &mut self,
            _from_addr: Address,
            _op_index: i32,
            _location: Arc<dyn ExternalLocation>,
            _source: SourceType,
            _ref_type: RefType,
        ) -> Result<Arc<dyn Reference>, InvalidInputException> {
            unimplemented!()
        }

        fn remove_all_references_from_range(&mut self, _begin_addr: Address, _end_addr: Address) {}

        fn remove_all_references_from(&mut self, from_addr: Address) {
            self.refs.retain(|r| r.from_address() != from_addr);
        }

        fn remove_all_references_to(&mut self, to_addr: Address) {
            self.refs.retain(|r| r.to_address() != to_addr);
        }

        fn get_references_to_variable(&self, _var: &dyn Variable) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_referenced_variable(&self, _reference: &dyn Reference) -> Option<Box<dyn Variable>> {
            None
        }

        fn set_primary(&mut self, _reference: Arc<dyn Reference>, _is_primary: bool) {}

        fn has_flow_references_from(&self, _addr: Address) -> bool {
            false
        }

        fn get_flow_references_from(&self, _addr: Address) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_external_references(&self) -> Box<dyn ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }

        fn get_references_to(&self, addr: Address) -> Box<dyn ReferenceIterator> {
            let matches: Vec<Arc<dyn Reference>> = self
                .refs
                .iter()
                .filter(|r| r.to_address() == addr)
                .cloned()
                .collect();
            Box::new(crate::program::model::symbol::ReferenceIteratorAdapter::new(matches))
        }

        fn get_reference_iterator(&self, _start_addr: Address) -> Box<dyn ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }

        fn get_reference(
            &self,
            from_addr: Address,
            to_addr: Address,
            op_index: i32,
        ) -> Option<Arc<dyn Reference>> {
            self.refs
                .iter()
                .find(|r| {
                    r.from_address() == from_addr
                        && r.to_address() == to_addr
                        && r.operand_index() == op_index
                })
                .cloned()
        }

        fn get_references_from(&self, addr: Address) -> Vec<Arc<dyn Reference>> {
            self.refs
                .iter()
                .filter(|r| r.from_address() == addr)
                .cloned()
                .collect()
        }

        fn get_references_from_operand(
            &self,
            _from_addr: Address,
            _op_index: i32,
        ) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn has_references_from_operand(&self, _from_addr: Address, _op_index: i32) -> bool {
            false
        }

        fn has_references_from(&self, from_addr: Address) -> bool {
            self.refs.iter().any(|r| r.from_address() == from_addr)
        }

        fn get_primary_reference_from(
            &self,
            _addr: Address,
            _op_index: i32,
        ) -> Option<Arc<dyn Reference>> {
            None
        }

        fn get_reference_source_iterator(
            &self,
            _start_addr: Address,
            _forward: bool,
        ) -> Box<dyn AddressIterator> {
            Box::new(crate::program::model::address::EmptyAddressIterator)
        }

        fn get_reference_source_iterator_in_set(
            &self,
            _addr_set: Option<&dyn crate::program::model::address::AddressSetView>,
            _forward: bool,
        ) -> Box<dyn AddressIterator> {
            Box::new(crate::program::model::address::EmptyAddressIterator)
        }

        fn get_reference_destination_iterator(
            &self,
            _start_addr: Address,
            _forward: bool,
        ) -> Box<dyn AddressIterator> {
            Box::new(crate::program::model::address::EmptyAddressIterator)
        }

        fn get_reference_destination_iterator_in_set(
            &self,
            _addr_set: Option<&dyn crate::program::model::address::AddressSetView>,
            _forward: bool,
        ) -> Box<dyn AddressIterator> {
            Box::new(crate::program::model::address::EmptyAddressIterator)
        }

        fn get_reference_count_to(&self, to_addr: Address) -> i32 {
            self.refs.iter().filter(|r| r.to_address() == to_addr).count() as i32
        }

        fn get_reference_count_from(&self, from_addr: Address) -> i32 {
            self.refs
                .iter()
                .filter(|r| r.from_address() == from_addr)
                .count() as i32
        }

        fn get_reference_destination_count(&self) -> i32 {
            0
        }

        fn get_reference_source_count(&self) -> i32 {
            0
        }

        fn has_references_to(&self, to_addr: Address) -> bool {
            self.refs.iter().any(|r| r.to_address() == to_addr)
        }

        fn update_ref_type(
            &mut self,
            reference: Arc<dyn Reference>,
            _ref_type: RefType,
        ) -> Arc<dyn Reference> {
            reference
        }

        fn set_association(&mut self, _symbol: Arc<dyn Symbol>, _reference: Arc<dyn Reference>) {}

        fn remove_association(&mut self, _reference: Arc<dyn Reference>) {}

        fn delete(&mut self, reference: Arc<dyn Reference>) {
            self.refs.retain(|r| {
                !(r.from_address() == reference.from_address()
                    && r.to_address() == reference.to_address()
                    && r.operand_index() == reference.operand_index())
            });
        }

        fn get_reference_level(&self, _to_addr: Address) -> i8 {
            0
        }
    }

    impl ManagerDB for MockRefDbManager {
        fn invalidate_cache(&mut self, _all: bool) -> io::Result<()> {
            Ok(())
        }

        fn delete_address_range(
            &mut self,
            _start_addr: &Address,
            _end_addr: &Address,
        ) -> io::Result<()> {
            Ok(())
        }

        fn move_address_range(
            &mut self,
            _from_addr: &Address,
            _to_addr: &Address,
            _length: u64,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    impl ReferenceDbManager for MockRefDbManager {
        fn symbol_removed(&mut self, symbol: &dyn Symbol) {
            self.symbol_events
                .push(format!("removed:{}", symbol.get_name()));
        }

        fn symbol_added(&mut self, symbol: &dyn Symbol) {
            self.symbol_events
                .push(format!("added:{}", symbol.get_name()));
        }

        fn move_references_to(
            &mut self,
            old_to_addr: Address,
            new_to_addr: Address,
            monitor: &dyn TaskMonitor,
        ) -> Result<i32, MoveReferencesToError> {
            let moving: Vec<Arc<dyn Reference>> = self
                .refs
                .iter()
                .filter(|r| r.to_address() == old_to_addr)
                .cloned()
                .collect();

            for _ in &moving {
                monitor.check_cancelled()?;
            }

            self.refs.retain(|r| r.to_address() != old_to_addr);
            for r in &moving {
                self.refs.push(Arc::new(MemReferenceImpl::new(
                    r.from_address(),
                    new_to_addr.clone(),
                    r.reference_type(),
                    r.source(),
                    r.operand_index(),
                    r.is_primary(),
                )));
            }

            Ok(moving.len() as i32)
        }

        fn get_external_entry_iterator(&self) -> Box<dyn AddressIterator> {
            let addrs: Vec<Address> = self
                .external_entries
                .iter()
                .map(|&offset| addr(offset))
                .collect();
            Box::new(AddressIteratorAdapter::from_vec(addrs))
        }

        fn is_external_entry_point(&self, to_addr: Address) -> bool {
            self.external_entries.contains(&to_addr.offset())
        }

        fn add_external_entry_point_ref(&mut self, to_addr: Address) {
            self.external_entries.insert(to_addr.offset());
        }

        fn remove_external_entry_point(&mut self, addr: Address) {
            self.external_entries.remove(&addr.offset());
        }
    }

    struct MockSymbol(String);

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            addr(0)
        }

        fn get_name(&self) -> &str {
            &self.0
        }

        fn get_symbol_type(&self) -> crate::program::model::symbol::SymbolType {
            crate::program::model::symbol::SymbolType::Label
        }

        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }

        fn is_primary(&self) -> bool {
            true
        }

        fn get_id(&self) -> i64 {
            1
        }

        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut mgr: Box<dyn ReferenceDbManager> = Box::new(MockRefDbManager::new());

        let from1 = addr(0x1000);
        let from2 = addr(0x1010);
        let old_to = addr(0x2000);
        let new_to = addr(0x3000);

        mgr.add_memory_reference(from1.clone(), old_to.clone(), RefType::Read, SourceType::UserDefined, 0);
        mgr.add_memory_reference(from2.clone(), old_to.clone(), RefType::Write, SourceType::Analysis, 1);

        assert_eq!(mgr.get_reference_count_to(old_to.clone()), 2);

        let monitor = crate::util::task::DummyMonitor;
        let moved = mgr
            .move_references_to(old_to.clone(), new_to.clone(), &monitor)
            .unwrap();
        assert_eq!(moved, 2);

        assert!(!mgr.has_references_to(old_to.clone()));
        assert_eq!(mgr.get_reference_count_to(new_to.clone()), 2);

        assert!(!mgr.is_external_entry_point(new_to.clone()));
        mgr.add_external_entry_point_ref(new_to.clone());
        assert!(mgr.is_external_entry_point(new_to.clone()));

        let mut entries = Vec::new();
        let mut it = mgr.get_external_entry_iterator();
        while let Some(a) = it.next_address() {
            entries.push(a);
        }
        assert_eq!(entries, vec![new_to.clone()]);

        mgr.remove_external_entry_point(new_to.clone());
        assert!(!mgr.is_external_entry_point(new_to.clone()));

        let sym = MockSymbol("foo".to_string());
        mgr.symbol_added(&sym);
        mgr.symbol_removed(&sym);
    }
}
