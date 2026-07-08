//! The ReferenceManager interface. Defines methods for managing references.
//!
//! Port of `ghidra.program.model.symbol.ReferenceManager`. Java's overloaded
//! `addExternalReference`, `removeAllReferencesFrom`, and `getReferencesFrom`/
//! `getReferenceSourceIterator`/`getReferenceDestinationIterator` methods are each given a
//! distinct Rust name, since Rust traits cannot overload on parameter type alone. The two
//! `AddressSetView`-restricted iterator overloads take `Option<&dyn AddressSetView>` in place of
//! Java's nullable `addrSet` parameter (`None` means "all addresses").

use std::sync::Arc;

use thiserror::Error;

use crate::program::model::address::{Address, AddressIterator, AddressSetView};
use crate::program::model::lang::Register;
use crate::program::model::listing::Variable;
use crate::program::model::symbol::{
    ExternalLocation, Namespace, RefType, Reference, ReferenceIterator, SourceType, Symbol,
};
use crate::util::exception::{DuplicateNameException, InvalidInputException};

/// Operand index which corresponds to the instruction/data mnemonic.
///
/// Stands in for `ReferenceManager.MNEMONIC = Reference.MNEMONIC`.
pub const MNEMONIC: i32 = crate::program::model::symbol::reference::MNEMONIC;

/// Error produced by [`ReferenceManager::add_external_reference`] and
/// [`ReferenceManager::add_external_reference_in_namespace`].
///
/// Combines the two checked exceptions declared on the corresponding overloaded Java
/// `addExternalReference` methods.
#[derive(Error, Debug, PartialEq)]
pub enum AddExternalReferenceError {
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
}

/// Interface for managing references.
///
/// Port of `ghidra.program.model.symbol.ReferenceManager`.
pub trait ReferenceManager: Send + Sync {
    /// Add a memory, stack, register or external reference.
    ///
    /// # Returns
    /// The new reference.
    fn add_reference(&mut self, reference: Arc<dyn Reference>) -> Arc<dyn Reference>;

    /// Add a reference to a stack location. If a reference already exists for the `from_addr`
    /// and `op_index`, the existing reference is replaced with the new reference.
    ///
    /// # Returns
    /// The new stack reference.
    fn add_stack_reference(
        &mut self,
        from_addr: Address,
        op_index: i32,
        stack_offset: i32,
        ref_type: RefType,
        source: SourceType,
    ) -> Arc<dyn Reference>;

    /// Add a reference to a register. If a reference already exists for the `from_addr` and
    /// `op_index`, the existing reference is replaced with the new reference.
    ///
    /// # Returns
    /// The new register reference.
    fn add_register_reference(
        &mut self,
        from_addr: Address,
        op_index: i32,
        register: &Register,
        ref_type: RefType,
        source: SourceType,
    ) -> Arc<dyn Reference>;

    /// Adds a memory reference. The first memory reference placed on an operand will be made
    /// primary by default. All non-memory references will be removed from the specified
    /// operand. Certain reference types may not be specified (e.g. `RefType::FallThrough`).
    ///
    /// # Returns
    /// The new memory reference.
    ///
    /// # Panics
    /// Implementations should reject unsupported `ref_type` values, mirroring Java's
    /// `IllegalArgumentException`.
    fn add_memory_reference(
        &mut self,
        from_addr: Address,
        to_addr: Address,
        ref_type: RefType,
        source: SourceType,
        op_index: i32,
    ) -> Arc<dyn Reference>;

    /// Add an offset memory reference. The first memory reference placed on an operand will be
    /// made primary by default. All non-memory references will be removed from the specified
    /// operand. If `to_addr` corresponds to the EXTERNAL memory block, the resulting offset
    /// reference will report to/base address as the same regardless of specified offset.
    ///
    /// `to_addr_is_base`: if true `to_addr` is treated as a base address, else treated as
    /// `(base + offset)`. It is generally preferred to specify a base address to ensure proper
    /// handling of the EXTERNAL block case.
    ///
    /// # Returns
    /// The new offset reference.
    fn add_offset_mem_reference(
        &mut self,
        from_addr: Address,
        to_addr: Address,
        to_addr_is_base: bool,
        offset: i64,
        ref_type: RefType,
        source: SourceType,
        op_index: i32,
    ) -> Arc<dyn Reference>;

    /// Add a shifted memory reference; the "to" address is computed as the value at the operand
    /// at `op_index` shifted by some number of bits, specified in `shift_value`. The first memory
    /// reference placed on an operand will be made primary by default. All non-memory references
    /// will be removed from the specified operand.
    ///
    /// # Returns
    /// The new shifted reference.
    fn add_shifted_mem_reference(
        &mut self,
        from_addr: Address,
        to_addr: Address,
        shift_value: i32,
        ref_type: RefType,
        source: SourceType,
        op_index: i32,
    ) -> Arc<dyn Reference>;

    /// Adds an external reference to an external symbol identified by `library_name`. If a
    /// reference already exists at `from_addr` and `op_index` the existing reference is replaced
    /// with a new reference. If the external symbol cannot be found, a new Library and/or
    /// external location symbol will be created which corresponds to the specified
    /// library/file named `library_name` and the location within that file identified by
    /// `ext_label` and/or its memory address `ext_addr`. Either or both `ext_label` or
    /// `ext_addr` must be specified.
    ///
    /// # Errors
    /// Returns `Err` if `library_name` is invalid, or an invalid `ext_label` is specified, or
    /// neither `ext_label` nor `ext_addr` was specified properly, or another non-Library
    /// namespace has the same name as `library_name`.
    fn add_external_reference(
        &mut self,
        from_addr: Address,
        library_name: &str,
        ext_label: Option<&str>,
        ext_addr: Option<Address>,
        source: SourceType,
        op_index: i32,
        ref_type: RefType,
    ) -> Result<Arc<dyn Reference>, AddExternalReferenceError>;

    /// Adds an external reference within an existing external namespace. If a reference already
    /// exists for the `from_addr` and `op_index`, the existing reference is replaced with the
    /// new reference.
    ///
    /// # Errors
    /// Returns `Err` if an invalid `ext_label` is specified, or neither `ext_label` nor
    /// `ext_addr` was specified properly, or another non-Library namespace has the same name.
    fn add_external_reference_in_namespace(
        &mut self,
        from_addr: Address,
        ext_namespace: Arc<dyn Namespace>,
        ext_label: Option<&str>,
        ext_addr: Option<Address>,
        source: SourceType,
        op_index: i32,
        ref_type: RefType,
    ) -> Result<Arc<dyn Reference>, AddExternalReferenceError>;

    /// Adds an external reference targeting an existing external location. If a reference
    /// already exists for the `from_addr` and `op_index`, the existing reference is replaced
    /// with the new reference.
    ///
    /// # Errors
    /// Returns `Err` if the input is invalid.
    fn add_external_reference_for_location(
        &mut self,
        from_addr: Address,
        op_index: i32,
        location: Arc<dyn ExternalLocation>,
        source: SourceType,
        ref_type: RefType,
    ) -> Result<Arc<dyn Reference>, InvalidInputException>;

    /// Removes all references where the "from" address is in the given range (inclusive).
    fn remove_all_references_from_range(&mut self, begin_addr: Address, end_addr: Address);

    /// Remove all stack, external, and memory references for the given "from" address.
    fn remove_all_references_from(&mut self, from_addr: Address);

    /// Remove all stack, external, and memory references for the given "to" address.
    fn remove_all_references_to(&mut self, to_addr: Address);

    /// Returns all references to the given variable. Only data references to storage are
    /// considered.
    ///
    /// # Returns
    /// The variable references, or an empty vector if none exist.
    fn get_references_to_variable(&self, var: &dyn Variable) -> Vec<Arc<dyn Reference>>;

    /// Returns the referenced function variable, or `None` if the variable is not found.
    fn get_referenced_variable(&self, reference: &dyn Reference) -> Option<Box<dyn Variable>>;

    /// Set the given reference's primary attribute.
    fn set_primary(&mut self, reference: Arc<dyn Reference>, is_primary: bool);

    /// Return whether the given address has flow references from it.
    fn has_flow_references_from(&self, addr: Address) -> bool;

    /// Get all flow references from the given address.
    fn get_flow_references_from(&self, addr: Address) -> Vec<Arc<dyn Reference>>;

    /// Returns an iterator over all external space references.
    fn get_external_references(&self) -> Box<dyn ReferenceIterator>;

    /// Get an iterator over all references that have the given address as their "to" address.
    fn get_references_to(&self, addr: Address) -> Box<dyn ReferenceIterator>;

    /// Get an iterator over references starting with the specified `start_addr`. A forward
    /// iterator is returned with references sorted on the from address.
    fn get_reference_iterator(&self, start_addr: Address) -> Box<dyn ReferenceIterator>;

    /// Get the reference that has the given from and to address, and operand index, or `None` if
    /// no such reference exists.
    fn get_reference(
        &self,
        from_addr: Address,
        to_addr: Address,
        op_index: i32,
    ) -> Option<Arc<dyn Reference>>;

    /// Get all references "from" the specified address.
    fn get_references_from(&self, addr: Address) -> Vec<Arc<dyn Reference>>;

    /// Returns all references "from" the given `from_addr` and operand (specified by
    /// `op_index`).
    fn get_references_from_operand(&self, from_addr: Address, op_index: i32) -> Vec<Arc<dyn Reference>>;

    /// Returns true if there are any memory references at the given address/`op_index`. Keep in
    /// mind this is a rather inefficient method as it must examine all references from the
    /// specified `from_addr`.
    fn has_references_from_operand(&self, from_addr: Address, op_index: i32) -> bool;

    /// Returns true if there are any memory references at the given address.
    fn has_references_from(&self, from_addr: Address) -> bool;

    /// Get the primary reference from the given address, or `None` if none exists.
    fn get_primary_reference_from(&self, addr: Address, op_index: i32) -> Option<Arc<dyn Reference>>;

    /// Returns an iterator over addresses that are the "from" address in a reference.
    fn get_reference_source_iterator(
        &self,
        start_addr: Address,
        forward: bool,
    ) -> Box<dyn AddressIterator>;

    /// Returns an iterator over all addresses that are the "from" address in a reference,
    /// restricted by the given address set. `addr_set` of `None` means all addresses.
    fn get_reference_source_iterator_in_set(
        &self,
        addr_set: Option<&dyn AddressSetView>,
        forward: bool,
    ) -> Box<dyn AddressIterator>;

    /// Returns an iterator over all addresses that are the "to" address in a reference.
    fn get_reference_destination_iterator(
        &self,
        start_addr: Address,
        forward: bool,
    ) -> Box<dyn AddressIterator>;

    /// Returns an iterator over all addresses that are the "to" address in a memory reference,
    /// restricted by the given address set. `addr_set` of `None` means all addresses.
    fn get_reference_destination_iterator_in_set(
        &self,
        addr_set: Option<&dyn AddressSetView>,
        forward: bool,
    ) -> Box<dyn AddressIterator>;

    /// Returns the number of references to the specified `to_addr`.
    fn get_reference_count_to(&self, to_addr: Address) -> i32;

    /// Returns the number of references from the specified `from_addr`.
    fn get_reference_count_from(&self, from_addr: Address) -> i32;

    /// Return the number of references for "to" addresses.
    fn get_reference_destination_count(&self) -> i32;

    /// Return the number of references for "from" addresses.
    fn get_reference_source_count(&self) -> i32;

    /// Return true if a memory reference exists with the given "to" address.
    fn has_references_to(&self, to_addr: Address) -> bool;

    /// Update the reference type on a memory reference.
    ///
    /// # Returns
    /// The updated reference.
    fn update_ref_type(&mut self, reference: Arc<dyn Reference>, ref_type: RefType) -> Arc<dyn Reference>;

    /// Associates the given reference with the given symbol. Applies to memory references only
    /// where a specified label symbol must have an address which matches the reference
    /// to-address. Stack and register reference associations to variable symbols are always
    /// inferred.
    ///
    /// # Panics
    /// Implementations should reject a reference that does not already exist, or whose "to"
    /// address does not match the symbol's address, mirroring Java's
    /// `IllegalArgumentException`.
    fn set_association(&mut self, symbol: Arc<dyn Symbol>, reference: Arc<dyn Reference>);

    /// Removes any symbol associations with the given reference.
    ///
    /// # Panics
    /// Implementations should reject a reference that does not exist, mirroring Java's
    /// `IllegalArgumentException`.
    fn remove_association(&mut self, reference: Arc<dyn Reference>);

    /// Deletes the given reference object.
    fn delete(&mut self, reference: Arc<dyn Reference>);

    /// Returns the reference level for the references to the given address.
    fn get_reference_level(&self, to_addr: Address) -> i8;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    /// Minimal mock proving `ReferenceManager` is object-safe and usable via `Box<dyn _>`.
    struct MockReferenceManager;

    impl ReferenceManager for MockReferenceManager {
        fn add_reference(&mut self, reference: Arc<dyn Reference>) -> Arc<dyn Reference> {
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
            _register: &Register,
            _ref_type: RefType,
            _source: SourceType,
        ) -> Arc<dyn Reference> {
            unimplemented!()
        }

        fn add_memory_reference(
            &mut self,
            _from_addr: Address,
            _to_addr: Address,
            _ref_type: RefType,
            _source: SourceType,
            _op_index: i32,
        ) -> Arc<dyn Reference> {
            unimplemented!()
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

        fn remove_all_references_from(&mut self, _from_addr: Address) {}

        fn remove_all_references_to(&mut self, _to_addr: Address) {}

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

        fn get_references_to(&self, _addr: Address) -> Box<dyn ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }

        fn get_reference_iterator(&self, _start_addr: Address) -> Box<dyn ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }

        fn get_reference(
            &self,
            _from_addr: Address,
            _to_addr: Address,
            _op_index: i32,
        ) -> Option<Arc<dyn Reference>> {
            None
        }

        fn get_references_from(&self, _addr: Address) -> Vec<Arc<dyn Reference>> {
            Vec::new()
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

        fn has_references_from(&self, _from_addr: Address) -> bool {
            false
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
            _addr_set: Option<&dyn AddressSetView>,
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
            _addr_set: Option<&dyn AddressSetView>,
            _forward: bool,
        ) -> Box<dyn AddressIterator> {
            Box::new(crate::program::model::address::EmptyAddressIterator)
        }

        fn get_reference_count_to(&self, _to_addr: Address) -> i32 {
            0
        }

        fn get_reference_count_from(&self, _from_addr: Address) -> i32 {
            0
        }

        fn get_reference_destination_count(&self) -> i32 {
            0
        }

        fn get_reference_source_count(&self) -> i32 {
            0
        }

        fn has_references_to(&self, _to_addr: Address) -> bool {
            false
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

        fn delete(&mut self, _reference: Arc<dyn Reference>) {}

        fn get_reference_level(&self, _to_addr: Address) -> i8 {
            0
        }
    }

    #[test]
    fn mock_reference_manager_is_object_safe() {
        let mut manager: Box<dyn ReferenceManager> = Box::new(MockReferenceManager);

        assert_eq!(manager.get_reference_count_to(addr(0x1000)), 0);
        assert!(!manager.has_references_from(addr(0x1000)));
        assert_eq!(manager.get_reference_level(addr(0x1000)), 0);

        manager.remove_all_references_from(addr(0x1000));
        manager.remove_all_references_to(addr(0x1000));
    }

    #[test]
    fn mnemonic_matches_reference_constant() {
        assert_eq!(MNEMONIC, crate::program::model::symbol::reference::MNEMONIC);
    }
}
