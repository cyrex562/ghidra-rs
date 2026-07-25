//! Port of `ghidra.program.util.CodeUnitLocation`.
//!
//! `CodeUnitLocation` provides information about a location in a program within a `CodeUnit`. It
//! extends [`ProgramLocation`] and adds exactly one piece of real behavior: an `isValid`
//! override that additionally requires a code unit to exist at the location's address (Java's
//! constructors otherwise just snap the incoming address to the start of the code unit that
//! contains it, which is state, not behavior).
//!
//! It was selected as a dependency-cycle cut-point, so it is ported here as an object-safe trait
//! rather than a concrete struct, following the same approach as [`ProgramLocation`]:
//! implementors provide whatever `Program`/`Address` state the Java constructors captured
//! (including the code-unit-alignment behavior of the address-only Java constructors), and expose
//! it through the supertrait's accessor methods.
//!
//! The four Java constructors (populating vs. XML-restore, plus the `protected` byte-address and
//! ref-address variants) don't map onto trait methods, for the same reason [`ProgramLocation`]'s
//! don't: implementors are expected to replicate the relevant constructor's behavior themselves.
//!
//! The `isValid` override needs `Program.getListing()`, but the Rust port of
//! [`Program::get_listing`](crate::program::model::listing::Program::get_listing) takes
//! `&mut self`, while [`ProgramLocation::is_valid`] takes a shared `&dyn Program`. Rather than
//! force a mutability change onto `ProgramLocation`'s existing signature (which every other
//! implementor already relies on), the override is exposed here as a distinct method,
//! [`CodeUnitLocation::is_valid_for_code_unit`], that takes the
//! [`Listing`](crate::program::model::listing::Listing) handle directly: callers that already
//! hold a `&mut dyn Program` obtain the listing via `Program::get_listing()` and pass it along.

use crate::program::model::listing::{Listing, Program};
use crate::program::util::ProgramLocation;

/// `CodeUnitLocation` provides information about the location in a program within a `CodeUnit`.
///
/// Port of `ghidra.program.util.CodeUnitLocation`.
pub trait CodeUnitLocation: ProgramLocation {
    /// Returns true if this location represents a valid location in the given program, i.e. the
    /// program's address factory recognizes the address (see [`ProgramLocation::is_valid`]) and a
    /// code unit exists at that address in `listing`.
    ///
    /// Port of `CodeUnitLocation.isValid(Program)`.
    fn is_valid_for_code_unit(&self, program: &dyn Program, listing: &dyn Listing) -> bool {
        self.is_valid(program) && listing.get_code_unit_containing(&self.get_address()).is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{
        Address, AddressFactory, AddressSpace, AddressSpaceType, DefaultAddressFactory,
    };
    use crate::program::model::lang::Register;
    use crate::program::model::listing::{CodeUnit, StubListing};
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType, Reference, ReferenceIterator, SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{CommentType, MemBuffer};

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    /// A `CodeUnit` stand-in whose presence (not its contents) is all this test needs: only
    /// `Option::is_some()` is ever called on the `Arc<dyn CodeUnit>` that wraps it.
    struct UnusedCodeUnit;

    impl MemBuffer for UnusedCodeUnit {
        fn get_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }
    }

    impl PropertySet for UnusedCodeUnit {}

    impl CodeUnit for UnusedCodeUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_label(&self) -> Option<String> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_min_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_max_address(&self) -> Address {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_mnemonic_string(&self) -> String {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_length(&self) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            unimplemented!("not exercised by this smoke test")
        }
        fn contains(&self, _test_addr: &Address) -> bool {
            unimplemented!("not exercised by this smoke test")
        }
        fn compare_to(&self, _addr: &Address) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
            unimplemented!("not exercised by this smoke test")
        }
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
            unimplemented!("not exercised by this smoke test")
        }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn remove_external_reference(&mut self, _op_index: i32) {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &Register,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_num_operands(&self) -> i32 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// Minimal [`StubListing`] whose `get_code_unit_containing` is toggled on construction; every
    /// other query panics if reached (it shouldn't be, for this test).
    struct MockListing {
        has_code_unit: bool,
    }

    impl StubListing for MockListing {
        fn get_code_unit_containing(&self, _addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            self.has_code_unit.then(|| Arc::new(UnusedCodeUnit) as Arc<dyn CodeUnit>)
        }
    }

    struct MockProgram {
        factory: Arc<dyn AddressFactory>,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            Some(self.factory.clone())
        }
    }

    /// A minimal implementor proving the trait is object-safe.
    struct FixedCodeUnitLocation {
        address: Address,
    }

    impl ProgramLocation for FixedCodeUnitLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
    }

    impl CodeUnitLocation for FixedCodeUnitLocation {}

    #[test]
    fn is_valid_for_code_unit_requires_both_a_valid_address_and_a_code_unit_there() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let other = AddressSpace::new("other", 32, 1, AddressSpaceType::Ram, 1);
        let program = MockProgram {
            factory: Arc::new(DefaultAddressFactory::new(vec![ram])) as Arc<dyn AddressFactory>,
        };

        let loc: Box<dyn CodeUnitLocation> =
            Box::new(FixedCodeUnitLocation { address: ram_address(0x400) });

        let listing_with_code_unit = MockListing { has_code_unit: true };
        assert!(loc.is_valid_for_code_unit(&program, &listing_with_code_unit));

        let listing_without_code_unit = MockListing { has_code_unit: false };
        assert!(!loc.is_valid_for_code_unit(&program, &listing_without_code_unit));

        let loc_outside_program: Box<dyn CodeUnitLocation> =
            Box::new(FixedCodeUnitLocation { address: Address::new(other, 0x400) });
        assert!(!loc_outside_program.is_valid_for_code_unit(&program, &listing_with_code_unit));
    }
}
