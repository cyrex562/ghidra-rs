//! Port of `ghidra.program.util.XRefFieldLocation`.
//!
//! The Java class is a thin data holder that extends
//! [`CodeUnitLocation`](crate::program::util::code_unit_location::CodeUnitLocation) (itself a
//! subclass of `ProgramLocation`) and adds no new fields of its own: it is built through
//! `CodeUnitLocation`'s protected `(program, addr, componentPath, refAddr, row, col, charOffset)`
//! constructor, passing `row = 0` and reusing the inherited `col` slot to carry the XREF index
//! and the inherited `refAddr` slot (already exposed by
//! [`ProgramLocation::get_ref_address`](crate::program::util::ProgramLocation::get_ref_address))
//! to carry the reference address. It was selected as a dependency-cycle cut-point, so it is
//! ported here as an object-safe trait rather than a concrete struct, following the same approach
//! as its sibling `*FieldLocation` traits
//! ([`AddressFieldLocation`](crate::program::util::address_field_location::AddressFieldLocation),
//! [`OffsetFieldLocation`](crate::program::util::offset_field_location::OffsetFieldLocation)):
//! implementors provide whatever `Program`/`Address`/component-path/ref-address/column state the
//! Java constructor captured, and expose it through the supertrait's accessors. Java's two
//! constructors (populating vs. XML-restore) don't map onto trait methods and are left to
//! implementors.
//!
//! `toString` is Java `Object`-identity boilerplate that implementors can derive/implement
//! directly on their concrete type instead of through this trait, for the same reason
//! [`ProgramLocation`](crate::program::util::ProgramLocation)'s isn't ported either.

use crate::program::util::code_unit_location::CodeUnitLocation;

/// Provides specific information about a program location within the XREF field of a
/// `CodeUnitLocation` object.
///
/// Port of `ghidra.program.util.XRefFieldLocation`.
pub trait XRefFieldLocation: CodeUnitLocation {
    /// Returns the index of the XREF in the list of all XREFs at this address.
    ///
    /// Port of `XRefFieldLocation.getIndex()`, which delegates to the inherited `getColumn()`:
    /// the Java constructor stores the XREF index in `CodeUnitLocation`'s `col` slot (via
    /// `super(program, addr, componentPath, refAddr, 0, index, charOffset)`), so this default
    /// simply forwards to [`ProgramLocation::get_column`](crate::program::util::ProgramLocation::get_column)
    /// rather than needing its own field.
    fn get_index(&self) -> i32 {
        self.get_column()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Program;
    use crate::program::util::ProgramLocation;

    /// A minimal implementor proving the trait is object-safe and that `get_index` correctly
    /// forwards to `get_column` (the real Java behavior), exercising both a non-zero index and
    /// the default (zero) case through a `dyn XRefFieldLocation`.
    struct FixedXRefFieldLocation {
        address: Address,
        ref_address: Option<Address>,
        column: i32,
    }

    impl ProgramLocation for FixedXRefFieldLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
        fn get_ref_address(&self) -> Option<Address> {
            self.ref_address.clone()
        }
        fn get_column(&self) -> i32 {
            self.column
        }
    }

    impl CodeUnitLocation for FixedXRefFieldLocation {}

    impl XRefFieldLocation for FixedXRefFieldLocation {}

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    #[test]
    fn get_index_forwards_to_get_column() {
        let loc: Box<dyn XRefFieldLocation> = Box::new(FixedXRefFieldLocation {
            address: ram_address(0x400),
            ref_address: Some(ram_address(0x800)),
            column: 3,
        });

        assert_eq!(loc.get_index(), 3);
        assert_eq!(loc.get_column(), loc.get_index());
    }

    #[test]
    fn default_index_is_zero_when_column_is_unset() {
        let loc: Box<dyn XRefFieldLocation> = Box::new(FixedXRefFieldLocation {
            address: ram_address(0x400),
            ref_address: None,
            column: 0,
        });

        assert_eq!(loc.get_index(), 0);
    }

    #[test]
    fn ref_address_round_trips_through_the_program_location_supertrait() {
        let ref_addr = ram_address(0x900);
        let loc: Box<dyn XRefFieldLocation> = Box::new(FixedXRefFieldLocation {
            address: ram_address(0x400),
            ref_address: Some(ref_addr.clone()),
            column: 1,
        });

        assert_eq!(loc.get_ref_address(), Some(ref_addr));
    }
}
