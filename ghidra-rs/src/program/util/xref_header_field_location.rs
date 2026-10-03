//! Port of `ghidra.program.util.XRefHeaderFieldLocation`.
//!
//! The Java class represents a location within the XREF field header that precedes the XREF
//! field locations. It is a marker subclass of
//! [`XRefFieldLocation`](crate::program::util::xref_field_location::XRefFieldLocation) that adds
//! no new fields or methods: its populating constructor,
//! `XRefHeaderFieldLocation(program, addr, componentPath, charOffset)`, forwards to
//! `XRefFieldLocation`'s public `(program, addr, componentPath, refAddr, index, charOffset)`
//! constructor as `super(program, addr, componentPath, null, 0, charOffset)` — `refAddr` and
//! `index` are always fixed to `null`/`0` (so [`XRefFieldLocation::get_index`] is always `0` for a
//! header location); the address, `componentPath`, and `charOffset` are variable. Following the
//! same approach as its sibling `*FieldLocation`/`*Location` cut-points, it is ported here as an
//! object-safe marker trait with no accessors of its own. Java's two constructors (populating vs.
//! XML-restore) don't map onto trait methods and are left to implementors, which are expected to
//! fix `refAddr`/`index` as the Java constructor does.

use crate::program::util::xref_field_location::XRefFieldLocation;

/// Contains specific location information within the XREF field header that precedes the XREF
/// field locations.
///
/// Port of `ghidra.program.util.XRefHeaderFieldLocation`.
pub trait XRefHeaderFieldLocation: XRefFieldLocation {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Program;
    use crate::program::util::code_unit_location::CodeUnitLocation;
    use crate::program::util::ProgramLocation;

    /// A minimal implementor proving the trait is object-safe and that it reproduces the exact
    /// field values Java's constructor always fixes: `refAddr = null` (so `get_ref_address()` is
    /// always `None`) and `index = 0` (so `get_index()`, which forwards to `get_column()`, is
    /// always `0`), with the address, `componentPath`, and `charOffset` variable.
    struct FixedXRefHeaderFieldLocation {
        address: Address,
        component_path: Vec<i32>,
        char_offset: i32,
    }

    impl ProgramLocation for FixedXRefHeaderFieldLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
        fn get_component_path(&self) -> Option<&[i32]> {
            Some(&self.component_path)
        }
        fn get_char_offset(&self) -> i32 {
            self.char_offset
        }
        // refAddr and column (index) keep the supertrait's None/zero defaults, matching
        // `super(program, addr, componentPath, null, 0, charOffset)`.
    }

    impl CodeUnitLocation for FixedXRefHeaderFieldLocation {}

    impl XRefFieldLocation for FixedXRefHeaderFieldLocation {}

    impl XRefHeaderFieldLocation for FixedXRefHeaderFieldLocation {}

    #[test]
    fn trait_object_always_has_no_ref_address_and_a_zero_index() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x400);

        let loc: Box<dyn XRefHeaderFieldLocation> = Box::new(FixedXRefHeaderFieldLocation {
            address: addr.clone(),
            component_path: vec![1],
            char_offset: 5,
        });

        assert_eq!(loc.get_address(), addr);
        assert_eq!(loc.get_component_path(), Some(&[1][..]));
        assert_eq!(loc.get_char_offset(), 5);
        assert_eq!(loc.get_ref_address(), None);
        assert_eq!(loc.get_index(), 0);
        assert_eq!(loc.get_column(), 0);
    }
}
