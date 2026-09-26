//! Port of `ghidra.program.util.IndentFieldLocation`.
//!
//! The Java class is a marker subclass of
//! [`CodeUnitLocation`](crate::program::util::code_unit_location::CodeUnitLocation) that adds no
//! new fields or methods of its own: its populating constructor,
//! `IndentFieldLocation(program, addr, componentPath)`, forwards to `CodeUnitLocation`'s protected
//! `(program, addr, componentPath, refAddr, row, col, charOffset)` constructor as
//! `super(program, addr, componentPath, null, 0, 0, 0)` — i.e. `refAddr`, `row`, `col`, and
//! `charOffset` are all always fixed to their zero/`null` default, and only `componentPath` is
//! ever variable. In Java the class exists purely so callers can `instanceof`-check "the cursor is
//! on the indent field" without any accompanying state. Following the same approach as its sibling
//! `*FieldLocation`/`*Location` cut-points
//! ([`AddressFieldLocation`](crate::program::util::address_field_location::AddressFieldLocation),
//! [`XRefFieldLocation`](crate::program::util::xref_field_location::XRefFieldLocation)), it is
//! ported here as an object-safe trait rather than a concrete struct — but since Java adds no new
//! accessors, the trait itself adds none either; it exists solely as a marker so implementors
//! (and their callers) can be distinguished from a plain `CodeUnitLocation`. Java's two
//! constructors (populating vs. XML-restore) don't map onto trait methods and are left to
//! implementors, which are expected to zero `refAddr`/`row`/`col`/`charOffset` as the Java
//! constructor does.

use crate::program::util::code_unit_location::CodeUnitLocation;

/// Provides specific information about a program location within the indent field of a
/// `CodeUnitLocation` object.
///
/// Port of `ghidra.program.util.IndentFieldLocation`.
pub trait IndentFieldLocation: CodeUnitLocation {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Program;
    use crate::program::util::ProgramLocation;

    /// A minimal implementor proving the trait is object-safe and that it reproduces the exact
    /// field values Java's constructor always fixes: `refAddr = null`, `row = 0`, `col = 0`,
    /// `charOffset = 0`, with only `componentPath` (and the address) variable.
    struct FixedIndentFieldLocation {
        address: Address,
        component_path: Vec<i32>,
    }

    impl ProgramLocation for FixedIndentFieldLocation {
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
        // refAddr, row, col, and charOffset all keep the supertrait's zero/None defaults,
        // matching `super(program, addr, componentPath, null, 0, 0, 0)`.
    }

    impl CodeUnitLocation for FixedIndentFieldLocation {}

    impl IndentFieldLocation for FixedIndentFieldLocation {}

    #[test]
    fn trait_object_carries_the_component_path_with_everything_else_zeroed() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x400);

        let loc: Box<dyn IndentFieldLocation> = Box::new(FixedIndentFieldLocation {
            address: addr.clone(),
            component_path: vec![2, 0],
        });

        assert_eq!(loc.get_address(), addr);
        assert_eq!(loc.get_component_path(), Some(&[2, 0][..]));
        assert_eq!(loc.get_ref_address(), None);
        assert_eq!(loc.get_row(), 0);
        assert_eq!(loc.get_column(), 0);
        assert_eq!(loc.get_char_offset(), 0);
    }
}
