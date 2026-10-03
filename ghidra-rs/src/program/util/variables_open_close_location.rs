//! Port of `ghidra.program.util.VariablesOpenCloseLocation`.
//!
//! The Java class is a marker subclass of
//! [`CodeUnitLocation`](crate::program::util::code_unit_location::CodeUnitLocation) representing
//! the cursor being on the variables open/close widget. It adds no new fields or methods: its
//! populating constructor, `VariablesOpenCloseLocation(program, addr)`, forwards to
//! `CodeUnitLocation`'s public `(program, addr, componentPath, row, col, charOffset)` constructor
//! as `super(program, addr, null, 0, 0, 0)` — `componentPath`, `row`, `col`, and `charOffset` are
//! all always fixed; only the address is ever variable. Following the same approach as its
//! sibling `*FieldLocation`/`*Location` cut-points
//! ([`IndentFieldLocation`](crate::program::util::indent_field_location::IndentFieldLocation)), it
//! is ported here as an object-safe marker trait with no accessors of its own: implementors (and
//! their callers) are distinguished from a plain `CodeUnitLocation` by the trait bound alone.
//! Java's two constructors (populating vs. XML-restore) don't map onto trait methods and are left
//! to implementors, which are expected to zero `componentPath`/`row`/`col`/`charOffset` as the
//! Java constructor does.

use crate::program::util::code_unit_location::CodeUnitLocation;

/// A `ProgramLocation` that represents the cursor being on the variables open/close widget.
///
/// Port of `ghidra.program.util.VariablesOpenCloseLocation`.
pub trait VariablesOpenCloseLocation: CodeUnitLocation {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Program;
    use crate::program::util::ProgramLocation;

    /// A minimal implementor proving the trait is object-safe and that it reproduces the exact
    /// field values Java's constructor always fixes: `componentPath = null`, `row = 0`,
    /// `col = 0`, `charOffset = 0`, with only the address variable.
    struct FixedVariablesOpenCloseLocation {
        address: Address,
    }

    impl ProgramLocation for FixedVariablesOpenCloseLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
        // componentPath, row, col, and charOffset all keep the supertrait's None/zero defaults,
        // matching `super(program, addr, null, 0, 0, 0)`.
    }

    impl CodeUnitLocation for FixedVariablesOpenCloseLocation {}

    impl VariablesOpenCloseLocation for FixedVariablesOpenCloseLocation {}

    #[test]
    fn trait_object_carries_only_the_address_with_everything_else_zeroed() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x400);

        let loc: Box<dyn VariablesOpenCloseLocation> =
            Box::new(FixedVariablesOpenCloseLocation { address: addr.clone() });

        assert_eq!(loc.get_address(), addr);
        assert_eq!(loc.get_component_path(), None);
        assert_eq!(loc.get_row(), 0);
        assert_eq!(loc.get_column(), 0);
        assert_eq!(loc.get_char_offset(), 0);
    }
}
