//! Port of `ghidra.program.util.AssignedVariableLocation`.
//!
//! The Java class is a marker subclass of
//! [`ProgramLocation`](crate::program::util::program_location::ProgramLocation) (not
//! `CodeUnitLocation`) that adds no new fields or methods: its populating constructor,
//! `AssignedVariableLocation(program, addr, row, charOffset)`, forwards to `ProgramLocation`'s
//! public `(program, addr, row, col, charOffset)` constructor as
//! `super(program, addr, row, 0, charOffset)` — `col` is always fixed to `0`; the address, `row`,
//! and `charOffset` are all variable. Note the Java default constructor's doc comment ("Get the
//! row within a group of pcode strings") is a stale copy-paste — the same one that also appears
//! verbatim on
//! [`ParallelInstructionLocation`](crate::program::util::parallel_instruction_location::ParallelInstructionLocation)'s
//! default constructor in the real source — and doesn't describe an actual accessor on this class;
//! it is reproduced here as-is (on the trait doc, not a method) rather than "fixed", per this
//! port's policy of not silently correcting upstream quirks. Following the same approach as its
//! sibling `*FieldLocation`/`*Location` cut-points, it is ported here as an object-safe marker
//! trait with no accessors of its own. Java's two constructors (populating vs. XML-restore) don't
//! map onto trait methods and are left to implementors, which are expected to zero `col` as the
//! Java constructor does.

use crate::program::util::program_location::ProgramLocation;

/// A `ProgramLocation` representing a variable assignment within a group of pcode strings.
///
/// Port of `ghidra.program.util.AssignedVariableLocation`.
pub trait AssignedVariableLocation: ProgramLocation {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Program;

    /// A minimal implementor proving the trait is object-safe and that it reproduces the exact
    /// field values Java's constructor always fixes: `col = 0`, with the address, `row`, and
    /// `charOffset` all variable.
    struct FixedAssignedVariableLocation {
        address: Address,
        row: i32,
        char_offset: i32,
    }

    impl ProgramLocation for FixedAssignedVariableLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
        fn get_row(&self) -> i32 {
            self.row
        }
        fn get_char_offset(&self) -> i32 {
            self.char_offset
        }
        // col keeps the supertrait's zero default, matching
        // `super(program, addr, row, 0, charOffset)`.
    }

    impl AssignedVariableLocation for FixedAssignedVariableLocation {}

    #[test]
    fn trait_object_carries_address_row_and_char_offset_with_col_zeroed() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x400);

        let loc: Box<dyn AssignedVariableLocation> = Box::new(FixedAssignedVariableLocation {
            address: addr.clone(),
            row: 1,
            char_offset: 3,
        });

        assert_eq!(loc.get_address(), addr);
        assert_eq!(loc.get_row(), 1);
        assert_eq!(loc.get_char_offset(), 3);
        assert_eq!(loc.get_column(), 0);
    }
}
