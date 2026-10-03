//! Port of `ghidra.program.util.ParallelInstructionLocation`.
//!
//! The Java class is a marker subclass of
//! [`ProgramLocation`](crate::program::util::program_location::ProgramLocation) (not
//! `CodeUnitLocation`) that adds no new fields or methods: its populating constructor,
//! `ParallelInstructionLocation(program, addr, charOffset)`, forwards to `ProgramLocation`'s
//! public `(program, addr, row, col, charOffset)` constructor as
//! `super(program, addr, 0, 0, charOffset)` — `row` and `col` are always fixed to `0`; only the
//! address and `charOffset` are ever variable. Note the Java default constructor's doc comment
//! ("Get the row within a group of pcode strings") is a stale copy-paste from elsewhere in this
//! file family and doesn't describe an actual accessor on this class — the constructor itself
//! takes no arguments and returns nothing; it is reproduced here as-is (on the trait doc, not a
//! method) rather than "fixed", per this port's policy of not silently correcting upstream
//! quirks. Following the same approach as its sibling `*FieldLocation`/`*Location` cut-points, it
//! is ported here as an object-safe marker trait with no accessors of its own. Java's two
//! constructors (populating vs. XML-restore) don't map onto trait methods and are left to
//! implementors, which are expected to zero `row`/`col` as the Java constructor does.

use crate::program::util::program_location::ProgramLocation;

/// A `ProgramLocation` representing a location within a parallel instruction group.
///
/// Port of `ghidra.program.util.ParallelInstructionLocation`.
pub trait ParallelInstructionLocation: ProgramLocation {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Program;

    /// A minimal implementor proving the trait is object-safe and that it reproduces the exact
    /// field values Java's constructor always fixes: `row = 0`, `col = 0`, with only the address
    /// and `charOffset` variable.
    struct FixedParallelInstructionLocation {
        address: Address,
        char_offset: i32,
    }

    impl ProgramLocation for FixedParallelInstructionLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
        fn get_char_offset(&self) -> i32 {
            self.char_offset
        }
        // row and col keep the supertrait's zero defaults, matching
        // `super(program, addr, 0, 0, charOffset)`.
    }

    impl ParallelInstructionLocation for FixedParallelInstructionLocation {}

    #[test]
    fn trait_object_carries_address_and_char_offset_with_row_and_col_zeroed() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(ram, 0x400);

        let loc: Box<dyn ParallelInstructionLocation> =
            Box::new(FixedParallelInstructionLocation { address: addr.clone(), char_offset: 9 });

        assert_eq!(loc.get_address(), addr);
        assert_eq!(loc.get_char_offset(), 9);
        assert_eq!(loc.get_row(), 0);
        assert_eq!(loc.get_column(), 0);
    }
}
