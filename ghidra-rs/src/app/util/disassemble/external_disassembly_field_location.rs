//! Port of `ghidra.app.util.disassemble.ExternalDisassemblyFieldLocation`.
//!
//! # Skipped: code-unit address snapping
//!
//! Java's `super(program, addr, row, 0, charOffset)` chains to `ProgramLocation(Program, Address,
//! int, int, int)`, which snaps `addr` to the start of whatever `CodeUnit` contains it (via the
//! private `getCodeUnitAddress`) for [`ProgramLocation::get_address`], while
//! [`ProgramLocation::get_byte_address`] keeps the original, unsnapped address. The
//! [`ProgramLocation`] trait's own docs already leave that snapping to each implementor (no
//! `Listing` dependency is threaded through the trait), and
//! [`GenericDataTypeProgramLocation`](crate::app::plugin::core::navigation::locationreferences::generic_data_type_program_location::GenericDataTypeProgramLocation)
//! established the precedent for skipping it in a leaf, non-cut-point `ProgramLocation`
//! implementor: this port follows that same precedent, so [`Self::get_address`] and
//! [`Self::get_byte_address`] both simply return the constructor's `addr` argument, unsnapped.
//!
//! # Omitted: the no-arg "for deserialization" constructor
//!
//! Java's `ExternalDisassemblyFieldLocation()` leaves every field at its Java default (`program`/
//! `addr` both `null`), existing only so XML-based state restoration (`saveState`/`restoreState`,
//! via `ProgramLocation.getLocation`) can instantiate the class reflectively before populating it.
//! [`ProgramLocation`]'s own docs already omit `saveState`/`restoreState`/`getLocation` entirely
//! (no `SaveState`/`ClassSearcher` port exists to round-trip through), and this port's
//! [`ExternalDisassemblyFieldLocation`] struct has no way to represent a "half-constructed, all
//! fields absent" state (`Arc<dyn Program>`/`Address` are both non-nullable), so the no-arg
//! constructor is not modeled here either.

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::util::program_location::ProgramLocation;

/// A program location within an externally-rendered disassembly field (see
/// `SleighDevTools`'s external disassembler support).
///
/// Port of `ghidra.app.util.disassemble.ExternalDisassemblyFieldLocation`.
pub struct ExternalDisassemblyFieldLocation {
    program: Arc<dyn Program>,
    addr: Address,
    row: i32,
    char_offset: i32,
}

impl ExternalDisassemblyFieldLocation {
    /// Constructs a location at `addr`, on the given `row` within a group of pcode strings, at
    /// `char_offset` within that row.
    ///
    /// Port of `ExternalDisassemblyFieldLocation(Program, Address, int, int)`. Java hard-codes
    /// the inherited `col` field to `0` (not exposed as a constructor parameter); this port
    /// preserves that by simply relying on [`ProgramLocation::get_column`]'s default (`0`)
    /// rather than storing a column at all.
    pub fn new(program: Arc<dyn Program>, addr: Address, row: i32, char_offset: i32) -> Self {
        ExternalDisassemblyFieldLocation { program, addr, row, char_offset }
    }
}

impl ProgramLocation for ExternalDisassemblyFieldLocation {
    fn get_program(&self) -> Arc<dyn Program> {
        self.program.clone()
    }

    /// See the module docs for why this is unsnapped (equal to [`Self::get_byte_address`]) rather
    /// than adjusted to a containing code unit's minimum address.
    fn get_address(&self) -> Address {
        self.addr.clone()
    }

    fn get_byte_address(&self) -> Address {
        self.addr.clone()
    }

    fn get_row(&self) -> i32 {
        self.row
    }

    fn get_char_offset(&self) -> i32 {
        self.char_offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    struct MockProgram;
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    fn program() -> Arc<dyn Program> {
        Arc::new(MockProgram)
    }

    #[test]
    fn accessors_round_trip_constructor_arguments() {
        let loc = ExternalDisassemblyFieldLocation::new(program(), addr(0x1000), 3, 7);
        assert_eq!(loc.get_address(), addr(0x1000));
        assert_eq!(loc.get_row(), 3);
        assert_eq!(loc.get_char_offset(), 7);
    }

    #[test]
    fn column_is_always_zero() {
        // Faithful quirk: the Java constructor hard-codes `col` to 0; it is never a caller-
        // supplied value.
        let loc = ExternalDisassemblyFieldLocation::new(program(), addr(0x2000), 1, 1);
        assert_eq!(loc.get_column(), 0);
    }

    #[test]
    fn address_and_byte_address_are_both_the_unsnapped_constructor_address() {
        let loc = ExternalDisassemblyFieldLocation::new(program(), addr(0x3000), 0, 0);
        assert_eq!(loc.get_address(), loc.get_byte_address());
        assert_eq!(loc.get_address(), addr(0x3000));
    }

    #[test]
    fn ref_address_and_component_path_default_to_none() {
        let loc = ExternalDisassemblyFieldLocation::new(program(), addr(0x4000), 0, 0);
        assert_eq!(loc.get_ref_address(), None);
        assert_eq!(loc.get_component_path(), None);
    }

    #[test]
    fn object_safe_as_boxed_trait() {
        let loc: Box<dyn ProgramLocation> =
            Box::new(ExternalDisassemblyFieldLocation::new(program(), addr(0x5000), 2, 4));
        assert_eq!(loc.get_row(), 2);
        assert_eq!(loc.get_char_offset(), 4);
        assert_eq!(loc.get_column(), 0);
    }
}
