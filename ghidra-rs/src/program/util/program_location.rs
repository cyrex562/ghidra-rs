//! Port of `ghidra.program.util.ProgramLocation`.
//!
//! `ProgramLocation` provides information about a location in a program in the most generic way:
//! an address, the "byte" address the field was derived from (which may differ from `addr` when
//! the location has been snapped back to the start of a containing [`CodeUnit`], see
//! [`CodeUnit`](crate::program::model::listing::CodeUnit)), an optional "referred to" address, an
//! optional nested-[`Data`](crate::program::model::listing::Data)-component path, and a
//! row/column/character-offset cursor position within whatever field the (unported) subclass
//! represents.
//!
//! It was selected as a dependency-cycle cut-point, so it is ported here as an object-safe trait
//! rather than a concrete struct: implementors provide whatever `Program`/`Address` state the Java
//! constructors captured (including the code-unit-alignment behavior of the address-only Java
//! constructors, via the private `getCodeUnitAddress` helper), and expose it through the trait's
//! accessor methods.
//! [`ProgramLocation::is_valid`] is the one piece of real getter-derived behavior Java implements
//! directly on the base class (rather than in a field-location subclass), so it is ported as a
//! default method built on the other accessors.
//!
//! Several members of the Java class are intentionally omitted, since none map cleanly onto an
//! object-safe trait and no current caller needs them:
//! - The seven `ProgramLocation(...)` constructors (including the `getCodeUnitAddress` helper they
//!   share) don't map onto trait methods; implementors are expected to replicate the relevant
//!   constructor's behavior themselves.
//! - `saveState`/`restoreState` and the static `getLocation` factory round-trip a location through
//!   [`SaveState`](crate::framework::seam_stubs::SaveState) plus a `_CLASSNAME` string that
//!   `getLocation` resolves back to a concrete subclass via `ClassSearcher` reflection, and
//!   `restoreState` in turn resolves stored address strings via `ProgramUtilities.parseAddress`'s
//!   external/stack-address fallback logic. Neither `ClassSearcher`
//!   (`ghidra.util.classfinder.ClassSearcher`) nor `ProgramUtilities`
//!   (`ghidra.program.util.ProgramUtilities`) is ported yet (both TODO in `PORT_MANIFEST.tsv`), and
//!   reflection-based dynamic class lookup has no clean Rust equivalent regardless, so these are
//!   left to implementors.
//! - `compareTo` delegates to `ProgramLocationComparator`, an unported (TODO) helper that orders
//!   locations by fragment membership and code-unit iteration, not just by field access on this
//!   type; `equals`/`hashCode`/`toString` are Java `Object`-identity boilerplate that implementors
//!   can derive/implement directly on their concrete type instead of through this trait.
//! - `clone`/`getTranslatedCopy` need `Object.clone()` of an unknown concrete subtype, which has no
//!   trait-object equivalent; implementors that need a translated copy can build one from this
//!   trait's accessors plus their own state.

use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::listing::Program;

/// `ProgramLocation` provides information about a location in a program in the most generic way.
///
/// Port of `ghidra.program.util.ProgramLocation`.
pub trait ProgramLocation {
    /// Returns the program associated with this location.
    ///
    /// Port of `ProgramLocation.getProgram()`.
    fn get_program(&self) -> Arc<dyn Program>;

    /// Returns the address associated with this location.
    ///
    /// Note: this may not be the same as the byte address. For example, in a code unit location
    /// this may be the minimum address of the code unit that contains the byte address.
    ///
    /// Port of `ProgramLocation.getAddress()`.
    fn get_address(&self) -> Address;

    /// Returns the byte level address associated with this location.
    ///
    /// Port of `ProgramLocation.getByteAddress()`.
    fn get_byte_address(&self) -> Address;

    /// Returns the "referred to" address if the location is over a reference in some field.
    ///
    /// Port of `ProgramLocation.getRefAddress()`.
    fn get_ref_address(&self) -> Option<Address> {
        None
    }

    /// Returns the component path for the code unit. `None` for an `Instruction` or a top-level
    /// `Data` object.
    ///
    /// Port of `ProgramLocation.getComponentPath()`.
    fn get_component_path(&self) -> Option<&[i32]> {
        None
    }

    /// Returns the row within the program location.
    ///
    /// Port of `ProgramLocation.getRow()`.
    fn get_row(&self) -> i32 {
        0
    }

    /// Returns the column index of the display piece represented by this location. For most
    /// locations, there is only one display item per row, in which case this value is 0.
    ///
    /// Port of `ProgramLocation.getColumn()`.
    fn get_column(&self) -> i32 {
        0
    }

    /// Returns the character offset in the display item at the (row, col).
    ///
    /// Port of `ProgramLocation.getCharOffset()`.
    fn get_char_offset(&self) -> i32 {
        0
    }

    /// Returns true if this location represents a valid location in the given program.
    ///
    /// Port of `ProgramLocation.isValid(Program)`.
    fn is_valid(&self, test_program: &dyn Program) -> bool {
        match test_program.get_address_factory() {
            Some(factory) => factory.is_valid_address(&self.get_address()),
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{
        AddressFactory, AddressSpace, AddressSpaceType, DefaultAddressFactory,
    };

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

    /// A minimal implementor proving the trait is object-safe and that its accessors round-trip
    /// the state they were built with.
    struct FixedLocation {
        address: Address,
        byte_address: Address,
        ref_address: Option<Address>,
        component_path: Vec<i32>,
        row: i32,
        column: i32,
        char_offset: i32,
    }

    impl ProgramLocation for FixedLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.byte_address.clone()
        }
        fn get_ref_address(&self) -> Option<Address> {
            self.ref_address.clone()
        }
        fn get_component_path(&self) -> Option<&[i32]> {
            Some(&self.component_path)
        }
        fn get_row(&self) -> i32 {
            self.row
        }
        fn get_column(&self) -> i32 {
            self.column
        }
        fn get_char_offset(&self) -> i32 {
            self.char_offset
        }
    }

    #[test]
    fn accessors_round_trip_through_a_boxed_trait_object() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let byte_addr = Address::new(ram.clone(), 0x1010);
        let code_unit_addr = Address::new(ram.clone(), 0x1000);
        let ref_addr = Address::new(ram, 0x2000);

        let loc: Box<dyn ProgramLocation> = Box::new(FixedLocation {
            address: code_unit_addr.clone(),
            byte_address: byte_addr.clone(),
            ref_address: Some(ref_addr.clone()),
            component_path: vec![1, 2],
            row: 3,
            column: 1,
            char_offset: 5,
        });

        assert_eq!(loc.get_address(), code_unit_addr);
        assert_eq!(loc.get_byte_address(), byte_addr);
        assert_ne!(loc.get_address(), loc.get_byte_address());
        assert_eq!(loc.get_ref_address(), Some(ref_addr));
        assert_eq!(loc.get_component_path(), Some(&[1, 2][..]));
        assert_eq!(loc.get_row(), 3);
        assert_eq!(loc.get_column(), 1);
        assert_eq!(loc.get_char_offset(), 5);
    }

    #[test]
    fn is_valid_checks_the_address_against_the_program_s_address_factory() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let other = AddressSpace::new("other", 32, 1, AddressSpaceType::Ram, 1);
        let in_program = Address::new(ram.clone(), 0x400);
        let not_in_program = Address::new(other, 0x400);

        let program = MockProgram {
            factory: Arc::new(DefaultAddressFactory::new(vec![ram])) as Arc<dyn AddressFactory>,
        };

        let valid_loc: Box<dyn ProgramLocation> = Box::new(FixedLocation {
            address: in_program.clone(),
            byte_address: in_program,
            ref_address: None,
            component_path: Vec::new(),
            row: 0,
            column: 0,
            char_offset: 0,
        });
        assert!(valid_loc.is_valid(&program));

        let invalid_loc: Box<dyn ProgramLocation> = Box::new(FixedLocation {
            address: not_in_program.clone(),
            byte_address: not_in_program,
            ref_address: None,
            component_path: Vec::new(),
            row: 0,
            column: 0,
            char_offset: 0,
        });
        assert!(!invalid_loc.is_valid(&program));
    }
}
