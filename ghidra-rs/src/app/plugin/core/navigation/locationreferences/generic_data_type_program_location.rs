//! A [`ProgramLocation`] that signals "this is a data type, not a real place in the listing."
//!
//! Java source: `ghidra.app.plugin.core.navigation.locationreferences.GenericDataTypeProgramLocation`,
//! a package-private `class GenericDataTypeProgramLocation extends ProgramLocation`.
//!
//! # Graduating the seam stub
//!
//! [`crate::app::seam_stubs::GenericDataTypeProgramLocation`] was a placeholder trait explicitly
//! documented as standing in "before the real class is ported." This is that real class; the
//! placeholder trait is now removed, and
//! [`GenericDataTypeLocationDescriptorBase`](crate::app::plugin::core::navigation::locationreferences::generic_data_type_location_descriptor::GenericDataTypeLocationDescriptorBase)
//! (the placeholder's only consumer) holds this concrete struct directly instead of a `dyn`
//! placeholder, matching how Java's constructor already narrows the `location` parameter's
//! *effective* type to exactly this class (see that module's own docs on the `AssertException`
//! check it replaced with a static type).
//!
//! # Fields
//!
//! `dataType` is stored as `Arc<dyn DataType>` rather than `Box<dyn DataType>`, following
//! [`DataDB`](crate::program::database::code::data_db)'s established pattern for "store a trait
//! object once, hand back an owned `Box<dyn DataType>` sharing it on every call" (Java's
//! `getDataType()` returns the *same* field reference every time, and `Box<dyn DataType>` has no
//! generic `Clone`): [`Self::get_data_type`] uses the same
//! [`share_data_type`](crate::program::seam_stubs::share_data_type) helper `DataDB` does.
//!
//! # Address, simplified
//!
//! Java's `ProgramLocation(Program, Address)` constructor snaps `addr` to the start of whatever
//! `CodeUnit` contains it (via the private `getCodeUnitAddress`), while `byteAddr` keeps the
//! unsnapped address. This class's own javadoc says it "is not really connected to the listing,"
//! and the [`ProgramLocation`] trait's own docs already leave `getCodeUnitAddress`'s snapping to
//! each implementor (no `Listing` dependency is threaded through this trait), so this port skips
//! it: both [`Self::get_address`] and [`Self::get_byte_address`] simply return
//! `program.get_min_address()`, unsnapped -- consistent with [`MockLocation`] in this package's
//! sibling test module, which does the same for its own dummy address.
use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::Program;
use crate::program::seam_stubs::share_data_type;
use crate::program::util::program_location::ProgramLocation;

/// A [`ProgramLocation`] used to signal that it describes a data type and is not really
/// connected to the listing.
///
/// Port of `ghidra.app.plugin.core.navigation.locationreferences.GenericDataTypeProgramLocation`.
pub struct GenericDataTypeProgramLocation {
    program: Arc<dyn Program>,
    address: crate::program::model::address::Address,
    data_type: Arc<dyn DataType>,
}

impl GenericDataTypeProgramLocation {
    /// Constructs a location anchored at `program`'s minimum address, carrying `data_type`.
    ///
    /// Port of `GenericDataTypeProgramLocation(Program, DataType)`.
    ///
    /// # Panics
    /// Panics if `program` has no minimum address (i.e. no memory), since Java's
    /// `program.getMinAddress()` can return `null` there but this port's
    /// [`ProgramLocation::get_address`] cannot represent a null address. See the module docs.
    pub fn new(program: Arc<dyn Program>, data_type: Arc<dyn DataType>) -> Self {
        let address = program
            .get_min_address()
            .expect("GenericDataTypeProgramLocation requires a program with a minimum address");
        Self { program, address, data_type }
    }

    /// The data type this location describes.
    ///
    /// Port of `getDataType()`. Returns a fresh `Box` sharing the same underlying value on every
    /// call (see the module docs).
    pub fn get_data_type(&self) -> Box<dyn DataType> {
        share_data_type(&self.data_type)
    }
}

impl ProgramLocation for GenericDataTypeProgramLocation {
    fn get_program(&self) -> Arc<dyn Program> {
        self.program.clone()
    }

    fn get_address(&self) -> crate::program::model::address::Address {
        self.address.clone()
    }

    fn get_byte_address(&self) -> crate::program::model::address::Address {
        self.address.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    struct MockDataType {
        name: String,
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.name == dt.get_name()
        }
    }

    fn test_address() -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, 0x400000)
    }

    struct MockProgram;
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_min_address(&self) -> Option<Address> {
            Some(test_address())
        }
    }

    struct NoMemoryProgram;
    impl DomainObject for NoMemoryProgram {}
    impl Program for NoMemoryProgram {
        fn get_name(&self) -> String {
            "empty".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        // get_min_address left at its default: None.
    }

    fn location(type_name: &str) -> GenericDataTypeProgramLocation {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let data_type: Arc<dyn DataType> = Arc::new(MockDataType { name: type_name.to_string() });
        GenericDataTypeProgramLocation::new(program, data_type)
    }

    #[test]
    fn address_and_byte_address_are_the_programs_minimum_address() {
        let loc = location("Foo");
        assert_eq!(loc.get_address(), test_address());
        assert_eq!(loc.get_byte_address(), test_address());
    }

    #[test]
    fn get_data_type_returns_the_data_type_passed_at_construction() {
        let loc = location("Bar");
        assert_eq!(loc.get_data_type().get_name(), "Bar");
    }

    #[test]
    fn get_data_type_can_be_called_repeatedly() {
        let loc = location("Baz");
        assert_eq!(loc.get_data_type().get_name(), "Baz");
        assert_eq!(loc.get_data_type().get_name(), "Baz");
    }

    #[test]
    fn get_program_returns_the_same_program() {
        let loc = location("Foo");
        assert_eq!(Program::get_name(&*loc.get_program()), "mock");
    }

    #[test]
    fn get_ref_address_defaults_to_none() {
        let loc = location("Foo");
        assert_eq!(loc.get_ref_address(), None);
    }

    #[test]
    #[should_panic(expected = "requires a program with a minimum address")]
    fn new_panics_when_program_has_no_memory() {
        let program: Arc<dyn Program> = Arc::new(NoMemoryProgram);
        let data_type: Arc<dyn DataType> = Arc::new(MockDataType { name: "Foo".to_string() });
        GenericDataTypeProgramLocation::new(program, data_type);
    }
}
