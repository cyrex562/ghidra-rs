use std::sync::Arc;

use crate::app::seam_stubs::{DataTypeLocationDescriptor, GenericDataTypeProgramLocation, ReferenceUtils};
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::Program;
use crate::program::util::program_location::ProgramLocation;

/// A location descriptor that is used when the user wants to create a descriptor that describes a
/// data type, but not a real location that contains a data type. Most location descriptors
/// describe an exact point in the listing display; this one is designed to describe a data type
/// without pointing to any real position in the display.
///
/// Port of `ghidra.app.plugin.core.navigation.locationreferences.GenericDataTypeLocationDescriptor`.
///
/// Java's class is directly instantiable *and* extended by
/// `GenericCompositeDataTypeLocationDescriptor` and `FunctionDefinitionLocationDescriptor` (both
/// still TODO), so the shared state lives here in [`GenericDataTypeLocationDescriptorBase`] while
/// [`GenericDataTypeLocationDescriptor`] declares only the two methods those subclasses go on to
/// override (`generateLabel` and `equals`); every other overridden method
/// (`getDataType`/`getHomeLocation`/`getDataTypeName`/`getSourceDataType`/`getBaseDataType`) is
/// never overridden further, so it lives directly on the base struct.
///
/// The Java constructor takes a generic `ProgramLocation` and throws `AssertException` if it is
/// not a `GenericDataTypeProgramLocation`. Since every real call site already constructs (or is
/// handed) a `GenericDataTypeProgramLocation` before calling this constructor, that runtime check
/// is encoded here as the static type of the `location` parameter instead -- it cannot fail.
pub struct GenericDataTypeLocationDescriptorBase {
    location: Arc<dyn GenericDataTypeProgramLocation>,
    program: Arc<dyn Program>,
    /// The data type passed in at construction time (Java: `originalDataType`).
    original_data_type: Box<dyn DataType>,
    /// The data type used to find references; may be the same as `original_data_type` (Java:
    /// `baseDataType`).
    base_data_type: Box<dyn DataType>,
    label: String,
}

impl GenericDataTypeLocationDescriptorBase {
    pub fn new(
        location: Arc<dyn GenericDataTypeProgramLocation>,
        program: Arc<dyn Program>,
        data_type: Box<dyn DataType>,
    ) -> Self {
        let base_data_type = ReferenceUtils::get_base_data_type(location.get_data_type());
        let label = format!("\"{}\" (DataType)", data_type.get_name());
        Self {
            location,
            program,
            original_data_type: data_type,
            base_data_type,
            label,
        }
    }

    /// Port of `GenericDataTypeLocationDescriptor.getDataType()`.
    ///
    /// Overridden so that the (dummy) location is never consulted to see if the user clicked on
    /// or inside of a structure.
    pub fn get_data_type(&self) -> &dyn DataType {
        self.base_data_type.as_ref()
    }

    /// Port of `GenericDataTypeLocationDescriptor.getHomeLocation()`.
    ///
    /// Overridden to signal that this location descriptor is not associated with any place in the
    /// program.
    pub fn get_home_location(&self) -> Option<Arc<dyn ProgramLocation>> {
        None
    }

    /// Port of `GenericDataTypeLocationDescriptor.getDataTypeName()`.
    pub fn get_data_type_name(&self) -> String {
        self.original_data_type.get_name()
    }

    /// Port of `GenericDataTypeLocationDescriptor.getSourceDataType()`.
    ///
    /// Called from the (Java) parent constructor, so it consults the location rather than
    /// `original_data_type`.
    pub fn get_source_data_type(&self) -> Box<dyn DataType> {
        self.location.get_data_type()
    }

    /// Port of `GenericDataTypeLocationDescriptor.getBaseDataType()`.
    pub fn get_base_data_type(&self) -> Box<dyn DataType> {
        ReferenceUtils::get_base_data_type(self.get_source_data_type())
    }

    /// Port of `LocationDescriptor.getLabel()`.
    pub fn get_label(&self) -> &str {
        &self.label
    }

    pub fn program(&self) -> &Arc<dyn Program> {
        &self.program
    }

    pub fn location(&self) -> &Arc<dyn GenericDataTypeProgramLocation> {
        &self.location
    }
}

impl DataTypeLocationDescriptor for GenericDataTypeLocationDescriptorBase {
    fn get_type_name(&self) -> String {
        self.get_data_type_name()
    }
}

/// The overridable behavior of [`GenericDataTypeLocationDescriptorBase`]: the two methods that
/// `GenericCompositeDataTypeLocationDescriptor` (TODO) goes on to override further.
pub trait GenericDataTypeLocationDescriptor: DataTypeLocationDescriptor {
    fn base(&self) -> &GenericDataTypeLocationDescriptorBase;

    /// Port of `GenericDataTypeLocationDescriptor.generateLabel()`.
    ///
    /// Implemented to ignore the location being provided, since this is a 'dummy' type class.
    fn generate_label(&self) -> String {
        format!("\"{}\" (DataType)", self.base().get_data_type_name())
    }
}

impl GenericDataTypeLocationDescriptor for GenericDataTypeLocationDescriptorBase {
    fn base(&self) -> &GenericDataTypeLocationDescriptorBase {
        self
    }
}

/// Port of `GenericDataTypeLocationDescriptor.equals(Object)`.
///
/// Overridden to perform a simple check against data types, since the program locations are dummy
/// locations. Java's `instanceof`/exact-class check is implied by `PartialEq`'s `Self`-typed
/// parameter.
impl PartialEq for GenericDataTypeLocationDescriptorBase {
    fn eq(&self, other: &Self) -> bool {
        self.get_data_type().is_equivalent(other.get_data_type())
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

    impl MockDataType {
        fn new(name: &str) -> Self {
            Self { name: name.to_string() }
        }
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.name == dt.get_name()
        }
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
    }

    fn test_address() -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, 0)
    }

    struct MockLocation {
        program: Arc<dyn Program>,
        type_name: String,
    }

    impl ProgramLocation for MockLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }
        fn get_address(&self) -> Address {
            test_address()
        }
        fn get_byte_address(&self) -> Address {
            test_address()
        }
    }

    impl GenericDataTypeProgramLocation for MockLocation {
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType::new(&self.type_name))
        }
    }

    fn descriptor_for(type_name: &str) -> GenericDataTypeLocationDescriptorBase {
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let location = Arc::new(MockLocation { program: program.clone(), type_name: type_name.to_string() });
        GenericDataTypeLocationDescriptorBase::new(location, program, Box::new(MockDataType::new(type_name)))
    }

    #[test]
    fn generate_label_wraps_type_name_in_quotes_with_data_type_suffix() {
        let descriptor = descriptor_for("Foo");
        assert_eq!(descriptor.generate_label(), "\"Foo\" (DataType)");
        assert_eq!(descriptor.get_label(), "\"Foo\" (DataType)");
    }

    #[test]
    fn get_data_type_name_matches_original_data_type() {
        let descriptor = descriptor_for("Bar");
        assert_eq!(descriptor.get_data_type_name(), "Bar");
        assert_eq!(descriptor.get_type_name(), "Bar");
    }

    #[test]
    fn get_home_location_is_always_none() {
        let descriptor = descriptor_for("Foo");
        assert!(descriptor.get_home_location().is_none());
    }

    #[test]
    fn equals_compares_by_underlying_data_type() {
        let a = descriptor_for("Foo");
        let b = descriptor_for("Foo");
        let c = descriptor_for("Baz");
        assert!(a == b);
        assert!(a != c);
    }
}
