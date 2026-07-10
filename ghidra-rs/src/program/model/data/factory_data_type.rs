use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_type::DataType;
use crate::program::seam_stubs::MemBuffer;

/// A [`DataType`] class that creates data types dynamically should implement this trait.
/// This prevents them being directly referred to by a data instance within the listing
/// or within a composite (e.g., added to a composite using the structure editor).
/// `FactoryDataType`s should never be parented (e.g., Pointer, Structure component, Typedef, etc.).
///
/// Port of `ghidra.program.model.data.FactoryDataType`.
///
/// Java's `getLength()` default override always returns `-1`. Rust cannot override a
/// supertrait's default method (`DataType::get_length`) under the same name without creating
/// an ambiguous call site, so implementations of this trait must implement
/// [`DataType::get_length`] directly and return `-1`.
pub trait FactoryDataType: BuiltInDataType {
    /// Returns the appropriate DataType which corresponds to the specified memory location.
    fn get_data_type(&self, buf: &dyn MemBuffer) -> Box<dyn DataType>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockMemBuffer;
    impl MemBuffer for MockMemBuffer {
        fn get_address(&self) -> crate::program::model::address::Address {
            crate::program::model::address::SpecialAddress::no_address()
        }
    }

    struct MockFactoryDataType;

    impl DataType for MockFactoryDataType {
        fn get_length(&self) -> i32 {
            -1
        }
    }

    impl BuiltInDataType for MockFactoryDataType {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn crate::program::model::data::data_organization::DataOrganization>,
        ) -> Option<String> {
            None
        }

        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl FactoryDataType for MockFactoryDataType {
        fn get_data_type(&self, _buf: &dyn MemBuffer) -> Box<dyn DataType> {
            Box::new(MockFactoryDataType)
        }
    }

    #[test]
    fn fabricates_data_type_with_required_length() {
        let factory = MockFactoryDataType;
        let dt = factory.get_data_type(&MockMemBuffer);
        assert_eq!(dt.get_length(), -1);
    }

    #[test]
    fn usable_as_trait_object() {
        let factory = MockFactoryDataType;
        let dyn_factory: &dyn FactoryDataType = &factory;
        assert_eq!(dyn_factory.get_length(), -1);
    }
}
