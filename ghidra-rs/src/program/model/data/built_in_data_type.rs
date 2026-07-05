use crate::program::model::data::data_organization::DataOrganization;
use crate::program::seam_stubs::{DataType, Settings};

/// NOTE: ALL DATATYPE CLASSES MUST END IN "DataType". If not, the (Java) `ClassSearcher`
/// will not find them; this naming convention is not enforced by the Rust trait.
///
/// Interface to mark classes as a built-in data type.
///
/// Port of `ghidra.program.model.data.BuiltInDataType`. The Java `ExtensionPoint` marker
/// interface (used for classpath discovery) has no Rust equivalent and is dropped.
pub trait BuiltInDataType: DataType {
    /// Generate a suitable C-type declaration for this data-type as a #define or typedef.
    /// Since the length of a Dynamic datatype is unknown, such datatypes should only be
    /// referenced in C via a pointer. FactoryDataTypes should never be referenced and will
    /// always return `None`.
    ///
    /// `data_organization` is `None` for the default organization.
    ///
    /// Returns the definition C-statement (e.g. #define or typedef), or `None` if the type
    /// name is a standard C-primitive name or if the type is a FactoryDataType or Dynamic.
    fn get_c_type_declaration(&self, data_organization: Option<&dyn DataOrganization>)
        -> Option<String>;

    /// Set the default settings for this data type.
    ///
    /// NOTE: This method is reserved for internal DB use.
    fn set_default_settings(&mut self, settings: &dyn Settings);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct MockBuiltInDataType {
        default_settings: Option<()>,
    }

    impl DataType for MockBuiltInDataType {}

    impl BuiltInDataType for MockBuiltInDataType {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            data_organization.map(|_| "typedef int mock_t;".to_string())
        }

        fn set_default_settings(&mut self, _settings: &dyn Settings) {
            self.default_settings = Some(());
        }
    }

    #[test]
    fn returns_none_for_default_organization() {
        let built_in = MockBuiltInDataType {
            default_settings: None,
        };
        assert_eq!(built_in.get_c_type_declaration(None), None);
    }

    #[test]
    fn usable_as_trait_object() {
        let mut built_in = MockBuiltInDataType {
            default_settings: None,
        };
        let settings = MockSettings;
        let dyn_built_in: &mut dyn BuiltInDataType = &mut built_in;
        dyn_built_in.set_default_settings(&settings);
        assert!(built_in.default_settings.is_some());
    }
}
