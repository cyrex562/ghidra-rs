use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::enum_::Enum;
use crate::program::seam_stubs::Composite;

/// NOTE: all `AnnotationHandler` implementations must have names ending in
/// "AnnotationHandler" so that the (Java) `ClassSearcher` can find them; this
/// naming convention is not enforced by the Rust trait.
///
/// AnnotationHandlers provide prefix/suffix information for various datatypes
/// for specific C-like languages.
///
/// Port of `ghidra.program.model.data.AnnotationHandler`. The Java interface's
/// two overloads of `getPrefix`/`getSuffix` (one taking an `Enum`, one taking a
/// `Composite`) are split into distinctly named methods, since Rust traits do
/// not support overloading by parameter type. The Java `ExtensionPoint` marker
/// interface (used for classpath discovery) has no Rust equivalent and is
/// dropped; `toString` is represented via a `Display` supertrait bound.
pub trait AnnotationHandler: std::fmt::Display {
    /// Returns the prefix for type Enum.
    fn get_enum_prefix(&self, e: &dyn Enum, member: &str) -> String;

    /// Returns the suffix for type Enum.
    fn get_enum_suffix(&self, e: &dyn Enum, member: &str) -> String;

    /// Returns the prefix for type Composite.
    fn get_composite_prefix(&self, c: &dyn Composite, dtc: &dyn DataTypeComponent) -> String;

    /// Returns the suffix for type Composite.
    fn get_composite_suffix(&self, c: &dyn Composite, dtc: &dyn DataTypeComponent) -> String;

    /// Returns the description of the specific handler.
    fn get_description(&self) -> String;

    /// Returns the name of the C-like language that this handler supports.
    fn get_language_name(&self) -> String;

    /// Returns known extensions for the output file type. If no extensions are
    /// preferred, an empty vec should be returned.
    fn get_file_extensions(&self) -> Vec<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockEnum;
    impl crate::program::model::data::data_type::DataType for MockEnum {}
    impl Enum for MockEnum {
        fn get_value_for_name(&self, _name: &str) -> Option<i64> {
            None
        }
        fn get_name_for_value(&self, _value: i64) -> Option<String> {
            None
        }
        fn get_names_for_value(&self, _value: i64) -> Option<Vec<String>> {
            None
        }
        fn get_comment(&self, _name: &str) -> String {
            String::new()
        }
        fn get_values(&self) -> Vec<i64> {
            Vec::new()
        }
        fn get_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_count(&self) -> i32 {
            0
        }
        fn add(&mut self, _name: &str, _value: i64) {}
        fn add_with_comment(&mut self, _name: &str, _value: i64, _comment: &str) {}
        fn remove(&mut self, _name: &str) {}
        fn set_description(&mut self, _description: &str) {}
        fn get_enum_representation(
            &self,
            big_int: i128,
            _settings: &dyn crate::program::seam_stubs::Settings,
            _bit_length: i32,
        ) -> String {
            big_int.to_string()
        }
        fn contains_name(&self, _name: &str) -> bool {
            false
        }
        fn contains_value(&self, _value: i64) -> bool {
            false
        }
        fn is_signed(&self) -> bool {
            false
        }
        fn get_signed_state(&self) -> crate::program::database::data::EnumSignedState {
            crate::program::database::data::EnumSignedState::None
        }
        fn get_max_possible_value(&self) -> i64 {
            0
        }
        fn get_min_possible_value(&self) -> i64 {
            0
        }
        fn get_minimum_possible_length(&self) -> i32 {
            1
        }
        fn clone_enum(&self, _dtm: &dyn crate::program::seam_stubs::DataTypeManager) -> Box<dyn Enum> {
            Box::new(MockEnum)
        }
    }

    struct MockComposite;
    impl Composite for MockComposite {}

    struct MockDataTypeComponent;
    impl DataTypeComponent for MockDataTypeComponent {}

    struct MockAnnotationHandler;

    impl std::fmt::Display for MockAnnotationHandler {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Mock C Annotation Handler")
        }
    }

    impl AnnotationHandler for MockAnnotationHandler {
        fn get_enum_prefix(&self, _e: &dyn Enum, _member: &str) -> String {
            String::new()
        }
        fn get_enum_suffix(&self, _e: &dyn Enum, _member: &str) -> String {
            String::new()
        }
        fn get_composite_prefix(&self, _c: &dyn Composite, _dtc: &dyn DataTypeComponent) -> String {
            String::new()
        }
        fn get_composite_suffix(&self, _c: &dyn Composite, _dtc: &dyn DataTypeComponent) -> String {
            String::new()
        }
        fn get_description(&self) -> String {
            "Mock".to_string()
        }
        fn get_language_name(&self) -> String {
            "C".to_string()
        }
        fn get_file_extensions(&self) -> Vec<String> {
            vec!["h".to_string(), "c".to_string()]
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let handler = MockAnnotationHandler;
        let dyn_handler: &dyn AnnotationHandler = &handler;
        let e = MockEnum;
        let c = MockComposite;
        let dtc = MockDataTypeComponent;

        assert_eq!(dyn_handler.get_language_name(), "C");
        assert_eq!(dyn_handler.get_description(), "Mock");
        assert_eq!(dyn_handler.get_file_extensions(), vec!["h", "c"]);
        assert_eq!(dyn_handler.get_enum_prefix(&e, "MEMBER"), "");
        assert_eq!(dyn_handler.get_enum_suffix(&e, "MEMBER"), "");
        assert_eq!(dyn_handler.get_composite_prefix(&c, &dtc), "");
        assert_eq!(dyn_handler.get_composite_suffix(&c, &dtc), "");
        assert_eq!(dyn_handler.to_string(), "Mock C Annotation Handler");
    }
}
