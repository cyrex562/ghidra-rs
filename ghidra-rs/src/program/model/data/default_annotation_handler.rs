use crate::program::model::data::annotation_handler::AnnotationHandler;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::enum_::Enum;
use std::fmt;

/// The default annotation handler that provides prefix/suffix information for C/C++ code generation.
///
/// This is a simple default implementation that returns empty prefixes and suffixes for all types.
/// Port of `ghidra.program.model.data.DefaultAnnotationHandler`.
#[derive(Debug, Clone)]
pub struct DefaultAnnotationHandler;

impl fmt::Display for DefaultAnnotationHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get_language_name())
    }
}

impl AnnotationHandler for DefaultAnnotationHandler {
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
        "Default C Annotations".to_string()
    }

    fn get_language_name(&self) -> String {
        "C/C++".to_string()
    }

    fn get_file_extensions(&self) -> Vec<String> {
        vec!["c".to_string(), "h".to_string(), "cpp".to_string()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_enum_prefix_returns_empty_string() {
        let handler = DefaultAnnotationHandler;
        let prefix = handler.get_enum_prefix(&MockEnum, "MEMBER");
        assert_eq!(prefix, "");
    }

    #[test]
    fn get_enum_suffix_returns_empty_string() {
        let handler = DefaultAnnotationHandler;
        let suffix = handler.get_enum_suffix(&MockEnum, "MEMBER");
        assert_eq!(suffix, "");
    }

    #[test]
    fn get_composite_prefix_returns_empty_string() {
        let handler = DefaultAnnotationHandler;
        let prefix = handler.get_composite_prefix(&MockComposite, &MockDataTypeComponent);
        assert_eq!(prefix, "");
    }

    #[test]
    fn get_composite_suffix_returns_empty_string() {
        let handler = DefaultAnnotationHandler;
        let suffix = handler.get_composite_suffix(&MockComposite, &MockDataTypeComponent);
        assert_eq!(suffix, "");
    }

    #[test]
    fn get_description_returns_default_c_annotations() {
        let handler = DefaultAnnotationHandler;
        assert_eq!(handler.get_description(), "Default C Annotations");
    }

    #[test]
    fn get_language_name_returns_c_cpp() {
        let handler = DefaultAnnotationHandler;
        assert_eq!(handler.get_language_name(), "C/C++");
    }

    #[test]
    fn get_file_extensions_returns_c_h_cpp() {
        let handler = DefaultAnnotationHandler;
        let extensions = handler.get_file_extensions();
        assert_eq!(extensions, vec!["c", "h", "cpp"]);
    }

    #[test]
    fn to_string_returns_language_name() {
        let handler = DefaultAnnotationHandler;
        assert_eq!(handler.to_string(), "C/C++");
    }

    #[test]
    fn clone_creates_independent_instance() {
        let handler1 = DefaultAnnotationHandler;
        let handler2 = handler1.clone();
        assert_eq!(handler1.get_language_name(), handler2.get_language_name());
    }

    #[test]
    fn usable_as_trait_object() {
        let handler = DefaultAnnotationHandler;
        let dyn_handler: &dyn AnnotationHandler = &handler;

        assert_eq!(dyn_handler.get_language_name(), "C/C++");
        assert_eq!(dyn_handler.get_description(), "Default C Annotations");
        assert_eq!(dyn_handler.get_file_extensions(), vec!["c", "h", "cpp"]);
        assert_eq!(dyn_handler.get_enum_prefix(&MockEnum, "MEMBER"), "");
        assert_eq!(dyn_handler.get_enum_suffix(&MockEnum, "MEMBER"), "");
        assert_eq!(
            dyn_handler.get_composite_prefix(&MockComposite, &MockDataTypeComponent),
            ""
        );
        assert_eq!(
            dyn_handler.get_composite_suffix(&MockComposite, &MockDataTypeComponent),
            ""
        );
        assert_eq!(dyn_handler.to_string(), "C/C++");
    }

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
        fn clone_enum(
            &self,
            _dtm: &dyn crate::program::model::data::data_type_manager::DataTypeManager,
        ) -> Box<dyn Enum> {
            Box::new(MockEnum)
        }
    }

    struct MockComposite;
    impl crate::program::model::data::data_type::DataType for MockComposite {}
    impl Composite for MockComposite {}

    struct MockDataTypeComponent;
    impl DataTypeComponent for MockDataTypeComponent {}
}
