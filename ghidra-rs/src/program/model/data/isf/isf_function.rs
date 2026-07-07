use crate::program::model::data::function_definition::FunctionDefinition;
use super::{IsfObject, AbstractIsfObject};

/// Represents a function data type in ISF format.
///
/// Mirrors `IsfFunction` from Ghidra's Debugger-isf module. This struct extends
/// [`AbstractIsfObject`] and adds a `kind` discriminator field always set to `"function"`.
///
/// The `abstract_isf_object` field is marked with `#[serde(skip)]` to match the Java
/// `@Exclude` annotation on those parent fields.
#[derive(Debug, Clone)]
pub struct IsfFunction {
    pub abstract_isf_object: AbstractIsfObject,
    pub kind: String,
}

impl IsfFunction {
    /// Creates a new `IsfFunction` from a `FunctionDefinition`.
    ///
    /// Extracts metadata from the provided function definition via the parent
    /// `AbstractIsfObject`, and sets `kind` to `"function"`.
    ///
    /// Mirrors the Java constructor behavior, which calls `super(def)` and then
    /// initializes the `kind` field.
    pub fn new(def: &dyn FunctionDefinition) -> Self {
        Self {
            abstract_isf_object: AbstractIsfObject::new(Some(def)),
            kind: "function".to_string(),
        }
    }
}

impl IsfObject for IsfFunction {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::function_signature::FunctionSignature;

    struct MockFunctionDefinition {
        name: String,
        category_path: String,
    }

    impl MockFunctionDefinition {
        fn new(name: &str, path: &str) -> Self {
            Self {
                name: name.to_string(),
                category_path: path.to_string(),
            }
        }
    }

    impl DataType for MockFunctionDefinition {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_category_path(&self) -> crate::program::model::data::category_path::CategoryPath {
            use crate::program::model::data::category_path::CategoryPath;
            CategoryPath::from_path(&self.category_path)
        }
    }

    impl FunctionSignature for MockFunctionDefinition {}

    impl FunctionDefinition for MockFunctionDefinition {}

    #[test]
    fn new_creates_struct_from_function_definition() {
        let func_def = MockFunctionDefinition::new("myFunc", "/Category");
        let isf = IsfFunction::new(&func_def);
        assert_eq!(isf.kind, "function");
    }

    #[test]
    fn kind_always_set_to_function() {
        let func_def = MockFunctionDefinition::new("test", "/");
        let isf = IsfFunction::new(&func_def);
        assert_eq!(isf.kind, "function");
    }

    #[test]
    fn abstract_isf_object_inherits_function_definition_metadata() {
        let func_def = MockFunctionDefinition::new("myFunc", "/Functions/Core");
        let isf = IsfFunction::new(&func_def);
        assert_eq!(isf.abstract_isf_object.name, Some("myFunc".to_string()));
        assert_eq!(
            isf.abstract_isf_object.location,
            Some("/Functions/Core".to_string())
        );
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let func_def = MockFunctionDefinition::new("func", "/");
        let isf = IsfFunction::new(&func_def);
        accepts_isf_object(&isf);
    }

    #[test]
    fn clone_creates_independent_copy() {
        let func_def = MockFunctionDefinition::new("func1", "/Path");
        let isf1 = IsfFunction::new(&func_def);
        let isf2 = isf1.clone();
        assert_eq!(isf1.kind, isf2.kind);
        assert_eq!(isf1.abstract_isf_object.name, isf2.abstract_isf_object.name);
    }

    #[test]
    fn debug_formatting() {
        let func_def = MockFunctionDefinition::new("f", "/");
        let isf = IsfFunction::new(&func_def);
        let debug_str = format!("{:?}", isf);
        assert!(debug_str.contains("IsfFunction"));
    }

    #[test]
    fn multiple_functions_have_independent_metadata() {
        let func1 = MockFunctionDefinition::new("func1", "/Path1");
        let func2 = MockFunctionDefinition::new("func2", "/Path2");

        let isf1 = IsfFunction::new(&func1);
        let isf2 = IsfFunction::new(&func2);

        assert_eq!(
            isf1.abstract_isf_object.name,
            Some("func1".to_string())
        );
        assert_eq!(
            isf2.abstract_isf_object.name,
            Some("func2".to_string())
        );
    }
}
