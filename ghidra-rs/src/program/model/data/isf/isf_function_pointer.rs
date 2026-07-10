use crate::program::model::data::function_definition::FunctionDefinition;
use super::{IsfObject, AbstractIsfObject, IsfFunction};

/// Represents a function pointer data type in ISF format.
///
/// Mirrors `IsfFunctionPointer` from Ghidra's Debugger-isf module. This struct extends
/// [`AbstractIsfObject`] and adds a `kind` discriminator field always set to `"pointer"`,
/// with a `subtype` field containing the pointed-to function signature.
///
/// The `abstract_isf_object` field is marked conceptually as excluded from serialization
/// (matching the Java `@Exclude` annotation on parent fields).
pub struct IsfFunctionPointer {
    pub abstract_isf_object: AbstractIsfObject,
    pub kind: String,
    pub subtype: Box<dyn IsfObject>,
}

impl std::fmt::Debug for IsfFunctionPointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsfFunctionPointer")
            .field("abstract_isf_object", &self.abstract_isf_object)
            .field("kind", &self.kind)
            .field("subtype", &"<dyn IsfObject>")
            .finish()
    }
}

impl IsfFunctionPointer {
    /// Creates a new `IsfFunctionPointer` from a `FunctionDefinition`.
    ///
    /// Extracts metadata from the provided function definition via the parent
    /// `AbstractIsfObject`, sets `kind` to `"pointer"`, and creates an `IsfFunction`
    /// as the subtype.
    ///
    /// Mirrors the Java constructor behavior, which calls `super(def)` and then
    /// initializes the `kind` and `subtype` fields.
    pub fn new(def: &dyn FunctionDefinition) -> Self {
        Self {
            abstract_isf_object: AbstractIsfObject::new(Some(def)),
            kind: "pointer".to_string(),
            subtype: Box::new(IsfFunction::new(def)),
        }
    }
}

impl IsfObject for IsfFunctionPointer {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::function_signature::FunctionSignature;

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
            CategoryPath::parse(&self.category_path).unwrap()
        }
    }

    impl FunctionSignature for MockFunctionDefinition {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_prototype_string_with_calling_convention(
            &self,
            _include_calling_convention: bool,
        ) -> String {
            String::new()
        }

        fn get_arguments(
            &self,
        ) -> Vec<Box<dyn crate::program::model::data::parameter_definition::ParameterDefinition>>
        {
            Vec::new()
        }

        fn get_return_type(&self) -> Box<dyn DataType> {
            Box::new(MockFunctionDefinition::new("", ""))
        }

        fn get_comment(&self) -> Option<String> {
            None
        }

        fn has_var_args(&self) -> bool {
            false
        }

        fn has_no_return(&self) -> bool {
            false
        }

        fn get_calling_convention(
            &self,
        ) -> Option<Box<dyn crate::program::seam_stubs::PrototypeModel>> {
            None
        }

        fn get_calling_convention_name(&self) -> String {
            String::new()
        }

        fn is_equivalent_signature(
            &self,
            _signature: &dyn FunctionSignature,
        ) -> bool {
            false
        }
    }

    impl FunctionDefinition for MockFunctionDefinition {
        fn set_arguments(
            &mut self,
            _args: Vec<Box<dyn crate::program::model::data::parameter_definition::ParameterDefinition>>,
        ) {
        }

        fn set_return_type(&mut self, _data_type: Box<dyn DataType>) -> Result<(), String> {
            Ok(())
        }

        fn set_comment(&mut self, _comment: Option<String>) {}

        fn set_var_args(&mut self, _has_var_args: bool) {}

        fn set_no_return(&mut self, _has_no_return: bool) {}

        fn set_generic_calling_convention(
            &mut self,
            _generic_calling_convention: &dyn crate::program::seam_stubs::GenericCallingConvention,
        ) {
        }

        fn set_calling_convention(
            &mut self,
            _convention_name: Option<String>,
        ) -> Result<(), crate::util::exception::InvalidInputException> {
            Ok(())
        }

        fn replace_argument(
            &mut self,
            _ordinal: i32,
            _name: Option<String>,
            _dt: Box<dyn DataType>,
            _comment: Option<String>,
            _source: crate::program::model::symbol::source_type::SourceType,
        ) {
        }
    }

    #[test]
    fn new_creates_struct_from_function_definition() {
        let func_def = MockFunctionDefinition::new("myFunc", "/Category");
        let isf = IsfFunctionPointer::new(&func_def);
        assert_eq!(isf.kind, "pointer");
    }

    #[test]
    fn kind_always_set_to_pointer() {
        let func_def = MockFunctionDefinition::new("test", "/");
        let isf = IsfFunctionPointer::new(&func_def);
        assert_eq!(isf.kind, "pointer");
    }

    #[test]
    fn abstract_isf_object_inherits_function_definition_metadata() {
        let func_def = MockFunctionDefinition::new("myFunc", "/Functions/Core");
        let isf = IsfFunctionPointer::new(&func_def);
        assert_eq!(isf.abstract_isf_object.name, Some("myFunc".to_string()));
        assert_eq!(
            isf.abstract_isf_object.location,
            Some("/Functions/Core".to_string())
        );
    }

    #[test]
    fn subtype_is_isf_function() {
        let func_def = MockFunctionDefinition::new("testFunc", "/Path");
        let isf = IsfFunctionPointer::new(&func_def);
        fn accepts_isf_object<T: IsfObject + ?Sized>(_: &T) {}
        accepts_isf_object(&*isf.subtype);
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let func_def = MockFunctionDefinition::new("func", "/");
        let isf = IsfFunctionPointer::new(&func_def);
        accepts_isf_object(&isf);
    }

    #[test]
    fn debug_formatting() {
        let func_def = MockFunctionDefinition::new("f", "/");
        let isf = IsfFunctionPointer::new(&func_def);
        let debug_str = format!("{:?}", isf);
        assert!(debug_str.contains("IsfFunctionPointer"));
        assert!(debug_str.contains("kind"));
        assert!(debug_str.contains("subtype"));
    }

    #[test]
    fn multiple_function_pointers_have_independent_metadata() {
        let func1 = MockFunctionDefinition::new("func1", "/Path1");
        let func2 = MockFunctionDefinition::new("func2", "/Path2");

        let isf1 = IsfFunctionPointer::new(&func1);
        let isf2 = IsfFunctionPointer::new(&func2);

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
