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
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
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
