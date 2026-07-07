use crate::program::model::data::isf::IsfObject;
use crate::program::model::listing::Function;

/// Represents an extended logical location for SARIF export.
///
/// Mirrors `ExtLogicalLocation` from Ghidra's `sarif.export` package.
/// Encapsulates location information including name, kind, decorated name,
/// fully qualified name, and URI derived from a function's program.
#[derive(Debug, Clone)]
pub struct ExtLogicalLocation {
    pub name: String,
    pub kind: String,
    pub decorated_name: String,
    pub fully_qualified_name: String,
    pub uri: String,
}

impl ExtLogicalLocation {
    /// Creates a new `ExtLogicalLocation` from function context and location details.
    ///
    /// # Arguments
    ///
    /// * `key` - The name of the logical location.
    /// * `function` - Optional function reference; if `None`, URI defaults to "UNKNOWN".
    /// * `location` - The location descriptor string.
    /// * `op` - The operation or decorator name.
    ///
    /// The fully qualified name is constructed as `{location}:{key}`.
    /// The URI is set to the program's executable path if a function is provided,
    /// otherwise defaults to "UNKNOWN".
    pub fn new(
        key: &str,
        function: Option<&dyn Function>,
        location: &str,
        op: &str,
    ) -> Self {
        let uri = match function {
            Some(f) => f.get_program().get_executable_path(),
            None => "UNKNOWN".to_string(),
        };

        Self {
            name: key.to_string(),
            kind: "variable".to_string(),
            decorated_name: op.to_string(),
            fully_qualified_name: format!("{}:{}", location, key),
            uri,
        }
    }

    /// Get the name of this logical location.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Get the decorated name of this logical location.
    pub fn get_decorated_name(&self) -> &str {
        &self.decorated_name
    }

    /// Get the fully qualified name of this logical location.
    ///
    /// Note: The Java source has a typo (`getFullyQualfiedName`), but this
    /// method uses the correct spelling.
    pub fn get_fully_qualified_name(&self) -> &str {
        &self.fully_qualified_name
    }
}

impl IsfObject for ExtLogicalLocation {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct MockProgram {
        executable_path: String,
    }

    impl crate::framework::model::DomainObject for MockProgram {}
    impl crate::program::model::listing::Program for MockProgram {
        fn get_name(&self) -> String {
            "MockProgram".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86:LE:64:default".to_string()
        }

        fn get_executable_path(&self) -> String {
            self.executable_path.clone()
        }
    }

    struct MockFunction {
        program: MockProgram,
    }

    impl crate::framework::model::DomainObject for MockFunction {}
    impl crate::program::model::symbol::Namespace for MockFunction {
        fn get_id(&self) -> i64 {
            1
        }

        fn get_path_to_root(&self) -> Vec<&dyn crate::program::model::symbol::Namespace> {
            vec![]
        }

        fn get_symbol(&self) -> Option<&dyn crate::program::model::symbol::Symbol> {
            None
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn crate::program::model::symbol::Namespace>> {
            None
        }

        fn get_name(&self) -> String {
            "MockFunction".to_string()
        }
    }

    impl Function for MockFunction {
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            Arc::new(MockProgram {
                executable_path: self.program.executable_path.clone(),
            })
        }
    }

    #[test]
    fn creates_logical_location_with_key_and_operation() {
        let location = ExtLogicalLocation::new("test_var", None, "function_scope", "read");

        assert_eq!(location.name, "test_var");
        assert_eq!(location.kind, "variable");
        assert_eq!(location.decorated_name, "read");
    }

    #[test]
    fn fully_qualified_name_combines_location_and_key() {
        let location = ExtLogicalLocation::new("my_var", None, "func_name", "write");

        assert_eq!(location.fully_qualified_name, "func_name:my_var");
    }

    #[test]
    fn uri_is_unknown_when_function_is_none() {
        let location = ExtLogicalLocation::new("var", None, "scope", "op");

        assert_eq!(location.uri, "UNKNOWN");
    }

    #[test]
    fn uri_uses_program_executable_path_when_function_provided() {
        let func = MockFunction {
            program: MockProgram {
                executable_path: "/path/to/binary".to_string(),
            },
        };

        let location = ExtLogicalLocation::new("var", Some(&func), "scope", "op");

        assert_eq!(location.uri, "/path/to/binary");
    }

    #[test]
    fn get_name_returns_key() {
        let location = ExtLogicalLocation::new("test_key", None, "location", "op");

        assert_eq!(location.get_name(), "test_key");
    }

    #[test]
    fn get_decorated_name_returns_operation() {
        let location = ExtLogicalLocation::new("var", None, "scope", "delete");

        assert_eq!(location.get_decorated_name(), "delete");
    }

    #[test]
    fn get_fully_qualified_name_matches_field() {
        let location = ExtLogicalLocation::new("x", None, "globals", "assign");

        assert_eq!(location.get_fully_qualified_name(), "globals:x");
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let location = ExtLogicalLocation::new("var", None, "scope", "op");
        accepts_isf_object(&location);
    }

    #[test]
    fn kind_is_always_variable() {
        let loc1 = ExtLogicalLocation::new("v1", None, "s1", "op1");
        let loc2 = ExtLogicalLocation::new("v2", None, "s2", "op2");

        assert_eq!(loc1.kind, "variable");
        assert_eq!(loc2.kind, "variable");
    }

    #[test]
    fn handles_empty_location_string() {
        let location = ExtLogicalLocation::new("var", None, "", "op");

        assert_eq!(location.fully_qualified_name, ":var");
    }

    #[test]
    fn handles_special_characters_in_names() {
        let location = ExtLogicalLocation::new("var::special", None, "func::name", "op");

        assert_eq!(location.fully_qualified_name, "func::name:var::special");
    }
}
