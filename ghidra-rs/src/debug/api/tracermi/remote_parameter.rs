/// A named parameter to a remote method.
///
/// Corresponds to `ghidra.debug.api.tracermi.RemoteParameter`.
pub trait RemoteParameter {
    /// Get the parameter's name.
    fn name(&self) -> &str;

    /// Get the parameter's type, as a schema name.
    fn type_(&self) -> &SchemaName;

    /// Check whether a value for this parameter must be supplied.
    fn required(&self) -> bool;

    /// Get the default value, or `None` if no default is configured.
    fn get_default_value(&self) -> Option<&dyn std::any::Any>;

    /// Get the parameter's human-readable display label.
    fn display(&self) -> &str;

    /// Get the parameter's human-readable description.
    fn description(&self) -> &str;
}

/// A schema name, identifying a type in a trace schema context.
///
/// Corresponds to `ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemaName {
    name: String,
}

impl SchemaName {
    /// Creates a new schema name with the given string.
    pub fn new(name: impl Into<String>) -> Self {
        SchemaName {
            name: name.into(),
        }
    }

    /// Get the schema name as a string.
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// Consume this schema name and return the owned string.
    pub fn into_string(self) -> String {
        self.name
    }
}

impl std::fmt::Display for SchemaName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name)
    }
}

impl From<String> for SchemaName {
    fn from(name: String) -> Self {
        SchemaName { name }
    }
}

impl From<&str> for SchemaName {
    fn from(name: &str) -> Self {
        SchemaName {
            name: name.to_owned(),
        }
    }
}

impl AsRef<str> for SchemaName {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_name_new_stores_string() {
        let name = SchemaName::new("MySchema");
        assert_eq!(name.as_str(), "MySchema");
    }

    #[test]
    fn schema_name_from_string() {
        let name = SchemaName::from("TestSchema".to_string());
        assert_eq!(name.as_str(), "TestSchema");
    }

    #[test]
    fn schema_name_from_str() {
        let name = SchemaName::from("StrSchema");
        assert_eq!(name.as_str(), "StrSchema");
    }

    #[test]
    fn schema_name_into_string() {
        let name = SchemaName::new("MySchema");
        let owned = name.into_string();
        assert_eq!(owned, "MySchema");
    }

    #[test]
    fn schema_name_display() {
        let name = SchemaName::new("DisplaySchema");
        assert_eq!(name.to_string(), "DisplaySchema");
    }

    #[test]
    fn schema_name_as_ref_str() {
        let name = SchemaName::new("RefSchema");
        let as_str: &str = name.as_ref();
        assert_eq!(as_str, "RefSchema");
    }

    #[test]
    fn schema_name_clone_eq() {
        let name1 = SchemaName::new("Schema");
        let name2 = name1.clone();
        assert_eq!(name1, name2);
    }

    #[test]
    fn schema_name_eq_different_content() {
        let name1 = SchemaName::new("Schema1");
        let name2 = SchemaName::new("Schema2");
        assert_ne!(name1, name2);
    }

    #[test]
    fn schema_name_ord() {
        let name1 = SchemaName::new("AAA");
        let name2 = SchemaName::new("BBB");
        assert!(name1 < name2);
        assert!(name2 > name1);
    }

    #[test]
    fn schema_name_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(SchemaName::new("Schema"));
        assert!(set.contains(&SchemaName::new("Schema")));
    }

    struct TestParameter {
        name: String,
        type_: SchemaName,
        required: bool,
        default: Option<Box<dyn std::any::Any>>,
        display: String,
        description: String,
    }

    impl RemoteParameter for TestParameter {
        fn name(&self) -> &str {
            &self.name
        }

        fn type_(&self) -> &SchemaName {
            &self.type_
        }

        fn required(&self) -> bool {
            self.required
        }

        fn get_default_value(&self) -> Option<&dyn std::any::Any> {
            self.default.as_ref().map(|b| b.as_ref())
        }

        fn display(&self) -> &str {
            &self.display
        }

        fn description(&self) -> &str {
            &self.description
        }
    }

    #[test]
    fn remote_parameter_trait_methods() {
        let param = TestParameter {
            name: "count".to_string(),
            type_: SchemaName::new("Integer"),
            required: true,
            default: Some(Box::new(42i64)),
            display: "Count".to_string(),
            description: "Number of items".to_string(),
        };

        assert_eq!(param.name(), "count");
        assert_eq!(param.type_(), &SchemaName::new("Integer"));
        assert!(param.required());
        assert!(param.get_default_value().is_some());
        assert_eq!(param.display(), "Count");
        assert_eq!(param.description(), "Number of items");
    }

    #[test]
    fn remote_parameter_optional_default() {
        let param = TestParameter {
            name: "optional_param".to_string(),
            type_: SchemaName::new("String"),
            required: false,
            default: None,
            display: "Optional Param".to_string(),
            description: "A parameter with no default".to_string(),
        };

        assert!(!param.required());
        assert!(param.get_default_value().is_none());
    }

    #[test]
    fn remote_parameter_required_no_default() {
        let param = TestParameter {
            name: "required_param".to_string(),
            type_: SchemaName::new("Object"),
            required: true,
            default: None,
            display: "Required Param".to_string(),
            description: "Must be supplied".to_string(),
        };

        assert!(param.required());
        assert!(param.get_default_value().is_none());
    }
}
