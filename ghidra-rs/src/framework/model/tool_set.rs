/// A named, described set of tools.
///
/// NOTE: ToolSets are currently not implemented in Ghidra; this trait is a
/// forward-declaration of the contract only.
pub trait ToolSet {
    /// Returns the name of this toolset.
    fn name(&self) -> &str;

    /// Sets the name of this toolset.
    fn set_name(&mut self, name: &str);

    /// Returns the description of this toolset.
    fn description(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleToolSet {
        name: String,
        description: String,
    }

    impl ToolSet for SimpleToolSet {
        fn name(&self) -> &str {
            &self.name
        }

        fn set_name(&mut self, name: &str) {
            self.name = name.to_string();
        }

        fn description(&self) -> &str {
            &self.description
        }
    }

    #[test]
    fn test_name_roundtrip() {
        let mut ts = SimpleToolSet { name: "initial".to_string(), description: String::new() };
        assert_eq!(ts.name(), "initial");
        ts.set_name("updated");
        assert_eq!(ts.name(), "updated");
    }

    #[test]
    fn test_description() {
        let ts = SimpleToolSet {
            name: "tools".to_string(),
            description: "A set of analysis tools".to_string(),
        };
        assert_eq!(ts.description(), "A set of analysis tools");
    }

    #[test]
    fn test_set_name_empty() {
        let mut ts = SimpleToolSet { name: "tools".to_string(), description: String::new() };
        ts.set_name("");
        assert_eq!(ts.name(), "");
    }
}
