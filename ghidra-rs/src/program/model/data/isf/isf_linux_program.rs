use std::collections::HashMap;

use super::IsfObject;

/// Represents an ISF Linux program descriptor.
///
/// Mirrors `IsfLinuxProgram` from Ghidra's Debugger-isf module. `kind` is
/// always `"dwarf"` and `hash_type` is always `"sha256"`; `name` and
/// `hash_value` are extracted from the supplied metadata map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsfLinuxProgram {
    pub kind: String,
    pub name: Option<String>,
    pub hash_type: String,
    pub hash_value: Option<String>,
}

impl IsfLinuxProgram {
    /// Creates a new `IsfLinuxProgram` from the provided metadata map.
    ///
    /// Looks up `"Program Name"` and `"Executable SHA256"` in `meta_data`,
    /// matching the Java constructor's `metaData.get(...)` calls which return
    /// `null` when absent.
    pub fn new(meta_data: &HashMap<String, String>) -> Self {
        Self {
            kind: "dwarf".to_string(),
            name: meta_data.get("Program Name").cloned(),
            hash_type: "sha256".to_string(),
            hash_value: meta_data.get("Executable SHA256").cloned(),
        }
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn hash_type(&self) -> &str {
        &self.hash_type
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn hash_value(&self) -> Option<&str> {
        self.hash_value.as_deref()
    }
}

impl IsfObject for IsfLinuxProgram {}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn fixed_fields_match_java() {
        let meta = make_map(&[
            ("Program Name", "test_prog"),
            ("Executable SHA256", "abc123"),
        ]);
        let prog = IsfLinuxProgram::new(&meta);
        assert_eq!(prog.kind(), "dwarf");
        assert_eq!(prog.hash_type(), "sha256");
    }

    #[test]
    fn name_and_hash_extracted_from_map() {
        let meta = make_map(&[
            ("Program Name", "my_binary"),
            ("Executable SHA256", "deadbeef"),
        ]);
        let prog = IsfLinuxProgram::new(&meta);
        assert_eq!(prog.name(), Some("my_binary"));
        assert_eq!(prog.hash_value(), Some("deadbeef"));
    }

    #[test]
    fn missing_keys_yield_none() {
        let meta = HashMap::new();
        let prog = IsfLinuxProgram::new(&meta);
        assert_eq!(prog.name(), None);
        assert_eq!(prog.hash_value(), None);
        assert_eq!(prog.kind(), "dwarf");
        assert_eq!(prog.hash_type(), "sha256");
    }

    #[test]
    fn partial_map_only_name_present() {
        let meta = make_map(&[("Program Name", "only_name")]);
        let prog = IsfLinuxProgram::new(&meta);
        assert_eq!(prog.name(), Some("only_name"));
        assert_eq!(prog.hash_value(), None);
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let meta = HashMap::new();
        let prog = IsfLinuxProgram::new(&meta);
        accepts_isf_object(&prog);
    }

    #[test]
    fn clone_is_independent() {
        let meta = make_map(&[
            ("Program Name", "clone_test"),
            ("Executable SHA256", "hash_val"),
        ]);
        let a = IsfLinuxProgram::new(&meta);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
