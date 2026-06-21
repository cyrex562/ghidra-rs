use std::collections::HashMap;

use serde_json::Value;

use super::{IsfLinuxProgram, IsfObject};

/// Represents an ISF Linux OS descriptor.
///
/// Mirrors `IsfLinuxOS` from Ghidra's `Debugger-isf` module. On construction,
/// a single [`IsfLinuxProgram`] is serialized to JSON and appended to both
/// the `symbols` and `types` arrays, matching the Java source behaviour where
/// `gson.toJsonTree(pgm)` was added to each array.
pub struct IsfLinuxOS {
    pub symbols: Vec<Value>,
    pub types: Vec<Value>,
}

impl IsfLinuxOS {
    /// Creates a new `IsfLinuxOS` from the supplied metadata map.
    ///
    /// Constructs an [`IsfLinuxProgram`] and serializes it into both
    /// `symbols` and `types`, replicating the Java constructor's use of
    /// `gson.toJsonTree`.
    pub fn new(meta_data: &HashMap<String, String>) -> Self {
        let pgm = IsfLinuxProgram::new(meta_data);
        let json = serde_json::to_value(&pgm)
            .expect("IsfLinuxProgram fields are always serializable");
        Self {
            symbols: vec![json.clone()],
            types: vec![json],
        }
    }
}

impl IsfObject for IsfLinuxOS {}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn symbols_and_types_both_populated() {
        let meta = make_map(&[
            ("Program Name", "test_prog"),
            ("Executable SHA256", "abc123"),
        ]);
        let os = IsfLinuxOS::new(&meta);
        assert_eq!(os.symbols.len(), 1);
        assert_eq!(os.types.len(), 1);
    }

    #[test]
    fn symbols_and_types_contain_same_value() {
        let meta = make_map(&[
            ("Program Name", "my_binary"),
            ("Executable SHA256", "deadbeef"),
        ]);
        let os = IsfLinuxOS::new(&meta);
        assert_eq!(os.symbols[0], os.types[0]);
    }

    #[test]
    fn serialized_json_has_expected_fields() {
        let meta = make_map(&[
            ("Program Name", "elf_binary"),
            ("Executable SHA256", "cafebabe"),
        ]);
        let os = IsfLinuxOS::new(&meta);
        let val = &os.symbols[0];
        assert_eq!(val["kind"], "dwarf");
        assert_eq!(val["hash_type"], "sha256");
        assert_eq!(val["name"], "elf_binary");
        assert_eq!(val["hash_value"], "cafebabe");
    }

    #[test]
    fn missing_metadata_keys_serialize_as_null() {
        let meta = HashMap::new();
        let os = IsfLinuxOS::new(&meta);
        let val = &os.symbols[0];
        assert_eq!(val["kind"], "dwarf");
        assert_eq!(val["hash_type"], "sha256");
        assert!(val["name"].is_null());
        assert!(val["hash_value"].is_null());
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let meta = make_map(&[("Program Name", "x"), ("Executable SHA256", "y")]);
        let os = IsfLinuxOS::new(&meta);
        accepts_isf_object(&os);
    }

    #[test]
    fn partial_metadata_handled_correctly() {
        let meta = make_map(&[("Program Name", "only_name")]);
        let os = IsfLinuxOS::new(&meta);
        let val = &os.symbols[0];
        assert_eq!(val["name"], "only_name");
        assert!(val["hash_value"].is_null());
    }
}
