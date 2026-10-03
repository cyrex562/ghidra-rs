use std::collections::HashMap;

/// Store of preprocessor macro definitions.
///
/// Mirrors `ghidra.pcodeCPort.slgh_compile.PreprocessorDefinitions`. Java's
/// `lookup` returns a `Pair<Boolean, String>`; here we use `Option<String>`
/// (`None` == not defined, `Some("")` == defined with an empty value, which is
/// what `@define FOO` with no value produces).
pub trait PreprocessorDefinitions {
    /// Returns the value of `key`, or `None` if it is not defined.
    fn lookup(&self, key: &str) -> Option<String>;

    /// Defines (or redefines) `key` to `value`.
    fn set(&mut self, key: &str, value: &str);

    /// Removes any definition of `key`.
    fn undefine(&mut self, key: &str);
}

/// Hash-map backed [`PreprocessorDefinitions`].
///
/// Mirrors `ghidra.sleigh.grammar.HashMapPreprocessorDefinitionsAdapter`.
#[derive(Debug, Default, Clone)]
pub struct HashMapPreprocessorDefinitions {
    map: HashMap<String, String>,
}

impl HashMapPreprocessorDefinitions {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PreprocessorDefinitions for HashMapPreprocessorDefinitions {
    fn lookup(&self, key: &str) -> Option<String> {
        self.map.get(key).cloned()
    }

    fn set(&mut self, key: &str, value: &str) {
        self.map.insert(key.to_string(), value.to_string());
    }

    fn undefine(&mut self, key: &str) {
        self.map.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_undefined_returns_none() {
        let defs = HashMapPreprocessorDefinitions::new();
        assert_eq!(defs.lookup("FOO"), None);
    }

    #[test]
    fn set_and_lookup() {
        let mut defs = HashMapPreprocessorDefinitions::new();
        defs.set("FOO", "bar");
        assert_eq!(defs.lookup("FOO"), Some("bar".to_string()));
    }

    #[test]
    fn empty_value_is_still_defined() {
        let mut defs = HashMapPreprocessorDefinitions::new();
        defs.set("FLAG", "");
        assert_eq!(defs.lookup("FLAG"), Some(String::new()));
    }

    #[test]
    fn undefine_removes_key() {
        let mut defs = HashMapPreprocessorDefinitions::new();
        defs.set("FOO", "bar");
        defs.undefine("FOO");
        assert_eq!(defs.lookup("FOO"), None);
    }

    #[test]
    fn redefine_overwrites() {
        let mut defs = HashMapPreprocessorDefinitions::new();
        defs.set("FOO", "1");
        defs.set("FOO", "2");
        assert_eq!(defs.lookup("FOO"), Some("2".to_string()));
    }
}
