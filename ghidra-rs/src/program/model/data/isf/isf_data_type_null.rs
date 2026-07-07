use super::IsfObject;

/// Represents a null/void ISF data type.
///
/// Mirrors `IsfDataTypeNull` from Ghidra's Debugger-isf module. The constructor
/// initialises `kind` to `"base"` and `name` to `"void"`, matching the Java source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsfDataTypeNull {
    kind: String,
    name: String,
}

impl IsfDataTypeNull {
    /// Creates a new `IsfDataTypeNull` with `kind = "base"` and `name = "void"`.
    pub fn new() -> Self {
        Self {
            kind: "base".to_string(),
            name: "void".to_string(),
        }
    }

    /// Returns the kind string (always `"base"`).
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Returns the name string (always `"void"`).
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Default for IsfDataTypeNull {
    fn default() -> Self {
        Self::new()
    }
}

impl IsfObject for IsfDataTypeNull {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values_match_java() {
        let dt = IsfDataTypeNull::new();
        assert_eq!(dt.kind(), "base");
        assert_eq!(dt.name(), "void");
    }

    #[test]
    fn default_trait_matches_new() {
        let a = IsfDataTypeNull::new();
        let b = IsfDataTypeNull::default();
        assert_eq!(a, b);
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let dt = IsfDataTypeNull::new();
        accepts_isf_object(&dt);
    }

    #[test]
    fn clone_is_independent() {
        let a = IsfDataTypeNull::new();
        let b = a.clone();
        assert_eq!(a, b);
    }
}
