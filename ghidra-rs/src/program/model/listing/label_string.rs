use std::sync::Arc;

use crate::program::model::symbol::Symbol;

/// Types of labels that can be associated with a LabelString.
///
/// Corresponds to the ordinal values used by `LabelType` in the Java source for compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelType {
    /// A label for code (e.g., a function or branch target).
    CodeLabel,
    /// A label for a variable or data location.
    Variable,
    /// A label for an external reference.
    External,
}

/// Represents a label string with an optional associated symbol.
///
/// This is a simple data container that holds:
/// - A label string (the actual label text)
/// - A label type (code, variable, or external)
/// - An optional symbol reference
#[derive(Clone)]
pub struct LabelString {
    label: String,
    label_type: LabelType,
    symbol: Option<Arc<dyn Symbol>>,
}

impl std::fmt::Debug for LabelString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LabelString")
            .field("label", &self.label)
            .field("label_type", &self.label_type)
            .field("symbol", &self.symbol.is_some())
            .finish()
    }
}

impl LabelString {
    /// Creates a new LabelString with the given label and type, with no associated symbol.
    pub fn new(label: impl Into<String>, label_type: LabelType) -> Self {
        Self {
            label: label.into(),
            label_type,
            symbol: None,
        }
    }

    /// Creates a new LabelString with the given label, symbol, and type.
    pub fn with_symbol(
        label: impl Into<String>,
        symbol: Arc<dyn Symbol>,
        label_type: LabelType,
    ) -> Self {
        Self {
            label: label.into(),
            label_type,
            symbol: Some(symbol),
        }
    }

    /// Returns a reference to the associated symbol, if one exists.
    pub fn get_symbol(&self) -> Option<&Arc<dyn Symbol>> {
        self.symbol.as_ref()
    }

    /// Returns the label type.
    pub fn get_label_type(&self) -> LabelType {
        self.label_type
    }

    /// Returns the label string.
    pub fn label(&self) -> &str {
        &self.label
    }
}

impl std::fmt::Display for LabelString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock Symbol for testing
    struct MockSymbol {
        name: String,
    }

    impl MockSymbol {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
            }
        }
    }

    impl crate::program::model::symbol::Symbol for MockSymbol {
        fn get_address(&self) -> crate::program::model::address::Address {
            unimplemented!()
        }

        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_symbol_type(&self) -> crate::program::model::symbol::SymbolType {
            crate::program::model::symbol::SymbolType::Label
        }

        fn get_source(&self) -> crate::program::model::symbol::SourceType {
            crate::program::model::symbol::SourceType::Analysis
        }

        fn is_primary(&self) -> bool {
            true
        }

        fn get_id(&self) -> i64 {
            1
        }

        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    #[test]
    fn new_without_symbol() {
        let label_str = LabelString::new("test_label", LabelType::CodeLabel);
        assert_eq!(label_str.label(), "test_label");
        assert_eq!(label_str.get_label_type(), LabelType::CodeLabel);
        assert!(label_str.get_symbol().is_none());
    }

    #[test]
    fn new_with_symbol() {
        let symbol = Arc::new(MockSymbol::new("my_symbol")) as Arc<dyn Symbol>;
        let label_str = LabelString::with_symbol("test_label", symbol.clone(), LabelType::Variable);
        assert_eq!(label_str.label(), "test_label");
        assert_eq!(label_str.get_label_type(), LabelType::Variable);
        assert!(label_str.get_symbol().is_some());
        assert_eq!(label_str.get_symbol().unwrap().get_name(), "my_symbol");
    }

    #[test]
    fn display_returns_label() {
        let label_str = LabelString::new("my_label", LabelType::CodeLabel);
        assert_eq!(label_str.to_string(), "my_label");
    }

    #[test]
    fn label_type_code_label() {
        let label_str = LabelString::new("code", LabelType::CodeLabel);
        assert_eq!(label_str.get_label_type(), LabelType::CodeLabel);
    }

    #[test]
    fn label_type_variable() {
        let label_str = LabelString::new("var", LabelType::Variable);
        assert_eq!(label_str.get_label_type(), LabelType::Variable);
    }

    #[test]
    fn label_type_external() {
        let label_str = LabelString::new("ext", LabelType::External);
        assert_eq!(label_str.get_label_type(), LabelType::External);
    }

    #[test]
    fn get_symbol_returns_none_when_not_set() {
        let label_str = LabelString::new("label", LabelType::CodeLabel);
        assert!(label_str.get_symbol().is_none());
    }

    #[test]
    fn clone_preserves_values() {
        let label_str = LabelString::new("original", LabelType::CodeLabel);
        let cloned = label_str.clone();
        assert_eq!(cloned.label(), "original");
        assert_eq!(cloned.get_label_type(), LabelType::CodeLabel);
        assert!(cloned.get_symbol().is_none());
    }

    #[test]
    fn debug_format() {
        let label_str = LabelString::new("debug_label", LabelType::External);
        let debug_str = format!("{:?}", label_str);
        assert!(debug_str.contains("LabelString"));
        assert!(debug_str.contains("debug_label"));
    }

    #[test]
    fn label_type_variants_are_distinct() {
        assert_ne!(LabelType::CodeLabel, LabelType::Variable);
        assert_ne!(LabelType::Variable, LabelType::External);
        assert_ne!(LabelType::CodeLabel, LabelType::External);
    }

    #[test]
    fn label_type_clone_preserves_variant() {
        let variants = [LabelType::CodeLabel, LabelType::Variable, LabelType::External];
        for variant in variants.iter() {
            assert_eq!(variant.clone(), *variant);
        }
    }

    #[test]
    fn label_type_hash_consistent_with_equality() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(LabelType::CodeLabel);
        assert!(set.contains(&LabelType::CodeLabel));
        assert!(!set.contains(&LabelType::Variable));
    }

    #[test]
    fn label_string_with_empty_label() {
        let label_str = LabelString::new("", LabelType::CodeLabel);
        assert_eq!(label_str.label(), "");
        assert_eq!(label_str.to_string(), "");
    }

    #[test]
    fn label_string_with_symbol_and_empty_label() {
        let symbol = Arc::new(MockSymbol::new("sym")) as Arc<dyn Symbol>;
        let label_str = LabelString::with_symbol("", symbol, LabelType::Variable);
        assert_eq!(label_str.label(), "");
        assert!(label_str.get_symbol().is_some());
    }
}
