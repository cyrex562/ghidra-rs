//! Port of `ghidra.app.plugin.core.symboltree.SymbolCategory`.
//!
//! Java gives this class a private constructor, so the only instances that can ever exist
//! are the seven `public static final` constants it declares itself. This port mirrors that
//! by making [`SymbolCategory::new`] private (`pub(self)`, i.e. not `pub`) and exposing only
//! the seven `pub const` values below, keeping the "closed set of categories" invariant the
//! Java class enforces via visibility.

use crate::program::model::symbol::SymbolType;

/// A named grouping of symbols in the symbol tree, optionally restricted to one
/// [`SymbolType`].
///
/// Port of `ghidra.app.plugin.core.symboltree.SymbolCategory`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SymbolCategory {
    name: &'static str,
    symbol_type: Option<SymbolType>,
}

impl SymbolCategory {
    /// Port of `SymbolCategory(String name, SymbolType type)`, private in Java. `type` is
    /// `null` for [`SymbolCategory::ROOT_CATEGORY`], hence `Option<SymbolType>` here.
    const fn new(name: &'static str, symbol_type: Option<SymbolType>) -> Self {
        Self { name, symbol_type }
    }

    /// Port of the `FUNCTION_CATEGORY` static.
    pub const FUNCTION_CATEGORY: SymbolCategory =
        SymbolCategory::new("Functions", Some(SymbolType::Function));
    /// Port of the `EXPORTS_CATEGORY` static.
    pub const EXPORTS_CATEGORY: SymbolCategory =
        SymbolCategory::new("Exports", Some(SymbolType::Label));
    /// Port of the `IMPORTS_CATEGORY` static.
    pub const IMPORTS_CATEGORY: SymbolCategory =
        SymbolCategory::new("Imports", Some(SymbolType::Library));
    /// Port of the `LABEL_CATEGORY` static.
    pub const LABEL_CATEGORY: SymbolCategory =
        SymbolCategory::new("Labels", Some(SymbolType::Label));
    /// Port of the `ROOT_CATEGORY` static. Java passes `null` for the type here; this is the
    /// only category with `symbol_type == None`.
    pub const ROOT_CATEGORY: SymbolCategory = SymbolCategory::new("Global", None);
    /// Port of the `NAMESPACE_CATEGORY` static.
    pub const NAMESPACE_CATEGORY: SymbolCategory =
        SymbolCategory::new("Namespaces", Some(SymbolType::Namespace));
    /// Port of the `CLASS_CATEGORY` static.
    pub const CLASS_CATEGORY: SymbolCategory =
        SymbolCategory::new("Classes", Some(SymbolType::Class));

    /// Port of `getName()`.
    pub fn get_name(&self) -> &'static str {
        self.name
    }

    /// Port of `getSymbolType()`.
    pub fn get_symbol_type(&self) -> Option<SymbolType> {
        self.symbol_type
    }
}

impl std::fmt::Display for SymbolCategory {
    /// Port of `toString()`, which returns `name`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_category_has_expected_name_and_type() {
        assert_eq!(SymbolCategory::FUNCTION_CATEGORY.get_name(), "Functions");
        assert_eq!(
            SymbolCategory::FUNCTION_CATEGORY.get_symbol_type(),
            Some(SymbolType::Function)
        );
    }

    #[test]
    fn exports_category_uses_label_symbol_type() {
        assert_eq!(SymbolCategory::EXPORTS_CATEGORY.get_name(), "Exports");
        assert_eq!(
            SymbolCategory::EXPORTS_CATEGORY.get_symbol_type(),
            Some(SymbolType::Label)
        );
    }

    #[test]
    fn imports_category_uses_library_symbol_type() {
        assert_eq!(SymbolCategory::IMPORTS_CATEGORY.get_name(), "Imports");
        assert_eq!(
            SymbolCategory::IMPORTS_CATEGORY.get_symbol_type(),
            Some(SymbolType::Library)
        );
    }

    #[test]
    fn label_category_uses_label_symbol_type() {
        assert_eq!(SymbolCategory::LABEL_CATEGORY.get_name(), "Labels");
        assert_eq!(
            SymbolCategory::LABEL_CATEGORY.get_symbol_type(),
            Some(SymbolType::Label)
        );
    }

    /// Java constructs `ROOT_CATEGORY` with a `null` type: `new SymbolCategory("Global",
    /// null)`. Verify the port preserves that as `None` rather than defaulting to some
    /// symbol type.
    #[test]
    fn root_category_has_no_symbol_type() {
        assert_eq!(SymbolCategory::ROOT_CATEGORY.get_name(), "Global");
        assert_eq!(SymbolCategory::ROOT_CATEGORY.get_symbol_type(), None);
    }

    #[test]
    fn namespace_category_uses_namespace_symbol_type() {
        assert_eq!(SymbolCategory::NAMESPACE_CATEGORY.get_name(), "Namespaces");
        assert_eq!(
            SymbolCategory::NAMESPACE_CATEGORY.get_symbol_type(),
            Some(SymbolType::Namespace)
        );
    }

    #[test]
    fn class_category_uses_class_symbol_type() {
        assert_eq!(SymbolCategory::CLASS_CATEGORY.get_name(), "Classes");
        assert_eq!(
            SymbolCategory::CLASS_CATEGORY.get_symbol_type(),
            Some(SymbolType::Class)
        );
    }

    #[test]
    fn display_matches_name() {
        assert_eq!(SymbolCategory::FUNCTION_CATEGORY.to_string(), "Functions");
        assert_eq!(SymbolCategory::ROOT_CATEGORY.to_string(), "Global");
    }

    #[test]
    fn categories_with_same_fields_are_equal() {
        assert_eq!(
            SymbolCategory::FUNCTION_CATEGORY,
            SymbolCategory::FUNCTION_CATEGORY
        );
        assert_ne!(SymbolCategory::FUNCTION_CATEGORY, SymbolCategory::LABEL_CATEGORY);
    }
}
