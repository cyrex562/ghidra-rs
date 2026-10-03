//! Port of `sarif.export.symbols.ExtSymbol`.

use crate::program::model::data::isf::IsfObject;
use crate::program::model::symbol::{NamespaceType, SourceType, Symbol, SymbolType};

/// Mirrors `SourceType.toString()` -- the Java `enum`'s *default*, unoverridden `toString()`,
/// which returns the declared constant name (`"DEFAULT"`, `"USER_DEFINED"`, ...), not the
/// human-readable string [`SourceType::display_string`] returns (`"Default"`, `"User Defined"`,
/// ...; that one mirrors the distinct, explicitly-defined `SourceType.getDisplayString()`).
/// `ExtSymbol` specifically calls the former (`symbol.getSource().toString()`).
fn source_type_enum_name(source: SourceType) -> &'static str {
    match source {
        SourceType::Default => "DEFAULT",
        SourceType::Analysis => "ANALYSIS",
        SourceType::AI => "AI",
        SourceType::Imported => "IMPORTED",
        SourceType::UserDefined => "USER_DEFINED",
    }
}

/// A symbol, extended with SARIF-export-specific fields.
///
/// Port of `sarif.export.symbols.ExtSymbol`.
pub struct ExtSymbol {
    pub name: String,
    pub location: String,
    pub namespace_is_class: Option<bool>,
    pub kind: String,
    pub r#type: Option<String>,
    pub source_type: String,
    pub primary: bool,
    pub pinned: bool,
}

impl ExtSymbol {
    /// Constructs an `ExtSymbol` describing `symbol`.
    ///
    /// Port of `ExtSymbol(Symbol symbol)`.
    ///
    /// # `instanceof` checks become `get_symbol_type()`/`get_type()` comparisons
    ///
    /// Java's `symbol instanceof ClassSymbol`/`LibrarySymbol`/`NamespaceSymbol` (and, inside
    /// [`namespace_string`], `namespace instanceof GhidraClass`) are reproduced via
    /// [`Symbol::get_symbol_type`]/[`crate::program::model::symbol::Namespace::get_type`]
    /// comparisons rather than trait-object downcasting: each of those concrete Java classes
    /// exists specifically to return one fixed [`SymbolType`]/[`NamespaceType`] from its
    /// `getSymbolType()`/`getType()` override (already ported that way -- see e.g.
    /// `ClassSymbol`/`LibrarySymbol`/`NamespaceSymbol`'s own trait docs in
    /// `program::database::symbol`, and [`GhidraClass::get_type`]'s default), so the comparison
    /// is exactly equivalent for every real implementor and needs no downcasting machinery.
    ///
    /// # Preserved quirk: `type` is never set to `"function"`
    ///
    /// Java explicitly does *not* add a `FunctionSymbol` branch (`type == "function"`), with the
    /// comment `// NB: DO NOT add type==function, as this will affect the execution order`. This
    /// is preserved as-is: a `Symbol` whose [`Symbol::get_symbol_type`] is
    /// [`SymbolType::Function`] leaves [`ExtSymbol::r#type`] as `None`, exactly like any other
    /// symbol kind not covered by the three checks below.
    pub fn new(symbol: &dyn Symbol) -> Self {
        let name = symbol.get_name().to_string();
        let mut namespace_is_class = None;
        let location = namespace_string(symbol, &mut namespace_is_class);
        let kind = if check_global(symbol) { "global" } else { "local" }.to_string();
        let source_type = source_type_enum_name(symbol.get_source()).to_string();
        let primary = symbol.is_primary();
        let pinned = symbol.is_pinned();

        let r#type = match symbol.get_symbol_type() {
            SymbolType::Class => Some("class".to_string()),
            SymbolType::Library => Some("library".to_string()),
            SymbolType::Namespace => Some("namespace".to_string()),
            _ => None,
        };

        ExtSymbol { name, location, namespace_is_class, kind, r#type, source_type, primary, pinned }
    }
}

impl IsfObject for ExtSymbol {}

/// Returns the name of `symbol` qualified with any namespace information, e.g.
/// `"User32.dll::SomeClass::"`. Sets `*namespace_is_class` to `Some(true)` if any ancestor
/// namespace walked is a [`GhidraClass`](crate::program::model::listing::GhidraClass); left
/// untouched (`None`) otherwise -- mirroring Java's `Boolean namespaceIsClass` field, which is
/// only ever assigned `true`, never `false`.
///
/// Port of the private `getNamespace(Symbol)`.
fn namespace_string(symbol: &dyn Symbol, namespace_is_class: &mut Option<bool>) -> String {
    let mut segments: Vec<String> = Vec::new();
    // Java's `symbol.getParentNamespace()` is documented to never return null (it returns the
    // global namespace itself for a top-level symbol); this port's `Symbol::get_parent_namespace`
    // defaults to `None` for not-yet-wired-up implementors, which is treated the same as already
    // being at the global namespace (matching `Symbol::is_global`'s own default -- see its docs).
    let mut current = symbol.get_parent_namespace();
    while let Some(namespace) = current {
        if namespace.is_global() {
            break;
        }
        segments.insert(0, format!("{}::", namespace.get_name()));
        if namespace.get_type() == NamespaceType::Class {
            *namespace_is_class = Some(true);
        }
        current = namespace.get_parent_namespace();
    }
    segments.concat()
}

/// Port of the private `checkGlobal(Symbol)`.
fn check_global(symbol: &dyn Symbol) -> bool {
    if symbol.is_global() {
        return true;
    }
    match symbol.get_parent_namespace() {
        Some(parent) => parent.is_library(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::Namespace;
    use std::sync::Arc;

    fn test_addr() -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, 0x1000)
    }

    struct MockSymbol {
        name: String,
        symbol_type: SymbolType,
        source: SourceType,
        primary: bool,
        pinned: bool,
        is_global: bool,
        parent: Option<Arc<dyn Namespace>>,
    }

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            test_addr()
        }
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_symbol_type(&self) -> SymbolType {
            self.symbol_type
        }
        fn get_source(&self) -> SourceType {
            self.source
        }
        fn is_primary(&self) -> bool {
            self.primary
        }
        fn get_id(&self) -> i64 {
            0
        }
        fn get_parent_id(&self) -> i64 {
            -1
        }
        fn is_pinned(&self) -> bool {
            self.pinned
        }
        fn is_global(&self) -> bool {
            self.is_global
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent.clone()
        }
    }

    fn plain_symbol(name: &str, symbol_type: SymbolType) -> MockSymbol {
        MockSymbol {
            name: name.to_string(),
            symbol_type,
            source: SourceType::UserDefined,
            primary: true,
            pinned: false,
            is_global: true,
            parent: None,
        }
    }

    struct MockNamespace {
        name: String,
        symbol_type: SymbolType,
        namespace_type: NamespaceType,
        is_global: bool,
        parent: Option<Arc<dyn Namespace>>,
    }

    impl Namespace for MockNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol {
                name: self.name.clone(),
                symbol_type: self.symbol_type,
                source: SourceType::UserDefined,
                primary: true,
                pinned: false,
                is_global: self.is_global,
                parent: self.parent.clone(),
            })
        }
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            self.parent.clone()
        }
        fn get_id(&self) -> i64 {
            if self.is_global {
                crate::program::model::symbol::GLOBAL_NAMESPACE_ID
            } else {
                42
            }
        }
        fn is_global(&self) -> bool {
            self.is_global
        }
        fn get_type(&self) -> NamespaceType {
            self.namespace_type
        }
    }

    fn global_namespace() -> Arc<dyn Namespace> {
        Arc::new(MockNamespace {
            name: "Global".to_string(),
            symbol_type: SymbolType::Namespace,
            namespace_type: NamespaceType::Namespace,
            is_global: true,
            parent: None,
        })
    }

    #[test]
    fn source_type_enum_name_matches_java_default_tostring() {
        assert_eq!(source_type_enum_name(SourceType::Default), "DEFAULT");
        assert_eq!(source_type_enum_name(SourceType::Analysis), "ANALYSIS");
        assert_eq!(source_type_enum_name(SourceType::AI), "AI");
        assert_eq!(source_type_enum_name(SourceType::Imported), "IMPORTED");
        assert_eq!(source_type_enum_name(SourceType::UserDefined), "USER_DEFINED");
    }

    #[test]
    fn label_symbol_at_global_scope_has_no_type_and_empty_location() {
        let symbol = plain_symbol("main", SymbolType::Label);
        let ext = ExtSymbol::new(&symbol);

        assert_eq!(ext.name, "main");
        assert_eq!(ext.location, "");
        assert_eq!(ext.r#type, None);
        assert_eq!(ext.kind, "global");
        assert_eq!(ext.namespace_is_class, None);
        assert_eq!(ext.source_type, "USER_DEFINED");
        assert!(ext.primary);
        assert!(!ext.pinned);
    }

    #[test]
    fn class_symbol_type_is_class() {
        let symbol = plain_symbol("MyClass", SymbolType::Class);
        let ext = ExtSymbol::new(&symbol);
        assert_eq!(ext.r#type, Some("class".to_string()));
    }

    #[test]
    fn library_symbol_type_is_library() {
        let symbol = plain_symbol("user32.dll", SymbolType::Library);
        let ext = ExtSymbol::new(&symbol);
        assert_eq!(ext.r#type, Some("library".to_string()));
    }

    #[test]
    fn namespace_symbol_type_is_namespace() {
        let symbol = plain_symbol("ns", SymbolType::Namespace);
        let ext = ExtSymbol::new(&symbol);
        assert_eq!(ext.r#type, Some("namespace".to_string()));
    }

    #[test]
    fn function_symbol_type_is_never_set_matching_java_quirk() {
        // Java deliberately never assigns type == "function" (see the NB comment in the source);
        // this preserves that exactly.
        let symbol = plain_symbol("foo", SymbolType::Function);
        let ext = ExtSymbol::new(&symbol);
        assert_eq!(ext.r#type, None);
    }

    #[test]
    fn nested_namespace_builds_qualified_location_string() {
        let lib = Arc::new(MockNamespace {
            name: "User32.dll".to_string(),
            symbol_type: SymbolType::Library,
            namespace_type: NamespaceType::Library,
            is_global: false,
            parent: Some(global_namespace()),
        });
        let class_ns: Arc<dyn Namespace> = Arc::new(MockNamespace {
            name: "SomeClass".to_string(),
            symbol_type: SymbolType::Class,
            namespace_type: NamespaceType::Class,
            is_global: false,
            parent: Some(lib.clone()),
        });

        let symbol = MockSymbol {
            name: "printf".to_string(),
            symbol_type: SymbolType::Label,
            source: SourceType::Imported,
            primary: true,
            pinned: false,
            is_global: false,
            parent: Some(class_ns),
        };

        let ext = ExtSymbol::new(&symbol);
        assert_eq!(ext.location, "User32.dll::SomeClass::");
        assert_eq!(ext.namespace_is_class, Some(true));
    }

    #[test]
    fn namespace_is_class_none_when_no_class_ancestor() {
        let lib: Arc<dyn Namespace> = Arc::new(MockNamespace {
            name: "User32.dll".to_string(),
            symbol_type: SymbolType::Library,
            namespace_type: NamespaceType::Library,
            is_global: false,
            parent: Some(global_namespace()),
        });

        let symbol = MockSymbol {
            name: "printf".to_string(),
            symbol_type: SymbolType::Label,
            source: SourceType::Imported,
            primary: true,
            pinned: false,
            is_global: false,
            parent: Some(lib),
        };

        let ext = ExtSymbol::new(&symbol);
        assert_eq!(ext.location, "User32.dll::");
        assert_eq!(ext.namespace_is_class, None);
    }

    #[test]
    fn check_global_true_for_symbol_directly_in_a_library() {
        let lib: Arc<dyn Namespace> = Arc::new(MockNamespace {
            name: "User32.dll".to_string(),
            symbol_type: SymbolType::Library,
            namespace_type: NamespaceType::Library,
            is_global: false,
            parent: Some(global_namespace()),
        });

        let symbol = MockSymbol {
            name: "printf".to_string(),
            symbol_type: SymbolType::Label,
            source: SourceType::Imported,
            primary: true,
            pinned: false,
            is_global: false,
            parent: Some(lib),
        };

        let ext = ExtSymbol::new(&symbol);
        assert_eq!(ext.kind, "global");
    }

    #[test]
    fn check_global_false_for_local_symbol_in_a_class() {
        let class_ns: Arc<dyn Namespace> = Arc::new(MockNamespace {
            name: "SomeClass".to_string(),
            symbol_type: SymbolType::Class,
            namespace_type: NamespaceType::Class,
            is_global: false,
            parent: Some(global_namespace()),
        });

        let symbol = MockSymbol {
            name: "field".to_string(),
            symbol_type: SymbolType::Label,
            source: SourceType::UserDefined,
            primary: true,
            pinned: false,
            is_global: false,
            parent: Some(class_ns),
        };

        let ext = ExtSymbol::new(&symbol);
        assert_eq!(ext.kind, "local");
    }

    #[test]
    fn pinned_and_source_type_are_captured() {
        let mut symbol = plain_symbol("x", SymbolType::Label);
        symbol.pinned = true;
        symbol.source = SourceType::Analysis;
        let ext = ExtSymbol::new(&symbol);
        assert!(ext.pinned);
        assert_eq!(ext.source_type, "ANALYSIS");
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let symbol = plain_symbol("x", SymbolType::Label);
        let ext = ExtSymbol::new(&symbol);
        accepts_isf_object(&ext);
    }
}
