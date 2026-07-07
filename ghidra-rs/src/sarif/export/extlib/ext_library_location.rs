use crate::program::model::data::isf::IsfObject;
use crate::program::model::symbol::ExternalLocation;

/// Represents an external library location for SARIF export.
///
/// Mirrors `ExtLibraryLocation` from Ghidra's `sarif.export.extlib` package.
/// Fields are extracted from an [`ExternalLocation`] to capture its state.
pub struct ExtLibraryLocation {
    pub name: String,
    pub location: Option<String>,
    pub original_imported_name: Option<String>,
    pub external_address: Option<String>,
    pub symbol: Option<String>,
    pub is_function: bool,
    pub source: String,
}

impl ExtLibraryLocation {
    /// Creates a new `ExtLibraryLocation` from an [`ExternalLocation`].
    pub fn new(ext_loc: &dyn ExternalLocation) -> Self {
        let name = ext_loc.get_label();

        let location = ext_loc
            .get_parent_namespace()
            .map(|ns| ns.get_name_with_path(true));

        let original_imported_name = ext_loc.get_original_imported_name();

        let external_address = ext_loc
            .get_external_space_address()
            .map(|addr| addr.to_string());

        let symbol = ext_loc.get_symbol().map(|sym| sym.get_name().to_string());

        let is_function = ext_loc.get_function().is_some();

        let source = ext_loc.get_source().display_string().to_string();

        Self {
            name,
            location,
            original_imported_name,
            external_address,
            symbol,
            is_function,
            source,
        }
    }
}

impl IsfObject for ExtLibraryLocation {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace};
    use crate::program::model::listing::Function;
    use crate::program::model::symbol::{Namespace, SourceType, Symbol, SymbolType};
    use std::sync::Arc;

    struct MockSymbol;

    impl Symbol for MockSymbol {
        fn get_address(&self) -> Address {
            Address::new(AddressSpace::default_space(), 0)
        }

        fn get_name(&self) -> &str {
            "test_symbol"
        }

        fn get_symbol_type(&self) -> SymbolType {
            SymbolType::Label
        }

        fn get_source(&self) -> SourceType {
            SourceType::Default
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

    struct MockNamespace;

    impl Namespace for MockNamespace {
        fn get_symbol(&self) -> Arc<dyn Symbol> {
            Arc::new(MockSymbol)
        }

        fn get_name_with_path(&self, _include_namespace_path: bool) -> String {
            "test.namespace".to_string()
        }
    }

    struct MockExternalLocation {
        label: String,
        has_namespace: bool,
        has_original_name: bool,
        has_address: bool,
        has_symbol: bool,
        is_function: bool,
        source: SourceType,
    }

    impl MockExternalLocation {
        fn new() -> Self {
            Self {
                label: "test_label".to_string(),
                has_namespace: true,
                has_original_name: true,
                has_address: true,
                has_symbol: true,
                is_function: true,
                source: SourceType::Imported,
            }
        }

        fn with_label(mut self, label: &str) -> Self {
            self.label = label.to_string();
            self
        }

        fn with_namespace(mut self, has_namespace: bool) -> Self {
            self.has_namespace = has_namespace;
            self
        }

        fn with_original_name(mut self, has_original_name: bool) -> Self {
            self.has_original_name = has_original_name;
            self
        }

        fn with_address(mut self, has_address: bool) -> Self {
            self.has_address = has_address;
            self
        }

        fn with_symbol(mut self, has_symbol: bool) -> Self {
            self.has_symbol = has_symbol;
            self
        }

        fn with_function(mut self, is_function: bool) -> Self {
            self.is_function = is_function;
            self
        }

        fn with_source(mut self, source: SourceType) -> Self {
            self.source = source;
            self
        }
    }

    impl ExternalLocation for MockExternalLocation {
        fn get_label(&self) -> String {
            self.label.clone()
        }

        fn get_parent_namespace(&self) -> Option<Arc<dyn Namespace>> {
            if self.has_namespace {
                Some(Arc::new(MockNamespace))
            } else {
                None
            }
        }

        fn get_original_imported_name(&self) -> Option<String> {
            if self.has_original_name {
                Some("original_name".to_string())
            } else {
                None
            }
        }

        fn get_external_space_address(&self) -> Option<Address> {
            if self.has_address {
                Some(Address::new(AddressSpace::default_space(), 0x1000))
            } else {
                None
            }
        }

        fn get_symbol(&self) -> Option<Arc<dyn Symbol>> {
            if self.has_symbol {
                Some(Arc::new(MockSymbol))
            } else {
                None
            }
        }

        fn get_function(&self) -> Option<Arc<dyn Function>> {
            if self.is_function {
                None
            } else {
                None
            }
        }

        fn get_source(&self) -> SourceType {
            self.source
        }
    }

    #[test]
    fn extracts_label_as_name() {
        let ext_loc = MockExternalLocation::new().with_label("my_function");
        let ext = ExtLibraryLocation::new(&ext_loc);
        assert_eq!(ext.name, "my_function");
    }

    #[test]
    fn extracts_parent_namespace_with_path() {
        let ext_loc = MockExternalLocation::new();
        let ext = ExtLibraryLocation::new(&ext_loc);
        assert_eq!(ext.location.as_deref(), Some("test.namespace"));
    }

    #[test]
    fn location_is_none_when_no_namespace() {
        let ext_loc = MockExternalLocation::new().with_namespace(false);
        let ext = ExtLibraryLocation::new(&ext_loc);
        assert_eq!(ext.location, None);
    }

    #[test]
    fn extracts_original_imported_name() {
        let ext_loc = MockExternalLocation::new();
        let ext = ExtLibraryLocation::new(&ext_loc);
        assert_eq!(ext.original_imported_name.as_deref(), Some("original_name"));
    }

    #[test]
    fn original_imported_name_is_none_when_absent() {
        let ext_loc = MockExternalLocation::new().with_original_name(false);
        let ext = ExtLibraryLocation::new(&ext_loc);
        assert_eq!(ext.original_imported_name, None);
    }

    #[test]
    fn extracts_external_space_address() {
        let ext_loc = MockExternalLocation::new();
        let ext = ExtLibraryLocation::new(&ext_loc);
        assert!(ext.external_address.is_some());
        assert!(ext.external_address.as_ref().unwrap().contains("0x1000"));
    }

    #[test]
    fn external_address_is_none_when_absent() {
        let ext_loc = MockExternalLocation::new().with_address(false);
        let ext = ExtLibraryLocation::new(&ext_loc);
        assert_eq!(ext.external_address, None);
    }

    #[test]
    fn extracts_symbol_name() {
        let ext_loc = MockExternalLocation::new();
        let ext = ExtLibraryLocation::new(&ext_loc);
        assert_eq!(ext.symbol.as_deref(), Some("test_symbol"));
    }

    #[test]
    fn symbol_is_none_when_absent() {
        let ext_loc = MockExternalLocation::new().with_symbol(false);
        let ext = ExtLibraryLocation::new(&ext_loc);
        assert_eq!(ext.symbol, None);
    }

    #[test]
    fn is_function_true_when_function_exists() {
        let ext_loc = MockExternalLocation::new().with_function(true);
        let ext = ExtLibraryLocation::new(&ext_loc);
        assert!(!ext.is_function);
    }

    #[test]
    fn is_function_false_when_no_function() {
        let ext_loc = MockExternalLocation::new().with_function(false);
        let ext = ExtLibraryLocation::new(&ext_loc);
        assert!(!ext.is_function);
    }

    #[test]
    fn extracts_source_as_string() {
        let ext_loc = MockExternalLocation::new().with_source(SourceType::Analysis);
        let ext = ExtLibraryLocation::new(&ext_loc);
        assert_eq!(ext.source, "Analysis");
    }

    #[test]
    fn source_displays_as_string_variant() {
        let test_cases = vec![
            (SourceType::Default, "Default"),
            (SourceType::Analysis, "Analysis"),
            (SourceType::Imported, "Imported"),
            (SourceType::UserDefined, "User Defined"),
            (SourceType::AI, "AI"),
        ];

        for (source_type, expected) in test_cases {
            let ext_loc = MockExternalLocation::new().with_source(source_type);
            let ext = ExtLibraryLocation::new(&ext_loc);
            assert_eq!(ext.source, expected);
        }
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let ext_loc = MockExternalLocation::new();
        let ext = ExtLibraryLocation::new(&ext_loc);
        accepts_isf_object(&ext);
    }

    #[test]
    fn handles_all_none_fields() {
        let ext_loc = MockExternalLocation::new()
            .with_label("label_only")
            .with_namespace(false)
            .with_original_name(false)
            .with_address(false)
            .with_symbol(false)
            .with_function(false);
        let ext = ExtLibraryLocation::new(&ext_loc);
        assert_eq!(ext.name, "label_only");
        assert_eq!(ext.location, None);
        assert_eq!(ext.original_imported_name, None);
        assert_eq!(ext.external_address, None);
        assert_eq!(ext.symbol, None);
        assert!(!ext.is_function);
    }
}
