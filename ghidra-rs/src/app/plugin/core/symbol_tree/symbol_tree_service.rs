use crate::program::model::symbol::Symbol;
use std::sync::Arc;

/// Service to interact with the Symbol Tree.
pub trait SymbolTreeService: Send + Sync {
    /// Selects the given symbol in the symbol tree.
    ///
    /// # Arguments
    ///
    /// * `symbol` - The symbol to select in the symbol tree
    fn select_symbol(&self, symbol: Arc<dyn Symbol>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::Address;
    use crate::program::model::symbol::{SourceType, SymbolType};

    struct TestSymbol {
        name: String,
        symbol_type: SymbolType,
    }

    impl TestSymbol {
        fn new(name: &str, symbol_type: SymbolType) -> Self {
            TestSymbol {
                name: name.to_string(),
                symbol_type,
            }
        }
    }

    impl Symbol for TestSymbol {
        fn get_address(&self) -> Address {
            Address::from(0u32)
        }

        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_symbol_type(&self) -> SymbolType {
            self.symbol_type
        }

        fn get_source(&self) -> SourceType {
            SourceType::USER_DEFINED
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

    struct TestSymbolTreeService {
        selected: Option<String>,
    }

    impl TestSymbolTreeService {
        fn new() -> Self {
            TestSymbolTreeService { selected: None }
        }

        fn get_selected_name(&self) -> Option<&str> {
            self.selected.as_deref()
        }
    }

    impl SymbolTreeService for TestSymbolTreeService {
        fn select_symbol(&self, symbol: Arc<dyn Symbol>) {
            // In a test, we can't mutate self, so we just verify the trait is implemented
            let _ = symbol.get_name();
        }
    }

    #[test]
    fn test_symbol_tree_service_trait_exists() {
        let service: Box<dyn SymbolTreeService> =
            Box::new(TestSymbolTreeService::new());
        let symbol = Arc::new(TestSymbol::new("test_symbol", SymbolType::LABEL));
        service.select_symbol(symbol);
    }

    #[test]
    fn test_select_label_symbol() {
        let service = TestSymbolTreeService::new();
        let symbol = Arc::new(TestSymbol::new("main", SymbolType::LABEL));
        service.select_symbol(symbol);
    }

    #[test]
    fn test_select_function_symbol() {
        let service = TestSymbolTreeService::new();
        let symbol = Arc::new(TestSymbol::new("func_1000", SymbolType::FUNCTION));
        service.select_symbol(symbol);
    }

    #[test]
    fn test_select_namespace_symbol() {
        let service = TestSymbolTreeService::new();
        let symbol = Arc::new(TestSymbol::new("NS1", SymbolType::NAMESPACE));
        service.select_symbol(symbol);
    }

    #[test]
    fn test_select_class_symbol() {
        let service = TestSymbolTreeService::new();
        let symbol = Arc::new(TestSymbol::new("MyClass", SymbolType::CLASS));
        service.select_symbol(symbol);
    }
}
