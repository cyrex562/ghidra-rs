use crate::program::model::listing::Program;
use crate::program::model::symbol::Symbol;
use std::sync::Arc;

/// A filter for symbols used in the symbol table UI.
///
/// Port of `ghidra.app.plugin.core.symtable.SymbolFilter`.
pub trait SymbolFilter: Send + Sync {
    /// Check if this symbol is accepted by the filter.
    ///
    /// # Arguments
    /// * `symbol` - The symbol to check
    /// * `program` - The program containing the symbol
    ///
    /// # Returns
    /// true if the symbol passes this filter, false otherwise
    fn accepts(&self, symbol: Arc<dyn Symbol>, program: &dyn Program) -> bool;

    /// Check if this filter accepts only code symbols.
    ///
    /// # Returns
    /// true if this filter only accepts code symbols, false otherwise
    fn accepts_only_code_symbols(&self) -> bool;

    /// Check if this filter accepts default label symbols.
    ///
    /// # Returns
    /// true if this filter accepts default label symbols, false otherwise
    fn accepts_default_label_symbols(&self) -> bool;

    /// Check if this filter accepts all symbols.
    ///
    /// # Returns
    /// true if this filter accepts all symbols (no filtering), false otherwise
    fn accepts_all(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct AllAcceptingFilter;

    impl SymbolFilter for AllAcceptingFilter {
        fn accepts(&self, _symbol: Arc<dyn Symbol>, _program: &dyn Program) -> bool {
            true
        }

        fn accepts_only_code_symbols(&self) -> bool {
            false
        }

        fn accepts_default_label_symbols(&self) -> bool {
            true
        }

        fn accepts_all(&self) -> bool {
            true
        }
    }

    #[test]
    fn test_accepts_all_filter() {
        let filter = AllAcceptingFilter;
        assert!(filter.accepts_all());
        assert!(!filter.accepts_only_code_symbols());
        assert!(filter.accepts_default_label_symbols());
    }

    struct CodeOnlyFilter;

    impl SymbolFilter for CodeOnlyFilter {
        fn accepts(&self, _symbol: Arc<dyn Symbol>, _program: &dyn Program) -> bool {
            true
        }

        fn accepts_only_code_symbols(&self) -> bool {
            true
        }

        fn accepts_default_label_symbols(&self) -> bool {
            false
        }

        fn accepts_all(&self) -> bool {
            false
        }
    }

    #[test]
    fn test_code_only_filter() {
        let filter = CodeOnlyFilter;
        assert!(filter.accepts_only_code_symbols());
        assert!(!filter.accepts_default_label_symbols());
        assert!(!filter.accepts_all());
    }

    struct NoDefaultLabelsFilter;

    impl SymbolFilter for NoDefaultLabelsFilter {
        fn accepts(&self, _symbol: Arc<dyn Symbol>, _program: &dyn Program) -> bool {
            true
        }

        fn accepts_only_code_symbols(&self) -> bool {
            false
        }

        fn accepts_default_label_symbols(&self) -> bool {
            false
        }

        fn accepts_all(&self) -> bool {
            false
        }
    }

    #[test]
    fn test_no_default_labels_filter() {
        let filter = NoDefaultLabelsFilter;
        assert!(!filter.accepts_only_code_symbols());
        assert!(!filter.accepts_default_label_symbols());
        assert!(!filter.accepts_all());
    }
}
