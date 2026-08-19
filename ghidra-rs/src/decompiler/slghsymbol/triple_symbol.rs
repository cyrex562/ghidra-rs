//! Models `ghidra.pcodeCPort.slghsymbol.TripleSymbol`.

use crate::decompiler::seam_stubs::PatternExpression;

/// The central sleigh object for pattern matching and semantics.
///
/// This is an abstract type that serves as the base for symbols that can be used in the triple
/// (token, context, semantic) of a SLEIGH rule. Implementations provide pattern expressions for
/// matching and a size for alignment/layout.
///
/// Models the abstract class `ghidra.pcodeCPort.slghsymbol.TripleSymbol`.
pub trait TripleSymbol: Send + Sync {
    /// Gets the pattern expression for this symbol.
    ///
    /// Subclasses must implement this to provide the pattern used during parsing or matching.
    fn get_pattern_expression(&self) -> Box<dyn PatternExpression>;

    /// Returns the size of this symbol outside of any specific context.
    ///
    /// The default is 0 (no inherent size; context determines it). Subclasses may override.
    fn get_size(&self) -> i32 {
        0
    }

    /// Collects local value exports from this symbol.
    ///
    /// By default, a symbol has no local value exports (the vector is not modified).
    /// Subclasses that define context modifications may override to populate the vector.
    fn collect_local_values(&self, _results: &mut Vec<i64>) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPattern;
    impl PatternExpression for MockPattern {}

    struct TestSymbol;
    impl TripleSymbol for TestSymbol {
        fn get_pattern_expression(&self) -> Box<dyn PatternExpression> {
            Box::new(MockPattern)
        }
    }

    #[test]
    fn get_pattern_expression_works() {
        let symbol = TestSymbol;
        let _pattern = symbol.get_pattern_expression();
    }

    #[test]
    fn get_size_defaults_to_zero() {
        let symbol = TestSymbol;
        assert_eq!(symbol.get_size(), 0);
    }

    #[test]
    fn collect_local_values_does_nothing_by_default() {
        let symbol = TestSymbol;
        let mut results = vec![];
        symbol.collect_local_values(&mut results);
        assert_eq!(results.len(), 0);
    }

    struct CustomSizeSymbol;
    impl TripleSymbol for CustomSizeSymbol {
        fn get_pattern_expression(&self) -> Box<dyn PatternExpression> {
            Box::new(MockPattern)
        }

        fn get_size(&self) -> i32 {
            42
        }
    }

    #[test]
    fn get_size_can_be_overridden() {
        let symbol = CustomSizeSymbol;
        assert_eq!(symbol.get_size(), 42);
    }

    struct ExportingSymbol;
    impl TripleSymbol for ExportingSymbol {
        fn get_pattern_expression(&self) -> Box<dyn PatternExpression> {
            Box::new(MockPattern)
        }

        fn collect_local_values(&self, results: &mut Vec<i64>) {
            results.push(1);
            results.push(2);
        }
    }

    #[test]
    fn collect_local_values_can_be_overridden() {
        let symbol = ExportingSymbol;
        let mut results = vec![];
        symbol.collect_local_values(&mut results);
        assert_eq!(results, vec![1, 2]);
    }
}
