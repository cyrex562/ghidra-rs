//! Models `ghidra.pcodeCPort.slghsymbol.SpecificSymbol`.

use super::triple_symbol::TripleSymbol;
use crate::program::model::lang::sleigh::template::VarnodeTpl;

/// A symbol that resolves to a concrete varnode during constructor semantics (as opposed to
/// symbols that only participate in parsing/printing).
///
/// Models the abstract class `ghidra.pcodeCPort.slghsymbol.SpecificSymbol`, which extends
/// `TripleSymbol`.
pub trait SpecificSymbol: TripleSymbol {
    /// The varnode template this symbol resolves to.
    fn get_varnode(&self) -> Box<VarnodeTpl>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::seam_stubs::PatternExpression;
    use crate::program::model::lang::sleigh::template::ConstTpl;

    struct MockPattern;
    impl PatternExpression for MockPattern {}

    struct FixedSymbol;
    impl TripleSymbol for FixedSymbol {
        fn get_pattern_expression(&self) -> Box<dyn PatternExpression> {
            Box::new(MockPattern)
        }
    }

    impl SpecificSymbol for FixedSymbol {
        fn get_varnode(&self) -> Box<VarnodeTpl> {
            Box::new(VarnodeTpl {
                space: ConstTpl::new(),
                offset: ConstTpl::new(),
                size: ConstTpl::new(),
            })
        }
    }

    #[test]
    fn get_varnode_returns_varnode_tpl() {
        let symbol = FixedSymbol;
        let dyn_symbol: &dyn SpecificSymbol = &symbol;
        let _varnode = dyn_symbol.get_varnode();
    }

    #[test]
    fn triple_symbol_methods_are_implemented() {
        let symbol = FixedSymbol;
        let _pattern = symbol.get_pattern_expression();
        assert_eq!(symbol.get_size(), 0);
        let mut values = vec![];
        symbol.collect_local_values(&mut values);
        assert_eq!(values.len(), 0);
    }
}
