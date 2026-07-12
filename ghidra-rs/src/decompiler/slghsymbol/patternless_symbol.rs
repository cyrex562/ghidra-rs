//! Models `ghidra.pcodeCPort.slghsymbol.PatternlessSymbol`.

use super::sleigh_symbol::SleighSymbol;
use crate::decompiler::seam_stubs::PatternExpression;
use crate::decompiler::slghpatexpress::ConstantValue;
use crate::decompiler::slghsymbol::triple_symbol::TripleSymbol;
use crate::sleigh::grammar::location::Location;

/// A symbol that behaves like a constant zero pattern expression.
///
/// This abstract class provides a pattern expression that always matches the constant 0,
/// used as a base for symbols that don't require pattern matching (like epsilon symbols
/// or varnode symbols). Concrete subclasses must implement [`SpecificSymbol::get_varnode`]
/// to be fully instantiable.
///
/// Models `ghidra.pcodeCPort.slghsymbol.PatternlessSymbol`.
pub struct PatternlessSymbol {
    symbol: SleighSymbol,
    patexp: ConstantValue,
}

impl PatternlessSymbol {
    /// Creates a new patternless symbol at the given location.
    pub fn new(location: Location) -> Self {
        Self {
            symbol: SleighSymbol::new(location.clone()),
            patexp: ConstantValue::new(location),
        }
    }

    /// Creates a new patternless symbol with a name at the given location.
    pub fn with_name(location: Location, name: impl Into<String>) -> Self {
        Self {
            symbol: SleighSymbol::with_name(location.clone(), name),
            patexp: ConstantValue::new(location),
        }
    }

    /// Gets a reference to the base SleighSymbol.
    pub fn symbol(&self) -> &SleighSymbol {
        &self.symbol
    }

    /// Gets a mutable reference to the base SleighSymbol.
    pub fn symbol_mut(&mut self) -> &mut SleighSymbol {
        &mut self.symbol
    }

    /// Gets the pattern expression (constant 0).
    pub fn get_pattern_expression(&self) -> Box<dyn PatternExpression> {
        Box::new(self.patexp.clone())
    }

    /// Gets the name of this symbol.
    pub fn name(&self) -> &str {
        self.symbol.name()
    }
}

impl TripleSymbol for PatternlessSymbol {
    fn get_pattern_expression(&self) -> Box<dyn PatternExpression> {
        self.get_pattern_expression()
    }
}

impl Clone for PatternlessSymbol {
    fn clone(&self) -> Self {
        Self {
            symbol: SleighSymbol::new(self.symbol.location().clone()),
            patexp: self.patexp.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc() -> Location {
        Location::new("test.sla", 10)
    }

    #[test]
    fn new_creates_unnamed_symbol() {
        let pls = PatternlessSymbol::new(loc());
        assert_eq!(pls.name(), "");
    }

    #[test]
    fn with_name_sets_name() {
        let pls = PatternlessSymbol::with_name(loc(), "my_symbol");
        assert_eq!(pls.name(), "my_symbol");
    }

    #[test]
    fn get_pattern_expression_returns_boxed_pattern() {
        let pls = PatternlessSymbol::new(loc());
        let _pattern = pls.get_pattern_expression();
    }

    #[test]
    fn triple_symbol_trait_provides_pattern_expression() {
        let pls = PatternlessSymbol::new(loc());
        let dyn_symbol: &dyn TripleSymbol = &pls;
        let _pattern = dyn_symbol.get_pattern_expression();
    }

    #[test]
    fn clone_creates_independent_instance() {
        let pls1 = PatternlessSymbol::with_name(loc(), "original");
        let pls2 = pls1.clone();
        assert_eq!(pls1.name(), pls2.name());
    }

    #[test]
    fn get_size_defaults_to_zero() {
        let pls = PatternlessSymbol::new(loc());
        let dyn_symbol: &dyn TripleSymbol = &pls;
        assert_eq!(dyn_symbol.get_size(), 0);
    }

    #[test]
    fn collect_local_values_does_nothing_by_default() {
        let pls = PatternlessSymbol::new(loc());
        let mut results = vec![];
        let dyn_symbol: &dyn TripleSymbol = &pls;
        dyn_symbol.collect_local_values(&mut results);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn symbol_accessor_provides_base_symbol() {
        let pls = PatternlessSymbol::with_name(loc(), "test_sym");
        let sym = pls.symbol();
        assert_eq!(sym.name(), "test_sym");
    }

    #[test]
    fn symbol_mut_allows_modification() {
        let mut pls = PatternlessSymbol::new(loc());
        pls.symbol_mut().set_was_sought(true);
        assert!(pls.symbol().was_sought());
    }
}
