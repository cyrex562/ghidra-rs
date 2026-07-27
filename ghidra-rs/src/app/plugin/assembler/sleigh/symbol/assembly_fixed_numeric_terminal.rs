//! Mirrors `ghidra.app.plugin.assembler.sleigh.symbol.AssemblyFixedNumericTerminal`.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar;
use crate::app::plugin::assembler::sleigh::symbol::AssemblyNumericTerminal;
use crate::app::plugin::assembler::sleigh::tree::AssemblyParseNumericToken;
use crate::app::seam_stubs::AssemblyNumericSymbols;
use crate::program::model::address::AddressSpace;

/// An [`AssemblyNumericSymbols`] with no labels, standing in for Java's
/// `AssemblyNumericSymbols.EMPTY` singleton (a default-constructed instance with no labels
/// registered). Only used by [`AssemblyFixedNumericTerminal::match_fixed`], which -- like the
/// Java method it mirrors -- deliberately ignores the caller-supplied symbols.
struct EmptyNumericSymbols;

impl AssemblyNumericSymbols for EmptyNumericSymbols {
    fn choose(&self, _name: &str, _space: Option<&AddressSpace>) -> BTreeSet<i64> {
        BTreeSet::new()
    }

    fn get_suggestions(
        &self,
        _got: &str,
        _space: Option<&AddressSpace>,
        _max: usize,
    ) -> Vec<String> {
        Vec::new()
    }
}

/// A terminal that accepts only a particular numeric value.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.symbol.AssemblyFixedNumericTerminal`, a concrete
/// class extending [`AssemblyNumericTerminal`] (itself already a trait, having been cut from the
/// same grammar/terminal/parse-tree dependency cycle this type is now cut for) that adds a single
/// `val: long` field on top of the inherited `name`/`bitsize`/`space`. Unlike a fixed string
/// terminal, this accepts any encoding (decimal, hex, octal) of the given value, not just a
/// literal spelling of it.
///
/// The Java constructor (`AssemblyFixedNumericTerminal(long val)`) fixes `bitsize` to `0`
/// (unbounded) and `space` to `null` by calling `super("" + val, 0, null)` -- properties of a
/// concrete instantiation, not something this trait can enforce, so implementers are expected to
/// return `0`/`None` from the inherited [`AssemblyNumericTerminal::bitsize`]/
/// [`AssemblyNumericTerminal::space`] and `val.to_string()` from their
/// [`AssemblySymbol::terminal_tag`](crate::app::seam_stubs::AssemblySymbol::terminal_tag), matching
/// the Java constructor's `name` argument.
///
/// `toString()`, `getSuggestions(String, AssemblyNumericSymbols)`, and
/// `match(String, int, AssemblyGrammar, AssemblyNumericSymbols)` are all overridden, so --
/// following the same shadowing convention [`AssemblyNumericTerminal`] itself uses for its own
/// overrides of `AssemblyTerminal` -- they're re-modeled here as distinctly-named default methods
/// ([`fixed_display_string`](Self::fixed_display_string),
/// [`get_fixed_suggestions`](Self::get_fixed_suggestions), [`match_fixed`](Self::match_fixed))
/// built on the required [`val`](Self::val) accessor plus the inherited
/// [`AssemblyNumericTerminal::match_numeric`]. A concrete implementer is expected to wire
/// `AssemblyTerminal::match`/`get_suggestions` to these, exactly as a plain
/// `AssemblyNumericTerminal` implementer wires them to `match_numeric`/`get_numeric_suggestions`.
///
/// Java's override deliberately matches against `AssemblyNumericSymbols.EMPTY` rather than the
/// caller-supplied `symbols` (`// TODO: Allow label substitution here? For now, no.`), then
/// filters the result down to tokens whose value equals [`val`](Self::val).
/// [`match_fixed`](Self::match_fixed) reproduces this exactly, using a local empty
/// [`AssemblyNumericSymbols`] implementation in place of the concrete `EMPTY` singleton (which,
/// like the rest of that unported class, this trait has no way to conjure).
pub trait AssemblyFixedNumericTerminal: AssemblyNumericTerminal {
    /// The fixed numeric value this terminal accepts.
    ///
    /// Mirrors `AssemblyFixedNumericTerminal.getVal()` (and the `val` field it returns).
    fn val(&self) -> i64;

    /// Mirrors `AssemblyFixedNumericTerminal.toString()`, which overrides
    /// `AssemblyTerminal.toString()` (via `AssemblySymbol`) to print just the fixed value.
    fn fixed_display_string(&self) -> String {
        self.val().to_string()
    }

    /// Provide the fixed value as the sole suggestion.
    ///
    /// Mirrors `AssemblyFixedNumericTerminal.getSuggestions(String, AssemblyNumericSymbols)`.
    fn get_fixed_suggestions(
        &self,
        _got: &str,
        _symbols: &dyn AssemblyNumericSymbols,
    ) -> Vec<String> {
        vec![self.val().to_string()]
    }

    /// Try to match a numeric literal equal to [`val`](Self::val) at the given position.
    ///
    /// Mirrors `AssemblyFixedNumericTerminal.match(String, int, AssemblyGrammar,
    /// AssemblyNumericSymbols)`, which ignores the caller-supplied `symbols` (matching against
    /// `AssemblyNumericSymbols.EMPTY` instead, disabling label substitution) and filters the
    /// inherited match down to tokens whose numeric value equals [`val`](Self::val).
    fn match_fixed(
        &self,
        buffer: &str,
        pos: usize,
        grammar: Option<&dyn AssemblyGrammar>,
        _symbols: &dyn AssemblyNumericSymbols,
    ) -> Vec<Arc<dyn AssemblyParseNumericToken>> {
        let val = self.val();
        self.match_numeric(buffer, pos, grammar, &EmptyNumericSymbols)
            .into_iter()
            .filter(|tok| tok.get_numeric_value() == val)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::assembler::sleigh::symbol::AssemblyTerminal;
    use crate::app::plugin::assembler::sleigh::tree::AssemblyParseToken;
    use crate::app::seam_stubs::AssemblySymbol;

    struct MockSymbols {
        labels: std::collections::BTreeMap<&'static str, i64>,
    }

    impl AssemblyNumericSymbols for MockSymbols {
        fn choose(&self, name: &str, _space: Option<&AddressSpace>) -> BTreeSet<i64> {
            self.labels.get(name).copied().into_iter().collect()
        }

        fn get_suggestions(
            &self,
            got: &str,
            _space: Option<&AddressSpace>,
            _max: usize,
        ) -> Vec<String> {
            self.labels
                .keys()
                .filter(|k| k.starts_with(got))
                .map(|k| k.to_string())
                .collect()
        }
    }

    fn no_symbols() -> MockSymbols {
        MockSymbols {
            labels: std::collections::BTreeMap::new(),
        }
    }

    struct PlainTerminal(String);

    impl std::fmt::Display for PlainTerminal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl AssemblySymbol for PlainTerminal {
        fn terminal_tag(&self) -> &str {
            &self.0
        }
    }

    impl AssemblyTerminal for PlainTerminal {
        fn r#match(
            &self,
            _buffer: &str,
            _pos: usize,
            _grammar: &dyn AssemblyGrammar,
            _symbols: &dyn AssemblyNumericSymbols,
        ) -> Vec<Arc<dyn AssemblyParseToken>> {
            Vec::new()
        }

        fn get_suggestions(&self, _got: &str, _symbols: &dyn AssemblyNumericSymbols) -> Vec<String> {
            Vec::new()
        }
    }

    #[derive(Clone)]
    struct NumericToken {
        term_tag: String,
        str_val: String,
        val: i64,
    }

    impl AssemblyParseToken for NumericToken {
        fn get_string(&self) -> &str {
            &self.str_val
        }

        fn get_sym(&self) -> Arc<dyn AssemblyTerminal> {
            Arc::new(PlainTerminal(self.term_tag.clone()))
        }
    }

    impl AssemblyParseNumericToken for NumericToken {
        fn get_numeric_value(&self) -> i64 {
            self.val
        }
    }

    struct FixedTerminal {
        tag: String,
        val: i64,
    }

    impl FixedTerminal {
        fn new(val: i64) -> Self {
            Self {
                tag: val.to_string(),
                val,
            }
        }
    }

    impl std::fmt::Display for FixedTerminal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", AssemblyFixedNumericTerminal::fixed_display_string(self))
        }
    }

    impl AssemblySymbol for FixedTerminal {
        fn terminal_tag(&self) -> &str {
            &self.tag
        }
    }

    impl AssemblyTerminal for FixedTerminal {
        fn r#match(
            &self,
            buffer: &str,
            pos: usize,
            grammar: &dyn AssemblyGrammar,
            symbols: &dyn AssemblyNumericSymbols,
        ) -> Vec<Arc<dyn AssemblyParseToken>> {
            self.match_fixed(buffer, pos, Some(grammar), symbols)
                .into_iter()
                .map(|tok| -> Arc<dyn AssemblyParseToken> {
                    Arc::new(NumericToken {
                        term_tag: self.tag.clone(),
                        str_val: tok.get_string().to_string(),
                        val: tok.get_numeric_value(),
                    })
                })
                .collect()
        }

        fn get_suggestions(&self, got: &str, symbols: &dyn AssemblyNumericSymbols) -> Vec<String> {
            self.get_fixed_suggestions(got, symbols)
        }
    }

    impl AssemblyNumericTerminal for FixedTerminal {
        fn bitsize(&self) -> i32 {
            0
        }

        fn space(&self) -> Option<Arc<AddressSpace>> {
            None
        }

        fn make_token(
            &self,
            _grammar: Option<&dyn AssemblyGrammar>,
            str_val: &str,
            num_val: i64,
        ) -> Arc<dyn AssemblyParseNumericToken> {
            Arc::new(NumericToken {
                term_tag: self.tag.clone(),
                str_val: str_val.to_string(),
                val: num_val,
            })
        }
    }

    impl AssemblyFixedNumericTerminal for FixedTerminal {
        fn val(&self) -> i64 {
            self.val
        }
    }

    struct NoopGrammar;
    impl AssemblyGrammar for NoopGrammar {
        fn add_production(&mut self, _prod: Arc<dyn crate::app::seam_stubs::AssemblyProduction>) {}
        fn add_constructor_production(
            &mut self,
            _lhs: Arc<dyn crate::app::seam_stubs::AssemblyNonTerminal>,
            _rhs: Arc<dyn crate::app::seam_stubs::AssemblySentential>,
            _pattern: crate::program::model::lang::sleigh::pattern::DisjointPattern,
            _cons: Arc<dyn crate::app::seam_stubs::Constructor>,
            _indices: Vec<usize>,
        ) {
        }
        fn get_semantics(
            &self,
            _prod: &dyn crate::app::seam_stubs::AssemblyProduction,
        ) -> Vec<Arc<dyn crate::app::seam_stubs::AssemblyConstructorSemantic>> {
            Vec::new()
        }
        fn get_semantic(
            &self,
            _cons: &dyn crate::app::seam_stubs::Constructor,
        ) -> Option<Arc<dyn crate::app::seam_stubs::AssemblyConstructorSemantic>> {
            None
        }
        fn combine(&mut self, _that: &dyn AssemblyGrammar) {}
        fn get_pure_recursive(&self) -> Vec<Arc<dyn crate::app::seam_stubs::AssemblyProduction>> {
            Vec::new()
        }
        fn get_pure_recursion(
            &self,
            _lhs: &dyn crate::app::seam_stubs::AssemblyNonTerminal,
        ) -> Option<Arc<dyn crate::app::seam_stubs::AssemblyProduction>> {
            None
        }
    }

    #[test]
    fn matches_decimal_encoding_of_the_fixed_value() {
        let term = FixedTerminal::new(42);
        let toks = term.match_fixed("42", 0, None, &no_symbols());
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].get_numeric_value(), 42);
        assert_eq!(toks[0].get_string(), "42");
    }

    #[test]
    fn matches_hex_encoding_of_the_fixed_value() {
        let term = FixedTerminal::new(42);
        let toks = term.match_fixed("0x2a", 0, None, &no_symbols());
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].get_numeric_value(), 42);
        assert_eq!(toks[0].get_string(), "0x2a");
    }

    #[test]
    fn rejects_a_different_value() {
        let term = FixedTerminal::new(42);
        let toks = term.match_fixed("43", 0, None, &no_symbols());
        assert!(toks.is_empty());
    }

    #[test]
    fn ignores_caller_supplied_labels_even_when_they_resolve_to_the_fixed_value() {
        let term = FixedTerminal::new(42);
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("foo", 42i64);
        let symbols = MockSymbols { labels };
        // Java matches against `AssemblyNumericSymbols.EMPTY`, not the passed-in symbols, so a
        // label that *would* resolve to 42 must still fail to match.
        let toks = term.match_fixed("foo", 0, None, &symbols);
        assert!(toks.is_empty());
    }

    #[test]
    fn get_fixed_suggestions_is_just_the_value() {
        let term = FixedTerminal::new(42);
        assert_eq!(term.get_fixed_suggestions("", &no_symbols()), vec!["42".to_string()]);
    }

    #[test]
    fn fixed_display_string_is_just_the_value() {
        let term = FixedTerminal::new(42);
        assert_eq!(term.fixed_display_string(), "42");
        assert_eq!(format!("{term}"), "42");
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let term = FixedTerminal::new(7);
        let as_dyn: &dyn AssemblyFixedNumericTerminal = &term;
        assert_eq!(as_dyn.val(), 7);
        let toks = as_dyn.match_fixed("7", 0, None, &no_symbols());
        assert_eq!(toks.len(), 1);
    }

    #[test]
    fn wired_through_assembly_terminal_match() {
        let term = FixedTerminal::new(42);
        let grammar = NoopGrammar;
        let symbols = no_symbols();
        let toks = AssemblyTerminal::r#match(&term, "42", 0, &grammar, &symbols);
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].get_string(), "42");

        let none = AssemblyTerminal::r#match(&term, "99", 0, &grammar, &symbols);
        assert!(none.is_empty());
    }
}
