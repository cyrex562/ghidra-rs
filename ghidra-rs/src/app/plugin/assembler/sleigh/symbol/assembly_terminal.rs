//! Mirrors `ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal`.

use std::sync::Arc;

use crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar;
use crate::app::plugin::assembler::sleigh::tree::AssemblyParseToken;
use crate::app::seam_stubs::{AssemblyNumericSymbols, AssemblySymbol};

/// The type of terminal for an assembly grammar.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal`, an abstract class
/// extending the unported `AssemblySymbol`. This type was chosen as the cut-point for a
/// dependency cycle running through the grammar, terminal, and parse-tree types (the prior
/// placeholder it replaces was referenced by
/// [`AssemblyParseToken`](crate::app::plugin::assembler::sleigh::tree::AssemblyParseToken)).
/// [`AssemblySymbol`] is modeled as a placeholder supertrait in [`crate::app::seam_stubs`] (still
/// unported), exposing the `Display` bound and stable identity tag that its LAZY
/// `toString`/`equals`/`hashCode` (all defined in terms of `toString()`) require -- unchanged
/// from what the prior placeholder exposed directly, so existing implementers still satisfy this
/// trait. [`AssemblyGrammar`] and [`AssemblyParseToken`] are already-ported traits, referenced
/// here via `&dyn`/`Arc<dyn>` rather than concrete types.
/// [`AssemblyNumericSymbols`](crate::app::seam_stubs::AssemblyNumericSymbols) isn't ported yet
/// either, so it's modeled as an empty placeholder trait: `AssemblyTerminal` only ever passes it
/// through to implementers, never calling a method on it itself.
pub trait AssemblyTerminal: AssemblySymbol {
    /// Attempt to match a token from the input buffer starting at a given position.
    ///
    /// Mirrors `AssemblyTerminal.match(String, int, AssemblyGrammar, AssemblyNumericSymbols)`.
    ///
    /// * `buffer` - the input buffer
    /// * `pos` - the cursor position in the buffer
    /// * `grammar` - the grammar containing this terminal
    /// * `symbols` - symbols from the program, suitable for use as numeric terminals
    fn r#match(
        &self,
        buffer: &str,
        pos: usize,
        grammar: &dyn AssemblyGrammar,
        symbols: &dyn AssemblyNumericSymbols,
    ) -> Vec<Arc<dyn AssemblyParseToken>>;

    /// Provide a collection of strings that this terminal would have accepted.
    ///
    /// Mirrors `AssemblyTerminal.getSuggestions(String, AssemblyNumericSymbols)`.
    ///
    /// * `got` - the remaining contents of the input buffer
    /// * `symbols` - the program symbols, if applicable
    fn get_suggestions(&self, got: &str, symbols: &dyn AssemblyNumericSymbols) -> Vec<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSymbols;
    impl AssemblyNumericSymbols for MockSymbols {
        fn choose(
            &self,
            _name: &str,
            _space: Option<&crate::program::model::address::AddressSpace>,
        ) -> std::collections::BTreeSet<i64> {
            std::collections::BTreeSet::new()
        }

        fn get_suggestions(
            &self,
            _got: &str,
            _space: Option<&crate::program::model::address::AddressSpace>,
            _max: usize,
        ) -> Vec<String> {
            Vec::new()
        }
    }

    /// A terminal that matches a fixed literal keyword, exercising real (non-trivial) match and
    /// suggestion behavior rather than trivially-true stubs.
    struct KeywordTerminal(&'static str);

    impl std::fmt::Display for KeywordTerminal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl AssemblySymbol for KeywordTerminal {
        fn terminal_tag(&self) -> &str {
            self.0
        }
    }

    struct MockGrammar;
    impl AssemblyGrammar for MockGrammar {
        fn add_production(
            &mut self,
            _prod: Arc<dyn crate::app::seam_stubs::AssemblyProduction>,
        ) {
        }
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

    struct MockToken {
        term: Arc<dyn AssemblyTerminal>,
        str: String,
    }

    impl AssemblyParseToken for MockToken {
        fn get_string(&self) -> &str {
            &self.str
        }
        fn get_sym(&self) -> Arc<dyn AssemblyTerminal> {
            self.term.clone()
        }
    }

    impl AssemblyTerminal for KeywordTerminal {
        fn r#match(
            &self,
            buffer: &str,
            pos: usize,
            _grammar: &dyn AssemblyGrammar,
            _symbols: &dyn AssemblyNumericSymbols,
        ) -> Vec<Arc<dyn AssemblyParseToken>> {
            let rest = &buffer[pos..];
            if rest.starts_with(self.0) {
                let term: Arc<dyn AssemblyTerminal> = Arc::new(KeywordTerminal(self.0));
                let tok: Arc<dyn AssemblyParseToken> = Arc::new(MockToken {
                    term,
                    str: self.0.to_string(),
                });
                vec![tok]
            }
            else {
                Vec::new()
            }
        }

        fn get_suggestions(&self, got: &str, _symbols: &dyn AssemblyNumericSymbols) -> Vec<String> {
            if self.0.starts_with(got) {
                vec![self.0.to_string()]
            }
            else {
                Vec::new()
            }
        }
    }

    #[test]
    fn match_succeeds_on_matching_prefix() {
        let term = KeywordTerminal("mov");
        let grammar = MockGrammar;
        let symbols = MockSymbols;
        let toks = term.r#match("mov r0, r1", 0, &grammar, &symbols);
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].get_string(), "mov");
    }

    #[test]
    fn match_fails_on_non_matching_input() {
        let term = KeywordTerminal("mov");
        let grammar = MockGrammar;
        let symbols = MockSymbols;
        let toks = term.r#match("add r0, r1", 0, &grammar, &symbols);
        assert!(toks.is_empty());
    }

    #[test]
    fn match_respects_start_position() {
        let term = KeywordTerminal("mov");
        let grammar = MockGrammar;
        let symbols = MockSymbols;
        let toks = term.r#match("  mov r0, r1", 2, &grammar, &symbols);
        assert_eq!(toks.len(), 1);
    }

    #[test]
    fn get_suggestions_matches_prefix() {
        let term = KeywordTerminal("mov");
        let symbols = MockSymbols;
        assert_eq!(term.get_suggestions("mo", &symbols), vec!["mov".to_string()]);
    }

    #[test]
    fn get_suggestions_empty_for_non_matching_prefix() {
        let term = KeywordTerminal("mov");
        let symbols = MockSymbols;
        assert!(term.get_suggestions("xyz", &symbols).is_empty());
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let term = KeywordTerminal("mov");
        let as_dyn: &dyn AssemblyTerminal = &term;
        assert_eq!(as_dyn.terminal_tag(), "mov");
        assert_eq!(format!("{as_dyn}"), "mov");
    }
}
