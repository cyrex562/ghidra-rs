//! Mirrors `ghidra.app.plugin.assembler.sleigh.parse.AssemblyParser`.

use std::io;
use std::sync::Arc;

use crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar;
use crate::app::plugin::assembler::sleigh::parse::assembly_parse_result::AssemblyParseResult;
use crate::app::seam_stubs::AssemblyNumericSymbols;
use crate::program::model::address::AddressSpace;

/// An [`AssemblyNumericSymbols`] with no labels, standing in for Java's
/// `AssemblyNumericSymbols.EMPTY` singleton (a default-constructed instance with no labels
/// registered). Only used by [`AssemblyParser::parse_default`], which -- like
/// `AssemblyParser.parse(String)`, the Java method it mirrors -- delegates to the two-argument
/// form with that concrete singleton. Reuses the same pattern as
/// [`AssemblyFixedNumericTerminal`](
/// crate::app::plugin::assembler::sleigh::symbol::AssemblyFixedNumericTerminal)'s own private
/// copy, rather than sharing one: neither this crate nor [`AssemblyNumericSymbols`] itself has a
/// shared `EMPTY` instance yet.
struct EmptyNumericSymbols;

impl AssemblyNumericSymbols for EmptyNumericSymbols {
    fn choose(&self, _name: &str, _space: Option<&AddressSpace>) -> std::collections::BTreeSet<i64> {
        std::collections::BTreeSet::new()
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

/// Encapsulates LALR(1) parsing for a given grammar.
///
/// This implementation is somewhat unconventional in that it permits ambiguous grammars. Instead
/// of complaining, it produces the set of all possible parse trees. Of course, this comes at the
/// cost of some efficiency.
///
/// See Alfred V. Aho, Monica S. Lam, Ravi Sethi, Jeffrey D. Ullman, *Compilers: Principles,
/// Techniques, & Tools*. Boston, MA: Pearson, 2007.
///
/// See Jackson, Stephen. [LALR(1) Parsing](http://web.cs.dal.ca/~sjackson/lalr1.html). Halifax,
/// Nova Scotia, Canada: Dalhousie University.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.parse.AssemblyParser`, a concrete class that sits
/// at the center of a dependency cycle running through the grammar, symbol, and parse-tree
/// packages (it references `AssemblyGrammar`, `AssemblyFirstFollow`, `AssemblyParseState`,
/// `AssemblyExtendedGrammar`, `AssemblyParseActionGotoTable`, and constructs an
/// `AssemblyParseMachine` per call to `parse`), so it was chosen as this cycle's cut-point. This
/// trait models only the class's *public* surface -- the single constructor
/// (`AssemblyParser(AssemblyGrammar)`), the private/protected LALR-construction machinery it
/// drives from that constructor (`buildLR0Machine`, `addLR0State`, `buildExtendedGrammar`,
/// `extend`, `buildActionGotoTable`, and the private `MergeKey`/`MergeValue` helper classes), and
/// the `protected final` fields those methods populate (`grammar`, `ff`, `states`, `table`,
/// `extendedGrammar`, `extff`, `mergers`, `actions`) are all left out: they describe *how* one
/// particular implementation builds a parser from a grammar, not capabilities other types across
/// the cycle need to call through this trait. A concrete implementor is free to run that same
/// algorithm (or any other) in its own constructor and hold the resulting tables however it
/// likes.
///
/// [`AssemblyGrammar`] is already a real port (also chosen as a cut-point for this same cycle),
/// used directly. [`AssemblyNumericSymbols`] and [`AssemblyParseResult`] are handled the same way
/// as [`AssemblyGrammar`]: the former is an existing minimal placeholder in
/// [`crate::app::seam_stubs`], and the latter is [`AssemblyParseResult`], another real port (also
/// a cut-point for this cycle) reused here as-is. Constructed results are returned as
/// `Box<dyn AssemblyParseResult>` (owned, non-shared), the same convention used by
/// [`AssemblyResolution`](crate::app::plugin::assembler::sleigh::sem::AssemblyResolution)'s own
/// `Vec<Box<dyn AssemblyResolution>>` returns, since each parse produces fresh, independently
/// owned trees or errors rather than values shared with the parser's own state.
///
/// The eight `print*(PrintStream)` debugging methods are ported as required trait methods taking
/// `&mut dyn std::io::Write` (mirroring [`AbstractAssemblyGrammar::print`](
/// crate::app::plugin::assembler::sleigh::grammars::AbstractAssemblyGrammar::print)'s existing
/// `PrintStream` convention) rather than default methods, since each formats a different piece of
/// the implementor's own internal state (LR(0) states, the extended grammar, first/follow sets,
/// the merge table, the Action/Goto table) that this trait has no field of its own to read.
/// [`print_stuff`](Self::print_stuff) is the exception: it is a default method, mirroring
/// `AssemblyParser.printStuff(PrintStream)`, which does nothing but invoke the other eight in a
/// fixed order.
pub trait AssemblyParser {
    /// Parse the given sentence with the given defined symbols.
    ///
    /// The tokenizer for numeric terminals also accepts any key in `symbols`. In such cases, the
    /// resulting token is assigned the value of the symbol.
    ///
    /// Mirrors `AssemblyParser.parse(String, AssemblyNumericSymbols)`.
    fn parse(
        &self,
        input: &str,
        symbols: &dyn AssemblyNumericSymbols,
    ) -> Vec<Box<dyn AssemblyParseResult>>;

    /// Parse the given sentence.
    ///
    /// Mirrors `AssemblyParser.parse(String)`, which delegates to the two-argument form with
    /// `AssemblyNumericSymbols.EMPTY`.
    fn parse_default(&self, input: &str) -> Vec<Box<dyn AssemblyParseResult>> {
        self.parse(input, &EmptyNumericSymbols)
    }

    /// Get the grammar used to construct this parser.
    ///
    /// Mirrors `AssemblyParser.getGrammar()`.
    fn get_grammar(&self) -> Arc<dyn AssemblyGrammar>;

    /// For debugging: print the general grammar.
    ///
    /// Mirrors `AssemblyParser.printGrammar(PrintStream)`.
    fn print_grammar(&self, out: &mut dyn io::Write) -> io::Result<()>;

    /// For debugging: print the LR(0) states.
    ///
    /// Mirrors `AssemblyParser.printLR0States(PrintStream)`.
    fn print_lr0_states(&self, out: &mut dyn io::Write) -> io::Result<()>;

    /// For debugging: print the LR(0) transition table.
    ///
    /// Mirrors `AssemblyParser.printLR0TransitionTable(PrintStream)`.
    fn print_lr0_transition_table(&self, out: &mut dyn io::Write) -> io::Result<()>;

    /// For debugging: print the extended grammar.
    ///
    /// Mirrors `AssemblyParser.printExtendedGrammar(PrintStream)`.
    fn print_extended_grammar(&self, out: &mut dyn io::Write) -> io::Result<()>;

    /// For debugging: print the general first/follow sets.
    ///
    /// Mirrors `AssemblyParser.printGeneralFF(PrintStream)`.
    fn print_general_ff(&self, out: &mut dyn io::Write) -> io::Result<()>;

    /// For debugging: print the extended first/follow sets.
    ///
    /// Mirrors `AssemblyParser.printExtendedFF(PrintStream)`.
    fn print_extended_ff(&self, out: &mut dyn io::Write) -> io::Result<()>;

    /// For debugging: print the merge table.
    ///
    /// Mirrors `AssemblyParser.printMergers(PrintStream)`.
    fn print_mergers(&self, out: &mut dyn io::Write) -> io::Result<()>;

    /// For debugging: print the Action/Goto parse table.
    ///
    /// Mirrors `AssemblyParser.printParseTable(PrintStream)`.
    fn print_parse_table(&self, out: &mut dyn io::Write) -> io::Result<()>;

    /// For debugging: print everything above, in order.
    ///
    /// Mirrors `AssemblyParser.printStuff(PrintStream)`.
    fn print_stuff(&self, out: &mut dyn io::Write) -> io::Result<()> {
        self.print_grammar(out)?;
        self.print_general_ff(out)?;
        self.print_lr0_states(out)?;
        self.print_lr0_transition_table(out)?;
        self.print_extended_grammar(out)?;
        self.print_extended_ff(out)?;
        self.print_mergers(out)?;
        self.print_parse_table(out)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockGrammar;

    impl AssemblyGrammar for MockGrammar {
        fn add_production(&mut self, _prod: Arc<dyn crate::app::seam_stubs::AssemblyProduction>) {}

        fn add_constructor_production(
            &mut self,
            _lhs: Arc<dyn crate::app::seam_stubs::AssemblyNonTerminal>,
            _rhs: Arc<dyn crate::app::plugin::assembler::sleigh::grammars::AssemblySentential>,
            _pattern: crate::program::model::lang::sleigh::pattern::DisjointPattern,
            _cons: Arc<dyn crate::app::seam_stubs::Constructor>,
            _indices: Vec<usize>,
        ) {
            unimplemented!("not exercised by this smoke test")
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

    /// Stands in for `AssemblyParseAcceptResult`.
    struct MockAccept(String);

    impl std::fmt::Display for MockAccept {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "tree: {}", self.0)
        }
    }

    impl AssemblyParseResult for MockAccept {
        fn is_error(&self) -> bool {
            false
        }
    }

    /// Stands in for `AssemblyParseErrorResult`.
    struct MockError(String);

    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Error at '{}'", self.0)
        }
    }

    impl AssemblyParseResult for MockError {
        fn is_error(&self) -> bool {
            true
        }
    }

    /// Stands in for the real `AssemblyParser`: a hand-rolled parser that only accepts the single
    /// sentence "good", proving [`AssemblyParser::parse`] branches on real input rather than
    /// returning a canned result, and that the debug-print methods and the
    /// [`print_stuff`](AssemblyParser::print_stuff) default compose them in the documented order.
    struct MockParser {
        grammar: Arc<dyn AssemblyGrammar>,
    }

    impl AssemblyParser for MockParser {
        fn parse(
            &self,
            input: &str,
            symbols: &dyn AssemblyNumericSymbols,
        ) -> Vec<Box<dyn AssemblyParseResult>> {
            // Exercise `symbols`, matching Java's `AssemblyNumericSymbols.EMPTY` resolving no
            // labels for any name.
            assert!(symbols.choose("anything", None).is_empty());
            if input == "good" {
                vec![Box::new(MockAccept(input.to_string()))]
            } else {
                vec![Box::new(MockError(input.to_string()))]
            }
        }

        fn get_grammar(&self) -> Arc<dyn AssemblyGrammar> {
            self.grammar.clone()
        }

        fn print_grammar(&self, out: &mut dyn io::Write) -> io::Result<()> {
            writeln!(out, "grammar")
        }

        fn print_lr0_states(&self, out: &mut dyn io::Write) -> io::Result<()> {
            writeln!(out, "lr0-states")
        }

        fn print_lr0_transition_table(&self, out: &mut dyn io::Write) -> io::Result<()> {
            writeln!(out, "lr0-table")
        }

        fn print_extended_grammar(&self, out: &mut dyn io::Write) -> io::Result<()> {
            writeln!(out, "extended-grammar")
        }

        fn print_general_ff(&self, out: &mut dyn io::Write) -> io::Result<()> {
            writeln!(out, "general-ff")
        }

        fn print_extended_ff(&self, out: &mut dyn io::Write) -> io::Result<()> {
            writeln!(out, "extended-ff")
        }

        fn print_mergers(&self, out: &mut dyn io::Write) -> io::Result<()> {
            writeln!(out, "mergers")
        }

        fn print_parse_table(&self, out: &mut dyn io::Write) -> io::Result<()> {
            writeln!(out, "parse-table")
        }
    }

    #[test]
    fn parse_default_uses_empty_numeric_symbols() {
        let parser = MockParser { grammar: Arc::new(MockGrammar) };
        let results = parser.parse_default("good");
        assert_eq!(results.len(), 1);
        assert!(!results[0].is_error());
        assert_eq!(results[0].to_string(), "tree: good");
    }

    #[test]
    fn parse_branches_on_input() {
        let parser = MockParser { grammar: Arc::new(MockGrammar) };
        let good = parser.parse("good", &EmptyNumericSymbols);
        let bad = parser.parse("bogus", &EmptyNumericSymbols);
        assert!(!good[0].is_error());
        assert!(bad[0].is_error());
        assert_eq!(bad[0].to_string(), "Error at 'bogus'");
    }

    #[test]
    fn get_grammar_returns_shared_instance() {
        let grammar: Arc<dyn AssemblyGrammar> = Arc::new(MockGrammar);
        let parser = MockParser { grammar: grammar.clone() };
        assert!(parser.get_grammar().get_pure_recursive().is_empty());
    }

    #[test]
    fn print_stuff_composes_all_sections_in_order() {
        let parser = MockParser { grammar: Arc::new(MockGrammar) };
        let mut buf = Vec::new();
        parser.print_stuff(&mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert_eq!(
            text,
            "grammar\ngeneral-ff\nlr0-states\nlr0-table\nextended-grammar\nextended-ff\nmergers\nparse-table\n"
        );
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let parser: Box<dyn AssemblyParser> =
            Box::new(MockParser { grammar: Arc::new(MockGrammar) });
        let mut buf = Vec::new();
        parser.print_grammar(&mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "grammar\n");
    }
}
