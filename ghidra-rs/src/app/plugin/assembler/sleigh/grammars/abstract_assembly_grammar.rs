//! Mirrors `ghidra.app.plugin.assembler.sleigh.grammars.AbstractAssemblyGrammar`.

use std::sync::Arc;

use crate::app::plugin::assembler::sleigh::grammars::abstract_assembly_production::AbstractAssemblyProduction;
use crate::app::plugin::assembler::sleigh::grammars::assembly_grammar_exception::AssemblyGrammarException;
use crate::app::plugin::assembler::sleigh::grammars::assembly_sentential::AssemblySentential;
use crate::app::plugin::assembler::sleigh::symbol::AssemblyTerminal;
use crate::app::seam_stubs::AssemblyNonTerminal;

/// Defines a context-free grammar, usually for the purpose of parsing mnemonic assembly
/// instructions.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.grammars.AbstractAssemblyGrammar<NT extends
/// AssemblyNonTerminal, P extends AbstractAssemblyProduction<NT>>`, the abstract superclass of
/// [`AssemblyGrammar`](crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar) and
/// [`AssemblyExtendedGrammar`](
/// crate::app::plugin::assembler::sleigh::grammars::AssemblyExtendedGrammar), chosen as a
/// cut-point for the same dependency cycle running through the grammar, production, and symbol
/// types that those two subclasses (and [`AssemblySentential`], [`AbstractAssemblyProduction`])
/// were already cut on. As with those, Java's `NT`/`P` generic parameters are dropped: `NT` is
/// replaced by the crate's existing [`AssemblyNonTerminal`] placeholder and `P` by the
/// now-ported [`AbstractAssemblyProduction`] trait, both referenced through `Arc<dyn Trait>`
/// rather than threading type parameters through this trait.
///
/// Every method here operates on the class's five `protected final` fields (`productions`,
/// `prodList`, `nonterminals`, `terminals`, `symbols`, plus the mutable `startName`) -- concrete
/// data structures owned by the class itself, not supplied by subclasses. Since a Rust trait has
/// no fields of its own, the members that read or write that state
/// ([`new_production`](Self::new_production) -- the one truly abstract Java method --
/// [`add_production`](Self::add_production), [`set_start_name`](Self::set_start_name),
/// [`get_start_name`](Self::get_start_name), [`get_non_terminal`](Self::get_non_terminal),
/// [`get_terminal`](Self::get_terminal), [`non_terminals`](Self::non_terminals),
/// [`terminals`](Self::terminals), [`productions_of`](Self::productions_of), and
/// [`iter_productions`](Self::iter_productions)) are required hooks that a concrete implementer
/// must back with its own storage. Every other method
/// ([`add_production_from_parts`](Self::add_production_from_parts),
/// [`is_pure_recursive`](Self::is_pure_recursive), [`set_start`](Self::set_start),
/// [`get_start`](Self::get_start), [`combine`](Self::combine), [`print`](Self::print),
/// [`verify`](Self::verify), [`iter`](Self::iter), [`productions_of_non_terminal`](
/// Self::productions_of_non_terminal), and [`contains`](Self::contains)) is a default method
/// built entirely on that required core, mirroring the corresponding Java logic exactly.
///
/// [`add_production`](Self::add_production) stands in for the full body of
/// `addProduction(AbstractAssemblyProduction)`: Java's `productions` field is a *set-valued*
/// multimap (`TreeSetValuedTreeMap`), so `productions.put(lname, prod)` only assigns
/// `prod.idx = prodList.size()` and appends to `prodList` when `(lname, prod)` is not already
/// present; implementers of this hook are responsible for reproducing that dedup-on-insert
/// behavior (via [`AbstractAssemblyProduction::set_index`]), for defaulting the start symbol to
/// the first production's LHS when none is set yet, and for registering the LHS and every RHS
/// non-terminal/terminal into their respective name-keyed tables -- exactly as Java's
/// `addProduction` does with `symbols`/`nonterminals`/`terminals`.
///
/// [`verify`](Self::verify) is ported as a default method, but restructured slightly: rather than
/// re-scanning every production's RHS symbols for `instanceof AssemblyNonTerminal` (impossible to
/// test through a trait object), it walks [`non_terminals`](Self::non_terminals) -- which, by
/// `add_production`'s contract, already contains every non-terminal seen anywhere in the grammar,
/// LHS or RHS -- and checks each has a defining production via
/// [`productions_of`](Self::productions_of). This is equivalent to Java's per-production RHS scan
/// (both ultimately ask "does every non-terminal that appears anywhere have a defining
/// production?"), just phrased over the symbol table instead of re-deriving it from productions.
///
/// [`contains`](Self::contains) is similarly restructured as a default: Java's `symbols` map is
/// the union of `nonterminals` and `terminals`, so `symbols.containsKey(name)` is reproduced as
/// `get_non_terminal(name).is_some() || get_terminal(name).is_some()` rather than requiring a
/// third, separately-maintained lookup.
pub trait AbstractAssemblyGrammar {
    /// Construct a new production given its LHS and RHS.
    ///
    /// Mirrors the abstract `AbstractAssemblyGrammar.newProduction(NT, AssemblySentential<NT>)`.
    /// Because a concrete grammar may use a different production type, it must provide this
    /// factory.
    fn new_production(
        &self,
        lhs: Arc<dyn AssemblyNonTerminal>,
        rhs: Arc<dyn AssemblySentential>,
    ) -> Arc<dyn AbstractAssemblyProduction>;

    /// Add a production to the grammar.
    ///
    /// Mirrors `AbstractAssemblyGrammar.addProduction(AbstractAssemblyProduction)`. See the
    /// trait-level docs for the dedup-on-insert / symbol-table-registration contract this hook
    /// must fulfill.
    fn add_production(&mut self, prod: Arc<dyn AbstractAssemblyProduction>);

    /// Change the start symbol for the grammar, by name.
    ///
    /// Mirrors `AbstractAssemblyGrammar.setStartName(String)`. `None` mirrors Java's `null`.
    fn set_start_name(&mut self, start_name: Option<String>);

    /// Get the name of the start symbol for the grammar.
    ///
    /// Mirrors `AbstractAssemblyGrammar.getStartName()`.
    fn get_start_name(&self) -> Option<String>;

    /// Get the named non-terminal.
    ///
    /// Mirrors `AbstractAssemblyGrammar.getNonTerminal(String)`.
    fn get_non_terminal(&self, name: &str) -> Option<Arc<dyn AssemblyNonTerminal>>;

    /// Get the named terminal.
    ///
    /// Mirrors `AbstractAssemblyGrammar.getTerminal(String)`.
    fn get_terminal(&self, name: &str) -> Option<Arc<dyn AssemblyTerminal>>;

    /// Get the non-terminals known to this grammar.
    ///
    /// Mirrors `AbstractAssemblyGrammar.nonTerminals()`. Includes every non-terminal that has
    /// appeared as an LHS or RHS symbol in any added production, not only those with a defining
    /// production.
    fn non_terminals(&self) -> Vec<Arc<dyn AssemblyNonTerminal>>;

    /// Get the terminals known to this grammar.
    ///
    /// Mirrors `AbstractAssemblyGrammar.terminals()`.
    fn terminals(&self) -> Vec<Arc<dyn AssemblyTerminal>>;

    /// Get all productions where the left-hand side non-terminal has the given name.
    ///
    /// Mirrors `AbstractAssemblyGrammar.productionsOf(String)`, returning an empty `Vec` if no
    /// production defines `name`.
    fn productions_of(&self, name: &str) -> Vec<Arc<dyn AbstractAssemblyProduction>>;

    /// Get all productions in the grammar, in the order they were added.
    ///
    /// Backs [`iter`](Self::iter); mirrors iterating `AbstractAssemblyGrammar.prodList`, which is
    /// what `AbstractAssemblyGrammar.iterator()` (`Iterable<P>`) traverses.
    fn iter_productions(&self) -> Vec<Arc<dyn AbstractAssemblyProduction>>;

    /// Add a production to the grammar, given its LHS and RHS.
    ///
    /// Mirrors `AbstractAssemblyGrammar.addProduction(NT, AssemblySentential<NT>)`.
    fn add_production_from_parts(
        &mut self,
        lhs: Arc<dyn AssemblyNonTerminal>,
        rhs: Arc<dyn AssemblySentential>,
    ) {
        let prod = self.new_production(lhs, rhs);
        self.add_production(prod);
    }

    /// Check if the given production is purely recursive, i.e., of the form `I => I`.
    ///
    /// Mirrors the protected `AbstractAssemblyGrammar.isPureRecursive(P)`, comparing the LHS to
    /// the sole RHS symbol via `Display` (both `AssemblyNonTerminal` and `AssemblySymbol` mirror
    /// Java's LAZY, `toString()`-based `equals()` in this crate).
    fn is_pure_recursive(&self, prod: &dyn AbstractAssemblyProduction) -> bool {
        let rhs = prod.rhs();
        if rhs.size() != 1 {
            return false;
        }
        prod.lhs().to_string() == rhs.get_symbol(0).to_string()
    }

    /// Change the start symbol for the grammar.
    ///
    /// Mirrors `AbstractAssemblyGrammar.setStart(AssemblyNonTerminal)`.
    fn set_start(&mut self, nt: Option<Arc<dyn AssemblyNonTerminal>>) {
        self.set_start_name(nt.map(|nt| nt.get_name()));
    }

    /// Get the start symbol for the grammar.
    ///
    /// Mirrors `AbstractAssemblyGrammar.getStart()`.
    fn get_start(&self) -> Option<Arc<dyn AssemblyNonTerminal>> {
        self.get_non_terminal(&self.get_start_name()?)
    }

    /// Add all the productions of a given grammar to this one.
    ///
    /// Mirrors `AbstractAssemblyGrammar.combine(AbstractAssemblyGrammar)`.
    fn combine(&mut self, that: &dyn AbstractAssemblyGrammar) {
        for prod in that.iter_productions() {
            self.add_production(prod);
        }
    }

    /// Print the productions of this grammar to the given writer, one per line.
    ///
    /// Mirrors `AbstractAssemblyGrammar.print(PrintStream)`.
    fn print(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        for prod in self.iter_productions() {
            writeln!(out, "{}", prod.display_string())?;
        }
        Ok(())
    }

    /// Check that the grammar is consistent.
    ///
    /// Mirrors `AbstractAssemblyGrammar.verify()`. The grammar is consistent if every
    /// non-terminal appearing in the grammar also appears as the left-hand side of some
    /// production; if not, such non-terminals are said to be undefined. Returns
    /// [`AssemblyGrammarException`] instead of throwing.
    fn verify(&self) -> Result<(), AssemblyGrammarException> {
        let start_name = self.get_start_name();
        let start_has_production = start_name
            .as_deref()
            .map(|name| !self.productions_of(name).is_empty())
            .unwrap_or(false);
        if !start_has_production {
            return Err(AssemblyGrammarException::new("Start symbol has no defining production"));
        }
        for nt in self.non_terminals() {
            if self.productions_of(&nt.get_name()).is_empty() {
                return Err(AssemblyGrammarException::new(format!(
                    "Grammar has non-terminal '{}' without a defining production",
                    nt.get_name()
                )));
            }
        }
        Ok(())
    }

    /// Traverse the productions, in the order they were added.
    ///
    /// Mirrors `AbstractAssemblyGrammar.iterator()`.
    fn iter(&self) -> Box<dyn Iterator<Item = Arc<dyn AbstractAssemblyProduction>> + '_> {
        Box::new(self.iter_productions().into_iter())
    }

    /// Get all productions where the left-hand side is the given non-terminal.
    ///
    /// Mirrors `AbstractAssemblyGrammar.productionsOf(AssemblyNonTerminal)`.
    fn productions_of_non_terminal(
        &self,
        nt: &dyn AssemblyNonTerminal,
    ) -> Vec<Arc<dyn AbstractAssemblyProduction>> {
        self.productions_of(&nt.get_name())
    }

    /// Check if the grammar contains any symbol (terminal or non-terminal) with the given name.
    ///
    /// Mirrors `AbstractAssemblyGrammar.contains(String)`.
    fn contains(&self, name: &str) -> bool {
        self.get_non_terminal(name).is_some() || self.get_terminal(name).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Clone)]
    struct MockNonTerminal(String);

    impl MockNonTerminal {
        fn new(name: impl Into<String>) -> Self {
            Self(name.into())
        }
    }

    impl std::fmt::Display for MockNonTerminal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "[{}]", self.0)
        }
    }

    impl AssemblyNonTerminal for MockNonTerminal {
        fn get_name(&self) -> String {
            self.0.clone()
        }
    }

    struct MockSymbol(&'static str);

    impl std::fmt::Display for MockSymbol {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl crate::app::seam_stubs::AssemblySymbol for MockSymbol {
        fn terminal_tag(&self) -> &str {
            self.0
        }
    }

    #[derive(Default, Clone)]
    struct MockSentential {
        symbols: Vec<Arc<dyn crate::app::seam_stubs::AssemblySymbol>>,
    }

    impl AssemblySentential for MockSentential {
        fn add_symbol(&mut self, symbol: Arc<dyn crate::app::seam_stubs::AssemblySymbol>) -> bool {
            self.symbols.push(symbol);
            true
        }
        fn get_symbols(&self) -> Vec<Arc<dyn crate::app::seam_stubs::AssemblySymbol>> {
            self.symbols.clone()
        }
        fn finish(&mut self) {}
        fn sub(&self, from_index: usize, to_index: usize) -> Box<dyn AssemblySentential> {
            Box::new(MockSentential { symbols: self.symbols[from_index..to_index].to_vec() })
        }
        fn white_space_symbol(&self) -> Arc<dyn crate::app::seam_stubs::AssemblySymbol> {
            unimplemented!()
        }
        fn make_string_terminal(
            &self,
            _str: &str,
        ) -> Arc<dyn crate::app::seam_stubs::AssemblySymbol> {
            unimplemented!()
        }
    }

    /// A production backed by plain fields, so tests can build LHS/RHS pairs directly rather than
    /// going through a grammar's own `new_production`.
    struct MockProduction {
        idx: Mutex<i32>,
        lhs: Arc<dyn AssemblyNonTerminal>,
        rhs: Arc<dyn AssemblySentential>,
    }

    impl AbstractAssemblyProduction for MockProduction {
        fn index(&self) -> i32 {
            *self.idx.lock().unwrap()
        }
        fn set_index(&mut self, idx: i32) {
            *self.idx.lock().unwrap() = idx;
        }
        fn lhs(&self) -> Arc<dyn AssemblyNonTerminal> {
            self.lhs.clone()
        }
        fn rhs(&self) -> Arc<dyn AssemblySentential> {
            self.rhs.clone()
        }
    }

    fn sentential_of(names: &[&'static str]) -> Arc<dyn AssemblySentential> {
        let mut s = MockSentential::default();
        for name in names {
            s.add_symbol(Arc::new(MockSymbol(name)));
        }
        Arc::new(s)
    }

    /// An `AssemblySymbol` that renders bracketed, matching [`MockNonTerminal`]'s `Display`, so
    /// that RHS references to a non-terminal compare equal (by the LAZY, `toString()`-based rule
    /// this trait's default methods use) to that non-terminal's own LHS appearance.
    struct MockRhsNonTerminalSymbol(&'static str);

    impl std::fmt::Display for MockRhsNonTerminalSymbol {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "[{}]", self.0)
        }
    }

    impl crate::app::seam_stubs::AssemblySymbol for MockRhsNonTerminalSymbol {
        fn terminal_tag(&self) -> &str {
            self.0
        }
    }

    /// Builds a production whose RHS symbols are all treated as non-terminal references (see
    /// [`MockRhsNonTerminalSymbol`]), for tests exercising non-terminal registration/lookup.
    fn production(lhs_name: &'static str, rhs_names: &[&'static str]) -> Arc<dyn AbstractAssemblyProduction> {
        let mut rhs = MockSentential::default();
        for name in rhs_names {
            rhs.add_symbol(Arc::new(MockRhsNonTerminalSymbol(name)));
        }
        Arc::new(MockProduction {
            idx: Mutex::new(-1),
            lhs: Arc::new(MockNonTerminal::new(lhs_name)),
            rhs: Arc::new(rhs),
        })
    }

    /// A grammar storing productions and a symbol table with plain collections, exercising the
    /// default methods' real (non-trivial) behavior rather than trivially-true assertions.
    #[derive(Default)]
    struct TestGrammar {
        prod_list: Vec<Arc<dyn AbstractAssemblyProduction>>,
        productions: HashMap<String, Vec<Arc<dyn AbstractAssemblyProduction>>>,
        nonterminals: HashMap<String, Arc<dyn AssemblyNonTerminal>>,
        start_name: Option<String>,
    }

    impl AbstractAssemblyGrammar for TestGrammar {
        fn new_production(
            &self,
            lhs: Arc<dyn AssemblyNonTerminal>,
            rhs: Arc<dyn AssemblySentential>,
        ) -> Arc<dyn AbstractAssemblyProduction> {
            Arc::new(MockProduction { idx: Mutex::new(-1), lhs, rhs })
        }

        fn add_production(&mut self, mut prod: Arc<dyn AbstractAssemblyProduction>) {
            let lname = prod.get_name();
            let bucket = self.productions.entry(lname.clone()).or_default();
            if !bucket.iter().any(|p| Arc::ptr_eq(p, &prod)) {
                if let Some(p) = Arc::get_mut(&mut prod) {
                    p.set_index(self.prod_list.len() as i32);
                }
                bucket.push(prod.clone());
                self.prod_list.push(prod.clone());
            }
            if self.start_name.is_none() {
                self.start_name = Some(lname.clone());
            }
            let lhs = prod.lhs();
            self.nonterminals.insert(lhs.get_name(), lhs);
            for sym in prod.rhs().get_symbols() {
                // The mock's non-terminals all render as "[name]"; anything else is a terminal
                // and (since this crate has no real terminal type wired up yet) simply skipped,
                // matching how the other tests in this cycle leave terminal bookkeeping untested.
                let text = sym.to_string();
                if text.starts_with('[') && text.ends_with(']') {
                    let name = text[1..text.len() - 1].to_string();
                    self.nonterminals
                        .entry(name.clone())
                        .or_insert_with(|| Arc::new(MockNonTerminal::new(name)));
                }
            }
        }

        fn set_start_name(&mut self, start_name: Option<String>) {
            self.start_name = start_name;
        }

        fn get_start_name(&self) -> Option<String> {
            self.start_name.clone()
        }

        fn get_non_terminal(&self, name: &str) -> Option<Arc<dyn AssemblyNonTerminal>> {
            self.nonterminals.get(name).cloned()
        }

        fn get_terminal(&self, _name: &str) -> Option<Arc<dyn AssemblyTerminal>> {
            None
        }

        fn non_terminals(&self) -> Vec<Arc<dyn AssemblyNonTerminal>> {
            self.nonterminals.values().cloned().collect()
        }

        fn terminals(&self) -> Vec<Arc<dyn AssemblyTerminal>> {
            Vec::new()
        }

        fn productions_of(&self, name: &str) -> Vec<Arc<dyn AbstractAssemblyProduction>> {
            self.productions.get(name).cloned().unwrap_or_default()
        }

        fn iter_productions(&self) -> Vec<Arc<dyn AbstractAssemblyProduction>> {
            self.prod_list.clone()
        }
    }

    #[test]
    fn add_production_sets_index_and_defaults_start() {
        let mut grammar = TestGrammar::default();
        grammar.add_production_from_parts(Arc::new(MockNonTerminal::new("insn")), sentential_of(&["a"]));
        assert_eq!(grammar.get_start_name().as_deref(), Some("insn"));
        assert_eq!(grammar.iter_productions()[0].index(), 0);
    }

    #[test]
    fn add_production_registers_rhs_non_terminal() {
        let mut grammar = TestGrammar::default();
        grammar.add_production(production("insn", &["op"]));
        assert!(grammar.get_non_terminal("op").is_some());
        assert!(grammar.get_non_terminal("insn").is_some());
    }

    #[test]
    fn is_pure_recursive_detects_i_to_i() {
        let grammar = TestGrammar::default();
        let recursive = production("I", &["I"]);
        let non_recursive = production("I", &["a", "I"]);
        assert!(grammar.is_pure_recursive(recursive.as_ref()));
        assert!(!grammar.is_pure_recursive(non_recursive.as_ref()));
    }

    #[test]
    fn verify_fails_when_start_has_no_production() {
        let mut grammar = TestGrammar::default();
        grammar.set_start(Some(Arc::new(MockNonTerminal::new("insn"))));
        assert!(grammar.verify().is_err());
    }

    #[test]
    fn verify_fails_on_undefined_non_terminal() {
        let mut grammar = TestGrammar::default();
        grammar.add_production(production("insn", &["op"]));
        let err = grammar.verify().unwrap_err();
        assert!(err.message().contains("op"));
    }

    #[test]
    fn verify_succeeds_when_every_non_terminal_is_defined() {
        let mut grammar = TestGrammar::default();
        grammar.add_production(production("insn", &["op"]));
        grammar.add_production(production("op", &["a"]));
        grammar.add_production(production("a", &[]));
        assert!(grammar.verify().is_ok());
    }

    #[test]
    fn combine_merges_productions_from_another_grammar() {
        let mut source = TestGrammar::default();
        source.add_production(production("insn", &["a"]));

        let mut dest = TestGrammar::default();
        dest.combine(&source);

        assert_eq!(dest.iter_productions().len(), 1);
        assert!(dest.get_non_terminal("insn").is_some());
    }

    #[test]
    fn productions_of_returns_empty_for_unknown_name() {
        let grammar = TestGrammar::default();
        assert!(grammar.productions_of("nope").is_empty());
    }

    #[test]
    fn productions_of_non_terminal_delegates_by_name() {
        let mut grammar = TestGrammar::default();
        grammar.add_production(production("insn", &["a"]));
        let nt = MockNonTerminal::new("insn");
        assert_eq!(grammar.productions_of_non_terminal(&nt).len(), 1);
    }

    #[test]
    fn contains_checks_non_terminal_table() {
        let mut grammar = TestGrammar::default();
        grammar.add_production(production("insn", &["op"]));
        assert!(grammar.contains("insn"));
        assert!(grammar.contains("op"));
        assert!(!grammar.contains("nope"));
    }

    #[test]
    fn print_writes_one_line_per_production() {
        let mut grammar = TestGrammar::default();
        grammar.add_production(production("insn", &["a"]));
        grammar.add_production(production("op", &["b"]));

        let mut buf = Vec::new();
        grammar.print(&mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.contains("=>"));
    }

    #[test]
    fn iter_yields_productions_in_insertion_order() {
        let mut grammar = TestGrammar::default();
        grammar.add_production(production("a", &["x"]));
        grammar.add_production(production("b", &["y"]));
        let names: Vec<String> = grammar.iter().map(|p| p.get_name()).collect();
        assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let mut grammar = TestGrammar::default();
        grammar.add_production(production("insn", &["a"]));
        let as_dyn: &dyn AbstractAssemblyGrammar = &grammar;
        assert!(as_dyn.contains("insn"));
        assert_eq!(as_dyn.iter_productions().len(), 1);
    }
}
