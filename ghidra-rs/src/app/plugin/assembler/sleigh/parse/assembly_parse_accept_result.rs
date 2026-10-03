//! Mirrors `ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseAcceptResult`.

use std::fmt;
use std::sync::Arc;

use crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar;
use crate::app::plugin::assembler::sleigh::parse::AssemblyParseResult;
use crate::app::plugin::assembler::sleigh::tree::AssemblyParseBranch;

/// A successful result from parsing.
///
/// Port of `ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseAcceptResult`, a concrete class
/// extending the already-ported [`AssemblyParseResult`] trait -- one of its two concrete
/// subclasses, alongside
/// [`AssemblyParseErrorResult`](crate::app::plugin::assembler::sleigh::parse::AssemblyParseErrorResult),
/// that trait's own docs anticipated porting later.
///
/// # Divergence: `toString()`
/// Java's `toString()` is `tree.print(new PrintStream(baos))`, i.e. the zero-argument convenience
/// overload of `AssemblyParseTreeNode.print(PrintStream)`. That overload (along with the
/// `grammar` field it reads internally) belongs to the still-unported `AssemblyParseTreeNode`
/// superclass, and is explicitly excluded from this crate's ported
/// [`AssemblyParseBranch`](crate::app::plugin::assembler::sleigh::tree::AssemblyParseBranch) trait
/// (see that trait's own docs). Two substitutes are offered here instead:
/// * [`Display`] (satisfying [`AssemblyParseResult`]'s `Display` supertrait bound) delegates to
///   [`AssemblyParseBranch::display_string`], a real, single-line rendering already on the ported
///   trait (`AssemblyParseBranch.toString()` in Java) -- not byte-identical to the multi-line
///   `print()` dump, but a faithful, non-fake rendering built entirely from what this crate has
///   actually ported.
/// * [`to_display_string`](Self::to_display_string) reproduces the fuller, multi-line rendering
///   via [`AssemblyParseBranch::print_indented`], which needs an explicit `&dyn AssemblyGrammar`
///   parameter for the same reason `print()`'s zero-arg convenience wrapper isn't available (the
///   ported `AssemblyParseBranch` trait has no `grammar` field of its own to read one from) --
///   mirroring the same "inject the otherwise-implicit dependency as a parameter" precedent
///   already used by
///   [`RichHeaderRecord::to_display_string`](crate::format::pe::rich::RichHeaderRecord::to_display_string).
pub struct AssemblyParseAcceptResult {
    tree: Arc<dyn AssemblyParseBranch>,
}

impl AssemblyParseAcceptResult {
    /// Construct an accept result.
    ///
    /// Mirrors the `protected AssemblyParseAcceptResult(AssemblyParseBranch tree)` constructor,
    /// called (in Java) only via `AssemblyParseResult.accept(AssemblyParseBranch)` (not yet
    /// ported -- see this struct's own docs).
    pub fn new(tree: Arc<dyn AssemblyParseBranch>) -> Self {
        AssemblyParseAcceptResult { tree }
    }

    /// Get the tree.
    ///
    /// Mirrors `AssemblyParseAcceptResult.getTree()`.
    pub fn get_tree(&self) -> Arc<dyn AssemblyParseBranch> {
        self.tree.clone()
    }

    /// Render the parse tree in full, indented, multi-line form.
    ///
    /// The closest available substitute for `toString()`'s `tree.print(PrintStream)` call -- see
    /// this struct's own docs for why a grammar parameter is required here (and why [`Display`]
    /// uses a different, single-line rendering instead).
    pub fn to_display_string(&self, grammar: &dyn AssemblyGrammar) -> String {
        self.tree.print_indented(grammar, "")
    }
}

impl fmt::Display for AssemblyParseAcceptResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.tree.display_string())
    }
}

impl AssemblyParseResult for AssemblyParseAcceptResult {
    /// Mirrors `AssemblyParseAcceptResult.isError()`, which always returns `false`.
    fn is_error(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::assembler::sleigh::grammars::{AbstractAssemblyProduction, AssemblySentential};
    use crate::app::seam_stubs::{
        AssemblyConstructorSemantic, AssemblyNonTerminal, AssemblyParseTreeNode, AssemblyProduction,
        AssemblySymbol,
    };

    struct MockNonTerminal(&'static str);

    impl fmt::Display for MockNonTerminal {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "[{}]", self.0)
        }
    }

    impl AssemblyNonTerminal for MockNonTerminal {
        fn get_name(&self) -> String {
            self.0.to_string()
        }
    }

    struct MockSymbol(&'static str);

    impl fmt::Display for MockSymbol {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl AssemblySymbol for MockSymbol {
        fn terminal_tag(&self) -> &str {
            self.0
        }
    }

    #[derive(Default, Clone)]
    struct MockSentential {
        symbols: Vec<Arc<dyn AssemblySymbol>>,
    }

    impl AssemblySentential for MockSentential {
        fn add_symbol(&mut self, symbol: Arc<dyn AssemblySymbol>) -> bool {
            self.symbols.push(symbol);
            true
        }
        fn get_symbols(&self) -> Vec<Arc<dyn AssemblySymbol>> {
            self.symbols.clone()
        }
        fn finish(&mut self) {}
        fn sub(&self, from_index: usize, to_index: usize) -> Box<dyn AssemblySentential> {
            Box::new(MockSentential { symbols: self.symbols[from_index..to_index].to_vec() })
        }
        fn white_space_symbol(&self) -> Arc<dyn AssemblySymbol> {
            unimplemented!("not exercised by this test")
        }
        fn make_string_terminal(&self, _str: &str) -> Arc<dyn AssemblySymbol> {
            unimplemented!("not exercised by this test")
        }
    }

    struct MockProduction {
        idx: i32,
        lhs: Arc<dyn AssemblyNonTerminal>,
        rhs: Arc<dyn AssemblySentential>,
    }

    impl AbstractAssemblyProduction for MockProduction {
        fn index(&self) -> i32 {
            self.idx
        }
        fn set_index(&mut self, idx: i32) {
            self.idx = idx;
        }
        fn lhs(&self) -> Arc<dyn AssemblyNonTerminal> {
            self.lhs.clone()
        }
        fn rhs(&self) -> Arc<dyn AssemblySentential> {
            self.rhs.clone()
        }
    }

    impl AssemblyProduction for MockProduction {
        fn is_constructor(&self) -> bool {
            true
        }
    }

    /// A leaf-only branch (no children), just enough to exercise `display_string`/`print_indented`.
    struct LeafBranch {
        production: Arc<dyn AssemblyProduction>,
    }

    impl AssemblyParseBranch for LeafBranch {
        fn get_production(&self) -> Arc<dyn AssemblyProduction> {
            self.production.clone()
        }
        fn get_substitutions(&self) -> Vec<Arc<dyn AssemblyParseTreeNode>> {
            Vec::new()
        }
        fn prepend_child(&mut self, _child: Arc<dyn AssemblyParseTreeNode>) {
            unimplemented!("not exercised by this test")
        }
    }

    struct MockGrammar;

    impl AssemblyGrammar for MockGrammar {
        fn add_production(&mut self, _prod: Arc<dyn AssemblyProduction>) {
            unimplemented!("not exercised by this test")
        }
        fn add_constructor_production(
            &mut self,
            _lhs: Arc<dyn AssemblyNonTerminal>,
            _rhs: Arc<dyn AssemblySentential>,
            _pattern: crate::program::model::lang::sleigh::pattern::DisjointPattern,
            _cons: Arc<dyn crate::app::seam_stubs::Constructor>,
            _indices: Vec<usize>,
        ) {
            unimplemented!("not exercised by this test")
        }
        fn get_semantics(
            &self,
            _prod: &dyn AssemblyProduction,
        ) -> Vec<Arc<dyn AssemblyConstructorSemantic>> {
            Vec::new()
        }
        fn get_semantic(
            &self,
            _cons: &dyn crate::app::seam_stubs::Constructor,
        ) -> Option<Arc<dyn AssemblyConstructorSemantic>> {
            None
        }
        fn combine(&mut self, _that: &dyn AssemblyGrammar) {
            unimplemented!("not exercised by this test")
        }
        fn get_pure_recursive(&self) -> Vec<Arc<dyn AssemblyProduction>> {
            Vec::new()
        }
        fn get_pure_recursion(
            &self,
            _lhs: &dyn AssemblyNonTerminal,
        ) -> Option<Arc<dyn AssemblyProduction>> {
            None
        }
    }

    fn make_tree() -> Arc<dyn AssemblyParseBranch> {
        let mut rhs = MockSentential::default();
        rhs.add_symbol(Arc::new(MockSymbol("insn")));
        let production: Arc<dyn AssemblyProduction> = Arc::new(MockProduction {
            idx: 0,
            lhs: Arc::new(MockNonTerminal("insn")),
            rhs: Arc::new(rhs),
        });
        Arc::new(LeafBranch { production })
    }

    #[test]
    fn is_error_is_always_false() {
        let result = AssemblyParseAcceptResult::new(make_tree());
        assert!(!result.is_error());
    }

    #[test]
    fn get_tree_returns_the_stored_tree() {
        let tree = make_tree();
        let result = AssemblyParseAcceptResult::new(tree.clone());
        assert_eq!(result.get_tree().display_string(), tree.display_string());
    }

    #[test]
    fn display_delegates_to_the_trees_display_string() {
        let tree = make_tree();
        let expected = tree.display_string();
        let result = AssemblyParseAcceptResult::new(tree);
        assert_eq!(result.to_string(), expected);
        assert_eq!(result.to_string(), "[insn]");
    }

    #[test]
    fn to_display_string_renders_the_full_indented_tree() {
        let result = AssemblyParseAcceptResult::new(make_tree());
        let rendered = result.to_display_string(&MockGrammar);
        assert!(rendered.starts_with("[insn] := 0. [insn] => insn"));
        assert!(rendered.ends_with('\n'));
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let result: Box<dyn AssemblyParseResult> = Box::new(AssemblyParseAcceptResult::new(make_tree()));
        assert!(!result.is_error());
        assert_eq!(result.to_string(), "[insn]");
    }
}
