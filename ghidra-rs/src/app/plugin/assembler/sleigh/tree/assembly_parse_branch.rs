//! Mirrors `ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch`.

use std::sync::Arc;

use crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar;
use crate::app::seam_stubs::{AssemblyParseTreeNode, AssemblyProduction};

/// A branch in a parse tree, corresponding to the application of a production.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch`, a concrete class
/// extending the unported `AssemblyParseTreeNode` and implementing `Iterable<AssemblyParseTreeNode>`.
/// That class was chosen as the cut-point for a dependency cycle running through the grammar,
/// production, and parse-tree types. This trait models only the members
/// `AssemblyParseBranch.java` itself declares (its own public/protected methods and overrides of
/// `AssemblyParseTreeNode`'s abstract methods) -- the inherited `AssemblyParseTreeNode` surface
/// (`getParent()`, `setParent()`, `getGrammar()`, the public `print(PrintStream)` convenience
/// overload) belongs to that still-unported superclass and is left for its own port, mirroring the
/// same exclusion already made for
/// [`AssemblyParseToken`](crate::app::plugin::assembler::sleigh::tree::AssemblyParseToken). The
/// constructor's `AssemblyGrammar` parameter is likewise dropped for the same reason.
///
/// [`AssemblyProduction`] (the type of `prod`) and [`AssemblyParseTreeNode`] (the element type of
/// `substs`) aren't ported yet, so both are modeled as minimal placeholder traits in
/// [`crate::app::seam_stubs`], referenced here via `Arc<dyn Trait>` rather than concrete types.
/// [`AssemblyGrammar`] is already a real ported trait, used directly (as an explicit parameter to
/// [`print_indented`](Self::print_indented) rather than a stored field, since this trait has no
/// `grammar` field of its own -- see [`AssemblyParseTreeNode`]'s doc comment for the same
/// reasoning).
///
/// `substs` (a `List<AssemblyParseTreeNode>` built up right-to-left by repeated
/// [`add_child`](Self::add_child) calls) is modeled via two hooks: the required
/// [`prepend_child`](Self::prepend_child) (storage-dependent, since this trait has no field of its
/// own, mirroring [`AssemblySentential::add_symbol`](
/// crate::app::plugin::assembler::sleigh::grammars::AssemblySentential::add_symbol)) and the
/// default [`add_child`](Self::add_child) built on it (mirroring how
/// [`AssemblySentential::add_ws`](
/// crate::app::plugin::assembler::sleigh::grammars::AssemblySentential::add_ws) is a default method
/// built on that same required hook). [`get_production`](Self::get_production) and
/// [`get_substitutions`](Self::get_substitutions) are likewise required hooks standing in for the
/// constructor-assigned `prod` field and the `substs` list (returning cloned handles rather than
/// Java's unmodifiable list view, mirroring [`AssemblySentential::get_symbols`](
/// crate::app::plugin::assembler::sleigh::grammars::AssemblySentential::get_symbols)).
///
/// `expects`, `isComplete`, `getSym`, `toString`, `getSubstitution`, `iterator`, `isConstructor`,
/// `generateString`, and the protected `print(PrintStream, String)` override (renamed
/// `print_indented` per this crate's `display_string`/`print_indented` convention) are all pure
/// functions of [`get_production`](Self::get_production)/[`get_substitutions`](Self::get_substitutions),
/// so they're ported as default trait methods.
///
/// `equals()`/`hashCode()` are not mapped: Java's override combines a hash built from `prod`
/// *and* `substs` with an equals that compares `substs` *only* (never `prod`) -- meaning two
/// branches with equal `substs` but different `prod` would be `equals()`-equal yet have different
/// `hashCode()`s, violating the `equals`/`hashCode` contract. Reproducing that unsound pairing
/// would be meaningless, mirroring the precedent already set on
/// [`AssemblySentential`](crate::app::plugin::assembler::sleigh::grammars::AssemblySentential) for
/// the same kind of mismatch.
pub trait AssemblyParseBranch {
    /// Get the production applied to create this branch.
    ///
    /// Mirrors `AssemblyParseBranch.getProduction()` (and the constructor-assigned `prod` field it
    /// returns).
    fn get_production(&self) -> Arc<dyn AssemblyProduction>;

    /// Get the list of children, indexed by corresponding symbol from the RHS.
    ///
    /// Mirrors `AssemblyParseBranch.getSubstitutions()`, returning cloned handles rather than
    /// Java's unmodifiable list view.
    fn get_substitutions(&self) -> Vec<Arc<dyn AssemblyParseTreeNode>>;

    /// Prepend a child to storage.
    ///
    /// Stands in for the list mutation `this.substs.add(0, child)` performed by
    /// `AssemblyParseBranch.addChild`, isolated as a required hook (rather than part of
    /// [`add_child`](Self::add_child) itself) since storage is implementer-specific -- this trait
    /// has no field of its own to mutate.
    fn prepend_child(&mut self, child: Arc<dyn AssemblyParseTreeNode>);

    /// See what symbol is expected next.
    ///
    /// The child added next must be associated with the symbol expected next.
    ///
    /// Mirrors the protected `AssemblyParseBranch.expects()`. Returns `None` once the branch is
    /// [complete](Self::is_complete), mirroring Java's `null` return in that case.
    fn expects(&self) -> Option<Arc<dyn crate::app::seam_stubs::AssemblySymbol>> {
        if self.is_complete() {
            return None;
        }
        let rhs = self.get_production().rhs();
        let idx = rhs.size() - self.get_substitutions().len() - 1;
        Some(rhs.get_symbol(idx))
    }

    /// Check if the branch is full.
    ///
    /// Mirrors the protected `AssemblyParseBranch.isComplete()`: true if every symbol on the RHS
    /// has a corresponding child.
    fn is_complete(&self) -> bool {
        self.get_production().rhs().size() == self.get_substitutions().len()
    }

    /// Prepend a child to this branch.
    ///
    /// Because LR parsers produce rightmost derivations, they necessarily populate the branches
    /// right to left. During reduction, each child is popped from the stack, traversing them in
    /// reverse order. This method prepends children so that when reduction is complete, the
    /// children are aligned to the corresponding symbols from the RHS of the production.
    ///
    /// Mirrors `AssemblyParseBranch.addChild(AssemblyParseTreeNode)`. The parent-link side effect
    /// (`child.setParent(this)`) is dropped, since parent-link storage belongs to the still-unported
    /// `AssemblyParseTreeNode` superclass (see this trait's own doc comment). The assertion is
    /// reproduced via [`AssemblySymbol::terminal_tag`](crate::app::seam_stubs::AssemblySymbol::terminal_tag),
    /// the same identity-comparison convention [`AssemblyParseToken`](
    /// crate::app::plugin::assembler::sleigh::tree::AssemblyParseToken)'s `equals` uses in place of
    /// Java's `AssemblySymbol.equals`.
    fn add_child(&mut self, child: Arc<dyn AssemblyParseTreeNode>) {
        if let Some(expected) = self.expects() {
            debug_assert_eq!(
                expected.terminal_tag(),
                child.get_sym().terminal_tag(),
                "child does not match the symbol expected next"
            );
        }
        self.prepend_child(child);
    }

    /// Get the symbol for which this node is substituted.
    ///
    /// Mirrors `AssemblyParseBranch.getSym()` (an override of `AssemblyParseTreeNode.getSym()`,
    /// narrowed here from `AssemblySymbol` to `AssemblyNonTerminal`): the LHS of the applied
    /// production.
    fn get_sym(&self) -> Arc<dyn crate::app::seam_stubs::AssemblyNonTerminal> {
        self.get_production().lhs()
    }

    /// Mirrors `AssemblyParseBranch.toString()`.
    fn display_string(&self) -> String {
        self.get_sym().to_string()
    }

    /// Get the <em>i</em>th child, corresponding to the <em>i</em>th symbol from the RHS.
    ///
    /// Mirrors `AssemblyParseBranch.getSubstitution(int)`. Panics if `i` is out of bounds,
    /// matching Java's `List.get` throwing `IndexOutOfBoundsException`.
    fn get_substitution(&self, i: usize) -> Arc<dyn AssemblyParseTreeNode> {
        self.get_substitutions()[i].clone()
    }

    /// Iterate over the children, indexed by corresponding symbol from the RHS.
    ///
    /// Mirrors `AssemblyParseBranch.iterator()` (`Iterable<AssemblyParseTreeNode>`).
    fn iter(&self) -> Box<dyn Iterator<Item = Arc<dyn AssemblyParseTreeNode>> + '_> {
        Box::new(self.get_substitutions().into_iter())
    }

    /// Mirrors `AssemblyParseBranch.isConstructor()`, which delegates to the applied production.
    fn is_constructor(&self) -> bool {
        self.get_production().is_constructor()
    }

    /// Generate the string that this branch parsed.
    ///
    /// Mirrors `AssemblyParseBranch.generateString()`: the concatenation of each child's own
    /// generated string, in RHS order.
    fn generate_string(&self) -> String {
        self.get_substitutions()
            .iter()
            .map(|node| node.generate_string())
            .collect()
    }

    /// For debugging: format this branch (and its children) with the given indent.
    ///
    /// Mirrors the protected `AssemblyParseBranch.print(PrintStream, String)`, returning the
    /// formatted text instead of writing to a stream, and taking `grammar` explicitly since this
    /// trait has no `grammar` field of its own to inherit (see this trait's own doc comment).
    fn print_indented(&self, grammar: &dyn AssemblyGrammar, indent: &str) -> String {
        let mut out = format!(
            "{indent}{} := {}",
            self.get_sym(),
            self.get_production().display_string()
        );
        let sems = grammar.get_semantics(self.get_production().as_ref());
        if !sems.is_empty() {
            let joined = sems
                .iter()
                .map(|sem| sem.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(" ({joined})"));
        }
        out.push('\n');
        let child_indent = format!("  {indent}");
        for child in self.get_substitutions() {
            out.push_str(&child.print_indented(grammar, &child_indent));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::assembler::sleigh::grammars::AssemblySentential;
    use crate::app::plugin::assembler::sleigh::grammars::AbstractAssemblyProduction;
    use crate::app::seam_stubs::{AssemblyConstructorSemantic, AssemblyNonTerminal, AssemblySymbol};
    use std::sync::Mutex;

    struct MockNonTerminal(&'static str);

    impl std::fmt::Display for MockNonTerminal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "[{}]", self.0)
        }
    }

    impl AssemblyNonTerminal for MockNonTerminal {
        fn get_name(&self) -> String {
            self.0.to_string()
        }
    }

    struct MockSymbol(&'static str);

    impl std::fmt::Display for MockSymbol {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
            unimplemented!()
        }
        fn make_string_terminal(&self, _str: &str) -> Arc<dyn AssemblySymbol> {
            unimplemented!()
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

    impl AssemblyProduction for MockProduction {}

    struct MockSemantic(&'static str);

    impl std::fmt::Display for MockSemantic {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl AssemblyConstructorSemantic for MockSemantic {}

    /// A grammar recording just enough state to exercise `print_indented`'s semantics lookup.
    #[derive(Default)]
    struct MockGrammar {
        semantics: Vec<Arc<dyn AssemblyConstructorSemantic>>,
    }

    impl AssemblyGrammar for MockGrammar {
        fn add_production(&mut self, _prod: Arc<dyn AssemblyProduction>) {}
        fn add_constructor_production(
            &mut self,
            _lhs: Arc<dyn AssemblyNonTerminal>,
            _rhs: Arc<dyn AssemblySentential>,
            _pattern: crate::program::model::lang::sleigh::pattern::DisjointPattern,
            _cons: Arc<dyn crate::app::seam_stubs::Constructor>,
            _indices: Vec<usize>,
        ) {
        }
        fn get_semantics(
            &self,
            _prod: &dyn AssemblyProduction,
        ) -> Vec<Arc<dyn AssemblyConstructorSemantic>> {
            self.semantics.clone()
        }
        fn get_semantic(
            &self,
            _cons: &dyn crate::app::seam_stubs::Constructor,
        ) -> Option<Arc<dyn AssemblyConstructorSemantic>> {
            None
        }
        fn combine(&mut self, _that: &dyn AssemblyGrammar) {}
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

    /// A leaf child standing in for a token, proving `AssemblyParseTreeNode`'s minimal surface.
    struct MockLeaf {
        sym: Arc<dyn AssemblySymbol>,
        text: String,
    }

    impl AssemblyParseTreeNode for MockLeaf {
        fn get_sym(&self) -> Arc<dyn AssemblySymbol> {
            self.sym.clone()
        }
        fn print_indented(&self, _grammar: &dyn AssemblyGrammar, indent: &str) -> String {
            format!("{indent}'{}'\n", self.text)
        }
        fn generate_string(&self) -> String {
            self.text.clone()
        }
    }

    /// A minimal implementer, proving object-safety and exercising the default methods' real
    /// (non-trivial) behavior rather than trivially-true assertions.
    #[derive(Default)]
    struct Branch {
        prod: Option<Arc<dyn AssemblyProduction>>,
        substs: Mutex<Vec<Arc<dyn AssemblyParseTreeNode>>>,
    }

    impl AssemblyParseBranch for Branch {
        fn get_production(&self) -> Arc<dyn AssemblyProduction> {
            self.prod.clone().expect("production must be set")
        }
        fn get_substitutions(&self) -> Vec<Arc<dyn AssemblyParseTreeNode>> {
            self.substs.lock().unwrap().clone()
        }
        fn prepend_child(&mut self, child: Arc<dyn AssemblyParseTreeNode>) {
            self.substs.get_mut().unwrap().insert(0, child);
        }
    }

    /// Builds a branch for the production `insn => a b` (RHS symbols tagged `"a"` and `"b"`).
    fn make_branch() -> Branch {
        let mut rhs = MockSentential::default();
        rhs.add_symbol(Arc::new(MockSymbol("a")));
        rhs.add_symbol(Arc::new(MockSymbol("b")));
        let prod: Arc<dyn AssemblyProduction> = Arc::new(MockProduction {
            idx: 5,
            lhs: Arc::new(MockNonTerminal("insn")),
            rhs: Arc::new(rhs),
        });
        Branch { prod: Some(prod), substs: Mutex::new(Vec::new()) }
    }

    fn leaf(tag: &'static str, text: &str) -> Arc<dyn AssemblyParseTreeNode> {
        Arc::new(MockLeaf { sym: Arc::new(MockSymbol(tag)), text: text.to_string() })
    }

    #[test]
    fn expects_walks_rhs_right_to_left_until_complete() {
        let mut branch = make_branch();
        assert_eq!(branch.expects().unwrap().terminal_tag(), "b");
        branch.add_child(leaf("b", "2"));
        assert_eq!(branch.expects().unwrap().terminal_tag(), "a");
        branch.add_child(leaf("a", "1"));
        assert!(branch.expects().is_none());
    }

    #[test]
    fn is_complete_once_every_rhs_symbol_has_a_child() {
        let mut branch = make_branch();
        assert!(!branch.is_complete());
        branch.add_child(leaf("b", "2"));
        assert!(!branch.is_complete());
        branch.add_child(leaf("a", "1"));
        assert!(branch.is_complete());
    }

    #[test]
    fn add_child_aligns_reduction_order_to_rhs_order() {
        let mut branch = make_branch();
        branch.add_child(leaf("b", "2"));
        branch.add_child(leaf("a", "1"));
        assert_eq!(branch.generate_string(), "12");
    }

    #[test]
    fn get_sym_returns_the_production_lhs() {
        let branch = make_branch();
        assert_eq!(branch.get_sym().get_name(), "insn");
        assert_eq!(branch.display_string(), "[insn]");
    }

    #[test]
    fn is_constructor_delegates_to_the_production() {
        let branch = make_branch();
        assert!(branch.is_constructor());
    }

    #[test]
    fn get_substitution_indexes_children_in_rhs_order() {
        let mut branch = make_branch();
        branch.add_child(leaf("b", "2"));
        branch.add_child(leaf("a", "1"));
        assert_eq!(branch.get_substitution(0).generate_string(), "1");
        assert_eq!(branch.get_substitution(1).generate_string(), "2");
    }

    #[test]
    fn iter_yields_children_in_rhs_order() {
        let mut branch = make_branch();
        branch.add_child(leaf("b", "2"));
        branch.add_child(leaf("a", "1"));
        let texts: Vec<String> = branch.iter().map(|n| n.generate_string()).collect();
        assert_eq!(texts, vec!["1".to_string(), "2".to_string()]);
    }

    #[test]
    fn print_indented_includes_production_and_children_but_omits_semantics_when_empty() {
        let mut branch = make_branch();
        branch.add_child(leaf("b", "2"));
        branch.add_child(leaf("a", "1"));
        let grammar = MockGrammar::default();
        let out = branch.print_indented(&grammar, "");
        assert_eq!(out, "[insn] := 5. [insn] => a b\n  '1'\n  '2'\n");
    }

    #[test]
    fn print_indented_appends_joined_semantics_when_present() {
        let branch = make_branch();
        let grammar = MockGrammar {
            semantics: vec![
                Arc::new(MockSemantic("foo.sinc:1")),
                Arc::new(MockSemantic("foo.sinc:2")),
            ],
        };
        let out = branch.print_indented(&grammar, "");
        assert_eq!(out, "[insn] := 5. [insn] => a b (foo.sinc:1, foo.sinc:2)\n");
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let mut branch = make_branch();
        let as_dyn: &mut dyn AssemblyParseBranch = &mut branch;
        as_dyn.add_child(leaf("b", "2"));
        as_dyn.add_child(leaf("a", "1"));
        assert!(as_dyn.is_complete());
        assert_eq!(as_dyn.generate_string(), "12");
    }
}
