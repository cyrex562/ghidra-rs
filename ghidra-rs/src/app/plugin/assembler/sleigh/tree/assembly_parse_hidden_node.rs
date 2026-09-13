//! Mirrors `ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseHiddenNode`.

use std::sync::Arc;

use crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar;
use crate::app::plugin::assembler::sleigh::symbol::AssemblySymbol;
use crate::app::plugin::assembler::sleigh::tree::assembly_parse_tree_node::{
    AssemblyParseTreeNode, AssemblyParseTreeNodeBase,
};

/// A node that does not correspond to any symbol, and so is "hidden" from the parse tree's
/// generated text.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseHiddenNode`, a concrete class
/// extending [`AssemblyParseTreeNode`]. Per this crate's composition-over-inheritance convention,
/// the inherited state (`parent`, `grammar`) lives in a stored [`AssemblyParseTreeNodeBase`]
/// rather than being re-declared here -- this is the trait's first real (non-test) implementer.
///
/// # Deviation from Java: `getSym()` returns `null`
///
/// `AssemblyParseHiddenNode.getSym()` overrides the abstract `AssemblyParseTreeNode.getSym()` to
/// return `null`: a hidden node stands for nothing on the RHS of any production, so it has no
/// associated symbol. [`AssemblyParseTreeNode::get_sym`] was widened from `Arc<dyn AssemblySymbol>`
/// to `Option<Arc<dyn AssemblySymbol>>` (see that trait's own doc comment) specifically so this
/// type can return `None` faithfully, rather than fabricating a placeholder symbol Java never had.
///
/// # Deviation/quirk: `print(PrintStream, String)` ignores its `indent` argument
///
/// Every other `print(PrintStream, String)` override in this package (`AssemblyParseBranch`,
/// `AssemblyParseToken`) prepends `indent` to its output. `AssemblyParseHiddenNode.print` does not:
/// it unconditionally prints the literal text `<hidden>`, dropping the `indent` parameter on the
/// floor. That is reproduced as-is below (`print_indented` ignores its `indent` argument) rather
/// than "fixed" to match the sibling classes' behavior, with a dedicated test asserting the output
/// is indent-independent.
pub struct AssemblyParseHiddenNode {
    base: AssemblyParseTreeNodeBase,
}

impl AssemblyParseHiddenNode {
    /// Construct a hidden node for a tree parsed by the given grammar.
    ///
    /// Mirrors `AssemblyParseHiddenNode(AssemblyGrammar grammar)`.
    pub fn new(grammar: Arc<dyn AssemblyGrammar>) -> Self {
        Self { base: AssemblyParseTreeNodeBase::new(grammar) }
    }
}

impl AssemblyParseTreeNode for AssemblyParseHiddenNode {
    fn base(&self) -> &AssemblyParseTreeNodeBase {
        &self.base
    }

    /// Mirrors `AssemblyParseHiddenNode.getSym()`, which returns `null`. See the struct's own docs
    /// for why this trait's `get_sym` returns `Option`.
    fn get_sym(&self) -> Option<Arc<dyn AssemblySymbol>> {
        None
    }

    /// Mirrors the protected `AssemblyParseHiddenNode.print(PrintStream, String)`, which ignores
    /// its `indent` parameter entirely (see the struct's own docs).
    fn print_indented(&self, _indent: &str) -> String {
        "<hidden>".to_string()
    }

    /// Mirrors `AssemblyParseHiddenNode.generateString()`: a hidden node contributes nothing to
    /// the generated text.
    fn generate_string(&self) -> String {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::{
        AssemblyConstructorSemantic, AssemblyNonTerminal,
        AssemblyProduction as SeamAssemblyProduction,
    };
    use crate::app::plugin::assembler::sleigh::tree::assembly_parse_branch::AssemblyParseBranch;

    /// A grammar that records nothing -- these tests don't exercise any real grammar behavior,
    /// only that a node correctly hands back whatever grammar it was built with.
    struct MockGrammar;

    impl AssemblyGrammar for MockGrammar {
        fn add_production(&mut self, _prod: Arc<dyn SeamAssemblyProduction>) {}
        fn add_constructor_production(
            &mut self,
            _lhs: Arc<dyn AssemblyNonTerminal>,
            _rhs: Arc<
                dyn crate::app::plugin::assembler::sleigh::grammars::AssemblySentential,
            >,
            _pattern: crate::program::model::lang::sleigh::pattern::DisjointPattern,
            _cons: Arc<dyn crate::app::seam_stubs::Constructor>,
            _indices: Vec<usize>,
        ) {
        }
        fn get_semantics(
            &self,
            _prod: &dyn SeamAssemblyProduction,
        ) -> Vec<Arc<dyn AssemblyConstructorSemantic>> {
            Vec::new()
        }
        fn get_semantic(
            &self,
            _cons: &dyn crate::app::seam_stubs::Constructor,
        ) -> Option<Arc<dyn AssemblyConstructorSemantic>> {
            None
        }
        fn combine(&mut self, _that: &dyn AssemblyGrammar) {}
        fn get_pure_recursive(&self) -> Vec<Arc<dyn SeamAssemblyProduction>> {
            Vec::new()
        }
        fn get_pure_recursion(
            &self,
            _lhs: &dyn AssemblyNonTerminal,
        ) -> Option<Arc<dyn SeamAssemblyProduction>> {
            None
        }
    }

    /// A minimal implementer of [`AssemblyParseBranch`], used only as a `parent` value below.
    struct StubBranch;

    impl AssemblyParseBranch for StubBranch {
        fn get_production(&self) -> Arc<dyn crate::app::seam_stubs::AssemblyProduction> {
            unimplemented!("not exercised by this test")
        }
        fn get_substitutions(
            &self,
        ) -> Vec<Arc<dyn crate::app::seam_stubs::AssemblyParseTreeNode>> {
            Vec::new()
        }
        fn prepend_child(&mut self, _child: Arc<dyn crate::app::seam_stubs::AssemblyParseTreeNode>) {
            unimplemented!("not exercised by this test")
        }
    }

    #[test]
    fn get_grammar_returns_the_constructor_argument() {
        let grammar: Arc<dyn AssemblyGrammar> = Arc::new(MockGrammar);
        let node = AssemblyParseHiddenNode::new(grammar.clone());
        assert!(Arc::ptr_eq(&node.get_grammar(), &grammar));
    }

    /// Java: `AssemblyParseHiddenNode.getSym()` always returns `null`.
    #[test]
    fn get_sym_is_always_none() {
        let node = AssemblyParseHiddenNode::new(Arc::new(MockGrammar));
        assert!(node.get_sym().is_none());
    }

    /// Java: `generateString()` contributes nothing.
    #[test]
    fn generate_string_is_empty() {
        let node = AssemblyParseHiddenNode::new(Arc::new(MockGrammar));
        assert_eq!(node.generate_string(), "");
    }

    /// Java: `print(PrintStream, String)` always prints the literal `<hidden>`.
    #[test]
    fn print_indented_is_always_hidden_marker() {
        let node = AssemblyParseHiddenNode::new(Arc::new(MockGrammar));
        assert_eq!(node.print_indented(""), "<hidden>");
    }

    /// Quirk (see the struct's own docs): unlike its sibling node types, the `indent` argument is
    /// completely ignored -- the output is identical no matter what indent is passed.
    #[test]
    fn print_indented_ignores_the_indent_argument() {
        let node = AssemblyParseHiddenNode::new(Arc::new(MockGrammar));
        assert_eq!(node.print_indented("    "), node.print_indented(""));
        assert_eq!(node.print_indented("    "), "<hidden>");
    }

    /// Java: `print(PrintStream)` (inherited from `AssemblyParseTreeNode`) just calls
    /// `print(out, "")`.
    #[test]
    fn print_delegates_to_print_indented_with_empty_indent() {
        let node = AssemblyParseHiddenNode::new(Arc::new(MockGrammar));
        assert_eq!(node.print(), "<hidden>");
    }

    #[test]
    fn get_parent_is_none_before_set_parent() {
        let node = AssemblyParseHiddenNode::new(Arc::new(MockGrammar));
        assert!(node.get_parent().is_none());
    }

    #[test]
    fn set_parent_then_get_parent_round_trips_while_parent_is_alive() {
        let node = AssemblyParseHiddenNode::new(Arc::new(MockGrammar));
        let parent: Arc<dyn AssemblyParseBranch> = Arc::new(StubBranch);

        node.set_parent(Some(&parent));

        assert!(node.get_parent().is_some());
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let node = AssemblyParseHiddenNode::new(Arc::new(MockGrammar));
        let as_dyn: &dyn AssemblyParseTreeNode = &node;
        assert_eq!(as_dyn.generate_string(), "");
        assert!(as_dyn.get_sym().is_none());
        assert_eq!(as_dyn.print(), "<hidden>");
    }
}
