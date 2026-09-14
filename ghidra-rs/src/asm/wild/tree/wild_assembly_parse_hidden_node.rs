//! Port of `ghidra.asm.wild.tree.WildAssemblyParseHiddenNode`.

use std::sync::Arc;

use crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar;
use crate::app::plugin::assembler::sleigh::symbol::AssemblySymbol;
use crate::app::plugin::assembler::sleigh::tree::assembly_parse_tree_node::{
    AssemblyParseTreeNode, AssemblyParseTreeNodeBase,
};

/// A hidden parse-tree node standing in for an unmatched wildcard operand.
///
/// Port of `ghidra.asm.wild.tree.WildAssemblyParseHiddenNode`, a concrete class extending
/// [`AssemblyParseTreeNode`] directly -- *not*
/// [`AssemblyParseHiddenNode`](crate::app::plugin::assembler::sleigh::tree::AssemblyParseHiddenNode),
/// despite the similar name and near-identical behavior (both hide themselves from generated
/// text, return no symbol, and print a fixed marker ignoring their indent). Ported per this
/// crate's composition-over-inheritance convention with a stored [`AssemblyParseTreeNodeBase`],
/// the same treatment `AssemblyParseHiddenNode` itself received.
///
/// # Deviation/quirk: `print(PrintStream, String)` ignores its `indent` argument
///
/// Like its sibling `AssemblyParseHiddenNode`, this class's `print` override unconditionally
/// prints the literal text `<wild-hidden>`, dropping the `indent` parameter on the floor. That is
/// reproduced as-is below (`print_indented` ignores its `indent` argument), with a dedicated test
/// asserting the output is indent-independent.
pub struct WildAssemblyParseHiddenNode {
    base: AssemblyParseTreeNodeBase,
    /// The wildcard name this hidden node stands in for.
    ///
    /// Port of the public final field `WildAssemblyParseHiddenNode.wildcard`.
    pub wildcard: String,
}

impl WildAssemblyParseHiddenNode {
    /// Construct a hidden node for a tree parsed by the given grammar, standing in for the given
    /// wildcard.
    ///
    /// Port of `WildAssemblyParseHiddenNode(AssemblyGrammar grammar, String wildcard)`.
    pub fn new(grammar: Arc<dyn AssemblyGrammar>, wildcard: impl Into<String>) -> Self {
        Self { base: AssemblyParseTreeNodeBase::new(grammar), wildcard: wildcard.into() }
    }
}

impl AssemblyParseTreeNode for WildAssemblyParseHiddenNode {
    fn base(&self) -> &AssemblyParseTreeNodeBase {
        &self.base
    }

    /// Port of `WildAssemblyParseHiddenNode.getSym()`, which returns `null`. See
    /// [`AssemblyParseTreeNode::get_sym`]'s own docs for why this trait's `get_sym` returns
    /// `Option`.
    fn get_sym(&self) -> Option<Arc<dyn AssemblySymbol>> {
        None
    }

    /// Port of the protected `WildAssemblyParseHiddenNode.print(PrintStream, String)`, which
    /// ignores its `indent` parameter entirely (see the struct's own docs).
    fn print_indented(&self, _indent: &str) -> String {
        "<wild-hidden>".to_string()
    }

    /// Port of `WildAssemblyParseHiddenNode.generateString()`: a hidden node contributes nothing
    /// to the generated text.
    fn generate_string(&self) -> String {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::assembler::sleigh::tree::assembly_parse_branch::AssemblyParseBranch;
    use crate::app::seam_stubs::{
        AssemblyConstructorSemantic, AssemblyNonTerminal,
        AssemblyProduction as SeamAssemblyProduction,
    };

    /// A grammar that records nothing -- these tests don't exercise any real grammar behavior,
    /// only that a node correctly hands back whatever grammar it was built with.
    struct MockGrammar;

    impl AssemblyGrammar for MockGrammar {
        fn add_production(&mut self, _prod: Arc<dyn SeamAssemblyProduction>) {}
        fn add_constructor_production(
            &mut self,
            _lhs: Arc<dyn AssemblyNonTerminal>,
            _rhs: Arc<dyn crate::app::plugin::assembler::sleigh::grammars::AssemblySentential>,
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
        fn get_substitutions(&self) -> Vec<Arc<dyn crate::app::seam_stubs::AssemblyParseTreeNode>> {
            Vec::new()
        }
        fn prepend_child(&mut self, _child: Arc<dyn crate::app::seam_stubs::AssemblyParseTreeNode>) {
            unimplemented!("not exercised by this test")
        }
    }

    #[test]
    fn get_grammar_returns_the_constructor_argument() {
        let grammar: Arc<dyn AssemblyGrammar> = Arc::new(MockGrammar);
        let node = WildAssemblyParseHiddenNode::new(grammar.clone(), "reg");
        assert!(Arc::ptr_eq(&node.get_grammar(), &grammar));
    }

    #[test]
    fn wildcard_field_stores_constructor_argument() {
        let node = WildAssemblyParseHiddenNode::new(Arc::new(MockGrammar), "reg");
        assert_eq!(node.wildcard, "reg");
    }

    /// Java: `WildAssemblyParseHiddenNode.getSym()` always returns `null`.
    #[test]
    fn get_sym_is_always_none() {
        let node = WildAssemblyParseHiddenNode::new(Arc::new(MockGrammar), "reg");
        assert!(node.get_sym().is_none());
    }

    /// Java: `generateString()` contributes nothing.
    #[test]
    fn generate_string_is_empty() {
        let node = WildAssemblyParseHiddenNode::new(Arc::new(MockGrammar), "reg");
        assert_eq!(node.generate_string(), "");
    }

    /// Java: `print(PrintStream, String)` always prints the literal `<wild-hidden>`.
    #[test]
    fn print_indented_is_always_wild_hidden_marker() {
        let node = WildAssemblyParseHiddenNode::new(Arc::new(MockGrammar), "reg");
        assert_eq!(node.print_indented(""), "<wild-hidden>");
    }

    /// Quirk (see the struct's own docs): the `indent` argument is completely ignored -- the
    /// output is identical no matter what indent is passed.
    #[test]
    fn print_indented_ignores_the_indent_argument() {
        let node = WildAssemblyParseHiddenNode::new(Arc::new(MockGrammar), "reg");
        assert_eq!(node.print_indented("    "), node.print_indented(""));
        assert_eq!(node.print_indented("    "), "<wild-hidden>");
    }

    /// Java: `print(PrintStream)` (inherited from `AssemblyParseTreeNode`) just calls
    /// `print(out, "")`.
    #[test]
    fn print_delegates_to_print_indented_with_empty_indent() {
        let node = WildAssemblyParseHiddenNode::new(Arc::new(MockGrammar), "reg");
        assert_eq!(node.print(), "<wild-hidden>");
    }

    #[test]
    fn get_parent_is_none_before_set_parent() {
        let node = WildAssemblyParseHiddenNode::new(Arc::new(MockGrammar), "reg");
        assert!(node.get_parent().is_none());
    }

    #[test]
    fn set_parent_then_get_parent_round_trips_while_parent_is_alive() {
        let node = WildAssemblyParseHiddenNode::new(Arc::new(MockGrammar), "reg");
        let parent: Arc<dyn AssemblyParseBranch> = Arc::new(StubBranch);

        node.set_parent(Some(&parent));

        assert!(node.get_parent().is_some());
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let node = WildAssemblyParseHiddenNode::new(Arc::new(MockGrammar), "reg");
        let as_dyn: &dyn AssemblyParseTreeNode = &node;
        assert_eq!(as_dyn.generate_string(), "");
        assert!(as_dyn.get_sym().is_none());
        assert_eq!(as_dyn.print(), "<wild-hidden>");
    }
}
