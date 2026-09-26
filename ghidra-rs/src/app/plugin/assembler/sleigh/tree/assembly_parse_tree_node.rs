//! Mirrors `ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseTreeNode`.

use std::sync::{Arc, Mutex, Weak};

use crate::app::plugin::assembler::sleigh::grammars::AssemblyGrammar;
use crate::app::plugin::assembler::sleigh::symbol::AssemblySymbol;
use crate::app::plugin::assembler::sleigh::tree::assembly_parse_branch::AssemblyParseBranch;

/// A node in a parse tree.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseTreeNode`, an abstract class with
/// no `extends` clause. Ported per this crate's composition-over-inheritance convention:
/// [`AssemblyParseTreeNodeBase`] holds the two fields the Java class declares (`parent`, the
/// `final grammar`) and the concrete (non-abstract) methods built on them
/// ([`get_parent`](AssemblyParseTreeNodeBase::get_parent),
/// [`set_parent`](AssemblyParseTreeNodeBase::set_parent),
/// [`get_grammar`](AssemblyParseTreeNodeBase::get_grammar)); the [`AssemblyParseTreeNode`] trait
/// requires a concrete node to expose that base (via [`base`](AssemblyParseTreeNode::base)) and to
/// supply the three abstract members (`getSym()`, the protected `print(PrintStream, String)`, and
/// `generateString()`), while providing the base's concrete methods (plus the public `print()`
/// convenience overload) as defaults built on top.
///
/// # Relationship to the existing `AssemblyParseBranch`/`AssemblyParseToken` ports
///
/// `ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseBranch` and `...AssemblyParseToken` --
/// the class's only two direct Java subclasses -- were already ported before this class was, and
/// each deliberately narrowed itself to just its own declared members, leaving this superclass's
/// surface (`getParent`/`setParent`/`getGrammar`/the public `print(PrintStream)` overload, plus the
/// `grammar` field itself) for "its own port" -- see their own module docs. Those two ports
/// currently speak a lighter placeholder trait,
/// [`crate::app::seam_stubs::AssemblyParseTreeNode`], as their shared child/parent type instead of
/// this one (that placeholder's `print_indented` takes the grammar as an explicit parameter,
/// precisely because the concrete types behind it don't hold a grammar field of their own). This
/// port does *not* retrofit those two already-complete, already-tested ports onto this new real
/// base -- doing so would mean threading a `base(&self) -> &AssemblyParseTreeNodeBase` requirement
/// (and therefore a stored `grammar`/`parent`) through every implementer of both traits, which is a
/// collateral rewire across the grammar/tree/parse packages well outside a single class's porting
/// scope. This mirrors the precedent already set by
/// [`AssemblySymbol`](crate::app::plugin::assembler::sleigh::symbol::AssemblySymbol), whose real
/// port likewise left its own still-depended-upon `crate::app::seam_stubs::AssemblySymbol`
/// placeholder in place rather than migrating its ~15 call sites as a side effect.
///
/// # Deviations from Java
///
/// * **`parent` is a [`Weak`] reference, not a strong one.** Java's `protected AssemblyParseBranch
///   parent` is an ordinary (strong) field; the GC has no trouble with a branch owning its children
///   (`AssemblyParseBranch.substs`) while a child also points back at its parent, since that's just
///   a reference cycle a tracing collector reclaims normally. Rust's `Arc` cannot: a strong
///   `parent: Arc<dyn AssemblyParseBranch>` alongside a branch's `substs: Vec<Arc<dyn
///   AssemblyParseTreeNode>>` would be an unreclaimable cycle. Storing `parent` as a [`Weak`]
///   instead breaks the cycle at the cost of [`get_parent`](AssemblyParseTreeNodeBase::get_parent)
///   returning `None` if every strong reference to the parent has already been dropped elsewhere --
///   which never happens in Java (nothing drops a live branch out from under its own children) and
///   is exercised as a deliberate, documented case in this port's own tests rather than silently
///   assumed away.
pub struct AssemblyParseTreeNodeBase {
    parent: Mutex<Option<Weak<dyn AssemblyParseBranch>>>,
    grammar: Arc<dyn AssemblyGrammar>,
}

impl AssemblyParseTreeNodeBase {
    /// Construct a node for a tree parsed by the given grammar.
    ///
    /// Mirrors `AssemblyParseTreeNode(AssemblyGrammar grammar)`.
    pub fn new(grammar: Arc<dyn AssemblyGrammar>) -> Self {
        Self { parent: Mutex::new(None), grammar }
    }

    /// Get the branch which contains this node.
    ///
    /// Mirrors `AssemblyParseTreeNode.getParent()`. See the struct's own docs for why this can
    /// return `None` even after [`set_parent`](Self::set_parent) was called with `Some`, unlike
    /// Java's strong-reference field.
    pub fn get_parent(&self) -> Option<Arc<dyn AssemblyParseBranch>> {
        self.parent.lock().unwrap().as_ref().and_then(Weak::upgrade)
    }

    /// Set the branch which contains this node.
    ///
    /// Mirrors the protected `AssemblyParseTreeNode.setParent(AssemblyParseBranch)`. Java's own
    /// comment on this method: "NOTE: Cannot assert, since the LR parser may backtrack and
    /// reassign." -- reproduced here as-is; this method performs no validation of the previous
    /// value for exactly that reason.
    pub fn set_parent(&self, parent: Option<&Arc<dyn AssemblyParseBranch>>) {
        *self.parent.lock().unwrap() = parent.map(Arc::downgrade);
    }

    /// Get the grammar used to parse the tree.
    ///
    /// Mirrors `AssemblyParseTreeNode.getGrammar()`.
    pub fn get_grammar(&self) -> Arc<dyn AssemblyGrammar> {
        self.grammar.clone()
    }
}

/// Port of the `ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseTreeNode` abstract class. See
/// the module docs for the composition-over-inheritance split with [`AssemblyParseTreeNodeBase`].
pub trait AssemblyParseTreeNode {
    /// The shared state (`parent`, `grammar`) every parse tree node carries.
    fn base(&self) -> &AssemblyParseTreeNodeBase;

    /// Get the symbol for which this node is substituted.
    ///
    /// For a branch, this is the LHS of the corresponding production. For a token, this is the
    /// terminal whose tokenizer matched it. For a hidden node (see
    /// [`AssemblyParseHiddenNode`](crate::app::plugin::assembler::sleigh::tree::AssemblyParseHiddenNode)),
    /// there is no associated symbol.
    ///
    /// Mirrors the abstract `AssemblyParseTreeNode.getSym()`. Returns `Option` rather than a bare
    /// `Arc<dyn AssemblySymbol>` because the Java method is declared to return a plain (nullable)
    /// `AssemblySymbol`, and `AssemblyParseHiddenNode.getSym()` really does return `null` --
    /// reproduced here as `None` rather than fabricated as some placeholder symbol.
    fn get_sym(&self) -> Option<Arc<dyn AssemblySymbol>>;

    /// For debugging: format the tree with the given indent.
    ///
    /// Mirrors the protected abstract `AssemblyParseTreeNode.print(PrintStream, String)`,
    /// returning the formatted text instead of writing it to a stream, per this crate's
    /// `display_string`/`print_indented` convention.
    fn print_indented(&self, indent: &str) -> String;

    /// Generate the string that this node parsed.
    ///
    /// Mirrors the abstract `AssemblyParseTreeNode.generateString()`.
    fn generate_string(&self) -> String;

    /// Get the branch which contains this node.
    ///
    /// Mirrors `AssemblyParseTreeNode.getParent()`.
    fn get_parent(&self) -> Option<Arc<dyn AssemblyParseBranch>> {
        self.base().get_parent()
    }

    /// Set the branch which contains this node.
    ///
    /// Mirrors the protected `AssemblyParseTreeNode.setParent(AssemblyParseBranch)`.
    fn set_parent(&self, parent: Option<&Arc<dyn AssemblyParseBranch>>) {
        self.base().set_parent(parent)
    }

    /// Get the grammar used to parse the tree.
    ///
    /// Mirrors `AssemblyParseTreeNode.getGrammar()`.
    fn get_grammar(&self) -> Arc<dyn AssemblyGrammar> {
        self.base().get_grammar()
    }

    /// For debugging: display this parse tree.
    ///
    /// Mirrors `AssemblyParseTreeNode.print(PrintStream)`, which just calls `print(out, "")`;
    /// returns the formatted text instead of writing it to a stream, matching
    /// [`print_indented`](Self::print_indented).
    fn print(&self) -> String {
        self.print_indented("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::{
        AssemblyConstructorSemantic, AssemblyNonTerminal,
        AssemblyProduction as SeamAssemblyProduction,
    };

    struct MockSymbol(&'static str);

    impl std::fmt::Display for MockSymbol {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl AssemblySymbol for MockSymbol {
        fn name(&self) -> &str {
            self.0
        }
    }

    /// A grammar that records nothing -- this module's tests don't exercise any real grammar
    /// behavior, only that a node correctly hands back whatever grammar it was built with.
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

    /// A leaf node with no children, standing in for a concrete subclass like `AssemblyParseToken`.
    struct Leaf {
        base: AssemblyParseTreeNodeBase,
        sym: Arc<dyn AssemblySymbol>,
        text: String,
    }

    impl AssemblyParseTreeNode for Leaf {
        fn base(&self) -> &AssemblyParseTreeNodeBase {
            &self.base
        }
        fn get_sym(&self) -> Option<Arc<dyn AssemblySymbol>> {
            Some(self.sym.clone())
        }
        fn print_indented(&self, indent: &str) -> String {
            format!("{indent}'{}'\n", self.text)
        }
        fn generate_string(&self) -> String {
            self.text.clone()
        }
    }

    /// A minimal implementer of the real, already-ported [`AssemblyParseBranch`] trait, used only
    /// as a `parent` value in these tests.
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

    fn leaf(grammar: Arc<dyn AssemblyGrammar>, tag: &'static str, text: &str) -> Leaf {
        Leaf {
            base: AssemblyParseTreeNodeBase::new(grammar),
            sym: Arc::new(MockSymbol(tag)),
            text: text.to_string(),
        }
    }

    /// Java: `getGrammar()` returns exactly the constructor's `grammar` argument.
    #[test]
    fn get_grammar_returns_the_constructor_argument() {
        let grammar: Arc<dyn AssemblyGrammar> = Arc::new(MockGrammar);
        let node = leaf(grammar.clone(), "imm", "42");
        assert!(Arc::ptr_eq(&node.get_grammar(), &grammar));
    }

    /// Java: `getParent()` returns `null` (here, `None`) before `setParent` is ever called.
    #[test]
    fn get_parent_is_none_before_set_parent() {
        let node = leaf(Arc::new(MockGrammar), "imm", "42");
        assert!(node.get_parent().is_none());
    }

    /// Java: `setParent`/`getParent` round-trip while the parent is still alive elsewhere.
    #[test]
    fn set_parent_then_get_parent_round_trips_while_parent_is_alive() {
        let node = leaf(Arc::new(MockGrammar), "imm", "42");
        let parent: Arc<dyn AssemblyParseBranch> = Arc::new(StubBranch);

        node.set_parent(Some(&parent));

        assert!(node.get_parent().is_some());
        drop(parent);
    }

    /// Java's `setParent` doc comment: "NOTE: Cannot assert, since the LR parser may backtrack and
    /// reassign." -- reassigning (including clearing back to `None`) is accepted unconditionally,
    /// with no validation of the previous value.
    #[test]
    fn set_parent_allows_reassignment_and_clearing() {
        let node = leaf(Arc::new(MockGrammar), "imm", "42");
        let first: Arc<dyn AssemblyParseBranch> = Arc::new(StubBranch);
        let second: Arc<dyn AssemblyParseBranch> = Arc::new(StubBranch);

        node.set_parent(Some(&first));
        assert!(node.get_parent().is_some());

        node.set_parent(Some(&second));
        assert!(node.get_parent().is_some());

        node.set_parent(None);
        assert!(node.get_parent().is_none());
    }

    /// Deviation from Java (documented on [`AssemblyParseTreeNodeBase`]): once every strong
    /// reference to the parent is dropped, `get_parent` reports `None` rather than keeping the
    /// parent alive -- the trade-off this port makes to avoid an unreclaimable `Arc` cycle.
    #[test]
    fn get_parent_becomes_none_once_the_parent_is_dropped() {
        let node = leaf(Arc::new(MockGrammar), "imm", "42");
        let parent: Arc<dyn AssemblyParseBranch> = Arc::new(StubBranch);
        node.set_parent(Some(&parent));
        assert!(node.get_parent().is_some());

        drop(parent);

        assert!(node.get_parent().is_none());
    }

    /// Java: `print(PrintStream)` just calls `print(out, "")`.
    #[test]
    fn print_delegates_to_print_indented_with_empty_indent() {
        let node = leaf(Arc::new(MockGrammar), "imm", "42");
        assert_eq!(node.print(), node.print_indented(""));
        assert_eq!(node.print(), "'42'\n");
    }

    #[test]
    fn generate_string_returns_the_raw_value() {
        let node = leaf(Arc::new(MockGrammar), "imm", "42");
        assert_eq!(node.generate_string(), "42");
    }

    #[test]
    fn get_sym_returns_the_matched_symbol() {
        let node = leaf(Arc::new(MockGrammar), "imm", "42");
        assert_eq!(node.get_sym().unwrap().get_name(), "imm");
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let node = leaf(Arc::new(MockGrammar), "imm", "42");
        let as_dyn: &dyn AssemblyParseTreeNode = &node;
        assert_eq!(as_dyn.generate_string(), "42");
        assert!(as_dyn.get_parent().is_none());
    }
}
