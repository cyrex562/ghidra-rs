//! Port of `ghidra.app.plugin.processors.sleigh.OpTplWalker`.

use crate::decompiler::opcodes::OpCode;
use crate::program::model::lang::sleigh::template::{ConstructTpl, OpTpl};
use crate::program::model::lang::sleigh::walker::ConstructTree;

/// Result of [`OpTplWalker::next_op_tpl`]: either an ordinary [`OpTpl`] to emit, or the operand
/// index of a virtual/BUILD directive to recurse into. Stands in for the `Object` Java's
/// `nextOpTpl()` returns (an `Integer` or an `OpTpl`), with `null` mapped to `None`.
#[derive(Debug, Clone)]
pub enum NextOpTpl<'a> {
    /// A BUILD directive (or virtual build directive, when there is no `oparray`) naming the
    /// operand to recurse into next.
    OperandIndex(i32),
    /// An ordinary p-code template op to emit as-is.
    Op(&'a OpTpl),
}

/// Walks the [`OpTpl`]s of a parse tree (or a single [`ConstructTpl`]) in the order they would
/// be emitted.
///
/// Port of `ghidra.app.plugin.processors.sleigh.OpTplWalker`. The tree is a [`ConstructTree`]
/// (see its docs) and the current node is an index into it.
pub struct OpTplWalker<'a> {
    tree: Option<&'a ConstructTree>,
    /// The current node being visited.
    point: Option<usize>,
    /// Current array of ops being traversed.
    oparray: Option<&'a [OpTpl]>,
    /// Depth of current node within the tree.
    depth: i32,
    /// Path of operands from the root.
    breadcrumb: Vec<i32>,
    /// Maximum number of directives for this point.
    maxsize: i32,
    sectionnum: i32,
}

impl<'a> OpTplWalker<'a> {
    /// Constructor for walking an entire parse tree from its node `root`, through the named
    /// section `sectionnum` (or the main section for `-1`). Port of
    /// `OpTplWalker(ConstructState, int)`.
    pub fn new(tree: &'a ConstructTree, root: usize, sectionnum: i32) -> Self {
        // NOTE: breadcrumb array size limits depth of parse
        let mut walker = Self {
            tree: Some(tree),
            point: Some(root),
            oparray: None,
            depth: 0,
            breadcrumb: vec![0; 64],
            maxsize: 0,
            sectionnum,
        };
        walker.setup_point();
        walker
    }

    /// Constructor for walking a single template. Port of `OpTplWalker(ConstructTpl)`.
    pub fn for_template(tpl: &'a ConstructTpl) -> Self {
        Self {
            tree: None,
            point: None,
            oparray: Some(&tpl.vec),
            depth: 0,
            breadcrumb: vec![0; 1],
            maxsize: tpl.vec.len() as i32,
            sectionnum: -1,
        }
    }

    /// Port of the private `setupPoint()`.
    fn setup_point(&mut self) {
        self.maxsize = 0;
        self.oparray = None;
        let (Some(tree), Some(point)) = (self.tree, self.point) else {
            return;
        };
        let Some(ct) = tree.get(point).ct.as_ref() else {
            return;
        };
        let tpl = if self.sectionnum < 0 {
            match ct.get_templ() {
                Some(tpl) => Some(tpl),
                None => return,
            }
        } else {
            ct.get_named_templ(self.sectionnum)
        };
        match tpl {
            // Empty named section implies straight list of build directives
            None => self.maxsize = ct.get_num_operands() as i32,
            Some(tpl) => {
                self.oparray = Some(&tpl.vec);
                self.maxsize = tpl.vec.len() as i32;
            }
        }
    }

    /// The tree node being visited. Port of `OpTplWalker.getState()`.
    pub fn get_state(&self) -> Option<usize> {
        self.point
    }

    /// Port of `OpTplWalker.isState()`.
    pub fn is_state(&self) -> bool {
        self.point.is_some() || self.maxsize > 0
    }

    /// While walking the ops in order, follow a particular BUILD directive into its respective
    /// constructor and template; use [`OpTplWalker::pop_build`] to backtrack. Port of
    /// `OpTplWalker.pushBuild(int)`.
    ///
    /// # Panics
    /// If the walker is not on a tree node or `buildnum` is not an operand of it (Java's
    /// `NullPointerException`/`IndexOutOfBoundsException`).
    pub fn push_build(&mut self, buildnum: i32) {
        let tree = self.tree.expect("pushBuild on a single-template walker");
        let point = self.point.expect("pushBuild past the end of the walk");
        self.point = Some(tree.get_sub_state(point, buildnum as usize));
        self.depth += 1;
        self.breadcrumb[self.depth as usize] = 0;
        self.setup_point();
    }

    /// Move to the parent of the current node. Port of `OpTplWalker.popBuild()`.
    pub fn pop_build(&mut self) {
        let (Some(tree), Some(point)) = (self.tree, self.point) else {
            self.maxsize = 0;
            self.oparray = None;
            return;
        };
        self.point = tree.get(point).parent;
        self.depth -= 1;
        if self.point.is_some() {
            self.setup_point();
        } else {
            self.maxsize = 0;
            self.oparray = None;
        }
    }

    /// The next op (or BUILD operand index) in traversal order, or `None` once this point is
    /// exhausted. Port of `OpTplWalker.nextOpTpl()`.
    pub fn next_op_tpl(&mut self) -> Option<NextOpTpl<'a>> {
        let depth = self.depth as usize;
        let curind = self.breadcrumb[depth];
        self.breadcrumb[depth] += 1;
        if curind >= self.maxsize {
            return None;
        }
        let Some(oparray) = self.oparray else {
            return Some(NextOpTpl::OperandIndex(curind)); // Virtual build directive
        };
        let op = &oparray[curind as usize];
        if op.get_opcode() != OpCode::CpuiMultiequal {
            // if NOT a build directive, return ordinary OpTpl
            return Some(NextOpTpl::Op(op));
        }
        // Get the operand index from the build directive
        Some(NextOpTpl::OperandIndex(
            op.get_in(0).offset.value_real as i32,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::sleigh::constructor::Constructor;
    use crate::program::model::lang::sleigh::template::const_tpl::{ConstTpl, ConstTplType};
    use crate::program::model::lang::sleigh::template::varnode_tpl::VarnodeTpl;
    use std::sync::Arc;

    fn real_varnode(offset: u64) -> VarnodeTpl {
        VarnodeTpl {
            space: ConstTpl::new(),
            offset: ConstTpl {
                tp: ConstTplType::Real,
                value_real: offset,
                value_spaceid: None,
                handle_index: 0,
                select: None,
            },
            size: ConstTpl::new(),
        }
    }

    fn leaf_constructor() -> Arc<Constructor> {
        let mut ct = Constructor::new();
        ct.templ = Some(ConstructTpl::new()); // empty op vec, no operands
        Arc::new(ct)
    }

    fn root_constructor(named: Option<ConstructTpl>) -> Arc<Constructor> {
        let mut copy_op = OpTpl::with_opcode(OpCode::CpuiCopy);
        copy_op.set_output(real_varnode(0));

        let mut build_op = OpTpl::with_opcode(OpCode::CpuiMultiequal);
        build_op.add_input(real_varnode(0)); // BUILD operand 0

        let mut tpl = ConstructTpl::new();
        tpl.vec.push(copy_op);
        tpl.vec.push(build_op);

        let mut ct = Constructor::new();
        ct.templ = Some(tpl);
        ct.operands = vec![7];
        ct.named_templ = vec![named];
        Arc::new(ct)
    }

    /// A root constructor whose template holds one ordinary op and a BUILD of operand 0, and a
    /// leaf constructor (operand 0) with an empty template.
    fn build_tree(named: Option<ConstructTpl>) -> ConstructTree {
        let mut tree = ConstructTree::new();
        tree.get_mut(ConstructTree::ROOT).ct = Some(root_constructor(named));
        let leaf = tree.add_state(Some(ConstructTree::ROOT));
        tree.get_mut(leaf).ct = Some(leaf_constructor());
        tree
    }

    #[test]
    fn walks_ordinary_op_then_follows_build_directive_and_pops_back() {
        let tree = build_tree(None);
        let mut walker = OpTplWalker::new(&tree, ConstructTree::ROOT, -1);

        assert!(walker.is_state());

        // First op: the ordinary CPUI_COPY.
        match walker.next_op_tpl() {
            Some(NextOpTpl::Op(op)) => assert_eq!(op.get_opcode(), OpCode::CpuiCopy),
            other => panic!("expected an ordinary op, got {other:?}"),
        }

        // Second op: a BUILD directive naming operand 0.
        match walker.next_op_tpl() {
            Some(NextOpTpl::OperandIndex(0)) => {}
            other => panic!("expected BUILD operand 0, got {other:?}"),
        }

        // No more ops at this point.
        assert!(walker.next_op_tpl().is_none());

        // Follow the BUILD directive into the leaf constructor.
        walker.push_build(0);
        assert_eq!(walker.get_state(), Some(1));
        // isState() is true whenever point is non-null, regardless of maxsize
        assert!(walker.is_state());
        // The leaf's template is empty (0 ops), so there is nothing left to walk here.
        assert!(walker.next_op_tpl().is_none());

        // Backtrack to the root; its ops were already consumed.
        walker.pop_build();
        assert_eq!(walker.get_state(), Some(ConstructTree::ROOT));
        assert!(walker.next_op_tpl().is_none());

        // Popping the root ends the walk.
        walker.pop_build();
        assert!(!walker.is_state());
    }

    #[test]
    fn empty_named_section_is_a_list_of_virtual_builds() {
        // Section 0 of the root is empty, so each operand is an implied BUILD.
        let tree = build_tree(None);
        let mut walker = OpTplWalker::new(&tree, ConstructTree::ROOT, 0);
        match walker.next_op_tpl() {
            Some(NextOpTpl::OperandIndex(0)) => {}
            other => panic!("expected virtual BUILD 0, got {other:?}"),
        }
        assert!(walker.next_op_tpl().is_none());
    }

    #[test]
    fn named_section_ops_are_walked_when_present() {
        let mut named = ConstructTpl::new();
        named.vec.push(OpTpl::with_opcode(OpCode::CpuiIntAdd));
        let tree = build_tree(Some(named));
        let mut walker = OpTplWalker::new(&tree, ConstructTree::ROOT, 0);
        match walker.next_op_tpl() {
            Some(NextOpTpl::Op(op)) => assert_eq!(op.get_opcode(), OpCode::CpuiIntAdd),
            other => panic!("expected INT_ADD, got {other:?}"),
        }
    }

    #[test]
    fn single_template_walk_has_no_state() {
        let mut tpl = ConstructTpl::new();
        tpl.vec.push(OpTpl::with_opcode(OpCode::CpuiCopy));
        let mut walker = OpTplWalker::for_template(&tpl);
        assert!(walker.is_state());
        assert!(walker.get_state().is_none());
        assert!(matches!(walker.next_op_tpl(), Some(NextOpTpl::Op(_))));
        assert!(walker.next_op_tpl().is_none());
        // popBuild with no point simply empties the walk
        walker.pop_build();
        assert!(!walker.is_state());
    }
}
