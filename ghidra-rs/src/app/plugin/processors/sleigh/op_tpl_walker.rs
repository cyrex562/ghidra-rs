use crate::app::seam_stubs::ConstructState;
use crate::decompiler::opcodes::OpCode;
use crate::program::model::lang::sleigh::template::OpTpl;
use std::sync::Arc;

/// Result of [`OpTplWalker::next_op_tpl`]: either an ordinary [`OpTpl`] to emit, or the operand
/// index of a virtual/BUILD directive to recurse into. Stands in for the `Object` Java's
/// `nextOpTpl()` returns (an `Integer` or an `OpTpl`), with `null` mapped to `None`.
#[derive(Debug, Clone)]
pub enum NextOpTpl {
    /// A BUILD directive (or virtual build directive, when there is no `oparray`) naming the
    /// operand to recurse into next.
    OperandIndex(i32),
    /// An ordinary p-code template op to emit as-is.
    Op(OpTpl),
}

/// Walks the [`OpTpl`]s of a parse tree (or a single [`ConstructTpl`]) in the correct order.
///
/// Port of `ghidra.app.plugin.processors.sleigh.OpTplWalker`. Supports walking the tree of an
/// entire `SleighInstructionPrototype` or just a single `ConstructTpl`. The private `setupPoint`
/// helper is exposed as a default method ([`setup_point`](Self::setup_point)) since the other
/// default methods need to call it; it is not meant to be called directly by users of the trait.
///
/// Java's two constructors are dropped, as traits cannot provide them; a concrete implementor is
/// expected to offer equivalents (one seeded with a root [`ConstructState`] and section number,
/// walking [`setup_point`](Self::setup_point) immediately; one seeded with a single
/// `ConstructTpl`'s op vector directly, with no `point`). Java's fixed-size `breadcrumb` array
/// (sized to cap recursion depth at 64, or 1 for the single-template constructor) is modeled as a
/// growable `Vec<i32>` instead, since a trait has no constructor to size it up front; this only
/// relaxes the artificial depth cap, it does not change walking behavior.
pub trait OpTplWalker {
    /// The current node being visited (Java's `point` field), or `None` when walking a single
    /// template with no parse tree.
    fn point(&self) -> Option<Arc<dyn ConstructState>>;
    /// Sets [`point`](Self::point).
    fn set_point(&mut self, point: Option<Arc<dyn ConstructState>>);

    /// The current array of ops being traversed (Java's `oparray` field), or `None` for an empty
    /// named section implying a straight list of build directives.
    fn oparray(&self) -> Option<&Vec<OpTpl>>;
    /// Sets [`oparray`](Self::oparray).
    fn set_oparray(&mut self, oparray: Option<Vec<OpTpl>>);

    /// Depth of the current node within the tree (Java's `depth` field).
    fn depth(&self) -> i32;
    /// Sets [`depth`](Self::depth).
    fn set_depth(&mut self, depth: i32);

    /// Path of operands from the root (Java's `breadcrumb` field), indexed by
    /// [`depth`](Self::depth).
    fn breadcrumb(&self) -> &Vec<i32>;
    /// Mutable access to [`breadcrumb`](Self::breadcrumb).
    fn breadcrumb_mut(&mut self) -> &mut Vec<i32>;

    /// Maximum number of directives for this point (Java's `maxsize` field).
    fn maxsize(&self) -> i32;
    /// Sets [`maxsize`](Self::maxsize).
    fn set_maxsize(&mut self, maxsize: i32);

    /// The named section being traversed, or -1 for the main section (Java's `sectionnum` field,
    /// fixed at construction).
    fn sectionnum(&self) -> i32;

    /// Recomputes [`oparray`](Self::oparray)/[`maxsize`](Self::maxsize) for the current
    /// [`point`](Self::point). Stands in for the private `setupPoint()`.
    fn setup_point(&mut self) {
        self.set_maxsize(0);
        self.set_oparray(None);
        let Some(point) = self.point() else {
            return;
        };
        let Some(ct) = point.constructor() else {
            return;
        };
        let sectionnum = self.sectionnum();
        let tpl = if sectionnum < 0 {
            match ct.templ.clone() {
                Some(tpl) => tpl,
                None => return,
            }
        } else {
            match ct
                .named_templ
                .get(sectionnum as usize)
                .and_then(|t| t.clone())
            {
                Some(tpl) => tpl,
                // Empty named section implies straight list of build directives.
                None => {
                    self.set_maxsize(ct.operands.len() as i32);
                    return;
                }
            }
        };
        self.set_maxsize(tpl.vec.len() as i32);
        self.set_oparray(Some(tpl.vec));
    }

    /// Stands in for `OpTplWalker.getState()`.
    fn get_state(&self) -> Option<Arc<dyn ConstructState>> {
        self.point()
    }

    /// Stands in for `OpTplWalker.isState()`.
    fn is_state(&self) -> bool {
        self.point().is_some() || self.maxsize() > 0
    }

    /// While walking the [`OpTpl`]s in order, follow a particular BUILD directive into its
    /// respective constructor/template. Use [`pop_build`](Self::pop_build) to backtrack. Stands
    /// in for `OpTplWalker.pushBuild(int)`.
    fn push_build(&mut self, buildnum: i32) {
        let next = self.point().map(|point| point.sub_state(buildnum));
        self.set_point(next);
        self.set_depth(self.depth() + 1);
        let depth = self.depth() as usize;
        let breadcrumb = self.breadcrumb_mut();
        if breadcrumb.len() <= depth {
            breadcrumb.resize(depth + 1, 0);
        }
        breadcrumb[depth] = 0;
        self.setup_point();
    }

    /// Moves to the parent of the current node. Stands in for `OpTplWalker.popBuild()`.
    fn pop_build(&mut self) {
        let Some(point) = self.point() else {
            self.set_maxsize(0);
            self.set_oparray(None);
            return;
        };
        let parent = point.parent();
        self.set_point(parent.clone());
        self.set_depth(self.depth() - 1);
        if parent.is_some() {
            self.setup_point();
        } else {
            self.set_maxsize(0);
            self.set_oparray(None);
        }
    }

    /// Returns the next [`OpTpl`] (or BUILD operand index) in traversal order, or `None` once
    /// this point is exhausted. Stands in for `OpTplWalker.nextOpTpl()`.
    fn next_op_tpl(&mut self) -> Option<NextOpTpl> {
        let depth = self.depth() as usize;
        let breadcrumb = self.breadcrumb_mut();
        if breadcrumb.len() <= depth {
            breadcrumb.resize(depth + 1, 0);
        }
        let curind = breadcrumb[depth];
        breadcrumb[depth] += 1;
        if curind >= self.maxsize() {
            return None;
        }
        let Some(oparray) = self.oparray() else {
            // Virtual build directive.
            return Some(NextOpTpl::OperandIndex(curind));
        };
        let op = &oparray[curind as usize];
        if op.get_opcode() != OpCode::CpuiMultiequal {
            // Not a build directive: return the ordinary OpTpl.
            return Some(NextOpTpl::Op(op.clone()));
        }
        // Get the operand index from the build directive.
        let real_curind = op.get_in(0).offset.value_real as i32;
        Some(NextOpTpl::OperandIndex(real_curind))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::sleigh::constructor::Constructor;
    use crate::program::model::lang::sleigh::template::const_tpl::{ConstTpl, ConstTplType};
    use crate::program::model::lang::sleigh::template::varnode_tpl::VarnodeTpl;
    use crate::program::model::lang::sleigh::template::ConstructTpl;
    use std::sync::Mutex;

    /// A tiny fixed two-node tree: a root constructor whose template contains one ordinary op
    /// and one BUILD directive targeting operand 0, and a single child (leaf) constructor with
    /// an empty template (a bare list of `num_operands` virtual build directives). Parent/child
    /// links are wired up (via interior mutability, since both sides of the link must exist
    /// before the other can reference it) once both nodes are built, in
    /// [`build_tree`](self::build_tree).
    struct MockConstructState {
        ct: Option<Arc<Constructor>>,
        parent: Mutex<Option<Arc<dyn ConstructState>>>,
        children: Mutex<Vec<Arc<dyn ConstructState>>>,
    }

    impl ConstructState for MockConstructState {
        fn constructor(&self) -> Option<Arc<Constructor>> {
            self.ct.clone()
        }
        fn sub_state(&self, index: i32) -> Arc<dyn ConstructState> {
            self.children.lock().unwrap()[index as usize].clone()
        }
        fn parent(&self) -> Option<Arc<dyn ConstructState>> {
            self.parent.lock().unwrap().clone()
        }
    }

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

    fn root_constructor() -> Arc<Constructor> {
        let mut copy_op = OpTpl::with_opcode(OpCode::CpuiCopy);
        copy_op.set_output(real_varnode(0));

        let mut build_op = OpTpl::with_opcode(OpCode::CpuiMultiequal);
        build_op.add_input(real_varnode(0)); // BUILD operand 0

        let mut tpl = ConstructTpl::new();
        tpl.vec.push(copy_op);
        tpl.vec.push(build_op);

        let mut ct = Constructor::new();
        ct.templ = Some(tpl);
        Arc::new(ct)
    }

    fn build_tree() -> Arc<dyn ConstructState> {
        let leaf: Arc<MockConstructState> = Arc::new(MockConstructState {
            ct: Some(leaf_constructor()),
            parent: Mutex::new(None),
            children: Mutex::new(Vec::new()),
        });
        let root: Arc<MockConstructState> = Arc::new(MockConstructState {
            ct: Some(root_constructor()),
            parent: Mutex::new(None),
            children: Mutex::new(vec![leaf.clone() as Arc<dyn ConstructState>]),
        });
        *leaf.parent.lock().unwrap() = Some(root.clone() as Arc<dyn ConstructState>);
        root
    }

    struct MockOpTplWalker {
        point: Option<Arc<dyn ConstructState>>,
        oparray: Option<Vec<OpTpl>>,
        depth: i32,
        breadcrumb: Vec<i32>,
        maxsize: i32,
        sectionnum: i32,
    }

    impl MockOpTplWalker {
        fn for_tree(root: Arc<dyn ConstructState>, sectionnum: i32) -> Self {
            let mut walker = Self {
                point: Some(root),
                oparray: None,
                depth: 0,
                breadcrumb: vec![0],
                maxsize: 0,
                sectionnum,
            };
            walker.setup_point();
            walker
        }
    }

    impl OpTplWalker for MockOpTplWalker {
        fn point(&self) -> Option<Arc<dyn ConstructState>> {
            self.point.clone()
        }
        fn set_point(&mut self, point: Option<Arc<dyn ConstructState>>) {
            self.point = point;
        }
        fn oparray(&self) -> Option<&Vec<OpTpl>> {
            self.oparray.as_ref()
        }
        fn set_oparray(&mut self, oparray: Option<Vec<OpTpl>>) {
            self.oparray = oparray;
        }
        fn depth(&self) -> i32 {
            self.depth
        }
        fn set_depth(&mut self, depth: i32) {
            self.depth = depth;
        }
        fn breadcrumb(&self) -> &Vec<i32> {
            &self.breadcrumb
        }
        fn breadcrumb_mut(&mut self) -> &mut Vec<i32> {
            &mut self.breadcrumb
        }
        fn maxsize(&self) -> i32 {
            self.maxsize
        }
        fn set_maxsize(&mut self, maxsize: i32) {
            self.maxsize = maxsize;
        }
        fn sectionnum(&self) -> i32 {
            self.sectionnum
        }
    }

    #[test]
    fn walks_ordinary_op_then_follows_build_directive_and_pops_back() {
        let root = build_tree();
        let mut walker = MockOpTplWalker::for_tree(root, -1);

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
        assert!(walker.get_state().is_some());
        // isState() is true whenever point is non-null, regardless of maxsize -- matching
        // Java's `if (point != null) return true;` short-circuit.
        assert!(walker.is_state());
        // The leaf's template is empty (0 ops), so there is nothing left to walk here.
        assert!(walker.next_op_tpl().is_none());

        // Backtrack to the root; its second op index (BUILD) was already consumed, so the walk
        // is exhausted there too, but the state itself should be non-null again.
        walker.pop_build();
        assert!(walker.get_state().is_some());
    }

    /// Proves `dyn OpTplWalker` is object safe and usable through a trait object.
    #[test]
    fn is_object_safe() {
        let root = build_tree();
        let mut walker: Box<dyn OpTplWalker> = Box::new(MockOpTplWalker::for_tree(root, -1));
        assert!(walker.is_state());
        assert!(walker.next_op_tpl().is_some());
    }
}
