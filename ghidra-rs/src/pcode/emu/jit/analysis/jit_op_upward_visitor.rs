//! A visitor that traverses the use-def graph upward, from uses toward definitions.
//!
//! Port of `ghidra.pcode.emu.jit.analysis.JitOpUpwardVisitor`.

use crate::pcode::emu::jit::op::{JitPhiOp, JitUnOp};
use crate::pcode::emu::jit::var::JitOutVar;
use crate::pcode::seam_stubs::{JitBinOp, JitBranchIndOp, JitCBranchOp, JitCallOtherDefOp, JitCallOtherOp, JitCatenateOp, JitLoadOp, JitStoreOp, JitSynthSubPieceOp, };
use crate::pcode::emu::jit::op::JitOp;

use super::jit_op_visitor::JitOpVisitor;

/// A visitor that traverses the use-def graph upward, that is from uses toward definitions.
///
/// # Differences from Java
///
/// Java expresses this purely as `JitOpUpwardVisitor extends JitOpVisitor`, overriding several of
/// the parent interface's default methods; any implementor automatically picks up the override
/// via Java's most-specific-default-method-wins rule. Rust has no equivalent: the methods
/// declared here share their names with [`JitOpVisitor`]'s, but are distinct trait items with
/// their own default bodies, not overrides. A type that implements both traits cannot reach these
/// through `self.visit_un_op(..)` dot syntax -- that's ambiguous (`E0034`; see
/// [`MemBufferMixin`](crate::program::model::mem::mem_buffer_mixin::MemBufferMixin) for the same
/// shape of problem elsewhere in this port) -- so a `JitOpVisitor` impl that wants this upward
/// traversal must forward explicitly, e.g. `<Self as JitOpUpwardVisitor>::visit_un_op(self, op)`,
/// mirroring Java's `JitOpUpwardVisitor.super.visitUnOp(op)`.
pub trait JitOpUpwardVisitor: JitOpVisitor {
    /// Port of `visitUnOp`: visit the operand.
    ///
    /// Requires `Self: Sized`, like [`JitOpVisitor::visit_val`], since the body reborrows `self`
    /// into that `Self: Sized`-bounded call.
    fn visit_un_op(&mut self, un_op: &dyn JitUnOp)
    where
        Self: Sized,
    {
        self.visit_val(un_op.u().as_ref());
    }

    /// Port of `visitBinOp`: visit the left operand, then the right.
    fn visit_bin_op(&mut self, bin_op: &dyn JitBinOp)
    where
        Self: Sized,
    {
        self.visit_val(bin_op.l().as_ref());
        self.visit_val(bin_op.r().as_ref());
    }

    /// Port of `visitStoreOp`: visit the offset operand, then the value.
    fn visit_store_op(&mut self, store_op: &JitStoreOp)
    where
        Self: Sized,
    {
        self.visit_val(store_op.offset().as_ref());
        self.visit_val(store_op.value().as_ref());
    }

    /// Port of `visitLoadOp`: visit the offset operand.
    fn visit_load_op(&mut self, load_op: &JitLoadOp)
    where
        Self: Sized,
    {
        self.visit_val(load_op.offset().as_ref());
    }

    /// Port of `visitCallOtherOp`: visit each argument.
    fn visit_call_other_op(&mut self, other_op: &JitCallOtherOp)
    where
        Self: Sized,
    {
        for v in other_op.args() {
            self.visit_val(v.as_ref());
        }
    }

    /// Port of `visitCallOtherDefOp`: visit each argument.
    fn visit_call_other_def_op(&mut self, other_op: &JitCallOtherDefOp)
    where
        Self: Sized,
    {
        for v in other_op.args() {
            self.visit_val(v.as_ref());
        }
    }

    /// Port of `visitCatenateOp`: visit each part.
    fn visit_catenate_op(&mut self, cat_op: &JitCatenateOp)
    where
        Self: Sized,
    {
        for p in cat_op.parts() {
            self.visit_val(p.as_ref());
        }
    }

    /// Port of `visitPhiOp`: visit each option's value.
    fn visit_phi_op(&mut self, phi_op: &JitPhiOp)
    where
        Self: Sized,
    {
        for opt in phi_op.inputs() {
            self.visit_val(opt.as_ref());
        }
    }

    /// Port of `visitSubPieceOp`: visit the input operand.
    fn visit_sub_piece_op(&mut self, piece_op: &JitSynthSubPieceOp)
    where
        Self: Sized,
    {
        self.visit_val(piece_op.v().as_ref());
    }

    /// Port of `visitCBranchOp`: visit the condition operand.
    fn visit_c_branch_op(&mut self, c_branch_op: &JitCBranchOp)
    where
        Self: Sized,
    {
        self.visit_val(c_branch_op.cond());
    }

    /// Port of `visitBranchIndOp`: visit the target operand.
    fn visit_branch_ind_op(&mut self, branch_ind_op: &JitBranchIndOp)
    where
        Self: Sized,
    {
        self.visit_val(branch_ind_op.target());
    }

    /// Port of `visitOutVar`: visit the op that defines this variable.
    ///
    /// Requires `Self: Sized`, like [`JitOpVisitor::visit_op`], since the body reborrows `self`
    /// as the `&mut dyn JitOpVisitor` that [`JitOp::accept`](JitOp::accept)
    /// takes.
    fn visit_out_var(&mut self, v: &dyn JitOutVar)
    where
        Self: Sized,
    {
        let definition = v.definition().expect("JitOutVar visited upward without a definition");
        definition.accept(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::op::JitDefOp;
    use crate::pcode::emu::jit::var::JitVal;
    use crate::pcode::emu::jit::analysis::jit_type_behavior::JitTypeBehavior;
    use crate::pcode::seam_stubs::JitBlock;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{OpCode, PcodeOp, SequenceNumber, Varnode};
    use std::sync::{Arc, Mutex};

    /// A [`JitVal`] that reports a caller-chosen `size()`, used purely as an identifying tag so
    /// tests can assert the order values were visited in.
    struct TagVal(i32);

    impl JitVal for TagVal {
        fn size(&self) -> i32 {
            self.0
        }
        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }

    /// Records the `size()` tag of every value passed to `visit_val`, and the sentinel `-1` for
    /// every `JitPhiOp` passed to `visit_phi_op` (through `JitOpVisitor`, not
    /// `JitOpUpwardVisitor` -- see `visit_out_var_dispatches_to_definitions_op`).
    #[derive(Default)]
    struct RecordingVisitor {
        visited: Mutex<Vec<i32>>,
    }

    impl JitOpVisitor for RecordingVisitor {
        fn visit_val(&mut self, v: &dyn JitVal)
        where
            Self: Sized,
        {
            self.visited.lock().unwrap().push(v.size());
        }

        fn visit_phi_op(&mut self, _phi_op: &JitPhiOp) {
            self.visited.lock().unwrap().push(-1);
        }
    }

    impl JitOpUpwardVisitor for RecordingVisitor {}

    struct MockUnOp(i32);
    impl JitOp for MockUnOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
        fn link(&self) {}
        fn unlink(&self) {}
    }
    impl JitDefOp for MockUnOp {
        fn out(&self) -> Arc<dyn JitOutVar> {
            unimplemented!()
        }
    }
    impl JitUnOp for MockUnOp {
        fn u(&self) -> Arc<dyn JitVal> {
            Arc::new(TagVal(self.0))
        }

        fn u_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
    }

    struct MockBinOp(i32, i32);
    impl JitOp for MockBinOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
        fn link(&self) {}
        fn unlink(&self) {}
    }
    impl JitDefOp for MockBinOp {
        fn out(&self) -> Arc<dyn JitOutVar> {
            unimplemented!()
        }
    }
    impl JitBinOp for MockBinOp {
        fn l(&self) -> Box<dyn JitVal> {
            Box::new(TagVal(self.0))
        }
        fn r(&self) -> Box<dyn JitVal> {
            Box::new(TagVal(self.1))
        }
        fn l_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
        fn r_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
    }

    // Java: `JitOpUpwardVisitor.visitUnOp` visits `u()`.
    #[test]
    fn visit_un_op_visits_operand() {
        let un_op = MockUnOp(7);
        let mut visitor = RecordingVisitor::default();

        <RecordingVisitor as JitOpUpwardVisitor>::visit_un_op(&mut visitor, &un_op);

        assert_eq!(&*visitor.visited.lock().unwrap(), &[7]);
    }

    // Java: `JitOpUpwardVisitor.visitBinOp` visits `l()` then `r()`, in that order.
    #[test]
    fn visit_bin_op_visits_left_then_right() {
        let bin_op = MockBinOp(10, 20);
        let mut visitor = RecordingVisitor::default();

        <RecordingVisitor as JitOpUpwardVisitor>::visit_bin_op(&mut visitor, &bin_op);

        assert_eq!(&*visitor.visited.lock().unwrap(), &[10, 20]);
    }

    // Java: `JitOpUpwardVisitor.visitStoreOp` visits `offset()` then `value()`.
    #[test]
    fn visit_store_op_visits_offset_then_value() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let store_op = JitStoreOp::new(
            PcodeOp::new(
                OpCode::Store,
                SequenceNumber::new(Address::new(Arc::clone(&space), 0), 0),
                vec![],
                None,
            ),
            (*space).clone(),
            Arc::new(TagVal(1)),
            Arc::new(TagVal(2)),
        );
        let mut visitor = RecordingVisitor::default();

        <RecordingVisitor as JitOpUpwardVisitor>::visit_store_op(&mut visitor, &store_op);

        assert_eq!(&*visitor.visited.lock().unwrap(), &[1, 2]);
    }

    // Java: `JitOpUpwardVisitor.visitCallOtherOp` visits every element of `args()`, in order.
    #[test]
    fn visit_call_other_op_visits_each_arg_in_order() {
        let other_op =
            JitCallOtherOp::new(vec![Box::new(TagVal(1)), Box::new(TagVal(2)), Box::new(TagVal(3))]);
        let mut visitor = RecordingVisitor::default();

        <RecordingVisitor as JitOpUpwardVisitor>::visit_call_other_op(&mut visitor, &other_op);

        assert_eq!(&*visitor.visited.lock().unwrap(), &[1, 2, 3]);
    }

    // Java: `JitOpUpwardVisitor.visitCatenateOp` visits every element of `parts()`, in order.
    #[test]
    fn visit_catenate_op_visits_each_part_in_order() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let out: Arc<dyn JitOutVar> = Arc::new(StubOutVar(varnode(&space, 0x1000, 2)));
        let cat_op = JitCatenateOp::new(out, vec![Arc::new(TagVal(5)), Arc::new(TagVal(6))]);
        let mut visitor = RecordingVisitor::default();

        <RecordingVisitor as JitOpUpwardVisitor>::visit_catenate_op(&mut visitor, &cat_op);

        assert_eq!(&*visitor.visited.lock().unwrap(), &[5, 6]);
    }

    fn varnode(space: &Arc<AddressSpace>, offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(Arc::clone(space), offset), size)
    }

    struct StubOutVar(Varnode);
    impl JitVal for StubOutVar {
        fn size(&self) -> i32 {
            self.0.get_size()
        }
        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }
    impl crate::pcode::emu::jit::var::JitVar for StubOutVar {
        fn id(&self) -> i32 {
            0
        }
        fn space(&self) -> Arc<AddressSpace> {
            self.0.get_address().space().clone()
        }
    }
    impl crate::pcode::emu::jit::var::JitVarnodeVar for StubOutVar {
        fn varnode(&self) -> Varnode {
            self.0.clone()
        }
    }
    impl JitOutVar for StubOutVar {
        fn set_definition(&self, _definition: Option<&dyn JitDefOp>) {}
        fn definition(&self) -> Option<Arc<dyn JitDefOp>> {
            None
        }
    }

    // Java: `JitOpUpwardVisitor.visitPhiOp` visits every value in `options().values()`; here,
    // `JitPhiOp::inputs()`, in insertion order.
    #[test]
    fn visit_phi_op_visits_each_option_value() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let out: Arc<dyn JitOutVar> = Arc::new(StubOutVar(varnode(&space, 0x1000, 4)));
        let block = JitBlock::new();
        let val1: Arc<dyn JitVal> = Arc::new(TagVal(11));
        let val2: Arc<dyn JitVal> = Arc::new(TagVal(22));
        let phi = JitPhiOp::with_options(
            block,
            out,
            vec![
                (crate::pcode::seam_stubs::BlockFlow::entry(block), val1),
                (crate::pcode::seam_stubs::BlockFlow::entry(block), val2),
            ],
        );
        let mut visitor = RecordingVisitor::default();

        <RecordingVisitor as JitOpUpwardVisitor>::visit_phi_op(&mut visitor, &phi);

        assert_eq!(&*visitor.visited.lock().unwrap(), &[11, 22]);
    }

    // Java: `visitOutVar` calls `visitOp(v.definition())`; a `null` definition NPEs in Java,
    // ported here as a panic on `None`.
    #[test]
    #[should_panic(expected = "JitOutVar visited upward without a definition")]
    fn visit_out_var_panics_without_definition() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let out_var = StubOutVar(varnode(&space, 0x1000, 4));
        let mut visitor = RecordingVisitor::default();

        <RecordingVisitor as JitOpUpwardVisitor>::visit_out_var(&mut visitor, &out_var);
    }

    // Java: `visitOutVar` dispatches to the definer's own `visitXxx` (here `visitPhiOp`) through
    // `visitOp`'s double dispatch -- exercising `JitDefOp::accept` reached from a `JitOutVar`'s
    // `definition()`, not `JitOpUpwardVisitor`'s own `visit_phi_op`.
    #[test]
    fn visit_out_var_dispatches_to_definitions_op() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let phi_out: Arc<dyn JitOutVar> = Arc::new(StubOutVar(varnode(&space, 0x2000, 4)));
        let phi: Arc<dyn JitDefOp> = Arc::new(JitPhiOp::new(JitBlock::new(), phi_out));

        struct DefOutVar(Arc<dyn JitDefOp>);
        impl JitVal for DefOutVar {
            fn size(&self) -> i32 {
                0
            }
            fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
            fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
        }
        impl crate::pcode::emu::jit::var::JitVar for DefOutVar {
            fn id(&self) -> i32 {
                0
            }
            fn space(&self) -> Arc<AddressSpace> {
                AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
            }
        }
        impl crate::pcode::emu::jit::var::JitVarnodeVar for DefOutVar {
            fn varnode(&self) -> Varnode {
                Varnode::new(
                    Address::new(
                        crate::pcode::emu::jit::var::JitVar::space(self),
                        0,
                    ),
                    4,
                )
            }
        }
        impl JitOutVar for DefOutVar {
            fn set_definition(&self, _definition: Option<&dyn JitDefOp>) {}
            fn definition(&self) -> Option<Arc<dyn JitDefOp>> {
                Some(Arc::clone(&self.0))
            }
        }

        let out_var = DefOutVar(phi);
        let mut visitor = RecordingVisitor::default();

        <RecordingVisitor as JitOpUpwardVisitor>::visit_out_var(&mut visitor, &out_var);

        // The `-1` sentinel comes from `RecordingVisitor`'s `JitOpVisitor::visit_phi_op`
        // override, proving `visit_out_var` reached it via `accept`, not via
        // `JitOpUpwardVisitor::visit_phi_op` (which would instead have recorded the phi's
        // (empty) option values).
        assert_eq!(&*visitor.visited.lock().unwrap(), &[-1]);
    }
}
