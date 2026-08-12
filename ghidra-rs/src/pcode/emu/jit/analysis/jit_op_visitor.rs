//! A visitor for traversing the use-def graph.
//!
//! Port of `ghidra.pcode.emu.jit.analysis.JitOpVisitor`.

use crate::pcode::emu::jit::op::{JitPhiOp, JitUnOp};
use crate::pcode::emu::jit::var::JitOutVar;
use crate::pcode::emu::jit::var::{JitDirectMemoryVar, JitVal, JitVar};
use crate::pcode::seam_stubs::{JitBranchIndOp, JitBranchOp, JitCBranchOp, JitCallOtherDefOp, JitCallOtherMissingOp, JitCallOtherOp, JitCatenateOp, JitConstVal, JitFailVal, JitIndirectMemoryVar, JitInputVar, JitLoadOp, JitMissingVar, JitNopOp, JitStoreOp, JitSynthSubPieceOp, JitUnimplementedOp, };
use crate::pcode::emu::jit::op::JitOp;
use crate::pcode::seam_stubs::JitBinOp;

/// A visitor for traversing the use-def graph.
///
/// The default implementations here do nothing other than discern the type of an op and
/// variable and dispatch the invocations appropriately. To traverse the graph upward, consider
/// `JitOpUpwardVisitor` (not yet ported). Note no "downward" visitor is currently provided,
/// because it was not needed.
///
/// # Differences from Java
///
/// Java dispatches `visitOp`/`visitVal`/`visitVar` via an exhaustive `switch` over the sealed
/// `JitOp`/`JitVal`/`JitVar` hierarchies, e.g. `switch (op) { case JitUnOp unOp -> ...; case
/// JitPhiOp phiOp -> ...; ... }`. Rust has no equivalent of a sealed-interface pattern match
/// over a `dyn` trait, so dispatch here is instead double-dispatch: [`JitOp::accept`],
/// [`JitVal::accept_val`], and [`JitVar::accept_var`] (grown on those traits, see `STUBS.tsv`)
/// call back into the matching `visit_*` method here. Every concrete leaf type ported so far
/// overrides its `accept*` method to route correctly; types not yet ported -- including the
/// still-interface-level `JitUnOp`, `JitBinOp`, and `JitOutVar` cases, which have no concrete
/// implementor in this crate yet -- fall back to the `accept*` default, which mirrors Java's
/// `default -> throw new AssertionError(...)` arm.
///
/// `visit_op`, `visit_val`, and `visit_var` require `Self: Sized` (so they cannot be called
/// through a `dyn JitOpVisitor`) because their default bodies must reborrow `self` as the `&mut
/// dyn JitOpVisitor` the `accept*` methods take; every other method remains callable through a
/// trait object.
#[allow(unused_variables)]
pub trait JitOpVisitor: Send + Sync {
    /// Visit an op node.
    ///
    /// The default implementation dispatches this to the type-specific `visit` method.
    fn visit_op(&mut self, op: &dyn JitOp)
    where
        Self: Sized,
    {
        op.accept(self);
    }

    /// Visit a [`JitUnOp`].
    fn visit_un_op(&mut self, un_op: &dyn JitUnOp) {}

    /// Visit a [`JitBinOp`].
    fn visit_bin_op(&mut self, bin_op: &dyn JitBinOp) {}

    /// Visit a [`JitStoreOp`].
    fn visit_store_op(&mut self, store_op: &JitStoreOp) {}

    /// Visit a [`JitLoadOp`].
    fn visit_load_op(&mut self, load_op: &JitLoadOp) {}

    /// Visit a [`JitCallOtherOp`].
    fn visit_call_other_op(&mut self, other_op: &JitCallOtherOp) {}

    /// Visit a [`JitCallOtherDefOp`].
    fn visit_call_other_def_op(&mut self, other_op: &JitCallOtherDefOp) {}

    /// Visit a [`JitCallOtherMissingOp`].
    fn visit_call_other_missing_op(&mut self, other_op: &JitCallOtherMissingOp) {}

    /// Visit a [`JitCatenateOp`].
    fn visit_catenate_op(&mut self, cat_op: &JitCatenateOp) {}

    /// Visit a [`JitPhiOp`].
    fn visit_phi_op(&mut self, phi_op: &JitPhiOp) {}

    /// Visit a [`JitSynthSubPieceOp`].
    fn visit_sub_piece_op(&mut self, piece_op: &JitSynthSubPieceOp) {}

    /// Visit a [`JitBranchOp`].
    fn visit_branch_op(&mut self, branch_op: &JitBranchOp) {}

    /// Visit a [`JitCBranchOp`].
    fn visit_c_branch_op(&mut self, c_branch_op: &JitCBranchOp) {}

    /// Visit a [`JitBranchIndOp`].
    fn visit_branch_ind_op(&mut self, branch_ind_op: &JitBranchIndOp) {}

    /// Visit a [`JitUnimplementedOp`].
    fn visit_unimplemented_op(&mut self, unimpl_op: &JitUnimplementedOp) {}

    /// Visit a [`JitNopOp`].
    fn visit_nop_op(&mut self, nop_op: &JitNopOp) {}

    /// Visit a [`JitVal`].
    ///
    /// The default implementation dispatches this to the type-specific `visit` method.
    fn visit_val(&mut self, v: &dyn JitVal)
    where
        Self: Sized,
    {
        v.accept_val(self);
    }

    /// Visit a [`JitVar`].
    ///
    /// The default implementation dispatches this to the type-specific `visit` method.
    fn visit_var(&mut self, v: &dyn JitVar)
    where
        Self: Sized,
    {
        v.accept_var(self);
    }

    /// Visit a [`JitConstVal`].
    fn visit_const_val(&mut self, const_val: &JitConstVal) {}

    /// Visit a [`JitFailVal`].
    fn visit_fail_val(&mut self, fail_val: &JitFailVal) {}

    /// Visit a [`JitDirectMemoryVar`].
    fn visit_direct_memory_var(&mut self, dir_mem_var: &JitDirectMemoryVar) {}

    /// Visit a [`JitIndirectMemoryVar`].
    ///
    /// NOTE: These should not ordinarily appear in the use-def graph. There is only the one
    /// `JitIndirectMemoryVar::INSTANCE`, and it's used as a temporary dummy. Indirect memory
    /// access is instead modeled by the [`JitLoadOp`].
    fn visit_indirect_memory_var(&mut self, ind_mem_var: &JitIndirectMemoryVar) {
        let _ = ind_mem_var;
        panic!("AssertionError");
    }

    /// Visit a [`JitInputVar`].
    fn visit_input_var(&mut self, input_var: &JitInputVar) {}

    /// Visit a [`JitMissingVar`].
    fn visit_missing_var(&mut self, missing_var: &JitMissingVar) {}

    /// Visit a [`JitOutVar`].
    fn visit_out_var(&mut self, out_var: &dyn JitOutVar) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::op::JitDefOp;
    use crate::pcode::emu::jit::var::JitOutVar as JitOutVarStub;
    use crate::pcode::seam_stubs::JitBlock;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::Varnode;
    use std::sync::{Arc, Mutex};

    fn varnode(space: &Arc<AddressSpace>, offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(Arc::clone(space), offset), size)
    }

    struct MockOutVar {
        varnode: Varnode,
    }

    impl JitVal for MockOutVar {
        fn size(&self) -> i32 {
            self.varnode.get_size()
        }

        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}

        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }

    impl JitVar for MockOutVar {
        fn id(&self) -> i32 {
            0
        }

        fn space(&self) -> Arc<AddressSpace> {
            self.varnode.get_address().space().clone()
        }
    }

    impl crate::pcode::emu::jit::var::JitVarnodeVar for MockOutVar {
        fn varnode(&self) -> Varnode {
            self.varnode.clone()
        }
    }

    impl JitOutVarStub for MockOutVar {
        fn set_definition(&self, _definition: Option<&dyn JitDefOp>) {}

        fn definition(&self) -> Option<Arc<dyn JitDefOp>> {
            None
        }
    }

    #[derive(Default)]
    struct RecordingVisitor {
        phi_ops: Mutex<Vec<()>>,
        direct_memory_vars: Mutex<Vec<i32>>,
        const_vals: Mutex<Vec<()>>,
        input_vars: Mutex<Vec<()>>,
        nop_ops: Mutex<Vec<()>>,
    }

    impl JitOpVisitor for RecordingVisitor {
        fn visit_phi_op(&mut self, _phi_op: &JitPhiOp) {
            self.phi_ops.lock().unwrap().push(());
        }

        fn visit_direct_memory_var(&mut self, dir_mem_var: &JitDirectMemoryVar) {
            self.direct_memory_vars.lock().unwrap().push(dir_mem_var.id());
        }

        fn visit_const_val(&mut self, _const_val: &JitConstVal) {
            self.const_vals.lock().unwrap().push(());
        }

        fn visit_input_var(&mut self, _input_var: &JitInputVar) {
            self.input_vars.lock().unwrap().push(());
        }

        fn visit_nop_op(&mut self, _nop_op: &JitNopOp) {
            self.nop_ops.lock().unwrap().push(());
        }
    }

    // Java: `visitOp`'s default dispatches to the type-specific method -- here, an override of
    // `visitPhiOp` fires, not the (no-op) default `visitOp`/`visitUnOp`/etc.
    #[test]
    fn visit_op_dispatches_to_overridden_leaf_method() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let out = Arc::new(MockOutVar { varnode: varnode(&space, 0x1000, 4) });
        let phi = JitPhiOp::new(JitBlock::new(), out);

        let mut visitor = RecordingVisitor::default();
        visitor.visit_op(&phi as &dyn JitOp);

        assert_eq!(visitor.phi_ops.lock().unwrap().len(), 1);
    }

    // A second concrete `JitOp` (not `JitPhiOp`) exercises the general mechanism, not just one
    // hard-coded case.
    #[test]
    fn visit_op_dispatches_nop_op() {
        let mut visitor = RecordingVisitor::default();
        visitor.visit_op(&JitNopOp as &dyn JitOp);

        assert_eq!(visitor.nop_ops.lock().unwrap().len(), 1);
    }

    // Java: `visitVal`, given a `JitVar` (here `JitDirectMemoryVar`), dispatches through
    // `visitVar` to `visitDirectMemoryVar`.
    #[test]
    fn visit_val_dispatches_direct_memory_var_through_var_chain() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let dm_var = JitDirectMemoryVar::new(7, varnode(&space, 0x2000, 4));

        let mut visitor = RecordingVisitor::default();
        visitor.visit_val(&dm_var as &dyn JitVal);

        assert_eq!(&*visitor.direct_memory_vars.lock().unwrap(), &[7]);
    }

    #[test]
    fn visit_val_dispatches_const_val() {
        let mut visitor = RecordingVisitor::default();
        visitor.visit_val(&JitConstVal::new(0, 0) as &dyn JitVal);

        assert_eq!(visitor.const_vals.lock().unwrap().len(), 1);
    }

    // `JitInputVar` is a `JitVal` but (per its type-level doc) not a `JitVar` in this port, so it
    // routes straight to `visit_input_var` rather than through `visit_var`.
    #[test]
    fn visit_val_dispatches_input_var() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let input_var = JitInputVar::new(varnode(&space, 0x3000, 4));

        let mut visitor = RecordingVisitor::default();
        visitor.visit_val(&input_var as &dyn JitVal);

        assert_eq!(visitor.input_vars.lock().unwrap().len(), 1);
    }

    // Java: `default void visitIndirectMemoryVar(...) { throw new AssertionError(); }` -- unlike
    // every other leaf method, this default is not a no-op.
    #[test]
    #[should_panic(expected = "AssertionError")]
    fn visit_indirect_memory_var_default_panics() {
        struct NoOpVisitor;
        impl JitOpVisitor for NoOpVisitor {}

        let mut visitor = NoOpVisitor;
        visitor.visit_var(&JitIndirectMemoryVar::INSTANCE as &dyn JitVar);
    }

    // Unoverridden op/var visits are no-ops, per Java's empty default bodies.
    #[test]
    fn unoverridden_visits_are_no_ops() {
        struct NoOpVisitor;
        impl JitOpVisitor for NoOpVisitor {}

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let out = Arc::new(MockOutVar { varnode: varnode(&space, 0x1000, 4) });
        let phi = JitPhiOp::new(JitBlock::new(), out);

        let mut visitor = NoOpVisitor;
        visitor.visit_op(&phi as &dyn JitOp);
        visitor.visit_val(&JitConstVal::new(0, 0) as &dyn JitVal);
    }
}
