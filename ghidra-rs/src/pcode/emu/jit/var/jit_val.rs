//! A p-code value use-def node.
//!
//! Port of `ghidra.pcode.emu.jit.var.JitVal`.
//!
//! For a table of value/variable node classes and generators, see `ValGen` (not yet ported).

use std::sync::Arc;

use crate::pcode::emu::jit::analysis::jit_type_behavior::JitTypeBehavior;
use crate::pcode::seam_stubs::{JitConstVal, JitMissingVar};
use crate::pcode::emu::jit::op::JitOp;
use super::JitOutVar;

/// The use of a value node by an operator node.
///
/// Port of `JitVal.ValUse`.
#[derive(Clone)]
pub struct ValUse {
    /// The operator node.
    pub op: Arc<dyn JitOp>,
    /// The position of the operand in the operator's inputs.
    pub position: i32,
}

impl ValUse {
    /// Port of the canonical record constructor `new ValUse(JitOp, int)`.
    pub fn new(op: Arc<dyn JitOp>, position: i32) -> Self {
        Self { op, position }
    }

    /// Port of `ValUse.type()`.
    pub fn type_(&self) -> JitTypeBehavior {
        self.op.type_for(self.position)
    }
}

/// Create a constant value.
///
/// Port of `JitVal.constant(int, BigInteger)`. `BigInteger` is stood in for by `i128`, since no
/// arbitrary-precision integer type exists in this crate yet (see [`JitConstVal`]'s doc).
pub fn constant(size: i32, value: i128) -> JitConstVal {
    JitConstVal::new(size, value)
}

/// A p-code value use-def node.
///
/// For a table of value/variable node classes and generators, see `ValGen` (not yet ported).
pub trait JitVal: Send + Sync {
    /// The size in bytes.
    fn size(&self) -> i32;

    /// The list of uses.
    ///
    /// Java's `AbstractJitVal` (not yet ported) is the sole implementor of this method's
    /// backing storage; every implementor in this crate currently treats use tracking as a
    /// no-op (see [`add_use`](Self::add_use)/[`remove_use`](Self::remove_use)), so this
    /// defaults to an empty list to match. Replace with real tracking once `AbstractJitVal.java`
    /// is ported.
    fn uses(&self) -> Vec<ValUse> {
        Vec::new()
    }

    /// Add a use.
    ///
    /// In most cases, uses should be final, once this value node has been entered into the
    /// use-def graph. An exception deals with phi nodes ([`JitPhiOp`](
    /// crate::pcode::emu::jit::op::JitPhiOp)), as this analysis occurs after each intra-block
    /// portion of the graph has been constructed. During inter-block analysis, additional uses
    /// will get recorded. Even further uses may be recorded using op-use analysis, since it may
    /// generate more phi nodes.
    fn add_use(&self, op: &dyn JitOp, position: i32);

    /// Remove a use.
    fn remove_use(&self, op: &dyn JitOp, position: i32);

    /// Whether this value is a `JitInputVar`, i.e., an input to the passage.
    ///
    /// Grown (see `STUBS.tsv`) to stand in for Java's `instanceof JitInputVar` check in
    /// `JitPhiOp.hasInputOption()`, since `JitInputVar` is not a downcast target here. Defaulted
    /// to `false` so existing `impl JitVal for Foo` blocks keep compiling; only `JitInputVar`
    /// overrides it.
    fn is_input_var(&self) -> bool {
        false
    }

    /// This value as a [`JitConstVal`], if it is one.
    ///
    /// Grown (see `STUBS.tsv`) to stand in for Java's `instanceof JitConstVal` checks in
    /// [`JitDataFlowArithmetic`](crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic::JitDataFlowArithmetic)'s
    /// `subpiece` and `toConcrete`, in the same style as [`is_input_var`](Self::is_input_var):
    /// `dyn JitVal` carries no downcast facility, so each check becomes a defaulted query that
    /// only the matching type overrides.
    fn as_const_val(&self) -> Option<&JitConstVal> {
        None
    }

    /// This value as a [`JitVarnodeVar`](crate::pcode::emu::jit::var::JitVarnodeVar), if it is
    /// one. See [`as_const_val`](Self::as_const_val).
    fn as_varnode_var(&self) -> Option<&dyn crate::pcode::emu::jit::var::JitVarnodeVar> {
        None
    }

    /// This value as a [`JitOutVar`], if it is one. See [`as_const_val`](Self::as_const_val).
    fn as_out_var(&self) -> Option<&dyn JitOutVar> {
        None
    }

    /// This value as a [`JitMissingVar`], if it is one.
    ///
    /// Grown (see `STUBS.tsv`) to stand in for Java's `instanceof JitMissingVar` check in
    /// [`JitDataFlowBlockAnalyzer`](crate::pcode::emu::jit::analysis::jit_data_flow_block_analyzer::JitDataFlowBlockAnalyzer)'s
    /// `fillPhiFromBlock` and `MiniDFState.generatePhis`. See [`as_const_val`](Self::as_const_val).
    fn as_missing_var(&self) -> Option<&JitMissingVar> {
        None
    }

    /// Double-dispatch hook standing in for Java's `switch (v) { case JitConstVal ... }` in
    /// `JitOpVisitor.visitVal`.
    ///
    /// Grown (see `STUBS.tsv`) for
    /// [`JitOpVisitor`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor): a
    /// sealed-interface `switch` has no Rust equivalent over a `dyn` trait, so each concrete
    /// `JitVal` overrides this to call back into its matching `JitOpVisitor::visit_*` method.
    /// Defaulted so existing `impl JitVal for Foo` blocks keep compiling; the default mirrors
    /// Java's unreachable `default -> throw new AssertionError()` arm.
    fn accept_val(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        let _ = visitor;
        panic!("AssertionError: unrecognized JitVal");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockOp;

    impl JitOp for MockOp {
        fn type_for(&self, position: i32) -> JitTypeBehavior {
            if position == 0 {
                JitTypeBehavior::Integer
            } else {
                JitTypeBehavior::Float
            }
        }

        fn link(&self) {}

        fn unlink(&self) {}
    }

    struct MockVal;

    impl JitVal for MockVal {
        fn size(&self) -> i32 {
            4
        }

        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}

        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }

    // Java: `JitVal.constant(size, value)` returns `new JitConstVal(size, value)`, whose `size()`
    // and `value()` echo back the constructor arguments.
    #[test]
    fn constant_builds_jit_const_val_with_given_size_and_value() {
        let val = constant(4, 42);

        assert_eq!(val.size(), 4);
        assert_eq!(val.value(), 42);
    }

    // Java: `ValUse.type()` delegates to `op.typeFor(position)`.
    #[test]
    fn val_use_type_delegates_to_op_type_for() {
        let use0 = ValUse::new(Arc::new(MockOp), 0);
        let use1 = ValUse::new(Arc::new(MockOp), 1);

        assert_eq!(use0.type_(), JitTypeBehavior::Integer);
        assert_eq!(use1.type_(), JitTypeBehavior::Float);
    }

    // Java's `JitVal` interface declares no default for `uses()`, `size()`, `addUse()`, or
    // `removeUse()`; this port defaults `uses()` and `is_input_var()` so pre-existing
    // implementors (which predate this port and never track a use list) keep compiling.
    #[test]
    fn uses_and_is_input_var_default() {
        let val = MockVal;

        assert!(val.uses().is_empty());
        assert!(!val.is_input_var());
    }
}
