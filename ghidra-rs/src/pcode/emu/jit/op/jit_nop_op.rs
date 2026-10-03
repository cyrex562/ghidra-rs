//! The use-def node for a nop p-code op, or an inlined `CALLOTHER`.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitNopOp`.

use std::sync::Arc;

use crate::pcode::emu::jit::analysis::jit_type_behavior::JitTypeBehavior;
use crate::pcode::emu::jit::var::JitVal;
use crate::program::model::pcode::PcodeOp;

use super::JitOp;

/// The use-def node for a `NopPcodeOp` or an inlined `PcodeOp.CALLOTHER`.
///
/// When a callother is inlined, the original op is preserved for bookkeeping, but wrapping it in
/// this use-def node class ensures that no code is emitted for it.
///
/// # Differences from Java
///
/// Java declares this as a `record JitNopOp(PcodeOp op) implements JitOp`, giving it a
/// structurally-generated `op()` accessor plus `equals`/`hashCode`/`toString` derived from that
/// single component (and, transitively, from `PcodeOp`'s own identity-based `equals`, since
/// `PcodeOp` never overrides it -- see [`PcodeOp`]'s own "Deviation" doc). This crate instead
/// derives `PartialEq`/`Eq`/`Debug` structurally on `PcodeOp`, and this struct follows suit for
/// the same reason: no cheap notion of Java object identity exists for owned Rust values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JitNopOp {
    op: PcodeOp,
}

impl JitNopOp {
    /// Port of the record constructor `JitNopOp(PcodeOp op)`.
    pub fn new(op: PcodeOp) -> Self {
        Self { op }
    }

    /// Port of the record accessor `op()`.
    pub fn op(&self) -> &PcodeOp {
        &self.op
    }

    /// Port of `JitNopOp.canBeRemoved()`.
    ///
    /// An inherent method rather than a trait member, matching this crate's established
    /// convention for `canBeRemoved`/`op`/`inputs` across every other `JitOp` implementor (see
    /// [`JitOp`]'s docs).
    pub fn can_be_removed(&self) -> bool {
        true
    }
}

impl JitOp for JitNopOp {
    /// Port of `JitNopOp.typeFor(int)`, which always throws `AssertionError` -- a nop op has no
    /// inputs to ask about.
    fn type_for(&self, _position: i32) -> JitTypeBehavior {
        panic!("AssertionError")
    }

    /// Port of `JitNopOp.link()`: nothing.
    fn link(&self) {}

    /// Port of `JitNopOp.unlink()`: nothing.
    fn unlink(&self) {}

    /// Port of `JitNopOp.inputs()`, which always returns `List.of()`.
    fn inputs(&self) -> Vec<Arc<dyn JitVal>> {
        Vec::new()
    }

    fn accept(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_nop_op(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{OpCode, SequenceNumber};

    fn nop_pcode_op() -> PcodeOp {
        let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0);
        let seqnum = SequenceNumber::new(addr, 0);
        PcodeOp::new(OpCode::Unimplemented, seqnum, vec![], None)
    }

    #[test]
    fn op_accessor_returns_wrapped_op() {
        let op = nop_pcode_op();
        let nop = JitNopOp::new(op.clone());
        assert_eq!(nop.op(), &op);
    }

    #[test]
    fn can_be_removed_is_always_true() {
        let nop = JitNopOp::new(nop_pcode_op());
        assert!(nop.can_be_removed());
    }

    #[test]
    fn link_and_unlink_are_no_ops() {
        let nop = JitNopOp::new(nop_pcode_op());
        // Java: empty method bodies. Just confirm they don't panic.
        nop.link();
        nop.unlink();
    }

    #[test]
    fn inputs_is_always_empty() {
        let nop = JitNopOp::new(nop_pcode_op());
        assert!(JitOp::inputs(&nop).is_empty());
    }

    /// Java: `typeFor` is `throw new AssertionError()` unconditionally, since a nop op has no
    /// inputs at any position. Pin the panic to this exact call, not just "somewhere in the
    /// test" (a loose `#[should_panic]` would only prove *a* panic happened).
    #[test]
    fn type_for_panics_with_assertion_error() {
        let nop = JitNopOp::new(nop_pcode_op());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| nop.type_for(0)));
        assert!(result.is_err(), "typeFor should panic (Java: AssertionError)");
    }

    #[test]
    fn accept_dispatches_to_visit_nop_op() {
        struct Probe(bool);
        impl crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor for Probe {
            fn visit_nop_op(&mut self, _nop_op: &JitNopOp) {
                self.0 = true;
            }
        }
        let nop = JitNopOp::new(nop_pcode_op());
        let mut probe = Probe(false);
        nop.accept(&mut probe);
        assert!(probe.0);
    }

    #[test]
    fn structural_equality_matches_wrapped_op() {
        let a = JitNopOp::new(nop_pcode_op());
        let b = JitNopOp::new(nop_pcode_op());
        assert_eq!(a, b);
    }
}
