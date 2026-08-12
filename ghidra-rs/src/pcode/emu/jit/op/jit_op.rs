//! A p-code operator use-def node.
//!
//! Port of `ghidra.pcode.emu.jit.op.JitOp`.

use std::sync::Arc;

use crate::pcode::emu::jit::var::{JitVal, JitOutVar};
use crate::pcode::seam_stubs::{
    JitTypeBehavior, JitUnimplementedOp,
};
use crate::program::model::pcode::{OpCode, PcodeOp};

use super::{JitBoolNegateOp, JitDefOp};

/// A p-code operator use-def node.
///
/// Port of the `ghidra.pcode.emu.jit.op.JitOp` interface: the base of the use-def graph node
/// hierarchy built during JIT data-flow analysis (see
/// [`OpGen`](crate::pcode::seam_stubs::OpGen) for the accompanying table of p-code ops, use-def
/// nodes, and code generators).
///
/// # Differences from Java
///
/// Java declares six abstract instance methods: `op()`, `canBeRemoved()`, `inputs()`,
/// `typeFor(int)`, `link()`, and `unlink()`. Every concrete node already ported in this crate
/// implements `op()`/`canBeRemoved()`/`inputs()` as an ad hoc *inherent* method instead of a
/// trait member, because their Java return shapes vary in ways one object-safe trait signature
/// can't unify -- e.g.
/// [`JitPhiOp::inputs`](crate::pcode::emu::jit::op::jit_phi_op::JitPhiOp::inputs) returns
/// `Vec<Arc<dyn JitVal>>` (a dynamic option list), while [`JitBoolNegateOp::op`] returns a
/// `&PcodeOp` reference rather than an owned value. Only `typeFor`/`link`/`unlink` -- plus
/// `accept`, grown (see `STUBS.tsv`) for double-dispatch into
/// [`JitOpVisitor`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor) -- are common
/// enough across implementors to live on the trait itself. This matches how every existing
/// implementor (e.g. [`JitBoolNegateOp`],
/// [`JitPhiOp`](crate::pcode::emu::jit::op::jit_phi_op::JitPhiOp)) was already ported against
/// this trait's shape.
///
/// Java's three `static` factory methods (`stubOp`, `unOp`, `binOp`) have no Rust trait
/// equivalent (a trait can't dispatch a constructor over an as-yet-unknown implementor), so they
/// are ported as the free functions [`stub_op`], [`jit_op_un_op`], and [`jit_op_bin_op`] below.
pub trait JitOp: Send + Sync {
    /// Get the required type behavior for the input at the given position in `inputs()`.
    ///
    /// Port of `typeFor(int)`.
    fn type_for(&self, position: i32) -> JitTypeBehavior;

    /// Add this op to the uses of each input operand, and (if applicable) set the definition of
    /// the output operand to this op.
    ///
    /// Port of `link()`.
    fn link(&self);

    /// Remove this op from the uses of each input operand, and (if applicable) unset the
    /// definition of the output operand.
    ///
    /// Port of `unlink()`.
    fn unlink(&self);

    /// Double-dispatch hook standing in for Java's `switch (op) { case JitUnOp ... }` in
    /// `JitOpVisitor.visitOp`.
    ///
    /// Grown (see `STUBS.tsv`) for
    /// [`JitOpVisitor`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor): a
    /// sealed-interface `switch` has no Rust equivalent over a `dyn` trait, so each concrete
    /// `JitOp` overrides this to call back into its matching `JitOpVisitor::visit_*` method.
    /// Defaulted so `impl JitOp for Foo` blocks that don't need visiting keep compiling; the
    /// default mirrors Java's unreachable `default -> throw new AssertionError(...)` arm.
    fn accept(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        let _ = visitor;
        panic!("AssertionError: Unrecognized op");
    }
}

/// Create a use-def node for a nop or unimplemented op.
///
/// Port of `JitOp.stubOp(PcodeOp)`.
///
/// # Differences from Java
///
/// Java checks `op instanceof NopPcodeOp` first, dispatching to `JitNopOp` -- `NopPcodeOp` is an
/// unported inner class of `JitPassage` (a `PcodeOp` subclass with no extra fields of its own),
/// and this crate's [`PcodeOp`] has no subclass hierarchy to test against, so that branch cannot
/// be modeled yet. This falls straight through to the opcode switch, which only recognizes
/// [`OpCode::Unimplemented`] (Java's only other case); everything else -- including what would
/// have been a `NopPcodeOp` -- hits the `default` arm's panic, same as Java's
/// `UnsupportedOperationException`.
pub fn stub_op(op: &PcodeOp) -> Box<dyn JitOp> {
    match op.opcode {
        OpCode::Unimplemented => Box::new(JitUnimplementedOp),
        opcode => panic!("UnsupportedOperationException: Unrecognized stub op: {opcode:?}"),
    }
}

/// Create a use-def node for a unary p-code op.
///
/// Port of `JitOp.unOp(PcodeOp, JitOutVar, JitVal)`.
///
/// # Differences from Java
///
/// A free function rather than a trait member because Java declares it `static` on the `JitOp`
/// interface (see [`JitOp`]'s docs). Only [`OpCode::BoolNegate`] has a ported node type
/// ([`JitBoolNegateOp`]); every other arm of Java's switch names a class that is not ported yet,
/// so it panics as Java's `default` arm does for an unrecognized opcode. Extend it as each
/// `JitXxxOp.java` lands. Returns `Arc<dyn JitDefOp>` rather than `Box<dyn JitUnOp>` (Java's
/// `JitUnOp`) since the only caller
/// ([`JitDataFlowArithmetic`](crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic::JitDataFlowArithmetic))
/// only needs the `JitDefOp` view, and the produced node must be shareable like any other use-def
/// graph node.
pub fn jit_op_un_op(op: &PcodeOp, out: Arc<dyn JitOutVar>, u: Arc<dyn JitVal>) -> Arc<dyn JitDefOp> {
    match op.opcode {
        OpCode::BoolNegate => Arc::new(JitBoolNegateOp::new(op.clone(), out, u)),
        opcode => panic!("UnsupportedOperationException: Unrecognized un op: {opcode:?}"),
    }
}

/// Create a use-def node for a binary p-code op.
///
/// Port of `JitOp.binOp(PcodeOp, JitOutVar, JitVal, JitVal)`. See [`jit_op_un_op`]: no binary
/// node type is ported yet, so this always panics; the parameters are named to match Java's so
/// the arms can be filled in as they land.
pub fn jit_op_bin_op(
    op: &PcodeOp,
    out: Arc<dyn JitOutVar>,
    l: Arc<dyn JitVal>,
    r: Arc<dyn JitVal>,
) -> Arc<dyn JitDefOp> {
    let (_out, _l, _r) = (out, l, r);
    panic!("UnsupportedOperationException: Unrecognized bin op: {:?}", op.opcode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::op::JitDefOp as JitDefOpTrait;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::SequenceNumber;

    struct MockOutVar;

    impl JitVal for MockOutVar {
        fn size(&self) -> i32 {
            8
        }
        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }


    impl crate::pcode::emu::jit::var::JitVar for MockOutVar {
        fn id(&self) -> i32 {
            0
        }
        fn space(&self) -> Arc<AddressSpace> {
            Arc::new(AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0))
        }
    }

    impl crate::pcode::emu::jit::var::JitVarnodeVar for MockOutVar {
        fn varnode(&self) -> crate::program::model::pcode::Varnode {
            use crate::program::model::pcode::Varnode;
            let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
            let addr = Address::new(Arc::new(space), 0);
            Varnode::new(addr, 8)
        }
    }

    impl JitOutVar for MockOutVar {
        fn set_definition(&self, _definition: Option<&dyn JitDefOp>) {}
        fn definition(&self) -> Option<Arc<dyn JitDefOp>> {
            None
        }
    }

    struct MockVal;

    impl JitVal for MockVal {
        fn size(&self) -> i32 {
            8
        }
        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }

    fn nop_op(opcode: OpCode) -> PcodeOp {
        let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0);
        let seqnum = SequenceNumber::new(addr, 0);
        PcodeOp::new(opcode, seqnum, vec![], None)
    }

    #[test]
    fn stub_op_recognizes_unimplemented() {
        let op = nop_op(OpCode::Unimplemented);
        // Java: `stubOp` maps `PcodeOp.UNIMPLEMENTED` to a `JitUnimplementedOp`; confirm we get
        // one by checking it dispatches to the matching visitor callback rather than the
        // `accept` default (which would panic).
        struct Probe(bool);
        impl crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor for Probe {
            fn visit_unimplemented_op(
                &mut self,
                _op: &JitUnimplementedOp,
            ) {
                self.0 = true;
            }
        }
        let node = stub_op(&op);
        let mut probe = Probe(false);
        node.accept(&mut probe);
        assert!(probe.0);
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperationException")]
    fn stub_op_panics_on_unrecognized_opcode() {
        let op = nop_op(OpCode::Copy);
        stub_op(&op);
    }

    #[test]
    fn un_op_bool_negate_matches_java_type_behavior() {
        let op = nop_op(OpCode::BoolNegate);
        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let u = Arc::new(MockVal) as Arc<dyn JitVal>;

        let node = jit_op_un_op(&op, out, u);

        // Java: `JitBoolNegateOp.type()` (record component, defaulted via `JitUnOp`) is
        // `JitTypeBehavior.INTEGER`.
        assert_eq!(JitDefOpTrait::type_(&*node), JitTypeBehavior::Integer);
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperationException: Unrecognized un op")]
    fn un_op_panics_for_not_yet_ported_opcode() {
        let op = nop_op(OpCode::IntZext);
        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let u = Arc::new(MockVal) as Arc<dyn JitVal>;
        jit_op_un_op(&op, out, u);
    }

    #[test]
    #[should_panic(expected = "UnsupportedOperationException: Unrecognized bin op")]
    fn bin_op_panics_for_not_yet_ported_opcode() {
        let op = nop_op(OpCode::IntAdd);
        let out = Arc::new(MockOutVar) as Arc<dyn JitOutVar>;
        let l = Arc::new(MockVal) as Arc<dyn JitVal>;
        let r = Arc::new(MockVal) as Arc<dyn JitVal>;
        jit_op_bin_op(&op, out, l, r);
    }
}
