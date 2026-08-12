//! An extension for unary integer extension operators.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.IntExtUnOpGen`.
//!
//! # Differences from Java
//!
//! - Java's sole member is a `default` override of `genRun` (dispatching on the unified operand
//!   type, then delegating to the reader/writer pair -- `JitCodeGenerator.genReadToStack`/
//!   `genReadToOpnd` and `genWriteFromStack`/`genWriteFromOpnd`). It is not modeled here: it
//!   returns Java's `OpResult` (constructed as `LiveOpResult`) and takes a `Methods.RetReq`,
//!   neither of which is ported in this crate, and it is called only by the (also unported) JIT
//!   driver -- no implementor's own logic calls it. This follows the same precedent as
//!   [`OpGen`](crate::pcode::seam_stubs::OpGen)'s omitted `genRun`, which
//!   [`IntOpUnOpGen`](super::int_op_un_op_gen::IntOpUnOpGen) and
//!   [`IntOpBinOpGen`](super::int_op_bin_op_gen::IntOpBinOpGen) already rely on. With `genRun`
//!   unmodeled, Java's interface -- which declares no other members -- ports as a marker trait:
//!   implementors provide nothing beyond the [`UnOpGen`] bound itself.

use crate::pcode::emu::jit::gen::op::un_op_gen::UnOpGen;
use crate::pcode::emu::jit::var::JitOutVar;
use crate::pcode::emu::jit::op::jit_un_op::JitUnOp;

/// An extension for unary integer extension operators.
///
/// Port of `ghidra.pcode.emu.jit.gen.op.IntExtUnOpGen`.
///
/// The strategy here is to do nothing more than invoke the readers and writers. Because those are
/// responsible for converting between the types, with the appropriate signedness, the work of
/// extension is already done. We need only to know whether or not the operators should be
/// treated as signed or unsigned. Thankfully, that method is already required by a super
/// interface.
pub trait IntExtUnOpGen<T: JitUnOp>: UnOpGen<T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::op::{JitDefOp, JitOp};
    use crate::pcode::seam_stubs::{Ext, JitTypeBehavior, OpGen};
    use std::sync::Arc;

    struct TestUnOp;

    impl JitOp for TestUnOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }

        fn link(&self) {}

        fn unlink(&self) {}
    }

    impl JitDefOp for TestUnOp {
        fn out(&self) -> Arc<dyn JitOutVar> {
            unimplemented!()
        }
    }

    impl JitUnOp for TestUnOp {
        fn u(&self) -> Arc<dyn crate::pcode::emu::jit::var::JitVal> {
            unimplemented!()
        }

        fn u_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
    }

    /// Stand-in for Java's `IntSExtOpGen`, which implements `IntExtUnOpGen<JitIntSExtOp>` with
    /// `isSigned() -> true`.
    struct SExtGen;
    impl OpGen<TestUnOp> for SExtGen {}
    impl UnOpGen<TestUnOp> for SExtGen {
        fn is_signed(&self) -> bool {
            true
        }
    }
    impl IntExtUnOpGen<TestUnOp> for SExtGen {}

    /// Stand-in for Java's `IntZExtOpGen`, which implements `IntExtUnOpGen<JitIntZExtOp>` with
    /// `isSigned() -> false`.
    struct ZExtGen;
    impl OpGen<TestUnOp> for ZExtGen {}
    impl UnOpGen<TestUnOp> for ZExtGen {
        fn is_signed(&self) -> bool {
            false
        }
    }
    impl IntExtUnOpGen<TestUnOp> for ZExtGen {}

    #[test]
    fn ext_resolves_through_un_op_gen_default_like_java_implementors() {
        // Java: neither `IntSExtOpGen` nor `IntZExtOpGen` overrides `ext()`; `genRun` resolves it
        // via `UnOpGen`'s default (`Ext.forSigned(isSigned())`), unchanged by implementing
        // `IntExtUnOpGen`.
        assert_eq!(SExtGen.ext(), Ext::Sign);
        assert_eq!(ZExtGen.ext(), Ext::Zero);
    }

    #[test]
    fn int_ext_un_op_gen_extends_un_op_gen_like_java_interface() {
        // Java: `interface IntExtUnOpGen<T extends JitUnOp> extends UnOpGen<T>`.
        fn assert_is_un_op_gen<G: UnOpGen<TestUnOp>>(_gen: &G) {}
        assert_is_un_op_gen(&SExtGen);
        assert_is_un_op_gen(&ZExtGen);
    }
}
