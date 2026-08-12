//! A generator for a copy operation.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.CopyOpGen`.
//!
//! # Differences from Java
//!
//! - Java's sole member is a `default` override of `genRun` (dispatching on the unified operand
//!   type, then delegating to the reader/writer pair -- `JitCodeGenerator.genReadToStack`/
//!   `genReadToOpnd` and `genWriteFromStack`/`genWriteFromOpnd`). It is not modeled here: it
//!   returns Java's `OpResult` (constructed as `LiveOpResult`) and takes a `Methods.RetReq`,
//!   neither of which is ported in this crate, and it is called only by the (also unported) JIT
//!   driver -- no implementor's own logic calls it. This follows the same precedent as
//!   [`IntExtUnOpGen`](super::int_ext_un_op_gen::IntExtUnOpGen), which has an analogous limitation.

use crate::pcode::emu::jit::gen::op::int_ext_un_op_gen::IntExtUnOpGen;
use crate::pcode::emu::jit::gen::op::un_op_gen::UnOpGen;
use crate::pcode::seam_stubs::{JitCopyOp, OpGen};

/// A generator for a copy operation.
///
/// Port of `ghidra.pcode.emu.jit.gen.op.CopyOpGen`.
///
/// This is identical to [`IntZExtOpGen`](crate::pcode::seam_stubs::IntZExtOpGen), except that we
/// expect (require?) the output and input operand to agree in size, and so we don't actually
/// expect any extension. In the event that is not the case, it seems agreeable that zero
/// extension is applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyOpGen {
    /// The generator singleton
    Gen,
}

impl CopyOpGen {
    /// The singleton instance of `CopyOpGen`.
    pub const GEN: Self = CopyOpGen::Gen;
}

impl OpGen<JitCopyOp> for CopyOpGen {}

impl UnOpGen<JitCopyOp> for CopyOpGen {
    fn is_signed(&self) -> bool {
        false
    }
}

impl IntExtUnOpGen<JitCopyOp> for CopyOpGen {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::seam_stubs::{Ext, JitOp};
    use std::sync::Arc;

    #[test]
    fn copy_op_gen_is_not_signed() {
        assert!(!CopyOpGen::GEN.is_signed());
    }

    #[test]
    fn copy_op_gen_ext_is_zero() {
        assert_eq!(CopyOpGen::GEN.ext(), Ext::Zero);
    }

    #[test]
    fn copy_op_gen_implements_op_gen() {
        fn assert_is_op_gen<T: JitOp>(_gen: &impl OpGen<T>) {}
        assert_is_op_gen::<JitCopyOp>(&CopyOpGen::Gen);
    }

    #[test]
    fn copy_op_gen_implements_un_op_gen() {
        // Java: `public enum CopyOpGen implements IntExtUnOpGen<JitCopyOp>`.
        // This verifies the trait hierarchy: IntExtUnOpGen extends UnOpGen.
        use crate::pcode::emu::jit::op::jit_un_op::JitUnOp;
        fn assert_is_un_op_gen<T: JitUnOp>(_gen: &impl UnOpGen<T>) {}
        assert_is_un_op_gen::<JitCopyOp>(&CopyOpGen::Gen);
    }

    #[test]
    fn copy_op_gen_gen_constant_equals_enum_gen() {
        assert_eq!(CopyOpGen::GEN, CopyOpGen::Gen);
    }

    #[test]
    fn copy_op_gen_is_zero_sized_singleton() {
        // Java: an enum with exactly one constant is a zero-field singleton.
        assert_eq!(std::mem::size_of::<CopyOpGen>(), 0);
        assert_eq!(CopyOpGen::Gen, CopyOpGen::Gen);
    }
}
