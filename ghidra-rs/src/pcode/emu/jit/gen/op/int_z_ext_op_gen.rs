//! The generator for a `int_zext` op.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.IntZExtOpGen`.
//!
//! # Differences from Java
//!
//! Java's singleton `enum IntZExtOpGen implements IntExtUnOpGen<JitIntZExtOp> { GEN; }` becomes a
//! zero-sized unit-like enum with a single variant and a `GEN` constant, per the convention set by
//! [`CopyOpGen`](super::copy_op_gen::CopyOpGen), whose doc comment already notes that
//! `IntZExtOpGen` and `CopyOpGen` are identical except for size-agreement expectations that this
//! port (following [`IntExtUnOpGen`](super::int_ext_un_op_gen::IntExtUnOpGen)'s own docs) does not
//! model, since `genRun` itself is not ported.

use crate::pcode::emu::jit::gen::op::int_ext_un_op_gen::IntExtUnOpGen;
use crate::pcode::emu::jit::gen::op::un_op_gen::UnOpGen;
use crate::pcode::emu::jit::op::JitIntZExtOp;
use crate::pcode::seam_stubs::OpGen;

/// The generator for a [`JitIntZExtOp`] (`int_zext`).
///
/// Port of `ghidra.pcode.emu.jit.gen.op.IntZExtOpGen`.
///
/// This uses the unary operator generator and emits nothing extra. The unary generator template
/// emits code to load the input operand, this emits nothing, and then the template emits code to
/// write the output operand, including the necessary type conversion; that type conversion
/// performs the zero extension.
///
/// Note that this is equivalent to [`CopyOpGen`](super::copy_op_gen::CopyOpGen), except that
/// differences in operand sizes are expected here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntZExtOpGen {
    /// The generator singleton.
    Gen,
}

impl IntZExtOpGen {
    /// The singleton instance of `IntZExtOpGen`.
    pub const GEN: Self = IntZExtOpGen::Gen;
}

impl OpGen<JitIntZExtOp> for IntZExtOpGen {}

impl UnOpGen<JitIntZExtOp> for IntZExtOpGen {
    fn is_signed(&self) -> bool {
        false
    }
}

impl IntExtUnOpGen<JitIntZExtOp> for IntZExtOpGen {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::op::JitOp;
    use crate::pcode::seam_stubs::Ext;

    #[test]
    fn gen_implements_op_gen_for_jit_int_z_ext_op() {
        // Java: `enum IntZExtOpGen implements IntExtUnOpGen<JitIntZExtOp> { GEN; }`
        fn assert_is_op_gen<T: JitOp>(_gen: &impl OpGen<T>) {}
        assert_is_op_gen::<JitIntZExtOp>(&IntZExtOpGen::Gen);
    }

    #[test]
    fn gen_is_zero_sized_singleton() {
        assert_eq!(std::mem::size_of::<IntZExtOpGen>(), 0);
        assert_eq!(IntZExtOpGen::GEN, IntZExtOpGen::Gen);
    }

    #[test]
    fn is_signed_is_false() {
        // Java: `IntZExtOpGen.isSigned()` returns `false` (zero extension).
        assert!(!IntZExtOpGen::GEN.is_signed());
    }

    #[test]
    fn ext_is_zero() {
        assert_eq!(IntZExtOpGen::GEN.ext(), Ext::Zero);
    }

    #[test]
    fn int_z_ext_op_gen_extends_int_ext_un_op_gen_like_java_interface() {
        fn assert_is_int_ext_un_op_gen<G: IntExtUnOpGen<JitIntZExtOp>>(_gen: &G) {}
        assert_is_int_ext_un_op_gen(&IntZExtOpGen::GEN);
    }
}
