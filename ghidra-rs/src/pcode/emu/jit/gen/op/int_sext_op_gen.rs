//! The generator for a `int_sext` op.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.IntSExtOpGen`.
//!
//! # Differences from Java
//!
//! Java's singleton `enum IntSExtOpGen implements IntExtUnOpGen<JitIntSExtOp> { GEN; }` becomes a
//! zero-sized unit-like enum with a single variant and a `GEN` constant, per the convention set by
//! [`CopyOpGen`](super::copy_op_gen::CopyOpGen) and
//! [`IntZExtOpGen`](super::int_z_ext_op_gen::IntZExtOpGen), whose doc comment already notes that
//! `genRun` itself is not ported (see [`IntExtUnOpGen`](super::int_ext_un_op_gen::IntExtUnOpGen)'s
//! own docs).
//!
//! This works exactly the same as [`IntZExtOpGen`](super::int_z_ext_op_gen::IntZExtOpGen) except
//! that the conversions use sign extension (`is_signed` returns `true` instead of `false`).

use crate::pcode::emu::jit::gen::op::int_ext_un_op_gen::IntExtUnOpGen;
use crate::pcode::emu::jit::gen::op::un_op_gen::UnOpGen;
use crate::pcode::emu::jit::op::JitIntSExtOp;
use crate::pcode::emu::jit::gen::op::op_gen::OpGen;

/// The generator for a [`JitIntSExtOp`] (`int_sext`).
///
/// Port of `ghidra.pcode.emu.jit.gen.op.IntSExtOpGen`.
///
/// This uses the unary operator generator and emits nothing extra. The unary generator template
/// emits code to load the input operand, this emits nothing, and then the template emits code to
/// write the output operand, including the necessary type conversion; that type conversion
/// performs the sign extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntSExtOpGen {
    /// The generator singleton.
    Gen,
}

impl IntSExtOpGen {
    /// The singleton instance of `IntSExtOpGen`.
    pub const GEN: Self = IntSExtOpGen::Gen;
}

impl OpGen<JitIntSExtOp> for IntSExtOpGen {}

impl UnOpGen<JitIntSExtOp> for IntSExtOpGen {
    fn is_signed(&self) -> bool {
        true
    }
}

impl IntExtUnOpGen<JitIntSExtOp> for IntSExtOpGen {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::op::JitOp;
    use crate::pcode::seam_stubs::Ext;

    #[test]
    fn gen_implements_op_gen_for_jit_int_s_ext_op() {
        // Java: `enum IntSExtOpGen implements IntExtUnOpGen<JitIntSExtOp> { GEN; }`
        fn assert_is_op_gen<T: JitOp>(_gen: &impl OpGen<T>) {}
        assert_is_op_gen::<JitIntSExtOp>(&IntSExtOpGen::Gen);
    }

    #[test]
    fn gen_is_zero_sized_singleton() {
        assert_eq!(std::mem::size_of::<IntSExtOpGen>(), 0);
        assert_eq!(IntSExtOpGen::GEN, IntSExtOpGen::Gen);
    }

    #[test]
    fn is_signed_is_true() {
        // Java: `IntSExtOpGen.isSigned()` returns `true` (sign extension) -- the one behavioral
        // difference from `IntZExtOpGen`.
        assert!(IntSExtOpGen::GEN.is_signed());
    }

    #[test]
    fn ext_is_sign() {
        assert_eq!(IntSExtOpGen::GEN.ext(), Ext::Sign);
    }

    #[test]
    fn int_s_ext_op_gen_extends_int_ext_un_op_gen_like_java_interface() {
        fn assert_is_int_ext_un_op_gen<G: IntExtUnOpGen<JitIntSExtOp>>(_gen: &G) {}
        assert_is_int_ext_un_op_gen(&IntSExtOpGen::GEN);
    }
}
