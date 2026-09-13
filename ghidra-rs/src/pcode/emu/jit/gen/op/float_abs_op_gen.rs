//! The generator for a `float_abs` op.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.FloatAbsOpGen`.
//!
//! # Differences from Java
//!
//! - Java's singleton `enum FloatAbsOpGen implements FloatOpUnOpGen<JitFloatAbsOp> { GEN; }`
//!   becomes a zero-sized unit-like enum with a single variant and a `GEN` constant, per the
//!   convention set by [`CopyOpGen`](super::copy_op_gen::CopyOpGen).
//! - `opForFloat`/`opForDouble` emit an `invokestatic` to `Math.abs(float)`/`Math.abs(double)`,
//!   using `Op::invokestatic` and `Methods.Inv`'s stack-tracking `takeArg`/`ret` steps. Neither
//!   `Op` nor `Methods` is yet ported in this crate; per the precedent set throughout this package
//!   (see e.g. [`FloatOpUnOpGen`](super::float_op_un_op_gen::FloatOpUnOpGen)'s module docs), the
//!   shape-preserving [`Emitter::recast`] stands in for the invocation.

use crate::pcode::emu::jit::gen::op::float_op_un_op_gen::FloatOpUnOpGen;
use crate::pcode::emu::jit::gen::op::un_op_gen::UnOpGen;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::types::{TDouble, TFloat};
use crate::pcode::emu::jit::op::JitFloatAbsOp;
use crate::pcode::seam_stubs::OpGen;

/// The generator for a [`JitFloatAbsOp`] (`float_abs`).
///
/// Port of `ghidra.pcode.emu.jit.gen.op.FloatAbsOpGen`.
///
/// This uses the unary operator generator and emits an invocation of `Math.abs(float)` or
/// `Math.abs(double)`, depending on the type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatAbsOpGen {
    /// The generator singleton.
    Gen,
}

impl FloatAbsOpGen {
    /// The singleton instance of `FloatAbsOpGen`.
    pub const GEN: Self = FloatAbsOpGen::Gen;
}

impl OpGen<JitFloatAbsOp> for FloatAbsOpGen {}

impl UnOpGen<JitFloatAbsOp> for FloatAbsOpGen {
    fn is_signed(&self) -> bool {
        self.float_op_un_op_gen_is_signed()
    }
}

impl FloatOpUnOpGen<JitFloatAbsOp> for FloatAbsOpGen {
    fn op_for_float<N: Next>(&self, em: Emitter<Ent<N, TFloat>>) -> Emitter<Ent<N, TFloat>> {
        // invokestatic Math.abs(float) is not yet ported; see the module docs.
        em.recast()
    }

    fn op_for_double<N: Next>(&self, em: Emitter<Ent<N, TDouble>>) -> Emitter<Ent<N, TDouble>> {
        // invokestatic Math.abs(double) is not yet ported; see the module docs.
        em.recast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::emu::jit::gen::util::types::TRef;
    use crate::pcode::emu::jit::op::JitOp;
    use crate::pcode::seam_stubs::{Ext, MethodVisitor};

    #[test]
    fn gen_implements_op_gen_for_jit_float_abs_op() {
        // Java: `enum FloatAbsOpGen implements FloatOpUnOpGen<JitFloatAbsOp> { GEN; }`
        fn assert_is_op_gen<T: JitOp>(_gen: &impl OpGen<T>) {}
        assert_is_op_gen::<JitFloatAbsOp>(&FloatAbsOpGen::Gen);
    }

    #[test]
    fn gen_is_zero_sized_singleton() {
        assert_eq!(std::mem::size_of::<FloatAbsOpGen>(), 0);
        assert_eq!(FloatAbsOpGen::GEN, FloatAbsOpGen::Gen);
    }

    #[test]
    fn is_signed_is_false_like_float_operators() {
        assert!(!UnOpGen::is_signed(&FloatAbsOpGen::GEN));
        assert_eq!(FloatAbsOpGen::GEN.ext(), Ext::Zero);
    }

    #[test]
    fn op_for_float_preserves_the_stack_tail() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Tail, TFloat>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TFloat>> = FloatAbsOpGen::GEN.op_for_float(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn op_for_double_preserves_the_stack_tail() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Tail, TDouble>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TDouble>> = FloatAbsOpGen::GEN.op_for_double(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn float_abs_op_gen_extends_float_op_un_op_gen_like_java_interface() {
        fn assert_is_float_op_un_op_gen<G: FloatOpUnOpGen<JitFloatAbsOp>>(_gen: &G) {}
        assert_is_float_op_un_op_gen(&FloatAbsOpGen::GEN);
    }
}
