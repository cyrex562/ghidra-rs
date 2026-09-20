//! The generator for a `float_neg` op.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.FloatNegOpGen`.
//!
//! # Differences from Java
//!
//! - Java's singleton `enum FloatNegOpGen implements FloatOpUnOpGen<JitFloatNegOp> { GEN; }`
//!   becomes a zero-sized unit-like enum with a single variant and a `GEN` constant, per the
//!   convention set by [`CopyOpGen`](super::copy_op_gen::CopyOpGen).
//! - `opForFloat`/`opForDouble` emit `Op::fneg`/`Op::dneg`. The not-yet-ported `Op` (JVM opcode
//!   helper namespace) means the opcode itself is not modeled; per the precedent set throughout
//!   this package (see e.g. [`FloatOpUnOpGen`](super::float_op_un_op_gen::FloatOpUnOpGen)'s module
//!   docs), the shape-preserving [`Emitter::recast`] stands in for it.

use crate::pcode::emu::jit::gen::op::float_op_un_op_gen::FloatOpUnOpGen;
use crate::pcode::emu::jit::gen::op::un_op_gen::UnOpGen;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::types::{TDouble, TFloat};
use crate::pcode::emu::jit::op::JitFloatNegOp;
use crate::pcode::emu::jit::gen::op::op_gen::OpGen;

/// The generator for a [`JitFloatNegOp`] (`float_neg`).
///
/// Port of `ghidra.pcode.emu.jit.gen.op.FloatNegOpGen`.
///
/// This uses the unary operator generator and emits `fneg` or `dneg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatNegOpGen {
    /// The generator singleton.
    Gen,
}

impl FloatNegOpGen {
    /// The singleton instance of `FloatNegOpGen`.
    pub const GEN: Self = FloatNegOpGen::Gen;
}

impl OpGen<JitFloatNegOp> for FloatNegOpGen {}

impl UnOpGen<JitFloatNegOp> for FloatNegOpGen {
    fn is_signed(&self) -> bool {
        self.float_op_un_op_gen_is_signed()
    }
}

impl FloatOpUnOpGen<JitFloatNegOp> for FloatNegOpGen {
    fn op_for_float<N: Next>(&self, em: Emitter<Ent<N, TFloat>>) -> Emitter<Ent<N, TFloat>> {
        // Op::fneg is not yet ported; see the module docs.
        em.recast()
    }

    fn op_for_double<N: Next>(&self, em: Emitter<Ent<N, TDouble>>) -> Emitter<Ent<N, TDouble>> {
        // Op::dneg is not yet ported; see the module docs.
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
    fn gen_implements_op_gen_for_jit_float_neg_op() {
        // Java: `enum FloatNegOpGen implements FloatOpUnOpGen<JitFloatNegOp> { GEN; }`
        fn assert_is_op_gen<T: JitOp>(_gen: &impl OpGen<T>) {}
        assert_is_op_gen::<JitFloatNegOp>(&FloatNegOpGen::Gen);
    }

    #[test]
    fn gen_is_zero_sized_singleton() {
        assert_eq!(std::mem::size_of::<FloatNegOpGen>(), 0);
        assert_eq!(FloatNegOpGen::GEN, FloatNegOpGen::Gen);
    }

    #[test]
    fn is_signed_is_false_like_float_operators() {
        assert!(!UnOpGen::is_signed(&FloatNegOpGen::GEN));
        assert_eq!(FloatNegOpGen::GEN.ext(), Ext::Zero);
    }

    #[test]
    fn op_for_float_preserves_the_stack_tail() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Tail, TFloat>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TFloat>> = FloatNegOpGen::GEN.op_for_float(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn op_for_double_preserves_the_stack_tail() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Tail, TDouble>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TDouble>> = FloatNegOpGen::GEN.op_for_double(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn float_neg_op_gen_extends_float_op_un_op_gen_like_java_interface() {
        fn assert_is_float_op_un_op_gen<G: FloatOpUnOpGen<JitFloatNegOp>>(_gen: &G) {}
        assert_is_float_op_un_op_gen(&FloatNegOpGen::GEN);
    }
}
