//! The generator for a `float_lessequal` op.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.FloatLessEqualOpGen`.
//!
//! # Differences from Java
//!
//! - Java's singleton `enum FloatLessEqualOpGen implements FloatCompareBinOpGen<JitFloatLessEqualOp>
//!   { GEN; }` becomes a zero-sized unit-like enum with a single variant and a `GEN` constant, per
//!   the convention set by [`CopyOpGen`](super::copy_op_gen::CopyOpGen).
//! - `opForFloatCmp`/`opForDoubleCmp` emit `Op::fcmpg`/`Op::dcmpg`, and `opForCondJump` emits
//!   `Op::ifle`. The not-yet-ported `Op` (JVM opcode helper namespace) means none of these opcodes
//!   are modeled; per the precedent set throughout this package (see e.g.
//!   [`FloatCompareBinOpGen`](super::float_compare_bin_op_gen::FloatCompareBinOpGen)'s module
//!   docs), the shape-preserving [`Emitter::recast`] (and, for the label-producing
//!   `opForCondJump`, [`Lbl::place`] over a recast) stands in for each.

use crate::pcode::emu::jit::gen::op::bin_op_gen::BinOpGen;
use crate::pcode::emu::jit::gen::op::float_compare_bin_op_gen::FloatCompareBinOpGen;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::lbl::{Lbl, LblEm};
use crate::pcode::emu::jit::gen::util::types::{TDouble, TFloat, TInt};
use crate::pcode::emu::jit::op::JitFloatLessEqualOp;
use crate::pcode::seam_stubs::OpGen;

/// The generator for a [`JitFloatLessEqualOp`] (`float_lessequal`).
///
/// Port of `ghidra.pcode.emu.jit.gen.op.FloatLessEqualOpGen`.
///
/// This uses the float comparison operator generator and simply emits `fcmpg` or `dcmpg`
/// depending on the type and then `ifle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatLessEqualOpGen {
    /// The generator singleton.
    Gen,
}

impl FloatLessEqualOpGen {
    /// The singleton instance of `FloatLessEqualOpGen`.
    pub const GEN: Self = FloatLessEqualOpGen::Gen;
}

impl OpGen<JitFloatLessEqualOp> for FloatLessEqualOpGen {}

impl BinOpGen<JitFloatLessEqualOp> for FloatLessEqualOpGen {
    fn is_signed(&self) -> bool {
        self.float_compare_bin_op_gen_is_signed()
    }
}

impl FloatCompareBinOpGen<JitFloatLessEqualOp> for FloatLessEqualOpGen {
    fn op_for_float_cmp<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TFloat>, TFloat>>,
    ) -> Emitter<Ent<N, TInt>> {
        // Op::fcmpg is not yet ported; see the module docs.
        em.recast()
    }

    fn op_for_double_cmp<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TDouble>, TDouble>>,
    ) -> Emitter<Ent<N, TInt>> {
        // Op::dcmpg is not yet ported; see the module docs.
        em.recast()
    }

    fn op_for_cond_jump<N: Next>(&self, em: Emitter<Ent<N, TInt>>) -> LblEm<N, N> {
        // Op::ifle is not yet ported; see the module docs.
        Lbl::place(em.recast())
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
    fn gen_implements_op_gen_for_jit_float_less_equal_op() {
        // Java: `enum FloatLessEqualOpGen implements FloatCompareBinOpGen<JitFloatLessEqualOp> { GEN; }`
        fn assert_is_op_gen<T: JitOp>(_gen: &impl OpGen<T>) {}
        assert_is_op_gen::<JitFloatLessEqualOp>(&FloatLessEqualOpGen::Gen);
    }

    #[test]
    fn gen_is_zero_sized_singleton() {
        assert_eq!(std::mem::size_of::<FloatLessEqualOpGen>(), 0);
        assert_eq!(FloatLessEqualOpGen::GEN, FloatLessEqualOpGen::Gen);
    }

    #[test]
    fn is_signed_is_false_like_float_operators() {
        assert!(!BinOpGen::is_signed(&FloatLessEqualOpGen::GEN));
        assert_eq!(FloatLessEqualOpGen::GEN.ext(), Ext::Zero);
    }

    #[test]
    fn op_for_float_cmp_yields_an_int_result() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TFloat>, TFloat>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> = FloatLessEqualOpGen::GEN.op_for_float_cmp(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn op_for_double_cmp_yields_an_int_result() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TDouble>, TDouble>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> = FloatLessEqualOpGen::GEN.op_for_double_cmp(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn op_for_cond_jump_pops_the_comparison_result() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Tail, TInt>> = Emitter::new(MethodVisitor::new());
        let LblEm { em: result, .. } = FloatLessEqualOpGen::GEN.op_for_cond_jump(em);
        let _: Emitter<Tail> = result;
    }

    #[test]
    fn float_less_equal_op_gen_extends_float_compare_bin_op_gen_like_java_interface() {
        fn assert_is_float_compare<G: FloatCompareBinOpGen<JitFloatLessEqualOp>>(_gen: &G) {}
        assert_is_float_compare(&FloatLessEqualOpGen::GEN);
    }
}
