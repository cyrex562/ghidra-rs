//! The generator for a `float_floor` op.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.FloatFloorOpGen`.
//!
//! # Differences from Java
//!
//! - Java's singleton `enum FloatFloorOpGen implements FloatOpUnOpGen<JitFloatFloorOp> { GEN; }`
//!   becomes a zero-sized unit-like enum with a single variant and a `GEN` constant, per the
//!   convention set by [`CopyOpGen`](super::copy_op_gen::CopyOpGen).
//! - `opForFloat` is `em.emit(Op::f2d).emit(this::opForDouble).emit(Op::d2f)`: real composition
//!   (it does call `opForDouble`) surrounded by `Op::f2d`/`Op::d2f` conversions. `opForDouble`
//!   itself emits an `invokestatic` to `Math.floor(double)`. Neither `Op::f2d`/`Op::d2f` nor the
//!   invocation (which needs `Methods.Inv`) is yet ported in this crate; per the precedent set
//!   throughout this package (see e.g.
//!   [`FloatOpUnOpGen`](super::float_op_un_op_gen::FloatOpUnOpGen)'s module docs), the
//!   shape-preserving [`Emitter::recast`] stands in for each, while the real call from
//!   `op_for_float` to `op_for_double` is preserved.

use crate::pcode::emu::jit::gen::op::float_op_un_op_gen::FloatOpUnOpGen;
use crate::pcode::emu::jit::gen::op::un_op_gen::UnOpGen;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::types::{TDouble, TFloat};
use crate::pcode::emu::jit::op::JitFloatFloorOp;
use crate::pcode::seam_stubs::OpGen;

/// The generator for a [`JitFloatFloorOp`] (`float_floor`).
///
/// Port of `ghidra.pcode.emu.jit.gen.op.FloatFloorOpGen`.
///
/// This uses the unary operator generator and emits an invocation of `Math.floor(double)`,
/// surrounding it with conversions from and to `float` when the operand is a `float`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatFloorOpGen {
    /// The generator singleton.
    Gen,
}

impl FloatFloorOpGen {
    /// The singleton instance of `FloatFloorOpGen`.
    pub const GEN: Self = FloatFloorOpGen::Gen;
}

impl OpGen<JitFloatFloorOp> for FloatFloorOpGen {}

impl UnOpGen<JitFloatFloorOp> for FloatFloorOpGen {
    fn is_signed(&self) -> bool {
        self.float_op_un_op_gen_is_signed()
    }
}

impl FloatOpUnOpGen<JitFloatFloorOp> for FloatFloorOpGen {
    fn op_for_float<N: Next>(&self, em: Emitter<Ent<N, TFloat>>) -> Emitter<Ent<N, TFloat>> {
        // Op::f2d is not yet ported; see the module docs.
        let em: Emitter<Ent<N, TDouble>> = em.recast();
        let em = self.op_for_double(em);
        // Op::d2f is not yet ported; see the module docs.
        em.recast()
    }

    fn op_for_double<N: Next>(&self, em: Emitter<Ent<N, TDouble>>) -> Emitter<Ent<N, TDouble>> {
        // invokestatic Math.floor(double) is not yet ported; see the module docs.
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
    fn gen_implements_op_gen_for_jit_float_floor_op() {
        // Java: `enum FloatFloorOpGen implements FloatOpUnOpGen<JitFloatFloorOp> { GEN; }`
        fn assert_is_op_gen<T: JitOp>(_gen: &impl OpGen<T>) {}
        assert_is_op_gen::<JitFloatFloorOp>(&FloatFloorOpGen::Gen);
    }

    #[test]
    fn gen_is_zero_sized_singleton() {
        assert_eq!(std::mem::size_of::<FloatFloorOpGen>(), 0);
        assert_eq!(FloatFloorOpGen::GEN, FloatFloorOpGen::Gen);
    }

    #[test]
    fn is_signed_is_false_like_float_operators() {
        assert!(!UnOpGen::is_signed(&FloatFloorOpGen::GEN));
        assert_eq!(FloatFloorOpGen::GEN.ext(), Ext::Zero);
    }

    #[test]
    fn op_for_float_preserves_the_stack_tail_via_double_round_trip() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Tail, TFloat>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TFloat>> = FloatFloorOpGen::GEN.op_for_float(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn op_for_double_preserves_the_stack_tail() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Tail, TDouble>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TDouble>> = FloatFloorOpGen::GEN.op_for_double(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn float_floor_op_gen_extends_float_op_un_op_gen_like_java_interface() {
        fn assert_is_float_op_un_op_gen<G: FloatOpUnOpGen<JitFloatFloorOp>>(_gen: &G) {}
        assert_is_float_op_un_op_gen(&FloatFloorOpGen::GEN);
    }
}
