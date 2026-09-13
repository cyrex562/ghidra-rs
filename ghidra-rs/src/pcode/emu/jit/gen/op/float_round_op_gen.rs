//! The generator for a `float_round` op.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.FloatRoundOpGen`.
//!
//! # Differences from Java
//!
//! - Java's singleton `enum FloatRoundOpGen implements FloatOpUnOpGen<JitFloatRoundOp> { GEN; }`
//!   becomes a zero-sized unit-like enum with a single variant and a `GEN` constant, per the
//!   convention set by [`CopyOpGen`](super::copy_op_gen::CopyOpGen).
//! - The JVM provides `Math.round(float)`/`Math.round(double)`, but both return an `int`/`long`,
//!   which is unsuitable here since no type conversion is wanted. Java instead constructs
//!   `round(x) = floor(x + 0.5)` directly: `opForFloat` is
//!   `ldc(0.5f).fadd.f2d.invokestatic(Math.floor).d2f`, and `opForDouble` is
//!   `ldc(0.5).dadd.invokestatic(Math.floor)`. Notably, **`opForFloat` does not delegate to
//!   `opForDouble`** (unlike [`FloatCeilOpGen`](super::float_ceil_op_gen::FloatCeilOpGen)/
//!   [`FloatFloorOpGen`](super::float_floor_op_gen::FloatFloorOpGen)/
//!   [`FloatSqrtOpGen`](super::float_sqrt_op_gen::FloatSqrtOpGen)); it inlines its own,
//!   independent `float`-flavored sequence. This port preserves that structural difference: the
//!   two methods are independent, not composed.
//! - Every individual opcode in both sequences (`Op::ldc__f`/`Op::ldc__d`, `Op::fadd`/`Op::dadd`,
//!   `Op::f2d`/`Op::d2f`, and the `invokestatic` to `Math.floor(double)` via the not-yet-ported
//!   `Methods.Inv`) depends on the not-yet-ported `Op`/`Methods`/`GenConsts`; per the precedent set
//!   throughout this package (see e.g.
//!   [`FloatOpUnOpGen`](super::float_op_un_op_gen::FloatOpUnOpGen)'s module docs), the
//!   shape-preserving [`Emitter::recast`] stands in for the whole unmodeled sequence.

use crate::pcode::emu::jit::gen::op::float_op_un_op_gen::FloatOpUnOpGen;
use crate::pcode::emu::jit::gen::op::un_op_gen::UnOpGen;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::types::{TDouble, TFloat};
use crate::pcode::emu::jit::op::JitFloatRoundOp;
use crate::pcode::seam_stubs::OpGen;

/// The generator for a [`JitFloatRoundOp`] (`float_round`).
///
/// Port of `ghidra.pcode.emu.jit.gen.op.FloatRoundOpGen`.
///
/// The JVM does provide a `Math.round(float)` method, however it returns an `int`. (It has a
/// similar method for doubles with the same problem.) That would be suitable if a type conversion
/// were also desired, but that is not the case. Thus, we construct a rounding function without
/// conversion: `round(x) = floor(x + 0.5)`. This uses the unary operator generator and emits the
/// bytecode to implement that definition, applying type conversions as needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatRoundOpGen {
    /// The generator singleton.
    Gen,
}

impl FloatRoundOpGen {
    /// The singleton instance of `FloatRoundOpGen`.
    pub const GEN: Self = FloatRoundOpGen::Gen;
}

impl OpGen<JitFloatRoundOp> for FloatRoundOpGen {}

impl UnOpGen<JitFloatRoundOp> for FloatRoundOpGen {
    fn is_signed(&self) -> bool {
        self.float_op_un_op_gen_is_signed()
    }
}

impl FloatOpUnOpGen<JitFloatRoundOp> for FloatRoundOpGen {
    fn op_for_float<N: Next>(&self, em: Emitter<Ent<N, TFloat>>) -> Emitter<Ent<N, TFloat>> {
        // Java: `ldc(0.5f).fadd.f2d.invokestatic(Math.floor).d2f`. This does NOT delegate to
        // `op_for_double`; see the module docs. None of the individual opcodes are yet ported.
        em.recast()
    }

    fn op_for_double<N: Next>(&self, em: Emitter<Ent<N, TDouble>>) -> Emitter<Ent<N, TDouble>> {
        // Java: `ldc(0.5).dadd.invokestatic(Math.floor)`. Not yet ported; see the module docs.
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
    fn gen_implements_op_gen_for_jit_float_round_op() {
        // Java: `enum FloatRoundOpGen implements FloatOpUnOpGen<JitFloatRoundOp> { GEN; }`
        fn assert_is_op_gen<T: JitOp>(_gen: &impl OpGen<T>) {}
        assert_is_op_gen::<JitFloatRoundOp>(&FloatRoundOpGen::Gen);
    }

    #[test]
    fn gen_is_zero_sized_singleton() {
        assert_eq!(std::mem::size_of::<FloatRoundOpGen>(), 0);
        assert_eq!(FloatRoundOpGen::GEN, FloatRoundOpGen::Gen);
    }

    #[test]
    fn is_signed_is_false_like_float_operators() {
        assert!(!UnOpGen::is_signed(&FloatRoundOpGen::GEN));
        assert_eq!(FloatRoundOpGen::GEN.ext(), Ext::Zero);
    }

    #[test]
    fn op_for_float_preserves_the_stack_tail() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Tail, TFloat>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TFloat>> = FloatRoundOpGen::GEN.op_for_float(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn op_for_double_preserves_the_stack_tail() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Tail, TDouble>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TDouble>> = FloatRoundOpGen::GEN.op_for_double(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn float_round_op_gen_extends_float_op_un_op_gen_like_java_interface() {
        fn assert_is_float_op_un_op_gen<G: FloatOpUnOpGen<JitFloatRoundOp>>(_gen: &G) {}
        assert_is_float_op_un_op_gen(&FloatRoundOpGen::GEN);
    }
}
