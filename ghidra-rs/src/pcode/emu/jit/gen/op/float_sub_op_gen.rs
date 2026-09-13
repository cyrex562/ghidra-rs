//! The generator for a `float_sub` op.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.FloatSubOpGen`.
//!
//! # Differences from Java
//!
//! - Java's singleton `enum FloatSubOpGen implements FloatOpBinOpGen<JitFloatSubOp> { GEN; }`
//!   becomes a zero-sized unit-like enum with a single variant and a `GEN` constant, per the
//!   convention set by [`CopyOpGen`](super::copy_op_gen::CopyOpGen).
//! - `opForFloat`/`opForDouble` emit `Op::fsub`/`Op::dsub`. The not-yet-ported `Op` (JVM opcode
//!   helper namespace) means the opcode itself is not modeled; per the precedent set throughout
//!   this package (see e.g. [`FloatOpBinOpGen`](super::float_op_bin_op_gen::FloatOpBinOpGen)'s
//!   module docs), the shape-preserving [`Emitter::recast`] stands in for it.

use crate::pcode::emu::jit::gen::op::bin_op_gen::BinOpGen;
use crate::pcode::emu::jit::gen::op::float_op_bin_op_gen::FloatOpBinOpGen;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::types::{TDouble, TFloat};
use crate::pcode::emu::jit::op::JitFloatSubOp;
use crate::pcode::seam_stubs::OpGen;

/// The generator for a [`JitFloatSubOp`] (`float_sub`).
///
/// Port of `ghidra.pcode.emu.jit.gen.op.FloatSubOpGen`.
///
/// This uses the binary operator generator and simply emits `fsub` or `dsub` depending on the
/// type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatSubOpGen {
    /// The generator singleton.
    Gen,
}

impl FloatSubOpGen {
    /// The singleton instance of `FloatSubOpGen`.
    pub const GEN: Self = FloatSubOpGen::Gen;
}

impl OpGen<JitFloatSubOp> for FloatSubOpGen {}

impl BinOpGen<JitFloatSubOp> for FloatSubOpGen {
    fn is_signed(&self) -> bool {
        self.float_op_bin_op_gen_is_signed()
    }
}

impl FloatOpBinOpGen<JitFloatSubOp> for FloatSubOpGen {
    fn op_for_float<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TFloat>, TFloat>>,
    ) -> Emitter<Ent<N, TFloat>> {
        // Op::fsub is not yet ported; see the module docs.
        em.recast()
    }

    fn op_for_double<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TDouble>, TDouble>>,
    ) -> Emitter<Ent<N, TDouble>> {
        // Op::dsub is not yet ported; see the module docs.
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
    fn gen_implements_op_gen_for_jit_float_sub_op() {
        // Java: `enum FloatSubOpGen implements FloatOpBinOpGen<JitFloatSubOp> { GEN; }`
        fn assert_is_op_gen<T: JitOp>(_gen: &impl OpGen<T>) {}
        assert_is_op_gen::<JitFloatSubOp>(&FloatSubOpGen::Gen);
    }

    #[test]
    fn gen_is_zero_sized_singleton() {
        assert_eq!(std::mem::size_of::<FloatSubOpGen>(), 0);
        assert_eq!(FloatSubOpGen::GEN, FloatSubOpGen::Gen);
    }

    #[test]
    fn is_signed_is_false_like_float_operators() {
        assert!(!BinOpGen::is_signed(&FloatSubOpGen::GEN));
        assert_eq!(FloatSubOpGen::GEN.ext(), Ext::Zero);
    }

    #[test]
    fn op_for_float_preserves_the_stack_tail() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TFloat>, TFloat>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TFloat>> = FloatSubOpGen::GEN.op_for_float(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn op_for_double_preserves_the_stack_tail() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TDouble>, TDouble>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TDouble>> = FloatSubOpGen::GEN.op_for_double(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn float_sub_op_gen_extends_float_op_bin_op_gen_like_java_interface() {
        fn assert_is_float_op_bin_op_gen<G: FloatOpBinOpGen<JitFloatSubOp>>(_gen: &G) {}
        assert_is_float_op_bin_op_gen(&FloatSubOpGen::GEN);
    }
}
