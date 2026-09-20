//! The generator for a `bool_and` op.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.BoolAndOpGen`.
//!
//! # Differences from Java
//!
//! - Java's singleton `enum BoolAndOpGen implements IntBitwiseBinOpGen<JitBoolAndOp> { GEN; }`
//!   becomes a zero-sized unit-like enum with a single variant and a `GEN` constant, per the
//!   convention set by [`CopyOpGen`](super::copy_op_gen::CopyOpGen) and
//!   [`CBranchOpGen`](super::c_branch_op_gen::CBranchOpGen).
//! - `opForInt`/`opForLong` emit `Op::iand`/`Op::land`. The not-yet-ported `Op` (JVM opcode helper
//!   namespace) means the opcode itself is not modeled; per the precedent set throughout this
//!   package (see e.g. [`IntBitwiseBinOpGen`](super::int_bitwise_bin_op_gen::IntBitwiseBinOpGen)'s
//!   module docs), the shape-preserving [`Emitter::recast`] stands in for it.
//!
//! It is the responsibility of the slaspec author to ensure boolean values are 0 or 1. This
//! allows the generator to use bitwise logic instead of having to check for any non-zero value,
//! just like `OpBehaviorBoolAnd`. Thus, this is identical to
//! [`IntAndOpGen`](super::int_and_op_gen::IntAndOpGen). Because having bits other than the least
//! significant set in the inputs is "undefined behavior," Java notes this could technically be
//! optimized to only AND the least significant leg when dealing with mp-ints -- an optimization
//! neither Java nor this port performs.

use crate::pcode::emu::jit::gen::op::bin_op_gen::BinOpGen;
use crate::pcode::emu::jit::gen::op::int_bitwise_bin_op_gen::IntBitwiseBinOpGen;
use crate::pcode::emu::jit::gen::op::int_op_bin_op_gen::IntOpBinOpGen;
use crate::pcode::emu::jit::analysis::jit_type::{IntJitType, LongJitType, MpIntJitType};
use crate::pcode::emu::jit::gen::util::emitter::{Bot, Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TLong, TRef};
use crate::pcode::emu::jit::op::JitBoolAndOp;
use crate::pcode::seam_stubs::{JitCodeGenerator, Scope};
use crate::pcode::emu::jit::gen::op::op_gen::OpGen;
/// The generator for a [`JitBoolAndOp`] (`bool_and`).
///
/// Port of `ghidra.pcode.emu.jit.gen.op.BoolAndOpGen`.
///
/// This uses the bitwise binary operator and emits `iand` or `land` depending on the type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoolAndOpGen {
    /// The generator singleton.
    Gen,
}

impl BoolAndOpGen {
    /// The singleton instance of `BoolAndOpGen`.
    pub const GEN: Self = BoolAndOpGen::Gen;
}

impl OpGen<JitBoolAndOp> for BoolAndOpGen {}

impl BinOpGen<JitBoolAndOp> for BoolAndOpGen {
    fn is_signed(&self) -> bool {
        self.int_bitwise_bin_op_gen_is_signed()
    }
}

impl IntOpBinOpGen<JitBoolAndOp> for BoolAndOpGen {
    fn op_for_int<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TInt>, TInt>>,
        _type_: IntJitType,
    ) -> Emitter<Ent<N, TInt>> {
        // Op::iand is not yet ported; see the module docs.
        em.recast()
    }

    fn op_for_long<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TLong>, TLong>>,
        _type_: LongJitType,
    ) -> Emitter<Ent<N, TLong>> {
        // Op::land is not yet ported; see the module docs.
        em.recast()
    }

    fn gen_run_mp_int(
        &self,
        em: Emitter<Bot>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        op: &JitBoolAndOp,
        type_: MpIntJitType,
        scope: &dyn Scope,
    ) -> Emitter<Bot> {
        self.int_bitwise_bin_op_gen_gen_run_mp_int(em, local_this, gen, op, type_, scope)
    }
}

impl IntBitwiseBinOpGen<JitBoolAndOp> for BoolAndOpGen {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::emu::jit::gen::util::types::TRef;
    use crate::pcode::emu::jit::op::{JitDefOp, JitOp};
    use crate::pcode::emu::jit::var::{JitOutVar, JitVal};
    use crate::pcode::seam_stubs::{Ext, MethodVisitor};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{OpCode, PcodeOp, SequenceNumber};
    use std::sync::Arc;

    fn make_op() -> PcodeOp {
        let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0);
        PcodeOp::new(OpCode::BoolAnd, SequenceNumber::new(addr, 0), vec![], None)
    }

    struct MockOutVar;
    impl JitVal for MockOutVar {
        fn size(&self) -> i32 {
            1
        }
        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }
    impl crate::pcode::emu::jit::var::JitVar for MockOutVar {
        fn id(&self) -> i32 {
            0
        }
        fn space(&self) -> Arc<AddressSpace> {
            AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0)
        }
    }
    impl crate::pcode::emu::jit::var::JitVarnodeVar for MockOutVar {
        fn varnode(&self) -> crate::program::model::pcode::Varnode {
            use crate::program::model::pcode::Varnode;
            let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
            let addr = Address::new(space, 0);
            Varnode::new(addr, 1)
        }
    }
    impl JitOutVar for MockOutVar {
        fn set_definition(&self, _definition: Option<&dyn JitDefOp>) {}
        fn definition(&self) -> Option<Arc<dyn JitDefOp>> {
            None
        }
    }

    struct MockVal;
    impl JitVal for MockVal {
        fn size(&self) -> i32 {
            1
        }
        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }

    struct MockCodeGenerator;
    impl JitCodeGenerator for MockCodeGenerator {}

    struct MockScope;
    impl Scope for MockScope {}

    fn make_test_op() -> JitBoolAndOp {
        JitBoolAndOp::new(
            make_op(),
            Arc::new(MockOutVar) as Arc<dyn JitOutVar>,
            Arc::new(MockVal) as Arc<dyn JitVal>,
            Arc::new(MockVal) as Arc<dyn JitVal>,
        )
    }

    #[test]
    fn gen_implements_op_gen_for_jit_bool_and_op() {
        // Java: `enum BoolAndOpGen implements IntBitwiseBinOpGen<JitBoolAndOp> { GEN; }`
        fn assert_is_op_gen<T: JitOp>(_gen: &impl OpGen<T>) {}
        assert_is_op_gen::<JitBoolAndOp>(&BoolAndOpGen::Gen);
    }

    #[test]
    fn gen_is_zero_sized_singleton() {
        assert_eq!(std::mem::size_of::<BoolAndOpGen>(), 0);
        assert_eq!(BoolAndOpGen::GEN, BoolAndOpGen::Gen);
    }

    #[test]
    fn is_signed_is_false_like_bitwise_operators() {
        // Java: `IntBitwiseBinOpGen.isSigned()` unconditionally returns `false`.
        assert!(!BinOpGen::is_signed(&BoolAndOpGen::GEN));
        assert_eq!(BoolAndOpGen::GEN.ext(), Ext::Zero);
    }

    #[test]
    fn op_for_int_preserves_the_stack_tail() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TInt>, TInt>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> = BoolAndOpGen::GEN.op_for_int(em, IntJitType::I4);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn op_for_long_preserves_the_stack_tail() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TLong>, TLong>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TLong>> = BoolAndOpGen::GEN.op_for_long(em, LongJitType::I8);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn gen_run_mp_int_computes_the_leg_count() {
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0);
        let code_gen = MockCodeGenerator;
        let scope = MockScope;
        let op = make_test_op();

        // Java: `MpIntJitType.legsAlloc()` for a 9-byte mp-int is 3, driving the per-leg
        // `opForInt` loop that `IntBitwiseBinOpGen.genRunMpInt` performs.
        let type_ = MpIntJitType::for_size(9);
        assert_eq!(type_.legs_alloc(), 3);

        let result = IntOpBinOpGen::gen_run_mp_int(
            &BoolAndOpGen::GEN,
            em,
            &local_this,
            &code_gen,
            &op,
            type_,
            &scope,
        );
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn bool_and_op_gen_extends_int_bitwise_bin_op_gen_like_java_interface() {
        // Java: `interface BoolAndOpGen implements IntBitwiseBinOpGen<JitBoolAndOp>`.
        fn assert_is_int_bitwise<G: IntBitwiseBinOpGen<JitBoolAndOp>>(_gen: &G) {}
        assert_is_int_bitwise(&BoolAndOpGen::GEN);
    }
}
