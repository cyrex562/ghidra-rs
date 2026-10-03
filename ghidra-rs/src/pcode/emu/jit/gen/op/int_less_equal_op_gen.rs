//! The generator for a `int_lessequal` op.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.IntLessEqualOpGen`.
//!
//! # Differences from Java
//!
//! - Java's singleton `enum IntLessEqualOpGen implements IntCompareBinOpGen<JitIntLessEqualOp> {
//!   GEN; }` becomes a zero-sized unit-like enum with a single variant and a `GEN` constant, per
//!   the convention set by [`CopyOpGen`](super::copy_op_gen::CopyOpGen).
//! - `opForInt`/`opForLong` delegate to
//!   [`IntCompareBinOpGen::gen_int_via_ucmp_then_if`]/[`IntCompareBinOpGen::gen_long_via_ucmp_then_if`]
//!   with `Op::ifle` as the conditional-jump opcode. `Op::ifle` itself is not yet ported (see
//!   [`IntCompareBinOpGen`](super::int_compare_bin_op_gen::IntCompareBinOpGen)'s module docs), so
//!   the closure passed in its place uses `Lbl::place` over a shape-preserving [`Emitter::recast`],
//!   matching the precedent set by that module's own tests.

use crate::pcode::emu::jit::gen::op::bin_op_gen::BinOpGen;
use crate::pcode::emu::jit::gen::op::int_compare_bin_op_gen::IntCompareBinOpGen;
use crate::pcode::emu::jit::gen::op::int_pred_bin_op_gen::IntPredBinOpGen;
use crate::pcode::emu::jit::analysis::jit_type::{IntJitType, LongJitType, MpIntJitType};
use crate::pcode::emu::jit::gen::util::emitter::{Bot, Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::lbl::Lbl;
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TLong, TRef};
use crate::pcode::emu::jit::op::JitIntLessEqualOp;
use crate::pcode::seam_stubs::{JitCodeGenerator, Scope};
use crate::pcode::emu::jit::gen::op::op_gen::OpGen;
/// The generator for a [`JitIntLessEqualOp`] (`int_lessequal`).
///
/// Port of `ghidra.pcode.emu.jit.gen.op.IntLessEqualOpGen`.
///
/// This uses the (unsigned) integer comparison operator generator and simply emits `ifle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntLessEqualOpGen {
    /// The generator singleton.
    Gen,
}

impl IntLessEqualOpGen {
    /// The singleton instance of `IntLessEqualOpGen`.
    pub const GEN: Self = IntLessEqualOpGen::Gen;
}

impl OpGen<JitIntLessEqualOp> for IntLessEqualOpGen {}

impl BinOpGen<JitIntLessEqualOp> for IntLessEqualOpGen {
    fn is_signed(&self) -> bool {
        false
    }
}

impl IntPredBinOpGen<JitIntLessEqualOp> for IntLessEqualOpGen {
    fn op_for_int<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TInt>, TInt>>,
        _type_: IntJitType,
    ) -> Emitter<Ent<N, TInt>> {
        // Op::ifle is not yet ported; see the module docs.
        self.gen_int_via_ucmp_then_if(em, |em: Emitter<Ent<N, TInt>>| Lbl::place(em.recast()))
    }

    fn op_for_long<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TLong>, TLong>>,
        _type_: LongJitType,
    ) -> Emitter<Ent<N, TInt>> {
        // Op::ifle is not yet ported; see the module docs.
        self.gen_long_via_ucmp_then_if(em, |em: Emitter<Ent<N, TInt>>| Lbl::place(em.recast()))
    }

    fn gen_run_mp_int(
        &self,
        em: Emitter<Bot>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        op: &JitIntLessEqualOp,
        type_: MpIntJitType,
        scope: &dyn Scope,
    ) -> Emitter<Ent<Bot, TInt>> {
        self.int_compare_bin_op_gen_gen_run_mp_int(em, local_this, gen, op, type_, scope)
    }
}

impl IntCompareBinOpGen<JitIntLessEqualOp> for IntLessEqualOpGen {}

#[cfg(test)]
mod tests {
    use super::*;
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
        PcodeOp::new(OpCode::IntLessEqual, SequenceNumber::new(addr, 0), vec![], None)
    }

    struct MockOutVar;
    impl JitVal for MockOutVar {
        fn size(&self) -> i32 {
            4
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
            Varnode::new(addr, 4)
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
            4
        }
        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }

    struct MockCodeGenerator;
    impl JitCodeGenerator for MockCodeGenerator {}

    struct MockScope;
    impl Scope for MockScope {}

    fn make_test_op() -> JitIntLessEqualOp {
        JitIntLessEqualOp::new(
            make_op(),
            Arc::new(MockOutVar) as Arc<dyn JitOutVar>,
            Arc::new(MockVal) as Arc<dyn JitVal>,
            Arc::new(MockVal) as Arc<dyn JitVal>,
        )
    }

    #[test]
    fn gen_implements_op_gen_for_jit_int_less_equal_op() {
        // Java: `enum IntLessEqualOpGen implements IntCompareBinOpGen<JitIntLessEqualOp> { GEN; }`
        fn assert_is_op_gen<T: JitOp>(_gen: &impl OpGen<T>) {}
        assert_is_op_gen::<JitIntLessEqualOp>(&IntLessEqualOpGen::Gen);
    }

    #[test]
    fn gen_is_zero_sized_singleton() {
        assert_eq!(std::mem::size_of::<IntLessEqualOpGen>(), 0);
        assert_eq!(IntLessEqualOpGen::GEN, IntLessEqualOpGen::Gen);
    }

    #[test]
    fn is_signed_is_false() {
        assert!(!BinOpGen::is_signed(&IntLessEqualOpGen::GEN));
        assert_eq!(IntLessEqualOpGen::GEN.ext(), Ext::Zero);
    }

    #[test]
    fn op_for_int_reduces_two_ints_to_one_boolean() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TInt>, TInt>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> =
            IntLessEqualOpGen::GEN.op_for_int(em, IntJitType::I4);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn op_for_long_reduces_two_longs_to_one_boolean() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TLong>, TLong>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> =
            IntLessEqualOpGen::GEN.op_for_long(em, LongJitType::I8);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn gen_run_mp_int_delegates_to_int_compare_bin_op_gen() {
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0);
        let code_gen = MockCodeGenerator;
        let scope = MockScope;
        let op = make_test_op();

        let type_ = MpIntJitType::for_size(9);
        assert_eq!(type_.legs_alloc(), 3);

        let result = IntPredBinOpGen::gen_run_mp_int(
            &IntLessEqualOpGen::GEN,
            em,
            &local_this,
            &code_gen,
            &op,
            type_,
            &scope,
        );
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    fn int_less_equal_op_gen_extends_int_compare_bin_op_gen_like_java_interface() {
        fn assert_is_int_compare<G: IntCompareBinOpGen<JitIntLessEqualOp>>(_gen: &G) {}
        assert_is_int_compare(&IntLessEqualOpGen::GEN);
    }
}
