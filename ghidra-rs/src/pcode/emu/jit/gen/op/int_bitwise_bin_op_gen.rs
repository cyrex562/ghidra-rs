//! An extension for bitwise binary operators.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.IntBitwiseBinOpGen`.
//!
//! This provides a simple strategy for multi-precision integer implementation. Since all bit
//! positions are considered independently, the same
//! [`op_for_int`](super::int_op_bin_op_gen::IntOpBinOpGen::op_for_int) operator applies to each
//! pair of corresponding legs independently to compute each corresponding output leg.
//!
//! # Differences from Java
//!
//! - Java's `default boolean isSigned()` and `default Emitter<Bot> genRunMpInt(...)` override the
//!   abstract methods of the same name inherited from `BinOpGen`/`IntOpBinOpGen`. Rust cannot
//!   "override" a supertrait method by redeclaring it under the same name, so -- per the
//!   convention already set by
//!   [`SubInLongHandler`](crate::pcode::emu::jit::alloc::sub_in_long_handler::SubInLongHandler) --
//!   they are exposed here under distinct `int_bitwise_bin_op_gen_*` names. A concrete
//!   implementor's own `BinOpGen::is_signed` and `IntOpBinOpGen::gen_run_mp_int` impls should
//!   delegate to these.
//! - `genRunMpInt`'s per-leg loop (`type.legsAlloc()` iterations of: read one leg of each operand,
//!   apply `opForInt`, write the result leg) reads legs off the operand returned by
//!   `JitCodeGenerator.genReadToOpnd` via `Opnd.type().castLegsLE(opnd)`. The marker-only
//!   [`Opnd`](crate::pcode::seam_stubs::Opnd) stub does not expose leg accessors yet (see
//!   [`MpToStackConv`](crate::pcode::seam_stubs::MpToStackConv)'s docs for the same gap), so the
//!   loop itself is not modeled here; only the leg count (`type_.legs_alloc()`) -- the real,
//!   testable part -- is computed, mirroring
//!   [`BinOpGen::gen_mp_delegation_to_static_method`](super::bin_op_gen::BinOpGen::gen_mp_delegation_to_static_method).
//! - Java's `v: JitVar` parameter to `JitCodeGenerator.genWriteFromOpnd` is narrowed to `&dyn
//!   JitOutVar` at the call site (`op.out()`), since this crate's
//!   [`JitOutVar`](crate::pcode::seam_stubs::JitOutVar) stub does not (yet) extend the real
//!   [`JitVar`](crate::pcode::emu::jit::var::JitVar) port; see
//!   [`JitCodeGenerator::gen_write_from_opnd`](crate::pcode::seam_stubs::JitCodeGenerator::gen_write_from_opnd)'s
//!   doc.

use crate::pcode::emu::jit::analysis::jit_type::MpIntJitType;
use crate::pcode::emu::jit::gen::op::int_op_bin_op_gen::IntOpBinOpGen;
use crate::pcode::emu::jit::gen::util::emitter::{Bot, Emitter};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::TRef;
use crate::pcode::seam_stubs::{JitBinOp, JitCodeGenerator, MpIntLocalOpnd, Scope};

/// An extension for bitwise binary operators.
///
/// Port of `ghidra.pcode.emu.jit.gen.op.IntBitwiseBinOpGen<T>`. See the [module docs](self) for
/// how this differs from the Java interface.
pub trait IntBitwiseBinOpGen<T: JitBinOp>: IntOpBinOpGen<T> {
    /// Bitwise operators are never signed.
    ///
    /// Port of `IntBitwiseBinOpGen.isSigned`, which overrides `BinOpGen.isSigned`. See the
    /// [module docs](self) on why this is not named `is_signed`.
    fn int_bitwise_bin_op_gen_is_signed(&self) -> bool {
        false
    }

    /// Apply [`op_for_int`](IntOpBinOpGen::op_for_int) independently to each pair of
    /// corresponding legs to compute each output leg.
    ///
    /// Port of `IntBitwiseBinOpGen.genRunMpInt`, which overrides `IntOpBinOpGen.genRunMpInt`. See
    /// the [module docs](self) on why this is not named `gen_run_mp_int`, and on what of the
    /// per-leg loop is and is not modeled.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the empty stack.
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `gen`: the code generator.
    /// - `op`: the p-code op.
    /// - `type_`: the p-code type of the operands.
    /// - `scope`: a scope for generating temporary local storage.
    ///
    /// # Returns
    ///
    /// The emitter typed with the empty stack.
    fn int_bitwise_bin_op_gen_gen_run_mp_int(
        &self,
        em: Emitter<Bot>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        op: &T,
        type_: MpIntJitType,
        scope: &dyn Scope,
    ) -> Emitter<Bot> {
        let left =
            gen.gen_read_to_opnd(em, local_this, op.l().as_ref(), type_.clone(), self.ext(), scope);
        let right = gen.gen_read_to_opnd(
            left.em,
            local_this,
            op.r().as_ref(),
            type_.clone(),
            self.r_ext(),
            scope,
        );
        let em = right.em;
        let _ = (left.opnd, right.opnd);

        // Port of `type.legsAlloc()`: the leg count driving the per-leg `opForInt` loop in Java.
        // See the module docs for why the loop itself is not modeled.
        let _leg_count = type_.legs_alloc();

        let out = MpIntLocalOpnd::of(type_, "out");
        gen.gen_write_from_opnd(em, local_this, op.out().as_ref(), &out, self.ext(), scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::op::bin_op_gen::BinOpGen;
    use crate::pcode::emu::jit::gen::util::emitter::{Ent, Next};
    use crate::pcode::emu::jit::gen::util::types::{TInt, TLong};
    use crate::pcode::emu::jit::op::{JitDefOp, JitOp};
    use crate::pcode::emu::jit::var::{JitVal, JitOutVar};
    use crate::pcode::seam_stubs::{Ext, JitTypeBehavior, MethodVisitor};
    use std::sync::Arc;

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
        fn space(&self) -> Arc<crate::program::model::address::AddressSpace> {
            Arc::new(crate::program::model::address::AddressSpace::new("test", 64, 1, crate::program::model::address::AddressSpaceType::Ram, 0))
        }
    }

    impl crate::pcode::emu::jit::var::JitVarnodeVar for MockOutVar {
        fn varnode(&self) -> crate::program::model::pcode::Varnode {
            use crate::program::model::pcode::Varnode;
            use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
            let space = AddressSpace::new("test", 64, 1, AddressSpaceType::Ram, 0);
            let addr = Address::new(Arc::new(space), 0);
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

    struct TestBinOp;

    impl JitOp for TestBinOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
        fn link(&self) {}
        fn unlink(&self) {}
    }

    impl JitDefOp for TestBinOp {
        fn out(&self) -> Arc<dyn JitOutVar> {
            Arc::new(MockOutVar)
        }
    }

    impl JitBinOp for TestBinOp {
        fn l(&self) -> Box<dyn JitVal> {
            Box::new(MockVal)
        }
        fn r(&self) -> Box<dyn JitVal> {
            Box::new(MockVal)
        }
        fn l_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
        fn r_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
    }

    struct MockCodeGenerator;
    impl JitCodeGenerator for MockCodeGenerator {}

    struct MockScope;
    impl Scope for MockScope {}

    /// A stand-in for a concrete generator such as Java's `IntAndOpGen`, wiring `BinOpGen`'s
    /// abstract `is_signed` and `IntOpBinOpGen`'s abstract `gen_run_mp_int` to the
    /// `int_bitwise_bin_op_gen_*`-named overrides, per the [module docs](super).
    struct AndGen;
    impl crate::pcode::seam_stubs::OpGen<TestBinOp> for AndGen {}
    impl BinOpGen<TestBinOp> for AndGen {
        fn is_signed(&self) -> bool {
            self.int_bitwise_bin_op_gen_is_signed()
        }
    }
    impl IntOpBinOpGen<TestBinOp> for AndGen {
        fn op_for_int<N: Next>(
            &self,
            em: Emitter<Ent<Ent<N, TInt>, TInt>>,
            _type_: crate::pcode::emu::jit::analysis::jit_type::IntJitType,
        ) -> Emitter<Ent<N, TInt>> {
            em.recast()
        }

        fn op_for_long<N: Next>(
            &self,
            em: Emitter<Ent<Ent<N, TLong>, TLong>>,
            _type_: crate::pcode::emu::jit::analysis::jit_type::LongJitType,
        ) -> Emitter<Ent<N, TLong>> {
            em.recast()
        }

        fn gen_run_mp_int(
            &self,
            em: Emitter<Bot>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            op: &TestBinOp,
            type_: MpIntJitType,
            scope: &dyn Scope,
        ) -> Emitter<Bot> {
            self.int_bitwise_bin_op_gen_gen_run_mp_int(em, local_this, gen, op, type_, scope)
        }
    }
    impl IntBitwiseBinOpGen<TestBinOp> for AndGen {}

    #[test]
    fn is_signed_is_false_like_java_default_method() {
        // Java: `IntBitwiseBinOpGen.isSigned()` unconditionally returns `false`, regardless of
        // the underlying bitwise operator (AND/OR/XOR are never sign-dependent).
        assert!(!AndGen.int_bitwise_bin_op_gen_is_signed());
        assert!(!BinOpGen::is_signed(&AndGen));
    }

    #[test]
    fn ext_and_r_ext_are_zero_since_bitwise_ops_are_unsigned() {
        // Java: `ext()`/`rExt()` are `BinOpGen` defaults computed from `isSigned()`; since
        // `IntBitwiseBinOpGen` hardcodes `isSigned() == false`, both extensions are always
        // zero-extension, even though this generator's `is_signed` override forwards to it.
        assert_eq!(AndGen.ext(), Ext::Zero);
        assert_eq!(AndGen.r_ext(), Ext::Zero);
    }

    #[test]
    fn gen_run_mp_int_preserves_the_empty_stack_and_computes_the_leg_count() {
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0);
        let code_gen = MockCodeGenerator;
        let scope = MockScope;
        let op = TestBinOp;

        // Java: `MpIntJitType.legsAlloc()` for a 9-byte mp-int is 3 (`ceil(9 / 4)`), already
        // tested on `MpIntJitType` itself; `genRunMpInt` loops that many times over `opForInt`.
        let type_ = MpIntJitType::for_size(9);
        assert_eq!(type_.legs_alloc(), 3);

        let result = AndGen.int_bitwise_bin_op_gen_gen_run_mp_int(
            em,
            &local_this,
            &code_gen,
            &op,
            type_,
            &scope,
        );
        assert!(result.local_variables().is_empty());
    }
}
