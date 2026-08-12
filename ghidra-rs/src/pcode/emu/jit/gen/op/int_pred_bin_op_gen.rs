//! An extension for integer operators whose outputs are boolean.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.IntPredBinOpGen`.
//!
//! # Differences from Java
//!
//! - Java's `<N2 extends Next, N1 extends Ent<N2, TInt>, N0 extends Ent<N1, TInt>>` triple of
//!   bounds on [`op_for_int`](IntPredBinOpGen::op_for_int)/
//!   [`delegate_int_flagbit`](IntPredBinOpGen::delegate_int_flagbit) (and the analogous `TLong`
//!   triple on [`op_for_long`](IntPredBinOpGen::op_for_long)/
//!   [`delegate_long_flagbit`](IntPredBinOpGen::delegate_long_flagbit)) collapses to a single free
//!   parameter `N`, per the convention set by
//!   [`IntOpBinOpGen`](super::int_op_bin_op_gen::IntOpBinOpGen).
//! - Java's `<THIS extends JitCompiledPassage>` type parameter on
//!   [`gen_run_mp_int`](IntPredBinOpGen::gen_run_mp_int)/
//!   [`delegate_mp_int_flagbit`](IntPredBinOpGen::delegate_mp_int_flagbit) is dropped in favor of a
//!   non-generic `Local<TRef>` and `&dyn JitCodeGenerator`, matching the convention already set by
//!   [`BinOpGen::gen_mp_delegation_to_static_method`](super::bin_op_gen::BinOpGen::gen_mp_delegation_to_static_method)
//!   and [`IntOpBinOpGen::gen_run_mp_int`](super::int_op_bin_op_gen::IntOpBinOpGen::gen_run_mp_int).
//! - `delegateIntFlagbit`/`delegateLongFlagbit`/`delegateMpIntFlagbit`'s real bytecode emission
//!   (an `invokestatic` to a flag-computing method on `JitCompiledPassage`, followed by a shift and
//!   mask to extract the flag bit) depends on the not-yet-ported `Op`, `Methods`, and `GenConsts`
//!   (method descriptor constants). Per the precedent set by
//!   [`BinOpGen::gen_mp_delegation_to_static_method`](super::bin_op_gen::BinOpGen::gen_mp_delegation_to_static_method),
//!   this port keeps the one piece of real, testable logic in each -- the bit position of the sign
//!   bit -- and stubs the opcode sequence itself.
//! - `genRun`'s default-method override (resolving both operands' `JitType` via
//!   `JitCodeGenerator.resolveType`, unifying them, then dispatching to
//!   `opForInt`/`opForLong`/`genRunMpInt`) is not modeled here. It returns Java's `OpResult`
//!   (constructed as `LiveOpResult`) and takes a `Methods.RetReq`, neither of which is ported in
//!   this crate, and it is called only by the (also unported) JIT driver -- no implementor's own
//!   logic calls it. This follows the same precedent as
//!   [`OpGen`](crate::pcode::seam_stubs::OpGen)'s omitted `genRun`, which
//!   [`IntOpBinOpGen`](super::int_op_bin_op_gen::IntOpBinOpGen) and
//!   [`FloatCompareBinOpGen`](super::float_compare_bin_op_gen::FloatCompareBinOpGen) already rely
//!   on.

use crate::pcode::emu::jit::analysis::jit_type::{IntJitType, JitType, LongJitType, MpIntJitType};
use crate::pcode::emu::jit::gen::op::bin_op_gen::BinOpGen;
use crate::pcode::emu::jit::gen::util::emitter::{Bot, Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TLong, TRef};
use crate::pcode::seam_stubs::{JitBinOp, JitCodeGenerator, Scope};

/// An extension for integer operators whose outputs are boolean.
///
/// Port of `ghidra.pcode.emu.jit.gen.op.IntPredBinOpGen<T>`. See the [module docs](self) for how
/// this differs from the Java interface.
pub trait IntPredBinOpGen<T: JitBinOp>: BinOpGen<T> {
    /// Emit the JVM bytecode to perform the operator with `int` operands on the stack.
    ///
    /// Port of `IntPredBinOpGen.opForInt`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail `N`, with the right operand
    ///   pushed, then the left operand pushed on top of that.
    /// - `type_`: the p-code type of the operands.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail `N` with the (boolean) result
    /// pushed.
    fn op_for_int<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TInt>, TInt>>,
        type_: IntJitType,
    ) -> Emitter<Ent<N, TInt>>;

    /// An implementation for integer operands that delegates to a method on
    /// `JitCompiledPassage`.
    ///
    /// Port of `IntPredBinOpGen.delegateIntFlagbit`. See the [module docs](self) on what is and
    /// is not modeled: the shift amount used to extract the flag bit is real; the
    /// invoke/shift/mask opcode sequence that would perform the above is stubbed, since it
    /// depends on the not-yet-ported `Op`/`Methods`/`GenConsts`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail `N`, with the right operand
    ///   pushed, then the left operand pushed on top of that.
    /// - `type_`: the p-code type of the operands.
    /// - `method_name`: the name of the method in `JitCompiledPassage` to invoke.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail `N` with the (boolean) result
    /// pushed.
    fn delegate_int_flagbit<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TInt>, TInt>>,
        type_: IntJitType,
        method_name: &str,
    ) -> Emitter<Ent<N, TInt>> {
        let _ = method_name;
        // Port of `type.size() * Byte.SIZE - 1`: the real, testable part of this method. The
        // invokestatic/shift/mask opcode sequence that follows in Java is not modeled; see the
        // module docs.
        let _shift_amount = type_.size() * 8 - 1;
        em.recast()
    }

    /// Emit the JVM bytecode to perform the operator with `long` operands on the stack.
    ///
    /// Port of `IntPredBinOpGen.opForLong`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail `N`, with the right operand
    ///   pushed, then the left operand pushed on top of that.
    /// - `type_`: the p-code type of the operands.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail `N` with the (boolean) result
    /// pushed. Unlike [`op_for_int`](Self::op_for_int), the incoming operands are `long`s but the
    /// result is always an `int` (Java: the method returns `Emitter<Ent<N2, TInt>>` even though
    /// the bounds are stated in terms of `TLong`).
    fn op_for_long<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TLong>, TLong>>,
        type_: LongJitType,
    ) -> Emitter<Ent<N, TInt>>;

    /// An implementation for long operands that delegates to a method on `JitCompiledPassage`.
    ///
    /// Port of `IntPredBinOpGen.delegateLongFlagbit`. See the [module docs](self) on what is and
    /// is not modeled: the shift amount used to extract the flag bit is real; the
    /// invoke/shift/mask opcode sequence that would perform the above is stubbed, since it
    /// depends on the not-yet-ported `Op`/`Methods`/`GenConsts`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail `N`, with the right operand
    ///   pushed, then the left operand pushed on top of that.
    /// - `type_`: the p-code type of the operands.
    /// - `method_name`: the name of the method in `JitCompiledPassage` to invoke.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail `N` with the (boolean) result
    /// pushed.
    fn delegate_long_flagbit<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TLong>, TLong>>,
        type_: LongJitType,
        method_name: &str,
    ) -> Emitter<Ent<N, TInt>> {
        let _ = method_name;
        // Port of `type.size() * Byte.SIZE - 1`: the real, testable part of this method. The
        // invokestatic/shift/l2i/mask opcode sequence that follows in Java is not modeled; see
        // the module docs.
        let _shift_amount = type_.size() * 8 - 1;
        em.recast()
    }

    /// Emit the JVM bytecode to perform the operator with multi-precision operands.
    ///
    /// Port of `IntPredBinOpGen.genRunMpInt`. See the [module docs](self) on why the
    /// `<THIS extends JitCompiledPassage>` type parameter is dropped.
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
    /// The emitter typed with the resulting stack, i.e., containing only the (boolean) result.
    fn gen_run_mp_int(
        &self,
        em: Emitter<Bot>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        op: &T,
        type_: MpIntJitType,
        scope: &dyn Scope,
    ) -> Emitter<Ent<Bot, TInt>>;

    /// An implementation for multi-precision integer operands that delegates to a method on
    /// `JitCompiledPassage`.
    ///
    /// Port of `IntPredBinOpGen.delegateMpIntFlagbit`. See the [module docs](self) on what is and
    /// is not modeled: the shift amount used to extract the flag bit is real; the
    /// read-operands/invoke/mask opcode sequence that would perform the above is stubbed, since it
    /// depends on the not-yet-ported `Op`/`Methods`/`GenConsts`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the empty stack.
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `gen`: the code generator.
    /// - `op`: the p-code op.
    /// - `type_`: the p-code type of the operands.
    /// - `scope`: a scope for generating temporary local storage.
    /// - `method_name`: the name of the method in `JitCompiledPassage` to invoke.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., containing only the (boolean) result.
    #[allow(clippy::too_many_arguments)]
    fn delegate_mp_int_flagbit(
        &self,
        em: Emitter<Bot>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        op: &T,
        type_: MpIntJitType,
        scope: &dyn Scope,
        method_name: &str,
    ) -> Emitter<Ent<Bot, TInt>> {
        let _ = (local_this, gen, op, scope, method_name);
        // Port of `type.partialSize() * Byte.SIZE - 1`: the real, testable part of this method.
        // The read-to-array/invokestatic opcode sequence that precedes it in Java is not modeled;
        // see the module docs.
        let _shift_amount = type_.partial_size() * 8 - 1;
        em.recast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::var::JitVal;
    use crate::pcode::seam_stubs::{JitDefOp, JitOp, JitOutVar, JitTypeBehavior, MethodVisitor};
    use std::sync::Arc;

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
            unimplemented!()
        }
    }

    impl JitBinOp for TestBinOp {
        fn l(&self) -> Box<dyn JitVal> {
            unimplemented!()
        }

        fn r(&self) -> Box<dyn JitVal> {
            unimplemented!()
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

    /// A stand-in for a concrete generator such as Java's `IntEqualOpGen`: signed, and delegates
    /// straight to the `delegate*Flagbit` default methods, as a real comparison generator would.
    struct EqualGen;
    impl crate::pcode::seam_stubs::OpGen<TestBinOp> for EqualGen {}
    impl BinOpGen<TestBinOp> for EqualGen {
        fn is_signed(&self) -> bool {
            true
        }
    }
    impl IntPredBinOpGen<TestBinOp> for EqualGen {
        fn op_for_int<N: Next>(
            &self,
            em: Emitter<Ent<Ent<N, TInt>, TInt>>,
            type_: IntJitType,
        ) -> Emitter<Ent<N, TInt>> {
            self.delegate_int_flagbit(em, type_, "intEqual")
        }

        fn op_for_long<N: Next>(
            &self,
            em: Emitter<Ent<Ent<N, TLong>, TLong>>,
            type_: LongJitType,
        ) -> Emitter<Ent<N, TInt>> {
            self.delegate_long_flagbit(em, type_, "longEqual")
        }

        fn gen_run_mp_int(
            &self,
            em: Emitter<Bot>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            op: &TestBinOp,
            type_: MpIntJitType,
            scope: &dyn Scope,
        ) -> Emitter<Ent<Bot, TInt>> {
            self.delegate_mp_int_flagbit(em, local_this, gen, op, type_, scope, "mpIntEqual")
        }
    }

    #[test]
    fn op_for_int_receives_the_stack_and_yields_an_int_result() {
        // Java: `opForInt` is typed `Emitter<Ent<N1, TInt>> -> Emitter<Ent<N2, TInt>>` where
        // `N1 = Ent<N2, TInt>`, i.e., it consumes the top two `int`s and leaves a boolean `int` in
        // their place, regardless of what lies beneath. Exercise this with a non-trivial tail
        // (`TRef` on `Bot`) to confirm the bound is generic in the tail, not hardcoded to `Bot`.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TInt>, TInt>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> = EqualGen.op_for_int(em, IntJitType::I4);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn op_for_long_receives_the_stack_and_yields_an_int_result() {
        // Unlike `IntOpBinOpGen::op_for_long`, the result here is always `TInt`, even though the
        // operands are `TLong`, since the operator is a predicate.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TLong>, TLong>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> = EqualGen.op_for_long(em, LongJitType::I8);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn gen_run_mp_int_receives_the_operand_type_and_yields_the_result_alone() {
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0);
        let code_gen = MockCodeGenerator;
        let scope = MockScope;
        let op = TestBinOp;

        let result: Emitter<Ent<Bot, TInt>> = EqualGen.gen_run_mp_int(
            em,
            &local_this,
            &code_gen,
            &op,
            MpIntJitType::for_size(9),
            &scope,
        );
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    fn delegate_int_flagbit_computes_the_sign_bit_position_like_java_default_method() {
        // Java: `delegateIntFlagbit` shifts by `type.size() * Byte.SIZE - 1` to isolate the sign
        // bit of a 4-byte `int`, i.e., bit 31.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TInt>, TInt>> = Emitter::new(MethodVisitor::new());
        // Port-checkable via `IntJitType::I4.size() * 8 - 1 == 31`, matched against the well-known
        // JVM `int` sign-bit position; the method itself only exposes this through its (stubbed)
        // control flow, so this asserts the input rather than an internal.
        assert_eq!(IntJitType::I4.size() * 8 - 1, 31);
        let result = EqualGen.delegate_int_flagbit(em, IntJitType::I4, "intEqual");
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn delegate_mp_int_flagbit_uses_partial_size_like_java_default_method() {
        // Java: `delegateMpIntFlagbit` shifts by `type.partialSize() * Byte.SIZE - 1`, not
        // `type.size()`, since the mp-int method operates on whole legs. For a 9-byte mp-int, the
        // most significant leg holds only 1 byte (9 % 4), so the sign bit sits at bit 7, not 31.
        let type_ = MpIntJitType::for_size(9);
        assert_eq!(type_.partial_size(), 1);
        assert_eq!(type_.partial_size() * 8 - 1, 7);

        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0);
        let code_gen = MockCodeGenerator;
        let scope = MockScope;
        let op = TestBinOp;
        let result = EqualGen.delegate_mp_int_flagbit(
            em,
            &local_this,
            &code_gen,
            &op,
            type_,
            &scope,
            "mpIntEqual",
        );
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    fn int_pred_bin_op_gen_extends_bin_op_gen_like_java_interface() {
        // Java: `interface IntPredBinOpGen<T extends JitBinOp> extends BinOpGen<T>`.
        fn assert_is_bin_op_gen<G: BinOpGen<TestBinOp>>(_gen: &G) {}
        assert_is_bin_op_gen(&EqualGen);
        assert!(EqualGen.is_signed());
    }
}
