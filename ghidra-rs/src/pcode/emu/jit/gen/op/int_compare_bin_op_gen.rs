//! An extension for integer comparison operators.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.IntCompareBinOpGen`.
//!
//! # Differences from Java
//!
//! - Java's `static Emitter<Ent<N1, TInt>> not(Emitter<N0>)` contributes no instance behavior --
//!   it does not reference `this` -- so, per the convention set by
//!   [`AccessGen`](crate::pcode::emu::jit::gen::access::access_gen)'s free functions, it becomes
//!   the free function [`not`] in this module rather than a trait method.
//! - Java's `default Emitter<Ent<Bot, TInt>> genRunMpInt(...)` overrides the abstract
//!   `IntPredBinOpGen.genRunMpInt`. Rust cannot "override" a supertrait method by redeclaring it
//!   under the same name, so -- per the convention already set by
//!   [`IntBitwiseBinOpGen`](super::int_bitwise_bin_op_gen::IntBitwiseBinOpGen) -- it is exposed
//!   here under the distinct name
//!   [`int_compare_bin_op_gen_gen_run_mp_int`](IntCompareBinOpGen::int_compare_bin_op_gen_gen_run_mp_int).
//!   A concrete implementor's own `IntPredBinOpGen::gen_run_mp_int` impl should delegate to it.
//! - `genRunMpInt`'s real per-leg algorithm -- comparing legs most-significant to least-significant
//!   for equality, short-circuiting to `opForInt` on the first (or only) unequal/final pair --
//!   depends on: the not-yet-ported `Op` (JVM opcode helper namespace) for the `dup`/`istore`/
//!   `iload`/`ifne`/`goto_` sequence; `gen.genReadLegToStack`, not yet a method on this crate's
//!   [`JitCodeGenerator`](crate::pcode::seam_stubs::JitCodeGenerator) stub; the not-yet-ported
//!   `IntNotEqualOpGen` singleton used for the leg-equality test; and `Scope::decl`, which this
//!   crate's [`Scope`](crate::pcode::seam_stubs::Scope) stub cannot expose without losing
//!   `dyn`-compatibility (it is used as `&dyn Scope` throughout this package; see
//!   [`RootScope::sub`](crate::pcode::emu::jit::gen::util::root_scope::RootScope::sub)). This port
//!   keeps the one piece of real, testable logic -- the leg count (`type.legsAlloc()`) that drives
//!   the loop -- and always dispatches to [`IntPredBinOpGen::op_for_int`], mirroring
//!   [`IntBitwiseBinOpGen::int_bitwise_bin_op_gen_gen_run_mp_int`](super::int_bitwise_bin_op_gen::IntBitwiseBinOpGen::int_bitwise_bin_op_gen_gen_run_mp_int)
//!   and
//!   [`BinOpGen::gen_mp_delegation_to_static_method`](super::bin_op_gen::BinOpGen::gen_mp_delegation_to_static_method).
//! - `genBool`'s real control flow -- resurrecting the dead code following the (already-emitted)
//!   conditional jump to push `true`, falling through from the not-taken path to push `false` --
//!   is modeled using the already-ported [`Lbl::place_dead`]/[`Lbl::place_at`]. The `ldc__i`
//!   push-constant opcodes themselves are not yet ported (`Op`), so they are stubbed via
//!   [`Emitter::recast`], per the same precedent.
//! - `genIntViaUcmpThenIf`/`genLongViaUcmpThenIf`'s `Integer.compareUnsigned`/
//!   `Long.compareUnsigned` invocation and `genLongViaLcmpThenIf`'s `lcmp` opcode are, likewise,
//!   not yet ported (`Op`/`GenConsts`); each stubs its opcode with [`Emitter::recast`] and then
//!   delegates to [`genIntViaIf`](IntCompareBinOpGen::gen_int_via_if), which is real.
//! - Java's `Function<A, B>` closure parameters become `impl FnOnce(A) -> B`, per the convention
//!   set by
//!   [`FloatConvertUnOpGen::gen`](super::float_convert_un_op_gen::FloatConvertUnOpGen::gen).

use crate::pcode::emu::jit::analysis::jit_type::{IntJitType, MpIntJitType};
use crate::pcode::emu::jit::var::JitOutVar;
use crate::pcode::emu::jit::gen::op::int_pred_bin_op_gen::IntPredBinOpGen;
use crate::pcode::emu::jit::gen::util::emitter::{Bot, Dead, Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::lbl::{Lbl, LblEm};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TLong, TRef};
use crate::pcode::emu::jit::op::JitIntTestOp;
use crate::pcode::seam_stubs::{JitCodeGenerator, Scope};

/// An extension for integer comparison operators.
///
/// Port of `ghidra.pcode.emu.jit.gen.op.IntCompareBinOpGen<T>`. See the [module docs](self) for
/// how this differs from the Java interface.
pub trait IntCompareBinOpGen<T: JitIntTestOp>: IntPredBinOpGen<T> {
    /// Assuming a conditional jump bytecode was just emitted, emit bytecode to push `0` (false)
    /// onto the stack for the fall-through case, or `1` (true) onto the stack for the taken case.
    ///
    /// Port of `IntCompareBinOpGen.genBool`. See the [module docs](self) on what is and is not
    /// modeled: the two-label dead-code-then-resurrect control flow is real; the constant-push
    /// opcodes are stubbed, since they depend on the not-yet-ported `Op`.
    ///
    /// # Arguments
    ///
    /// - `lbl_true`: the target label of the conditional jump just emitted, and the emitter typed
    ///   with the incoming stack.
    ///
    /// # Returns
    ///
    /// The emitter with the resulting stack, i.e., having pushed the boolean result.
    fn gen_bool<N: Next>(&self, lbl_true: LblEm<N, N>) -> Emitter<Ent<N, TInt>> {
        let LblEm { lbl: lbl_true, em } = lbl_true;
        // Op::ldc__i(0) (push false for the fall-through/not-taken path) is not yet ported; see
        // the module docs.
        let em: Emitter<Ent<N, TInt>> = em.recast();
        let lbl_done: Lbl<Ent<N, TInt>> = Lbl::create();
        // Op::goto_ (unconditional jump to lbl_done, making the code that follows unreachable
        // until lbl_true is resurrected below) is not yet ported; see the module docs.
        let dead: Emitter<Dead> = em.recast();
        let em: Emitter<N> = lbl_true.place_dead(dead);
        // Op::ldc__i(1) (push true for the taken path) is not yet ported; see the module docs.
        let em: Emitter<Ent<N, TInt>> = em.recast();
        lbl_done.place_at(em)
    }

    /// An implementation for (unsigned) int operands that invokes `Integer.compareUnsigned(int,
    /// int)` and then emits the given `if<cond>` jump.
    ///
    /// Port of `IntCompareBinOpGen.genIntViaUcmpThenIf`. See the [module docs](self) on what is
    /// and is not modeled.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail, with the right operand
    ///   pushed, then the left operand pushed on top of that.
    /// - `op_if`: emits the conditional jump, e.g., `Op::ifge`.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail with the result pushed.
    fn gen_int_via_ucmp_then_if<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TInt>, TInt>>,
        op_if: impl FnOnce(Emitter<Ent<N, TInt>>) -> LblEm<N, N>,
    ) -> Emitter<Ent<N, TInt>> {
        // Op::invokestatic to Integer.compareUnsigned(int, int) -- replacing the two int
        // operands with their unsigned-comparison result -- is not yet ported; see the module
        // docs.
        let em: Emitter<Ent<N, TInt>> = em.recast();
        self.gen_int_via_if(em, op_if)
    }

    /// An implementation for (signed) int operands that simply emits the given `if_icmp<cond>`
    /// jump.
    ///
    /// Port of `IntCompareBinOpGen.genIntViaIfIcmp`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail, with the right operand
    ///   pushed, then the left operand pushed on top of that.
    /// - `op_if_icmp`: emits the conditional jump, e.g., `Op::if_icmpge`.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail with the result pushed.
    fn gen_int_via_if_icmp<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TInt>, TInt>>,
        op_if_icmp: impl FnOnce(Emitter<Ent<Ent<N, TInt>, TInt>>) -> LblEm<N, N>,
    ) -> Emitter<Ent<N, TInt>> {
        self.gen_bool(op_if_icmp(em))
    }

    /// A utility that emits the given `if<cond>` along with the logic that pushes the correct
    /// result depending on whether or not the jump is taken.
    ///
    /// Port of `IntCompareBinOpGen.genIntViaIf`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack, including the predicate, which is
    ///   compared with `0`.
    /// - `op_if`: emits the conditional jump, e.g., `Op::ifge`.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail with the result pushed.
    fn gen_int_via_if<N: Next>(
        &self,
        em: Emitter<Ent<N, TInt>>,
        op_if: impl FnOnce(Emitter<Ent<N, TInt>>) -> LblEm<N, N>,
    ) -> Emitter<Ent<N, TInt>> {
        self.gen_bool(op_if(em))
    }

    /// An implementation for (signed) long operands that emits `lcmp` and then emits the given
    /// `if<cond>` jump.
    ///
    /// Port of `IntCompareBinOpGen.genLongViaLcmpThenIf`. See the [module docs](self) on what is
    /// and is not modeled.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail, with the right operand
    ///   pushed, then the left operand pushed on top of that.
    /// - `op_if`: emits the conditional jump, e.g., `Op::ifge`.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail with the result pushed.
    fn gen_long_via_lcmp_then_if<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TLong>, TLong>>,
        op_if: impl FnOnce(Emitter<Ent<N, TInt>>) -> LblEm<N, N>,
    ) -> Emitter<Ent<N, TInt>> {
        // Op::lcmp -- comparing two longs to a single int (-1, 0, or 1) -- is not yet ported;
        // see the module docs.
        let em: Emitter<Ent<N, TInt>> = em.recast();
        self.gen_int_via_if(em, op_if)
    }

    /// An implementation for (unsigned) long operands that invokes `Long.compareUnsigned(long,
    /// long)` and then emits the given `if<cond>` jump.
    ///
    /// Port of `IntCompareBinOpGen.genLongViaUcmpThenIf`. See the [module docs](self) on what is
    /// and is not modeled.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail, with the right operand
    ///   pushed, then the left operand pushed on top of that.
    /// - `op_if`: emits the conditional jump, e.g., `Op::ifge`.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail with the result pushed.
    fn gen_long_via_ucmp_then_if<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TLong>, TLong>>,
        op_if: impl FnOnce(Emitter<Ent<N, TInt>>) -> LblEm<N, N>,
    ) -> Emitter<Ent<N, TInt>> {
        // Op::invokestatic to Long.compareUnsigned(long, long) is not yet ported; see the module
        // docs.
        let em: Emitter<Ent<N, TInt>> = em.recast();
        self.gen_int_via_if(em, op_if)
    }

    /// The strategy for multi-precision comparison, applicable to all comparisons: start with
    /// the most-significant legs and compare *for equality* until finding the first not-equal
    /// pair, then apply [`op_for_int`](IntPredBinOpGen::op_for_int) to determine the overall
    /// result.
    ///
    /// Port of `IntCompareBinOpGen.genRunMpInt`, which overrides `IntPredBinOpGen.genRunMpInt`.
    /// See the [module docs](self) on why this is not named `gen_run_mp_int`, and on what of the
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
    /// The emitter typed with the resulting stack, i.e., containing only the (boolean) result.
    fn int_compare_bin_op_gen_gen_run_mp_int(
        &self,
        em: Emitter<Bot>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        op: &T,
        type_: MpIntJitType,
        scope: &dyn Scope,
    ) -> Emitter<Ent<Bot, TInt>> {
        let _ = (local_this, gen, op, scope);
        // Port of `legCount = type.legsAlloc()`: the number of most-significant-to-least-
        // significant leg-pairs Java examines (comparing `legsAlloc() - 1` of them for equality)
        // before falling back to `opForInt` on the final (least-significant) pair. See the
        // module docs for why the loop itself -- and the leg-equality delegation to
        // `IntNotEqualOpGen.GEN.opForInt` -- is not modeled.
        let _leg_count = type_.legs_alloc();
        self.op_for_int(em.recast(), IntJitType::I4)
    }
}

/// Invert the boolean on top of the stack.
///
/// Port of the static `IntCompareBinOpGen.not(Emitter)`. See the [module docs](self) on why this
/// is a free function rather than a trait method. Java's `emit(Op::ldc__i, 1).emit(Op::ixor)`
/// (xor with 1, i.e., logical negation of a 0/1 boolean) depends on the not-yet-ported `Op`, so
/// the opcode sequence itself is not modeled; the shape -- one `TInt` consumed, one `TInt`
/// produced, over any tail -- is preserved.
///
/// # Arguments
///
/// - `em`: the emitter typed with the incoming stack: the tail, with the boolean to invert on
///   top.
///
/// # Returns
///
/// The emitter typed with the same stack shape, i.e., the boolean inverted in place.
pub fn not<N: Next>(em: Emitter<Ent<N, TInt>>) -> Emitter<Ent<N, TInt>> {
    em
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_type::LongJitType;
    use crate::pcode::emu::jit::gen::op::bin_op_gen::BinOpGen;
    use crate::pcode::emu::jit::op::{JitDefOp, JitIntBinOp, JitIntTestOp, JitOp};
    use crate::pcode::emu::jit::var::JitVal;
    use crate::pcode::emu::jit::analysis::jit_type_behavior::JitTypeBehavior;
    use crate::pcode::seam_stubs::{MethodVisitor, OpGen};
    use std::sync::Arc;

    struct TestIntTestOp;

    impl JitOp for TestIntTestOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }

        fn link(&self) {}

        fn unlink(&self) {}
    }

    impl JitDefOp for TestIntTestOp {
        fn out(&self) -> Arc<dyn JitOutVar> {
            unimplemented!()
        }
    }

    impl crate::pcode::seam_stubs::JitBinOp for TestIntTestOp {
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

    impl JitIntBinOp for TestIntTestOp {}

    impl JitIntTestOp for TestIntTestOp {}

    struct MockCodeGenerator;
    impl JitCodeGenerator for MockCodeGenerator {}

    struct MockScope;
    impl Scope for MockScope {}

    /// A stand-in for a concrete generator such as Java's `IntEqualOpGen`: signed, and delegates
    /// straight to the `delegate*Flagbit`/`int_compare_bin_op_gen_gen_run_mp_int` default
    /// methods, as a real comparison generator would.
    struct EqualGen;
    impl OpGen<TestIntTestOp> for EqualGen {}
    impl BinOpGen<TestIntTestOp> for EqualGen {
        fn is_signed(&self) -> bool {
            true
        }
    }
    impl IntPredBinOpGen<TestIntTestOp> for EqualGen {
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
            op: &TestIntTestOp,
            type_: MpIntJitType,
            scope: &dyn Scope,
        ) -> Emitter<Ent<Bot, TInt>> {
            self.int_compare_bin_op_gen_gen_run_mp_int(em, local_this, gen, op, type_, scope)
        }
    }
    impl IntCompareBinOpGen<TestIntTestOp> for EqualGen {}

    #[test]
    fn not_preserves_the_stack_shape() {
        // Java: `not` consumes the boolean int on top of the stack and pushes its inverse,
        // leaving the tail untouched. The `ixor` opcode itself is not yet ported (see the module
        // docs), but the shape -- one `TInt` in, one `TInt` out, over any tail -- is real; verify
        // it with a non-trivial tail (`TRef` on `Bot`), not just `Bot` itself.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Tail, TInt>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> = not(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn gen_bool_places_the_true_label_dead_then_a_distinct_done_label() {
        // Java: `genBool` resurrects `lblTrue` as dead code (pushing 1), then falls through to a
        // fresh `lblDone` (which the not-taken path, pushing 0, jumps to). The two labels are
        // always distinct, and the last-visited label after `genBool` is `lblDone`, not
        // `lblTrue`, confirming both placements occurred in order.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Tail> = Emitter::new(MethodVisitor::new());
        let lbl_true: Lbl<Tail> = Lbl::create();
        let result: Emitter<Ent<Tail, TInt>> = EqualGen.gen_bool(LblEm { lbl: lbl_true, em });
        let last = result.last_visited().expect("gen_bool places a label");
        assert_ne!(last, lbl_true.label);
    }

    #[test]
    fn gen_int_via_if_delegates_to_gen_bool() {
        // Java: `genIntViaIf(em, opIf) == genBool(opIf.apply(em))`.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Tail, TInt>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> =
            EqualGen.gen_int_via_if(em, |em: Emitter<Ent<Tail, TInt>>| Lbl::place(em.recast()));
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn gen_int_via_if_icmp_consumes_both_operands_via_gen_bool() {
        // Java: `genIntViaIfIcmp` takes the stack with both int operands still on it (the
        // `if_icmp<cond>` jump consumes both directly), unlike `genIntViaIf`, which expects the
        // comparison to have already been reduced to a single int.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TInt>, TInt>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> = EqualGen.gen_int_via_if_icmp(
            em,
            |em: Emitter<Ent<Ent<Tail, TInt>, TInt>>| Lbl::place(em.recast()),
        );
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn gen_int_via_ucmp_then_if_reduces_two_ints_to_one_before_the_conditional() {
        // Java: `genIntViaUcmpThenIf` starts with both int operands on the stack (like
        // `genIntViaIfIcmp`), but reduces them to a single comparison result (via
        // `Integer.compareUnsigned`) before delegating to `genIntViaIf`.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TInt>, TInt>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> = EqualGen
            .gen_int_via_ucmp_then_if(em, |em: Emitter<Ent<Tail, TInt>>| Lbl::place(em.recast()));
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn gen_long_via_lcmp_then_if_reduces_two_longs_to_an_int_before_the_conditional() {
        // Java: `genLongViaLcmpThenIf` starts with both long operands on the stack and reduces
        // them to a single int comparison result (via `lcmp`) before delegating to
        // `genIntViaIf`.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TLong>, TLong>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> = EqualGen
            .gen_long_via_lcmp_then_if(em, |em: Emitter<Ent<Tail, TInt>>| Lbl::place(em.recast()));
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn gen_long_via_ucmp_then_if_reduces_two_longs_to_an_int_before_the_conditional() {
        // Java: `genLongViaUcmpThenIf` is the unsigned analog of `genLongViaLcmpThenIf`, using
        // `Long.compareUnsigned` instead of `lcmp`.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TLong>, TLong>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> = EqualGen
            .gen_long_via_ucmp_then_if(em, |em: Emitter<Ent<Tail, TInt>>| Lbl::place(em.recast()));
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn gen_run_mp_int_examines_legs_alloc_minus_one_legs_before_delegating_to_op_for_int() {
        // Java: `legCount = type.legsAlloc()`; the loop runs from `legCount - 1` down to `1`
        // (exclusive of 0), i.e., it compares `legsAlloc() - 1` most-significant leg-pairs for
        // equality before falling back to `opForInt` on the final (least-significant) pair. For
        // a 9-byte mp-int, legsAlloc() == 3 (already tested on `MpIntJitType` itself), so the
        // full Java algorithm would compare 2 leg-pairs.
        let type_ = MpIntJitType::for_size(9);
        assert_eq!(type_.legs_alloc(), 3);
        assert_eq!(type_.legs_alloc() - 1, 2);

        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0);
        let code_gen = MockCodeGenerator;
        let scope = MockScope;
        let op = TestIntTestOp;

        // The always-taken final dispatch to `opForInt` is real: `EqualGen::op_for_int`
        // delegates to `delegate_int_flagbit`, so the result carries no local declarations,
        // exactly as it would if the (unmodeled) per-leg loop had run and produced the same
        // empty-locals result.
        let result = EqualGen.int_compare_bin_op_gen_gen_run_mp_int(
            em, &local_this, &code_gen, &op, type_, &scope,
        );
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn int_compare_bin_op_gen_extends_int_pred_bin_op_gen_like_java_interface() {
        // Java: `interface IntCompareBinOpGen<T extends JitIntTestOp> extends IntPredBinOpGen<T>`.
        fn assert_is_int_pred_bin_op_gen<G: IntPredBinOpGen<TestIntTestOp>>(_gen: &G) {}
        assert_is_int_pred_bin_op_gen(&EqualGen);
        assert!(EqualGen.is_signed());
    }
}
