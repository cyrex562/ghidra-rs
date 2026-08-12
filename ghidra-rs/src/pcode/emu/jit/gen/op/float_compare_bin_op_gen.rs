//! An extension for float comparison operators.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.FloatCompareBinOpGen`.
//!
//! # Differences from Java
//!
//! - Java's `default boolean isSigned()` overrides the abstract `BinOpGen.isSigned()`. Rust cannot
//!   "override" a supertrait method by redeclaring it under the same name, so -- per the
//!   convention already set by
//!   [`FloatOpBinOpGen`](super::float_op_bin_op_gen::FloatOpBinOpGen) -- it is exposed here under
//!   the distinct name
//!   [`float_compare_bin_op_gen_is_signed`](FloatCompareBinOpGen::float_compare_bin_op_gen_is_signed).
//!   A concrete implementor's own `BinOpGen::is_signed` impl should delegate to it.
//! - Java's `<N2 extends Next, N1 extends Ent<N2, TFloat>, N0 extends Ent<N1, TFloat>>` triple of
//!   bounds on [`op_for_float_cmp`](FloatCompareBinOpGen::op_for_float_cmp) (and the analogous
//!   `TDouble` triple on [`op_for_double_cmp`](FloatCompareBinOpGen::op_for_double_cmp)) collapses
//!   to a single free parameter `N`, per the convention set by
//!   [`IntOpBinOpGen`](super::int_op_bin_op_gen::IntOpBinOpGen): since [`Ent`] is a concrete Rust
//!   struct rather than a Java subtyping relationship, "a stack with two `TFloat`s on top" is just
//!   `Emitter<Ent<Ent<N, TFloat>, TFloat>>` for a free `N`, without needing named intermediate
//!   bounds. Likewise, Java's `<N1 extends Next, N0 extends Ent<N1, TInt>>` on
//!   [`op_for_cond_jump`](FloatCompareBinOpGen::op_for_cond_jump) collapses to a single free `N`.
//! - `genRun`'s default-method override (resolving both operands' `JitType` via
//!   `JitCodeGenerator.resolveType`, asserting they match, then dispatching to
//!   `opForFloatCmp`/`opForDoubleCmp` followed by `opForCondJump`, or `Unfinished.TODO` for the
//!   not-yet-supported multi-precision float case) is not modeled here. It returns Java's
//!   `OpResult` (constructed as `LiveOpResult`) and takes a `Methods.RetReq`, neither of which is
//!   ported in this crate, and it is called only by the (also unported) JIT driver -- no
//!   implementor's own logic calls it. This follows the same precedent as
//!   [`OpGen`](crate::pcode::seam_stubs::OpGen)'s omitted `genRun`, which
//!   [`FloatOpBinOpGen`](super::float_op_bin_op_gen::FloatOpBinOpGen) already relies on.

use crate::pcode::emu::jit::gen::op::bin_op_gen::BinOpGen;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::lbl::LblEm;
use crate::pcode::emu::jit::gen::util::types::{TDouble, TFloat, TInt};
use crate::pcode::emu::jit::op::JitFloatTestOp;

/// An extension for float comparison operators.
///
/// Port of `ghidra.pcode.emu.jit.gen.op.FloatCompareBinOpGen<T>`. See the [module docs](self) for
/// how this differs from the Java interface.
pub trait FloatCompareBinOpGen<T: JitFloatTestOp>: BinOpGen<T> {
    /// Float comparison operators are never signed.
    ///
    /// Port of `FloatCompareBinOpGen.isSigned`, which overrides `BinOpGen.isSigned`. See the
    /// [module docs](self) on why this is not named `is_signed`.
    fn float_compare_bin_op_gen_is_signed(&self) -> bool {
        false
    }

    /// Emit the JVM bytecode to perform the comparison with `float` operands on the stack.
    ///
    /// The result should be as defined by `Comparator.compare(Object, Object)`.
    ///
    /// Port of `FloatCompareBinOpGen.opForFloatCmp`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail `N`, with the right operand
    ///   pushed, then the left operand pushed on top of that.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail `N` with the comparison result
    /// pushed.
    fn op_for_float_cmp<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TFloat>, TFloat>>,
    ) -> Emitter<Ent<N, TInt>>;

    /// Emit the JVM bytecode to perform the comparison with `double` operands on the stack.
    ///
    /// The result should be as defined by `Comparator.compare(Object, Object)`.
    ///
    /// Port of `FloatCompareBinOpGen.opForDoubleCmp`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail `N`, with the right operand
    ///   pushed, then the left operand pushed on top of that.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail `N` with the comparison result
    /// pushed.
    fn op_for_double_cmp<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TDouble>, TDouble>>,
    ) -> Emitter<Ent<N, TInt>>;

    /// Emit the JVM opcode to perform the conditional jump.
    ///
    /// The condition should correspond to the true case of the p-code operator.
    ///
    /// Port of `FloatCompareBinOpGen.opForCondJump`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail `N`, with the comparison
    ///   result pushed.
    ///
    /// # Returns
    ///
    /// The target label and emitter typed with the resulting stack, i.e., with the comparison
    /// result popped, leaving just the tail `N`.
    fn op_for_cond_jump<N: Next>(&self, em: Emitter<Ent<N, TInt>>) -> LblEm<N, N>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::emu::jit::gen::util::types::TRef;
    use crate::pcode::emu::jit::op::{JitDefOp, JitFloatBinOp, JitOp};
    use crate::pcode::emu::jit::var::JitVal;
    use crate::pcode::seam_stubs::{Ext, JitBinOp, JitOutVar, JitTypeBehavior, MethodVisitor, OpGen};
    use std::sync::Arc;

    struct TestFloatTestOp;

    impl JitOp for TestFloatTestOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Float
        }

        fn link(&self) {}

        fn unlink(&self) {}
    }

    impl JitDefOp for TestFloatTestOp {
        fn out(&self) -> Arc<dyn JitOutVar> {
            unimplemented!()
        }
    }

    impl JitBinOp for TestFloatTestOp {
        fn l(&self) -> Box<dyn JitVal> {
            unimplemented!()
        }

        fn r(&self) -> Box<dyn JitVal> {
            unimplemented!()
        }

        fn l_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Float
        }

        fn r_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Float
        }
    }

    impl JitFloatBinOp for TestFloatTestOp {}

    impl JitFloatTestOp for TestFloatTestOp {}

    /// A stand-in for a concrete generator such as Java's `FloatLessOpGen`, wiring `BinOpGen`'s
    /// abstract `is_signed` to the `float_compare_bin_op_gen_is_signed` override, per the
    /// [module docs](super).
    struct LessGen;
    impl OpGen<TestFloatTestOp> for LessGen {}
    impl BinOpGen<TestFloatTestOp> for LessGen {
        fn is_signed(&self) -> bool {
            self.float_compare_bin_op_gen_is_signed()
        }
    }
    impl FloatCompareBinOpGen<TestFloatTestOp> for LessGen {
        fn op_for_float_cmp<N: Next>(
            &self,
            em: Emitter<Ent<Ent<N, TFloat>, TFloat>>,
        ) -> Emitter<Ent<N, TInt>> {
            em.recast()
        }

        fn op_for_double_cmp<N: Next>(
            &self,
            em: Emitter<Ent<Ent<N, TDouble>, TDouble>>,
        ) -> Emitter<Ent<N, TInt>> {
            em.recast()
        }

        fn op_for_cond_jump<N: Next>(&self, em: Emitter<Ent<N, TInt>>) -> LblEm<N, N> {
            crate::pcode::emu::jit::gen::util::lbl::Lbl::place(em.recast())
        }
    }

    #[test]
    fn is_signed_is_false_like_java_default_method() {
        // Java: `FloatCompareBinOpGen.isSigned()` unconditionally returns `false`, regardless of
        // the underlying comparison operator.
        assert!(!LessGen.float_compare_bin_op_gen_is_signed());
        assert!(!BinOpGen::is_signed(&LessGen));
    }

    #[test]
    fn ext_is_zero_since_float_ops_are_unsigned() {
        // Java: `ext()` is `BinOpGen`'s default, computed from `isSigned()`; since
        // `FloatCompareBinOpGen` hardcodes `isSigned() == false`, the extension is always
        // zero-extension, even though this generator's `is_signed` override forwards to it.
        assert_eq!(LessGen.ext(), Ext::Zero);
        assert_eq!(LessGen.r_ext(), Ext::Zero);
    }

    #[test]
    fn op_for_float_cmp_receives_the_stack_and_yields_an_int_result() {
        // Java: `opForFloatCmp` is typed `Emitter<Ent<N1, TFloat>> -> Emitter<Ent<N2, TInt>>`
        // where `N1 = Ent<N2, TFloat>`, i.e., it consumes the top two `float`s and leaves a
        // comparison `int` in their place, regardless of what lies beneath. Exercise this with a
        // non-trivial tail (`TRef` on `Bot`) to confirm the bound is generic in the tail, not
        // hardcoded to `Bot`.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TFloat>, TFloat>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> = LessGen.op_for_float_cmp(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn op_for_double_cmp_receives_the_stack_and_yields_an_int_result() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TDouble>, TDouble>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> = LessGen.op_for_double_cmp(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn op_for_cond_jump_pops_the_comparison_result_leaving_the_tail() {
        // Java: `opForCondJump` is typed `Emitter<Ent<N1, TInt>> -> LblEm<N1, N1>`, i.e., it
        // consumes the top `int` (the comparison result) and yields a label and emitter typed
        // with just the tail.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Tail, TInt>> = Emitter::new(MethodVisitor::new());
        let LblEm { em: result, .. } = LessGen.op_for_cond_jump(em);
        let _: Emitter<Tail> = result;
    }

    #[test]
    fn float_compare_bin_op_gen_extends_bin_op_gen_like_java_interface() {
        // Java: `interface FloatCompareBinOpGen<T extends JitFloatTestOp> extends BinOpGen<T>`.
        fn assert_is_bin_op_gen<G: BinOpGen<TestFloatTestOp>>(_gen: &G) {}
        assert_is_bin_op_gen(&LessGen);
        assert!(!LessGen.is_signed());
    }
}
