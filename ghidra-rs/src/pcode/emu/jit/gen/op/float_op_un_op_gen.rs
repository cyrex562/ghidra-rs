//! An extension for floating-point unary operators.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.FloatOpUnOpGen`.
//!
//! # Differences from Java
//!
//! - Java's `default boolean isSigned()` overrides the abstract `UnOpGen.isSigned()`. Rust cannot
//!   "override" a supertrait method by redeclaring it under the same name, so -- per the
//!   convention already set by
//!   [`IntBitwiseBinOpGen`](super::int_bitwise_bin_op_gen::IntBitwiseBinOpGen) -- it is exposed
//!   here under the distinct name
//!   [`float_op_un_op_gen_is_signed`](FloatOpUnOpGen::float_op_un_op_gen_is_signed). A concrete
//!   implementor's own `UnOpGen::is_signed` impl should delegate to it.
//! - Java's `<N1 extends Next, N0 extends Ent<N1, TFloat>>` pair of bounds on
//!   [`op_for_float`](FloatOpUnOpGen::op_for_float) (and the analogous `TDouble` pair on
//!   [`op_for_double`](FloatOpUnOpGen::op_for_double)) collapses to a single free parameter `N`,
//!   per the convention set by
//!   [`IntOpUnOpGen::op_for_int`](super::int_op_un_op_gen::IntOpUnOpGen::op_for_int): since
//!   [`Ent`] is a concrete Rust struct rather than a Java subtyping relationship, "a stack with a
//!   `TFloat` on top of tail `N`" is just `Emitter<Ent<N, TFloat>>` for a free `N`, without
//!   needing named intermediate bounds.
//! - `genRun`'s default-method override (resolving the operand's `JitType` via
//!   `JitCodeGenerator.resolveType`, then dispatching to `opForFloat`/`opForDouble`, or
//!   `Unfinished.TODO` for the not-yet-supported multi-precision float case) is not modeled here.
//!   It returns Java's `OpResult` (constructed as `LiveOpResult`) and takes a `Methods.RetReq`,
//!   neither of which is ported in this crate, and it is called only by the (also unported) JIT
//!   driver -- no implementor's own logic calls it. This follows the same precedent as
//!   [`OpGen`](crate::pcode::seam_stubs::OpGen)'s omitted `genRun`, which
//!   [`IntOpUnOpGen`](super::int_op_un_op_gen::IntOpUnOpGen) and
//!   [`IntExtUnOpGen`](super::int_ext_un_op_gen::IntExtUnOpGen) already rely on.

use crate::pcode::emu::jit::gen::op::un_op_gen::UnOpGen;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::types::{TDouble, TFloat};
use crate::pcode::emu::jit::op::jit_float_un_op::JitFloatUnOp;

/// An extension for floating-point unary operators.
///
/// Port of `ghidra.pcode.emu.jit.gen.op.FloatOpUnOpGen<T>`. See the [module docs](self) for how
/// this differs from the Java interface.
pub trait FloatOpUnOpGen<T: JitFloatUnOp>: UnOpGen<T> {
    /// Floating-point operators are never signed.
    ///
    /// Port of `FloatOpUnOpGen.isSigned`, which overrides `UnOpGen.isSigned`. See the
    /// [module docs](self) on why this is not named `is_signed`.
    fn float_op_un_op_gen_is_signed(&self) -> bool {
        false
    }

    /// Emit the JVM bytecode to perform the operator with a `float` operand on the stack.
    ///
    /// Port of `FloatOpUnOpGen.opForFloat`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail `N`, with the input operand
    ///   pushed on top.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail `N` with the result pushed.
    fn op_for_float<N: Next>(&self, em: Emitter<Ent<N, TFloat>>) -> Emitter<Ent<N, TFloat>>;

    /// Emit the JVM bytecode to perform the operator with a `double` operand on the stack.
    ///
    /// Port of `FloatOpUnOpGen.opForDouble`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail `N`, with the input operand
    ///   pushed on top.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail `N` with the result pushed.
    fn op_for_double<N: Next>(&self, em: Emitter<Ent<N, TDouble>>) -> Emitter<Ent<N, TDouble>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::emu::jit::gen::util::types::TRef;
    use crate::pcode::emu::jit::op::{JitDefOp, JitOp};
    use crate::pcode::emu::jit::var::JitVal;
    use crate::pcode::seam_stubs::{Ext, JitOutVar, JitTypeBehavior, MethodVisitor, OpGen};
    use std::sync::Arc;

    struct TestFloatUnOp;

    impl JitOp for TestFloatUnOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Float
        }

        fn link(&self) {}

        fn unlink(&self) {}
    }

    impl JitDefOp for TestFloatUnOp {
        fn out(&self) -> Arc<dyn JitOutVar> {
            unimplemented!()
        }
    }

    impl crate::pcode::emu::jit::op::jit_un_op::JitUnOp for TestFloatUnOp {
        fn u(&self) -> Arc<dyn JitVal> {
            unimplemented!()
        }

        fn u_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Float
        }
    }

    impl JitFloatUnOp for TestFloatUnOp {}

    /// A stand-in for a concrete generator such as Java's `FloatNegOpGen`, wiring `UnOpGen`'s
    /// abstract `is_signed` to the `float_op_un_op_gen_is_signed` override, per the
    /// [module docs](super).
    struct NegGen;
    impl OpGen<TestFloatUnOp> for NegGen {}
    impl UnOpGen<TestFloatUnOp> for NegGen {
        fn is_signed(&self) -> bool {
            self.float_op_un_op_gen_is_signed()
        }
    }
    impl FloatOpUnOpGen<TestFloatUnOp> for NegGen {
        fn op_for_float<N: Next>(&self, em: Emitter<Ent<N, TFloat>>) -> Emitter<Ent<N, TFloat>> {
            em
        }

        fn op_for_double<N: Next>(
            &self,
            em: Emitter<Ent<N, TDouble>>,
        ) -> Emitter<Ent<N, TDouble>> {
            em
        }
    }

    #[test]
    fn is_signed_is_false_like_java_default_method() {
        // Java: `FloatOpUnOpGen.isSigned()` unconditionally returns `false`, regardless of the
        // underlying floating-point operator.
        assert!(!NegGen.float_op_un_op_gen_is_signed());
        assert!(!UnOpGen::is_signed(&NegGen));
    }

    #[test]
    fn ext_is_zero_since_float_ops_are_unsigned() {
        // Java: `ext()` is `UnOpGen`'s default, computed from `isSigned()`; since
        // `FloatOpUnOpGen` hardcodes `isSigned() == false`, the extension is always
        // zero-extension, even though this generator's `is_signed` override forwards to it.
        assert_eq!(NegGen.ext(), Ext::Zero);
    }

    #[test]
    fn op_for_float_receives_the_stack_and_preserves_its_tail() {
        // Java: `opForFloat` is typed `Emitter<Ent<N1, TFloat>> -> Emitter<Ent<N1, TFloat>>`,
        // i.e., it replaces the top `float` in place, regardless of what lies beneath. Exercise
        // this with a non-trivial tail (`TRef` on `Bot`) to confirm the bound is generic in the
        // tail, not hardcoded to `Bot`.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Tail, TFloat>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TFloat>> = NegGen.op_for_float(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn op_for_double_receives_the_stack_and_preserves_its_tail() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Tail, TDouble>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TDouble>> = NegGen.op_for_double(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn float_op_un_op_gen_extends_un_op_gen_like_java_interface() {
        // Java: `interface FloatOpUnOpGen<T extends JitFloatUnOp> extends UnOpGen<T>`.
        fn assert_is_un_op_gen<G: UnOpGen<TestFloatUnOp>>(_gen: &G) {}
        assert_is_un_op_gen(&NegGen);
        assert!(!NegGen.is_signed());
    }
}
