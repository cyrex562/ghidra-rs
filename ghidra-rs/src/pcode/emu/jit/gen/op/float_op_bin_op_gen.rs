//! An extension for floating-point binary operators.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.FloatOpBinOpGen`.
//!
//! # Differences from Java
//!
//! - Java's `default boolean isSigned()` overrides the abstract `BinOpGen.isSigned()`. Rust cannot
//!   "override" a supertrait method by redeclaring it under the same name, so -- per the
//!   convention already set by
//!   [`FloatOpUnOpGen`](super::float_op_un_op_gen::FloatOpUnOpGen) -- it is exposed here under the
//!   distinct name
//!   [`float_op_bin_op_gen_is_signed`](FloatOpBinOpGen::float_op_bin_op_gen_is_signed). A concrete
//!   implementor's own `BinOpGen::is_signed` impl should delegate to it.
//! - Java's `<N2 extends Next, N1 extends Ent<N2, TFloat>, N0 extends Ent<N1, TFloat>>` triple of
//!   bounds on [`op_for_float`](FloatOpBinOpGen::op_for_float) (and the analogous `TDouble` triple
//!   on [`op_for_double`](FloatOpBinOpGen::op_for_double)) collapses to a single free parameter
//!   `N`, per the convention set by
//!   [`IntOpBinOpGen`](super::int_op_bin_op_gen::IntOpBinOpGen): since [`Ent`] is a concrete Rust
//!   struct rather than a Java subtyping relationship, "a stack with two `TFloat`s on top" is just
//!   `Emitter<Ent<Ent<N, TFloat>, TFloat>>` for a free `N`, without needing named intermediate
//!   bounds.
//! - `genRun`'s default-method override (resolving both operands' `JitType` via
//!   `JitCodeGenerator.resolveType`, asserting they match, then dispatching to
//!   `opForFloat`/`opForDouble`, or `Unfinished.TODO` for the not-yet-supported multi-precision
//!   float case) is not modeled here. It returns Java's `OpResult` (constructed as
//!   `LiveOpResult`) and takes a `Methods.RetReq`, neither of which is ported in this crate, and
//!   it is called only by the (also unported) JIT driver -- no implementor's own logic calls it.
//!   This follows the same precedent as [`OpGen`](crate::pcode::seam_stubs::OpGen)'s omitted
//!   `genRun`, which
//!   [`FloatOpUnOpGen`](super::float_op_un_op_gen::FloatOpUnOpGen) already relies on.

use crate::pcode::emu::jit::gen::op::bin_op_gen::BinOpGen;
use crate::pcode::emu::jit::var::JitOutVar;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::types::{TDouble, TFloat};
use crate::pcode::emu::jit::op::jit_float_bin_op::JitFloatBinOp;

/// An extension for floating-point binary operators.
///
/// Port of `ghidra.pcode.emu.jit.gen.op.FloatOpBinOpGen<T>`. See the [module docs](self) for how
/// this differs from the Java interface.
pub trait FloatOpBinOpGen<T: JitFloatBinOp>: BinOpGen<T> {
    /// Floating-point operators are never signed.
    ///
    /// Port of `FloatOpBinOpGen.isSigned`, which overrides `BinOpGen.isSigned`. See the
    /// [module docs](self) on why this is not named `is_signed`.
    fn float_op_bin_op_gen_is_signed(&self) -> bool {
        false
    }

    /// Emit the JVM bytecode to perform the operator with `float` operands on the stack.
    ///
    /// Port of `FloatOpBinOpGen.opForFloat`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail `N`, with the right operand
    ///   pushed, then the left operand pushed on top of that.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail `N` with the result pushed.
    fn op_for_float<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TFloat>, TFloat>>,
    ) -> Emitter<Ent<N, TFloat>>;

    /// Emit the JVM bytecode to perform the operator with `double` operands on the stack.
    ///
    /// Port of `FloatOpBinOpGen.opForDouble`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail `N`, with the right operand
    ///   pushed, then the left operand pushed on top of that.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail `N` with the result pushed.
    fn op_for_double<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TDouble>, TDouble>>,
    ) -> Emitter<Ent<N, TDouble>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::emu::jit::gen::util::types::TRef;
    use crate::pcode::emu::jit::op::{JitDefOp, JitOp};
    use crate::pcode::emu::jit::var::JitVal;
    use crate::pcode::seam_stubs::{Ext, JitBinOp, JitTypeBehavior, MethodVisitor, OpGen};
    use std::sync::Arc;

    struct TestFloatBinOp;

    impl JitOp for TestFloatBinOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Float
        }

        fn link(&self) {}

        fn unlink(&self) {}
    }

    impl JitDefOp for TestFloatBinOp {
        fn out(&self) -> Arc<dyn JitOutVar> {
            unimplemented!()
        }
    }

    impl JitBinOp for TestFloatBinOp {
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

    impl JitFloatBinOp for TestFloatBinOp {}

    /// A stand-in for a concrete generator such as Java's `FloatAddOpGen`, wiring `BinOpGen`'s
    /// abstract `is_signed` to the `float_op_bin_op_gen_is_signed` override, per the
    /// [module docs](super).
    struct AddGen;
    impl OpGen<TestFloatBinOp> for AddGen {}
    impl BinOpGen<TestFloatBinOp> for AddGen {
        fn is_signed(&self) -> bool {
            self.float_op_bin_op_gen_is_signed()
        }
    }
    impl FloatOpBinOpGen<TestFloatBinOp> for AddGen {
        fn op_for_float<N: Next>(
            &self,
            em: Emitter<Ent<Ent<N, TFloat>, TFloat>>,
        ) -> Emitter<Ent<N, TFloat>> {
            em.recast()
        }

        fn op_for_double<N: Next>(
            &self,
            em: Emitter<Ent<Ent<N, TDouble>, TDouble>>,
        ) -> Emitter<Ent<N, TDouble>> {
            em.recast()
        }
    }

    #[test]
    fn is_signed_is_false_like_java_default_method() {
        // Java: `FloatOpBinOpGen.isSigned()` unconditionally returns `false`, regardless of the
        // underlying floating-point operator.
        assert!(!AddGen.float_op_bin_op_gen_is_signed());
        assert!(!BinOpGen::is_signed(&AddGen));
    }

    #[test]
    fn ext_is_zero_since_float_ops_are_unsigned() {
        // Java: `ext()` is `BinOpGen`'s default, computed from `isSigned()`; since
        // `FloatOpBinOpGen` hardcodes `isSigned() == false`, the extension is always
        // zero-extension, even though this generator's `is_signed` override forwards to it.
        assert_eq!(AddGen.ext(), Ext::Zero);
        assert_eq!(AddGen.r_ext(), Ext::Zero);
    }

    #[test]
    fn op_for_float_receives_the_stack_and_preserves_its_tail() {
        // Java: `opForFloat` is typed `Emitter<Ent<N1, TFloat>> -> Emitter<Ent<N2, TFloat>>`
        // where `N1 = Ent<N2, TFloat>`, i.e., it consumes the top two `float`s and leaves one in
        // their place, regardless of what lies beneath. Exercise this with a non-trivial tail
        // (`TRef` on `Bot`) to confirm the bound is generic in the tail, not hardcoded to `Bot`.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TFloat>, TFloat>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TFloat>> = AddGen.op_for_float(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn op_for_double_receives_the_stack_and_preserves_its_tail() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TDouble>, TDouble>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TDouble>> = AddGen.op_for_double(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn float_op_bin_op_gen_extends_bin_op_gen_like_java_interface() {
        // Java: `interface FloatOpBinOpGen<T extends JitFloatBinOp> extends BinOpGen<T>`.
        fn assert_is_bin_op_gen<G: BinOpGen<TestFloatBinOp>>(_gen: &G) {}
        assert_is_bin_op_gen(&AddGen);
        assert!(!AddGen.is_signed());
    }
}
