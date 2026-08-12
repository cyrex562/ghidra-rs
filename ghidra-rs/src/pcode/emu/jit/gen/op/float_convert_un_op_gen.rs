//! An extension for float conversion operators.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.FloatConvertUnOpGen`.
//!
//! # Differences from Java
//!
//! - Java's `<THIS extends JitCompiledPassage>` type parameter, threaded through
//!   `Local<TRef<THIS>>` and `JitCodeGenerator<THIS>`, collapses away: per the convention already
//!   set by [`IntBitwiseBinOpGen`](super::int_bitwise_bin_op_gen::IntBitwiseBinOpGen), [`Local`] is
//!   a concrete record with a non-generic [`TRef`], and
//!   [`JitCodeGenerator`](crate::pcode::seam_stubs::JitCodeGenerator) is likewise non-generic in
//!   this crate.
//! - `gen`'s `gen: JitCodeGenerator<THIS>` parameter becomes a generic `gen: &G where G:
//!   JitCodeGenerator`, not `&dyn JitCodeGenerator`: it must call
//!   [`JitCodeGenerator::gen_read_to_stack`]/[`JitCodeGenerator::gen_write_from_stack`], which are
//!   themselves generic over the pushed/popped machine type and so carry a `where Self: Sized`
//!   bound (the same technique
//!   [`VarHandler`](crate::pcode::emu::jit::alloc::var_handler::VarHandler) uses to stay
//!   `dyn`-compatible elsewhere) -- incompatible with a `dyn` receiver.
//! - Java's `Function<? super Emitter<Ent<Bot, UT>>, Emitter<Ent<Bot, OT>>> opcode` becomes an
//!   `impl FnOnce(Emitter<Ent<Bot, UT>>) -> Emitter<Ent<Bot, OT>>`, since Rust closures need no
//!   `Function`-style wrapper interface.
//! - `gen`'s `v: JitVar` argument to `JitCodeGenerator.genWriteFromStack` (via `op.out()`) is
//!   `&dyn JitOutVar` here, since this crate's [`JitOutVar`](crate::pcode::seam_stubs::JitOutVar)
//!   stub does not (yet) extend the real [`JitVar`](crate::pcode::emu::jit::var::JitVal) port as a
//!   distinct type; see
//!   [`JitCodeGenerator::gen_write_from_opnd`](crate::pcode::seam_stubs::JitCodeGenerator::gen_write_from_opnd)'s
//!   doc for the established precedent.

use crate::pcode::emu::jit::analysis::jit_type::SimpleJitType;
use crate::pcode::emu::jit::gen::op::un_op_gen::UnOpGen;
use crate::pcode::emu::jit::gen::util::emitter::{Bot, Emitter, Ent};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{BPrim, TRef};
use crate::pcode::emu::jit::op::jit_un_op::JitUnOp;
use crate::pcode::seam_stubs::{JitCodeGenerator, Scope};

/// An extension for float conversion operators.
///
/// Port of `ghidra.pcode.emu.jit.gen.op.FloatConvertUnOpGen<T>`. See the [module docs](self) for
/// how this differs from the Java interface.
pub trait FloatConvertUnOpGen<T: JitUnOp>: UnOpGen<T> {
    /// An implementation based on a given bytecode op.
    ///
    /// Port of `FloatConvertUnOpGen.gen`. See the [module docs](self) for how this differs from
    /// the Java default method.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack (empty).
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `gen`: the code generator.
    /// - `op`: the p-code op.
    /// - `ut`: the p-code type of the input operand.
    /// - `ot`: the p-code type of the output operand.
    /// - `opcode`: the conversion, e.g. `Op::f2d`, applied to the operand once on the stack.
    /// - `scope`: a scope for generating temporary local storage.
    ///
    /// # Returns
    ///
    /// The emitter typed with the incoming (empty) stack.
    #[allow(clippy::too_many_arguments)]
    fn gen<G, UT, UJT, OT, OJT>(
        &self,
        em: Emitter<Bot>,
        local_this: &Local<TRef>,
        gen: &G,
        op: &T,
        ut: UJT,
        ot: OJT,
        opcode: impl FnOnce(Emitter<Ent<Bot, UT>>) -> Emitter<Ent<Bot, OT>>,
        scope: &dyn Scope,
    ) -> Emitter<Bot>
    where
        G: JitCodeGenerator,
        UT: BPrim,
        UJT: SimpleJitType<B = UT>,
        OT: BPrim,
        OJT: SimpleJitType<B = OT>,
    {
        let em = gen.gen_read_to_stack(em, local_this, op.u().as_ref(), ut, self.ext());
        let em = opcode(em);
        gen.gen_write_from_stack(em, local_this, op.out().as_ref(), ot, self.ext(), scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_type::{DoubleJitType, FloatJitType};
    use crate::pcode::emu::jit::gen::util::types::{TDouble, TFloat};
    use crate::pcode::emu::jit::op::{JitDefOp, JitOp};
    use crate::pcode::emu::jit::var::JitVal;
    use crate::pcode::seam_stubs::{Ext, JitOutVar, JitTypeBehavior, MethodVisitor, OpGen};
    use std::sync::Arc;

    struct MockVal;

    impl JitVal for MockVal {
        fn size(&self) -> i32 {
            4
        }
        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }

    struct MockOutVar;

    impl JitVal for MockOutVar {
        fn size(&self) -> i32 {
            8
        }
        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}
    }

    impl JitOutVar for MockOutVar {
        fn set_definition(&self, _definition: Option<&dyn JitDefOp>) {}
        fn definition(&self) -> Option<Arc<dyn JitDefOp>> {
            None
        }
        fn varnode(&self) -> crate::program::model::pcode::Varnode {
            unimplemented!("not exercised: gen_write_from_stack's stub body ignores v")
        }
    }

    struct TestFloat2DoubleOp;

    impl JitOp for TestFloat2DoubleOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Float
        }
        fn link(&self) {}
        fn unlink(&self) {}
    }

    impl JitDefOp for TestFloat2DoubleOp {
        fn out(&self) -> Arc<dyn JitOutVar> {
            Arc::new(MockOutVar)
        }
    }

    impl JitUnOp for TestFloat2DoubleOp {
        fn u(&self) -> Arc<dyn JitVal> {
            Arc::new(MockVal)
        }
        fn u_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Float
        }
    }

    struct MockCodeGenerator;
    impl JitCodeGenerator for MockCodeGenerator {}

    struct MockScope;
    impl Scope for MockScope {}

    /// A stand-in for Java's `FloatFloat2FloatOpGen`, which implements
    /// `FloatConvertUnOpGen<JitFloatFloat2FloatOp>` with `isSigned() -> false`.
    struct Float2DoubleGen;
    impl OpGen<TestFloat2DoubleOp> for Float2DoubleGen {}
    impl UnOpGen<TestFloat2DoubleOp> for Float2DoubleGen {
        fn is_signed(&self) -> bool {
            false
        }
    }
    impl FloatConvertUnOpGen<TestFloat2DoubleOp> for Float2DoubleGen {}

    #[test]
    fn gen_reads_the_input_operand_applies_the_opcode_and_writes_the_output() {
        // Java: `FloatFloat2FloatOpGen.genRun`, on a `float`-to-`double` widening, dispatches to
        // `gen(em, localThis, gen, op, FloatJitType.F4, DoubleJitType.F8, Op::f2d, scope)`. The
        // `f2d` opcode itself replaces the `float` on the stack with a `double`; here that's
        // modeled type-level by an `Ent<Bot, TFloat> -> Ent<Bot, TDouble>` recast, since `Op` is
        // not yet ported.
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0);
        let code_gen = MockCodeGenerator;
        let scope = MockScope;
        let op = TestFloat2DoubleOp;

        let f2d = |em: Emitter<Ent<Bot, TFloat>>| -> Emitter<Ent<Bot, TDouble>> { em.recast() };

        let result: Emitter<Bot> = Float2DoubleGen.gen(
            em,
            &local_this,
            &code_gen,
            &op,
            FloatJitType,
            DoubleJitType,
            f2d,
            &scope,
        );
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn float_convert_un_op_gen_extends_un_op_gen_like_java_interface() {
        // Java: `interface FloatConvertUnOpGen<T extends JitUnOp> extends UnOpGen<T>`.
        fn assert_is_un_op_gen<G: UnOpGen<TestFloat2DoubleOp>>(_gen: &G) {}
        assert_is_un_op_gen(&Float2DoubleGen);
        assert!(!Float2DoubleGen.is_signed());
    }
}
