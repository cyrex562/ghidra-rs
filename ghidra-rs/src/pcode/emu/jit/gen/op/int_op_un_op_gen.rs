//! An extension for integer unary operators.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.IntOpUnOpGen`.
//!
//! # Differences from Java
//!
//! - Java's `<N1 extends Next, N0 extends Ent<N1, TInt>>` pair of bounds on
//!   [`op_for_int`](IntOpUnOpGen::op_for_int) (and the analogous `TLong` pair on
//!   [`op_for_long`](IntOpUnOpGen::op_for_long)) collapses to a single free parameter `N`, per the
//!   convention set by
//!   [`IntOpBinOpGen`](super::int_op_bin_op_gen::IntOpBinOpGen::op_for_int): since [`Ent`] is a
//!   concrete Rust struct rather than a Java subtyping relationship, "a stack with a `TInt` on top
//!   of tail `N`" is just `Emitter<Ent<N, TInt>>` for a free `N`, without needing named
//!   intermediate bounds.
//! - Java's `<THIS extends JitCompiledPassage>` type parameter on
//!   [`gen_run_mp_int`](IntOpUnOpGen::gen_run_mp_int) is dropped in favor of a non-generic
//!   `Local<TRef>` and `&dyn JitCodeGenerator`, matching the convention already set by
//!   [`IntOpBinOpGen::gen_run_mp_int`](super::int_op_bin_op_gen::IntOpBinOpGen::gen_run_mp_int).
//! - `genRun`'s default-method override (dispatching on the resolved operand type, then
//!   delegating to `opForInt`/`opForLong`/`genRunMpInt`) is not modeled here. It calls
//!   `JitCodeGenerator.resolveType`, `.genReadToStack`, and `.genWriteFromStack`, and returns
//!   Java's `OpResult` (constructed as `LiveOpResult`) via a `Methods.RetReq` parameter -- none of
//!   which are ported in this crate -- and it is called only by the (also unported) JIT driver, no
//!   implementor's own logic calls it. This follows the same precedent as
//!   [`IntOpBinOpGen`](super::int_op_bin_op_gen::IntOpBinOpGen)'s omitted `genRun`.

use crate::pcode::emu::jit::analysis::jit_type::{IntJitType, LongJitType, MpIntJitType};
use crate::pcode::emu::jit::var::JitOutVar;
use crate::pcode::emu::jit::gen::op::un_op_gen::UnOpGen;
use crate::pcode::emu::jit::gen::util::emitter::{Bot, Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TLong, TRef};
use crate::pcode::emu::jit::op::jit_un_op::JitUnOp;
use crate::pcode::seam_stubs::{JitCodeGenerator, Scope};

/// An extension that provides conveniences and common implementations for integer unary p-code
/// operators.
///
/// Port of `ghidra.pcode.emu.jit.gen.op.IntOpUnOpGen`.
pub trait IntOpUnOpGen<T: JitUnOp>: UnOpGen<T> {
    /// Emit the JVM bytecode to perform the operator with an `int` operand on the stack.
    ///
    /// Port of `IntOpUnOpGen.opForInt`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail `N`, with the input operand
    ///   pushed on top.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail `N` with the result pushed.
    fn op_for_int<N: Next>(&self, em: Emitter<Ent<N, TInt>>) -> Emitter<Ent<N, TInt>>;

    /// Emit the JVM bytecode to perform the operator with a `long` operand on the stack.
    ///
    /// Port of `IntOpUnOpGen.opForLong`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail `N`, with the input operand
    ///   pushed on top.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail `N` with the result pushed.
    fn op_for_long<N: Next>(&self, em: Emitter<Ent<N, TLong>>) -> Emitter<Ent<N, TLong>>;

    /// Emit the JVM bytecode to perform the operator with a multi-precision operand.
    ///
    /// Port of `IntOpUnOpGen.genRunMpInt`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the empty stack.
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `gen`: the code generator.
    /// - `op`: the p-code op.
    /// - `type_`: the p-code type of the operand.
    /// - `scope`: a scope for generating temporary local storage.
    ///
    /// # Returns
    ///
    /// The emitter typed with the empty stack.
    fn gen_run_mp_int(
        &self,
        em: Emitter<Bot>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        op: &T,
        type_: MpIntJitType,
        scope: &dyn Scope,
    ) -> Emitter<Bot>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::op::{JitDefOp, JitOp};
    use crate::pcode::emu::jit::var::JitVal;
    use crate::pcode::seam_stubs::{JitTypeBehavior, MethodVisitor};
    use std::sync::Arc;

    struct TestUnOp;

    impl JitOp for TestUnOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }

        fn link(&self) {}

        fn unlink(&self) {}
    }

    impl JitDefOp for TestUnOp {
        fn out(&self) -> Arc<dyn JitOutVar> {
            unimplemented!()
        }
    }

    impl JitUnOp for TestUnOp {
        fn u(&self) -> Arc<dyn JitVal> {
            unimplemented!()
        }

        fn u_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
    }

    struct MockCodeGenerator;
    impl JitCodeGenerator for MockCodeGenerator {}

    struct MockScope;
    impl Scope for MockScope {}

    /// A stand-in for a concrete generator such as Java's `IntNegateOpGen`: signed, and echoes
    /// the type it was asked to operate on back to the caller so the test can assert what
    /// actually reached the trait method, rather than asserting something trivially true.
    struct NegGen;
    impl crate::pcode::seam_stubs::OpGen<TestUnOp> for NegGen {}
    impl UnOpGen<TestUnOp> for NegGen {
        fn is_signed(&self) -> bool {
            true
        }
    }
    impl IntOpUnOpGen<TestUnOp> for NegGen {
        fn op_for_int<N: Next>(&self, em: Emitter<Ent<N, TInt>>) -> Emitter<Ent<N, TInt>> {
            em.recast()
        }

        fn op_for_long<N: Next>(&self, em: Emitter<Ent<N, TLong>>) -> Emitter<Ent<N, TLong>> {
            em.recast()
        }

        fn gen_run_mp_int(
            &self,
            em: Emitter<Bot>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _op: &TestUnOp,
            type_: MpIntJitType,
            _scope: &dyn Scope,
        ) -> Emitter<Bot> {
            // Port-checkable content: `MpIntJitType.legsAlloc()` for a 9-byte mp-int is 3, per
            // Java's `ceil(size / 4)` leg-count computation (already ported and tested on
            // `MpIntJitType` itself).
            assert_eq!(type_.legs_alloc(), 3);
            em
        }
    }

    #[test]
    fn op_for_int_receives_the_stack_and_preserves_its_tail() {
        // Java: `opForInt` is typed `Emitter<Ent<N1, TInt>> -> Emitter<Ent<N1, TInt>>`, i.e., it
        // replaces the top `int` in place, regardless of what lies beneath. Exercise this with a
        // non-trivial tail (`TRef` on `Bot`) to confirm the bound is generic in the tail, not
        // hardcoded to `Bot`.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Tail, TInt>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> = NegGen.op_for_int(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn op_for_long_receives_the_stack_and_preserves_its_tail() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Tail, TLong>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TLong>> = NegGen.op_for_long(em);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn gen_run_mp_int_receives_the_operand_type_and_preserves_the_empty_stack() {
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0);
        let code_gen = MockCodeGenerator;
        let scope = MockScope;
        let op = TestUnOp;

        let result = NegGen.gen_run_mp_int(
            em,
            &local_this,
            &code_gen,
            &op,
            MpIntJitType::for_size(9),
            &scope,
        );
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn int_op_un_op_gen_extends_un_op_gen_like_java_interface() {
        // Java: `interface IntOpUnOpGen<T extends JitUnOp> extends UnOpGen<T>`.
        fn assert_is_un_op_gen<G: UnOpGen<TestUnOp>>(_gen: &G) {}
        assert_is_un_op_gen(&NegGen);
        assert!(NegGen.is_signed());
    }
}
