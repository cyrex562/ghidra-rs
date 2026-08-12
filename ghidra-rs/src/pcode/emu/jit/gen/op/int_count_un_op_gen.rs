//! An extension for unary integer operators that count bits.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.IntCountUnOpGen`.
//!
//! # Differences from Java
//!
//! - Java's `<N1 extends Next, N0 extends Ent<N1, TInt>>` pair of bounds on
//!   [`op_for_int`](IntCountUnOpGen::op_for_int) (and the analogous `TLong` pair on
//!   [`op_for_long`](IntCountUnOpGen::op_for_long)) collapses to a single free parameter `N`, per
//!   the convention set by
//!   [`IntOpUnOpGen::op_for_int`](super::int_op_un_op_gen::IntOpUnOpGen::op_for_int): since [`Ent`]
//!   is a concrete Rust struct rather than a Java subtyping relationship, "a stack with a value on
//!   top of tail `N`" is just `Emitter<Ent<N, T>>` for a free `N`, without needing named
//!   intermediate bounds.
//! - Java's `<THIS extends JitCompiledPassage>` type parameter on
//!   [`gen_run_mp_int`](IntCountUnOpGen::gen_run_mp_int) is dropped in favor of a non-generic
//!   `Local<TRef>` and `&dyn JitCodeGenerator`, matching the convention already set by
//!   [`IntOpUnOpGen::gen_run_mp_int`](super::int_op_un_op_gen::IntOpUnOpGen::gen_run_mp_int).
//! - `genRun`'s default-method override (dispatching on the resolved operand type, then
//!   delegating to `opForInt`/`opForLong`/`genRunMpInt`, and finally writing a fixed `I4` result)
//!   is not modeled here. It calls `JitCodeGenerator.resolveType`, `.genReadToStack`, and
//!   `.genWriteFromStack`, and returns Java's `OpResult` (constructed as `LiveOpResult`) via a
//!   `Methods.RetReq` parameter -- none of which are ported in this crate -- and it is called only
//!   by the (also unported) JIT driver, no implementor's own logic calls it. This follows the same
//!   precedent as [`IntOpUnOpGen`](super::int_op_un_op_gen::IntOpUnOpGen)'s omitted `genRun`.

use crate::pcode::emu::jit::analysis::jit_type::{IntJitType, LongJitType, MpIntJitType};
use crate::pcode::emu::jit::gen::op::un_op_gen::UnOpGen;
use crate::pcode::emu::jit::gen::util::emitter::{Bot, Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TLong, TRef};
use crate::pcode::emu::jit::op::jit_un_op::JitUnOp;
use crate::pcode::seam_stubs::{JitCodeGenerator, Scope};

/// An extension for unary integer operators that count bits.
///
/// Port of `ghidra.pcode.emu.jit.gen.op.IntCountUnOpGen`.
///
/// Unlike [`IntOpUnOpGen`](super::int_op_un_op_gen::IntOpUnOpGen), whose operators preserve the
/// operand's width, these operators (e.g., population count, leading/trailing zero count) always
/// produce a fixed-width `int` result, regardless of the input's width.
pub trait IntCountUnOpGen<T: JitUnOp>: UnOpGen<T> {
    /// Emit the JVM bytecode to perform the operator with an `int` operand on the stack.
    ///
    /// Port of `IntCountUnOpGen.opForInt`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail `N`, with the input operand
    ///   pushed on top.
    /// - `type_`: the p-code type of the input operand.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail `N` with the result pushed.
    fn op_for_int<N: Next>(&self, em: Emitter<Ent<N, TInt>>, type_: IntJitType) -> Emitter<Ent<N, TInt>>;

    /// Emit the JVM bytecode to perform the operator with a `long` operand on the stack.
    ///
    /// Port of `IntCountUnOpGen.opForLong`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail `N`, with the input operand
    ///   pushed on top.
    /// - `type_`: the p-code type of the input operand.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail `N` with an `int` result
    /// pushed -- note the result is always `int`-typed, even though the operand was `long`.
    fn op_for_long<N: Next>(&self, em: Emitter<Ent<N, TLong>>, type_: LongJitType) -> Emitter<Ent<N, TInt>>;

    /// Emit the JVM bytecode to perform the operator with a multi-precision operand.
    ///
    /// Port of `IntCountUnOpGen.genRunMpInt`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the empty stack.
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `gen`: the code generator.
    /// - `op`: the p-code op.
    /// - `type_`: the p-code type of the input operand.
    /// - `scope`: a scope for generating temporary local storage.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., with only the `int` result pushed.
    fn gen_run_mp_int(
        &self,
        em: Emitter<Bot>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        op: &T,
        type_: MpIntJitType,
        scope: &dyn Scope,
    ) -> Emitter<Ent<Bot, TInt>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_type::JitType;
    use crate::pcode::emu::jit::op::{JitDefOp, JitOp};
    use crate::pcode::emu::jit::var::JitVal;
    use crate::pcode::seam_stubs::{JitOutVar, JitTypeBehavior, MethodVisitor};
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

    /// A stand-in for a concrete generator such as Java's `IntPopcountOpGen`: signed, and echoes
    /// the type it was asked to operate on back to the caller so the test can assert what actually
    /// reached the trait method, rather than asserting something trivially true.
    struct PopcountGen;
    impl crate::pcode::seam_stubs::OpGen<TestUnOp> for PopcountGen {}
    impl UnOpGen<TestUnOp> for PopcountGen {
        fn is_signed(&self) -> bool {
            false
        }
    }
    impl IntCountUnOpGen<TestUnOp> for PopcountGen {
        fn op_for_int<N: Next>(&self, em: Emitter<Ent<N, TInt>>, type_: IntJitType) -> Emitter<Ent<N, TInt>> {
            assert_eq!(type_.size(), 4);
            em
        }

        fn op_for_long<N: Next>(&self, em: Emitter<Ent<N, TLong>>, type_: LongJitType) -> Emitter<Ent<N, TInt>> {
            assert_eq!(type_.size(), 8);
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
        ) -> Emitter<Ent<Bot, TInt>> {
            // Port-checkable content: `MpIntJitType.legsAlloc()` for a 9-byte mp-int is 3, per
            // Java's `ceil(size / 4)` leg-count computation (already ported and tested on
            // `MpIntJitType` itself).
            assert_eq!(type_.legs_alloc(), 3);
            em.recast()
        }
    }

    #[test]
    fn op_for_int_receives_the_operand_type_and_preserves_the_tail() {
        // Java: `opForInt` is typed `Emitter<Ent<N1, TInt>> -> Emitter<Ent<N1, TInt>>`, i.e., it
        // replaces the top `int` in place, regardless of what lies beneath. Exercise this with a
        // non-trivial tail (`TRef` on `Bot`) to confirm the bound is generic in the tail, not
        // hardcoded to `Bot`.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Tail, TInt>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> = PopcountGen.op_for_int(em, IntJitType::for_size(4));
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn op_for_long_narrows_the_top_of_stack_to_int() {
        // Java: `opForLong` is typed `Emitter<Ent<N1, TLong>> -> Emitter<Ent<N1, TInt>>`, i.e.,
        // unlike `IntOpUnOpGen`, the count is always `int`-sized even though the operand was
        // `long`.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Tail, TLong>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> = PopcountGen.op_for_long(em, LongJitType::for_size(8));
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn gen_run_mp_int_receives_the_operand_type_and_yields_an_int_result() {
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0);
        let code_gen = MockCodeGenerator;
        let scope = MockScope;
        let op = TestUnOp;

        let result: Emitter<Ent<Bot, TInt>> = PopcountGen.gen_run_mp_int(
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
    fn int_count_un_op_gen_extends_un_op_gen_like_java_interface() {
        // Java: `interface IntCountUnOpGen<T extends JitUnOp> extends UnOpGen<T>`.
        fn assert_is_un_op_gen<G: UnOpGen<TestUnOp>>(_gen: &G) {}
        assert_is_un_op_gen(&PopcountGen);
        assert!(!PopcountGen.is_signed());
    }
}
