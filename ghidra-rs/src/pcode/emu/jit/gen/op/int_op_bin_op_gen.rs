//! An extension for integer binary operators.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.IntOpBinOpGen`.
//!
//! # Differences from Java
//!
//! - Java's `<N2 extends Next, N1 extends Ent<N2, TInt>, N0 extends Ent<N1, TInt>>` triple of
//!   bounds on [`op_for_int`](IntOpBinOpGen::op_for_int) (and the analogous `TLong` triple on
//!   [`op_for_long`](IntOpBinOpGen::op_for_long)) collapses to a single free parameter `N`, per
//!   the convention set by [`emitter`](crate::pcode::emu::jit::gen::util::emitter): since
//!   [`Ent`] is a concrete Rust struct rather than a Java subtyping relationship, "any stack with
//!   a `TInt` on top" is just `Emitter<Ent<N, TInt>>` for a free `N`, without needing named
//!   intermediate bounds.
//! - Java's `<THIS extends JitCompiledPassage>` type parameter on
//!   [`gen_run_mp_int`](IntOpBinOpGen::gen_run_mp_int) is dropped in favor of a non-generic
//!   `Local<TRef>` and `&dyn JitCodeGenerator`, matching the convention already set by
//!   [`BinOpGen::gen_mp_delegation_to_static_method`](super::bin_op_gen::BinOpGen::gen_mp_delegation_to_static_method).
//! - `genRun`'s default-method override (dispatching on the unified operand type, then delegating
//!   to `opForInt`/`opForLong`/`genRunMpInt`) is not modeled here. It returns Java's `OpResult`
//!   (constructed as `LiveOpResult`) and takes a `Methods.RetReq`, neither of which is ported in
//!   this crate, and it is called only by the (also unported) JIT driver -- no implementor's own
//!   logic calls it. This follows the same precedent as
//!   [`OpGen`](crate::pcode::seam_stubs::OpGen)'s omitted `genRun`, which
//!   [`BinOpGen`](super::bin_op_gen::BinOpGen) already relies on.

use crate::pcode::emu::jit::analysis::jit_type::{IntJitType, LongJitType, MpIntJitType};
use crate::pcode::emu::jit::var::JitOutVar;
use crate::pcode::emu::jit::gen::op::bin_op_gen::BinOpGen;
use crate::pcode::emu::jit::gen::util::emitter::{Bot, Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TLong, TRef};
use crate::pcode::seam_stubs::{JitBinOp, JitCodeGenerator, Scope};

/// An extension that provides conveniences and common implementations for integer binary p-code
/// operators.
///
/// Port of `ghidra.pcode.emu.jit.gen.op.IntOpBinOpGen`.
pub trait IntOpBinOpGen<T: JitBinOp>: BinOpGen<T> {
    /// Emit the JVM bytecode to perform the operator with `int` operands on the stack.
    ///
    /// Port of `IntOpBinOpGen.opForInt`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail `N`, with the right operand
    ///   pushed, then the left operand pushed on top of that.
    /// - `type_`: the p-code type of the operands.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail `N` with the result pushed.
    fn op_for_int<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TInt>, TInt>>,
        type_: IntJitType,
    ) -> Emitter<Ent<N, TInt>>;

    /// Emit the JVM bytecode to perform the operator with `long` operands on the stack.
    ///
    /// Port of `IntOpBinOpGen.opForLong`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack: the tail `N`, with the right operand
    ///   pushed, then the left operand pushed on top of that.
    /// - `type_`: the p-code type of the operands.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., the tail `N` with the result pushed.
    fn op_for_long<N: Next>(
        &self,
        em: Emitter<Ent<Ent<N, TLong>, TLong>>,
        type_: LongJitType,
    ) -> Emitter<Ent<N, TLong>>;

    /// Emit the JVM bytecode to perform the operator with multi-precision operands.
    ///
    /// Port of `IntOpBinOpGen.genRunMpInt`.
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
    use crate::pcode::emu::jit::analysis::jit_type_behavior::JitTypeBehavior;
    use crate::pcode::seam_stubs::MethodVisitor;
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

    /// A stand-in for a concrete generator such as Java's `IntAddOpGen`: signed, and echoes the
    /// type it was asked to operate on back to the caller so the test can assert what actually
    /// reached the trait method, rather than asserting something trivially true.
    struct AddGen;
    impl crate::pcode::seam_stubs::OpGen<TestBinOp> for AddGen {}
    impl BinOpGen<TestBinOp> for AddGen {
        fn is_signed(&self) -> bool {
            true
        }
    }
    impl IntOpBinOpGen<TestBinOp> for AddGen {
        fn op_for_int<N: Next>(
            &self,
            em: Emitter<Ent<Ent<N, TInt>, TInt>>,
            type_: IntJitType,
        ) -> Emitter<Ent<N, TInt>> {
            assert_eq!(type_, IntJitType::I4);
            em.recast()
        }

        fn op_for_long<N: Next>(
            &self,
            em: Emitter<Ent<Ent<N, TLong>, TLong>>,
            type_: LongJitType,
        ) -> Emitter<Ent<N, TLong>> {
            assert_eq!(type_, LongJitType::I8);
            em.recast()
        }

        fn gen_run_mp_int(
            &self,
            em: Emitter<Bot>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _op: &TestBinOp,
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
    fn op_for_int_receives_the_operand_type_and_preserves_the_stack_tail() {
        // Java: `opForInt` is typed `Emitter<Ent<N1, TInt>> -> Emitter<Ent<N2, TInt>>` where
        // `N1 = Ent<N2, TInt>`, i.e., it consumes the top two `int`s and leaves one in their
        // place, regardless of what lies beneath. Exercise this with a non-trivial tail (`TRef`
        // on `Bot`) to confirm the bound is generic in the tail, not hardcoded to `Bot`.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TInt>, TInt>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TInt>> = AddGen.op_for_int(em, IntJitType::I4);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn op_for_long_receives_the_operand_type_and_preserves_the_stack_tail() {
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Ent<Ent<Tail, TLong>, TLong>> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Tail, TLong>> = AddGen.op_for_long(em, LongJitType::I8);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn gen_run_mp_int_receives_the_operand_type_and_preserves_the_empty_stack() {
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0);
        let code_gen = MockCodeGenerator;
        let scope = MockScope;
        let op = TestBinOp;

        let result = AddGen.gen_run_mp_int(
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
    fn int_op_bin_op_gen_extends_bin_op_gen_like_java_interface() {
        // Java: `interface IntOpBinOpGen<T extends JitBinOp> extends BinOpGen<T>`.
        fn assert_is_bin_op_gen<G: BinOpGen<TestBinOp>>(_gen: &G) {}
        assert_is_bin_op_gen(&AddGen);
        assert!(AddGen.is_signed());
    }
}
