//! Conveniences and common implementations for bytecode generators of binary p-code operators.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.BinOpGen`.
//!
//! # Differences from Java
//!
//! - Java's `<THIS extends JitCompiledPassage>` type parameter, repeated on
//!   `genMpDelegationToStaticMethod`, is dropped in favor of a non-generic `Local<TRef>` and `&dyn
//!   JitCodeGenerator`, matching the convention set by
//!   [`MpAccessGen`](crate::pcode::emu::jit::gen::access::mp_access_gen::MpAccessGen) and
//!   [`VarGen`](crate::pcode::emu::jit::gen::var::var_gen::VarGen).
//! - `genMpDelegationToStaticMethod`'s real bytecode emission depends on the not-yet-ported `Op`
//!   (JVM opcode helper namespace), `Methods`, and `GenConsts` (method descriptor constants). This
//!   port keeps the one piece of real, testable logic -- the number of `int` legs the mp-int type
//!   requires -- and stubs the opcode sequence itself, in the same spirit as
//!   [`FieldForArrDirect::gen_load`](crate::pcode::seam_stubs::FieldForArrDirect::gen_load) and
//!   [`AccessGen::gen_read_to_bool`](crate::pcode::emu::jit::gen::access::access_gen::gen_read_to_bool).
//! - `OpGen<T>` is not yet ported; a minimal marker placeholder lives in
//!   [`seam_stubs`](crate::pcode::seam_stubs); see `STUBS.tsv`.

use crate::pcode::emu::jit::analysis::jit_type::MpIntJitType;
use crate::pcode::emu::jit::op::JitBinOp;
use crate::pcode::emu::jit::var::JitOutVar;
use crate::pcode::emu::jit::gen::util::emitter::Bot;
use crate::pcode::emu::jit::gen::util::emitter::Emitter;
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::TRef;
use crate::pcode::seam_stubs::{Ext, JitCodeGenerator, OpGen, Scope};

/// A choice of static method parameter to take as operator output.
///
/// Port of `BinOpGen.TakeOut`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TakeOut {
    /// The out (first) parameter.
    Out,
    /// The left (second) parameter.
    Left,
}

/// An extension that provides conveniences and common implementations for binary p-code
/// operators.
///
/// Port of `ghidra.pcode.emu.jit.gen.op.BinOpGen`.
pub trait BinOpGen<T: JitBinOp>: OpGen<T> {
    /// Emit bytecode that implements an mp-int binary operator via delegation to a static method
    /// on `JitCompiledPassage`.
    ///
    /// Port of `BinOpGen.genMpDelegationToStaticMethod`. The method must have the signature
    /// `void method(int[] out, int[] inL, int[] inR)`. It presumes the left operand's legs are at
    /// the top of the stack, least-significant leg on top, followed by the right operand's legs,
    /// also least-significant leg on top. It allocates the output array, moves the operands into
    /// their respective input arrays, invokes the method, and places the result legs on the
    /// stack, least-significant leg on top.
    ///
    /// See the [module docs](self) for what is and is not modeled by this port: the leg-count
    /// computation is real; the opcode sequence that would perform the above is stubbed, since it
    /// depends on the not-yet-ported `Op`/`Methods`/`GenConsts`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the empty stack.
    /// - `gen`: the code generator.
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `type_`: the type of the operands.
    /// - `method_name`: the name of the method in `JitCompiledPassage` to invoke.
    /// - `op`: the p-code op.
    /// - `slack_left`: the number of extra ints to allocate for the left operand's array, to
    ///   facilitate Knuth's division algorithm, which may require an extra leading leg in the
    ///   dividend after normalization.
    /// - `take_out`: which operand of the static method to actually take for the output, to
    ///   facilitate the remainder operator, whose result Knuth's algorithm leaves where the
    ///   dividend was.
    /// - `scope`: a scope for generating temporary local storage.
    ///
    /// # Returns
    ///
    /// The emitter typed with the empty stack.
    #[allow(clippy::too_many_arguments)]
    fn gen_mp_delegation_to_static_method(
        &self,
        em: Emitter<Bot>,
        gen: &dyn JitCodeGenerator,
        local_this: &Local<TRef>,
        type_: MpIntJitType,
        method_name: &str,
        op: &dyn JitBinOp,
        slack_left: i32,
        take_out: TakeOut,
        scope: &dyn Scope,
    ) -> Emitter<Bot> {
        let _ = (gen, local_this, method_name, op, slack_left, take_out, scope);
        // Port of `legCount = type.legsAlloc()`: the real, testable part of this method. The
        // array-allocation/read/invoke/write opcode sequence that follows in Java is not modeled;
        // see the module docs.
        let _leg_count = type_.legs_alloc();
        em
    }

    /// Whether this operator is signed.
    ///
    /// Port of `BinOpGen.isSigned`.
    ///
    /// In many cases, the operator itself is not affected by the signedness of the operands;
    /// however, if size adjustments to the operands are needed, this can determine how those
    /// operands are extended.
    fn is_signed(&self) -> bool;

    /// When loading and storing variables, the kind of extension to apply.
    ///
    /// Port of `BinOpGen.ext`.
    fn ext(&self) -> Ext {
        Ext::for_signed(self.is_signed())
    }

    /// When loading the right operand, the kind of extension to apply.
    ///
    /// Port of `BinOpGen.rExt`.
    fn r_ext(&self) -> Ext {
        self.ext()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::op::{JitDefOp, JitOp};
    use crate::pcode::emu::jit::var::JitVal;
    use crate::pcode::emu::jit::analysis::jit_type_behavior::JitTypeBehavior;
    use crate::pcode::seam_stubs::{MethodVisitor, Scope};
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
        fn l(&self) -> Arc<dyn JitVal> {
            unimplemented!()
        }

        fn r(&self) -> Arc<dyn JitVal> {
            unimplemented!()
        }

        fn l_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }

        fn r_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
    }

    struct SignedGen;
    impl OpGen<TestBinOp> for SignedGen {}
    impl BinOpGen<TestBinOp> for SignedGen {
        fn is_signed(&self) -> bool {
            true
        }
    }

    struct UnsignedGen;
    impl OpGen<TestBinOp> for UnsignedGen {}
    impl BinOpGen<TestBinOp> for UnsignedGen {
        fn is_signed(&self) -> bool {
            false
        }
    }

    struct MockCodeGenerator;
    impl JitCodeGenerator for MockCodeGenerator {}

    struct MockScope;
    impl Scope for MockScope {}

    fn make_local_this() -> Local<TRef> {
        Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0)
    }

    #[test]
    fn take_out_variants_are_distinct() {
        // Java: BinOpGen.TakeOut has exactly the constants OUT and LEFT.
        assert_ne!(TakeOut::Out, TakeOut::Left);
    }

    #[test]
    fn ext_matches_is_signed_like_java_default_method() {
        // Java: default Ext ext() { return Ext.forSigned(isSigned()); }
        assert_eq!(SignedGen.ext(), Ext::Sign);
        assert_eq!(UnsignedGen.ext(), Ext::Zero);
    }

    #[test]
    fn r_ext_defaults_to_ext_like_java_default_method() {
        // Java: default Ext rExt() { return ext(); }
        assert_eq!(SignedGen.r_ext(), SignedGen.ext());
        assert_eq!(UnsignedGen.r_ext(), UnsignedGen.ext());
    }

    #[test]
    fn gen_mp_delegation_to_static_method_returns_the_empty_stack_for_either_take_out() {
        let gen_impl = SignedGen;
        let code_gen = MockCodeGenerator;
        let local_this = make_local_this();
        let scope = MockScope;
        let op = TestBinOp;
        let type_ = MpIntJitType::for_size(9);

        for take_out in [TakeOut::Out, TakeOut::Left] {
            let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
            // Java: genMpDelegationToStaticMethod takes and returns Emitter<Bot>, i.e., it does
            // not change the incoming (empty) JVM operand stack's type.
            let result: Emitter<Bot> = gen_impl.gen_mp_delegation_to_static_method(
                em,
                &code_gen,
                &local_this,
                type_.clone(),
                "mpIntBinOp",
                &op,
                1,
                take_out,
                &scope,
            );
            assert!(result.local_variables().is_empty());
        }
    }
}
