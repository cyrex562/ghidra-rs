//! An extension for integer shift operators.
//!
//! Port of `ghidra.pcode.emu.jit.gen.op.IntShiftBinOpGen`.
//!
//! # Differences from Java
//!
//! - Java's `default Ext rExt()` overrides the abstract `BinOpGen.rExt`. Rust cannot "override" a
//!   supertrait method by redeclaring it under the same name, so -- per the convention already set
//!   by [`IntBitwiseBinOpGen`](super::int_bitwise_bin_op_gen::IntBitwiseBinOpGen) -- it is exposed
//!   here under the distinct name
//!   [`int_shift_bin_op_gen_r_ext`](IntShiftBinOpGen::int_shift_bin_op_gen_r_ext). A concrete
//!   implementor's own `BinOpGen::r_ext` impl should delegate to it.
//! - Java's `<THIS extends JitCompiledPassage>` type parameter, threaded through
//!   `Local<TRef<THIS>>` and `JitCodeGenerator<THIS>`, collapses away, per the convention already
//!   set by [`FloatConvertUnOpGen`](super::float_convert_un_op_gen::FloatConvertUnOpGen): [`Local`]
//!   is a concrete record with a non-generic [`TRef`], and
//!   [`JitCodeGenerator`](crate::pcode::seam_stubs::JitCodeGenerator) is likewise non-generic in
//!   this crate.
//! - [`gen_shift_prim_prim`](IntShiftBinOpGen::gen_shift_prim_prim)/
//!   [`gen_shift_mp_prim`](IntShiftBinOpGen::gen_shift_mp_prim)/
//!   [`gen_shift_prim_mp`](IntShiftBinOpGen::gen_shift_prim_mp)/
//!   [`gen_shift_mp_mp`](IntShiftBinOpGen::gen_shift_mp_mp)'s `gen: JitCodeGenerator<THIS>`
//!   parameter becomes a generic `gen: &G where G: JitCodeGenerator`, not `&dyn JitCodeGenerator`:
//!   they must call
//!   [`JitCodeGenerator::gen_read_to_stack`]/[`JitCodeGenerator::gen_write_from_stack`]/
//!   [`JitCodeGenerator::gen_read_to_array`]/[`JitCodeGenerator::gen_write_from_array`], which are
//!   themselves generic over the pushed/popped machine type and so carry a `where Self: Sized`
//!   bound, incompatible with a `dyn` receiver, per the same precedent as
//!   [`FloatConvertUnOpGen::gen`](super::float_convert_un_op_gen::FloatConvertUnOpGen::gen).
//!   [`JitCodeGenerator::gen_read_to_array`]/[`JitCodeGenerator::gen_write_from_array`] did not
//!   exist on that stub before this port; they are grown here (see `STUBS.tsv`), mirroring
//!   `gen_read_to_stack`/`gen_write_from_stack`.
//! - The four `genShift*` default methods' real bytecode emission -- allocating the output `int[]`
//!   for the mp-int cases, and the `invokestatic` to the named `JitCompiledPassage` method with its
//!   `MthDesc`-typed signature -- depends on the not-yet-ported `Op` (JVM opcode helper namespace)
//!   and `Methods.Inv` (the invocation builder `takeArg`/`ret`/`retVoid` step). Per the precedent
//!   set by
//!   [`BinOpGen::gen_mp_delegation_to_static_method`](super::bin_op_gen::BinOpGen::gen_mp_delegation_to_static_method),
//!   each method keeps its real, testable logic -- reading/writing operands through
//!   [`JitCodeGenerator`]'s already-real stack-shape plumbing, and (for the mp-int output cases)
//!   the leg count and byte size driving the output array's allocation -- and stubs the invocation
//!   sequence itself via [`Emitter::recast`].
//! - Java's `MthDesc<..>` parameter (the type-checked descriptor of the overloaded
//!   `JitCompiledPassage` method to invoke) is dropped: since the invocation itself is not modeled
//!   (see above), there is nothing for it to describe here.
//! - Java's `JitVar outVar` parameter is narrowed to `&dyn JitOutVar` at each call site, per the
//!   same convention as
//!   [`JitCodeGenerator::gen_write_from_stack`](crate::pcode::seam_stubs::JitCodeGenerator::gen_write_from_stack)'s
//!   doc.
//! - `genRun`'s default-method override (resolving both operands' `JitType` via
//!   `JitCodeGenerator.resolveType`, then dispatching to one of the four `genShift*` methods based
//!   on the pair) is not modeled here. It returns Java's `OpResult` (constructed as
//!   `LiveOpResult`) and takes a `JitBlock`, neither of which is ported in this crate, and it is
//!   called only by the (also unported) JIT driver -- no implementor's own logic calls it. This
//!   follows the same precedent as [`OpGen`](crate::pcode::seam_stubs::OpGen)'s omitted `genRun`,
//!   which
//!   [`IntPredBinOpGen`](super::int_pred_bin_op_gen::IntPredBinOpGen) and
//!   [`IntOpBinOpGen`](super::int_op_bin_op_gen::IntOpBinOpGen) already rely on.

use crate::pcode::emu::jit::analysis::jit_type::{MpIntJitType, SimpleJitType};
use crate::pcode::emu::jit::gen::op::bin_op_gen::BinOpGen;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{BPrim, TRef};
use crate::pcode::emu::jit::op::JitIntBinOp;
use crate::pcode::emu::jit::var::JitVal;
use crate::pcode::seam_stubs::{Ext, JitCodeGenerator, JitOutVar, Scope};

/// An extension for integer shift operators.
///
/// Port of `ghidra.pcode.emu.jit.gen.op.IntShiftBinOpGen<T>`. This is just going to invoke one of
/// `JitCompiledPassage.intLeft(int, int)`, `JitCompiledPassage.intRight(int, int)`,
/// `JitCompiledPassage.intSRight(int, int)`, or one of their overloaded methods, depending on the
/// operand types. See the [module docs](self) for how this differs from the Java interface.
pub trait IntShiftBinOpGen<T: JitIntBinOp>: BinOpGen<T> {
    /// The shift amount is always treated unsigned.
    ///
    /// Port of `IntShiftBinOpGen.rExt`, which overrides `BinOpGen.rExt`. See the
    /// [module docs](self) on why this is not named `r_ext`.
    fn int_shift_bin_op_gen_r_ext(&self) -> Ext {
        Ext::Zero
    }

    /// The name of the static method in `JitCompiledPassage` to invoke.
    ///
    /// Port of `IntShiftBinOpGen.methodName`.
    fn method_name(&self) -> &str;

    /// The implementation when both operands are simple primitives.
    ///
    /// Port of `IntShiftBinOpGen.genShiftPrimPrim`. See the [module docs](self) on what is and is
    /// not modeled: the operand read/write plumbing is real; the invocation of the named
    /// `JitCompiledPassage` method is stubbed, since it depends on the not-yet-ported `Op`/
    /// `Methods`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack.
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `gen`: the code generator.
    /// - `out_var`: the output operand.
    /// - `out_type`: the p-code type of the output value.
    /// - `l_val`: the left operand.
    /// - `l_type`: the p-code type of the left operand.
    /// - `r_val`: the right operand.
    /// - `r_type`: the p-code type of the right operand.
    /// - `scope`: a scope for generating temporary local storage.
    ///
    /// # Returns
    ///
    /// The emitter typed with the incoming stack, unchanged.
    #[allow(clippy::too_many_arguments)]
    fn gen_shift_prim_prim<G, LT, LJT, RT, RJT, N>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &G,
        out_var: &dyn JitOutVar,
        out_type: LJT,
        l_val: &dyn JitVal,
        l_type: LJT,
        r_val: &dyn JitVal,
        r_type: RJT,
        scope: &dyn Scope,
    ) -> Emitter<N>
    where
        G: JitCodeGenerator,
        LT: BPrim,
        LJT: SimpleJitType<B = LT>,
        RT: BPrim,
        RJT: SimpleJitType<B = RT>,
        N: Next,
    {
        let em = gen.gen_read_to_stack(em, local_this, l_val, l_type, self.ext());
        let em =
            gen.gen_read_to_stack(em, local_this, r_val, r_type, self.int_shift_bin_op_gen_r_ext());
        // Op::invokestatic to JitCompiledPassage.<method_name()>, per Methods.Inv's
        // takeArg/takeArg/ret steps, is not yet ported; see the module docs. It replaces the two
        // pushed operands with a single LT-typed result.
        let em: Emitter<Ent<N, LT>> = em.recast();
        gen.gen_write_from_stack(em, local_this, out_var, out_type, self.ext(), scope)
    }

    /// The implementation when the left operand is an mp-int and the right is a primitive.
    ///
    /// Port of `IntShiftBinOpGen.genShiftMpPrim`. See the [module docs](self) on what is and is
    /// not modeled: the operand read/write plumbing and the output array's leg count/size are
    /// real; the array allocation and the invocation of the named `JitCompiledPassage` method are
    /// stubbed.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack.
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `gen`: the code generator.
    /// - `out_var`: the output operand.
    /// - `out_type`: the p-code type of the output value.
    /// - `l_val`: the left operand.
    /// - `l_type`: the p-code type of the left operand.
    /// - `r_val`: the right operand.
    /// - `r_type`: the p-code type of the right operand.
    /// - `scope`: a scope for generating temporary local storage.
    ///
    /// # Returns
    ///
    /// The emitter typed with the incoming stack, unchanged.
    #[allow(clippy::too_many_arguments)]
    fn gen_shift_mp_prim<G, RT, RJT, N>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &G,
        out_var: &dyn JitOutVar,
        out_type: MpIntJitType,
        l_val: &dyn JitVal,
        l_type: MpIntJitType,
        r_val: &dyn JitVal,
        r_type: RJT,
        scope: &dyn Scope,
    ) -> Emitter<N>
    where
        G: JitCodeGenerator,
        RT: BPrim,
        RJT: SimpleJitType<B = RT>,
        N: Next,
    {
        // Port of `outType.legsAlloc()`/`outType.size()`: the real, testable part of the output
        // `int[]` allocation. The `ldc__i`/`newarray`/`dup` opcode sequence that would perform the
        // allocation in Java is not modeled; see the module docs.
        let _legs_alloc = out_type.legs_alloc();
        let _size = out_type.size;
        let em = gen.gen_read_to_array(em, local_this, l_val, l_type, self.ext(), scope, 0);
        let em =
            gen.gen_read_to_stack(em, local_this, r_val, r_type, self.int_shift_bin_op_gen_r_ext());
        // Op::invokestatic to JitCompiledPassage.<method_name()>, per Methods.Inv's four
        // takeArg/retVoid steps, is not yet ported; see the module docs. It consumes the output,
        // left array, and right primitive, leaving only the output array (kept live via Java's
        // `dup`) for gen_write_from_array below.
        let em: Emitter<Ent<N, TRef>> = em.recast();
        gen.gen_write_from_array(em, local_this, out_var, out_type, self.ext(), scope)
    }

    /// The implementation when the left operand is a primitive and the right operand is an
    /// mp-int.
    ///
    /// Port of `IntShiftBinOpGen.genShiftPrimMp`. See the [module docs](self) on what is and is
    /// not modeled: the operand read/write plumbing is real; the invocation of the named
    /// `JitCompiledPassage` method is stubbed.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack.
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `gen`: the code generator.
    /// - `out_var`: the output operand.
    /// - `out_type`: the p-code type of the output value.
    /// - `l_val`: the left operand.
    /// - `l_type`: the p-code type of the left operand.
    /// - `r_val`: the right operand.
    /// - `r_type`: the p-code type of the right operand.
    /// - `scope`: a scope for generating temporary local storage.
    ///
    /// # Returns
    ///
    /// The emitter typed with the incoming stack, unchanged.
    #[allow(clippy::too_many_arguments)]
    fn gen_shift_prim_mp<G, LT, LJT, N>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &G,
        out_var: &dyn JitOutVar,
        out_type: LJT,
        l_val: &dyn JitVal,
        l_type: LJT,
        r_val: &dyn JitVal,
        r_type: MpIntJitType,
        scope: &dyn Scope,
    ) -> Emitter<N>
    where
        G: JitCodeGenerator,
        LT: BPrim,
        LJT: SimpleJitType<B = LT>,
        N: Next,
    {
        let em = gen.gen_read_to_stack(em, local_this, l_val, l_type, self.ext());
        let em = gen.gen_read_to_array(
            em,
            local_this,
            r_val,
            r_type,
            self.int_shift_bin_op_gen_r_ext(),
            scope,
            0,
        );
        // Op::invokestatic to JitCompiledPassage.<method_name()>, per Methods.Inv's
        // takeArg/takeArg/ret steps, is not yet ported; see the module docs. It replaces the
        // pushed primitive and array with a single LT-typed result.
        let em: Emitter<Ent<N, LT>> = em.recast();
        gen.gen_write_from_stack(em, local_this, out_var, out_type, self.ext(), scope)
    }

    /// The implementation when both operands are mp-ints.
    ///
    /// Port of `IntShiftBinOpGen.genShiftMpMp`. See the [module docs](self) on what is and is not
    /// modeled: the operand read/write plumbing and the output array's leg count/size are real;
    /// the array allocation and the invocation of the named `JitCompiledPassage` method are
    /// stubbed.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack.
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `gen`: the code generator.
    /// - `out_var`: the output operand.
    /// - `out_type`: the p-code type of the output value.
    /// - `l_val`: the left operand.
    /// - `l_type`: the p-code type of the left operand.
    /// - `r_val`: the right operand.
    /// - `r_type`: the p-code type of the right operand.
    /// - `scope`: a scope for generating temporary local storage.
    ///
    /// # Returns
    ///
    /// The emitter typed with the incoming stack, unchanged.
    #[allow(clippy::too_many_arguments)]
    fn gen_shift_mp_mp<G, N>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &G,
        out_var: &dyn JitOutVar,
        out_type: MpIntJitType,
        l_val: &dyn JitVal,
        l_type: MpIntJitType,
        r_val: &dyn JitVal,
        r_type: MpIntJitType,
        scope: &dyn Scope,
    ) -> Emitter<N>
    where
        G: JitCodeGenerator,
        N: Next,
    {
        // Port of `outType.legsAlloc()`/`outType.size()`: the real, testable part of the output
        // `int[]` allocation. See the module docs on why the allocation opcodes themselves are
        // not modeled.
        let _legs_alloc = out_type.legs_alloc();
        let _size = out_type.size;
        let em = gen.gen_read_to_array(em, local_this, l_val, l_type, self.ext(), scope, 0);
        let em =
            gen.gen_read_to_array(em, local_this, r_val, r_type, self.int_shift_bin_op_gen_r_ext(), scope, 0);
        // Op::invokestatic to JitCompiledPassage.<method_name()>, per Methods.Inv's four
        // takeArg/retVoid steps, is not yet ported; see the module docs. See gen_shift_mp_prim on
        // why the stack shape reduces to a single `int[]` reference afterward.
        let em: Emitter<Ent<N, TRef>> = em.recast();
        gen.gen_write_from_array(em, local_this, out_var, out_type, self.ext(), scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_type::IntJitType;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::emu::jit::gen::util::types::TInt;
    use crate::pcode::seam_stubs::{JitDefOp, JitTypeBehavior, MethodVisitor, OpGen, };
use crate::pcode::emu::jit::op::JitOp;
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
            4
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

    struct TestIntBinOp;

    impl JitOp for TestIntBinOp {
        fn type_for(&self, _position: i32) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
        fn link(&self) {}
        fn unlink(&self) {}
    }

    impl JitDefOp for TestIntBinOp {
        fn out(&self) -> Arc<dyn crate::pcode::seam_stubs::JitOutVar> {
            Arc::new(MockOutVar)
        }
    }

    impl crate::pcode::seam_stubs::JitBinOp for TestIntBinOp {
        fn l(&self) -> Box<dyn JitVal> {
            Box::new(MockVal)
        }
        fn r(&self) -> Box<dyn JitVal> {
            Box::new(MockVal)
        }
        fn l_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
        fn r_type(&self) -> JitTypeBehavior {
            JitTypeBehavior::Integer
        }
    }

    impl JitIntBinOp for TestIntBinOp {}

    struct MockCodeGenerator;
    impl JitCodeGenerator for MockCodeGenerator {}

    struct MockScope;
    impl Scope for MockScope {}

    /// A stand-in for a concrete generator such as Java's `IntLeftOpGen`: signed, invoking
    /// `JitCompiledPassage.intLeft`.
    struct LeftGen;
    impl OpGen<TestIntBinOp> for LeftGen {}
    impl BinOpGen<TestIntBinOp> for LeftGen {
        fn is_signed(&self) -> bool {
            true
        }

        fn r_ext(&self) -> Ext {
            self.int_shift_bin_op_gen_r_ext()
        }
    }
    impl IntShiftBinOpGen<TestIntBinOp> for LeftGen {
        fn method_name(&self) -> &str {
            "intLeft"
        }
    }

    #[test]
    fn method_name_is_the_abstract_java_method() {
        // Java: `String methodName()` has no default -- each concrete generator names the
        // `JitCompiledPassage` static method it invokes.
        assert_eq!(LeftGen.method_name(), "intLeft");
    }

    #[test]
    fn r_ext_is_always_zero_regardless_of_signedness_like_java_default_method() {
        // Java: `default Ext rExt() { return Ext.ZERO; }` -- the shift amount is always treated
        // unsigned, even for a signed shift operator (e.g. arithmetic right-shift).
        assert_eq!(LeftGen.int_shift_bin_op_gen_r_ext(), Ext::Zero);
        assert_eq!(BinOpGen::r_ext(&LeftGen), Ext::Zero);
        // ...unlike `ext()`, which still reflects `isSigned()`.
        assert_eq!(LeftGen.ext(), Ext::Sign);
    }

    #[test]
    fn gen_shift_prim_prim_reads_both_operands_and_writes_the_result_preserving_the_stack() {
        // Java: `genShiftPrimPrim` is typed `Emitter<N> -> Emitter<N>`: it reads both operands
        // onto the stack, replaces them with the static method's result, and writes that result
        // back out, leaving the incoming stack tail untouched. Exercise this with a non-trivial
        // tail (`TRef` on `Bot`) to confirm the shape is generic in `N`, not hardcoded to `Bot`.
        type Tail = Ent<Bot, TRef>;
        let em: Emitter<Tail> = Emitter::new(MethodVisitor::new());
        let local_this = Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0);
        let code_gen = MockCodeGenerator;
        let scope = MockScope;

        let result: Emitter<Tail> = LeftGen.gen_shift_prim_prim(
            em,
            &local_this,
            &code_gen,
            &MockOutVar,
            IntJitType::I4,
            &MockVal,
            IntJitType::I4,
            &MockVal,
            IntJitType::I4,
            &scope,
        );
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn gen_shift_mp_prim_computes_the_output_legs_and_preserves_the_stack() {
        // Java: `MpIntJitType.legsAlloc()`/`.size()` for a 9-byte mp-int are 3 and 9
        // (already tested on `MpIntJitType` itself); `genShiftMpPrim` uses both to allocate the
        // output array before reading the operands and invoking the shift method.
        let out_type = MpIntJitType::for_size(9);
        assert_eq!(out_type.legs_alloc(), 3);
        assert_eq!(out_type.size, 9);

        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0);
        let code_gen = MockCodeGenerator;
        let scope = MockScope;

        let result = LeftGen.gen_shift_mp_prim(
            em,
            &local_this,
            &code_gen,
            &MockOutVar,
            out_type.clone(),
            &MockVal,
            out_type,
            &MockVal,
            IntJitType::I4,
            &scope,
        );
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn gen_shift_prim_mp_reads_both_operands_and_preserves_the_stack() {
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0);
        let code_gen = MockCodeGenerator;
        let scope = MockScope;

        let result = LeftGen.gen_shift_prim_mp(
            em,
            &local_this,
            &code_gen,
            &MockOutVar,
            IntJitType::I4,
            &MockVal,
            IntJitType::I4,
            &MockVal,
            MpIntJitType::for_size(9),
            &scope,
        );
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn gen_shift_mp_mp_computes_the_output_legs_and_preserves_the_stack() {
        let out_type = MpIntJitType::for_size(9);
        assert_eq!(out_type.legs_alloc(), 3);

        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0);
        let code_gen = MockCodeGenerator;
        let scope = MockScope;

        let result = LeftGen.gen_shift_mp_mp(
            em,
            &local_this,
            &code_gen,
            &MockOutVar,
            out_type.clone(),
            &MockVal,
            out_type.clone(),
            &MockVal,
            out_type,
            &scope,
        );
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn int_shift_bin_op_gen_extends_bin_op_gen_like_java_interface() {
        // Java: `interface IntShiftBinOpGen<T extends JitIntBinOp> extends BinOpGen<T>`.
        fn assert_is_bin_op_gen<G: BinOpGen<TestIntBinOp>>(_gen: &G) {}
        assert_is_bin_op_gen(&LeftGen);
        assert!(LeftGen.is_signed());
    }
}
