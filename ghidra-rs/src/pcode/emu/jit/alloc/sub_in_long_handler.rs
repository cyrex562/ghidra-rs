//! A handler for a p-code variable stored in part of a JVM `long`.
//!
//! Port of `ghidra.pcode.emu.jit.alloc.SubInLongHandler`.
//!
//! # Differences from Java
//!
//! - Java's two type parameters (`ST`, `SJT`, the sub variable's JVM/p-code type) and the fixed
//!   `SubVarHandler<ST, SJT, TLong, LongJitType>` supertrait arguments are all dropped: per
//!   [`SubVarHandler`]'s module docs, that trait already erases the containing variable's type
//!   (`WT`/`WJT`, here always `TLong`/`LongJitType`) through [`JvmLocal`](
//!   crate::pcode::emu::jit::alloc::jvm_local::JvmLocal), so there is nothing left for this trait
//!   to fix. It becomes a plain `trait SubInLongHandler: SubVarHandler`.
//! - `genLoadToBool` and `genStoreFromStack` override [`VarHandler`]'s abstract methods of the
//!   same name (inherited through [`SubVarHandler`]). Per the convention
//!   [`SubVarHandler`] already sets -- Rust cannot "override" a supertrait method by redeclaring
//!   it -- they are exposed here under distinct `sub_in_long_handler_*` names; a concrete
//!   implementor's own [`VarHandler`] impl should delegate to these.
//! - Both methods' real bodies are JVM bytecode built from `Op` (opcode emitters) and
//!   `Opnd`'s static `convert` dispatch, neither of which is ported (see the
//!   [`AlignedMpIntHandler`](crate::pcode::emu::jit::alloc::aligned_mp_int_handler)
//!   module docs for the same gap). Following that convention, the *values* Java's bytecode
//!   computes and pushes ([`SubVarHandler::long_mask`], [`SubVarHandler::bit_shift`]) are computed
//!   for real, and the emission itself collapses to [`Emitter::recast`], which is sound here since
//!   neither method's net JVM-stack shape depends on any runtime value.

use crate::pcode::emu::jit::alloc::sub_var_handler::SubVarHandler;
use crate::pcode::emu::jit::analysis::jit_type::SimpleJitType;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::types::{BPrim, TInt};
use crate::pcode::seam_stubs::{Ext, JitCodeGenerator, Scope};

/// A handler for a p-code variable stored in part of a JVM `long`.
///
/// Port of `ghidra.pcode.emu.jit.alloc.SubInLongHandler<ST, SJT>`. See the
/// [module docs](self) for what is erased and why.
pub trait SubInLongHandler: SubVarHandler {
    /// Emit bytecode to load the varnode's value, interpreted as a boolean, as an integer onto
    /// the JVM stack.
    ///
    /// Port of `SubInLongHandler.genLoadToBool`, which overrides `VarHandler.genLoadToBool`. See
    /// the [module docs](self) on why this is not named `gen_load_to_bool`.
    ///
    /// Java: `lload local(); ldc__l longMask(); land; ldc__l 0; lcmp` -- loads the containing
    /// local, masks off this sub variable's bits, and compares the result against zero, leaving
    /// one `int` on the stack.
    fn sub_in_long_handler_gen_load_to_bool<N: Next>(
        &self,
        em: Emitter<N>,
        gen: &dyn JitCodeGenerator,
    ) -> Emitter<Ent<N, TInt>>
    where
        Self: Sized,
    {
        let _ = (gen, self.local(), self.long_mask());
        em.recast()
    }

    /// Emit bytecode to store a value into a variable from the JVM stack.
    ///
    /// Port of `SubInLongHandler.genStoreFromStack`, which overrides
    /// `VarHandler.genStoreFromStack`. See the [module docs](self) on why this is not named
    /// `gen_store_from_stack`.
    ///
    /// Java: converts the incoming value to a `long` (`LongJitType.I8`), shifts it left by
    /// [`SubVarHandler::bit_shift`], masks it to this sub variable's bits, ORs in the unmasked
    /// bits of the containing local (`lload local(); land ~longMask()`), then stores the result
    /// back into the containing local -- popping the incoming value and leaving the stack
    /// otherwise unchanged.
    fn sub_in_long_handler_gen_store_from_stack<FT, FJT, N1>(
        &self,
        em: Emitter<Ent<N1, FT>>,
        gen: &dyn JitCodeGenerator,
        type_: FJT,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N1>
    where
        FT: BPrim,
        FJT: SimpleJitType<B = FT>,
        N1: Next,
        Self: Sized,
    {
        let _ = (gen, type_, ext, scope, self.local(), self.bit_shift(), self.long_mask());
        em.recast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::alloc::jvm_local::JvmLocal;
    use crate::pcode::emu::jit::alloc::var_handler::VarHandler;
    use crate::pcode::emu::jit::analysis::jit_type::{AnyJitType, IntJitType, JitType, LongJitType};
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::emu::jit::gen::util::types::{TRef, T_INT};
    use crate::pcode::seam_stubs::{MethodVisitor, MpToStackConv, Opnd, OpndEm};
    use crate::pcode::emu::jit::analysis::jit_type::MpIntJitType;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::pcode::Varnode;

    fn make_varnode(offset: i64, size: i32) -> Varnode {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, offset);
        Varnode::new(addr, size)
    }

    struct MockCodeGenerator;
    impl JitCodeGenerator for MockCodeGenerator {}

    struct MockScope;
    impl Scope for MockScope {}

    struct TestConv;

    impl MpToStackConv for TestConv {
        fn convert_opnd_to_stack<TT: BPrim, TJT: SimpleJitType<B = TT>, N: Next>(
            &self,
            em: Emitter<N>,
            _from: &dyn Opnd<MpIntJitType>,
            _to: TJT,
            _ext: Ext,
        ) -> Emitter<Ent<N, TT>> {
            em.recast()
        }

        fn convert_array_to_stack<TT: BPrim, TJT: SimpleJitType<B = TT>, N: Next>(
            &self,
            em: Emitter<Ent<N, TRef>>,
            _from: MpIntJitType,
            _to: TJT,
            _ext: Ext,
        ) -> Emitter<Ent<N, TT>> {
            em.recast()
        }
    }

    /// A minimal implementor covering every abstract member of [`VarHandler`]/[`SubVarHandler`],
    /// mirroring
    /// [`sub_var_handler::tests::TestSubVarHandler`](
    /// crate::pcode::emu::jit::alloc::sub_var_handler::tests), fixed to a `long`-typed containing
    /// local as `SubInLongHandler` requires.
    struct TestSubInLongHandler {
        vn: Varnode,
        local: JvmLocal,
        sub_type: AnyJitType,
        byte_shift: i32,
    }

    impl VarHandler for TestSubInLongHandler {
        fn vn(&self) -> Varnode {
            self.vn.clone()
        }

        fn type_(&self) -> AnyJitType {
            self.sub_type.clone()
        }

        fn gen_load_to_stack<TT, TJT, N>(
            &self,
            em: Emitter<N>,
            _gen: &dyn JitCodeGenerator,
            _type_: TJT,
            _ext: Ext,
        ) -> Emitter<Ent<N, TT>>
        where
            TT: BPrim,
            TJT: SimpleJitType<B = TT>,
            N: Next,
        {
            em.recast()
        }

        fn gen_load_to_opnd<N: Next>(
            &self,
            em: Emitter<N>,
            gen: &dyn JitCodeGenerator,
            type_: MpIntJitType,
            ext: Ext,
            scope: &dyn Scope,
        ) -> OpndEm<MpIntJitType, N> {
            self.sub_var_handler_gen_load_to_opnd(em, gen, type_, ext, scope)
        }

        fn gen_load_leg_to_stack<N: Next>(
            &self,
            em: Emitter<N>,
            _gen: &dyn JitCodeGenerator,
            _type_: MpIntJitType,
            _leg: i32,
            _ext: Ext,
        ) -> Emitter<Ent<N, TInt>> {
            em.recast()
        }

        fn gen_load_to_array<N: Next>(
            &self,
            em: Emitter<N>,
            gen: &dyn JitCodeGenerator,
            type_: MpIntJitType,
            ext: Ext,
            scope: &dyn Scope,
            slack: i32,
        ) -> Emitter<Ent<N, TRef>> {
            self.sub_var_handler_gen_load_to_array(em, gen, type_, ext, scope, slack)
        }

        fn gen_load_to_bool<N: Next>(
            &self,
            em: Emitter<N>,
            gen: &dyn JitCodeGenerator,
        ) -> Emitter<Ent<N, TInt>> {
            self.sub_in_long_handler_gen_load_to_bool(em, gen)
        }

        fn gen_store_from_stack<FT, FJT, N1>(
            &self,
            em: Emitter<Ent<N1, FT>>,
            gen: &dyn JitCodeGenerator,
            type_: FJT,
            ext: Ext,
            scope: &dyn Scope,
        ) -> Emitter<N1>
        where
            FT: BPrim,
            FJT: SimpleJitType<B = FT>,
            N1: Next,
        {
            self.sub_in_long_handler_gen_store_from_stack(em, gen, type_, ext, scope)
        }

        fn gen_store_from_opnd<N: Next>(
            &self,
            em: Emitter<N>,
            gen: &dyn JitCodeGenerator,
            opnd: &dyn Opnd<MpIntJitType>,
            ext: Ext,
            scope: &dyn Scope,
        ) -> Emitter<N> {
            self.sub_var_handler_gen_store_from_opnd(em, gen, opnd, ext, scope)
        }

        fn gen_store_from_array<N1: Next>(
            &self,
            em: Emitter<Ent<N1, TRef>>,
            gen: &dyn JitCodeGenerator,
            type_: MpIntJitType,
            ext: Ext,
            scope: &dyn Scope,
        ) -> Emitter<N1> {
            self.sub_var_handler_gen_store_from_array(em, gen, type_, ext, scope)
        }

        fn subpiece(
            &self,
            _endian: Endian,
            _byte_offset: i32,
            _max_byte_size: i32,
        ) -> Box<dyn VarHandler> {
            unimplemented!("TestSubInLongHandler::subpiece is not exercised by these tests")
        }
    }

    impl SubVarHandler for TestSubInLongHandler {
        type ConvToSub = TestConv;

        fn byte_shift(&self) -> i32 {
            self.byte_shift
        }

        fn local(&self) -> JvmLocal {
            self.local.clone()
        }

        fn get_conv_to_sub(&self) -> TestConv {
            TestConv
        }
    }

    impl SubInLongHandler for TestSubInLongHandler {}

    fn handler(byte_shift: i32, sub_type: AnyJitType) -> TestSubInLongHandler {
        TestSubInLongHandler {
            vn: make_varnode(0x1000, sub_type.size()),
            local: JvmLocal::of(LongJitType::I8.erase_simple(), make_varnode(0x1000, 8)),
            sub_type,
            byte_shift,
        }
    }

    #[test]
    fn long_mask_used_by_gen_load_to_bool_matches_java_formula() {
        // Java: `(-1L >>> (Long.SIZE - bitSize())) << bitShift()`. A 2-byte (16-bit) sub variable
        // shifted right by 1 byte (8 bits) within the containing long covers bits [8, 24), i.e.
        // 0x00FFFF00 -- the exact mask `genLoadToBool`/`genStoreFromStack` AND against.
        let h = handler(1, AnyJitType::Int(IntJitType::I2));
        assert_eq!(h.long_mask(), 0x0000_0000_00FF_FF00i64);
    }

    #[test]
    fn bit_shift_used_by_gen_store_from_stack_matches_java_formula() {
        // Java: `byteShift() * Byte.SIZE`, the amount genStoreFromStack shifts the incoming value
        // left by before masking it into the containing long.
        let h = handler(1, AnyJitType::Int(IntJitType::I2));
        assert_eq!(h.bit_shift(), 8);
    }

    #[test]
    fn default_overrides_delegate_through_var_handler() {
        // Exercises sub_in_long_handler_gen_load_to_bool/gen_store_from_stack (via the VarHandler
        // methods that delegate to them above), ensuring the type-level stack-shape plumbing
        // compiles and runs without panicking, matching Java's default-method override wiring.
        let gen = MockCodeGenerator;
        let scope = MockScope;
        let h = handler(0, AnyJitType::Int(IntJitType::I2));

        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let _: Emitter<Ent<Bot, TInt>> = h.gen_load_to_bool(em, &gen);

        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let em: Emitter<Ent<Bot, TInt>> = em.recast();
        let _: Emitter<Bot> = h.gen_store_from_stack(em, &gen, IntJitType::I2, Ext::Zero, &scope);

        let _ = T_INT;
    }
}
