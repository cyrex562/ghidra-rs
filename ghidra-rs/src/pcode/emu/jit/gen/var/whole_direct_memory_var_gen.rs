//! The generator for a (whole) direct memory variable.
//!
//! Port of `ghidra.pcode.emu.jit.gen.var.WholeDirectMemoryVarGen`.

use crate::pcode::emu::jit::analysis::jit_type::{MpIntJitType, SimpleJitType};
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TRef};
use crate::pcode::emu::jit::gen::var::direct_memory_var_gen::DirectMemoryVarGen;
use crate::pcode::emu::jit::gen::var::memory_var_gen::MemoryVarGen;
use crate::pcode::emu::jit::gen::var::sub_direct_memory_var_gen::SubDirectMemoryVarGen;
use crate::pcode::emu::jit::gen::var::var_gen::VarGen;
use crate::pcode::emu::jit::var::JitDirectMemoryVar;
use crate::pcode::seam_stubs::{Ext, JitCodeGenerator, Opnd, OpndEm, Scope};

/// The generator for a (whole) direct memory variable.
///
/// Port of `ghidra.pcode.emu.jit.gen.var.WholeDirectMemoryVarGen`, a Java `enum` with a single
/// `GEN` singleton implementing `DirectMemoryVarGen`. Ported as a unit struct with a `GEN`
/// constant standing in for the enum constant, matching how Java code reaches it
/// (`WholeDirectMemoryVarGen.GEN`).
///
/// # Differences from Java
///
/// - `subpiece(int, int)` is a real, non-defaulted override in Java
///   (`@Override public ValGen<JitDirectMemoryVar> subpiece(...)  { return new
///   SubDirectMemoryVarGen(byteOffset, maxByteSize); }`), but its body is now *exactly*
///   [`DirectMemoryVarGen::subpiece`]'s own default (see that method's doc comment for why the
///   default was written this way in the first place -- this type is precisely the case it was
///   generalized from). This type does not need to override it at all; it is listed here as an
///   explicit `impl` item purely for discoverability/faithfulness to the Java source structure,
///   not because the behavior differs from the trait default.
/// - Every other method ([`MemoryVarGen::get_varnode`], and the [`VarGen`] read/write methods)
///   uses the unmodified defaults: unlike
///   [`SubDirectMemoryVarGen`](crate::pcode::emu::jit::gen::var::sub_direct_memory_var_gen::SubDirectMemoryVarGen),
///   this type has no narrowing to apply -- it generates code for the *whole* variable's varnode,
///   which is exactly `MemoryVarGen`'s literal default `getVarnode` body (`v.varnode()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct WholeDirectMemoryVarGen;

impl WholeDirectMemoryVarGen {
    /// The singleton instance, mirroring the Java enum constant `WholeDirectMemoryVarGen.GEN`.
    pub const GEN: WholeDirectMemoryVarGen = WholeDirectMemoryVarGen;
}

impl MemoryVarGen<JitDirectMemoryVar> for WholeDirectMemoryVarGen {}

impl DirectMemoryVarGen for WholeDirectMemoryVarGen {
    /// Port of `WholeDirectMemoryVarGen.subpiece(int, int)`. See this type's own doc comment: this
    /// override's body is identical to [`DirectMemoryVarGen::subpiece`]'s default.
    fn subpiece(&self, byte_offset: i32, max_byte_size: i32) -> SubDirectMemoryVarGen {
        SubDirectMemoryVarGen::new(byte_offset, max_byte_size)
    }
}

impl VarGen<JitDirectMemoryVar> for WholeDirectMemoryVarGen {
    fn gen_val_init<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &JitDirectMemoryVar,
    ) -> Emitter<N> {
        MemoryVarGen::gen_val_init(self, em, local_this, gen, v)
    }

    fn gen_read_to_stack<JT, N>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &JitDirectMemoryVar,
        type_: JT,
        ext: Ext,
    ) -> Emitter<Ent<N, JT::B>>
    where
        JT: SimpleJitType,
        N: Next,
    {
        MemoryVarGen::gen_read_to_stack(self, em, local_this, gen, v, type_, ext)
    }

    fn gen_read_to_opnd<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &JitDirectMemoryVar,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
    ) -> OpndEm<MpIntJitType, N> {
        MemoryVarGen::gen_read_to_opnd(self, em, local_this, gen, v, type_, ext, scope)
    }

    fn gen_read_leg_to_stack<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &JitDirectMemoryVar,
        type_: MpIntJitType,
        leg: i32,
        ext: Ext,
    ) -> Emitter<Ent<N, TInt>> {
        MemoryVarGen::gen_read_leg_to_stack(self, em, local_this, gen, v, type_, leg, ext)
    }

    fn gen_read_to_array<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &JitDirectMemoryVar,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
        slack: i32,
    ) -> Emitter<Ent<N, TRef>> {
        MemoryVarGen::gen_read_to_array(self, em, local_this, gen, v, type_, ext, scope, slack)
    }

    fn gen_read_to_bool<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &JitDirectMemoryVar,
    ) -> Emitter<Ent<N, TInt>> {
        DirectMemoryVarGen::gen_read_to_bool(self, em, local_this, gen, v)
    }

    fn gen_write_from_stack<JT, N1>(
        &self,
        em: Emitter<Ent<N1, JT::B>>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &JitDirectMemoryVar,
        type_: JT,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N1>
    where
        JT: SimpleJitType,
        N1: Next,
    {
        DirectMemoryVarGen::gen_write_from_stack(self, em, local_this, gen, v, type_, ext, scope)
    }

    fn gen_write_from_opnd<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &JitDirectMemoryVar,
        opnd: &dyn Opnd<MpIntJitType>,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N> {
        DirectMemoryVarGen::gen_write_from_opnd(self, em, local_this, gen, v, opnd, ext, scope)
    }

    fn gen_write_from_array<N1: Next>(
        &self,
        em: Emitter<Ent<N1, TRef>>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &JitDirectMemoryVar,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N1> {
        DirectMemoryVarGen::gen_write_from_array(self, em, local_this, gen, v, type_, ext, scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_analysis_context::JitAnalysisContext;
    use crate::pcode::emu::jit::analysis::jit_type::IntJitType;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::seam_stubs::{FieldForArrDirect, MethodVisitor, StubMpOpnd};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::Endian;
    use crate::program::model::pcode::Varnode;

    struct MockCodeGenerator {
        endian: Endian,
    }

    impl JitCodeGenerator for MockCodeGenerator {
        fn get_analysis_context(&self) -> JitAnalysisContext {
            JitAnalysisContext::for_endian(self.endian)
        }

        fn request_field_for_arr_direct(&self, _space: &AddressSpace, offset: i64) -> FieldForArrDirect {
            FieldForArrDirect { offset }
        }
    }

    struct MockScope;
    impl Scope for MockScope {}

    fn make_local_this() -> Local<TRef> {
        Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0)
    }

    fn make_var(offset: i64, size: i32) -> JitDirectMemoryVar {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, offset);
        JitDirectMemoryVar::new(1, Varnode::new(addr, size))
    }

    #[test]
    fn subpiece_returns_a_sub_direct_memory_var_gen_with_the_given_bounds() {
        let sub = WholeDirectMemoryVarGen::GEN.subpiece(2, 4);
        assert_eq!(sub, SubDirectMemoryVarGen::new(2, 4));
    }

    #[test]
    fn get_varnode_uses_the_whole_variables_varnode_unmodified() {
        // Java: WholeDirectMemoryVarGen does not override getVarnode, so it keeps MemoryVarGen's
        // literal default (`v.varnode()`) -- unlike SubDirectMemoryVarGen, which narrows it.
        let v = make_var(0x1000, 8);
        let gen = WholeDirectMemoryVarGen::GEN;
        let code_gen = MockCodeGenerator { endian: Endian::Little };

        let vn = MemoryVarGen::get_varnode(&gen, &code_gen, &v);

        assert_eq!(vn.get_size(), 8);
        assert_eq!(vn.get_address().offset(), 0x1000);
    }

    #[test]
    fn gen_read_to_stack_reads_the_whole_varnode() {
        let v = make_var(0x1000, 4);
        let gen = WholeDirectMemoryVarGen::GEN;
        let code_gen = MockCodeGenerator { endian: Endian::Little };
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        let result: Emitter<Ent<Bot, TInt>> = MemoryVarGen::gen_read_to_stack(
            &gen,
            em,
            &local_this,
            &code_gen,
            &v,
            IntJitType::I4,
            Ext::Zero,
        );
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    #[should_panic(expected = "AssertionError: DirectMemoryVarGen prohibits genWriteFromStack")]
    fn gen_write_from_stack_is_prohibited() {
        let v = make_var(0x1000, 4);
        let gen = WholeDirectMemoryVarGen::GEN;
        let code_gen = MockCodeGenerator { endian: Endian::Little };
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let em: Emitter<Ent<Bot, TInt>> = em.recast();

        VarGen::gen_write_from_stack(&gen, em, &local_this, &code_gen, &v, IntJitType::I4, Ext::Zero, &MockScope);
    }

    #[test]
    #[should_panic(expected = "AssertionError: DirectMemoryVarGen prohibits genWriteFromOpnd")]
    fn gen_write_from_opnd_is_prohibited() {
        let v = make_var(0x1000, 9);
        let gen = WholeDirectMemoryVarGen::GEN;
        let code_gen = MockCodeGenerator { endian: Endian::Little };
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        VarGen::gen_write_from_opnd(&gen, em, &local_this, &code_gen, &v, &StubMpOpnd, Ext::Zero, &MockScope);
    }

    #[test]
    #[should_panic(expected = "AssertionError: DirectMemoryVarGen prohibits genWriteFromArray")]
    fn gen_write_from_array_is_prohibited() {
        let v = make_var(0x1000, 9);
        let gen = WholeDirectMemoryVarGen::GEN;
        let code_gen = MockCodeGenerator { endian: Endian::Little };
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let em: Emitter<Ent<Bot, TRef>> = em.recast();

        VarGen::gen_write_from_array(&gen, em, &local_this, &code_gen, &v, MpIntJitType::for_size(9), Ext::Zero, &MockScope);
    }

    #[test]
    #[should_panic(expected = "AssertionError: DirectMemoryVarGen prohibits genReadToBool")]
    fn gen_read_to_bool_is_prohibited() {
        let v = make_var(0x1000, 4);
        let gen = WholeDirectMemoryVarGen::GEN;
        let code_gen = MockCodeGenerator { endian: Endian::Little };
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        VarGen::gen_read_to_bool(&gen, em, &local_this, &code_gen, &v);
    }
}
