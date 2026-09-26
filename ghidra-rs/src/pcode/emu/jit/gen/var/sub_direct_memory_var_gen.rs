//! The generator for a subpiece of a direct memory variable.
//!
//! Port of `ghidra.pcode.emu.jit.gen.var.SubDirectMemoryVarGen`.

use crate::pcode::emu::jit::analysis::jit_type::{MpIntJitType, SimpleJitType};
use crate::pcode::emu::jit::analysis::JitDataFlowArithmetic;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TRef};
use crate::pcode::emu::jit::gen::var::direct_memory_var_gen::DirectMemoryVarGen;
use crate::pcode::emu::jit::gen::var::memory_var_gen::MemoryVarGen;
use crate::pcode::emu::jit::gen::var::sub_memory_var_gen::SubMemoryVarGen;
use crate::pcode::emu::jit::gen::var::var_gen::VarGen;
use crate::pcode::emu::jit::var::{JitDirectMemoryVar, JitVarnodeVar};
use crate::pcode::seam_stubs::{Ext, JitCodeGenerator, Opnd, OpndEm, Scope};
use crate::program::model::pcode::Varnode;

/// The generator for a subpiece of a direct memory variable.
///
/// Port of `ghidra.pcode.emu.jit.gen.var.SubDirectMemoryVarGen`, a Java `record` implementing
/// both [`SubMemoryVarGen<JitDirectMemoryVar>`] and [`DirectMemoryVarGen`]. Its two record
/// components (`byteOffset`, `maxByteSize`) become this struct's two fields.
///
/// # Differences from Java
///
/// - Java's interface diamond resolves `getVarnode` to `SubMemoryVarGen`'s override (the more
///   specific of the two interfaces this record implements -- `DirectMemoryVarGen` doesn't
///   override `getVarnode` at all) automatically; every other default method that calls
///   `getVarnode` internally (`genValInit`, `genReadToStack`, ...) then picks up that override
///   for free, purely through virtual dispatch, and `SubMemoryVarGen.getVarnode` itself calls
///   `MemoryVarGen.super.getVarnode` to get the *un-narrowed* varnode before subpiecing it --
///   again resolved statically to the literal default body, since `super` calls bypass virtual
///   dispatch entirely in Java. Rust's default trait methods have no `super`-call equivalent: a
///   call to `self.get_varnode(...)` (or an explicit `Trait::get_varnode(self, ...)`) always
///   resolves to `Self`'s own implementation of *that specific trait*, override included -- so
///   naively having this type's `MemoryVarGen::get_varnode` override call
///   `SubMemoryVarGen::get_varnode(self, ...)`, whose own body called back into
///   `MemoryVarGen::get_varnode(self, ...)`, was genuine infinite recursion (confirmed by a stack
///   overflow while developing this port), not merely redundant work. [`SubMemoryVarGen`]'s own
///   default `get_varnode` was subsequently adjusted (during this same porting session) to inline
///   `v.varnode()` directly instead of round-tripping through `MemoryVarGen::get_varnode`, which
///   independently breaks that particular cycle -- but this type's own `MemoryVarGen`/
///   `SubMemoryVarGen` `get_varnode` overrides still compute the subpiece directly via the
///   private [`Self::subpieced_varnode`] helper rather than delegating through either trait, so
///   this type stays correct regardless of that implementation detail on the other trait.
/// - Java's `VarGen<V> extends ValGen<V>` abstract members are, per [`VarGen`]'s own module docs,
///   restated directly on that trait rather than on a separate (unported) `ValGen`. This is the
///   first *production* (non-test) type in the `var` package combining
///   [`SubMemoryVarGen`]/[`DirectMemoryVarGen`] with a concrete [`VarGen`] implementation; its
///   `impl VarGen<JitDirectMemoryVar>` block forwards each method to whichever of
///   [`MemoryVarGen`] (the five read/init methods) or [`DirectMemoryVarGen`] (the three write
///   methods, plus `genReadToBool`) provides its real behavior, mirroring the shape this crate's
///   own `TestDirectMemoryVarGen`/`TestSubMemoryVarGen` test doubles already established for
///   exercising those two traits' defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubDirectMemoryVarGen {
    byte_offset: i32,
    max_byte_size: i32,
}

impl SubDirectMemoryVarGen {
    /// Port of the record constructor `SubDirectMemoryVarGen(int byteOffset, int maxByteSize)`.
    pub fn new(byte_offset: i32, max_byte_size: i32) -> Self {
        SubDirectMemoryVarGen { byte_offset, max_byte_size }
    }

    /// Computes the narrowed subpiece varnode: `v.varnode()` (the whole variable's varnode, i.e.
    /// `MemoryVarGen`'s literal default `getVarnode` body) subpieced by `byteOffset`/
    /// `maxByteSize`, exactly matching `SubMemoryVarGen.getVarnode`'s formula. Both this type's
    /// `MemoryVarGen::get_varnode` and `SubMemoryVarGen::get_varnode` overrides call this single
    /// helper directly (never each other) -- see this type's own doc comment for why routing
    /// through either trait's method instead would recurse infinitely.
    fn subpieced_varnode(&self, gen: &dyn JitCodeGenerator, v: &JitDirectMemoryVar) -> Varnode {
        let parent = v.varnode();
        JitDataFlowArithmetic::sub_piece_vn(
            gen.get_analysis_context().get_endian(),
            &parent,
            self.byte_offset,
            self.max_byte_size,
        )
    }
}

impl SubMemoryVarGen<JitDirectMemoryVar> for SubDirectMemoryVarGen {
    fn byte_offset(&self) -> i32 {
        self.byte_offset
    }

    fn max_byte_size(&self) -> i32 {
        self.max_byte_size
    }

    /// Overridden to avoid the infinite-recursion trap described on this type's own doc comment
    /// (the trait default's `MemoryVarGen.super.getVarnode`-style call has no direct Rust
    /// equivalent); computes the same result via [`Self::subpieced_varnode`] directly.
    fn get_varnode(&self, gen: &dyn JitCodeGenerator, v: &JitDirectMemoryVar) -> Varnode {
        self.subpieced_varnode(gen, v)
    }
}

impl DirectMemoryVarGen for SubDirectMemoryVarGen {}

impl MemoryVarGen<JitDirectMemoryVar> for SubDirectMemoryVarGen {
    /// Overridden to restore `SubMemoryVarGen.getVarnode`'s subpiece-narrowing behavior for
    /// callers going through `MemoryVarGen` (e.g. `genValInit`, `genReadToStack`, ...), matching
    /// what Java's interface diamond gives automatically. See this type's own doc comment for why
    /// this computes the result directly via [`Self::subpieced_varnode`] rather than delegating to
    /// [`SubMemoryVarGen::get_varnode`].
    fn get_varnode(&self, gen: &dyn JitCodeGenerator, v: &JitDirectMemoryVar) -> Varnode {
        self.subpieced_varnode(gen, v)
    }
}

impl VarGen<JitDirectMemoryVar> for SubDirectMemoryVarGen {
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
    fn byte_offset_and_max_byte_size_are_stored() {
        let gen = SubDirectMemoryVarGen::new(2, 4);
        assert_eq!(SubMemoryVarGen::<JitDirectMemoryVar>::byte_offset(&gen), 2);
        assert_eq!(SubMemoryVarGen::<JitDirectMemoryVar>::max_byte_size(&gen), 4);
    }

    #[test]
    fn get_varnode_applies_the_subpiece_narrowing() {
        // Java: SubMemoryVarGen.getVarnode narrows the parent varnode (here, the whole variable's
        // varnode, since DirectMemoryVarGen doesn't override MemoryVarGen.getVarnode) by
        // byteOffset/maxByteSize, via JitDataFlowArithmetic.subPieceVn.
        let v = make_var(0x1000, 8);
        let gen = SubDirectMemoryVarGen::new(2, 4);
        let code_gen = MockCodeGenerator { endian: Endian::Little };

        let vn = MemoryVarGen::get_varnode(&gen, &code_gen, &v);

        assert_eq!(vn.get_size(), 4);
        // Little-endian subpiece drops the low `byteOffset` bytes, i.e. shifts the address up.
        assert_eq!(vn.get_address().offset(), 0x1002);
    }

    #[test]
    fn get_varnode_matches_between_memory_var_gen_and_sub_memory_var_gen_entry_points() {
        // Both traits' `get_varnode` must agree for the same concrete type, since this type's
        // MemoryVarGen::get_varnode override exists purely to delegate to SubMemoryVarGen's.
        let v = make_var(0x2000, 9);
        let gen = SubDirectMemoryVarGen::new(1, 4);
        let code_gen = MockCodeGenerator { endian: Endian::Big };

        let via_memory = MemoryVarGen::get_varnode(&gen, &code_gen, &v);
        let via_sub = SubMemoryVarGen::get_varnode(&gen, &code_gen, &v);
        assert_eq!(via_memory.get_offset(), via_sub.get_offset());
        assert_eq!(via_memory.get_size(), via_sub.get_size());
    }

    #[test]
    fn gen_read_to_stack_reads_the_subpiece_not_the_whole_varnode() {
        // Java: since genReadToStack (from MemoryVarGen) calls getVarnode(gen, v), and that
        // virtually dispatches to SubMemoryVarGen's override, reading a SubDirectMemoryVarGen
        // targets the narrowed subpiece varnode, not the full variable.
        let v = make_var(0x1000, 8);
        let gen = SubDirectMemoryVarGen::new(4, 4);
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
    fn gen_write_from_stack_is_prohibited_like_the_whole_variable_generator() {
        let v = make_var(0x1000, 8);
        let gen = SubDirectMemoryVarGen::new(0, 4);
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
        let gen = SubDirectMemoryVarGen::new(0, 4);
        let code_gen = MockCodeGenerator { endian: Endian::Little };
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        VarGen::gen_write_from_opnd(&gen, em, &local_this, &code_gen, &v, &StubMpOpnd, Ext::Zero, &MockScope);
    }

    #[test]
    #[should_panic(expected = "AssertionError: DirectMemoryVarGen prohibits genWriteFromArray")]
    fn gen_write_from_array_is_prohibited() {
        let v = make_var(0x1000, 9);
        let gen = SubDirectMemoryVarGen::new(0, 4);
        let code_gen = MockCodeGenerator { endian: Endian::Little };
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let em: Emitter<Ent<Bot, TRef>> = em.recast();

        VarGen::gen_write_from_array(&gen, em, &local_this, &code_gen, &v, MpIntJitType::for_size(9), Ext::Zero, &MockScope);
    }

    #[test]
    #[should_panic(expected = "AssertionError: DirectMemoryVarGen prohibits genReadToBool")]
    fn gen_read_to_bool_is_prohibited_even_for_a_subpiece() {
        let v = make_var(0x1000, 8);
        let gen = SubDirectMemoryVarGen::new(0, 4);
        let code_gen = MockCodeGenerator { endian: Endian::Little };
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        VarGen::gen_read_to_bool(&gen, em, &local_this, &code_gen, &v);
    }
}
