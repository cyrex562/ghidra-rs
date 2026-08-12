//! The generator for a memory output variable.
//!
//! Port of `ghidra.pcode.emu.jit.gen.var.MemoryOutVarGen`.
//!
//! # Differences from Java
//!
//! - Java's `<THIS extends JitCompiledPassage>` type parameter, repeated on every method, is
//!   dropped in favor of a non-generic `Local<TRef>` and `&dyn JitCodeGenerator`, matching the
//!   convention set by
//!   [`DirectMemoryVarGen`](crate::pcode::emu::jit::gen::var::direct_memory_var_gen::DirectMemoryVarGen).
//! - `genWriteFromStack`'s Java bound `<T extends BPrim<?>, JT extends SimpleJitType<T, JT>>`
//!   dispatches to the byte-order-specific [`SimpleAccessGen`] via an unchecked cast that Java's
//!   sealed `SimpleJitType` hierarchy justifies. As in
//!   [`MemoryVarGen::gen_read_to_stack`](crate::pcode::emu::jit::gen::var::memory_var_gen::MemoryVarGen)'s
//!   `gen_read_value_direct_to_stack` helper, Rust cannot recover a generic `JT` from
//!   [`lookup_simple`]'s erased return, so this erases `JT` (via [`SimpleJitType::erase_simple`])
//!   to perform the lookup, then [`Emitter::recast`]s the incoming stack (typed `Ent<N1, JT::B>`)
//!   down to the concrete accessor's expected `Ent<N1, T>` -- the same "trust the caller's static
//!   typing" contract `recast` already serves throughout this port. Only [`IntJitType`] and
//!   [`LongJitType`] currently have real `SimpleAccessGen` implementations; the `Float`/`Double`
//!   arms are unimplemented until `FloatAccessGen`/`DoubleAccessGen` grow one, exactly as for
//!   `MemoryVarGen`.
//! - `JitMemoryOutVar` (`ghidra.pcode.emu.jit.var.JitMemoryOutVar`) is not yet ported as a
//!   top-level module; its stub in [`seam_stubs`](crate::pcode::seam_stubs) was grown (see
//!   `STUBS.tsv`) with `JitVal`/`JitVar`/`JitVarnodeVar`/`JitMemoryVar` impls mirroring the real
//!   `JitMemoryOutVar extends AbstractJitOutVar implements JitMemoryVar`, enough to satisfy
//!   `MemoryVarGen`'s `V: JitVarnodeVar` bound -- as
//!   [`JitLocalOutVar`](crate::pcode::seam_stubs::JitLocalOutVar) already does for
//!   [`LocalOutVarGen`](crate::pcode::emu::jit::gen::var::local_out_var_gen::LocalOutVarGen).
//! - `VarGen<V>` (`ghidra.pcode.emu.jit.gen.var.VarGen`) is this file's forward reference in a
//!   dependency cycle among the `var` package's generators, exactly as for
//!   [`MemoryVarGen`](crate::pcode::emu::jit::gen::var::memory_var_gen::MemoryVarGen); its stub in
//!   [`seam_stubs`](crate::pcode::seam_stubs) already has the three write methods this type
//!   overrides.

use crate::pcode::emu::jit::op::JitOp;
use crate::pcode::emu::jit::analysis::jit_type::{MpIntJitType, SimpleJitType};
use crate::pcode::emu::jit::gen::access::access_gen::{lookup_mp, lookup_simple, AnySimpleAccessGen};
use crate::pcode::emu::jit::gen::access::mp_access_gen::MpAccessGen;
use crate::pcode::emu::jit::gen::access::simple_access_gen::SimpleAccessGen;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::TRef;
use crate::pcode::emu::jit::gen::var::memory_var_gen::MemoryVarGen;
use crate::pcode::seam_stubs::{Ext, JitCodeGenerator, JitMemoryOutVar, Opnd, Scope};

/// The generator for a memory output variable.
///
/// Port of `ghidra.pcode.emu.jit.gen.var.MemoryOutVarGen`. See the [module docs](self).
pub trait MemoryOutVarGen: MemoryVarGen<JitMemoryOutVar> {
    /// Port of `MemoryOutVarGen.genWriteFromStack`.
    fn gen_write_from_stack<JT, N1>(
        &self,
        em: Emitter<Ent<N1, JT::B>>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &JitMemoryOutVar,
        type_: JT,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N1>
    where
        JT: SimpleJitType,
        N1: Next,
    {
        let _ = (ext, scope);
        let vn = self.get_varnode(gen, v);
        let endian = gen.get_analysis_context().get_endian();
        match lookup_simple(endian, &type_.erase_simple()) {
            AnySimpleAccessGen::Int(g) => g.gen_write_from_stack(em.recast(), local_this, gen, &vn),
            AnySimpleAccessGen::Long(g) => g.gen_write_from_stack(em.recast(), local_this, gen, &vn),
            AnySimpleAccessGen::Float(_) => {
                unimplemented!("FloatAccessGen does not implement SimpleAccessGen yet")
            }
            AnySimpleAccessGen::Double(_) => {
                unimplemented!("DoubleAccessGen does not implement SimpleAccessGen yet")
            }
        }
    }

    /// Port of `MemoryOutVarGen.genWriteFromOpnd`.
    fn gen_write_from_opnd<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &JitMemoryOutVar,
        opnd: &dyn Opnd<MpIntJitType>,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N> {
        let _ = (ext, scope);
        let vn = self.get_varnode(gen, v);
        let endian = gen.get_analysis_context().get_endian();
        lookup_mp(endian).gen_write_from_opnd(em, local_this, gen, opnd, &vn)
    }

    /// Port of `MemoryOutVarGen.genWriteFromArray`.
    fn gen_write_from_array<N1: Next>(
        &self,
        em: Emitter<Ent<N1, TRef>>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &JitMemoryOutVar,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N1> {
        let _ = (type_, ext);
        let vn = self.get_varnode(gen, v);
        let endian = gen.get_analysis_context().get_endian();
        lookup_mp(endian).gen_write_from_array(em, local_this, gen, &vn, scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_type::IntJitType;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::emu::jit::gen::util::types::TInt;
    use crate::pcode::emu::jit::gen::var::var_gen::VarGen;
    use crate::pcode::seam_stubs::{
        FieldForArrDirect, JitAnalysisContext, MethodVisitor, OpndEm, StubMpOpnd,
    };
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::Endian;
    use crate::program::model::pcode::Varnode;

    struct MockCodeGenerator {
        endian: Endian,
    }

    impl JitCodeGenerator for MockCodeGenerator {
        fn get_analysis_context(&self) -> JitAnalysisContext {
            JitAnalysisContext::new(self.endian)
        }

        fn request_field_for_arr_direct(
            &self,
            _space: &AddressSpace,
            offset: i64,
        ) -> FieldForArrDirect {
            FieldForArrDirect { offset }
        }
    }

    struct MockScope;
    impl Scope for MockScope {}

    /// A minimal implementor exercising `MemoryOutVarGen`'s default methods, in the same spirit
    /// as `TestDirectMemoryVarGen` in
    /// [`direct_memory_var_gen`](super::super::direct_memory_var_gen)'s tests: the read methods
    /// delegate to `MemoryVarGen`, unchanged, while the write methods delegate to
    /// `MemoryOutVarGen`'s overrides.
    struct TestMemoryOutVarGen;

    impl VarGen<JitMemoryOutVar> for TestMemoryOutVarGen {
        fn gen_val_init<N: Next>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitMemoryOutVar,
        ) -> Emitter<N> {
            MemoryVarGen::gen_val_init(self, em, local_this, gen, v)
        }

        fn gen_read_to_stack<JT, N>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitMemoryOutVar,
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
            v: &JitMemoryOutVar,
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
            v: &JitMemoryOutVar,
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
            v: &JitMemoryOutVar,
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
            v: &JitMemoryOutVar,
        ) -> Emitter<Ent<N, TInt>> {
            MemoryVarGen::gen_read_to_bool(self, em, local_this, gen, v)
        }

        fn gen_write_from_stack<JT, N1>(
            &self,
            em: Emitter<Ent<N1, JT::B>>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitMemoryOutVar,
            type_: JT,
            ext: Ext,
            scope: &dyn Scope,
        ) -> Emitter<N1>
        where
            JT: SimpleJitType,
            N1: Next,
        {
            MemoryOutVarGen::gen_write_from_stack(self, em, local_this, gen, v, type_, ext, scope)
        }

        fn gen_write_from_opnd<N: Next>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitMemoryOutVar,
            opnd: &dyn Opnd<MpIntJitType>,
            ext: Ext,
            scope: &dyn Scope,
        ) -> Emitter<N> {
            MemoryOutVarGen::gen_write_from_opnd(self, em, local_this, gen, v, opnd, ext, scope)
        }

        fn gen_write_from_array<N1: Next>(
            &self,
            em: Emitter<Ent<N1, TRef>>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitMemoryOutVar,
            type_: MpIntJitType,
            ext: Ext,
            scope: &dyn Scope,
        ) -> Emitter<N1> {
            MemoryOutVarGen::gen_write_from_array(self, em, local_this, gen, v, type_, ext, scope)
        }
    }

    impl MemoryVarGen<JitMemoryOutVar> for TestMemoryOutVarGen {}
    impl MemoryOutVarGen for TestMemoryOutVarGen {}

    fn make_local_this() -> Local<TRef> {
        Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0)
    }

    fn make_var(id: i32, offset: i64, size: i32) -> JitMemoryOutVar {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, offset);
        JitMemoryOutVar::new(id, Varnode::new(addr, size))
    }

    #[test]
    fn gen_write_from_stack_delegates_to_the_endian_specific_int_accessor() {
        // Java: genWriteFromStack delegates to AccessGen.lookupSimple(endian,
        // type).genWriteFromStack(em, localThis, gen, getVarnode(gen, v)).
        let v = make_var(1, 0x1000, 4);
        let gen_impl = TestMemoryOutVarGen;
        let code_gen = MockCodeGenerator { endian: Endian::Big };
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let em: Emitter<Ent<Bot, TInt>> = em.recast();

        let result: Emitter<Bot> = MemoryOutVarGen::gen_write_from_stack(
            &gen_impl,
            em,
            &local_this,
            &code_gen,
            &v,
            IntJitType::I4,
            Ext::Zero,
            &MockScope,
        );
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    fn gen_write_from_opnd_delegates_to_the_endian_specific_mp_accessor() {
        // Java: genWriteFromOpnd delegates to AccessGen.lookupMp(endian).genWriteFromOpnd(em,
        // localThis, gen, opnd, getVarnode(gen, v)).
        let v = make_var(2, 0x1000, 9);
        let gen_impl = TestMemoryOutVarGen;
        let code_gen = MockCodeGenerator { endian: Endian::Little };
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        let result: Emitter<Bot> = MemoryOutVarGen::gen_write_from_opnd(
            &gen_impl,
            em,
            &local_this,
            &code_gen,
            &v,
            &StubMpOpnd,
            Ext::Zero,
            &MockScope,
        );
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    fn gen_write_from_array_delegates_to_the_endian_specific_mp_accessor() {
        // Java: genWriteFromArray delegates to AccessGen.lookupMp(endian).genWriteFromArray(em,
        // localThis, gen, getVarnode(gen, v), scope).
        let v = make_var(3, 0x1000, 9);
        let gen_impl = TestMemoryOutVarGen;
        let code_gen = MockCodeGenerator { endian: Endian::Little };
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let em: Emitter<Ent<Bot, TRef>> = em.recast();

        let result: Emitter<Bot> = MemoryOutVarGen::gen_write_from_array(
            &gen_impl,
            em,
            &local_this,
            &code_gen,
            &v,
            MpIntJitType::for_size(9),
            Ext::Zero,
            &MockScope,
        );
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    fn jit_memory_out_var_satisfies_jit_varnode_var() {
        // Java: JitMemoryOutVar(id, varnode) -> AbstractJitOutVar(id, varnode) ->
        // AbstractJitVarnodeVar(id, varnode) -- id is caller-supplied, size/space derived from
        // the varnode.
        use crate::pcode::emu::jit::var::{JitVar, JitVarnodeVar};

        let v = make_var(7, 0x2000, 4);
        assert_eq!(JitVar::id(&v), 7);
        assert_eq!(v.varnode().get_offset(), 0x2000);
        assert_eq!(JitVarnodeVar::size(&v), 4);
    }

    #[test]
    #[should_panic(expected = "AssertionError: JitMemoryOutVar.addUse")]
    fn jit_memory_out_var_add_use_is_prohibited() {
        // Java: JitMemoryOutVar.addUse unconditionally throws AssertionError, since these
        // variables are never used by downstream p-code ops.
        use crate::pcode::emu::jit::var::JitVal;

        let v = make_var(4, 0x1000, 4);
        struct FakeOp;
        impl JitOp for FakeOp {
            fn type_for(&self, _position: i32) -> crate::pcode::seam_stubs::JitTypeBehavior {
                unimplemented!()
            }
            fn link(&self) {}
            fn unlink(&self) {}
        }
        JitVal::add_use(&v, &FakeOp, 0);
    }
}
