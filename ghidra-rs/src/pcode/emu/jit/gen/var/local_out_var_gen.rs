//! The generator for a local variable that is defined within the passage.
//!
//! Port of `ghidra.pcode.emu.jit.gen.var.LocalOutVarGen`.
//!
//! # Differences from Java
//!
//! - Java's `<THIS extends JitCompiledPassage>` type parameter, repeated on every method, is
//!   dropped in favor of a non-generic `Local<TRef>` and `&dyn JitCodeGenerator`, matching the
//!   convention set by
//!   [`InputVarGen`](crate::pcode::emu::jit::gen::var::input_var_gen::InputVarGen).
//! - Java's three overrides all delegate to `getHandler(gen, v).genStoreFrom*(...)`. Per
//!   [`LocalVarGen`]'s module docs, [`VarHandler`](crate::pcode::emu::jit::alloc::var_handler::VarHandler)'s
//!   `gen_store_from_*` methods each carry a `where Self: Sized` bound (to keep the trait
//!   object-safe for `subpiece`'s `Box<dyn VarHandler>`), so none of them can be called through
//!   the `Box<dyn VarHandler>` that `get_handler` returns. These three overrides are therefore
//!   left `unimplemented!()`, exactly as `LocalVarGen`'s own `genReadTo*` defaults are, pending
//!   either a real `JitAllocationModel` port (with a way to recover the concrete handler type) or
//!   a dyn-safe store path on `VarHandler`.
//! - `JitLocalOutVar` (`ghidra.pcode.emu.jit.var.JitLocalOutVar`) is not yet ported; its stub in
//!   [`seam_stubs`](crate::pcode::seam_stubs) was grown (see `STUBS.tsv`) with `JitVar`/
//!   `JitVarnodeVar` impls mirroring the real `JitLocalOutVar extends AbstractJitOutVar extends
//!   AbstractJitVarnodeVar`, enough to satisfy `LocalVarGen`'s `V: JitVarnodeVar` bound -- as
//!   [`JitInputVar`](crate::pcode::seam_stubs::JitInputVar) already does for
//!   [`InputVarGen`](crate::pcode::emu::jit::gen::var::input_var_gen::InputVarGen). Unlike
//!   `JitInputVar`'s fixed `id` of `-1`, `JitLocalOutVar`'s `id` is caller-supplied, matching
//!   `AbstractJitOutVar`'s constructor. `AbstractJitOutVar`'s `definition` bookkeeping
//!   (`JitOutVar.setDefinition`/`definition`) is not modeled by the stub, since `LocalOutVarGen`
//!   never touches it.
//! - `VarGen<V>` (`ghidra.pcode.emu.jit.gen.var.VarGen`) is this file's forward reference in a
//!   dependency cycle among the `var` package's generators, exactly as for
//!   [`InputVarGen`](crate::pcode::emu::jit::gen::var::input_var_gen::InputVarGen); its stub in
//!   [`seam_stubs`](crate::pcode::seam_stubs) already has the three write methods this type
//!   overrides.

use crate::pcode::emu::jit::analysis::jit_type::{MpIntJitType, SimpleJitType};
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::TRef;
use crate::pcode::emu::jit::gen::var::local_var_gen::LocalVarGen;
use crate::pcode::seam_stubs::{Ext, JitCodeGenerator, JitLocalOutVar, Opnd, Scope};

/// The generator for a local variable that is defined within the passage.
///
/// Port of `ghidra.pcode.emu.jit.gen.var.LocalOutVarGen`. See the [module docs](self).
pub trait LocalOutVarGen: LocalVarGen<JitLocalOutVar> {
    /// Port of `LocalOutVarGen.genWriteFromStack`. See the [module docs](self) on why this cannot
    /// yet delegate to [`LocalVarGen::get_handler`] as Java does.
    fn gen_write_from_stack<JT, N1>(
        &self,
        _em: Emitter<Ent<N1, JT::B>>,
        _local_this: &Local<TRef>,
        _gen: &dyn JitCodeGenerator,
        _v: &JitLocalOutVar,
        _type_: JT,
        _ext: Ext,
        _scope: &dyn Scope,
    ) -> Emitter<N1>
    where
        JT: SimpleJitType,
        N1: Next,
    {
        unimplemented!(
            "LocalOutVarGen::gen_write_from_stack: VarHandler::gen_store_from_stack requires \
             Self: Sized, see module docs"
        )
    }

    /// Port of `LocalOutVarGen.genWriteFromOpnd`. See the [module docs](self) on why this cannot
    /// yet delegate to [`LocalVarGen::get_handler`] as Java does.
    fn gen_write_from_opnd<N: Next>(
        &self,
        _em: Emitter<N>,
        _local_this: &Local<TRef>,
        _gen: &dyn JitCodeGenerator,
        _v: &JitLocalOutVar,
        _opnd: &dyn Opnd<MpIntJitType>,
        _ext: Ext,
        _scope: &dyn Scope,
    ) -> Emitter<N> {
        unimplemented!(
            "LocalOutVarGen::gen_write_from_opnd: VarHandler::gen_store_from_opnd requires \
             Self: Sized, see module docs"
        )
    }

    /// Port of `LocalOutVarGen.genWriteFromArray`. See the [module docs](self) on why this cannot
    /// yet delegate to [`LocalVarGen::get_handler`] as Java does.
    fn gen_write_from_array<N1: Next>(
        &self,
        _em: Emitter<Ent<N1, TRef>>,
        _local_this: &Local<TRef>,
        _gen: &dyn JitCodeGenerator,
        _v: &JitLocalOutVar,
        _type_: MpIntJitType,
        _ext: Ext,
        _scope: &dyn Scope,
    ) -> Emitter<N1> {
        unimplemented!(
            "LocalOutVarGen::gen_write_from_array: VarHandler::gen_store_from_array requires \
             Self: Sized, see module docs"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_type::IntJitType;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::emu::jit::gen::util::types::TInt;
    use crate::pcode::seam_stubs::{MethodVisitor, OpndEm, StubMpOpnd, VarGen};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::Varnode;

    struct MockCodeGenerator;
    impl JitCodeGenerator for MockCodeGenerator {}

    struct MockScope;
    impl Scope for MockScope {}

    /// A minimal implementor exercising `LocalOutVarGen`'s default methods, in the same spirit as
    /// `TestInputVarGen` in
    /// [`input_var_gen`](super::super::input_var_gen)'s tests: the read methods delegate to
    /// `LocalVarGen`, unchanged, while the write methods delegate to `LocalOutVarGen`'s overrides.
    struct TestLocalOutVarGen;

    impl VarGen<JitLocalOutVar> for TestLocalOutVarGen {
        fn gen_val_init<N: Next>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitLocalOutVar,
        ) -> Emitter<N> {
            LocalVarGen::gen_val_init(self, em, local_this, gen, v)
        }

        fn gen_read_to_stack<JT, N>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitLocalOutVar,
            type_: JT,
            ext: Ext,
        ) -> Emitter<Ent<N, JT::B>>
        where
            JT: SimpleJitType,
            N: Next,
        {
            LocalVarGen::gen_read_to_stack(self, em, local_this, gen, v, type_, ext)
        }

        fn gen_read_to_opnd<N: Next>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitLocalOutVar,
            type_: MpIntJitType,
            ext: Ext,
            scope: &dyn Scope,
        ) -> OpndEm<MpIntJitType, N> {
            LocalVarGen::gen_read_to_opnd(self, em, local_this, gen, v, type_, ext, scope)
        }

        fn gen_read_leg_to_stack<N: Next>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitLocalOutVar,
            type_: MpIntJitType,
            leg: i32,
            ext: Ext,
        ) -> Emitter<Ent<N, TInt>> {
            LocalVarGen::gen_read_leg_to_stack(self, em, local_this, gen, v, type_, leg, ext)
        }

        fn gen_read_to_array<N: Next>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitLocalOutVar,
            type_: MpIntJitType,
            ext: Ext,
            scope: &dyn Scope,
            slack: i32,
        ) -> Emitter<Ent<N, TRef>> {
            LocalVarGen::gen_read_to_array(self, em, local_this, gen, v, type_, ext, scope, slack)
        }

        fn gen_read_to_bool<N: Next>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitLocalOutVar,
        ) -> Emitter<Ent<N, TInt>> {
            LocalVarGen::gen_read_to_bool(self, em, local_this, gen, v)
        }

        fn gen_write_from_stack<JT, N1>(
            &self,
            em: Emitter<Ent<N1, JT::B>>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitLocalOutVar,
            type_: JT,
            ext: Ext,
            scope: &dyn Scope,
        ) -> Emitter<N1>
        where
            JT: SimpleJitType,
            N1: Next,
        {
            LocalOutVarGen::gen_write_from_stack(self, em, local_this, gen, v, type_, ext, scope)
        }

        fn gen_write_from_opnd<N: Next>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitLocalOutVar,
            opnd: &dyn Opnd<MpIntJitType>,
            ext: Ext,
            scope: &dyn Scope,
        ) -> Emitter<N> {
            LocalOutVarGen::gen_write_from_opnd(self, em, local_this, gen, v, opnd, ext, scope)
        }

        fn gen_write_from_array<N1: Next>(
            &self,
            em: Emitter<Ent<N1, TRef>>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitLocalOutVar,
            type_: MpIntJitType,
            ext: Ext,
            scope: &dyn Scope,
        ) -> Emitter<N1> {
            LocalOutVarGen::gen_write_from_array(self, em, local_this, gen, v, type_, ext, scope)
        }
    }

    impl LocalVarGen<JitLocalOutVar> for TestLocalOutVarGen {}
    impl LocalOutVarGen for TestLocalOutVarGen {}

    fn make_local_this() -> Local<TRef> {
        Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0)
    }

    fn make_var(id: i32, offset: i64, size: i32) -> JitLocalOutVar {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, offset);
        JitLocalOutVar::new(id, Varnode::new(addr, size))
    }

    #[test]
    #[should_panic(expected = "VarHandler::gen_store_from_stack requires Self: Sized")]
    fn gen_write_from_stack_is_not_yet_wired() {
        let v = make_var(1, 0x1000, 4);
        let gen_impl = TestLocalOutVarGen;
        let code_gen = MockCodeGenerator;
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let em: Emitter<Ent<Bot, TInt>> = em.recast();

        LocalOutVarGen::gen_write_from_stack(
            &gen_impl,
            em,
            &local_this,
            &code_gen,
            &v,
            IntJitType::I4,
            Ext::Zero,
            &MockScope,
        );
    }

    #[test]
    #[should_panic(expected = "VarHandler::gen_store_from_opnd requires Self: Sized")]
    fn gen_write_from_opnd_is_not_yet_wired() {
        let v = make_var(2, 0x1000, 9);
        let gen_impl = TestLocalOutVarGen;
        let code_gen = MockCodeGenerator;
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        LocalOutVarGen::gen_write_from_opnd(
            &gen_impl,
            em,
            &local_this,
            &code_gen,
            &v,
            &StubMpOpnd,
            Ext::Zero,
            &MockScope,
        );
    }

    #[test]
    #[should_panic(expected = "VarHandler::gen_store_from_array requires Self: Sized")]
    fn gen_write_from_array_is_not_yet_wired() {
        let v = make_var(3, 0x1000, 9);
        let gen_impl = TestLocalOutVarGen;
        let code_gen = MockCodeGenerator;
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let em: Emitter<Ent<Bot, TRef>> = em.recast();

        LocalOutVarGen::gen_write_from_array(
            &gen_impl,
            em,
            &local_this,
            &code_gen,
            &v,
            MpIntJitType::for_size(9),
            Ext::Zero,
            &MockScope,
        );
    }

    #[test]
    fn jit_local_out_var_satisfies_jit_varnode_var() {
        // Java: JitLocalOutVar(id, varnode) -> AbstractJitOutVar(id, varnode) ->
        // AbstractJitVarnodeVar(id, varnode) -- unlike JitInputVar's fixed id of -1, the id here
        // is caller-supplied, and size/space are derived from the varnode.
        use crate::pcode::emu::jit::var::{JitVar, JitVarnodeVar};

        let v = make_var(7, 0x2000, 4);
        assert_eq!(JitVar::id(&v), 7);
        assert_eq!(v.varnode().get_offset(), 0x2000);
        assert_eq!(JitVarnodeVar::size(&v), 4);
    }
}
