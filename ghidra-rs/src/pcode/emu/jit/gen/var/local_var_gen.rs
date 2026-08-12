//! The generator for local variable access.
//!
//! Port of `ghidra.pcode.emu.jit.gen.var.LocalVarGen`.
//!
//! These variables are presumed to be allocated as JVM locals. The generator emits `iload`/
//! `istore` (and friends) depending on the assigned type.
//!
//! # Differences from Java
//!
//! - Java's `<THIS extends JitCompiledPassage>` type parameter, repeated on every method, is
//!   dropped in favor of a non-generic `Local<TRef>` and `&dyn JitCodeGenerator`, matching the
//!   convention set by [`MemoryVarGen`](crate::pcode::emu::jit::gen::var::memory_var_gen::MemoryVarGen).
//! - `VarGen<V>` (`ghidra.pcode.emu.jit.gen.var.VarGen`) is this file's forward reference in a
//!   dependency cycle among the `var` package's generators, exactly as for
//!   [`MemoryVarGen`]; its stub lives in [`seam_stubs`](crate::pcode::seam_stubs). As with that
//!   type, a concrete implementor of this trait provides its own `impl VarGen<V> for Self` block
//!   whose bodies delegate to this trait's same-named defaults (see this module's tests for the
//!   pattern), since Rust supertrait bounds -- unlike Java's interface inheritance -- do not
//!   themselves supply method bodies.
//! - `getHandler`'s real behavior (`gen.getAllocationModel().getHandler(v)`) is ported faithfully
//!   as a one-line delegation to the new `JitAllocationModel` stub in
//!   [`seam_stubs`](crate::pcode::seam_stubs). But `genReadToStack`/`genReadToOpnd`/
//!   `genReadLegToStack`/`genReadToArray`/`genReadToBool` -- which in Java simply forward to the
//!   handler's matching `genLoad*` method -- cannot be ported that way here:
//!   [`VarHandler`](crate::pcode::emu::jit::alloc::var_handler::VarHandler)'s `gen_load_*` methods
//!   each carry a `where Self: Sized` bound (per that trait's own module docs, to keep the trait
//!   object-safe for `subpiece`'s `Box<dyn VarHandler>`), so none of them can be called through
//!   the `Box<dyn VarHandler>` that `get_handler`/`JitAllocationModel::get_handler` return. This
//!   is a genuine gap between Java's erased generics (where this dispatch is unremarkable) and
//!   Rust's monomorphized ones, not something this file can paper over: these five methods are
//!   left `unimplemented!()`, with signatures matching `VarGen<V>`'s so they can still be wired up
//!   once `JitAllocationModel` is ported with a way to recover the concrete handler type (or
//!   `VarHandler` grows a dyn-safe load path).

use crate::pcode::emu::jit::alloc::var_handler::VarHandler;
use crate::pcode::emu::jit::analysis::jit_type::{MpIntJitType, SimpleJitType};
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TRef};
use crate::pcode::emu::jit::var::JitVarnodeVar;
use crate::pcode::seam_stubs::{Ext, JitCodeGenerator, OpndEm, Scope};

/// The generator for local variable access.
///
/// Port of `ghidra.pcode.emu.jit.gen.var.LocalVarGen<V>`. See the [module docs](self).
pub trait LocalVarGen<V: JitVarnodeVar>: crate::pcode::emu::jit::gen::var::var_gen::VarGen<V> {
    /// Get the handler for a given p-code variable.
    ///
    /// This is made to be overridden for the implementation of subpiece handlers.
    ///
    /// Port of `LocalVarGen.getHandler`.
    fn get_handler(&self, gen: &dyn JitCodeGenerator, v: &V) -> Box<dyn VarHandler> {
        gen.get_allocation_model().get_handler(v)
    }

    /// Port of `LocalVarGen.genValInit`. Local variables need no class-level preparation, so this
    /// leaves the emitter untouched.
    fn gen_val_init<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
    ) -> Emitter<N> {
        let _ = (local_this, gen, v);
        em
    }

    /// Port of `LocalVarGen.genReadToStack`. See the [module docs](self) on why this cannot yet
    /// delegate to [`get_handler`](Self::get_handler) as Java does.
    fn gen_read_to_stack<JT, N>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: JT,
        ext: Ext,
    ) -> Emitter<Ent<N, JT::B>>
    where
        JT: SimpleJitType,
        N: Next,
    {
        let _ = (em, local_this, gen, v, type_, ext);
        unimplemented!(
            "LocalVarGen::gen_read_to_stack: VarHandler::gen_load_to_stack requires Self: Sized, \
             see module docs"
        )
    }

    /// Port of `LocalVarGen.genReadToOpnd`. See the [module docs](self) on why this cannot yet
    /// delegate to [`get_handler`](Self::get_handler) as Java does.
    fn gen_read_to_opnd<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
    ) -> OpndEm<MpIntJitType, N> {
        let _ = (em, local_this, gen, v, type_, ext, scope);
        unimplemented!(
            "LocalVarGen::gen_read_to_opnd: VarHandler::gen_load_to_opnd requires Self: Sized, \
             see module docs"
        )
    }

    /// Port of `LocalVarGen.genReadLegToStack`. See the [module docs](self) on why this cannot
    /// yet delegate to [`get_handler`](Self::get_handler) as Java does.
    fn gen_read_leg_to_stack<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: MpIntJitType,
        leg: i32,
        ext: Ext,
    ) -> Emitter<Ent<N, TInt>> {
        let _ = (em, local_this, gen, v, type_, leg, ext);
        unimplemented!(
            "LocalVarGen::gen_read_leg_to_stack: VarHandler::gen_load_leg_to_stack requires \
             Self: Sized, see module docs"
        )
    }

    /// Port of `LocalVarGen.genReadToArray`. See the [module docs](self) on why this cannot yet
    /// delegate to [`get_handler`](Self::get_handler) as Java does.
    #[allow(clippy::too_many_arguments)]
    fn gen_read_to_array<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
        slack: i32,
    ) -> Emitter<Ent<N, TRef>> {
        let _ = (em, local_this, gen, v, type_, ext, scope, slack);
        unimplemented!(
            "LocalVarGen::gen_read_to_array: VarHandler::gen_load_to_array requires Self: Sized, \
             see module docs"
        )
    }

    /// Port of `LocalVarGen.genReadToBool`. See the [module docs](self) on why this cannot yet
    /// delegate to [`get_handler`](Self::get_handler) as Java does.
    fn gen_read_to_bool<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
    ) -> Emitter<Ent<N, TInt>> {
        let _ = (em, local_this, gen, v);
        unimplemented!(
            "LocalVarGen::gen_read_to_bool: VarHandler::gen_load_to_bool requires Self: Sized, \
             see module docs"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_type::AnyJitType;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::emu::jit::var::JitVal;
    use crate::pcode::emu::jit::gen::var::var_gen::VarGen;
    use crate::pcode::seam_stubs::{JitAllocationModel, MethodVisitor};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::pcode::Varnode;
    use std::sync::Arc;

    struct TestVarnodeVar {
        varnode: Varnode,
    }

    impl JitVal for TestVarnodeVar {
        fn size(&self) -> i32 {
            self.varnode.get_size()
        }

        fn add_use(&self, _op: &dyn crate::pcode::seam_stubs::JitOp, _position: i32) {}
        fn remove_use(&self, _op: &dyn crate::pcode::seam_stubs::JitOp, _position: i32) {}
    }

    impl crate::pcode::emu::jit::var::JitVar for TestVarnodeVar {
        fn id(&self) -> i32 {
            1
        }

        fn space(&self) -> Arc<AddressSpace> {
            Arc::clone(self.varnode.get_address().space())
        }
    }

    impl JitVarnodeVar for TestVarnodeVar {
        fn varnode(&self) -> Varnode {
            self.varnode.clone()
        }
    }

    /// A handler whose only purpose is to be recovered, by identity, at the end of the
    /// `get_handler` delegation chain -- since its `gen_load_*` methods cannot be called through
    /// the `Box<dyn VarHandler>` `get_handler` returns (see the [module docs](super)), only the
    /// object-safe subset (`vn`/`name`/`type_`/`subpiece`) is exercised here.
    struct TestHandler {
        vn: Varnode,
    }

    impl VarHandler for TestHandler {
        fn vn(&self) -> Varnode {
            self.vn.clone()
        }

        fn type_(&self) -> AnyJitType {
            unimplemented!()
        }

        fn gen_load_to_stack<TT, TJT, N>(
            &self,
            _em: Emitter<N>,
            _gen: &dyn JitCodeGenerator,
            _type_: TJT,
            _ext: Ext,
        ) -> Emitter<Ent<N, TT>>
        where
            TT: crate::pcode::emu::jit::gen::util::types::BPrim,
            TJT: SimpleJitType<B = TT>,
            N: Next,
            Self: Sized,
        {
            unimplemented!()
        }

        fn gen_load_to_opnd<N: Next>(
            &self,
            _em: Emitter<N>,
            _gen: &dyn JitCodeGenerator,
            _type_: MpIntJitType,
            _ext: Ext,
            _scope: &dyn Scope,
        ) -> OpndEm<MpIntJitType, N>
        where
            Self: Sized,
        {
            unimplemented!()
        }

        fn gen_load_leg_to_stack<N: Next>(
            &self,
            _em: Emitter<N>,
            _gen: &dyn JitCodeGenerator,
            _type_: MpIntJitType,
            _leg: i32,
            _ext: Ext,
        ) -> Emitter<Ent<N, TInt>>
        where
            Self: Sized,
        {
            unimplemented!()
        }

        fn gen_load_to_array<N: Next>(
            &self,
            _em: Emitter<N>,
            _gen: &dyn JitCodeGenerator,
            _type_: MpIntJitType,
            _ext: Ext,
            _scope: &dyn Scope,
            _slack: i32,
        ) -> Emitter<Ent<N, TRef>>
        where
            Self: Sized,
        {
            unimplemented!()
        }

        fn gen_load_to_bool<N: Next>(
            &self,
            _em: Emitter<N>,
            _gen: &dyn JitCodeGenerator,
        ) -> Emitter<Ent<N, TInt>>
        where
            Self: Sized,
        {
            unimplemented!()
        }

        fn gen_store_from_stack<FT, FJT, N1>(
            &self,
            _em: Emitter<Ent<N1, FT>>,
            _gen: &dyn JitCodeGenerator,
            _type_: FJT,
            _ext: Ext,
            _scope: &dyn Scope,
        ) -> Emitter<N1>
        where
            FT: crate::pcode::emu::jit::gen::util::types::BPrim,
            FJT: SimpleJitType<B = FT>,
            N1: Next,
            Self: Sized,
        {
            unimplemented!()
        }

        fn gen_store_from_opnd<N: Next>(
            &self,
            _em: Emitter<N>,
            _gen: &dyn JitCodeGenerator,
            _opnd: &dyn crate::pcode::seam_stubs::Opnd<MpIntJitType>,
            _ext: Ext,
            _scope: &dyn Scope,
        ) -> Emitter<N>
        where
            Self: Sized,
        {
            unimplemented!()
        }

        fn gen_store_from_array<N1: Next>(
            &self,
            _em: Emitter<Ent<N1, TRef>>,
            _gen: &dyn JitCodeGenerator,
            _type_: MpIntJitType,
            _ext: Ext,
            _scope: &dyn Scope,
        ) -> Emitter<N1>
        where
            Self: Sized,
        {
            unimplemented!()
        }

        fn subpiece(&self, _endian: Endian, _byte_offset: i32, _max_byte_size: i32) -> Box<dyn VarHandler> {
            unimplemented!()
        }
    }

    struct MockAllocationModel {
        handler_vn: Varnode,
    }

    impl JitAllocationModel for MockAllocationModel {
        fn get_handler(&self, _v: &dyn JitVal) -> Box<dyn VarHandler> {
            Box::new(TestHandler { vn: self.handler_vn.clone() })
        }
    }

    struct MockCodeGenerator {
        handler_vn: Varnode,
    }

    impl JitCodeGenerator for MockCodeGenerator {
        fn get_allocation_model(&self) -> Box<dyn JitAllocationModel> {
            Box::new(MockAllocationModel { handler_vn: self.handler_vn.clone() })
        }
    }

    struct BlockedMockCodeGenerator;
    impl JitCodeGenerator for BlockedMockCodeGenerator {}

    /// A minimal implementor exercising `LocalVarGen`'s default methods, in the same spirit as
    /// `TestMemoryVarGen`/`TestDirectMemoryVarGen`.
    struct TestLocalVarGen;

    impl VarGen<TestVarnodeVar> for TestLocalVarGen {
        fn gen_val_init<N: Next>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &TestVarnodeVar,
        ) -> Emitter<N> {
            LocalVarGen::gen_val_init(self, em, local_this, gen, v)
        }

        fn gen_read_to_stack<JT, N>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &TestVarnodeVar,
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
            v: &TestVarnodeVar,
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
            v: &TestVarnodeVar,
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
            v: &TestVarnodeVar,
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
            v: &TestVarnodeVar,
        ) -> Emitter<Ent<N, TInt>> {
            LocalVarGen::gen_read_to_bool(self, em, local_this, gen, v)
        }

        // Java: LocalVarGen does not override VarGen's abstract genWriteFromStack/
        // genWriteFromOpnd/genWriteFromArray -- only its own concrete implementors (not yet
        // ported) provide real bodies. This test double has no real behavior to exercise here.
        fn gen_write_from_stack<JT, N1>(
            &self,
            _em: Emitter<Ent<N1, JT::B>>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &TestVarnodeVar,
            _type_: JT,
            _ext: Ext,
            _scope: &dyn Scope,
        ) -> Emitter<N1>
        where
            JT: SimpleJitType,
            N1: Next,
        {
            unimplemented!("TestLocalVarGen does not exercise gen_write_from_stack")
        }

        fn gen_write_from_opnd<N: Next>(
            &self,
            _em: Emitter<N>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &TestVarnodeVar,
            _opnd: &dyn crate::pcode::seam_stubs::Opnd<MpIntJitType>,
            _ext: Ext,
            _scope: &dyn Scope,
        ) -> Emitter<N> {
            unimplemented!("TestLocalVarGen does not exercise gen_write_from_opnd")
        }

        fn gen_write_from_array<N1: Next>(
            &self,
            _em: Emitter<Ent<N1, TRef>>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _v: &TestVarnodeVar,
            _type_: MpIntJitType,
            _ext: Ext,
            _scope: &dyn Scope,
        ) -> Emitter<N1> {
            unimplemented!("TestLocalVarGen does not exercise gen_write_from_array")
        }
    }

    impl LocalVarGen<TestVarnodeVar> for TestLocalVarGen {}

    fn make_local_this() -> Local<TRef> {
        Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0)
    }

    fn make_var(offset: i64, size: i32) -> TestVarnodeVar {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, offset);
        TestVarnodeVar { varnode: Varnode::new(addr, size) }
    }

    #[test]
    fn gen_val_init_leaves_the_emitter_untouched() {
        // Java: LocalVarGen.genValInit just returns `em`; local variables need no class-level
        // preparation (unlike memory variables, which request array-block fields).
        let v = make_var(0x1000, 4);
        let gen_impl = TestLocalVarGen;
        let code_gen = BlockedMockCodeGenerator;
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        let result = LocalVarGen::gen_val_init(&gen_impl, em, &local_this, &code_gen, &v);
        assert!(result.local_variables().is_empty());
    }

    #[test]
    fn get_handler_delegates_through_the_allocation_model() {
        // Java: default VarHandler getHandler(gen, v) { return gen.getAllocationModel()
        // .getHandler(v); } -- exercise the wiring via the handler's identity (its varnode),
        // since VarHandler's gen_load_* methods aren't callable through the returned
        // `Box<dyn VarHandler>` (see the module docs).
        let v = make_var(0x2000, 4);
        let gen_impl = TestLocalVarGen;
        let handler_vn = make_var(0x9000, 8).varnode;
        let code_gen = MockCodeGenerator { handler_vn: handler_vn.clone() };

        let handler = gen_impl.get_handler(&code_gen, &v);
        assert_eq!(handler.vn().get_offset(), handler_vn.get_offset());
        assert_eq!(handler.vn().get_size(), handler_vn.get_size());
    }

    #[test]
    #[should_panic(expected = "VarHandler::gen_load_to_stack requires Self: Sized")]
    fn gen_read_to_stack_is_not_yet_wired() {
        let v = make_var(0x1000, 4);
        let gen_impl = TestLocalVarGen;
        let code_gen = BlockedMockCodeGenerator;
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        LocalVarGen::gen_read_to_stack(
            &gen_impl,
            em,
            &local_this,
            &code_gen,
            &v,
            crate::pcode::emu::jit::analysis::jit_type::IntJitType::I4,
            Ext::Zero,
        );
    }
}
