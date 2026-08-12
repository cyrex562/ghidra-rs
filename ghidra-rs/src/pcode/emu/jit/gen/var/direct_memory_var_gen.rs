//! The generator for a direct memory variable.
//!
//! Port of `ghidra.pcode.emu.jit.gen.var.DirectMemoryVarGen`.
//!
//! This prohibits generation of code to write the variable.
//!
//! # Differences from Java
//!
//! - Java's `<THIS extends JitCompiledPassage>` type parameter, repeated on every method, is
//!   dropped in favor of a non-generic `Local<TRef>` and `&dyn JitCodeGenerator`, matching the
//!   convention set by [`MemoryVarGen`].
//! - Java's `throw new AssertionError()` bodies become `panic!`, since neither is meant to be
//!   reached: `VarGen`'s abstract `genWriteFromStack`/`genWriteFromOpnd`/`genWriteFromArray` and
//!   `MemoryVarGen`'s default `genReadToBool` are all overridden here purely to forbid the
//!   operation for direct memory variables, not to provide a real implementation.
//! - `VarGen` (`ghidra.pcode.emu.jit.gen.var.VarGen`) is this file's forward reference in a
//!   dependency cycle among the `var` package's generators; its stub in
//!   [`seam_stubs`](crate::pcode::seam_stubs) has grown the three write methods this type
//!   overrides (see that stub's docs).

use crate::pcode::emu::jit::analysis::jit_type::{MpIntJitType, SimpleJitType};
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TRef};
use crate::pcode::emu::jit::gen::var::memory_var_gen::MemoryVarGen;
use crate::pcode::emu::jit::var::JitDirectMemoryVar;
use crate::pcode::seam_stubs::{Ext, JitCodeGenerator, Opnd, Scope};

/// The generator for a direct memory variable.
///
/// Port of `ghidra.pcode.emu.jit.gen.var.DirectMemoryVarGen`. See the [module docs](self).
pub trait DirectMemoryVarGen: MemoryVarGen<JitDirectMemoryVar> {
    /// Port of `DirectMemoryVarGen.genWriteFromStack`.
    fn gen_write_from_stack<JT, N1>(
        &self,
        _em: Emitter<Ent<N1, JT::B>>,
        _local_this: &Local<TRef>,
        _gen: &dyn JitCodeGenerator,
        _v: &JitDirectMemoryVar,
        _type_: JT,
        _ext: Ext,
        _scope: &dyn Scope,
    ) -> Emitter<N1>
    where
        JT: SimpleJitType,
        N1: Next,
    {
        panic!("AssertionError: DirectMemoryVarGen prohibits genWriteFromStack")
    }

    /// Port of `DirectMemoryVarGen.genWriteFromOpnd`.
    fn gen_write_from_opnd<N: Next>(
        &self,
        _em: Emitter<N>,
        _local_this: &Local<TRef>,
        _gen: &dyn JitCodeGenerator,
        _v: &JitDirectMemoryVar,
        _opnd: &dyn Opnd<MpIntJitType>,
        _ext: Ext,
        _scope: &dyn Scope,
    ) -> Emitter<N> {
        panic!("AssertionError: DirectMemoryVarGen prohibits genWriteFromOpnd")
    }

    /// Port of `DirectMemoryVarGen.genWriteFromArray`.
    fn gen_write_from_array<N1: Next>(
        &self,
        _em: Emitter<Ent<N1, TRef>>,
        _local_this: &Local<TRef>,
        _gen: &dyn JitCodeGenerator,
        _v: &JitDirectMemoryVar,
        _type_: MpIntJitType,
        _ext: Ext,
        _scope: &dyn Scope,
    ) -> Emitter<N1> {
        panic!("AssertionError: DirectMemoryVarGen prohibits genWriteFromArray")
    }

    /// Port of `DirectMemoryVarGen.genReadToBool`.
    fn gen_read_to_bool<N: Next>(
        &self,
        _em: Emitter<N>,
        _local_this: &Local<TRef>,
        _gen: &dyn JitCodeGenerator,
        _v: &JitDirectMemoryVar,
    ) -> Emitter<Ent<N, TInt>> {
        panic!("AssertionError: DirectMemoryVarGen prohibits genReadToBool")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_type::IntJitType;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::seam_stubs::{
        FieldForArrDirect, JitAnalysisContext, MethodVisitor, OpndEm, StubMpOpnd, VarGen,
    };
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::Endian;
    use crate::program::model::pcode::Varnode;

    struct MockCodeGenerator;

    impl JitCodeGenerator for MockCodeGenerator {
        fn get_analysis_context(&self) -> JitAnalysisContext {
            JitAnalysisContext::new(Endian::Little)
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

    /// A minimal implementor exercising `DirectMemoryVarGen`'s default methods, in the same
    /// spirit as `TestMemoryVarGen` in [`memory_var_gen`](super::super::memory_var_gen)'s tests:
    /// the read methods delegate to `MemoryVarGen`, unchanged, while the write methods (and
    /// `genReadToBool`) delegate to `DirectMemoryVarGen`'s overrides, which forbid the operation.
    struct TestDirectMemoryVarGen;

    impl VarGen<JitDirectMemoryVar> for TestDirectMemoryVarGen {
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

    impl MemoryVarGen<JitDirectMemoryVar> for TestDirectMemoryVarGen {}
    impl DirectMemoryVarGen for TestDirectMemoryVarGen {}

    fn make_local_this() -> Local<TRef> {
        Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0)
    }

    fn make_var(offset: i64, size: i32) -> JitDirectMemoryVar {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, offset);
        JitDirectMemoryVar::new(1, Varnode::new(addr, size))
    }

    #[test]
    fn gen_read_to_stack_still_delegates_to_memory_var_gen() {
        // Java: DirectMemoryVarGen does not override genReadToStack, so it keeps
        // MemoryVarGen's real (non-throwing) behavior.
        let vn_offset = 0x1000;
        let v = make_var(vn_offset, 4);
        let gen_impl = TestDirectMemoryVarGen;
        let code_gen = MockCodeGenerator;
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        let result: Emitter<Ent<Bot, TInt>> = MemoryVarGen::gen_read_to_stack(
            &gen_impl,
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
        let gen_impl = TestDirectMemoryVarGen;
        let code_gen = MockCodeGenerator;
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let em: Emitter<Ent<Bot, TInt>> = em.recast();

        DirectMemoryVarGen::gen_write_from_stack(
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
    #[should_panic(expected = "AssertionError: DirectMemoryVarGen prohibits genWriteFromOpnd")]
    fn gen_write_from_opnd_is_prohibited() {
        let v = make_var(0x1000, 9);
        let gen_impl = TestDirectMemoryVarGen;
        let code_gen = MockCodeGenerator;
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        DirectMemoryVarGen::gen_write_from_opnd(
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
    #[should_panic(expected = "AssertionError: DirectMemoryVarGen prohibits genWriteFromArray")]
    fn gen_write_from_array_is_prohibited() {
        let v = make_var(0x1000, 9);
        let gen_impl = TestDirectMemoryVarGen;
        let code_gen = MockCodeGenerator;
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let em: Emitter<Ent<Bot, TRef>> = em.recast();

        DirectMemoryVarGen::gen_write_from_array(
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
    #[should_panic(expected = "AssertionError: DirectMemoryVarGen prohibits genReadToBool")]
    fn gen_read_to_bool_is_prohibited() {
        // Java: unlike MemoryVarGen (which delegates genReadToBool to AccessGen),
        // DirectMemoryVarGen overrides it to also throw AssertionError.
        let v = make_var(0x1000, 4);
        let gen_impl = TestDirectMemoryVarGen;
        let code_gen = MockCodeGenerator;
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        DirectMemoryVarGen::gen_read_to_bool(&gen_impl, em, &local_this, &code_gen, &v);
    }
}
