//! The generator for a local variable that is input to the passage.
//!
//! Port of `ghidra.pcode.emu.jit.gen.var.InputVarGen`.
//!
//! This prohibits generation of code to write the variable.
//!
//! # Differences from Java
//!
//! - Java's `<THIS extends JitCompiledPassage>` type parameter, repeated on every method, is
//!   dropped in favor of a non-generic `Local<TRef>` and `&dyn JitCodeGenerator`, matching the
//!   convention set by
//!   [`DirectMemoryVarGen`](crate::pcode::emu::jit::gen::var::direct_memory_var_gen::DirectMemoryVarGen).
//! - Java's `throw new AssertionError()` bodies become `panic!`, since neither is meant to be
//!   reached: `VarGen`'s abstract `genWriteFromStack`/`genWriteFromOpnd`/`genWriteFromArray` and
//!   `LocalVarGen`'s default `genReadToBool` are all overridden here purely to forbid the
//!   operation for passage-input variables, not to provide a real implementation.
//! - `VarGen<V>` (`ghidra.pcode.emu.jit.gen.var.VarGen`) is this file's forward reference in a
//!   dependency cycle among the `var` package's generators, exactly as for
//!   [`DirectMemoryVarGen`]; its stub in [`seam_stubs`](crate::pcode::seam_stubs) already has the
//!   three write methods this type overrides.
//! - Java's `InputVarGen extends LocalVarGen<JitInputVar>` requires `JitInputVar` to satisfy
//!   `LocalVarGen`'s `V: JitVarnodeVar` bound. [`JitInputVar`](crate::pcode::seam_stubs::JitInputVar)
//!   was grown (see `STUBS.tsv`) with `JitVar`/`JitVarnodeVar` impls mirroring the real
//!   `JitInputVar extends AbstractJitVarnodeVar` to satisfy that bound.

use crate::pcode::emu::jit::analysis::jit_type::{MpIntJitType, SimpleJitType};
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TRef};
use crate::pcode::emu::jit::gen::var::local_var_gen::LocalVarGen;
use crate::pcode::seam_stubs::{Ext, JitCodeGenerator, JitInputVar, Opnd, Scope};

/// The generator for a local variable that is input to the passage.
///
/// Port of `ghidra.pcode.emu.jit.gen.var.InputVarGen`. See the [module docs](self).
pub trait InputVarGen: LocalVarGen<JitInputVar> {
    /// Port of `InputVarGen.genWriteFromStack`.
    fn gen_write_from_stack<JT, N1>(
        &self,
        _em: Emitter<Ent<N1, JT::B>>,
        _local_this: &Local<TRef>,
        _gen: &dyn JitCodeGenerator,
        _v: &JitInputVar,
        _type_: JT,
        _ext: Ext,
        _scope: &dyn Scope,
    ) -> Emitter<N1>
    where
        JT: SimpleJitType,
        N1: Next,
    {
        panic!("AssertionError: InputVarGen prohibits genWriteFromStack")
    }

    /// Port of `InputVarGen.genWriteFromOpnd`.
    fn gen_write_from_opnd<N: Next>(
        &self,
        _em: Emitter<N>,
        _local_this: &Local<TRef>,
        _gen: &dyn JitCodeGenerator,
        _v: &JitInputVar,
        _opnd: &dyn Opnd<MpIntJitType>,
        _ext: Ext,
        _scope: &dyn Scope,
    ) -> Emitter<N> {
        panic!("AssertionError: InputVarGen prohibits genWriteFromOpnd")
    }

    /// Port of `InputVarGen.genWriteFromArray`.
    fn gen_write_from_array<N1: Next>(
        &self,
        _em: Emitter<Ent<N1, TRef>>,
        _local_this: &Local<TRef>,
        _gen: &dyn JitCodeGenerator,
        _v: &JitInputVar,
        _type_: MpIntJitType,
        _ext: Ext,
        _scope: &dyn Scope,
    ) -> Emitter<N1> {
        panic!("AssertionError: InputVarGen prohibits genWriteFromArray")
    }

    /// Port of `InputVarGen.genReadToBool`.
    fn gen_read_to_bool<N: Next>(
        &self,
        _em: Emitter<N>,
        _local_this: &Local<TRef>,
        _gen: &dyn JitCodeGenerator,
        _v: &JitInputVar,
    ) -> Emitter<Ent<N, TInt>> {
        panic!("AssertionError: InputVarGen prohibits genReadToBool")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_type::IntJitType;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::seam_stubs::{MethodVisitor, OpndEm, StubMpOpnd, VarGen};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::Varnode;

    struct MockCodeGenerator;
    impl JitCodeGenerator for MockCodeGenerator {}

    struct MockScope;
    impl Scope for MockScope {}

    /// A minimal implementor exercising `InputVarGen`'s default methods, in the same spirit as
    /// `TestDirectMemoryVarGen` in
    /// [`direct_memory_var_gen`](super::super::direct_memory_var_gen)'s tests: the read methods
    /// delegate to `LocalVarGen`, unchanged, while the write methods (and `genReadToBool`)
    /// delegate to `InputVarGen`'s overrides, which forbid the operation.
    struct TestInputVarGen;

    impl VarGen<JitInputVar> for TestInputVarGen {
        fn gen_val_init<N: Next>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitInputVar,
        ) -> Emitter<N> {
            LocalVarGen::gen_val_init(self, em, local_this, gen, v)
        }

        fn gen_read_to_stack<JT, N>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitInputVar,
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
            v: &JitInputVar,
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
            v: &JitInputVar,
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
            v: &JitInputVar,
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
            v: &JitInputVar,
        ) -> Emitter<Ent<N, TInt>> {
            InputVarGen::gen_read_to_bool(self, em, local_this, gen, v)
        }

        fn gen_write_from_stack<JT, N1>(
            &self,
            em: Emitter<Ent<N1, JT::B>>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitInputVar,
            type_: JT,
            ext: Ext,
            scope: &dyn Scope,
        ) -> Emitter<N1>
        where
            JT: SimpleJitType,
            N1: Next,
        {
            InputVarGen::gen_write_from_stack(self, em, local_this, gen, v, type_, ext, scope)
        }

        fn gen_write_from_opnd<N: Next>(
            &self,
            em: Emitter<N>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitInputVar,
            opnd: &dyn Opnd<MpIntJitType>,
            ext: Ext,
            scope: &dyn Scope,
        ) -> Emitter<N> {
            InputVarGen::gen_write_from_opnd(self, em, local_this, gen, v, opnd, ext, scope)
        }

        fn gen_write_from_array<N1: Next>(
            &self,
            em: Emitter<Ent<N1, TRef>>,
            local_this: &Local<TRef>,
            gen: &dyn JitCodeGenerator,
            v: &JitInputVar,
            type_: MpIntJitType,
            ext: Ext,
            scope: &dyn Scope,
        ) -> Emitter<N1> {
            InputVarGen::gen_write_from_array(self, em, local_this, gen, v, type_, ext, scope)
        }
    }

    impl LocalVarGen<JitInputVar> for TestInputVarGen {}
    impl InputVarGen for TestInputVarGen {}

    fn make_local_this() -> Local<TRef> {
        Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0)
    }

    fn make_var(offset: i64, size: i32) -> JitInputVar {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, offset);
        JitInputVar::new(Varnode::new(addr, size))
    }

    #[test]
    #[should_panic(expected = "AssertionError: InputVarGen prohibits genWriteFromStack")]
    fn gen_write_from_stack_is_prohibited() {
        let v = make_var(0x1000, 4);
        let gen_impl = TestInputVarGen;
        let code_gen = MockCodeGenerator;
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let em: Emitter<Ent<Bot, TInt>> = em.recast();

        InputVarGen::gen_write_from_stack(
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
    #[should_panic(expected = "AssertionError: InputVarGen prohibits genWriteFromOpnd")]
    fn gen_write_from_opnd_is_prohibited() {
        let v = make_var(0x1000, 9);
        let gen_impl = TestInputVarGen;
        let code_gen = MockCodeGenerator;
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        InputVarGen::gen_write_from_opnd(
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
    #[should_panic(expected = "AssertionError: InputVarGen prohibits genWriteFromArray")]
    fn gen_write_from_array_is_prohibited() {
        let v = make_var(0x1000, 9);
        let gen_impl = TestInputVarGen;
        let code_gen = MockCodeGenerator;
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let em: Emitter<Ent<Bot, TRef>> = em.recast();

        InputVarGen::gen_write_from_array(
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
    #[should_panic(expected = "AssertionError: InputVarGen prohibits genReadToBool")]
    fn gen_read_to_bool_is_prohibited() {
        // Java: unlike LocalVarGen (whose genReadToBool is not yet wired to a real handler but
        // does not throw AssertionError), InputVarGen overrides it to forbid the operation
        // outright, since a passage-input variable is never read as a phi-materialized boolean.
        let v = make_var(0x1000, 4);
        let gen_impl = TestInputVarGen;
        let code_gen = MockCodeGenerator;
        let local_this = make_local_this();
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());

        InputVarGen::gen_read_to_bool(&gen_impl, em, &local_this, &code_gen, &v);
    }

    #[test]
    fn jit_input_var_satisfies_jit_varnode_var() {
        // Java: JitInputVar extends AbstractJitVarnodeVar(-1, varnode), giving it a fixed id of
        // -1 and a space/size derived from the varnode -- this is what lets InputVarGen bind
        // LocalVarGen<JitInputVar> at all (LocalVarGen<V: JitVarnodeVar>).
        use crate::pcode::emu::jit::var::{JitVar, JitVarnodeVar};

        let v = make_var(0x2000, 4);
        assert_eq!(JitVar::id(&v), -1);
        assert_eq!(v.varnode().get_offset(), 0x2000);
        assert_eq!(JitVarnodeVar::size(&v), 4);
    }
}
