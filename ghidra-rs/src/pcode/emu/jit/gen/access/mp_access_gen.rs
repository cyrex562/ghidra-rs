//! An access generator for a multi-precision integer variable.
//!
//! Port of `ghidra.pcode.emu.jit.gen.access.MpAccessGen`.
//!
//! # Differences from Java
//!
//! - Java's `<THIS extends JitCompiledPassage>` type parameter, repeated on every method, is
//!   dropped in favor of a non-generic `Local<TRef>` and `&dyn JitCodeGenerator`, matching the
//!   convention set by
//!   [`InstanceFieldReq`](crate::pcode::emu::jit::gen::instance_field_req::InstanceFieldReq).
//! - `genWriteFromArray`'s Java bound `N0 extends Ent<N1, TRef<int[]>>` becomes the direct
//!   parameter type `Emitter<Ent<N1, TRef>>`, per the [`Emitter`](
//!   crate::pcode::emu::jit::gen::util::emitter) module docs on replacing such bounds. `int[]`
//!   itself collapses to the non-generic [`TRef`], as [`Types`](
//!   crate::pcode::emu::jit::gen::util::types) already does for every reference type in this port.
//! - `AccessGen<MpIntJitType>`, `Opnd<MpIntJitType>`, `Opnd.OpndEm`, and `Opnd.Ext` are not yet
//!   ported; minimal placeholders live in
//!   [`seam_stubs`](crate::pcode::seam_stubs). `AccessGen` contributes no instance methods (its
//!   Java members are all `static`), so its stub is a marker only.

use crate::pcode::emu::jit::analysis::jit_type::MpIntJitType;
use crate::pcode::emu::jit::gen::access::access_gen::AccessGen;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::TRef;
use crate::pcode::seam_stubs::{Ext, JitCodeGenerator, Opnd, OpndEm, Scope};
use crate::program::model::pcode::Varnode;

/// An access generator for a multi-precision integer variable.
///
/// Port of `ghidra.pcode.emu.jit.gen.access.MpAccessGen`.
pub trait MpAccessGen: AccessGen<MpIntJitType> {
    /// Emit bytecode to load the varnode's value into several locals.
    ///
    /// Port of `MpAccessGen.genReadToOpnd`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack.
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `gen`: the code generator.
    /// - `vn`: the varnode.
    /// - `type_`: the desired p-code type of the value.
    /// - `ext`: the kind of extension to apply.
    /// - `scope`: a scope for generating temporary local storage.
    ///
    /// # Returns
    ///
    /// The operand containing the locals, and the emitter typed with the incoming stack.
    fn gen_read_to_opnd<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        vn: &Varnode,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
    ) -> OpndEm<MpIntJitType, N>;

    /// Emit bytecode to load the varnode's value into an integer array in little-endian order,
    /// pushing its ref onto the JVM stack.
    ///
    /// Port of `MpAccessGen.genReadToArray`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack.
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `gen`: the code generator.
    /// - `vn`: the varnode.
    /// - `type_`: the desired p-code type of the value.
    /// - `ext`: the kind of extension to apply.
    /// - `scope`: a scope for generating temporary local storage.
    /// - `slack`: the number of additional, more significant, elements to allocate in the array.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., having the ref pushed onto it.
    #[allow(clippy::too_many_arguments)]
    fn gen_read_to_array<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        vn: &Varnode,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
        slack: i32,
    ) -> Emitter<Ent<N, TRef>>;

    /// Emit bytecode to store a value into a variable from the JVM stack.
    ///
    /// Port of `MpAccessGen.genWriteFromOpnd`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack.
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `gen`: the code generator.
    /// - `opnd`: the operand whose locals contain the value to be stored.
    /// - `vn`: the varnode.
    ///
    /// # Returns
    ///
    /// The emitter typed with the incoming stack.
    fn gen_write_from_opnd<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        opnd: &dyn Opnd<MpIntJitType>,
        vn: &Varnode,
    ) -> Emitter<N>;

    /// Emit bytecode to store a varnode's value from an array of integer legs, in little-endian
    /// order.
    ///
    /// Port of `MpAccessGen.genWriteFromArray`.
    ///
    /// # Arguments
    ///
    /// - `em`: the emitter typed with the incoming stack, having the array ref on top.
    /// - `local_this`: a handle to the local holding the `this` reference.
    /// - `gen`: the code generator.
    /// - `vn`: the varnode.
    /// - `scope`: a scope for generating temporary local storage.
    ///
    /// # Returns
    ///
    /// The emitter typed with the resulting stack, i.e., having popped the array.
    fn gen_write_from_array<N1: Next>(
        &self,
        em: Emitter<Ent<N1, TRef>>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        vn: &Varnode,
        scope: &dyn Scope,
    ) -> Emitter<N1>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::seam_stubs::MethodVisitor;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    struct MockCodeGenerator;
    impl JitCodeGenerator for MockCodeGenerator {}

    struct MockScope;
    impl Scope for MockScope {}

    struct MockOpnd;
    impl Opnd<MpIntJitType> for MockOpnd {}

    /// A minimal implementor exercising the type-level plumbing (stack shapes, `this`/generator
    /// pass-through) without any real bytecode-generation logic.
    struct TestMpAccessGen;

    impl AccessGen<MpIntJitType> for TestMpAccessGen {}

    impl MpAccessGen for TestMpAccessGen {
        fn gen_read_to_opnd<N: Next>(
            &self,
            em: Emitter<N>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _vn: &Varnode,
            _type_: MpIntJitType,
            _ext: Ext,
            _scope: &dyn Scope,
        ) -> OpndEm<MpIntJitType, N> {
            OpndEm::new(Box::new(MockOpnd), em)
        }

        fn gen_read_to_array<N: Next>(
            &self,
            em: Emitter<N>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _vn: &Varnode,
            _type_: MpIntJitType,
            _ext: Ext,
            _scope: &dyn Scope,
            _slack: i32,
        ) -> Emitter<Ent<N, TRef>> {
            em.recast()
        }

        fn gen_write_from_opnd<N: Next>(
            &self,
            em: Emitter<N>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _opnd: &dyn Opnd<MpIntJitType>,
            _vn: &Varnode,
        ) -> Emitter<N> {
            em
        }

        fn gen_write_from_array<N1: Next>(
            &self,
            em: Emitter<Ent<N1, TRef>>,
            _local_this: &Local<TRef>,
            _gen: &dyn JitCodeGenerator,
            _vn: &Varnode,
            _scope: &dyn Scope,
        ) -> Emitter<N1> {
            em.recast()
        }
    }

    fn make_varnode() -> Varnode {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x1000);
        Varnode::new(addr, 9)
    }

    fn make_local_this() -> Local<TRef> {
        Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0)
    }

    #[test]
    fn ext_for_signed_matches_java_enum_mapping() {
        // Java: Ext.forSigned(true) == Ext.SIGN; Ext.forSigned(false) == Ext.ZERO.
        assert_eq!(Ext::for_signed(true), Ext::Sign);
        assert_eq!(Ext::for_signed(false), Ext::Zero);
    }

    #[test]
    fn gen_read_to_opnd_returns_the_incoming_stack_shape() {
        let gen_impl = TestMpAccessGen;
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = make_local_this();
        let code_gen = MockCodeGenerator;
        let scope = MockScope;
        let vn = make_varnode();
        let type_ = MpIntJitType::for_size(9);

        // Java: genReadToOpnd returns an OpndEm<MpIntJitType, N> for the *incoming* stack N,
        // i.e., it does not itself alter the JVM operand stack.
        let result: OpndEm<MpIntJitType, Bot> = gen_impl.gen_read_to_opnd(
            em,
            &local_this,
            &code_gen,
            &vn,
            type_,
            Ext::Zero,
            &scope,
        );
        assert!(result.em.local_variables().is_empty());
    }

    #[test]
    fn gen_read_to_array_pushes_a_ref_onto_the_stack() {
        let gen_impl = TestMpAccessGen;
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = make_local_this();
        let code_gen = MockCodeGenerator;
        let scope = MockScope;
        let vn = make_varnode();
        let type_ = MpIntJitType::for_size(9);

        // Java: genReadToArray returns Emitter<Ent<N, TRef<int[]>>>, i.e., the resulting stack
        // has the array ref on top of the incoming stack N.
        let result: Emitter<Ent<Bot, TRef>> = gen_impl.gen_read_to_array(
            em,
            &local_this,
            &code_gen,
            &vn,
            type_,
            Ext::Sign,
            &scope,
            0,
        );
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    fn gen_write_from_array_pops_the_array_ref_off_the_stack() {
        let gen_impl = TestMpAccessGen;
        let em: Emitter<Ent<Bot, TRef>> = Emitter::<Bot>::new(MethodVisitor::new()).recast();
        let local_this = make_local_this();
        let code_gen = MockCodeGenerator;
        let scope = MockScope;
        let vn = make_varnode();

        // Java: genWriteFromArray consumes the array ref (N0 = Ent<N1, TRef<int[]>>) and returns
        // Emitter<N1>, i.e., the stack beneath it.
        let result: Emitter<Bot> =
            gen_impl.gen_write_from_array(em, &local_this, &code_gen, &vn, &scope);
        let _: Vec<_> = result.local_variables();
    }

    #[test]
    fn mp_access_gen_extends_access_gen() {
        let gen_impl = TestMpAccessGen;
        let _as_access_gen: &dyn AccessGen<MpIntJitType> = &gen_impl;
    }
}
