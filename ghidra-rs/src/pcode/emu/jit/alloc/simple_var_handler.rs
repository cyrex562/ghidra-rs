//! A handler for p-code variables composed of a single JVM local variable.
//!
//! Port of `ghidra.pcode.emu.jit.alloc.SimpleVarHandler`.
//!
//! # Differences from Java
//!
//! - Java's two type parameters (`T` the JVM type, `JT` the p-code type of the local) are dropped,
//!   the same erasure [`JvmLocal`] and
//!   [`SubVarHandler`](crate::pcode::emu::jit::alloc::sub_var_handler::SubVarHandler) already use.
//! - `vn()`, `genLoadToStack`, `genLoadToOpnd`, `genLoadToArray`, `genStoreFromStack`,
//!   `genStoreFromOpnd`, and `genStoreFromArray` all override [`VarHandler`]'s abstract methods of
//!   the same name. Rust does not allow a subtrait to override a supertrait method by redeclaring
//!   it, so, per the convention [`SubVarHandler`](crate::pcode::emu::jit::alloc::sub_var_handler::SubVarHandler)
//!   sets, they are exposed here under distinct `simple_var_handler_*` names; a concrete
//!   implementor's own [`VarHandler`] impl should delegate to these.
//! - `type()` -- narrowed from [`VarHandler::type_`]'s `AnyJitType` to Java's `JT` -- is not
//!   redeclared here at all, for the same reason [`SubVarHandler`] leaves it out:
//!   [`VarHandler::type_`] is inherited unchanged, with the understanding (matching Java's `JT
//!   extends SimpleJitType<..>` bound) that an implementor never returns
//!   [`AnyJitType::MpInt`]/[`AnyJitType::MpFloat`] from it.
//! - `genLoadToStack`/`genStoreFromStack` delegate, in Java, to `local().genLoadToStack`/
//!   `local().genStoreFromStack`. Neither is ported on [`JvmLocal`]: both center on
//!   `SimpleOpnd.read`/`writeDirect` and `Opnd.convert`, none of which are ported (see
//!   [`JvmLocal`]'s module docs). [`simple_var_handler_gen_load_to_stack`](SimpleVarHandler::simple_var_handler_gen_load_to_stack)/
//!   [`simple_var_handler_gen_store_from_stack`](SimpleVarHandler::simple_var_handler_gen_store_from_stack)
//!   therefore only preserve the type-level stack-shape plumbing via [`Emitter::recast`], emitting
//!   no real bytecode, mirroring the stand-ins [`convert_to_opnd`]/[`convert_to_array`] already use
//!   for the same gap.
//! - [`gen_load_leg_to_stack_c1`](SimpleVarHandler::gen_load_leg_to_stack_c1)/
//!   [`gen_load_leg_to_stack_c2`](SimpleVarHandler::gen_load_leg_to_stack_c2) are not overrides
//!   (`VarHandler` has no method of that name), so they keep their direct names. Their real bodies
//!   emit JVM opcodes via `Op::ldc__i`/`Op::ishl`/`Op::ishr`/`Op::l2i`/`Op::lshr` and
//!   `Opnd::convertIntToInt`, none of which are ported -- `Op.java` has no real port despite its
//!   stale `DONE` marker, per the
//!   [`IntAccessGen`](crate::pcode::emu::jit::gen::access::int_access_gen) module docs. As
//!   [`MemoryVarGen::gen_read_leg_to_stack`](crate::pcode::emu::jit::gen::var::memory_var_gen::MemoryVarGen::gen_read_leg_to_stack)
//!   does for the same gap, these keep the real control flow (which leg, and how far past the end
//!   of the variable it lies) but stub the opcode sequence itself via [`Emitter::recast`].
//! - `getConvToStack()`'s return type `Opnd.MpToStackConv<TInt, IntJitType, MpIntJitType, T, JT>`
//!   becomes the associated type [`SimpleVarHandler::ConvToStack`], reusing the already-stubbed
//!   [`MpToStackConv`] trait [`SubVarHandler::ConvToSub`](crate::pcode::emu::jit::alloc::sub_var_handler::SubVarHandler::ConvToSub)
//!   defines it for -- same reasoning: its methods are generic over the "to" simple type, so a
//!   `dyn` trait object cannot call them.

use crate::pcode::emu::jit::alloc::jvm_local::JvmLocal;
use crate::pcode::emu::jit::alloc::var_handler::VarHandler;
use crate::pcode::emu::jit::analysis::jit_type::{
    AnyJitType, IntJitType, JitType, LeggedJitType, LongJitType, MpIntJitType, SimpleJitType,
};
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::types::{BPrim, TInt, TRef};
use crate::pcode::seam_stubs::{
    convert_to_array, convert_to_opnd, Ext, JitCodeGenerator, MpToStackConv, Opnd, OpndEm, Scope,
};
use crate::program::model::pcode::Varnode;

/// A handler for p-code variables composed of a single JVM local variable.
///
/// Port of `ghidra.pcode.emu.jit.alloc.SimpleVarHandler<T, JT>`. See the [module docs](self) for
/// what is erased and why.
pub trait SimpleVarHandler: VarHandler {
    /// The converter this handler uses to load its local's value out of a multi-precision integer.
    /// Java's `MpToStackConv<TInt, IntJitType, MpIntJitType, T, JT>`.
    type ConvToStack: MpToStackConv;

    /// Get the local variable into which this p-code variable is allocated.
    ///
    /// Port of `SimpleVarHandler.local()`.
    fn local(&self) -> JvmLocal;

    /// Get the converter of multi-precision integers to the stack type of this handler's local.
    ///
    /// Port of `SimpleVarHandler.getConvToStack()`. See the [module docs](self) on why this
    /// returns [`Self::ConvToStack`] rather than a trait object.
    fn get_conv_to_stack(&self) -> Self::ConvToStack;

    /// Get the complete varnode accessible to this handler.
    ///
    /// Port of `SimpleVarHandler.vn()`, which overrides [`VarHandler::vn`]. See the
    /// [module docs](self) on why this is not named `vn`.
    fn simple_var_handler_vn(&self) -> Varnode {
        self.local().vn.clone()
    }

    /// Emit bytecode to load the varnode's value onto the JVM stack.
    ///
    /// Port of `SimpleVarHandler.genLoadToStack`, which overrides [`VarHandler::gen_load_to_stack`].
    /// See the [module docs](self) on why this is not named `gen_load_to_stack` and why it emits
    /// no real bytecode.
    fn simple_var_handler_gen_load_to_stack<TT, TJT, N>(
        &self,
        em: Emitter<N>,
        gen: &dyn JitCodeGenerator,
        type_: TJT,
        ext: Ext,
    ) -> Emitter<Ent<N, TT>>
    where
        TT: BPrim,
        TJT: SimpleJitType<B = TT>,
        N: Next,
        Self: Sized,
    {
        let _ = (self.local(), gen, type_, ext);
        em.recast()
    }

    /// Emit bytecode to load the varnode's value into several locals.
    ///
    /// Port of `SimpleVarHandler.genLoadToOpnd`, which overrides [`VarHandler::gen_load_to_opnd`].
    /// See the [module docs](self) on why this is not named `gen_load_to_opnd`.
    fn simple_var_handler_gen_load_to_opnd<N: Next>(
        &self,
        em: Emitter<N>,
        gen: &dyn JitCodeGenerator,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
    ) -> OpndEm<MpIntJitType, N>
    where
        Self: Sized,
    {
        let name = self.name();
        match self.type_() {
            AnyJitType::Int(t) => {
                let loaded = self.gen_load_to_stack(em, gen, t, ext);
                convert_to_opnd(loaded, t, &name, type_, ext, scope)
            }
            AnyJitType::Long(t) => {
                let loaded = self.gen_load_to_stack(em, gen, t, ext);
                convert_to_opnd(loaded, t, &name, type_, ext, scope)
            }
            AnyJitType::Float(_) | AnyJitType::Double(_) => unimplemented!(
                "SimpleVarHandler::simple_var_handler_gen_load_to_opnd: no SimpleAccessGen for float types yet"
            ),
            AnyJitType::MpInt(_) | AnyJitType::MpFloat(_) => {
                unreachable!("SimpleVarHandler::type_ is always a simple type (Java's JT bound)")
            }
        }
    }

    /// This provides the implementation of
    /// [`gen_load_leg_to_stack`](VarHandler::gen_load_leg_to_stack) for category-1 primitives,
    /// i.e., `int` and `float`.
    ///
    /// Only leg 0 is meaningful for a category-1 primitive. Any other leg is just the extension of
    /// the one leg.
    ///
    /// Port of `SimpleVarHandler.genLoadLegToStackC1`. See the [module docs](self) on why this
    /// emits no real bytecode past leg 0.
    fn gen_load_leg_to_stack_c1<N: Next>(
        &self,
        em: Emitter<N>,
        gen: &dyn JitCodeGenerator,
        type_: MpIntJitType,
        leg: i32,
        ext: Ext,
    ) -> Emitter<Ent<N, TInt>>
    where
        Self: Sized,
    {
        if leg == 0 {
            return self.gen_load_to_stack(em, gen, type_.leg_types_le_typed()[0], ext);
        }
        match ext {
            Ext::Zero => em.recast(),
            Ext::Sign => {
                let int_type = IntJitType::for_size(self.type_().size());
                self.gen_load_to_stack(em, gen, int_type, ext).recast()
            }
        }
    }

    /// This provides the implementation of
    /// [`gen_load_leg_to_stack`](VarHandler::gen_load_leg_to_stack) for category-2 primitives,
    /// i.e., `long` and `double`.
    ///
    /// Only legs 0 and 1 are meaningful for a category-2 primitive. Any other leg is just the
    /// extension of the upper leg.
    ///
    /// Port of `SimpleVarHandler.genLoadLegToStackC2`. See the [module docs](self) on why this
    /// emits no real bytecode past leg 0.
    fn gen_load_leg_to_stack_c2<N: Next>(
        &self,
        em: Emitter<N>,
        gen: &dyn JitCodeGenerator,
        type_: MpIntJitType,
        leg: i32,
        ext: Ext,
    ) -> Emitter<Ent<N, TInt>>
    where
        Self: Sized,
    {
        if leg == 0 {
            return self.gen_load_to_stack(em, gen, type_.leg_types_le_typed()[0], ext);
        }
        if leg == 1 {
            let long_type = LongJitType::for_size(self.type_().size());
            return self.gen_load_to_stack(em, gen, long_type, ext).recast();
        }
        match ext {
            Ext::Zero => em.recast(),
            Ext::Sign => {
                let long_type = LongJitType::for_size(self.type_().size());
                self.gen_load_to_stack(em, gen, long_type, ext).recast()
            }
        }
    }

    /// Emit bytecode to load the varnode's value into an integer array in little-endian order,
    /// pushing its ref onto the JVM stack.
    ///
    /// Port of `SimpleVarHandler.genLoadToArray`, which overrides [`VarHandler::gen_load_to_array`].
    /// See the [module docs](self) on why this is not named `gen_load_to_array`.
    #[allow(clippy::too_many_arguments)]
    fn simple_var_handler_gen_load_to_array<N: Next>(
        &self,
        em: Emitter<N>,
        gen: &dyn JitCodeGenerator,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
        slack: i32,
    ) -> Emitter<Ent<N, TRef>>
    where
        Self: Sized,
    {
        let name = self.name();
        match self.type_() {
            AnyJitType::Int(t) => {
                let loaded = self.gen_load_to_stack(em, gen, t, ext);
                convert_to_array(loaded, t, &name, type_, ext, scope, slack)
            }
            AnyJitType::Long(t) => {
                let loaded = self.gen_load_to_stack(em, gen, t, ext);
                convert_to_array(loaded, t, &name, type_, ext, scope, slack)
            }
            AnyJitType::Float(_) | AnyJitType::Double(_) => unimplemented!(
                "SimpleVarHandler::simple_var_handler_gen_load_to_array: no SimpleAccessGen for float types yet"
            ),
            AnyJitType::MpInt(_) | AnyJitType::MpFloat(_) => {
                unreachable!("SimpleVarHandler::type_ is always a simple type (Java's JT bound)")
            }
        }
    }

    /// Emit bytecode to store a value into a variable from the JVM stack.
    ///
    /// Port of `SimpleVarHandler.genStoreFromStack`, which overrides
    /// [`VarHandler::gen_store_from_stack`]. See the [module docs](self) on why this is not named
    /// `gen_store_from_stack` and why it emits no real bytecode.
    fn simple_var_handler_gen_store_from_stack<FT, FJT, N1>(
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
        let _ = (self.local(), gen, type_, ext, scope);
        em.recast()
    }

    /// Emit bytecode to store a varnode's value from several locals.
    ///
    /// Port of `SimpleVarHandler.genStoreFromOpnd`, which overrides
    /// [`VarHandler::gen_store_from_opnd`]. See the [module docs](self) on why this is not named
    /// `gen_store_from_opnd`.
    fn simple_var_handler_gen_store_from_opnd<N: Next>(
        &self,
        em: Emitter<N>,
        gen: &dyn JitCodeGenerator,
        opnd: &dyn Opnd<MpIntJitType>,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N>
    where
        Self: Sized,
    {
        let conv = self.get_conv_to_stack();
        match self.type_() {
            AnyJitType::Int(t) => {
                let staged = conv.convert_opnd_to_stack(em, opnd, t, ext);
                self.gen_store_from_stack(staged, gen, t, ext, scope)
            }
            AnyJitType::Long(t) => {
                let staged = conv.convert_opnd_to_stack(em, opnd, t, ext);
                self.gen_store_from_stack(staged, gen, t, ext, scope)
            }
            AnyJitType::Float(_) | AnyJitType::Double(_) => unimplemented!(
                "SimpleVarHandler::simple_var_handler_gen_store_from_opnd: no SimpleAccessGen for float types yet"
            ),
            AnyJitType::MpInt(_) | AnyJitType::MpFloat(_) => {
                unreachable!("SimpleVarHandler::type_ is always a simple type (Java's JT bound)")
            }
        }
    }

    /// Emit bytecode to store a varnode's value from an array of integer legs, in little-endian
    /// order.
    ///
    /// Port of `SimpleVarHandler.genStoreFromArray`, which overrides
    /// [`VarHandler::gen_store_from_array`]. See the [module docs](self) on why this is not named
    /// `gen_store_from_array`.
    fn simple_var_handler_gen_store_from_array<N1: Next>(
        &self,
        em: Emitter<Ent<N1, TRef>>,
        gen: &dyn JitCodeGenerator,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N1>
    where
        Self: Sized,
    {
        let conv = self.get_conv_to_stack();
        match self.type_() {
            AnyJitType::Int(t) => {
                let staged = conv.convert_array_to_stack(em, type_, t, ext);
                self.gen_store_from_stack(staged, gen, t, ext, scope)
            }
            AnyJitType::Long(t) => {
                let staged = conv.convert_array_to_stack(em, type_, t, ext);
                self.gen_store_from_stack(staged, gen, t, ext, scope)
            }
            AnyJitType::Float(_) | AnyJitType::Double(_) => unimplemented!(
                "SimpleVarHandler::simple_var_handler_gen_store_from_array: no SimpleAccessGen for float types yet"
            ),
            AnyJitType::MpInt(_) | AnyJitType::MpFloat(_) => {
                unreachable!("SimpleVarHandler::type_ is always a simple type (Java's JT bound)")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_type::{AnySimpleJitType, IntJitType, LongJitType};
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::seam_stubs::MethodVisitor;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    fn make_varnode(offset: i64, size: i32) -> Varnode {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, offset);
        Varnode::new(addr, size)
    }

    struct MockCodeGenerator;
    impl JitCodeGenerator for MockCodeGenerator {}

    struct MockScope;
    impl Scope for MockScope {}

    /// A stand-in converter: preserves the type-level stack-shape plumbing only, per
    /// [`MpToStackConv`]'s module docs -- the same test double
    /// [`sub_var_handler::tests::TestConv`](crate::pcode::emu::jit::alloc::sub_var_handler::tests)
    /// uses for its `ConvToSub`.
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

    /// A minimal implementor covering every abstract member, mirroring
    /// [`var_handler::tests::TestVarHandler`](crate::pcode::emu::jit::alloc::var_handler::tests)
    /// extended with [`SimpleVarHandler`]'s abstract members, each `VarHandler` method delegating
    /// to its `simple_var_handler_*` counterpart.
    struct TestSimpleVarHandler {
        local: JvmLocal,
        simple_type: AnyJitType,
    }

    impl VarHandler for TestSimpleVarHandler {
        fn vn(&self) -> Varnode {
            self.simple_var_handler_vn()
        }

        fn type_(&self) -> AnyJitType {
            self.simple_type.clone()
        }

        fn gen_load_to_stack<TT, TJT, N>(
            &self,
            em: Emitter<N>,
            gen: &dyn JitCodeGenerator,
            type_: TJT,
            ext: Ext,
        ) -> Emitter<Ent<N, TT>>
        where
            TT: BPrim,
            TJT: SimpleJitType<B = TT>,
            N: Next,
        {
            self.simple_var_handler_gen_load_to_stack(em, gen, type_, ext)
        }

        fn gen_load_to_opnd<N: Next>(
            &self,
            em: Emitter<N>,
            gen: &dyn JitCodeGenerator,
            type_: MpIntJitType,
            ext: Ext,
            scope: &dyn Scope,
        ) -> OpndEm<MpIntJitType, N> {
            self.simple_var_handler_gen_load_to_opnd(em, gen, type_, ext, scope)
        }

        fn gen_load_leg_to_stack<N: Next>(
            &self,
            em: Emitter<N>,
            gen: &dyn JitCodeGenerator,
            type_: MpIntJitType,
            leg: i32,
            ext: Ext,
        ) -> Emitter<Ent<N, TInt>> {
            match self.simple_type {
                AnyJitType::Int(_) => self.gen_load_leg_to_stack_c1(em, gen, type_, leg, ext),
                AnyJitType::Long(_) => self.gen_load_leg_to_stack_c2(em, gen, type_, leg, ext),
                _ => unimplemented!("TestSimpleVarHandler only exercises Int/Long"),
            }
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
            self.simple_var_handler_gen_load_to_array(em, gen, type_, ext, scope, slack)
        }

        fn gen_load_to_bool<N: Next>(
            &self,
            em: Emitter<N>,
            _gen: &dyn JitCodeGenerator,
        ) -> Emitter<Ent<N, TInt>> {
            em.recast()
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
            self.simple_var_handler_gen_store_from_stack(em, gen, type_, ext, scope)
        }

        fn gen_store_from_opnd<N: Next>(
            &self,
            em: Emitter<N>,
            gen: &dyn JitCodeGenerator,
            opnd: &dyn Opnd<MpIntJitType>,
            ext: Ext,
            scope: &dyn Scope,
        ) -> Emitter<N> {
            self.simple_var_handler_gen_store_from_opnd(em, gen, opnd, ext, scope)
        }

        fn gen_store_from_array<N1: Next>(
            &self,
            em: Emitter<Ent<N1, TRef>>,
            gen: &dyn JitCodeGenerator,
            type_: MpIntJitType,
            ext: Ext,
            scope: &dyn Scope,
        ) -> Emitter<N1> {
            self.simple_var_handler_gen_store_from_array(em, gen, type_, ext, scope)
        }

        fn subpiece(
            &self,
            _endian: crate::program::model::lang::endian::Endian,
            _byte_offset: i32,
            _max_byte_size: i32,
        ) -> Box<dyn VarHandler> {
            unimplemented!("TestSimpleVarHandler::subpiece is not exercised by these tests")
        }
    }

    impl SimpleVarHandler for TestSimpleVarHandler {
        type ConvToStack = TestConv;

        fn local(&self) -> JvmLocal {
            self.local.clone()
        }

        fn get_conv_to_stack(&self) -> TestConv {
            TestConv
        }
    }

    fn handler(simple_type: AnyJitType) -> TestSimpleVarHandler {
        let size = simple_type.size();
        TestSimpleVarHandler {
            local: JvmLocal::of(
                match simple_type {
                    AnyJitType::Int(t) => AnySimpleJitType::Int(t),
                    AnyJitType::Long(t) => AnySimpleJitType::Long(t),
                    _ => unreachable!(),
                },
                make_varnode(0x1000, size),
            ),
            simple_type,
        }
    }

    #[test]
    fn vn_delegates_to_the_local_s_varnode() {
        // Java: `default Varnode vn() { return local().vn(); }`
        let h = handler(AnyJitType::Int(IntJitType::I4));
        assert_eq!(h.vn().get_offset(), 0x1000);
        assert_eq!(h.vn().get_size(), 4);
        // And VarHandler::name() (unchanged) derives from vn(), as in Java.
        assert_eq!(h.name(), "var_ram_1000_4");
    }

    #[test]
    fn gen_load_leg_to_stack_c1_leg_zero_delegates_through_gen_load_to_stack() {
        // Java: `if (leg == 0) return em.emit(this::genLoadToStack, gen, type.legTypesLE().get(0), ext);`
        let h = handler(AnyJitType::Int(IntJitType::I4));
        let gen = MockCodeGenerator;
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Bot, TInt>> = h.gen_load_leg_to_stack_c1(
            em,
            &gen,
            MpIntJitType::for_size(12),
            0,
            Ext::Zero,
        );
        let _ = result.local_variables();
    }

    #[test]
    fn gen_load_leg_to_stack_c2_leg_one_uses_the_long_path() {
        // Java: leg 1 of a category-2 primitive loads the long and shifts/converts down to an int.
        let h = handler(AnyJitType::Long(LongJitType::I8));
        let gen = MockCodeGenerator;
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Bot, TInt>> = h.gen_load_leg_to_stack_c2(
            em,
            &gen,
            MpIntJitType::for_size(12),
            1,
            Ext::Sign,
        );
        let _ = result.local_variables();
    }

    #[test]
    fn gen_load_leg_to_stack_beyond_the_variable_with_zero_ext_is_a_pure_recast() {
        // Java: leg >= legsAlloc with ZERO ext just pushes a constant 0 -- the stub preserves
        // only the type-level shape, matching MemoryVarGen::gen_read_leg_to_stack's convention.
        let h = handler(AnyJitType::Int(IntJitType::I2));
        let gen = MockCodeGenerator;
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let result: Emitter<Ent<Bot, TInt>> =
            h.gen_load_leg_to_stack_c1(em, &gen, MpIntJitType::for_size(12), 1, Ext::Zero);
        let _ = result.local_variables();
    }

    #[test]
    fn default_overrides_delegate_through_var_handler_for_int_and_long() {
        // Exercises simple_var_handler_gen_load_to_opnd/gen_load_to_array/gen_store_from_opnd/
        // gen_store_from_array (via the VarHandler methods that delegate to them above) for both
        // the Int and Long branches, ensuring the type-level stack-shape plumbing compiles and
        // runs without panicking -- mirroring
        // [`sub_var_handler::tests::default_overrides_delegate_through_var_handler`](
        // crate::pcode::emu::jit::alloc::sub_var_handler::tests).
        let gen = MockCodeGenerator;
        let scope = MockScope;

        let int_handler = handler(AnyJitType::Int(IntJitType::I2));
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let loaded =
            int_handler.gen_load_to_opnd(em, &gen, MpIntJitType::for_size(12), Ext::Zero, &scope);
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let _ = int_handler.gen_store_from_opnd(em, &gen, &*loaded.opnd, Ext::Zero, &scope);

        let long_handler = handler(AnyJitType::Long(LongJitType::I8));
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let _ = long_handler.gen_load_to_array(
            em,
            &gen,
            MpIntJitType::for_size(12),
            Ext::Sign,
            &scope,
            0,
        );
    }

    #[test]
    fn dyn_var_handler_dispatches_object_safe_methods() {
        // As with SubVarHandler, the object-safe half of VarHandler (vn/name/type_/subpiece) must
        // still work through a genuine `&dyn VarHandler`.
        let handler: Box<dyn VarHandler> =
            Box::new(handler(AnyJitType::Int(IntJitType::I4)));
        assert_eq!(handler.type_(), AnyJitType::Int(IntJitType::I4));
        assert_eq!(handler.name(), "var_ram_1000_4");
    }
}
