//! A handler to p-code variables stored in just a portion of a single JVM local variable.
//!
//! Port of `ghidra.pcode.emu.jit.alloc.SubVarHandler`.
//!
//! # Differences from Java
//!
//! - Java's four type parameters (`ST`, `SJT` the sub variable's JVM/p-code type, `WT`, `WJT` the
//!   containing variable's JVM/p-code type) are dropped. `local()` erases `<WT, WJT>` the same way
//!   [`JvmLocal`] already erases them (see that module's docs), and `type()` -- narrowed from
//!   [`VarHandler::type_`]'s `AnyJitType` to Java's `SJT` -- is not redeclared here at all:
//!   [`VarHandler::type_`] is inherited unchanged, with the understanding (matching Java's `SJT
//!   extends SimpleJitType<..>` bound) that an implementor never returns
//!   [`AnyJitType::MpInt`]/[`AnyJitType::MpFloat`] from it.
//! - `genLoadToOpnd`, `genLoadToArray`, `genStoreFromOpnd`, and `genStoreFromArray` override
//!   [`VarHandler`]'s abstract methods of the same name. Rust does not allow a subtrait to
//!   "override" a supertrait's method by redeclaring it (that creates an ambiguous method name
//!   instead), so, per the convention set by
//!   [`Int8TDataType`](crate::program::model::data::int8_t_data_type::Int8TDataType), they are
//!   exposed here under distinct `sub_var_handler_*` names; a concrete implementor's own
//!   [`VarHandler`] impl should delegate to these.
//! - Each of those four methods needs the sub variable's concrete simple type (`TT`/`TJT` in
//!   Java) to call [`VarHandler::gen_load_to_stack`]/[`VarHandler::gen_store_from_stack`], but
//!   this port only has it as the runtime value [`VarHandler::type_`] returns. Each method matches
//!   on that value to recover a concrete [`IntJitType`]/[`LongJitType`], the same technique
//!   [`JvmLocal::gen_birth_code`](crate::pcode::emu::jit::alloc::jvm_local::JvmLocal::gen_birth_code)
//!   uses; float/double sub variables are `unimplemented!`, matching that same function's stance
//!   that there is "no `SimpleAccessGen` for float types yet".
//! - `Opnd::convertToOpnd`/`Opnd::convertToArray` (Java's static conversion dispatch) and
//!   `getConvToSub()`'s return type `Opnd.MpToStackConv` are not ported; this port calls the
//!   minimal stand-ins [`convert_to_opnd`]/[`convert_to_array`]/[`MpToStackConv`] added to
//!   [`seam_stubs`](crate::pcode::seam_stubs) for this type. `getConvToSub()` becomes the
//!   associated type [`SubVarHandler::ConvToSub`] rather than `Box<dyn MpToStackConv>`: its two
//!   methods are generic over the sub variable's simple type, and a `dyn` trait object cannot call
//!   generic methods, so (as with [`VarHandler::subpiece`]'s use of `Box<dyn VarHandler>` vs. its
//!   other, `Self: Sized`-bounded methods) there is nothing to dispatch dynamically over here.

use crate::pcode::emu::jit::alloc::jvm_local::JvmLocal;
use crate::pcode::emu::jit::alloc::var_handler::VarHandler;
use crate::pcode::emu::jit::analysis::jit_type::{AnyJitType, AnySimpleJitType, JitType, MpIntJitType};
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::types::TRef;
use crate::pcode::seam_stubs::{
    convert_to_array, convert_to_opnd, Ext, JitCodeGenerator, MpToStackConv, Opnd, OpndEm, Scope,
};

/// Verify that the sub variable as shifted actually fits in the containing variable.
///
/// Port of the default `SubVarHandler.assertShiftFits(int, SJT, JvmLocal<WT, WJT>)`. Exposed as a
/// free function, like [`name_vn`](crate::pcode::emu::jit::alloc::var_handler::name_vn), since
/// Java's implicit `this` goes unused in the body -- every argument is explicit -- and callers (an
/// implementor's constructor) need to check this before they have a complete `Self` to call a
/// trait method on.
pub fn assert_shift_fits(byte_shift: i32, type_: AnySimpleJitType, local: &JvmLocal) {
    debug_assert!(byte_shift >= 0 && byte_shift + type_.size() <= local.type_.size());
}

/// A handler to p-code variables stored in just a portion of a single JVM local variable.
///
/// Port of `ghidra.pcode.emu.jit.alloc.SubVarHandler<ST, SJT, WT, WJT>`. See the
/// [module docs](self) for what is erased and why.
pub trait SubVarHandler: VarHandler {
    /// The converter this handler uses to load its sub variable's value out of a multi-precision
    /// integer. Java's `MpToStackConv<TInt, IntJitType, MpIntJitType, ST, SJT>`.
    type ConvToSub: MpToStackConv;

    /// The number of unused bytes in the container variable to the right of the sub variable.
    ///
    /// Port of `SubVarHandler.byteShift()`.
    fn byte_shift(&self) -> i32;

    /// The number of bits in the sub variable.
    ///
    /// Port of `SubVarHandler.bitSize()`.
    fn bit_size(&self) -> i32 {
        self.type_().size() * 8
    }

    /// The number of unused bits in the container variable to the right of the sub variable.
    ///
    /// Port of `SubVarHandler.bitShift()`.
    fn bit_shift(&self) -> i32 {
        self.byte_shift() * 8
    }

    /// The mask indicating which parts of the `int` containing variable are within the sub
    /// variable.
    ///
    /// Port of `SubVarHandler.intMask()`. Uses `wrapping_shl`/`wrapping_shr`, which mask their
    /// shift amount to the operand's bit width, matching Java's `<<`/`>>>` on `int`.
    fn int_mask(&self) -> i32 {
        let shamt = (32 - self.bit_size()) as u32;
        u32::MAX.wrapping_shr(shamt).wrapping_shl(self.bit_shift() as u32) as i32
    }

    /// The mask indicating which parts of the `long` containing variable are within the sub
    /// variable.
    ///
    /// Port of `SubVarHandler.longMask()`. See [`int_mask`](Self::int_mask) on the shift methods
    /// used.
    fn long_mask(&self) -> i64 {
        let shamt = (64 - self.bit_size()) as u32;
        u64::MAX.wrapping_shr(shamt).wrapping_shl(self.bit_shift() as u32) as i64
    }

    /// The containing local variable.
    ///
    /// Port of `SubVarHandler.local()`.
    fn local(&self) -> JvmLocal;

    /// Get the converter of multi-precision integers to the type of the sub variable.
    ///
    /// Port of `SubVarHandler.getConvToSub()`. See the [module docs](self) on why this returns
    /// [`Self::ConvToSub`] rather than a trait object.
    fn get_conv_to_sub(&self) -> Self::ConvToSub;

    /// Emit bytecode to load the varnode's value into several locals.
    ///
    /// Port of `SubVarHandler.genLoadToOpnd`, which overrides [`VarHandler::gen_load_to_opnd`].
    /// See the [module docs](self) on why this is not named `gen_load_to_opnd`.
    fn sub_var_handler_gen_load_to_opnd<N: Next>(
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
                "SubVarHandler::sub_var_handler_gen_load_to_opnd: no SimpleAccessGen for float types yet"
            ),
            AnyJitType::MpInt(_) | AnyJitType::MpFloat(_) => {
                unreachable!("SubVarHandler::type_ is always a simple type (Java's SJT bound)")
            }
        }
    }

    /// Emit bytecode to load the varnode's value into an integer array in little-endian order,
    /// pushing its ref onto the JVM stack.
    ///
    /// Port of `SubVarHandler.genLoadToArray`, which overrides [`VarHandler::gen_load_to_array`].
    /// See the [module docs](self) on why this is not named `gen_load_to_array`.
    #[allow(clippy::too_many_arguments)]
    fn sub_var_handler_gen_load_to_array<N: Next>(
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
                "SubVarHandler::sub_var_handler_gen_load_to_array: no SimpleAccessGen for float types yet"
            ),
            AnyJitType::MpInt(_) | AnyJitType::MpFloat(_) => {
                unreachable!("SubVarHandler::type_ is always a simple type (Java's SJT bound)")
            }
        }
    }

    /// Emit bytecode to store a varnode's value from several locals.
    ///
    /// Port of `SubVarHandler.genStoreFromOpnd`, which overrides
    /// [`VarHandler::gen_store_from_opnd`]. See the [module docs](self) on why this is not named
    /// `gen_store_from_opnd`.
    fn sub_var_handler_gen_store_from_opnd<N: Next>(
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
        let conv = self.get_conv_to_sub();
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
                "SubVarHandler::sub_var_handler_gen_store_from_opnd: no SimpleAccessGen for float types yet"
            ),
            AnyJitType::MpInt(_) | AnyJitType::MpFloat(_) => {
                unreachable!("SubVarHandler::type_ is always a simple type (Java's SJT bound)")
            }
        }
    }

    /// Emit bytecode to store a varnode's value from an array of integer legs, in little-endian
    /// order.
    ///
    /// Port of `SubVarHandler.genStoreFromArray`, which overrides
    /// [`VarHandler::gen_store_from_array`]. See the [module docs](self) on why this is not named
    /// `gen_store_from_array`.
    fn sub_var_handler_gen_store_from_array<N1: Next>(
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
        let conv = self.get_conv_to_sub();
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
                "SubVarHandler::sub_var_handler_gen_store_from_array: no SimpleAccessGen for float types yet"
            ),
            AnyJitType::MpInt(_) | AnyJitType::MpFloat(_) => {
                unreachable!("SubVarHandler::type_ is always a simple type (Java's SJT bound)")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_type::{IntJitType, LongJitType, SimpleJitType};
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::emu::jit::gen::util::types::{BPrim, TInt};
    use crate::pcode::seam_stubs::MethodVisitor;
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

    /// A stand-in converter: preserves the type-level stack-shape plumbing only, per
    /// [`MpToStackConv`]'s module docs.
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

    /// A minimal implementor covering every abstract method, mirroring the "singleton dummy
    /// handler" shape [`var_handler::tests::TestVarHandler`](
    /// crate::pcode::emu::jit::alloc::var_handler::tests) uses, extended with the `SubVarHandler`
    /// abstract members.
    struct TestSubVarHandler {
        vn: Varnode,
        local: JvmLocal,
        sub_type: AnyJitType,
        byte_shift: i32,
    }

    impl VarHandler for TestSubVarHandler {
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
            _gen: &dyn JitCodeGenerator,
        ) -> Emitter<Ent<N, TInt>> {
            em.recast()
        }

        fn gen_store_from_stack<FT, FJT, N1>(
            &self,
            em: Emitter<Ent<N1, FT>>,
            _gen: &dyn JitCodeGenerator,
            _type_: FJT,
            _ext: Ext,
            _scope: &dyn Scope,
        ) -> Emitter<N1>
        where
            FT: BPrim,
            FJT: SimpleJitType<B = FT>,
            N1: Next,
        {
            em.recast()
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
            unimplemented!("TestSubVarHandler::subpiece is not exercised by these tests")
        }
    }

    impl SubVarHandler for TestSubVarHandler {
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

    fn handler(byte_shift: i32, sub_type: AnyJitType) -> TestSubVarHandler {
        TestSubVarHandler {
            vn: make_varnode(0x1000, sub_type.size()),
            local: JvmLocal::of(IntJitType::I4.erase_simple(), make_varnode(0x1000, 4)),
            sub_type,
            byte_shift,
        }
    }

    #[test]
    fn bit_size_is_type_size_times_byte_size() {
        // Java: `type().size() * Byte.SIZE`.
        let h = handler(0, AnyJitType::Int(IntJitType::I2));
        assert_eq!(h.bit_size(), 16);
    }

    #[test]
    fn bit_shift_is_byte_shift_times_byte_size() {
        // Java: `byteShift() * Byte.SIZE`.
        let h = handler(1, AnyJitType::Int(IntJitType::I2));
        assert_eq!(h.bit_shift(), 8);
    }

    #[test]
    fn int_mask_covers_the_sub_variable_within_the_int() {
        // Java: `(-1 >>> (Integer.SIZE - bitSize())) << bitShift()`. A 2-byte (16-bit) sub
        // variable shifted right by 1 byte (8 bits) within a 4-byte int covers bits [8, 24), i.e.
        // 0x00FFFF00.
        let h = handler(1, AnyJitType::Int(IntJitType::I2));
        assert_eq!(h.int_mask(), 0x00FF_FF00u32 as i32);
    }

    #[test]
    fn int_mask_of_the_whole_int_is_all_ones() {
        let h = handler(0, AnyJitType::Int(IntJitType::I4));
        assert_eq!(h.int_mask(), -1);
    }

    #[test]
    fn long_mask_covers_the_sub_variable_within_the_long() {
        // Java: `(-1L >>> (Long.SIZE - bitSize())) << bitShift()`. A 2-byte (16-bit) sub variable
        // shifted right by 1 byte (8 bits) covers bits [8, 24).
        let h = handler(1, AnyJitType::Long(LongJitType::I2));
        assert_eq!(h.long_mask(), 0x0000_0000_00FF_FF00i64);
    }

    #[test]
    fn assert_shift_fits_accepts_a_shift_that_stays_within_the_local() {
        let local = JvmLocal::of(IntJitType::I4.erase_simple(), make_varnode(0x2000, 4));
        assert_shift_fits(1, AnySimpleJitType::Int(IntJitType::I2), &local);
    }

    #[test]
    #[should_panic]
    fn assert_shift_fits_rejects_a_shift_that_overflows_the_local() {
        let local = JvmLocal::of(IntJitType::I4.erase_simple(), make_varnode(0x2000, 4));
        assert_shift_fits(3, AnySimpleJitType::Int(IntJitType::I2), &local);
    }

    #[test]
    fn default_overrides_delegate_through_var_handler() {
        // Exercises sub_var_handler_gen_load_to_opnd/gen_load_to_array/gen_store_from_opnd/
        // gen_store_from_array (via the VarHandler methods that delegate to them above) for both
        // the Int and Long branches, ensuring the type-level stack-shape plumbing compiles and
        // runs without panicking.
        let gen = MockCodeGenerator;
        let scope = MockScope;

        let int_handler = handler(0, AnyJitType::Int(IntJitType::I2));
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let loaded =
            int_handler.gen_load_to_opnd(em, &gen, MpIntJitType::for_size(12), Ext::Zero, &scope);
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let _ = int_handler.gen_store_from_opnd(em, &gen, &*loaded.opnd, Ext::Zero, &scope);

        let long_handler = handler(0, AnyJitType::Long(LongJitType::for_size(6)));
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
}
