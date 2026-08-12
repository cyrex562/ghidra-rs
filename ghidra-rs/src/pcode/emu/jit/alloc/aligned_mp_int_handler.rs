//! The handler for a varnode allocated as several JVM `int` locals, one per leg.
//!
//! Port of `ghidra.pcode.emu.jit.alloc.AlignedMpIntHandler`.
//!
//! In this case, we can usually give the operators direct access to the underlying mp-int operand.
//! We do need to be careful that we don't unintentionally permit the operator to use the
//! variable's storage for intermediate values. Thus, we have some provision for saying each leg is
//! read-only, which will cause attempts to store into them to instead generate a writable
//! temporary local. Such intermediate results will get written only by a call to
//! [`gen_store_from_opnd`](VarHandler::gen_store_from_opnd).
//!
//! # Differences from Java
//!
//! - Java's `JvmLocal<TInt, IntJitType>` element type collapses to the erased [`JvmLocal`], as
//!   everywhere else in this port (see that module's docs).
//! - `MpIntLocalOpnd` is not ported; the [`opnd`](AlignedMpIntHandler::opnd)/
//!   [`ro_opnd`](AlignedMpIntHandler::ro_opnd) members hold the minimal
//!   [`MpIntLocalOpnd`](crate::pcode::seam_stubs::MpIntLocalOpnd) placeholder, which carries the
//!   operand's type and name but not its legs -- there is no way to construct a
//!   [`SimpleOpnd`](crate::pcode::emu::jit::gen::opnd::simple_opnd::SimpleOpnd) value yet, and it
//!   is not object-safe besides. `createOpnd`/`createRoOpnd` therefore reduce to building the
//!   operand's name (`nameVn(vn)` and `nameVn(vn) + "_ro"`), which is the part of their behavior
//!   this port can still observe.
//! - Java's record accessors become public fields; `vn()` and `type()` are additionally exposed as
//!   [`VarHandler`] methods, as the interface requires. The canonical 5-argument record
//!   constructor is a plain struct literal; [`AlignedMpIntHandler::new`] is Java's "preferred"
//!   3-argument constructor, which derives the two operands.
//! - Every generator method's *bytecode* is stubbed. Their real bodies go through `Op` (the JVM
//!   opcode emitters), `Opnd`'s static conversions, and `JvmLocal.genLoadToStack`/
//!   `genStoreFromStack`, none of which are ported -- see the
//!   [`JvmLocal`] and [`SimpleVarHandler`](crate::pcode::emu::jit::alloc::simple_var_handler)
//!   module docs for that gap. Following the convention those set, each method keeps the *real*
//!   control flow -- which leg is selected, how many legs get zero- or sign-filled, which of
//!   Java's `switch` arms applies (including its `default -> throw new AssertionError()` for
//!   float types) -- and only the opcode sequence itself collapses to [`Emitter::recast`].
//! - `genStoreFromOpnd` is the one method whose control flow cannot be preserved: Java derives
//!   `legsIn` from `from.type().castLegsLE(from)`, and the marker-only
//!   [`Opnd`] stub exposes neither `type()` nor `legsLE()`. Since the per-leg loop and the trailing
//!   `genExt` are pure emission in this port state, it returns the emitter unchanged; restore the
//!   loop once `Opnd` is really ported.
//! - [`sub_handler`] (Java's package-private static `subHandler`, also used by
//!   `ShiftedMpIntHandler`) is ported in full: it is pure arithmetic over
//!   [`JitDataFlowArithmetic::sub_piece_vn`] and the leg list, with no bytecode involved. The three
//!   handlers it can return that are not ported yet --
//!   [`IntVarAlloc`], [`IntInIntHandler`], and [`ShiftedMpIntHandler`] -- are the forward edge of
//!   this file's dependency cycle, and are the minimal placeholders in
//!   [`seam_stubs`](crate::pcode::seam_stubs).

use crate::pcode::emu::jit::alloc::jvm_local::JvmLocal;
use crate::pcode::emu::jit::alloc::var_handler::{name_vn, VarHandler};
use crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic::JitDataFlowArithmetic;
use crate::pcode::emu::jit::analysis::jit_type::{
    AnyJitType, AnySimpleJitType, IntJitType, JitType, LeggedJitType, LongJitType, MpIntJitType,
    SimpleJitType,
};
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::types::{BPrim, TInt, TLong, TRef};
use crate::pcode::seam_stubs::{
    convert_opnd_to_array, convert_opnd_to_opnd, Ext, IntInIntHandler, IntVarAlloc,
    JitCodeGenerator, MpIntLocalOpnd, Opnd, OpndEm, Scope, ShiftedMpIntHandler,
};
use crate::program::model::lang::endian::Endian;
use crate::program::model::pcode::Varnode;

/// The number of bytes in a JVM `int`, i.e., Java's `Integer.BYTES`.
///
/// Duplicated here as in [`memory_var_gen`](crate::pcode::emu::jit::gen::var::memory_var_gen),
/// since [`jit_type`](crate::pcode::emu::jit::analysis::jit_type)'s copy is private.
const INT_BYTES: i32 = 4;

/// The number of bits in a JVM `int`, i.e., Java's `Integer.SIZE`.
const INT_SIZE: i32 = 32;

/// The handler used for a varnode requiring allocation of multiple integers, where those integers
/// correspond exactly to the variable's legs.
///
/// Port of `ghidra.pcode.emu.jit.alloc.AlignedMpIntHandler`. See the [module docs](self).
#[derive(Debug, Clone)]
pub struct AlignedMpIntHandler {
    /// The list of legs in little-endian order. Port of `AlignedMpIntHandler.legs()`.
    pub legs: Vec<JvmLocal>,
    /// The type of the full multi-precision integer variable. Port of
    /// `AlignedMpIntHandler.type()`.
    pub type_: MpIntJitType,
    /// The complete varnode accessible to this handler. Port of `AlignedMpIntHandler.vn()`.
    pub vn: Varnode,
    /// The (writable) list of local operands, in little-endian order. Port of
    /// `AlignedMpIntHandler.opnd()`.
    pub opnd: MpIntLocalOpnd,
    /// The read-only version of [`opnd`](Self::opnd). Port of `AlignedMpIntHandler.roOpnd()`.
    pub ro_opnd: MpIntLocalOpnd,
}

impl AlignedMpIntHandler {
    /// Create a handler for the given legs, type, and varnode, deriving both operands.
    ///
    /// Port of the preferred constructor `AlignedMpIntHandler(List, MpIntJitType, Varnode)`,
    /// which delegates to the canonical one with `createOpnd(..)`/`createRoOpnd(..)`.
    pub fn new(legs: Vec<JvmLocal>, type_: MpIntJitType, vn: Varnode) -> Self {
        let opnd = Self::create_opnd(&legs, &type_, &vn);
        let ro_opnd = Self::create_ro_opnd(&legs, &type_, &vn);
        Self { legs, type_, vn, opnd, ro_opnd }
    }

    /// Build the writable operand.
    ///
    /// Port of the private static `AlignedMpIntHandler.createOpnd`. Java collects `leg.opnd()`
    /// from each leg; this port has no legs to collect (see the [module docs](self)), so only the
    /// type and name survive.
    fn create_opnd(legs: &[JvmLocal], type_: &MpIntJitType, vn: &Varnode) -> MpIntLocalOpnd {
        let _ = legs;
        MpIntLocalOpnd::of(type_.clone(), name_vn(vn))
    }

    /// Build the read-only operand.
    ///
    /// Port of the private static `AlignedMpIntHandler.createRoOpnd`. Java wraps each leg with
    /// `SimpleOpnd.ofIntReadOnly(leg.type(), leg.local())`; see [`create_opnd`](Self::create_opnd)
    /// on why only the `_ro`-suffixed name survives here.
    fn create_ro_opnd(legs: &[JvmLocal], type_: &MpIntJitType, vn: &Varnode) -> MpIntLocalOpnd {
        let _ = legs;
        MpIntLocalOpnd::of(type_.clone(), format!("{}_ro", name_vn(vn)))
    }

    /// Emit bytecode to store a JVM `int` from the stack into the given local.
    ///
    /// Port of the protected `AlignedMpIntHandler.doGenStoreInt`. The emission itself is stubbed
    /// (see the [module docs](self)); the stack shape is real: the `int` is popped.
    pub fn do_gen_store_int<N1: Next>(
        &self,
        em: Emitter<Ent<N1, TInt>>,
        gen: &dyn JitCodeGenerator,
        type_: IntJitType,
        local: &JvmLocal,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N1> {
        let _ = (gen, type_, local, ext, scope);
        em.recast()
    }

    /// Emit bytecode to compute the sign of the `int` on the stack, and store that `int` into a
    /// given local.
    ///
    /// The `int` is copied and stored into the given local. Then, the sign of the `int` is
    /// computed and remains on the stack. Signed extension is assumed.
    ///
    /// Port of the protected `AlignedMpIntHandler.doGenStoreIntAndSign`. The stack shape is real:
    /// the incoming `int` is popped and the sign `int` is pushed.
    pub fn do_gen_store_int_and_sign<N1: Next>(
        &self,
        em: Emitter<Ent<N1, TInt>>,
        gen: &dyn JitCodeGenerator,
        type_: IntJitType,
        local: &JvmLocal,
        scope: &dyn Scope,
    ) -> Emitter<Ent<N1, TInt>> {
        // Java: dup; doGenStoreInt(.., SIGN, ..); ldc Integer.SIZE - 1; ishr
        let em = self.do_gen_store_int(em, gen, type_, local, Ext::Sign, scope);
        let _ = INT_SIZE - 1;
        em.recast()
    }

    /// Emit bytecode to store a JVM `long` from the stack into two given locals.
    ///
    /// Port of the protected `AlignedMpIntHandler.doGenStoreLong`. The `long` is popped. Note that
    /// the upper local receives the value typed `LongJitType.forSize(type.size() -
    /// Integer.BYTES)`, which panics for a `type` of 4 bytes or fewer, exactly as Java's
    /// `forSize` throws.
    #[allow(clippy::too_many_arguments)]
    pub fn do_gen_store_long<N1: Next>(
        &self,
        em: Emitter<Ent<N1, TLong>>,
        gen: &dyn JitCodeGenerator,
        type_: LongJitType,
        lower: &JvmLocal,
        upper: &JvmLocal,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N1> {
        let upper_type = LongJitType::for_size(type_.size() - INT_BYTES);
        let _ = (gen, lower, upper, upper_type, ext, scope, INT_SIZE);
        em.recast()
    }

    /// Emit bytecode to compute the sign of the `long` on the stack, and store that `long` into
    /// two given locals.
    ///
    /// The `long` is copied and stored into the given locals. Then, the sign of the `long` is
    /// computed and remains on the stack as an `int`. Signed extension is assumed.
    ///
    /// Port of the protected `AlignedMpIntHandler.doGenStoreLongAndSign`. The stack shape is real:
    /// the `long` is popped and the sign `int` is pushed.
    pub fn do_gen_store_long_and_sign<N1: Next>(
        &self,
        em: Emitter<Ent<N1, TLong>>,
        gen: &dyn JitCodeGenerator,
        type_: LongJitType,
        lower: &JvmLocal,
        upper: &JvmLocal,
        scope: &dyn Scope,
    ) -> Emitter<Ent<N1, TInt>> {
        let _ = (gen, type_, lower, upper, scope, IntJitType::I4, INT_SIZE);
        em.recast()
    }

    /// Emit bytecode to zero fill the given locals.
    ///
    /// Port of the protected `AlignedMpIntHandler.doGenZeroFill`. Each iteration pushes a constant
    /// 0 and immediately stores it, so the net stack shape is unchanged.
    pub fn do_gen_zero_fill<N: Next>(
        &self,
        em: Emitter<N>,
        gen: &dyn JitCodeGenerator,
        locals: &[JvmLocal],
        scope: &dyn Scope,
    ) -> Emitter<N> {
        let _ = (gen, locals, scope);
        em
    }

    /// Emit bytecode to sign fill the given locals.
    ///
    /// Port of the protected `AlignedMpIntHandler.doGenSignFill`. The sign `int` on top of the
    /// stack is `dup`ed into all but the last local, then consumed by the last, so the net shape
    /// pops one `int`. Java's `locals.getLast()` throws on an empty list; this panics instead.
    pub fn do_gen_sign_fill<N1: Next>(
        &self,
        em: Emitter<Ent<N1, TInt>>,
        gen: &dyn JitCodeGenerator,
        locals: &[JvmLocal],
        scope: &dyn Scope,
    ) -> Emitter<N1> {
        let (last, rest) = locals
            .split_last()
            .expect("NoSuchElementException: doGenSignFill with no locals");
        let _ = (gen, rest, last, scope);
        em.recast()
    }

    /// Emit bytecode to extend the value stored in our legs.
    ///
    /// Port of the protected `AlignedMpIntHandler.genExt`.
    ///
    /// - `def_legs`: the number of legs having the input value.
    /// - `legs_out`: the number of legs to receive the output value. If this is less than or equal
    ///   to `def_legs`, there is no extension to apply, so no code is emitted.
    pub fn gen_ext<N: Next>(
        &self,
        em: Emitter<N>,
        gen: &dyn JitCodeGenerator,
        def_legs: i32,
        legs_out: i32,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N> {
        if legs_out <= def_legs {
            return em;
        }
        let fill = &self.legs[def_legs as usize..legs_out as usize];
        match ext {
            Ext::Zero => self.do_gen_zero_fill(em, gen, fill, scope),
            Ext::Sign => {
                // Java: iload legs[defLegs - 1]; ldc Integer.SIZE - 1; ishr (signed)
                let _ = (&self.legs[(def_legs - 1) as usize], INT_SIZE - 1);
                self.do_gen_sign_fill(em.recast(), gen, fill, scope)
            }
        }
    }
}

/// A utility for implementing [`VarHandler::subpiece`], also used by `ShiftedMpIntHandler`.
///
/// Port of the package-private static `AlignedMpIntHandler.subHandler`. This is pure arithmetic
/// over the sub-varnode and the leg list, so it is ported in full.
///
/// - `endian`: the endianness of the emulation target. Technically, this is only used in the
///   naming of any temporary local variables.
/// - `vn`: the varnode of the original handler.
/// - `parts`: the parts (perhaps aligned to the legs) of the original handler.
/// - `cur_shift`: if shifted, the number of bytes. If aligned, 0.
/// - `add_shift`: the offset (in bytes) of the subpiece, i.e., additional shift.
/// - `max_byte_size`: the size in bytes of the output operand, which indicates the maximum size of
///   the resulting handler's varnode.
pub fn sub_handler(
    endian: Endian,
    vn: &Varnode,
    parts: &[JvmLocal],
    cur_shift: i32,
    add_shift: i32,
    max_byte_size: i32,
) -> Box<dyn VarHandler> {
    let sub_vn = JitDataFlowArithmetic::sub_piece_vn(endian, vn, add_shift, max_byte_size);
    let total_shift = cur_shift + add_shift;
    let first_part = total_shift / INT_BYTES;
    let last_part_excl = (total_shift + sub_vn.get_size() + INT_BYTES - 1) / INT_BYTES;
    let sub_parts = &parts[first_part as usize..last_part_excl as usize];
    let sub_shift = total_shift % INT_BYTES;

    if sub_parts.len() == 1 {
        let sub_type = IntJitType::for_size(sub_vn.get_size());
        if sub_shift == 0 {
            return Box::new(IntVarAlloc::new(sub_parts[0].clone(), sub_type));
        }
        return Box::new(IntInIntHandler::new(
            sub_parts[0].clone(),
            sub_type,
            sub_vn,
            sub_shift,
        ));
    }
    let sub_type = MpIntJitType::for_size(sub_vn.get_size());
    if sub_shift == 0 {
        return Box::new(AlignedMpIntHandler::new(sub_parts.to_vec(), sub_type, sub_vn));
    }
    Box::new(ShiftedMpIntHandler::new(
        sub_parts.to_vec(),
        sub_type,
        sub_vn,
        sub_shift,
    ))
}

impl VarHandler for AlignedMpIntHandler {
    fn vn(&self) -> Varnode {
        self.vn.clone()
    }

    fn type_(&self) -> AnyJitType {
        AnyJitType::MpInt(self.type_.clone())
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
        match type_.erase_simple() {
            // Java: `case IntJitType t -> em.emit(legs.get(0)::genLoadToStack, gen, to, ext)`
            AnySimpleJitType::Int(_) => {
                let _ = (&self.legs[0], gen, ext);
                em.recast()
            }
            AnySimpleJitType::Long(_) if self.legs.len() == 1 => {
                let _ = (&self.legs[0], gen, ext);
                em.recast()
            }
            // Java: load legs 0 and 1 as I8/ZERO, `lshl` the upper by Integer.SIZE, `lor`, then
            // convert the resulting I8 to the requested type.
            AnySimpleJitType::Long(_) => {
                let _ = (&self.legs[0], &self.legs[1], gen, LongJitType::I8, ext, INT_SIZE);
                em.recast()
            }
            // Java: `default -> throw new AssertionError()`
            AnySimpleJitType::Float(_) | AnySimpleJitType::Double(_) => {
                panic!("AssertionError: AlignedMpIntHandler cannot load to a float type")
            }
        }
    }

    fn gen_load_to_opnd<N: Next>(
        &self,
        em: Emitter<N>,
        gen: &dyn JitCodeGenerator,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
    ) -> OpndEm<MpIntJitType, N> {
        // Java: MpIntToMpInt.INSTANCE.convertOpndToOpnd(em, roOpnd, to, ext, scope). Note the
        // *read-only* operand: an operator must not scribble on this variable's storage.
        let _ = gen;
        convert_opnd_to_opnd(em, &self.ro_opnd, type_, ext, scope)
    }

    fn gen_load_leg_to_stack<N: Next>(
        &self,
        em: Emitter<N>,
        gen: &dyn JitCodeGenerator,
        type_: MpIntJitType,
        leg: i32,
        ext: Ext,
    ) -> Emitter<Ent<N, TInt>> {
        // Evaluated first in Java, so an out-of-range leg panics even when it is past our own
        // legs and would otherwise be handled by the extension branch below.
        let to_type = type_.leg_types_le_typed()[leg as usize];
        if leg as usize >= self.legs.len() {
            return match ext {
                // Java: ldc 0
                Ext::Zero => em.recast(),
                // Java: load the most significant leg, then `ldc Integer.SIZE - 1; ishr`
                Ext::Sign => {
                    let _ = (
                        self.legs.last().expect("NoSuchElementException: no legs"),
                        gen,
                        to_type,
                        INT_SIZE - 1,
                    );
                    em.recast()
                }
            };
        }
        let _ = (&self.legs[leg as usize], gen, to_type, ext);
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
        // Java: MpIntToMpInt.INSTANCE.convertOpndToArray(em, opnd, to, ext, scope, slack)
        let _ = gen;
        convert_opnd_to_array(em, &self.opnd, type_, ext, scope, slack)
    }

    fn gen_load_to_bool<N: Next>(
        &self,
        em: Emitter<N>,
        gen: &dyn JitCodeGenerator,
    ) -> Emitter<Ent<N, TInt>> {
        // Java: load leg 0, then `ior` every leg (including leg 0 again) onto it, then intToBool.
        let _ = (&self.legs[0], gen, IntJitType::I4);
        for leg in &self.legs {
            let _ = leg;
        }
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
        match type_.erase_simple() {
            AnySimpleJitType::Int(t) if self.legs.len() == 1 => {
                self.do_gen_store_int(em.recast(), gen, t, &self.legs[0], ext, scope)
            }
            AnySimpleJitType::Int(t) => match ext {
                Ext::Zero => {
                    let em = self.do_gen_store_int(em.recast(), gen, t, &self.legs[0], ext, scope);
                    self.do_gen_zero_fill(em, gen, &self.legs[1..], scope)
                }
                Ext::Sign => {
                    let em =
                        self.do_gen_store_int_and_sign(em.recast(), gen, t, &self.legs[0], scope);
                    self.do_gen_sign_fill(em, gen, &self.legs[1..], scope)
                }
            },
            // Java: `case LongJitType t when legs.size() == 1 -> em.emit(legs.get(0)
            // ::genStoreFromStack, gen, from, ext, scope)` -- the single leg swallows the whole
            // long, so there is no split.
            AnySimpleJitType::Long(t) if self.legs.len() == 1 => {
                let _ = (&self.legs[0], gen, t, ext, scope);
                em.recast()
            }
            AnySimpleJitType::Long(t) if self.legs.len() == 2 => self.do_gen_store_long(
                em.recast(),
                gen,
                t,
                &self.legs[0],
                &self.legs[1],
                ext,
                scope,
            ),
            AnySimpleJitType::Long(t) => match ext {
                Ext::Zero => {
                    let em = self.do_gen_store_long(
                        em.recast(),
                        gen,
                        t,
                        &self.legs[0],
                        &self.legs[1],
                        ext,
                        scope,
                    );
                    self.do_gen_zero_fill(em, gen, &self.legs[2..], scope)
                }
                Ext::Sign => {
                    let em = self.do_gen_store_long_and_sign(
                        em.recast(),
                        gen,
                        t,
                        &self.legs[0],
                        &self.legs[1],
                        scope,
                    );
                    self.do_gen_sign_fill(em, gen, &self.legs[2..], scope)
                }
            },
            // Java: `default -> throw new AssertionError()`
            AnySimpleJitType::Float(_) | AnySimpleJitType::Double(_) => {
                panic!("AssertionError: AlignedMpIntHandler cannot store from a float type")
            }
        }
    }

    fn gen_store_from_opnd<N: Next>(
        &self,
        em: Emitter<N>,
        gen: &dyn JitCodeGenerator,
        opnd: &dyn Opnd<MpIntJitType>,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N> {
        // Java derives `legsIn` from `from.type().castLegsLE(from)`, which the marker-only `Opnd`
        // stub cannot supply; see the module docs. Both the per-leg copy loop and the trailing
        // `genExt` are pure emission in this port state, so the stack is left as it is.
        let _ = (gen, opnd, ext, scope, self.opnd.type_.legs_alloc());
        em
    }

    fn gen_store_from_array<N1: Next>(
        &self,
        em: Emitter<Ent<N1, TRef>>,
        gen: &dyn JitCodeGenerator,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N1> {
        let from_leg_types = type_.leg_types_le_typed();
        // Java: `opnd.type().castLegsLE(opnd)`; the operand always has exactly one leg per leg of
        // its type, so the count and each leg's type come off the type instead (see module docs).
        let to_leg_types = self.opnd.type_.leg_types_le_typed();
        let legs_in = from_leg_types.len() as i32;
        let legs_out = to_leg_types.len() as i32;
        let def_legs = legs_in.min(legs_out);

        for i in 0..def_legs - 1 {
            // Java: dup; ldc i; iaload; convertIntToInt(fromLegType, toLeg.type(), ext);
            // toLeg.writeDirect -- all emission.
            let _ = (from_leg_types[i as usize], to_leg_types[i as usize], ext);
        }
        // Java indexes `defLegs - 1` unguarded, so a zero-leg source is an out-of-bounds throw.
        let _ = (
            from_leg_types[(def_legs - 1) as usize],
            to_leg_types[(def_legs - 1) as usize],
        );
        self.gen_ext(em.recast(), gen, def_legs, legs_out, ext, scope)
    }

    fn subpiece(&self, endian: Endian, byte_offset: i32, max_byte_size: i32) -> Box<dyn VarHandler> {
        sub_handler(endian, &self.vn, &self.legs, 0, byte_offset, max_byte_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::analysis::jit_type::FloatJitType;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::emu::jit::gen::util::types::TFloat;
    use crate::pcode::seam_stubs::MethodVisitor;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    fn make_varnode(offset: i64, size: i32) -> Varnode {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        Varnode::new(Address::new(space, offset), size)
    }

    struct MockCodeGenerator;
    impl JitCodeGenerator for MockCodeGenerator {}

    struct MockScope;
    impl Scope for MockScope {}

    /// A handler for a `size`-byte variable at `offset`, allocated one `int` leg per 4 bytes,
    /// each leg's varnode covering its own 4 bytes (little-endian layout).
    fn handler(offset: i64, size: i32) -> AlignedMpIntHandler {
        let type_ = MpIntJitType::for_size(size);
        let legs = (0..type_.legs_alloc())
            .map(|i| {
                JvmLocal::of(
                    IntJitType::I4.erase_simple(),
                    make_varnode(offset + (i * INT_BYTES) as i64, INT_BYTES),
                )
            })
            .collect();
        AlignedMpIntHandler::new(legs, type_, make_varnode(offset, size))
    }

    #[test]
    fn preferred_constructor_derives_both_operand_names() {
        // Java: createOpnd names the operand `VarHandler.nameVn(vn)`, and createRoOpnd suffixes
        // that same name with "_ro". Both carry the full mp-int type.
        let h = handler(0x1000, 16);
        assert_eq!(h.opnd.name, "var_ram_1000_16");
        assert_eq!(h.ro_opnd.name, "var_ram_1000_16_ro");
        assert_eq!(h.opnd.type_, MpIntJitType::for_size(16));
        assert_eq!(h.ro_opnd.type_, MpIntJitType::for_size(16));
        assert_eq!(h.legs.len(), 4);
    }

    #[test]
    fn var_handler_accessors_report_the_whole_varnode_and_mp_type() {
        let h = handler(0x1000, 16);
        assert_eq!(h.vn().get_offset(), 0x1000);
        assert_eq!(h.vn().get_size(), 16);
        assert_eq!(h.type_(), AnyJitType::MpInt(MpIntJitType::for_size(16)));
        // VarHandler::name() derives from vn(), as in Java.
        assert_eq!(h.name(), "var_ram_1000_16");
    }

    #[test]
    fn subpiece_aligned_to_a_leg_boundary_yields_another_aligned_mp_int_handler() {
        // 16-byte var at 0x1000, 4 legs. byteOffset 4, maxByteSize 8 (little-endian):
        //   subVn        = 0x1004, size 8
        //   totalShift   = 0 + 4 = 4
        //   firstPart    = 4 / 4 = 1
        //   lastPartExcl = (4 + 8 + 3) / 4 = 3   -> parts[1..3], i.e. 2 legs
        //   subShift     = 4 % 4 = 0             -> AlignedMpIntHandler
        let h = handler(0x1000, 16);
        let sub = h.subpiece(Endian::Little, 4, 8);
        assert_eq!(sub.vn().get_offset(), 0x1004);
        assert_eq!(sub.vn().get_size(), 8);
        assert_eq!(sub.type_(), AnyJitType::MpInt(MpIntJitType::for_size(8)));
    }

    #[test]
    fn subpiece_landing_in_one_whole_leg_yields_an_int_var_alloc() {
        // byteOffset 8, maxByteSize 4: subVn = 0x1008 size 4; totalShift 8; firstPart 2;
        // lastPartExcl = (8 + 4 + 3) / 4 = 3 -> parts[2..3], one leg; subShift 0 -> IntVarAlloc.
        let h = handler(0x1000, 16);
        let sub = h.subpiece(Endian::Little, 8, 4);
        assert_eq!(sub.vn().get_offset(), 0x1008);
        assert_eq!(sub.vn().get_size(), 4);
        assert_eq!(sub.type_(), AnyJitType::Int(IntJitType::I4));
    }

    #[test]
    fn subpiece_landing_inside_one_leg_yields_an_int_in_int_handler() {
        // byteOffset 9, maxByteSize 2: subVn = 0x1009 size 2; totalShift 9; firstPart 2;
        // lastPartExcl = (9 + 2 + 3) / 4 = 3 -> one leg; subShift = 9 % 4 = 1 -> IntInIntHandler,
        // whose vn is the sub varnode (not the leg's).
        let h = handler(0x1000, 16);
        let sub = h.subpiece(Endian::Little, 9, 2);
        assert_eq!(sub.vn().get_offset(), 0x1009);
        assert_eq!(sub.vn().get_size(), 2);
        assert_eq!(sub.type_(), AnyJitType::Int(IntJitType::I2));
    }

    #[test]
    fn subpiece_straddling_a_leg_boundary_yields_a_shifted_mp_int_handler() {
        // byteOffset 2, maxByteSize 8: subVn = 0x1002 size 8; totalShift 2; firstPart 0;
        // lastPartExcl = (2 + 8 + 3) / 4 = 3 -> parts[0..3], 3 legs; subShift 2 ->
        // ShiftedMpIntHandler.
        let h = handler(0x1000, 16);
        let sub = h.subpiece(Endian::Little, 2, 8);
        assert_eq!(sub.vn().get_offset(), 0x1002);
        assert_eq!(sub.vn().get_size(), 8);
        assert_eq!(sub.type_(), AnyJitType::MpInt(MpIntJitType::for_size(8)));
    }

    #[test]
    fn subpiece_is_big_endian_aware_via_sub_piece_vn() {
        // JitDataFlowArithmetic.subPieceVn on a big-endian target puts the least significant bytes
        // at the *end* of the varnode: addrOffset = size - offset - minSize = 16 - 4 - 8 = 4.
        let h = handler(0x1000, 16);
        let sub = h.subpiece(Endian::Big, 4, 8);
        assert_eq!(sub.vn().get_offset(), 0x1004);
        assert_eq!(sub.vn().get_size(), 8);
    }

    #[test]
    fn subpiece_truncates_to_the_remaining_size() {
        // Java: subPieceVn takes min(whole.size - offset, size), so an over-long maxByteSize is
        // clipped -- here to 16 - 12 = 4 bytes, landing in the single top leg.
        let h = handler(0x1000, 16);
        let sub = h.subpiece(Endian::Little, 12, 100);
        assert_eq!(sub.vn().get_size(), 4);
        assert_eq!(sub.type_(), AnyJitType::Int(IntJitType::I4));
    }

    #[test]
    #[should_panic(expected = "AssertionError")]
    fn gen_load_to_stack_rejects_float_types() {
        // Java: the switch's `default -> throw new AssertionError()` arm.
        let h = handler(0x1000, 16);
        let gen = MockCodeGenerator;
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let _: Emitter<Ent<Bot, TFloat>> =
            h.gen_load_to_stack(em, &gen, FloatJitType, Ext::Zero);
    }

    #[test]
    fn gen_ext_emits_nothing_when_the_output_is_no_wider_than_the_input() {
        // Java: `if (legsOut <= defLegs) return em;` -- notably it does *not* index legs, so this
        // holds even for a defLegs of 0, which the Ext.SIGN path would otherwise fault on.
        let h = handler(0x1000, 16);
        let gen = MockCodeGenerator;
        let scope = MockScope;
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let _: Emitter<Bot> = h.gen_ext(em, &gen, 0, 0, Ext::Sign, &scope);
    }

    #[test]
    #[should_panic(expected = "NoSuchElementException")]
    fn do_gen_sign_fill_rejects_an_empty_local_list() {
        // Java: `locals.getLast()` throws NoSuchElementException on an empty list.
        let h = handler(0x1000, 16);
        let gen = MockCodeGenerator;
        let scope = MockScope;
        let em: Emitter<Ent<Bot, TInt>> = Emitter::<Bot>::new(MethodVisitor::new()).recast();
        let _: Emitter<Bot> = h.do_gen_sign_fill(em, &gen, &[], &scope);
    }

    #[test]
    fn gen_load_leg_to_stack_accepts_legs_past_the_end_of_the_variable() {
        // Java: `if (leg >= legs.size())` extends rather than faulting -- ZERO pushes 0, SIGN
        // replicates the sign of the most significant leg. Here the 12-byte variable has 3 legs,
        // so leg 3 of a 16-byte request is pure extension.
        let h = handler(0x1000, 12);
        let gen = MockCodeGenerator;
        assert_eq!(h.legs.len(), 3);
        for ext in [Ext::Zero, Ext::Sign] {
            let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
            let _: Emitter<Ent<Bot, TInt>> =
                h.gen_load_leg_to_stack(em, &gen, MpIntJitType::for_size(16), 3, ext);
        }
    }

    #[test]
    #[should_panic]
    fn gen_load_leg_to_stack_faults_past_the_requested_type_s_legs() {
        // Java evaluates `type.legTypesLE().get(leg)` before the extension check, so a leg beyond
        // the *requested* type is an IndexOutOfBoundsException even though it is also beyond ours.
        let h = handler(0x1000, 12);
        let gen = MockCodeGenerator;
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let _: Emitter<Ent<Bot, TInt>> =
            h.gen_load_leg_to_stack(em, &gen, MpIntJitType::for_size(12), 3, Ext::Zero);
    }

    #[test]
    fn gen_store_from_array_extends_when_the_source_is_narrower() {
        // 16-byte handler (4 legs) storing from a 8-byte array (2 legs): defLegs = 2, legsOut = 4,
        // so genExt fills legs 2 and 3. The stack shape drops the array ref either way.
        let h = handler(0x1000, 16);
        let gen = MockCodeGenerator;
        let scope = MockScope;
        for ext in [Ext::Zero, Ext::Sign] {
            let em: Emitter<Ent<Bot, TRef>> = Emitter::<Bot>::new(MethodVisitor::new()).recast();
            let _: Emitter<Bot> =
                h.gen_store_from_array(em, &gen, MpIntJitType::for_size(8), ext, &scope);
        }
    }

    #[test]
    fn dyn_var_handler_dispatches_the_object_safe_half() {
        // `subpiece` forces object safety; the gen_* methods are `Self: Sized` and drop out.
        let h: Box<dyn VarHandler> = Box::new(handler(0x2000, 16));
        assert_eq!(h.name(), "var_ram_2000_16");
        let sub = h.subpiece(Endian::Little, 0, 16);
        assert_eq!(sub.vn().get_size(), 16);
        assert_eq!(sub.name(), "var_ram_2000_16");
    }
}
