//! A generator to emit code that accesses variables of various size in a
//! `JitBytesPcodeExecutorState`, for a specific type and byte order.
//!
//! Port of `ghidra.pcode.emu.jit.gen.access.AccessGen`.
//!
//! This is used by variable birthing and retirement as well as direct memory accesses. Dynamic
//! memory accesses, i.e., `JitStoreOp` store and `JitLoadOp` load, do not use this, though they
//! may borrow some portions.
//!
//! # Differences from Java
//!
//! - Java's `AccessGen<JT>` contributes no instance methods -- `lookup`, `lookupSimple`,
//!   `lookupMp`, and `genReadToBool` are all `static` -- so it is a marker trait here, and those
//!   four members become free functions in this module.
//! - Java's `lookup`/`lookupSimple` pattern-match on the sealed `JitType`/`SimpleJitType`
//!   hierarchy and unsafely cast the result to `AccessGen<T>`/`SimpleAccessGen<T, JT>` for the
//!   caller's statically-known `T`. Rust has no covariant existential return for a generic `T`
//!   chosen at the call site, so these take the already-ported erased enums
//!   [`AnyJitType`]/[`AnySimpleJitType`] (which exist for exactly this kind of dispatch; see their
//!   module docs) and return the matching erased [`AnyAccessGen`]/[`AnySimpleAccessGen`] instead.
//! - `FloatAccessGen`, `DoubleAccessGen`, and `MpIntAccessGen` are not yet ported. Minimal
//!   placeholders -- mirroring the BE/LE-constant shape of the already-ported
//!   [`IntAccessGen`](crate::pcode::emu::jit::gen::access::int_access_gen::IntAccessGen) and
//!   [`LongAccessGen`](crate::pcode::emu::jit::gen::access::long_access_gen::LongAccessGen), per
//!   the dependency context's guidance that these are Java enums, not interfaces -- live in
//!   [`seam_stubs`](crate::pcode::seam_stubs); see `STUBS.tsv`.
//! - `genReadToBool`'s real JVM-opcode emission (`Op::ldc__i`, `Op::invokestatic`, `Op::ior`, ...)
//!   is not yet ported, for the same reason given in the
//!   [`IntAccessGen`](crate::pcode::emu::jit::gen::access::int_access_gen) module docs. This port
//!   keeps the real, testable control flow -- splitting the varnode across a block boundary using
//!   `off + size < BLOCK_SIZE` (note: strictly less than, unlike the `<=` used by
//!   `ExportsLegAccessGen.genReadLegToStack`) -- and stubs the opcode sequence itself via
//!   `FieldForArrDirect::gen_load`.
//! - `BLOCK_SIZE` mirrors `GenConsts.BLOCK_SIZE`, as in
//!   [`IntAccessGen`](crate::pcode::emu::jit::gen::access::int_access_gen).
//! - `JitBytesPcodeExecutorState`, referenced only in the Java interface's doc comment (never in a
//!   signature), is not ported or stubbed here.

use crate::pcode::emu::jit::analysis::jit_type::{
    AnyJitType, AnySimpleJitType, DoubleJitType, FloatJitType, IntJitType, JitType, LongJitType,
    MpIntJitType,
};
use crate::pcode::emu::jit::gen::access::int_access_gen::IntAccessGen;
use crate::pcode::emu::jit::gen::access::long_access_gen::LongAccessGen;
use crate::pcode::emu::jit::gen::util::emitter::{Emitter, Ent, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TRef};
use crate::pcode::seam_stubs::{DoubleAccessGen, FloatAccessGen, JitCodeGenerator, MpIntAccessGen};
use crate::program::model::lang::Endian;
use crate::program::model::pcode::Varnode;

/// Mirrors `GenConsts.BLOCK_SIZE` (`SemisparseByteArray.BLOCK_SIZE`).
const BLOCK_SIZE: i64 = 0x1000;

/// A generator to emit code that accesses variables of various size in a
/// `JitBytesPcodeExecutorState`, for a specific type and byte order.
///
/// Port of `ghidra.pcode.emu.jit.gen.access.AccessGen`. Contributes no instance methods; see the
/// [module docs](self).
pub trait AccessGen<JT: JitType>: Send + Sync {}

impl AccessGen<FloatJitType> for FloatAccessGen {}
impl AccessGen<DoubleJitType> for DoubleAccessGen {}
impl AccessGen<MpIntJitType> for MpIntAccessGen {}

/// The result of [`lookup`]: an [`AccessGen`] for one of the closed set of p-code types, erased to
/// a common return type since Rust has no covariant existential return for a generic type chosen
/// at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnyAccessGen {
    /// An access generator for [`IntJitType`].
    Int(IntAccessGen),
    /// An access generator for [`LongJitType`].
    Long(LongAccessGen),
    /// An access generator for [`FloatJitType`].
    Float(FloatAccessGen),
    /// An access generator for [`DoubleJitType`].
    Double(DoubleAccessGen),
    /// An access generator for [`MpIntJitType`].
    MpInt(MpIntAccessGen),
}

/// Lookup the generator for accessing variables for the given type and byte order.
///
/// Port of `AccessGen.lookup(Endian, T)`.
pub fn lookup(endian: Endian, type_: &AnyJitType) -> AnyAccessGen {
    match (endian, type_) {
        (Endian::Big, AnyJitType::Int(_)) => AnyAccessGen::Int(IntAccessGen::Be),
        (Endian::Big, AnyJitType::Long(_)) => AnyAccessGen::Long(LongAccessGen::Be),
        (Endian::Big, AnyJitType::Float(_)) => AnyAccessGen::Float(FloatAccessGen::Be),
        (Endian::Big, AnyJitType::Double(_)) => AnyAccessGen::Double(DoubleAccessGen::Be),
        (Endian::Big, AnyJitType::MpInt(_)) => AnyAccessGen::MpInt(MpIntAccessGen::Be),
        (Endian::Little, AnyJitType::Int(_)) => AnyAccessGen::Int(IntAccessGen::Le),
        (Endian::Little, AnyJitType::Long(_)) => AnyAccessGen::Long(LongAccessGen::Le),
        (Endian::Little, AnyJitType::Float(_)) => AnyAccessGen::Float(FloatAccessGen::Le),
        (Endian::Little, AnyJitType::Double(_)) => AnyAccessGen::Double(DoubleAccessGen::Le),
        (Endian::Little, AnyJitType::MpInt(_)) => AnyAccessGen::MpInt(MpIntAccessGen::Le),
        (_, AnyJitType::MpFloat(_)) => panic!("AssertionError: no AccessGen for MpFloatJitType"),
    }
}

/// The result of [`lookup_simple`]: a [`SimpleAccessGen`](
/// crate::pcode::emu::jit::gen::access::simple_access_gen::SimpleAccessGen) for one of the closed
/// set of simple p-code types, erased as in [`AnyAccessGen`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnySimpleAccessGen {
    /// An access generator for [`IntJitType`].
    Int(IntAccessGen),
    /// An access generator for [`LongJitType`].
    Long(LongAccessGen),
    /// An access generator for [`FloatJitType`].
    Float(FloatAccessGen),
    /// An access generator for [`DoubleJitType`].
    Double(DoubleAccessGen),
}

/// Lookup the generator for accessing variables of simple types and the given byte order.
///
/// Port of `AccessGen.lookupSimple(Endian, JT)`.
pub fn lookup_simple(endian: Endian, type_: &AnySimpleJitType) -> AnySimpleAccessGen {
    match (endian, type_) {
        (Endian::Big, AnySimpleJitType::Int(_)) => AnySimpleAccessGen::Int(IntAccessGen::Be),
        (Endian::Big, AnySimpleJitType::Long(_)) => AnySimpleAccessGen::Long(LongAccessGen::Be),
        (Endian::Big, AnySimpleJitType::Float(_)) => AnySimpleAccessGen::Float(FloatAccessGen::Be),
        (Endian::Big, AnySimpleJitType::Double(_)) => {
            AnySimpleAccessGen::Double(DoubleAccessGen::Be)
        }
        (Endian::Little, AnySimpleJitType::Int(_)) => AnySimpleAccessGen::Int(IntAccessGen::Le),
        (Endian::Little, AnySimpleJitType::Long(_)) => AnySimpleAccessGen::Long(LongAccessGen::Le),
        (Endian::Little, AnySimpleJitType::Float(_)) => {
            AnySimpleAccessGen::Float(FloatAccessGen::Le)
        }
        (Endian::Little, AnySimpleJitType::Double(_)) => {
            AnySimpleAccessGen::Double(DoubleAccessGen::Le)
        }
    }
}

/// Lookup the generator for accessing variables of multi-precision integer type and the given
/// byte order.
///
/// Port of `AccessGen.lookupMp(Endian)`.
pub fn lookup_mp(endian: Endian) -> MpIntAccessGen {
    match endian {
        Endian::Big => MpIntAccessGen::Be,
        Endian::Little => MpIntAccessGen::Le,
    }
}

/// Emit bytecode to read the given varnode onto the stack as a p-code bool (JVM int).
///
/// Port of `AccessGen.genReadToBool(Emitter, Local, JitCodeGenerator, Varnode)`.
///
/// Preserves the Java control flow -- request the field(s) backing the block(s) the varnode
/// spans -- but the opcode emission itself (`Op::ldc__i`, `Op::invokestatic`, `Op::ior`, ...) is
/// stubbed; see the [module docs](self).
///
/// # Arguments
///
/// - `em`: the emitter typed with the incoming stack.
/// - `local_this`: a handle to the local holding the `this` reference.
/// - `gen`: the code generator.
/// - `vn`: the varnode.
///
/// # Returns
///
/// The emitter typed with the resulting stack, i.e., having pushed the value.
pub fn gen_read_to_bool<N: Next>(
    em: Emitter<N>,
    local_this: &Local<TRef>,
    gen: &dyn JitCodeGenerator,
    vn: &Varnode,
) -> Emitter<Ent<N, TInt>> {
    let space = vn.get_address().space();
    let offset = vn.get_offset();
    let block = offset.div_euclid(BLOCK_SIZE) * BLOCK_SIZE;
    let off = (offset - block) as i32;
    let size = vn.get_size();
    let blk_field = gen.request_field_for_arr_direct(space, block);
    if off + size < BLOCK_SIZE as i32 {
        let em = blk_field.gen_load(em, local_this, gen);
        return em.recast();
    }
    let nxt_field = gen.request_field_for_arr_direct(space, block + BLOCK_SIZE);
    let em = blk_field.gen_load(em, local_this, gen);
    let em = nxt_field.gen_load(em, local_this, gen);
    em.recast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::gen::util::emitter::Bot;
    use crate::pcode::seam_stubs::MethodVisitor;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use std::sync::Mutex;

    struct MockCodeGenerator {
        requested: Mutex<Vec<i64>>,
    }

    impl JitCodeGenerator for MockCodeGenerator {
        fn request_field_for_arr_direct(
            &self,
            _space: &AddressSpace,
            offset: i64,
        ) -> crate::pcode::seam_stubs::FieldForArrDirect {
            self.requested.lock().unwrap().push(offset);
            crate::pcode::seam_stubs::FieldForArrDirect { offset }
        }
    }

    fn make_local_this() -> Local<TRef> {
        Local::of(TRef::of_class("some/pkg/CompiledPassage"), "this", 0)
    }

    fn make_varnode(offset: i64, size: i32) -> Varnode {
        let space = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, offset);
        Varnode::new(addr, size)
    }

    #[test]
    fn lookup_matches_java_nested_switch() {
        // Java: lookup(BIG, IntJitType) -> IntAccessGen.BE; lookup(LITTLE, DoubleJitType) ->
        // DoubleAccessGen.LE; etc.
        assert_eq!(
            lookup(Endian::Big, &AnyJitType::Int(IntJitType::I4)),
            AnyAccessGen::Int(IntAccessGen::Be)
        );
        assert_eq!(
            lookup(Endian::Little, &AnyJitType::Long(LongJitType::I8)),
            AnyAccessGen::Long(LongAccessGen::Le)
        );
        assert_eq!(
            lookup(Endian::Big, &AnyJitType::Float(FloatJitType::F4)),
            AnyAccessGen::Float(FloatAccessGen::Be)
        );
        assert_eq!(
            lookup(Endian::Little, &AnyJitType::Double(DoubleJitType::F8)),
            AnyAccessGen::Double(DoubleAccessGen::Le)
        );
        assert_eq!(
            lookup(Endian::Big, &AnyJitType::MpInt(MpIntJitType::for_size(9))),
            AnyAccessGen::MpInt(MpIntAccessGen::Be)
        );
    }

    #[test]
    #[should_panic(expected = "AssertionError")]
    fn lookup_panics_for_mp_float_like_java_default_case() {
        use crate::pcode::emu::jit::analysis::jit_type::MpFloatJitType;
        lookup(Endian::Big, &AnyJitType::MpFloat(MpFloatJitType::for_size(10)));
    }

    #[test]
    fn lookup_simple_matches_java_nested_switch() {
        // Java: lookupSimple(BIG, IntJitType) -> IntAccessGen.BE; lookupSimple(LITTLE,
        // FloatJitType) -> FloatAccessGen.LE; etc. Unlike lookup, there is no MpInt/MpFloat case.
        assert_eq!(
            lookup_simple(Endian::Big, &AnySimpleJitType::Int(IntJitType::I4)),
            AnySimpleAccessGen::Int(IntAccessGen::Be)
        );
        assert_eq!(
            lookup_simple(Endian::Little, &AnySimpleJitType::Float(FloatJitType::F4)),
            AnySimpleAccessGen::Float(FloatAccessGen::Le)
        );
        assert_eq!(
            lookup_simple(Endian::Big, &AnySimpleJitType::Long(LongJitType::I8)),
            AnySimpleAccessGen::Long(LongAccessGen::Be)
        );
        assert_eq!(
            lookup_simple(Endian::Little, &AnySimpleJitType::Double(DoubleJitType::F8)),
            AnySimpleAccessGen::Double(DoubleAccessGen::Le)
        );
    }

    #[test]
    fn lookup_mp_matches_java_switch() {
        // Java: lookupMp(BIG) -> MpIntAccessGen.BE; lookupMp(LITTLE) -> MpIntAccessGen.LE.
        assert_eq!(lookup_mp(Endian::Big), MpIntAccessGen::Be);
        assert_eq!(lookup_mp(Endian::Little), MpIntAccessGen::Le);
    }

    #[test]
    fn gen_read_to_bool_within_one_block_requests_a_single_field() {
        // Java: off + size < BLOCK_SIZE takes the single-field branch.
        // offset 0x1000, size 4 -> block 0x1000, off 0, 0 + 4 < 0x1000.
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = make_local_this();
        let code_gen = MockCodeGenerator { requested: Mutex::new(Vec::new()) };
        let vn = make_varnode(0x1000, 4);

        let result: Emitter<Ent<Bot, TInt>> =
            gen_read_to_bool(em, &local_this, &code_gen, &vn);
        let _: Vec<_> = result.local_variables();
        assert_eq!(*code_gen.requested.lock().unwrap(), vec![0x1000]);
    }

    #[test]
    fn gen_read_to_bool_exactly_filling_a_block_still_requests_the_next_field() {
        // Java's condition is strictly `off + size < BLOCK_SIZE`, unlike
        // ExportsLegAccessGen.genReadLegToStack's `off + size <= BLOCK_SIZE`: a varnode that
        // exactly fills the block still takes the two-field branch.
        // offset 0x1000, size BLOCK_SIZE -> block 0x1000, off 0, 0 + BLOCK_SIZE == BLOCK_SIZE.
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = make_local_this();
        let code_gen = MockCodeGenerator { requested: Mutex::new(Vec::new()) };
        let vn = make_varnode(0x1000, BLOCK_SIZE as i32);

        let result: Emitter<Ent<Bot, TInt>> =
            gen_read_to_bool(em, &local_this, &code_gen, &vn);
        let _: Vec<_> = result.local_variables();
        assert_eq!(*code_gen.requested.lock().unwrap(), vec![0x1000, 0x2000]);
    }

    #[test]
    fn gen_read_to_bool_spanning_blocks_requests_both_fields() {
        // offset 0x2FFE, size 4 -> block 0x2000, off 0xFFE, 0xFFE + 4 > BLOCK_SIZE.
        let em: Emitter<Bot> = Emitter::new(MethodVisitor::new());
        let local_this = make_local_this();
        let code_gen = MockCodeGenerator { requested: Mutex::new(Vec::new()) };
        let vn = make_varnode(0x2FFE, 4);

        let result: Emitter<Ent<Bot, TInt>> =
            gen_read_to_bool(em, &local_this, &code_gen, &vn);
        let _: Vec<_> = result.local_variables();
        assert_eq!(*code_gen.requested.lock().unwrap(), vec![0x2000, 0x3000]);
    }

    #[test]
    fn concrete_types_implement_access_gen() {
        let _int: &dyn AccessGen<IntJitType> = &IntAccessGen::Be;
        let _long: &dyn AccessGen<LongJitType> = &LongAccessGen::Be;
        let _float: &dyn AccessGen<FloatJitType> = &FloatAccessGen::Be;
        let _double: &dyn AccessGen<DoubleJitType> = &DoubleAccessGen::Be;
        let _mpint: &dyn AccessGen<MpIntJitType> = &MpIntAccessGen::Be;
    }
}
