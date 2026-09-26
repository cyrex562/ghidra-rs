//! Port of `ghidra.pcode.emu.symz3.SymZ3PcodeExecutorStatePiece`.
//!
//! An executor state piece that addresses and stores values as [`SymValueZ3`] (Z3 symbolic
//! values), partitioned per-[`AddressSpace`] into register/unique/memory storage spaces.
//!
//! # Deviations from Java
//!
//! * Java splits this class into `SymZ3PcodeExecutorStatePiece` (concrete) extending the
//!   abstract, generic `AbstractSymZ3OffsetPcodeExecutorStatePiece<S>` (itself implementing
//!   `PcodeExecutorStatePiece<SymValueZ3, SymValueZ3>` directly -- it is *not* built on
//!   `AbstractLongOffsetPcodeExecutorStatePiece`, whose "long offset" domain does not fit a
//!   *symbolic* offset type). `AbstractSymZ3OffsetPcodeExecutorStatePiece` has exactly one
//!   subclass anywhere in Ghidra, so, following this crate's composition-over-inheritance
//!   convention for single-subclass Java abstract bases (see e.g. `SymZ3Space` itself, collapsed
//!   from an all-abstract class into a plain trait), its fields and concrete methods
//!   (`setVarInternal`/`getVarInternal`, the unique-space special case, the constant-space
//!   special case) are inlined directly into this one struct rather than kept as a separate
//!   ported type.
//! * Java's `PcodeStateCallbacks` has generic methods and so is not object-safe in this crate
//!   (see that trait's own docs); this struct is therefore generic over `CB: PcodeStateCallbacks`
//!   and stores its callbacks as `Arc<CB>`, matching the convention already established by
//!   [`BytesPcodeExecutorStatePiece`](crate::pcode::exec::bytes_pcode_executor_state_piece::BytesPcodeExecutorStatePiece).
//! * Java's Z3-touching methods each open their own `try (Context ctx = new Context())`; per the
//!   convention already established throughout this package (e.g.
//!   [`SymZ3UniqueSpace`](crate::pcode::emu::symz3::state::sym_z3_unique_space::SymZ3UniqueSpace),
//!   [`Z3InfixPrinter`](crate::pcode::emu::symz3::lib::z3_infix_printer::Z3InfixPrinter)), this
//!   struct instead holds its own `ctx: Arc<dyn Z3Context>`, injected at construction.
//! * The internal space map's value type is `SymZ3Space` in Java (a common supertype of
//!   `SymZ3RegisterSpace`/`SymZ3UniqueSpace`/`SymZ3MemorySpace`). The ported `SymZ3Space` trait
//!   has a generic `CB` method parameter and so is not object-safe (`&dyn SymZ3Space` does not
//!   exist), so the map instead holds the closed [`SymZ3SpaceKind`] enum over the three.
//! * Java's register and memory spaces report `dataWritten`/`readUninitialized` through a
//!   back-reference to this piece. This piece owns its spaces, so it fires those callbacks itself,
//!   around its calls into a register or memory space, at the points Java's spaces do; see
//!   [`SymZ3RegisterSpace`]'s module docs.
//! * `AbstractSymZ3OffsetPcodeExecutorStatePiece.getVarInternal`'s constant-space branch builds a
//!   fresh `SymValueZ3` from the offset's `BigInteger` value via `ctx.mkBV(b.toString(), size *
//!   8)`. The [`Z3Context`] seam's [`Z3Context::mk_bv`] takes an `i64` (not an arbitrary-precision
//!   string), so this port narrows through `SymValueZ3::to_long` instead of `to_big_integer`;
//!   faithful for anything that fits a 64-bit constant offset, which covers every realistic
//!   caller.
//! * `getRegisterValues()` throws `UnsupportedOperationException` in Java; ported as `unimplemented!`.
//! * `getConcreteBuffer` throws `ConcretionError` in Java (a `PcodeExecutionException`, an
//!   unchecked exception); [`PcodeExecutorStatePiece::get_concrete_buffer`]'s signature has no
//!   `Result`, so this panics instead, carrying the same message.
//! * Java's `printSymbolicSummary(PrintStream)` takes a `PrintStream`; per this crate's established
//!   convention for ported `print(PrintStream)` methods, this takes `&mut dyn std::io::Write` and
//!   returns `io::Result<()>`.

use std::collections::HashMap;
use std::sync::Arc;

use crate::feature::seam_stubs::Z3Context;
use crate::feature::symz3::model::sym_value_z3::SymValueZ3;
use crate::pcode::emu::symz3::internal_sym_z3_records_execution::InternalSymZ3RecordsExecution;
use crate::pcode::emu::symz3::internal_sym_z3_records_preconditions::InternalSymZ3RecordsPreconditions;
use crate::pcode::emu::symz3::lib::z3_infix_printer::Z3InfixPrinter;
use crate::pcode::emu::symz3::state::sym_z3_preconditions::SymZ3Preconditions;
use crate::pcode::emu::symz3::state::sym_z3_space::SymZ3Space;
use crate::pcode::emu::symz3::state::sym_z3_unique_space::SymZ3UniqueSpace;
use crate::pcode::emu::symz3::sym_z3_records_execution::{RecInstruction, RecOp, SymZ3RecordsExecution};
use crate::pcode::emu::symz3::sym_z3_records_preconditions::SymZ3RecordsPreconditions;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state_piece::{ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason};
use crate::pcode::exec::pcode_state_callbacks::{PcodeStateCallbacks, NONE};
use crate::pcode::emu::symz3::sym_z3_pcode_thread::SymZ3ThreadId;
use crate::pcode::emu::symz3::sym_z3_pcode_arithmetic::SymZ3PcodeArithmetic;
use crate::pcode::emu::symz3::state::sym_z3_memory_space::SymZ3MemorySpace;
use crate::pcode::emu::symz3::state::sym_z3_register_space::SymZ3RegisterSpace;
use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::listing::instruction::Instruction;
use crate::program::model::mem::MemBuffer;
use crate::program::model::pcode::PcodeOp;
use crate::util::msg::Msg;

/// The internal, per-[`AddressSpace`] storage backing a [`SymZ3PcodeExecutorStatePiece`].
///
/// Stands in for Java's `SymZ3Space` supertype where the map value is stored; see the module
/// docs for why this is a closed enum rather than a `dyn SymZ3Space`.
enum SymZ3SpaceKind {
    Register(SymZ3RegisterSpace),
    Unique(SymZ3UniqueSpace),
    Memory(SymZ3MemorySpace),
}

impl SymZ3SpaceKind {
    // Every variant is called through `SymZ3Space` by UFCS: `SymZ3UniqueSpace` also has inherent
    // `set(i64, ...)`/`get(i64, ...)`, which plain dot-call dispatch would pick instead.
    fn set<CB: PcodeStateCallbacks>(&mut self, offset: &SymValueZ3, size: i32, val: &SymValueZ3, cb: &CB) {
        match self {
            Self::Register(s) => SymZ3Space::set(s, offset, size, val, cb),
            Self::Unique(s) => SymZ3Space::set(s, offset, size, val, cb),
            Self::Memory(s) => SymZ3Space::set(s, offset, size, val, cb),
        }
    }

    fn get<CB: PcodeStateCallbacks>(&self, offset: &SymValueZ3, size: i32, reason: Reason, cb: &CB) -> SymValueZ3 {
        match self {
            Self::Register(s) => SymZ3Space::get(s, offset, size, reason, cb),
            Self::Unique(s) => SymZ3Space::get(s, offset, size, reason, cb),
            Self::Memory(s) => SymZ3Space::get(s, offset, size, reason, cb),
        }
    }

    /// Whether this space reports writes and uninitialized reads (Java's register and memory
    /// spaces do; its unique space does not).
    fn reports_callbacks(&self) -> bool {
        !matches!(self, Self::Unique(_))
    }

    /// Whether Java's `get` would report `readUninitialized` for this read: the register or memory
    /// has no value there. A register offset naming no register reports nothing.
    fn reads_uninitialized(&self, offset: &SymValueZ3, size: i32) -> bool {
        match self {
            Self::Register(s) => s.has_value_for(offset, size) == Some(false),
            Self::Unique(_) => false,
            Self::Memory(s) => !s.has_value_for(offset, size),
        }
    }

    fn printable_summary(&self) -> String {
        match self {
            Self::Register(s) => SymZ3Space::printable_summary(s),
            Self::Unique(s) => s.printable_summary(),
            Self::Memory(s) => SymZ3Space::printable_summary(s),
        }
    }

    fn stream_valuations(&self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> Vec<(String, String)> {
        match self {
            Self::Register(s) => SymZ3Space::stream_valuations(s, ctx, z3p),
            Self::Unique(s) => s.stream_valuations(ctx, z3p),
            Self::Memory(s) => s.stream_valuations(ctx, z3p),
        }
    }

    fn get_next_entry(&self, offset: i64) -> Option<(i64, SymValueZ3)> {
        match self {
            Self::Register(s) => s.get_next_entry(offset),
            Self::Unique(s) => s.get_next_entry(offset),
            Self::Memory(s) => s.get_next_entry(offset),
        }
    }
}

/// An executor state piece which internally uses [`SymValueZ3`] to address contents.
///
/// Port of `ghidra.pcode.emu.symz3.SymZ3PcodeExecutorStatePiece` (with
/// `AbstractSymZ3OffsetPcodeExecutorStatePiece` inlined; see the module docs).
pub struct SymZ3PcodeExecutorStatePiece<CB: PcodeStateCallbacks> {
    language: Arc<dyn Language>,
    address_arithmetic: Arc<dyn PcodeArithmetic<SymValueZ3>>,
    arithmetic: Arc<dyn PcodeArithmetic<SymValueZ3>>,
    cb: Arc<CB>,
    ctx: Arc<dyn Z3Context>,
    unique_space: Arc<AddressSpace>,
    space_map: HashMap<Arc<AddressSpace>, SymZ3SpaceKind>,
    preconditions: SymZ3Preconditions,
    ops: Vec<RecOp>,
    instructions: Vec<RecInstruction>,
}

impl<CB: PcodeStateCallbacks> SymZ3PcodeExecutorStatePiece<CB> {
    /// Create a state piece.
    ///
    /// Port of `SymZ3PcodeExecutorStatePiece(Language, PcodeArithmetic<SymValueZ3>,
    /// PcodeArithmetic<SymValueZ3>, PcodeStateCallbacks)`. `ctx` is an addition; see the module
    /// docs.
    pub fn new(
        language: Arc<dyn Language>,
        address_arithmetic: Arc<dyn PcodeArithmetic<SymValueZ3>>,
        arithmetic: Arc<dyn PcodeArithmetic<SymValueZ3>>,
        cb: Arc<CB>,
        ctx: Arc<dyn Z3Context>,
    ) -> Self {
        let unique_space = language
            .get_address_factory()
            .get_unique_space()
            .expect("Java: unchecked language.getAddressFactory().getUniqueSpace()");
        Self {
            language,
            address_arithmetic,
            arithmetic,
            cb,
            ctx,
            unique_space,
            space_map: HashMap::new(),
            preconditions: SymZ3Preconditions::new(),
            ops: Vec::new(),
            instructions: Vec::new(),
        }
    }

    /// Create the SymZ3 piece, deriving its value arithmetic from the language.
    ///
    /// Port of `SymZ3PcodeExecutorStatePiece(Language, PcodeArithmetic<SymValueZ3>,
    /// PcodeStateCallbacks)`, which delegates to the primary constructor via
    /// `SymZ3PcodeArithmetic.forLanguage(language)`, built here with this piece's own `ctx`.
    pub fn new_for_language(
        language: Arc<dyn Language>,
        address_arithmetic: Arc<dyn PcodeArithmetic<SymValueZ3>>,
        cb: Arc<CB>,
        ctx: Arc<dyn Z3Context>,
    ) -> Self {
        let arithmetic: Arc<dyn PcodeArithmetic<SymValueZ3>> =
            Arc::new(SymZ3PcodeArithmetic::for_language(language.as_ref(), Arc::clone(&ctx)));
        Self::new(language, address_arithmetic, arithmetic, cb, ctx)
    }

    /// Port of `newSpace(AddressSpace)`.
    fn new_space(&self, space: &Arc<AddressSpace>) -> SymZ3SpaceKind {
        if space.space_type() == AddressSpaceType::Constant {
            panic!("AssertionError: the constant space has no storage");
        }
        if space.space_type() == AddressSpaceType::Register {
            return SymZ3SpaceKind::Register(SymZ3RegisterSpace::new(
                Arc::clone(&self.language),
                Arc::clone(space),
                Arc::clone(&self.ctx),
            ));
        }
        if space.space_type() == AddressSpaceType::Unique {
            return SymZ3SpaceKind::Unique(SymZ3UniqueSpace::new(Arc::clone(&self.ctx)));
        }
        if space.is_loaded_memory_space() {
            return SymZ3SpaceKind::Memory(SymZ3MemorySpace::new(
                Arc::clone(&self.language),
                Arc::clone(space),
                Arc::clone(&self.ctx),
            ));
        }
        panic!("not yet supported space: {}", space.name());
    }

    /// Port of `getForSpace(AddressSpace, false)`.
    fn get_for_space(&self, space: &Arc<AddressSpace>) -> Option<&SymZ3SpaceKind> {
        self.space_map.get(space)
    }

    /// Port of `getForSpace(AddressSpace, true)`: lazily creates the space via [`Self::new_space`]
    /// if it does not already exist.
    fn get_or_create_space(&mut self, space: &Arc<AddressSpace>) -> &mut SymZ3SpaceKind {
        if !self.space_map.contains_key(space) {
            let created = self.new_space(space);
            self.space_map.insert(Arc::clone(space), created);
        }
        self.space_map
            .get_mut(space)
            .expect("space was just inserted if it was missing")
    }

    /// Port of the private helper `setVarInternal(AddressSpace, SymValueZ3, int, boolean,
    /// SymValueZ3, PcodeStateCallbacks)`, shared by `setVar`/`setVarInternal`.
    fn set_var_internal_with_cb<C: PcodeStateCallbacks>(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: &SymValueZ3,
        size: i32,
        _quantize: bool,
        val: &SymValueZ3,
        cb: &C,
    ) {
        if space.space_type() == AddressSpaceType::Constant {
            panic!("Cannot write to constant space");
        }
        if space.space_type() == AddressSpaceType::Unique {
            let unique_space = Arc::clone(&self.unique_space);
            self.get_or_create_space(&unique_space).set(offset, size, val, cb);
            return;
        }
        let target = self.get_or_create_space(space);
        target.set(offset, size, val, cb);
        let reports = target.reports_callbacks();
        if reports {
            // Java's register/memory space: `cb.dataWritten(piece, space, offset, size, val)`.
            cb.data_written_abstract::<SymValueZ3, SymValueZ3>(&*self, space, offset, size, val);
        }
    }

    /// Port of the private helper `getVarInternal(AddressSpace, SymValueZ3, int, boolean, Reason,
    /// PcodeStateCallbacks)`, shared by `getVar`/`getVarInternal`.
    fn get_var_internal_with_cb<C: PcodeStateCallbacks>(
        &self,
        space: &Arc<AddressSpace>,
        offset: &SymValueZ3,
        size: i32,
        _quantize: bool,
        reason: Reason,
        cb: &C,
    ) -> SymValueZ3 {
        if space.space_type() == AddressSpaceType::Constant {
            let long_val = offset.to_long(&*self.ctx).expect(
                "Java: unchecked assert offset.getBitVecExpr(ctx).isNumeral() for a constant-space offset",
            );
            let bv = self.ctx.mk_bv(long_val, (size * 8) as u32);
            return SymValueZ3::from_bit_vec(&*self.ctx, &*bv);
        }
        if space.space_type() == AddressSpaceType::Unique {
            return match self.get_for_space(&self.unique_space) {
                Some(s) => s.get(offset, size, reason, cb),
                None => panic!(
                    "Java: NPE -- getUnique's getForSpace(uniqueSpace, false) found nothing (never written)"
                ),
            };
        }
        match self.get_for_space(space) {
            Some(s) => {
                if s.reads_uninitialized(offset, size) {
                    // Java's register/memory space: `cb.readUninitialized(piece, space, offset,
                    // size, reason)`, before the read.
                    cb.read_uninitialized_abstract::<SymValueZ3, SymValueZ3>(self, space, offset, size, reason);
                }
                s.get(offset, size, reason, cb)
            }
            None => {
                Msg::warn(
                    "SymZ3PcodeExecutorStatePiece",
                    &"getFromNullSpace is returning 0 but that might not be what we want for symz3",
                );
                self.arithmetic.from_const_u64(0, size)
            }
        }
    }

    /// Port of `printableSummary()`. Takes `ctx`/`z3p` explicitly; see the module docs.
    pub fn printable_summary(&self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> String {
        let mut result = String::new();
        for space in self.space_map.values() {
            result.push_str(&space.printable_summary());
        }
        result.push_str(&self.preconditions.printable_summary(ctx, z3p));
        result
    }

    /// Port of `printSymbolicSummary(PrintStream)`. See the module docs for the `PrintStream` ->
    /// `&mut dyn Write` convention.
    pub fn print_symbolic_summary(
        &self,
        out: &mut dyn std::io::Write,
        ctx: &dyn Z3Context,
        z3p: &Z3InfixPrinter,
    ) -> std::io::Result<()> {
        writeln!(out, "{}", self.printable_summary(ctx, z3p))
    }

    /// Port of `streamValuations(Context, Z3InfixPrinter)`.
    pub fn stream_valuations(&self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> Vec<(String, String)> {
        self.space_map.values().flat_map(|s| s.stream_valuations(ctx, z3p)).collect()
    }

    /// Port of `streamPreconditions(Context, Z3InfixPrinter)`.
    pub fn stream_preconditions(&self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> Vec<String> {
        self.preconditions.stream_preconditions(ctx, z3p)
    }

    /// Access the language this piece was constructed with, as the shared handle it holds (Java
    /// only exposes it via the interface's `getLanguage()`).
    pub fn language(&self) -> &Arc<dyn Language> {
        &self.language
    }
}

impl<CB: PcodeStateCallbacks> ErasedPcodeExecutorStatePiece for SymZ3PcodeExecutorStatePiece<CB> {}

impl<CB: PcodeStateCallbacks> PcodeExecutorStatePiece<SymValueZ3, SymValueZ3> for SymZ3PcodeExecutorStatePiece<CB> {
    fn get_language(&self) -> Box<dyn Language> {
        // `Arc<dyn Language>` is itself a `Language`, sharing this piece's.
        Box::new(Arc::clone(&self.language))
    }

    fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<SymValueZ3>> {
        Arc::clone(&self.address_arithmetic)
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<SymValueZ3>> {
        Arc::clone(&self.arithmetic)
    }

    fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
        vec![self]
    }

    fn set_var_abstract(&mut self, space: &Arc<AddressSpace>, offset: &SymValueZ3, size: i32, quantize: bool, val: &SymValueZ3) {
        let cb = Arc::clone(&self.cb);
        self.set_var_internal_with_cb(space, offset, size, quantize, val, &*cb);
    }

    fn set_var_internal_abstract(&mut self, space: &Arc<AddressSpace>, offset: &SymValueZ3, size: i32, val: &SymValueZ3) {
        self.set_var_internal_with_cb(space, offset, size, false, val, &NONE);
    }

    fn get_var_abstract(&self, space: &Arc<AddressSpace>, offset: &SymValueZ3, size: i32, quantize: bool, reason: Reason) -> SymValueZ3 {
        let cb = Arc::clone(&self.cb);
        self.get_var_internal_with_cb(space, offset, size, quantize, reason, &*cb)
    }

    fn get_var_internal_abstract(&self, space: &Arc<AddressSpace>, offset: &SymValueZ3, size: i32, reason: Reason) -> SymValueZ3 {
        self.get_var_internal_with_cb(space, offset, size, false, reason, &NONE)
    }

    fn get_next_entry_internal(&self, space: &Arc<AddressSpace>, offset: i64) -> Option<(i64, SymValueZ3)> {
        self.get_for_space(space)?.get_next_entry(offset)
    }

    fn get_register_values(&self) -> Vec<(RegisterRef, SymValueZ3)> {
        unimplemented!("Java: SymZ3PcodeExecutorStatePiece.getRegisterValues() throws UnsupportedOperationException")
    }

    fn get_concrete_buffer(&self, _address: &Address, purpose: Purpose) -> Box<dyn MemBuffer> {
        panic!("Cannot make Symbolic concrete: {purpose:?}");
    }

    fn clear(&mut self) {
        self.space_map.clear();
        self.preconditions.clear();
        self.ops.clear();
        self.instructions.clear();
    }
}

impl<CB: PcodeStateCallbacks> SymZ3RecordsPreconditions for SymZ3PcodeExecutorStatePiece<CB> {
    fn get_preconditions(&self) -> Vec<String> {
        self.preconditions.get_preconditions()
    }
}

impl<CB: PcodeStateCallbacks> InternalSymZ3RecordsPreconditions for SymZ3PcodeExecutorStatePiece<CB> {
    fn add_precondition(&mut self, precondition: String) {
        self.preconditions.add_precondition(precondition);
    }
}

impl<CB: PcodeStateCallbacks> SymZ3RecordsExecution for SymZ3PcodeExecutorStatePiece<CB> {
    fn get_instructions(&self) -> Vec<RecInstruction> {
        self.instructions.clone()
    }

    fn get_ops(&self) -> Vec<RecOp> {
        self.ops.clone()
    }
}

impl<CB: PcodeStateCallbacks> InternalSymZ3RecordsExecution for SymZ3PcodeExecutorStatePiece<CB> {
    fn add_instruction(&mut self, thread: &SymZ3ThreadId, inst: Arc<dyn Instruction>) {
        let index = self.instructions.len() as i32;
        self.instructions.push(RecInstruction::new(index, thread.clone(), inst));
    }

    fn add_op(&mut self, thread: &SymZ3ThreadId, op: PcodeOp) {
        let index = self.ops.len() as i32;
        self.ops.push(RecOp::new(index, thread.clone(), op));
    }
}

/// Test-only fixtures shared by other modules that need a genuinely constructible
/// [`SymZ3PcodeExecutorStatePiece`] (a full `Language` mock, a numeral-only `Z3Context`, and a
/// `PcodeArithmetic<SymValueZ3>`), so those modules don't have to hand-roll their own -- following
/// the same `pub(crate) mod testing` convention already established by
/// [`crate::pcode::exec::pcode_program::testing`].
#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::pcode::exec::pcode_state_callbacks::NoPcodeStateCallbacks;
    use crate::program::model::address::{AddressFactory, DefaultAddressFactory};
    use crate::program::model::lang::language_id::LanguageID;
    use std::any::Any;

    // -- A minimal Z3Context/BitVecExpr/Expr test double, matching the pattern already
    // established by SymZ3MemoryMap/SymZ3RegisterMap's own test modules (numeral bit-vectors
    // only; no real solving). --

    #[derive(Clone)]
    struct Bv {
        text: String,
        size: u32,
        numeral: Option<i64>,
    }

    impl crate::feature::seam_stubs::Expr for Bv {
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn to_smt_string(&self) -> String {
            self.text.clone()
        }
    }

    impl crate::feature::seam_stubs::BitVecExpr for Bv {
        fn as_expr(&self) -> &dyn crate::feature::seam_stubs::Expr {
            self
        }
        fn sort_size(&self) -> u32 {
            self.size
        }
        fn is_numeral(&self) -> bool {
            self.numeral.is_some()
        }
        fn to_big_integer(&self) -> Option<i128> {
            self.numeral.map(|v| v as i128)
        }
        fn to_long(&self) -> Option<i64> {
            self.numeral
        }
    }

    /// A minimal boolean expression, only ever produced by [`MockCtx::parse_smt_lib2`] to hand
    /// back the numeral bit-vector it was asked to round-trip (see [`SymValueZ3::serialize_bit_vec`]'s
    /// "trivial equality" comment for why a bit-vector round-trips through a `BoolExpr` at all).
    #[derive(Clone)]
    struct Bl {
        smt: String,
        arg: Option<Bv>,
    }

    impl crate::feature::seam_stubs::Expr for Bl {
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn to_smt_string(&self) -> String {
            self.smt.clone()
        }
    }

    impl crate::feature::seam_stubs::BoolExpr for Bl {
        fn as_expr(&self) -> &dyn crate::feature::seam_stubs::Expr {
            self
        }
        fn bit_vec_arg(&self, index: usize) -> Option<Box<dyn crate::feature::seam_stubs::BitVecExpr>> {
            match (index, &self.arg) {
                (0, Some(bv)) => Some(Box::new(bv.clone())),
                _ => None,
            }
        }
    }

    pub(crate) struct MockCtx;

    impl MockCtx {
        fn bv(&self, text: impl Into<String>, size: u32, numeral: Option<i64>) -> Box<Bv> {
            Box::new(Bv { text: text.into(), size, numeral })
        }
    }

    impl Z3Context for MockCtx {
        /// Round-trippable encoding carrying enough of [`Bv`] (size, numeral, text) that
        /// [`Self::parse_smt_lib2`] can reconstruct it, mirroring the working pattern already
        /// established by `SymZ3RegisterMap`'s own `MockCtx`.
        fn smt_lib_for_bit_vec(&self, b: &dyn crate::feature::seam_stubs::BitVecExpr) -> String {
            let numeral = b.to_long().map(|v| v.to_string()).unwrap_or_default();
            format!("bv;{};{};{}", b.sort_size(), numeral, b.as_expr().to_smt_string())
        }
        fn smt_lib_for_bool(&self, b: &dyn crate::feature::seam_stubs::BoolExpr) -> String {
            format!("(assert {})", b.as_expr().to_smt_string())
        }
        fn parse_smt_lib2(&self, smt: &str) -> Option<Box<dyn crate::feature::seam_stubs::BoolExpr>> {
            let mut parts = smt.splitn(4, ';');
            match parts.next()? {
                "bv" => {
                    let size: u32 = parts.next()?.parse().ok()?;
                    let numeral_str = parts.next()?;
                    let numeral = if numeral_str.is_empty() { None } else { numeral_str.parse().ok() };
                    let text = parts.next()?.to_string();
                    let bv = Bv { text: text.clone(), size, numeral };
                    Some(Box::new(Bl { smt: format!("(= {0} {0})", text), arg: Some(bv) }))
                }
                _ => None,
            }
        }
        fn mk_bv(&self, value: i64, size_bits: u32) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
            self.bv(format!("#x{value:x}"), size_bits, Some(value))
        }
        fn mk_bv_const(&self, name: &str, size_bits: u32) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
            self.bv(name.to_string(), size_bits, None)
        }
        fn mk_true(&self) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
            unimplemented!()
        }
        fn mk_false(&self) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
            unimplemented!()
        }
        fn mk_eq(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
            unimplemented!()
        }
        fn mk_ite_bv(
            &self,
            _predicate: &dyn crate::feature::seam_stubs::BoolExpr,
            _t: &dyn crate::feature::seam_stubs::BitVecExpr,
            _f: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
            unimplemented!()
        }
        fn mk_ite_bool(
            &self,
            _predicate: &dyn crate::feature::seam_stubs::BoolExpr,
            _t: &dyn crate::feature::seam_stubs::BoolExpr,
            _f: &dyn crate::feature::seam_stubs::BoolExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
            unimplemented!()
        }
        fn mk_bvslt(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
            unimplemented!()
        }
        fn mk_bvsle(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
            unimplemented!()
        }
        fn mk_bvult(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
            unimplemented!()
        }
        fn mk_bvule(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
            unimplemented!()
        }
        fn mk_bv_add_no_overflow(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
            _signed: bool,
        ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
            unimplemented!()
        }
        fn mk_bv_sub_no_overflow(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
            unimplemented!()
        }
        fn mk_bvadd(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvsub(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvxor(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvand(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvor(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvmul(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvudiv(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvsdiv(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvshl(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvlshr(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvashr(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
            unimplemented!()
        }
        fn mk_concat(
            &self,
            _l: &dyn crate::feature::seam_stubs::BitVecExpr,
            _r: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
            unimplemented!()
        }
        fn mk_zero_ext(&self, _bits: u32, _b: &dyn crate::feature::seam_stubs::BitVecExpr) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
            unimplemented!()
        }
        fn mk_sign_ext(&self, _bits: u32, _b: &dyn crate::feature::seam_stubs::BitVecExpr) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
            unimplemented!()
        }
        fn mk_extract(
            &self,
            _high: u32,
            _low: u32,
            _b: &dyn crate::feature::seam_stubs::BitVecExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BitVecExpr> {
            unimplemented!()
        }
        fn mk_not(&self, _u: &dyn crate::feature::seam_stubs::BoolExpr) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
            unimplemented!()
        }
        fn mk_xor(
            &self,
            _l: &dyn crate::feature::seam_stubs::BoolExpr,
            _r: &dyn crate::feature::seam_stubs::BoolExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
            unimplemented!()
        }
        fn mk_and(
            &self,
            _l: &dyn crate::feature::seam_stubs::BoolExpr,
            _r: &dyn crate::feature::seam_stubs::BoolExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
            unimplemented!()
        }
        fn mk_or(
            &self,
            _l: &dyn crate::feature::seam_stubs::BoolExpr,
            _r: &dyn crate::feature::seam_stubs::BoolExpr,
        ) -> Box<dyn crate::feature::seam_stubs::BoolExpr> {
            unimplemented!()
        }
    }

    /// A [`Language`] test double reporting only what this piece actually needs: a unique address
    /// space via `get_address_factory`, plus (for the arithmetics' `forLanguage`) little-endianness.
    /// Every other method is unreachable and panics if called,
    /// mirroring the `TestLanguage` pattern already established in this package (see e.g.
    /// `SymZ3MemoryMap`'s own test module).
    struct TestLanguage {
        factory: DefaultAddressFactory,
    }

    macro_rules! unimplemented_language_methods {
        () => {
            fn get_language_id(&self) -> LanguageID {
                unimplemented!()
            }
            fn get_language_description(
                &self,
            ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
                unimplemented!()
            }
            fn get_parallel_instruction_helper(
                &self,
            ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>> {
                unimplemented!()
            }
            fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
                unimplemented!()
            }
            fn get_version(&self) -> i32 {
                unimplemented!()
            }
            fn get_minor_version(&self) -> i32 {
                unimplemented!()
            }
            fn get_default_data_space(&self) -> Arc<AddressSpace> {
                unimplemented!()
            }
            fn get_instruction_alignment(&self) -> i32 {
                unimplemented!()
            }
            fn supports_pcode(&self) -> bool {
                unimplemented!()
            }
            fn is_volatile(&self, _addr: &Address) -> bool {
                unimplemented!()
            }
            fn parse(
                &self,
                _buf: &dyn MemBuffer,
                _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
                _in_delay_slot: bool,
            ) -> Result<
                Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
                crate::program::model::lang::language::ParseError,
            > {
                unimplemented!()
            }
            fn get_number_of_user_defined_op_names(&self) -> i32 {
                unimplemented!()
            }
            fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
                unimplemented!()
            }
            fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
                unimplemented!()
            }
            fn get_register_in_space(&self, _addrspc: &Arc<AddressSpace>, _offset: i64, _size: i32) -> Option<RegisterRef> {
                unimplemented!()
            }
            fn get_registers(&self) -> Vec<RegisterRef> {
                unimplemented!()
            }
            fn get_register_names(&self) -> Vec<String> {
                unimplemented!()
            }
            fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
                unimplemented!()
            }
            fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
                unimplemented!()
            }
            fn get_context_base_register(&self) -> Option<RegisterRef> {
                unimplemented!()
            }
            fn get_context_registers(&self) -> Vec<RegisterRef> {
                unimplemented!()
            }
            fn get_default_memory_blocks(&self) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
                unimplemented!()
            }
            fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
                unimplemented!()
            }
            fn get_segmented_space(&self) -> String {
                unimplemented!()
            }
            fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
                unimplemented!()
            }
            fn apply_context_settings(&self, _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext) {
                unimplemented!()
            }
            fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
                unimplemented!()
            }
            fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>> {
                unimplemented!()
            }
            fn get_compiler_spec_by_id(
                &self,
                _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
            ) -> Result<Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>, crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException> {
                unimplemented!()
            }
            fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
                unimplemented!()
            }
            fn has_property(&self, _key: &str) -> bool {
                unimplemented!()
            }
            fn get_property_as_int(&self, _key: &str, _default_int: i32) -> i32 {
                unimplemented!()
            }
            fn get_property_as_boolean(&self, _key: &str, _default_boolean: bool) -> bool {
                unimplemented!()
            }
            fn get_property_or(&self, _key: &str, _default_string: &str) -> String {
                unimplemented!()
            }
            fn get_property(&self, _key: &str) -> Option<String> {
                unimplemented!()
            }
            fn get_property_keys(&self) -> std::collections::HashSet<String> {
                unimplemented!()
            }
            fn has_manual(&self) -> bool {
                unimplemented!()
            }
            fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
                unimplemented!()
            }
            fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
                unimplemented!()
            }
            fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
                unimplemented!()
            }
            fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
                unimplemented!()
            }
            fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
                unimplemented!()
            }
            fn get_maximum_instruction_length(&self) -> Option<i32> {
                unimplemented!()
            }
        };
    }

    impl Language for TestLanguage {
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            Box::new(self.factory.clone())
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            self.factory.get_default_address_space().expect("the test factory has a default space")
        }
        /// No program counter: a `PcodeExecutor` built over this language (as the SymZ3 thread
        /// executor's tests do) then sizes branches by the default space's pointer size.
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        unimplemented_language_methods!();
    }

    pub(crate) fn test_language() -> Arc<dyn Language> {
        let ram = AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0);
        let unique = AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 0);
        let register = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);
        let constant = AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 0);
        Arc::new(TestLanguage {
            factory: DefaultAddressFactory::new(vec![ram, unique, register, constant]),
        })
    }

    struct MockArithmetic;

    impl PcodeArithmetic<SymValueZ3> for MockArithmetic {
        fn get_domain(&self) -> &'static str {
            "SymValueZ3"
        }
        fn get_endian(&self) -> Option<crate::program::model::lang::endian::Endian> {
            None
        }
        fn unary_op(&self, _opcode: crate::program::model::pcode::OpCode, _sizeout: i32, _sizein1: i32, _in1: &SymValueZ3) -> SymValueZ3 {
            unimplemented!()
        }
        fn binary_op(
            &self,
            _opcode: crate::program::model::pcode::OpCode,
            _sizeout: i32,
            _sizein1: i32,
            _in1: &SymValueZ3,
            _sizein2: i32,
            _in2: &SymValueZ3,
        ) -> SymValueZ3 {
            unimplemented!()
        }
        fn ptr_add(&self, _sizeout: i32, _sizein_base: i32, _in_base: &SymValueZ3, _sizein_index: i32, _in_index: &SymValueZ3, _in_size: i32) -> SymValueZ3 {
            unimplemented!()
        }
        fn ptr_sub(&self, _sizeout: i32, _sizein_base: i32, _in_base: &SymValueZ3, _sizein_offset: i32, _in_offset: &SymValueZ3) -> SymValueZ3 {
            unimplemented!()
        }
        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &SymValueZ3,
            _sizein_value: i32,
            _in_value: &SymValueZ3,
        ) -> SymValueZ3 {
            unimplemented!()
        }
        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &SymValueZ3,
            _sizein_value: i32,
            _in_value: &SymValueZ3,
        ) -> SymValueZ3 {
            unimplemented!()
        }
        fn from_const_bytes(&self, _value: &[u8]) -> SymValueZ3 {
            unimplemented!()
        }
        fn from_const_u64(&self, value: u64, size: i32) -> SymValueZ3 {
            let ctx = MockCtx;
            SymValueZ3::from_bit_vec(&ctx, &*ctx.mk_bv(value as i64, (size * 8) as u32))
        }
        fn to_concrete(&self, _value: &SymValueZ3, _purpose: Purpose) -> Result<Vec<u8>, crate::pcode::exec::concretion_error::ConcretionError> {
            unimplemented!()
        }
        fn is_true(&self, _cond: &SymValueZ3, _purpose: Purpose) -> Result<bool, crate::pcode::exec::concretion_error::ConcretionError> {
            unimplemented!()
        }
        fn size_of(&self, _value: &SymValueZ3) -> i64 {
            unimplemented!()
        }
    }

    pub(crate) fn piece() -> SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks> {
        SymZ3PcodeExecutorStatePiece::new(
            test_language(),
            Arc::new(MockArithmetic),
            Arc::new(MockArithmetic),
            Arc::new(crate::pcode::exec::pcode_state_callbacks::NONE),
            Arc::new(MockCtx),
        )
    }

    pub(crate) fn ram_space(p: &SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks>) -> Arc<AddressSpace> {
        p.language.get_address_factory().get_address_spaces().into_iter().find(|s| s.name() == "ram").unwrap()
    }

    pub(crate) fn unique_space(p: &SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks>) -> Arc<AddressSpace> {
        Arc::clone(&p.unique_space)
    }

    pub(crate) fn const_space(p: &SymZ3PcodeExecutorStatePiece<NoPcodeStateCallbacks>) -> Arc<AddressSpace> {
        p.language.get_address_factory().get_constant_space().unwrap()
    }

    pub(crate) fn numeral(ctx: &MockCtx, value: i64, size: u32) -> SymValueZ3 {
        SymValueZ3::from_bit_vec(ctx, &*ctx.mk_bv(value, size))
    }

    #[test]
    fn set_and_get_a_unique_space_variable_round_trips() {
        let ctx = MockCtx;
        let mut p = piece();
        let space = unique_space(&p);
        let offset = numeral(&ctx, 8, 32);
        let val = numeral(&ctx, 0xAB, 8);

        p.set_var_abstract(&space, &offset, 1, false, &val);
        let got = p.get_var_abstract(&space, &offset, 1, false, Reason::ExecuteRead);

        assert_eq!(got, val);
    }

    #[test]
    fn get_var_from_the_constant_space_re_encodes_the_offset_as_a_value() {
        let ctx = MockCtx;
        let p = piece();
        let space = const_space(&p);
        let offset = numeral(&ctx, 42, 64);

        let got = p.get_var_abstract(&space, &offset, 4, false, Reason::ExecuteRead);

        assert_eq!(got.to_long(&ctx), Some(42));
    }

    #[test]
    #[should_panic(expected = "Cannot write to constant space")]
    fn set_var_on_the_constant_space_panics() {
        let ctx = MockCtx;
        let mut p = piece();
        let space = const_space(&p);
        let offset = numeral(&ctx, 42, 64);
        let val = numeral(&ctx, 1, 8);

        p.set_var_abstract(&space, &offset, 1, false, &val);
    }

    #[test]
    fn get_var_from_an_untouched_memory_space_falls_back_to_the_null_space_default() {
        let ctx = MockCtx;
        let p = piece();
        let space = ram_space(&p);
        let offset = numeral(&ctx, 0x1000, 64);

        let got = p.get_var_abstract(&space, &offset, 4, false, Reason::ExecuteRead);

        assert_eq!(got.to_long(&ctx), Some(0));
    }

    #[test]
    fn add_instruction_and_add_op_accumulate_in_order() {
        use crate::program::model::address::Address;
        use crate::program::model::pcode::OpCode;

        let mut p = piece();
        let thread = SymZ3ThreadId::new("[Threads][0]");
        let ram = ram_space(&p);
        let addr = ram.address(0x400);

        let op0 = PcodeOp::with_address_no_inputs(addr.clone(), 0, OpCode::Copy);
        let op1 = PcodeOp::with_address_no_inputs(addr, 1, OpCode::Copy);
        p.add_op(&thread, op0);
        p.add_op(&thread, op1);

        let ops = SymZ3RecordsExecution::get_ops(&p);
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].index, 0);
        assert_eq!(ops[1].index, 1);

        let _ = Address::new; // keep import used across cfg permutations
    }

    #[test]
    fn add_precondition_and_get_preconditions_round_trip() {
        let mut p = piece();
        InternalSymZ3RecordsPreconditions::add_precondition(&mut p, "x > 0".to_string());
        assert_eq!(SymZ3RecordsPreconditions::get_preconditions(&p), vec!["x > 0".to_string()]);
    }

    #[test]
    fn clear_empties_everything() {
        let ctx = MockCtx;
        let mut p = piece();
        let space = unique_space(&p);
        let offset = numeral(&ctx, 1, 32);
        let val = numeral(&ctx, 2, 8);
        p.set_var_abstract(&space, &offset, 1, false, &val);
        InternalSymZ3RecordsPreconditions::add_precondition(&mut p, "a".to_string());
        let thread = SymZ3ThreadId::new("[Threads][0]");
        p.add_op(&thread, PcodeOp::with_address_no_inputs(ram_space(&p).address(0), 0, crate::program::model::pcode::OpCode::Copy));

        p.clear();

        assert!(p.space_map.is_empty());
        assert!(SymZ3RecordsPreconditions::get_preconditions(&p).is_empty());
        assert!(SymZ3RecordsExecution::get_ops(&p).is_empty());
    }
}
