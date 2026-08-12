//! Utilities for evaluating or executing Sleigh/p-code in the Debugger.
//!
//! Corresponds to `ghidra.pcode.exec.DebuggerPcodeUtils`.
//!
//! Java's `DebuggerPcodeUtils` is an `enum` with no constants: a non-instantiable holder for
//! nested types and statics. [`DebuggerPcodeUtils`] mirrors that as an uninhabited enum, which is
//! likewise a pure namespace and cannot be constructed.
//!
//! # What is not ported yet
//!
//! Two groups of members are held back because the Java machinery they bind to has no Rust
//! counterpart to bind *to* yet -- porting them would mean inventing shapes that will not match
//! the real ports:
//!
//! - `LabelBoundPcodeParser` and the three `compileProgram`/`compileExpression` statics. The
//!   parser extends `SleighProgramCompiler.ErrorCollectingPcodeParser`, itself a subclass of the
//!   ANTLR-driven `PcodeParser`; neither is ported, and the overrides are template methods with
//!   nothing to override. Its `createSleighConstant` also needs `VarnodeSymbol`'s
//!   `(Location, String, AddressSpace, long, int)` constructor, which
//!   [`VarnodeSymbol`](crate::decompiler::slghsymbol::varnode_symbol::VarnodeSymbol) does not
//!   expose yet.
//! - `executorStateForCoordinates`, `executorForCoordinates`, `buildWatchState` and
//!   `buildWatchExecutor`. Beyond the unported `DefaultPcodeDebuggerAccess`,
//!   `DebuggerEmulationIntegration` and `DefaultPcodeTraceAccess`, each of these hinges on the
//!   `platform.getLanguage() instanceof SleighLanguage` narrowing.
//!   [`SleighLanguage`](crate::program::model::lang::sleigh::SleighLanguage) does not implement
//!   [`Language`] in this crate (see `AbstractPcodeMachine`'s module docs), so a
//!   `Box<dyn Language>` cannot be narrowed to it and the guard cannot be expressed.
//!
//! Everything else -- the watch-value domain, its arithmetic, and its state -- is ported here.

use std::fmt;
use std::sync::Arc;

use crate::pcode::exec::concretion_error::ConcretionError;
use crate::pcode::exec::location_pcode_arithmetic::LocationPcodeArithmetic;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::{
    ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
};
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::pcode::seam_stubs::{
    AddressesReadPcodeArithmetic, BytesPcodeArithmetic, TraceMemoryStatePcodeArithmetic,
    ValueLocation,
};
use crate::pcode::utils::bytes_to_big_integer;
use crate::program::model::address::{Address, AddressSet, AddressSpace};
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::mem::mem_buffer::MemBuffer;
use crate::program::model::pcode::OpCode;
use crate::trace::model::memory::trace_memory_state::TraceMemoryState;
use crate::util::seam_stubs::NumericUtilities;

/// Utilities for evaluating or executing Sleigh/p-code in the Debugger.
///
/// Port of `ghidra.pcode.exec.DebuggerPcodeUtils`, a Java `enum` declaring no constants. It has
/// no values, so this enum has no variants: it exists only to name the module's nested types
/// (which Java nests inside it) and, once their seams land, its statics.
pub enum DebuggerPcodeUtils {}

/// Render a `BigInteger`-equivalent `i128` the way Java's `BigInteger.toString(16)` does, i.e.
/// sign-magnitude, rather than Rust's two's-complement `{:x}`.
fn to_hex_string(value: i128) -> String {
    if value < 0 {
        format!("-{:x}", value.unsigned_abs())
    }
    else {
        format!("{:x}", value)
    }
}

/// A wrapper on a byte array to pretty print it.
///
/// Port of the record `DebuggerPcodeUtils.PrettyBytes`. Java's `bytes()` accessor returns a
/// defensive copy, since a Java array is always mutable through any reference to it; here `bytes`
/// is an immutable `Vec<u8>` reachable only by shared borrow (or by cloning the whole value), so
/// no copy is needed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrettyBytes {
    /// Whether [`Self::bytes`] is to be interpreted most-significant byte first.
    pub big_endian: bool,
    /// The wrapped bytes.
    pub bytes: Vec<u8>,
}

impl PrettyBytes {
    /// Port of the canonical record constructor `PrettyBytes(boolean, byte[])`.
    pub fn new(big_endian: bool, bytes: Vec<u8>) -> Self {
        Self { big_endian, bytes }
    }

    /// Render at most 256 bytes in lines of 16 space-separated bytes each.
    ///
    /// If the total exceeds 256 bytes, the last line will contain ellipses and indicate the total
    /// size in bytes.
    ///
    /// Port of `PrettyBytes.toBytesString()`.
    pub fn to_bytes_string(&self) -> String {
        let mut buf = String::new();
        let mut first = true;
        let mut i = 0;
        while i < self.bytes.len() {
            if i >= 256 {
                buf.push_str("\n... (count=");
                buf.push_str(&self.bytes.len().to_string());
                buf.push(')');
                break;
            }
            if first {
                first = false;
            }
            else {
                buf.push('\n');
            }
            let len = 16.min(self.bytes.len() - i);
            buf.push_str(&NumericUtilities::convert_bytes_to_string_range(&self.bytes, i, len, " "));
            i += 16;
        }
        buf
    }

    /// Render the bytes as an unsigned decimal integer, taking the endianness from
    /// [`Self::big_endian`].
    ///
    /// Port of `PrettyBytes.toIntegerString()`.
    pub fn to_integer_string(&self) -> String {
        self.to_big_integer(false).to_string()
    }

    /// Collect various integer representations: signed, unsigned; decimal, hexadecimal.
    ///
    /// This only presents those forms that differ from those already offered. The preferred form
    /// is unsigned decimal. If all four differ, then they are formatted on two lines: unsigned
    /// then signed.
    ///
    /// Port of `PrettyBytes.collectDisplays()`.
    pub fn collect_displays(&self) -> String {
        let unsigned = self.to_big_integer(false);
        let mut sb = String::new();
        let u_dec = unsigned.to_string();
        sb.push_str(&u_dec);
        let u_hex = to_hex_string(unsigned);
        let radix_matters = u_hex != u_dec;
        if radix_matters {
            sb.push_str(", 0x");
            sb.push_str(&u_hex);
        }
        let signed = self.to_big_integer(true);
        if signed != unsigned {
            sb.push_str(if radix_matters { "\n" } else { ", " });
            let s_dec = signed.to_string();
            sb.push_str(&s_dec);
            let s_hex = to_hex_string(signed);
            if s_hex != s_dec {
                sb.push_str(", -0x");
                sb.push_str(&s_hex[1..]);
            }
        }
        sb
    }

    /// Convert the array to a big integer with the given signedness.
    ///
    /// Port of `PrettyBytes.toBigInteger(boolean)`. As elsewhere in this crate, Java's
    /// `BigInteger` maps to `i128`.
    pub fn to_big_integer(&self, signed: bool) -> i128 {
        bytes_to_big_integer(&self.bytes, self.bytes.len(), self.big_endian, signed)
    }

    /// Get the number of bytes.
    ///
    /// Port of `PrettyBytes.length()`.
    pub fn length(&self) -> usize {
        self.bytes.len()
    }

    /// Whether there are no bytes at all.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Display for PrettyBytes {
    /// Port of `PrettyBytes.toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PrettyBytes[bigEndian={},bytes={},value={}]",
            self.big_endian,
            NumericUtilities::convert_bytes_to_string(&self.bytes, ":"),
            self.to_big_integer(false)
        )
    }
}

/// The value of a watch expression including its state, location, and addresses read.
///
/// Port of the record `DebuggerPcodeUtils.WatchValue`. Each auxiliary component is nullable in
/// Java, which the Rust port carries in an `Option`, matching how the corresponding arithmetics
/// type their domains.
#[derive(Debug, Clone, PartialEq)]
pub struct WatchValue {
    /// The concrete value.
    pub bytes: PrettyBytes,
    /// The trace memory state of the value.
    pub state: Option<TraceMemoryState>,
    /// Where the value is located, if it is located anywhere.
    pub location: Option<ValueLocation>,
    /// The physical addresses read while computing the value.
    pub reads: Option<AddressSet>,
}

impl WatchValue {
    /// Port of the canonical record constructor
    /// `WatchValue(PrettyBytes, TraceMemoryState, ValueLocation, AddressSetView)`.
    pub fn new(
        bytes: PrettyBytes,
        state: Option<TraceMemoryState>,
        location: Option<ValueLocation>,
        reads: Option<AddressSet>,
    ) -> Self {
        Self { bytes, state, location, reads }
    }

    /// Get the value as a big integer with the given signedness.
    ///
    /// Port of `WatchValue.toBigInteger(boolean)`.
    pub fn to_big_integer(&self, signed: bool) -> i128 {
        self.bytes.to_big_integer(signed)
    }

    /// Get the address of the value, or `None` where Java returns `null` because the value is not
    /// located anywhere.
    ///
    /// Port of `WatchValue.address()`.
    pub fn address(&self) -> Option<&Address> {
        self.location.as_ref()?.get_address()
    }

    /// Get the number of bytes.
    ///
    /// Port of `WatchValue.length()`.
    pub fn length(&self) -> usize {
        self.bytes.length()
    }

    /// Whether the value has no bytes at all.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// A p-code arithmetic on watch values.
///
/// Port of the enum `DebuggerPcodeUtils.WatchValuePcodeArithmetic`. This is just a composition of
/// four arithmetics; Java notes that `Pair<A,Pair<B,Pair<C,D>>>` would be unwieldy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatchValuePcodeArithmetic {
    /// Composes the big-endian bytes and location arithmetics.
    BigEndian,
    /// Composes the little-endian bytes and location arithmetics.
    LittleEndian,
}

/// The state component's arithmetic, shared by both variants.
const STATE: TraceMemoryStatePcodeArithmetic = TraceMemoryStatePcodeArithmetic::Instance;
/// The addresses-read component's arithmetic, shared by both variants.
const READS: AddressesReadPcodeArithmetic = AddressesReadPcodeArithmetic::Instance;

impl WatchValuePcodeArithmetic {
    /// Port of `WatchValuePcodeArithmetic.forEndian(boolean)`.
    pub fn for_endian(is_big_endian: bool) -> Self {
        if is_big_endian { Self::BigEndian } else { Self::LittleEndian }
    }

    /// Port of `WatchValuePcodeArithmetic.forLanguage(Language)`.
    pub fn for_language(language: &dyn Language) -> Self {
        Self::for_endian(language.is_big_endian())
    }

    /// The `bytes` component of the composition.
    fn bytes(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
        BytesPcodeArithmetic::for_endian(self.is_big_endian())
    }

    /// The `location` component of the composition.
    fn location(&self) -> LocationPcodeArithmetic {
        LocationPcodeArithmetic::for_endian(self.is_big_endian())
    }

    fn is_big_endian(&self) -> bool {
        matches!(self, Self::BigEndian)
    }
}

impl PcodeArithmetic<WatchValue> for WatchValuePcodeArithmetic {
    fn get_domain(&self) -> &'static str {
        "WatchValue"
    }

    /// Port of `getEndian()`, which defers to the `bytes` component. Since that component is
    /// selected by this variant's endianness, the answer is this variant's endianness.
    fn get_endian(&self) -> Option<Endian> {
        Some(if self.is_big_endian() { Endian::Big } else { Endian::Little })
    }

    fn unary_op(&self, opcode: OpCode, sizeout: i32, sizein1: i32, in1: &WatchValue) -> WatchValue {
        WatchValue::new(
            PrettyBytes::new(
                self.is_big_endian(),
                self.bytes().unary_op(opcode, sizeout, sizein1, &in1.bytes.bytes),
            ),
            STATE.unary_op(opcode, sizeout, sizein1, &in1.state),
            self.location().unary_op(opcode, sizeout, sizein1, &in1.location),
            READS.unary_op(opcode, sizeout, sizein1, &in1.reads),
        )
    }

    fn binary_op(
        &self,
        opcode: OpCode,
        sizeout: i32,
        sizein1: i32,
        in1: &WatchValue,
        sizein2: i32,
        in2: &WatchValue,
    ) -> WatchValue {
        WatchValue::new(
            PrettyBytes::new(
                self.is_big_endian(),
                self.bytes().binary_op(
                    opcode,
                    sizeout,
                    sizein1,
                    &in1.bytes.bytes,
                    sizein2,
                    &in2.bytes.bytes,
                ),
            ),
            STATE.binary_op(opcode, sizeout, sizein1, &in1.state, sizein2, &in2.state),
            self.location().binary_op(
                opcode,
                sizeout,
                sizein1,
                &in1.location,
                sizein2,
                &in2.location,
            ),
            READS.binary_op(opcode, sizeout, sizein1, &in1.reads, sizein2, &in2.reads),
        )
    }

    fn mod_before_store(
        &self,
        sizein_offset: i32,
        space: &AddressSpace,
        in_offset: &WatchValue,
        sizein_value: i32,
        in_value: &WatchValue,
    ) -> WatchValue {
        WatchValue::new(
            PrettyBytes::new(
                in_value.bytes.big_endian,
                self.bytes().mod_before_store(
                    sizein_offset,
                    space,
                    &in_offset.bytes.bytes,
                    sizein_value,
                    &in_value.bytes.bytes,
                ),
            ),
            STATE.mod_before_store(
                sizein_offset,
                space,
                &in_offset.state,
                sizein_value,
                &in_value.state,
            ),
            self.location().mod_before_store(
                sizein_offset,
                space,
                &in_offset.location,
                sizein_value,
                &in_value.location,
            ),
            READS.mod_before_store(
                sizein_offset,
                space,
                &in_offset.reads,
                sizein_value,
                &in_value.reads,
            ),
        )
    }

    fn mod_after_load(
        &self,
        sizein_offset: i32,
        space: &AddressSpace,
        in_offset: &WatchValue,
        sizein_value: i32,
        in_value: &WatchValue,
    ) -> WatchValue {
        WatchValue::new(
            PrettyBytes::new(
                self.is_big_endian(),
                self.bytes().mod_after_load(
                    sizein_offset,
                    space,
                    &in_offset.bytes.bytes,
                    sizein_value,
                    &in_value.bytes.bytes,
                ),
            ),
            STATE.mod_after_load(
                sizein_offset,
                space,
                &in_offset.state,
                sizein_value,
                &in_value.state,
            ),
            self.location().mod_after_load(
                sizein_offset,
                space,
                &in_offset.location,
                sizein_value,
                &in_value.location,
            ),
            READS.mod_after_load(
                sizein_offset,
                space,
                &in_offset.reads,
                sizein_value,
                &in_value.reads,
            ),
        )
    }

    fn from_const_bytes(&self, value: &[u8]) -> WatchValue {
        WatchValue::new(
            PrettyBytes::new(self.is_big_endian(), self.bytes().from_const_bytes(value)),
            STATE.from_const_bytes(value),
            self.location().from_const_bytes(value),
            READS.from_const_bytes(value),
        )
    }

    fn to_concrete(&self, value: &WatchValue, purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
        self.bytes().to_concrete(&value.bytes.bytes, purpose)
    }

    fn size_of(&self, value: &WatchValue) -> i64 {
        self.bytes().size_of(&value.bytes.bytes)
    }
}

/// A state piece composed from a bytes piece and the three auxiliary pieces that make up a
/// [`WatchValue`].
///
/// Port of `DebuggerPcodeUtils.WatchValuePcodeExecutorStatePiece`. As with
/// [`PairedPcodeExecutorStatePiece`](crate::pcode::exec::paired_pcode_executor_state_piece::PairedPcodeExecutorStatePiece),
/// the delegates are concrete type parameters rather than trait objects: this piece owns them and
/// never needs to swap one at runtime.
pub struct WatchValuePcodeExecutorStatePiece<PB, PS, PL, PR>
where
    PB: PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>,
    PS: PcodeExecutorStatePiece<Vec<u8>, Option<TraceMemoryState>>,
    PL: PcodeExecutorStatePiece<Vec<u8>, Option<ValueLocation>>,
    PR: PcodeExecutorStatePiece<Vec<u8>, Option<AddressSet>>,
{
    bytes_piece: PB,
    state_piece: PS,
    location_piece: PL,
    reads_piece: PR,
    arithmetic: WatchValuePcodeArithmetic,
}

impl<PB, PS, PL, PR> WatchValuePcodeExecutorStatePiece<PB, PS, PL, PR>
where
    PB: PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>,
    PS: PcodeExecutorStatePiece<Vec<u8>, Option<TraceMemoryState>>,
    PL: PcodeExecutorStatePiece<Vec<u8>, Option<ValueLocation>>,
    PR: PcodeExecutorStatePiece<Vec<u8>, Option<AddressSet>>,
{
    /// Port of `new WatchValuePcodeExecutorStatePiece(PcodeExecutorStatePiece<byte[], byte[]>,
    /// ..., ..., ...)`.
    pub fn new(bytes_piece: PB, state_piece: PS, location_piece: PL, reads_piece: PR) -> Self {
        let arithmetic = WatchValuePcodeArithmetic::for_language(&*bytes_piece.get_language());
        Self { bytes_piece, state_piece, location_piece, reads_piece, arithmetic }
    }

    /// The concrete-bytes delegate.
    pub fn get_bytes_piece(&self) -> &PB {
        &self.bytes_piece
    }

    /// The trace-memory-state delegate.
    pub fn get_state_piece(&self) -> &PS {
        &self.state_piece
    }

    /// The value-location delegate.
    pub fn get_location_piece(&self) -> &PL {
        &self.location_piece
    }

    /// The addresses-read delegate.
    pub fn get_reads_piece(&self) -> &PR {
        &self.reads_piece
    }

    /// Whether this piece's language is big endian.
    ///
    /// Java re-derives this from `getLanguage().isBigEndian()` on every read; a piece's language
    /// never changes, so the port takes it from the arithmetic chosen at construction, which is
    /// selected by exactly that call.
    fn is_big_endian(&self) -> bool {
        self.arithmetic.is_big_endian()
    }
}

impl<PB, PS, PL, PR> PcodeExecutorStatePiece<Vec<u8>, WatchValue>
    for WatchValuePcodeExecutorStatePiece<PB, PS, PL, PR>
where
    PB: PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>,
    PS: PcodeExecutorStatePiece<Vec<u8>, Option<TraceMemoryState>>,
    PL: PcodeExecutorStatePiece<Vec<u8>, Option<ValueLocation>>,
    PR: PcodeExecutorStatePiece<Vec<u8>, Option<AddressSet>>,
{
    fn get_language(&self) -> Box<dyn Language> {
        self.bytes_piece.get_language()
    }

    fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
        self.bytes_piece.get_address_arithmetic()
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<WatchValue>> {
        Arc::new(self.arithmetic)
    }

    fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
        let mut pieces = self.bytes_piece.stream_pieces();
        pieces.extend(self.state_piece.stream_pieces());
        pieces.extend(self.location_piece.stream_pieces());
        pieces.extend(self.reads_piece.stream_pieces());
        pieces
    }

    fn fork<CB: PcodeStateCallbacks>(&self, cb: &CB) -> Self
    where
        Self: Sized,
    {
        Self {
            bytes_piece: self.bytes_piece.fork(cb),
            state_piece: self.state_piece.fork(cb),
            location_piece: self.location_piece.fork(cb),
            reads_piece: self.reads_piece.fork(cb),
            arithmetic: self.arithmetic,
        }
    }

    fn set_var_internal_abstract(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: &Vec<u8>,
        size: i32,
        val: &WatchValue,
    ) {
        self.bytes_piece.set_var_internal_abstract(space, offset, size, &val.bytes.bytes);
        self.state_piece.set_var_internal_abstract(space, offset, size, &val.state);
        self.location_piece.set_var_internal_abstract(space, offset, size, &val.location);
        self.reads_piece.set_var_internal_abstract(space, offset, size, &val.reads);
    }

    fn set_var_abstract(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: &Vec<u8>,
        size: i32,
        quantize: bool,
        val: &WatchValue,
    ) {
        self.bytes_piece.set_var_abstract(space, offset, size, quantize, &val.bytes.bytes);
        self.state_piece.set_var_abstract(space, offset, size, quantize, &val.state);
        self.location_piece.set_var_abstract(space, offset, size, quantize, &val.location);
        self.reads_piece.set_var_abstract(space, offset, size, quantize, &val.reads);
    }

    fn get_var_abstract(
        &self,
        space: &Arc<AddressSpace>,
        offset: &Vec<u8>,
        size: i32,
        quantize: bool,
        reason: Reason,
    ) -> WatchValue {
        WatchValue::new(
            PrettyBytes::new(
                self.is_big_endian(),
                self.bytes_piece.get_var_abstract(space, offset, size, quantize, reason),
            ),
            self.state_piece.get_var_abstract(space, offset, size, quantize, reason),
            self.location_piece.get_var_abstract(space, offset, size, quantize, reason),
            self.reads_piece.get_var_abstract(space, offset, size, quantize, reason),
        )
    }

    fn get_var_internal_abstract(
        &self,
        space: &Arc<AddressSpace>,
        offset: &Vec<u8>,
        size: i32,
        reason: Reason,
    ) -> WatchValue {
        WatchValue::new(
            PrettyBytes::new(
                self.is_big_endian(),
                self.bytes_piece.get_var_internal_abstract(space, offset, size, reason),
            ),
            self.state_piece.get_var_internal_abstract(space, offset, size, reason),
            self.location_piece.get_var_internal_abstract(space, offset, size, reason),
            self.reads_piece.get_var_internal_abstract(space, offset, size, reason),
        )
    }

    /// Port of `getRegisterValues()`, which enumerates the registers known to the bytes piece and
    /// reads each auxiliary component at that register's own space, offset, and size.
    fn get_register_values(&self) -> Vec<(RegisterRef, WatchValue)> {
        let big_endian = self.is_big_endian();
        self.bytes_piece
            .get_register_values()
            .into_iter()
            .map(|(reg, bytes)| {
                let (space, offset, size) = {
                    let reg = reg.borrow();
                    (reg.address_space(), reg.address().offset(), reg.num_bytes())
                };
                let value = WatchValue::new(
                    PrettyBytes::new(big_endian, bytes),
                    self.state_piece.get_var(&space, offset, size, false, Reason::Inspect),
                    self.location_piece.get_var(&space, offset, size, false, Reason::Inspect),
                    self.reads_piece.get_var(&space, offset, size, false, Reason::Inspect),
                );
                (reg, value)
            })
            .collect()
    }

    fn get_concrete_buffer(&self, address: &Address, purpose: Purpose) -> Box<dyn MemBuffer> {
        self.bytes_piece.get_concrete_buffer(address, purpose)
    }

    fn clear(&mut self) {
        self.bytes_piece.clear();
        self.state_piece.clear();
        self.location_piece.clear();
        self.reads_piece.clear();
    }
}

/// A state storing [`WatchValue`]s, addressed by the concrete bytes of a watch value.
///
/// Port of `DebuggerPcodeUtils.WatchValuePcodeExecutorState`. Java derives it from
/// `AbstractPcodeExecutorState<byte[], WatchValue>`, whose whole body is delegation to the wrapped
/// piece plus the `extractAddress` hook; that base is not ported, so -- as
/// [`PairedPcodeExecutorState`](crate::pcode::exec::paired_pcode_executor_state::PairedPcodeExecutorState)
/// already does -- this wraps the piece and delegates directly.
pub struct WatchValuePcodeExecutorState<PB, PS, PL, PR>
where
    PB: PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>,
    PS: PcodeExecutorStatePiece<Vec<u8>, Option<TraceMemoryState>>,
    PL: PcodeExecutorStatePiece<Vec<u8>, Option<ValueLocation>>,
    PR: PcodeExecutorStatePiece<Vec<u8>, Option<AddressSet>>,
{
    piece: WatchValuePcodeExecutorStatePiece<PB, PS, PL, PR>,
}

impl<PB, PS, PL, PR> WatchValuePcodeExecutorState<PB, PS, PL, PR>
where
    PB: PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>,
    PS: PcodeExecutorStatePiece<Vec<u8>, Option<TraceMemoryState>>,
    PL: PcodeExecutorStatePiece<Vec<u8>, Option<ValueLocation>>,
    PR: PcodeExecutorStatePiece<Vec<u8>, Option<AddressSet>>,
{
    /// Port of `new WatchValuePcodeExecutorState(PcodeExecutorStatePiece<byte[], WatchValue>)`.
    pub fn new(piece: WatchValuePcodeExecutorStatePiece<PB, PS, PL, PR>) -> Self {
        Self { piece }
    }

    /// The wrapped piece.
    pub fn get_piece(&self) -> &WatchValuePcodeExecutorStatePiece<PB, PS, PL, PR> {
        &self.piece
    }

    /// Port of `extractAddress(WatchValue)`: a watch value addresses the state by its concrete
    /// bytes.
    fn extract_address(value: &WatchValue) -> &Vec<u8> {
        &value.bytes.bytes
    }
}

impl<PB, PS, PL, PR> PcodeExecutorStatePiece<WatchValue, WatchValue>
    for WatchValuePcodeExecutorState<PB, PS, PL, PR>
where
    PB: PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>,
    PS: PcodeExecutorStatePiece<Vec<u8>, Option<TraceMemoryState>>,
    PL: PcodeExecutorStatePiece<Vec<u8>, Option<ValueLocation>>,
    PR: PcodeExecutorStatePiece<Vec<u8>, Option<AddressSet>>,
{
    fn get_language(&self) -> Box<dyn Language> {
        self.piece.get_language()
    }

    fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<WatchValue>> {
        self.piece.get_arithmetic()
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<WatchValue>> {
        self.piece.get_arithmetic()
    }

    fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
        self.piece.stream_pieces()
    }

    fn fork<CB: PcodeStateCallbacks>(&self, cb: &CB) -> Self
    where
        Self: Sized,
    {
        Self::new(self.piece.fork(cb))
    }

    fn set_var_abstract(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: &WatchValue,
        size: i32,
        quantize: bool,
        val: &WatchValue,
    ) {
        let offset = Self::extract_address(offset).clone();
        self.piece.set_var_abstract(space, &offset, size, quantize, val);
    }

    fn set_var_internal_abstract(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: &WatchValue,
        size: i32,
        val: &WatchValue,
    ) {
        let offset = Self::extract_address(offset).clone();
        self.piece.set_var_internal_abstract(space, &offset, size, val);
    }

    fn set_var(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: i64,
        size: i32,
        quantize: bool,
        val: &WatchValue,
    ) {
        self.piece.set_var(space, offset, size, quantize, val);
    }

    fn set_var_internal(
        &mut self,
        space: &Arc<AddressSpace>,
        offset: i64,
        size: i32,
        val: &WatchValue,
    ) {
        self.piece.set_var_internal(space, offset, size, val);
    }

    fn get_var_abstract(
        &self,
        space: &Arc<AddressSpace>,
        offset: &WatchValue,
        size: i32,
        quantize: bool,
        reason: Reason,
    ) -> WatchValue {
        self.piece.get_var_abstract(space, Self::extract_address(offset), size, quantize, reason)
    }

    fn get_var_internal_abstract(
        &self,
        space: &Arc<AddressSpace>,
        offset: &WatchValue,
        size: i32,
        reason: Reason,
    ) -> WatchValue {
        self.piece.get_var_internal_abstract(space, Self::extract_address(offset), size, reason)
    }

    fn get_var(
        &self,
        space: &Arc<AddressSpace>,
        offset: i64,
        size: i32,
        quantize: bool,
        reason: Reason,
    ) -> WatchValue {
        self.piece.get_var(space, offset, size, quantize, reason)
    }

    fn get_var_internal(
        &self,
        space: &Arc<AddressSpace>,
        offset: i64,
        size: i32,
        reason: Reason,
    ) -> WatchValue {
        self.piece.get_var_internal(space, offset, size, reason)
    }

    fn get_register_values(&self) -> Vec<(RegisterRef, WatchValue)> {
        self.piece.get_register_values()
    }

    fn get_concrete_buffer(&self, address: &Address, purpose: Purpose) -> Box<dyn MemBuffer> {
        self.piece.get_concrete_buffer(address, purpose)
    }

    fn clear(&mut self) {
        self.piece.clear();
    }
}

impl<PB, PS, PL, PR> PcodeExecutorState<WatchValue> for WatchValuePcodeExecutorState<PB, PS, PL, PR>
where
    PB: PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>,
    PS: PcodeExecutorStatePiece<Vec<u8>, Option<TraceMemoryState>>,
    PL: PcodeExecutorStatePiece<Vec<u8>, Option<ValueLocation>>,
    PR: PcodeExecutorStatePiece<Vec<u8>, Option<AddressSet>>,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::rc::Rc;

    use crate::pcode::exec::pcode_state_callbacks::NoPcodeStateCallbacks;
    use crate::pcode::utils::{bytes_to_long, long_to_bytes};
    use crate::program::model::address::factory::AddressFactory;
    use crate::program::model::address::{AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::lang::register::Register;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 64, 1, AddressSpaceType::Register, 1)
    }

    // -----------------------------------------------------------------------------------------
    // PrettyBytes
    // -----------------------------------------------------------------------------------------

    #[test]
    fn to_string_renders_endianness_colon_delimited_bytes_and_unsigned_value() {
        let value = PrettyBytes::new(true, vec![0x12, 0x34]);
        assert_eq!(value.to_string(), "PrettyBytes[bigEndian=true,bytes=12:34,value=4660]");

        // The same bytes read little endian give a different value, but the same rendering order.
        let value = PrettyBytes::new(false, vec![0x12, 0x34]);
        assert_eq!(value.to_string(), "PrettyBytes[bigEndian=false,bytes=12:34,value=13330]");
    }

    #[test]
    fn to_big_integer_honors_endianness_and_signedness() {
        let be = PrettyBytes::new(true, vec![0xff, 0x00]);
        assert_eq!(be.to_big_integer(false), 0xff00);
        assert_eq!(be.to_big_integer(true), -256);

        let le = PrettyBytes::new(false, vec![0xff, 0x00]);
        assert_eq!(le.to_big_integer(false), 0x00ff);
        assert_eq!(le.to_big_integer(true), 0x00ff);
    }

    #[test]
    fn to_integer_string_is_the_unsigned_decimal_rendering() {
        assert_eq!(PrettyBytes::new(true, vec![0xff]).to_integer_string(), "255");
        assert_eq!(PrettyBytes::new(true, vec![0x00, 0x01]).to_integer_string(), "1");
    }

    #[test]
    fn to_bytes_string_wraps_every_sixteen_bytes() {
        let value = PrettyBytes::new(true, (0..20u8).collect());
        assert_eq!(
            value.to_bytes_string(),
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n10 11 12 13"
        );
    }

    #[test]
    fn to_bytes_string_truncates_after_256_bytes() {
        let value = PrettyBytes::new(true, vec![0xab; 300]);
        let rendered = value.to_bytes_string();
        let lines: Vec<&str> = rendered.split('\n').collect();
        // 256 bytes at 16 per line, then the ellipsis line.
        assert_eq!(lines.len(), 17);
        assert!(lines[..16].iter().all(|line| line.split(' ').count() == 16));
        assert_eq!(lines[16], "... (count=300)");
    }

    #[test]
    fn collect_displays_omits_forms_that_do_not_differ() {
        // Decimal and hex agree, and so do signed and unsigned: only one form is shown.
        assert_eq!(PrettyBytes::new(true, vec![0x05]).collect_displays(), "5");
        // Hex differs; signed still agrees with unsigned.
        assert_eq!(PrettyBytes::new(true, vec![0x0a]).collect_displays(), "10, 0xa");
    }

    #[test]
    fn collect_displays_shows_all_four_forms_on_two_lines() {
        assert_eq!(
            PrettyBytes::new(true, vec![0x80]).collect_displays(),
            "128, 0x80\n-128, -0x80"
        );
    }

    #[test]
    fn collect_displays_drops_the_signed_hex_when_it_matches_the_signed_decimal() {
        // -1 renders as "-1" in both bases, so only the decimal is appended.
        assert_eq!(PrettyBytes::new(true, vec![0xff]).collect_displays(), "255, 0xff\n-1");
    }

    // -----------------------------------------------------------------------------------------
    // WatchValue
    // -----------------------------------------------------------------------------------------

    #[test]
    fn watch_value_reports_its_length_value_and_address() {
        let ram = ram_space();
        let value = WatchValue::new(
            PrettyBytes::new(true, vec![0xff, 0xfe]),
            Some(TraceMemoryState::Known),
            Some(ValueLocation::from_const(0x1234, 2)),
            Some(AddressSet::from_address(ram.address(0x40))),
        );

        assert_eq!(value.length(), 2);
        assert_eq!(value.to_big_integer(false), 0xfffe);
        assert_eq!(value.to_big_integer(true), -2);
        assert_eq!(value.address().map(Address::offset), Some(0x1234));
    }

    #[test]
    fn watch_value_without_a_location_has_no_address() {
        let value =
            WatchValue::new(PrettyBytes::new(true, vec![0x01]), None, None, Some(AddressSet::new()));
        assert_eq!(value.address(), None);
    }

    // -----------------------------------------------------------------------------------------
    // WatchValuePcodeArithmetic
    // -----------------------------------------------------------------------------------------

    #[test]
    fn arithmetic_for_endian_and_for_language_select_the_matching_variant() {
        assert_eq!(
            WatchValuePcodeArithmetic::for_endian(true),
            WatchValuePcodeArithmetic::BigEndian
        );
        assert_eq!(
            WatchValuePcodeArithmetic::for_endian(false),
            WatchValuePcodeArithmetic::LittleEndian
        );
        assert_eq!(
            WatchValuePcodeArithmetic::for_language(&MockLanguage { big_endian: true }),
            WatchValuePcodeArithmetic::BigEndian
        );
        assert_eq!(
            WatchValuePcodeArithmetic::for_language(&MockLanguage { big_endian: false }),
            WatchValuePcodeArithmetic::LittleEndian
        );
    }

    #[test]
    fn arithmetic_reports_its_domain_and_endianness() {
        assert_eq!(WatchValuePcodeArithmetic::BigEndian.get_domain(), "WatchValue");
        assert_eq!(WatchValuePcodeArithmetic::BigEndian.get_endian(), Some(Endian::Big));
        assert_eq!(WatchValuePcodeArithmetic::LittleEndian.get_endian(), Some(Endian::Little));
    }

    // -----------------------------------------------------------------------------------------
    // WatchValuePcodeExecutorStatePiece / WatchValuePcodeExecutorState
    // -----------------------------------------------------------------------------------------

    /// A leaf state piece over `T`, keyed by the offset bytes. Enough of
    /// [`PcodeExecutorStatePiece`] is implemented (set/get, register values, fork, clear) to
    /// exercise the watch-value composition.
    struct MapPiece<T> {
        cells: HashMap<Vec<u8>, T>,
        registers: Vec<(RegisterRef, T)>,
        big_endian: bool,
    }

    impl<T: Clone + Default> MapPiece<T> {
        fn new(big_endian: bool) -> Self {
            Self { cells: HashMap::new(), registers: Vec::new(), big_endian }
        }
    }

    impl<T> ErasedPcodeExecutorStatePiece for MapPiece<T> {}

    impl<T: Clone + Default> PcodeExecutorStatePiece<Vec<u8>, T> for MapPiece<T> {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage { big_endian: self.big_endian })
        }

        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
            Arc::new(TestBytesArithmetic)
        }

        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<T>> {
            unimplemented!("not exercised by these tests")
        }

        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            vec![self]
        }

        fn fork<CB: PcodeStateCallbacks>(&self, _cb: &CB) -> Self {
            Self {
                cells: self.cells.clone(),
                registers: self.registers.clone(),
                big_endian: self.big_endian,
            }
        }

        fn set_var_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            offset: &Vec<u8>,
            _size: i32,
            _quantize: bool,
            val: &T,
        ) {
            self.cells.insert(offset.clone(), val.clone());
        }

        fn set_var_internal_abstract(
            &mut self,
            space: &Arc<AddressSpace>,
            offset: &Vec<u8>,
            size: i32,
            val: &T,
        ) {
            self.set_var_abstract(space, offset, size, false, val);
        }

        fn get_var_abstract(
            &self,
            _space: &Arc<AddressSpace>,
            offset: &Vec<u8>,
            _size: i32,
            _quantize: bool,
            _reason: Reason,
        ) -> T {
            self.cells.get(offset).cloned().unwrap_or_default()
        }

        fn get_var_internal_abstract(
            &self,
            space: &Arc<AddressSpace>,
            offset: &Vec<u8>,
            size: i32,
            reason: Reason,
        ) -> T {
            self.get_var_abstract(space, offset, size, false, reason)
        }

        fn get_register_values(&self) -> Vec<(RegisterRef, T)> {
            self.registers.clone()
        }

        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by these tests")
        }

        fn clear(&mut self) {
            self.cells.clear();
        }
    }

    /// Little-endian byte-array arithmetic, enough to turn `long` offsets into the `Vec<u8>`
    /// address domain the pieces are keyed by.
    struct TestBytesArithmetic;

    impl PcodeArithmetic<Vec<u8>> for TestBytesArithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }

        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, in1: &Vec<u8>) -> Vec<u8> {
            in1.clone()
        }

        fn binary_op(
            &self,
            _opcode: OpCode,
            sizeout: i32,
            _sizein1: i32,
            in1: &Vec<u8>,
            _sizein2: i32,
            in2: &Vec<u8>,
        ) -> Vec<u8> {
            let a = bytes_to_long(in1, in1.len(), false);
            let b = bytes_to_long(in2, in2.len(), false);
            long_to_bytes(a.wrapping_add(b), sizeout as usize, false)
        }

        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &Vec<u8>,
            _sizein_value: i32,
            in_value: &Vec<u8>,
        ) -> Vec<u8> {
            in_value.clone()
        }

        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &Vec<u8>,
            _sizein_value: i32,
            in_value: &Vec<u8>,
        ) -> Vec<u8> {
            in_value.clone()
        }

        fn from_const_bytes(&self, value: &[u8]) -> Vec<u8> {
            value.to_vec()
        }

        fn to_concrete(
            &self,
            value: &Vec<u8>,
            _purpose: Purpose,
        ) -> Result<Vec<u8>, ConcretionError> {
            Ok(value.clone())
        }

        fn size_of(&self, value: &Vec<u8>) -> i64 {
            value.len() as i64
        }
    }

    type TestPiece = WatchValuePcodeExecutorStatePiece<
        MapPiece<Vec<u8>>,
        MapPiece<Option<TraceMemoryState>>,
        MapPiece<Option<ValueLocation>>,
        MapPiece<Option<AddressSet>>,
    >;

    fn test_piece(big_endian: bool) -> TestPiece {
        WatchValuePcodeExecutorStatePiece::new(
            MapPiece::new(big_endian),
            MapPiece::new(big_endian),
            MapPiece::new(big_endian),
            MapPiece::new(big_endian),
        )
    }

    #[test]
    fn piece_takes_its_arithmetic_from_the_bytes_pieces_language() {
        assert_eq!(test_piece(true).arithmetic, WatchValuePcodeArithmetic::BigEndian);
        assert_eq!(test_piece(false).arithmetic, WatchValuePcodeArithmetic::LittleEndian);
    }

    #[test]
    fn piece_decomposes_a_watch_value_over_all_four_delegates() {
        let ram = ram_space();
        let mut piece = test_piece(true);
        let value = WatchValue::new(
            PrettyBytes::new(true, vec![0xde, 0xad]),
            Some(TraceMemoryState::Known),
            Some(ValueLocation::from_const(0x99, 2)),
            Some(AddressSet::from_address(ram.address(0x10))),
        );

        piece.set_var(&ram, 0x1000, 2, false, &value);
        let read = piece.get_var(&ram, 0x1000, 2, false, Reason::Inspect);

        assert_eq!(read, value);
        // Each component genuinely landed in its own delegate.
        let offset = long_to_bytes(0x1000, ram.pointer_size() as usize, false);
        assert_eq!(
            piece.get_bytes_piece().get_var_abstract(&ram, &offset, 2, false, Reason::Inspect),
            vec![0xde, 0xad]
        );
        assert_eq!(
            piece.get_state_piece().get_var_abstract(&ram, &offset, 2, false, Reason::Inspect),
            Some(TraceMemoryState::Known)
        );
    }

    #[test]
    fn piece_stamps_read_values_with_the_languages_endianness() {
        let ram = ram_space();
        let mut piece = test_piece(true);
        // Write with a little-endian PrettyBytes; the read-back must be re-stamped big endian,
        // because the piece labels every value it produces with its own language's endianness.
        piece.set_var(
            &ram,
            0x20,
            2,
            false,
            &WatchValue::new(PrettyBytes::new(false, vec![0x01, 0x02]), None, None, None),
        );

        let read = piece.get_var(&ram, 0x20, 2, false, Reason::Inspect);
        assert!(read.bytes.big_endian);
        assert_eq!(read.to_big_integer(false), 0x0102);
    }

    #[test]
    fn piece_composes_register_values_from_every_delegate() {
        let regs = register_space();
        let mut piece = test_piece(true);
        let r0 = Register::new("r0", "", regs.address(0x8), 4, false, Register::TYPE_NONE);
        piece.bytes_piece.registers.push((Rc::clone(&r0), vec![0, 0, 0, 7]));
        piece.state_piece.cells.insert(
            long_to_bytes(0x8, regs.pointer_size() as usize, false),
            Some(TraceMemoryState::Error),
        );

        let values = piece.get_register_values();

        assert_eq!(values.len(), 1);
        assert_eq!(values[0].0, r0);
        assert_eq!(values[0].1.bytes, PrettyBytes::new(true, vec![0, 0, 0, 7]));
        assert_eq!(values[0].1.state, Some(TraceMemoryState::Error));
        // Nothing was ever written to the location piece for that register.
        assert_eq!(values[0].1.location, None);
    }

    #[test]
    fn piece_fork_and_clear_reach_every_delegate() {
        let ram = ram_space();
        let mut piece = test_piece(true);
        let value =
            WatchValue::new(PrettyBytes::new(true, vec![1, 2]), Some(TraceMemoryState::Known), None, None);
        piece.set_var(&ram, 0x100, 2, false, &value);

        let mut forked = piece.fork(&NoPcodeStateCallbacks);
        forked.clear();

        assert_eq!(piece.get_var(&ram, 0x100, 2, false, Reason::Inspect), value);
        let cleared = forked.get_var(&ram, 0x100, 2, false, Reason::Inspect);
        assert_eq!(cleared.bytes, PrettyBytes::new(true, Vec::new()));
        assert_eq!(cleared.state, None);
    }

    #[test]
    fn state_addresses_itself_by_the_watch_values_concrete_bytes() {
        let ram = ram_space();
        let mut state = WatchValuePcodeExecutorState::new(test_piece(false));
        let stored =
            WatchValue::new(PrettyBytes::new(false, vec![0xaa, 0xbb]), Some(TraceMemoryState::Known), None, None);
        // Address the state with a watch value whose concrete bytes are the offset 0x1234.
        let offset = WatchValue::new(
            PrettyBytes::new(false, long_to_bytes(0x1234, 8, false)),
            Some(TraceMemoryState::Known),
            None,
            None,
        );

        state.set_var_abstract(&ram, &offset, 2, false, &stored);

        assert_eq!(state.get_var_abstract(&ram, &offset, 2, false, Reason::Inspect), stored);
        // The very same cell is reachable by the plain long offset.
        assert_eq!(state.get_var(&ram, 0x1234, 2, false, Reason::Inspect), stored);
    }

    /// A minimal language, per this crate's test convention. Only the endianness matters here.
    struct MockLanguage {
        big_endian: bool,
    }

    impl Language for MockLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::LanguageID {
            unimplemented!("not exercised by these tests")
        }
        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::LanguageDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::ParallelInstructionLanguageHelper>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("not exercised by these tests")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            Box::new(DefaultAddressFactory::new(vec![ram_space(), register_space()]))
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            ram_space()
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            ram_space()
        }
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn MemBuffer,
            _context: &mut dyn crate::program::model::lang::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::InstructionPrototype>,
            crate::program::model::lang::ParseError,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::DefaultProgramContext,
        ) {
        }
        fn reload_language(
            &self,
            _task_monitor: &dyn crate::util::task::TaskMonitor,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::CompilerSpec>,
            crate::program::model::lang::CompilerSpecNotFoundException,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unimplemented!("not exercised by these tests")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(
            &self,
            _instruction_mnemonic: &str,
        ) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn get_manual_exception(
            &self,
        ) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            Some(16)
        }
    }
}
