//! Minimal placeholder types for core types that a ported interface under [`crate::pcode`]
//! references before the real Rust port of that type exists yet. Each stub exposes only the
//! members needed by the interface(s) that currently reference it, and is expected to be
//! replaced (or grown into a supertrait/struct of) the real port once that Java class is ported.
//! See `STUBS.tsv` for provenance.

use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use crate::pcode::emu::jit::analysis::jit_type::{AnyJitType, IntJitType, LongJitType, MpIntJitType};
use crate::pcode::emu::jit::gen::access::mp_access_gen::MpAccessGen;
use crate::pcode::emu::jit::gen::util::emitter::{Bot, Ent, Emitter, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{TInt, TRef};
use crate::pcode::emu::jit::var::JitVar;
use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
use crate::pcode::exec::abstract_sleigh_pcode_userop_definition::AbstractSleighPcodeUseropDefinitionBase;
use crate::pcode::exec::concretion_error::ConcretionError;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_execution_exception::PcodeExecutionException;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::{
    ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
};
use crate::pcode::exec::pcode_frame::PcodeFrame;
use crate::pcode::exec::pcode_program::PcodeProgram;
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::pcode::exec::pcode_userop_library::{
    ErasedPcodeUseropLibrary, PcodeUseropLibrary, UseropMap,
};
use crate::pcode::exec::sleigh_pcode_userop_definition::{SignatureDef, SleighPcodeUseropDefinition};
use crate::pcode::exec::trace::data::pcode_trace_data_access::PcodeTraceDataAccess;
use crate::pcode::floatformat::big_float::{BigFloat, MathContext};
use crate::program::model::address::{
    Address, AddressRange, AddressSet, AddressSetView, AddressSpace, AddressSpaceType,
};
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::listing::default_program_context::DefaultProgramContext;
use crate::program::model::mem::mem_buffer::MemBuffer;
use crate::program::model::pcode::{OpCode, Varnode};
use crate::trace::model::memory::trace_memory_state::TraceMemoryState;
use std::collections::HashMap;

fn value_location_const_space() -> &'static Arc<AddressSpace> {
    static SPACE: OnceLock<Arc<AddressSpace>> = OnceLock::new();
    SPACE.get_or_init(|| AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 0))
}

fn value_location_is_zero(vn: &Varnode) -> bool {
    vn.is_constant() && vn.get_offset() == 0
}

/// Placeholder for `ghidra.pcode.exec.ValueLocation`, referenced by
/// [`LocationPcodeArithmetic`](crate::pcode::exec::location_pcode_arithmetic::LocationPcodeArithmetic)
/// before the real class is ported. Exposes only the members that call site needs: building a
/// location for a constant, testing whether a location is itself a constant, shifting a location
/// left by whole bytes (for `INT_LEFT`), and merging two locations (for `INT_OR`).
#[derive(Debug, Clone, PartialEq)]
pub struct ValueLocation {
    nodes: Vec<Varnode>,
}

impl ValueLocation {
    fn new(nodes: Vec<Varnode>) -> Self {
        let start = nodes
            .iter()
            .position(|vn| !value_location_is_zero(vn))
            .unwrap_or(nodes.len());
        Self { nodes: nodes[start..].to_vec() }
    }

    /// Port of `ValueLocation.fromConst(long, int)`.
    pub fn from_const(value: i64, size: i32) -> Self {
        let address = value_location_const_space().address(value);
        Self::new(vec![Varnode::new(address, size)])
    }

    /// Port of `ValueLocation.size()`.
    pub fn size(&self) -> i32 {
        self.nodes.iter().map(Varnode::get_size).sum()
    }

    /// Port of `ValueLocation.isEmpty()`.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Port of `ValueLocation.getAddress()`: the address of the first (most significant) varnode,
    /// or `None` where Java returns `null` for an empty location.
    pub fn get_address(&self) -> Option<&Address> {
        self.nodes.first().map(Varnode::get_address)
    }

    /// Port of `ValueLocation.getConst()`. Returns `None` if any varnode is non-constant.
    pub fn get_const(&self) -> Option<i128> {
        let mut result: i128 = 0;
        for vn in &self.nodes {
            if !vn.is_constant() {
                return None;
            }
            result <<= vn.get_size() as u32 * 8;
            result |= vn.get_address().unsigned_offset() as i128;
        }
        Some(result)
    }

    /// Port of `ValueLocation.shiftLeft(int)`. Returns `None` if `amount` is not a whole number
    /// of bytes.
    pub fn shift_left(&self, amount: i32) -> Option<Self> {
        if amount % 8 != 0 {
            return None;
        }
        let mut nodes = self.nodes.clone();
        nodes.push(Varnode::new(value_location_const_space().address(0), amount / 8));
        Some(Self::new(nodes))
    }

    /// Port of `ValueLocation.intOr(ValueLocation)`. Returns `None` if any paired varnodes
    /// mismatch in length or neither of a pair is a constant zero.
    pub fn int_or(&self, that: &Self) -> Option<Self> {
        if self.is_empty() {
            return Some(that.clone());
        }
        if that.is_empty() {
            return Some(self.clone());
        }
        let mut result = Vec::with_capacity(self.nodes.len().max(that.nodes.len()));
        let mut ia = self.nodes.len();
        let mut ib = that.nodes.len();
        while ia > 0 && ib > 0 {
            ia -= 1;
            ib -= 1;
            let vn_a = &self.nodes[ia];
            let vn_b = &that.nodes[ib];
            if vn_a.get_size() != vn_b.get_size() {
                return None;
            }
            if value_location_is_zero(vn_a) {
                result.push(vn_b.clone());
            } else if value_location_is_zero(vn_b) {
                result.push(vn_a.clone());
            } else {
                return None;
            }
        }
        while ia > 0 {
            ia -= 1;
            result.push(self.nodes[ia].clone());
        }
        while ib > 0 {
            ib -= 1;
            result.push(that.nodes[ib].clone());
        }
        result.reverse();
        Some(Self::new(result))
    }
}

/// Placeholder for `ghidra.pcode.floatformat.FloatFormat`, referenced by
/// [`BigFloat::to_display_string_with_format`](crate::pcode::floatformat::big_float::BigFloat::to_display_string_with_format)
/// before the real class is ported. Exposes only the members that method needs: the rounding
/// context used to format a decimal string, encoding a value to its bit pattern (`BigInteger` in
/// Java, `i128` here per the crate-wide convention), and decoding a formatted decimal back into a
/// value to check whether a shortened string still round-trips.
pub trait FloatFormat {
    /// Port of `FloatFormat.getDisplayContext()`.
    fn get_display_context(&self) -> MathContext;

    /// Port of `FloatFormat.getEncoding(BigFloat)`.
    fn get_encoding(&self, value: &dyn BigFloat) -> i128;

    /// Port of `FloatFormat.getBigFloat(BigDecimal)`. Takes `f64` rather than `BigDecimal`,
    /// matching how [`BigFloat::to_big_decimal`](crate::pcode::floatformat::big_float::BigFloat::to_big_decimal)
    /// represents that Java type here.
    fn get_big_float(&self, value: f64) -> Box<dyn BigFloat>;
}

/// Placeholder for `ghidra.pcode.pcoderaw.PcodeOpRaw`, referenced by
/// [`BreakTable`](crate::pcode::emulate::break_table::BreakTable) and
/// [`BreakTableCallBack`](crate::pcode::emulate::break_table_call_back::BreakTableCallBack)
/// before the real class is ported.
///
/// Grown (see `STUBS.tsv`) with a defaulted [`get_input`](Self::get_input) -- Java's
/// `PcodeOpRaw` extends `PcodeOp`, whose `getInput(int)` `BreakTableCallBack.doPcodeOpBreak`
/// needs -- so pre-existing bare `impl PcodeOpRaw for Foo {}` blocks keep compiling.
pub trait PcodeOpRaw: Send + Sync {
    /// Stands in for the inherited `PcodeOp.getInput(int)`.
    fn get_input(&self, index: usize) -> Option<crate::program::model::pcode::Varnode> {
        let _ = index;
        None
    }
}

/// Placeholder for `ghidra.pcode.emulate.Emulate`, referenced by
/// [`OpBehaviorOther`](crate::pcode::opbehavior::OpBehaviorOther),
/// [`BreakTable`](crate::pcode::emulate::break_table::BreakTable), and
/// [`EmulateInstructionStateModifierBase`](crate::pcode::emulate::emulate_instruction_state_modifier::EmulateInstructionStateModifierBase)
/// before the real class is ported. This is a minimal interface stub exposing only the methods
/// needed by existing references.
pub trait Emulate: Send + Sync {
    /// Placeholder for `Emulate.dispose()`.
    fn dispose(&self);

    /// Placeholder for `Emulate.getLanguage()`.
    fn get_language(&self) -> Box<dyn Language>;
}

/// Placeholder for `ghidra.pcode.exec.ComposedPcodeUseropLibrary`, referenced by
/// [`PcodeUseropLibrary::compose_with_override`](crate::pcode::exec::pcode_userop_library::PcodeUseropLibrary::compose_with_override)
/// before the real class is ported. Unlike most stubs here this is a struct, not a trait: `compose`
/// must *construct* the composed library, which a trait cannot express. Its members mirror the Java
/// class exactly -- it stores only the merged map (Java's sole field), and `compose_userops` keeps
/// Java's "name collisions are an error unless `override` is set" rule -- so the real port should
/// be a drop-in replacement.
pub struct ComposedPcodeUseropLibrary<T: 'static> {
    userops: UseropMap<T>,
}

impl<T: 'static> ComposedPcodeUseropLibrary<T> {
    /// Placeholder for `new ComposedPcodeUseropLibrary(Collection, boolean)`.
    pub fn new(libraries: &[&dyn PcodeUseropLibrary<T>], override_: bool) -> Self {
        Self { userops: Self::compose_userops(libraries, override_) }
    }

    /// Construct the composed library over an already-merged map, as produced by
    /// [`compose_userops`](Self::compose_userops) or
    /// [`compose_userop_maps`](Self::compose_userop_maps).
    pub fn from_userops(userops: UseropMap<T>) -> Self {
        Self { userops }
    }

    /// Placeholder for the static `composeUserops(Collection, boolean)`: obtain a map representing
    /// the composition of userops from all the given libraries.
    ///
    /// Name collisions are not allowed. If any two libraries export the same symbol, even if the
    /// definitions happen to do the same thing, it is an error -- unless `override_` is set,
    /// allowing libraries to the right to override userops from libraries to the left.
    pub fn compose_userops(libraries: &[&dyn PcodeUseropLibrary<T>], override_: bool) -> UseropMap<T> {
        Self::compose_userop_maps(libraries.iter().map(|lib| lib.get_userops()), override_)
    }

    /// As [`compose_userops`](Self::compose_userops), but over the libraries' userop maps
    /// directly, for callers that hold the maps rather than the libraries.
    pub fn compose_userop_maps<'a>(
        maps: impl IntoIterator<Item = &'a UseropMap<T>>,
        override_: bool,
    ) -> UseropMap<T> {
        let mut userops: UseropMap<T> = HashMap::new();
        for map in maps {
            for def in map.values() {
                let existing = userops.insert(def.get_name().to_string(), Arc::clone(def));
                if existing.is_some() && !override_ {
                    panic!(
                        "Cannot compose libraries with conflicting definitions on {}",
                        def.get_name()
                    );
                }
            }
        }
        userops
    }
}

impl<T: 'static> ErasedPcodeUseropLibrary for ComposedPcodeUseropLibrary<T> {}

impl<T: 'static> PcodeUseropLibrary<T> for ComposedPcodeUseropLibrary<T> {
    fn get_userops(&self) -> &UseropMap<T> {
        &self.userops
    }
}

/// Placeholder for `ghidra.pcode.exec.FixedSleighPcodeUseropDefinition`, referenced by
/// [`Builder::build`](crate::pcode::exec::abstract_sleigh_pcode_userop_definition::Builder::build)
/// before the real class (a single-signature `AbstractSleighPcodeUseropDefinition` subclass) is
/// ported. `get_body` is implemented faithfully (it only needs `SignatureDef::generate_body`);
/// `program_for` panics if actually invoked, since compiling Sleigh source requires the
/// also-unported `SleighProgramCompiler`.
pub struct FixedSleighPcodeUseropDefinition {
    #[allow(dead_code)]
    base: AbstractSleighPcodeUseropDefinitionBase,
    definition: SignatureDef,
}

impl FixedSleighPcodeUseropDefinition {
    /// Placeholder for `new FixedSleighPcodeUseropDefinition(SleighLanguage, String, SignatureDef)`.
    pub fn new(language: Arc<SleighLanguage>, name: String, definition: SignatureDef) -> Self {
        Self {
            base: AbstractSleighPcodeUseropDefinitionBase::new(language, name),
            definition,
        }
    }
}

impl SleighPcodeUseropDefinition for FixedSleighPcodeUseropDefinition {
    fn get_body(&self, args: &[Option<Varnode>]) -> String {
        self.definition.generate_body(args)
    }

    fn program_for(
        &self,
        _args: &[Option<Varnode>],
        _library: &dyn ErasedPcodeUseropLibrary,
    ) -> PcodeProgram {
        unimplemented!(
            "FixedSleighPcodeUseropDefinition::program_for needs SleighProgramCompiler, not yet ported"
        )
    }
}

/// Placeholder for `ghidra.pcode.exec.OverloadedSleighPcodeUseropDefinition`, referenced by
/// [`Builder::build`](crate::pcode::exec::abstract_sleigh_pcode_userop_definition::Builder::build)
/// before the real class (a multi-signature `AbstractSleighPcodeUseropDefinition` subclass) is
/// ported. `get_body` is implemented faithfully (dispatching on argument count, like Java's
/// `requireSignatureDef`); `program_for` panics if actually invoked, since compiling Sleigh
/// source requires the also-unported `SleighProgramCompiler`.
pub struct OverloadedSleighPcodeUseropDefinition {
    #[allow(dead_code)]
    base: AbstractSleighPcodeUseropDefinitionBase,
    definitions: HashMap<i32, SignatureDef>,
}

impl OverloadedSleighPcodeUseropDefinition {
    /// Placeholder for `new OverloadedSleighPcodeUseropDefinition(SleighLanguage, String, Map)`.
    pub fn new(language: Arc<SleighLanguage>, name: String, definitions: HashMap<i32, SignatureDef>) -> Self {
        Self {
            base: AbstractSleighPcodeUseropDefinitionBase::new(language, name),
            definitions,
        }
    }
}

impl SleighPcodeUseropDefinition for OverloadedSleighPcodeUseropDefinition {
    fn get_body(&self, args: &[Option<Varnode>]) -> String {
        let definition = self
            .definitions
            .get(&(args.len() as i32))
            .unwrap_or_else(|| panic!("Incorrect number of arguments to userop"));
        definition.generate_body(args)
    }

    fn program_for(
        &self,
        _args: &[Option<Varnode>],
        _library: &dyn ErasedPcodeUseropLibrary,
    ) -> PcodeProgram {
        unimplemented!(
            "OverloadedSleighPcodeUseropDefinition::program_for needs SleighProgramCompiler, not yet ported"
        )
    }
}

/// Placeholder for `ghidra.app.util.PseudoInstruction`, referenced by
/// [`InstructionDecoder`](crate::pcode::emu::instruction_decoder::InstructionDecoder) before the
/// real class is ported. This is a minimal interface stub exposing only the methods needed by
/// existing references.
pub trait PseudoInstruction: Send + Sync {}

/// Placeholder for `ghidra.program.model.lang.RegisterValue`, referenced by
/// [`InstructionDecoder`](crate::pcode::emu::instruction_decoder::InstructionDecoder) before the
/// real class is ported. This is a minimal interface stub exposing only the methods needed by
/// existing references.
///
/// Grown (see `STUBS.tsv`) with the four members
/// [`DefaultPcodeThread`](crate::pcode::emu::default_pcode_thread::DefaultPcodeThread)'s context
/// handling needs. All four are defaulted so pre-existing bare `impl RegisterValue for Foo {}`
/// blocks keep compiling; the defaults panic, since the real class carries the value and mask this
/// stub does not.
pub trait RegisterValue: Send + Sync {
    /// Stands in for `RegisterValue.getRegister()`: the register this value is associated with.
    fn get_register(&self) -> RegisterRef {
        unimplemented!("RegisterValue not yet ported")
    }

    /// Stands in for `RegisterValue.assign(Register, RegisterValue)`: apply only those bits having
    /// a value in `value` to this value, yielding the combined value.
    fn assign(&self, register: &RegisterRef, value: &dyn RegisterValue) -> Box<dyn RegisterValue> {
        let _ = (register, value);
        unimplemented!("RegisterValue not yet ported")
    }

    /// Stands in for `RegisterValue.getUnsignedValueIgnoreMask()`.
    fn get_unsigned_value_ignore_mask(&self) -> u128 {
        unimplemented!("RegisterValue not yet ported")
    }

    /// Stands in for `RegisterValue.combineValues(RegisterValue)`: combine `other`'s masked bits
    /// onto this value, preferring `other` wherever both specify a bit.
    fn combine_values(&self, other: &dyn RegisterValue) -> Box<dyn RegisterValue> {
        let _ = other;
        unimplemented!("RegisterValue not yet ported")
    }
}

/// Placeholder for `ghidra.pcode.emu.SparseAddressRangeMap`, referenced by
/// [`AbstractPcodeMachineBase`](crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachineBase)
/// as its store of access breakpoints. Exposes the four members that class needs, with the same
/// observable behavior; Java's page-index optimization (ranges bucketed by
/// `address >> PAGE_BITS`, which is why a breakpoint may not span more than one page boundary) is
/// left to the real port, since it changes only lookup cost, not results.
pub struct SparseAddressRangeMap<V> {
    spaces: HashMap<Arc<AddressSpace>, Vec<(AddressRange, V)>>,
    is_empty: bool,
}

impl<V> Default for SparseAddressRangeMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> SparseAddressRangeMap<V> {
    /// Placeholder for `new SparseAddressRangeMap<>()`.
    pub fn new() -> Self {
        Self { spaces: HashMap::new(), is_empty: true }
    }

    /// Placeholder for `SparseAddressRangeMap.put(AddressRange, V)`. Java returns the created
    /// entry; no caller uses it, so this returns nothing.
    pub fn put(&mut self, range: AddressRange, value: V) {
        self.spaces
            .entry(Arc::clone(range.space()))
            .or_default()
            .push((range, value));
        self.is_empty = false;
    }

    /// Placeholder for `SparseAddressRangeMap.hasEntry(Address, Predicate<V>)`: check whether any
    /// range containing `address` has a value satisfying `predicate`.
    pub fn has_entry(&self, address: &Address, predicate: impl Fn(&V) -> bool) -> bool {
        let Some(entries) = self.spaces.get(address.space()) else {
            return false;
        };
        entries
            .iter()
            .any(|(range, value)| range.contains(address) && predicate(value))
    }

    /// Placeholder for `SparseAddressRangeMap.clear()`.
    pub fn clear(&mut self) {
        self.spaces.clear();
        self.is_empty = true;
    }

    /// Placeholder for `SparseAddressRangeMap.isEmpty()`. As in Java, this reports whether
    /// anything has been put since construction or the last [`clear`](Self::clear), not whether
    /// the map currently holds ranges.
    pub fn is_empty(&self) -> bool {
        self.is_empty
    }
}

/// Placeholder for `ghidra.pcode.exec.InterruptPcodeExecutionException`, referenced by
/// [`AbstractPcodeMachineBase`](crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachineBase)
/// before the real class is ported. Java's class extends `PcodeExecutionException` with a fixed
/// message; here it wraps one, since Rust has no exception inheritance.
#[derive(Debug)]
pub struct InterruptPcodeExecutionException {
    inner: PcodeExecutionException,
}

impl InterruptPcodeExecutionException {
    /// Placeholder for `new InterruptPcodeExecutionException(PcodeFrame, Throwable)`. Every
    /// current call site passes `(null, null)`, so only the frame is accepted here.
    pub fn new(frame: Option<PcodeFrame>) -> Self {
        const MESSAGE: &str = "Execution hit breakpoint";
        let inner = match frame {
            Some(frame) => PcodeExecutionException::with_frame(MESSAGE, frame),
            None => PcodeExecutionException::with_message(MESSAGE),
        };
        Self { inner }
    }

    /// The wrapped execution exception, Java's `super`.
    pub fn as_execution_exception(&self) -> &PcodeExecutionException {
        &self.inner
    }

    /// Placeholder for the inherited `getMessage()`.
    pub fn message(&self) -> &str {
        self.inner.message()
    }
}

/// Placeholder for `ghidra.pcode.exec.SleighProgramCompiler`, referenced by
/// [`AbstractPcodeMachineBase::compile_sleigh`](crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachineBase::compile_sleigh)
/// before the real class is ported. Only the one static that call site uses is declared; it panics
/// if invoked, since compiling Sleigh source needs the whole (unported) compiler.
pub struct SleighProgramCompiler;

impl SleighProgramCompiler {
    /// Placeholder for the static
    /// `SleighProgramCompiler.compileProgram(SleighLanguage, String, String, PcodeUseropLibrary)`.
    pub fn compile_program<T: 'static>(
        _language: &SleighLanguage,
        _source_name: &str,
        _source: &str,
        _library: &dyn PcodeUseropLibrary<T>,
    ) -> PcodeProgram {
        unimplemented!("SleighProgramCompiler not yet ported")
    }
}

/// Placeholder for `ghidra.pcode.exec.SuspendedPcodeExecutionException`, thrown by
/// [`DefaultPcodeThread`](crate::pcode::emu::default_pcode_thread::DefaultPcodeThread)'s executor
/// when a p-code op is stepped while the thread or its machine is suspended. As with
/// [`InterruptPcodeExecutionException`], Java's class extends `PcodeExecutionException` with a
/// fixed message; here it wraps one.
#[derive(Debug)]
pub struct SuspendedPcodeExecutionException {
    inner: PcodeExecutionException,
}

impl SuspendedPcodeExecutionException {
    /// Placeholder for `new SuspendedPcodeExecutionException(PcodeFrame, Throwable)`. Every current
    /// call site passes a `null` cause, so only the frame is accepted here.
    pub fn new(frame: Option<PcodeFrame>) -> Self {
        const MESSAGE: &str = "Execution suspended by user";
        let inner = match frame {
            Some(frame) => PcodeExecutionException::with_frame(MESSAGE, frame),
            None => PcodeExecutionException::with_message(MESSAGE),
        };
        Self { inner }
    }

    /// The wrapped execution exception, Java's `super`.
    pub fn as_execution_exception(&self) -> &PcodeExecutionException {
        &self.inner
    }

    /// Placeholder for the inherited `getMessage()`.
    pub fn message(&self) -> &str {
        self.inner.message()
    }
}

/// Placeholder for `ghidra.pcode.exec.InjectionErrorPcodeExecutionException`, thrown by
/// [`PcodeEmulationLibrary`](crate::pcode::emu::default_pcode_thread::PcodeEmulationLibrary)'s
/// `emu_injection_err` userop, which a service invokes in place of an inject whose Sleigh source
/// failed to compile. See [`SuspendedPcodeExecutionException`] on the wrapping.
#[derive(Debug)]
pub struct InjectionErrorPcodeExecutionException {
    inner: PcodeExecutionException,
}

impl InjectionErrorPcodeExecutionException {
    /// Placeholder for `new InjectionErrorPcodeExecutionException(PcodeFrame, Throwable)`. The one
    /// call site passes `(null, null)`, so only the frame is accepted here.
    pub fn new(frame: Option<PcodeFrame>) -> Self {
        const MESSAGE: &str = "Error compiling injected Sleigh source";
        let inner = match frame {
            Some(frame) => PcodeExecutionException::with_frame(MESSAGE, frame),
            None => PcodeExecutionException::with_message(MESSAGE),
        };
        Self { inner }
    }

    /// The wrapped execution exception, Java's `super`.
    pub fn as_execution_exception(&self) -> &PcodeExecutionException {
        &self.inner
    }

    /// Placeholder for the inherited `getMessage()`.
    pub fn message(&self) -> &str {
        self.inner.message()
    }
}

/// Placeholder for `ghidra.program.util.ProgramContextImpl`, the default-context store
/// [`DefaultPcodeThread`](crate::pcode::emu::default_pcode_thread::DefaultPcodeThread) builds from
/// its language when the language has a context register.
///
/// The one behavior this stub really implements is receiving a language's context settings, since
/// that is what the thread's constructor does with it
/// (`language.applyContextSettings(defaultContext)`). Every read-back is a value of the *other*
/// `RegisterValue` stub -- [`crate::program::seam_stubs::RegisterValue`] is what
/// [`DefaultProgramContext`] deals in, while this module's [`RegisterValue`] is what the emulator
/// deals in -- and neither stub can be constructed, so the reads panic until the real class lands.
pub struct ProgramContextImpl {
    defaults: Vec<(Box<dyn crate::program::seam_stubs::RegisterValue>, Address, Address)>,
}

impl ProgramContextImpl {
    /// Placeholder for `new ProgramContextImpl(Language)`.
    pub fn new() -> Self {
        Self { defaults: Vec::new() }
    }

    /// The context settings received so far, i.e. what `Language.applyContextSettings` recorded.
    pub fn defaults(&self) -> &[(Box<dyn crate::program::seam_stubs::RegisterValue>, Address, Address)] {
        &self.defaults
    }

    /// Placeholder for the inherited `ProgramContext.getDefaultDisassemblyContext()`.
    pub fn get_default_disassembly_context(&self) -> Box<dyn RegisterValue> {
        unimplemented!("ProgramContextImpl not yet ported")
    }

    /// Placeholder for the inherited `ProgramContext.getDefaultValue(Register, Address)`, in the
    /// emulator's `RegisterValue` domain. Java returns `null` where there is no default.
    pub fn get_default_value(
        &self,
        register: &RegisterRef,
        address: &Address,
    ) -> Option<Box<dyn RegisterValue>> {
        let _ = (register, address);
        unimplemented!("ProgramContextImpl not yet ported")
    }

    /// Placeholder for the inherited `ProgramContext.getFlowValue(RegisterValue)`: the part of the
    /// given context that flows to the next instruction.
    pub fn get_flow_value(&self, value: &dyn RegisterValue) -> Box<dyn RegisterValue> {
        let _ = value;
        unimplemented!("ProgramContextImpl not yet ported")
    }
}

impl Default for ProgramContextImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultProgramContext for ProgramContextImpl {
    fn set_default_value(
        &mut self,
        register_value: Box<dyn crate::program::seam_stubs::RegisterValue>,
        start: &Address,
        end: &Address,
    ) {
        self.defaults.push((register_value, start.clone(), end.clone()));
    }

    fn get_default_value(
        &self,
        _register: &crate::program::model::lang::register::Register,
        _address: &Address,
    ) -> Option<Box<dyn crate::program::seam_stubs::RegisterValue>> {
        unimplemented!("ProgramContextImpl not yet ported")
    }
}

/// Marker trait for `ghidra.pcode.exec.BytesPcodeExecutorStatePiece`, referenced by
/// [`AuxEmulatorPartsFactory::create_shared_state`](crate::pcode::emu::auxiliary::aux_emulator_parts_factory::AuxEmulatorPartsFactory::create_shared_state)
/// and
/// [`AuxEmulatorPartsFactory::create_local_state`](crate::pcode::emu::auxiliary::aux_emulator_parts_factory::AuxEmulatorPartsFactory::create_local_state).
/// The real port is [`crate::pcode::exec::BytesPcodeExecutorStatePiece`].
pub trait BytesPcodeExecutorStatePiece: Send + Sync {}

/// Placeholder for `ghidra.pcode.exec.BytesPcodeArithmetic`, referenced by
/// [`AbstractBytesPcodeExecutorStatePiece`](crate::pcode::exec::abstract_bytes_pcode_executor_state_piece::AbstractBytesPcodeExecutorStatePiece)'s
/// two-argument constructor solely for its static factory `forLanguage`, used to build a default
/// arithmetic from a language alone, and by
/// [`WatchValuePcodeArithmetic`](crate::pcode::exec::debugger_pcode_utils::WatchValuePcodeArithmetic)
/// for `forEndian`. No other member is referenced.
pub struct BytesPcodeArithmetic;

impl BytesPcodeArithmetic {
    /// Port of the static factory `BytesPcodeArithmetic.forLanguage(Language)`.
    pub fn for_language(_language: &Arc<dyn Language>) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
        unimplemented!("BytesPcodeArithmetic not yet ported")
    }

    /// Port of the static factory `BytesPcodeArithmetic.forEndian(boolean)`, which selects between
    /// the Java enum's `BIG_ENDIAN` and `LITTLE_ENDIAN` constants.
    pub fn for_endian(_big_endian: bool) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
        unimplemented!("BytesPcodeArithmetic not yet ported")
    }

    /// As [`for_language`](Self::for_language), for a caller that already holds the concrete
    /// `SleighLanguage` Java upcasts to `Language` at the call site (e.g. `PcodeEmulator`'s
    /// `language` field, typed `SleighLanguage` per `AbstractPcodeMachine`). See
    /// `AbstractPcodeMachine`'s module docs on why `SleighLanguage` doesn't implement `Language`
    /// here, so the two entry points can't be unified yet.
    pub fn for_sleigh_language(_language: &Arc<SleighLanguage>) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
        unimplemented!("BytesPcodeArithmetic not yet ported")
    }
}


/// Placeholder for `ghidra.pcode.exec.BytesPcodeExecutorState`, referenced by
/// `PcodeEmulator::create_shared_state`/`create_local_state` before the real class (composed of
/// per-address-space `BytesPcodeExecutorStateSpace`s, also not yet ported) is ported. Only the
/// language is retained, enough to answer `get_arithmetic`/`get_address_arithmetic` faithfully
/// once [`BytesPcodeArithmetic`] itself is ported; every operation that would need real storage
/// panics.
pub struct BytesPcodeExecutorState {
    language: Arc<SleighLanguage>,
}

impl BytesPcodeExecutorState {
    /// Placeholder for `new BytesPcodeExecutorState(SleighLanguage, PcodeStateCallbacks)`. The
    /// callbacks aren't retained: without real per-address-space storage to read or write, there
    /// is nothing to forward them to.
    pub fn new<C: PcodeStateCallbacks>(language: Arc<SleighLanguage>, _cb: C) -> Self {
        Self { language }
    }
}

impl PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> for BytesPcodeExecutorState {
    fn get_language(&self) -> Box<dyn Language> {
        unimplemented!("BytesPcodeExecutorState not yet ported")
    }

    fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
        BytesPcodeArithmetic::for_sleigh_language(&self.language)
    }

    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
        BytesPcodeArithmetic::for_sleigh_language(&self.language)
    }

    fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
        vec![]
    }

    fn set_var_abstract(
        &mut self,
        _space: &Arc<AddressSpace>,
        _offset: &Vec<u8>,
        _size: i32,
        _quantize: bool,
        _val: &Vec<u8>,
    ) {
        unimplemented!("BytesPcodeExecutorState not yet ported")
    }

    fn set_var_internal_abstract(
        &mut self,
        _space: &Arc<AddressSpace>,
        _offset: &Vec<u8>,
        _size: i32,
        _val: &Vec<u8>,
    ) {
        unimplemented!("BytesPcodeExecutorState not yet ported")
    }

    fn get_var_abstract(
        &self,
        _space: &Arc<AddressSpace>,
        _offset: &Vec<u8>,
        _size: i32,
        _quantize: bool,
        _reason: Reason,
    ) -> Vec<u8> {
        unimplemented!("BytesPcodeExecutorState not yet ported")
    }

    fn get_var_internal_abstract(
        &self,
        _space: &Arc<AddressSpace>,
        _offset: &Vec<u8>,
        _size: i32,
        _reason: Reason,
    ) -> Vec<u8> {
        unimplemented!("BytesPcodeExecutorState not yet ported")
    }

    fn get_register_values(&self) -> Vec<(RegisterRef, Vec<u8>)> {
        vec![]
    }

    fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
        unimplemented!("BytesPcodeExecutorState not yet ported")
    }

    fn clear(&mut self) {}
}

impl PcodeExecutorState<Vec<u8>> for BytesPcodeExecutorState {}

/// Placeholder for the unported Java type `PcodeTraceMemoryAccess`
/// (`ghidra.pcode.exec.trace.data.PcodeTraceMemoryAccess`), referenced by
/// [`PcodeTraceAccess`](crate::pcode::exec::trace::data::PcodeTraceAccess). Generated stub: only
/// a shape hint. Java's `PcodeTraceMemoryAccess extends PcodeTraceDataAccess` (adds no members of
/// its own), so this mirrors that as a supertrait bound. Replace with the real port when
/// available.
pub trait PcodeTraceMemoryAccess: PcodeTraceDataAccess {
    // (no public methods parsed from the Java source)
}

/// The default data-access shim, for both memory and registers.
///
/// Port of `ghidra.pcode.exec.trace.data.DefaultPcodeTraceThreadAccess`.
///
/// This is not designed for use with the emulator, but rather with stand-alone p-code executors,
/// e.g., to evaluate a Sleigh expression. It multiplexes a given memory access shim and another
/// register access shim into a single shim for use in one state piece.
pub struct DefaultPcodeTraceThreadAccess {
    memory: Box<dyn PcodeTraceMemoryAccess>,
    registers: Box<
        dyn crate::pcode::exec::trace::data::pcode_trace_registers_access::PcodeTraceRegistersAccess,
    >,
}

impl DefaultPcodeTraceThreadAccess {
    /// Construct a shim multiplexing `memory` and `registers`.
    pub fn new(
        memory: Box<dyn PcodeTraceMemoryAccess>,
        registers: Box<
            dyn crate::pcode::exec::trace::data::pcode_trace_registers_access::PcodeTraceRegistersAccess,
        >,
    ) -> Self {
        Self { memory, registers }
    }
}

impl PcodeTraceDataAccess for DefaultPcodeTraceThreadAccess {
    fn get_language(&self) -> Box<dyn Language> {
        self.memory.get_language()
    }

    fn set_state(&mut self, range: &AddressRange, state: TraceMemoryState) {
        if range.space().space_type() == AddressSpaceType::Register {
            self.registers.set_state(range, state);
        } else {
            self.memory.set_state(range, state);
        }
    }

    fn get_viewport_state(&self, range: &AddressRange) -> TraceMemoryState {
        if range.space().space_type() == AddressSpaceType::Register {
            self.registers.get_viewport_state(range)
        } else {
            self.memory.get_viewport_state(range)
        }
    }

    fn intersect_view_known(
        &self,
        view: &dyn AddressSetView,
        use_full_spans: bool,
    ) -> Box<dyn AddressSetView> {
        let mem_known = self.memory.intersect_view_known(view, use_full_spans);
        let reg_known = self.registers.intersect_view_known(view, use_full_spans);
        Box::new(mem_known.union(reg_known.as_ref()))
    }

    fn put_bytes(&mut self, start: &Address, buf: &[u8]) -> usize {
        if start.is_register_address() {
            self.registers.put_bytes(start, buf)
        } else {
            self.memory.put_bytes(start, buf)
        }
    }

    fn get_bytes(&self, start: &Address, buf: &mut [u8]) -> usize {
        if start.is_register_address() {
            self.registers.get_bytes(start, buf)
        } else {
            self.memory.get_bytes(start, buf)
        }
    }

    fn translate(&self, address: &Address) -> Address {
        if address.is_register_address() {
            self.registers.translate(address)
        } else {
            self.memory.translate(address)
        }
    }

    fn get_property_access<T>(
        &self,
        _name: &str,
    ) -> Box<dyn crate::pcode::exec::trace::data::pcode_trace_property_access::PcodeTracePropertyAccess<T>>
    where
        T: 'static,
    {
        unimplemented!("This is meant for p-code executor use")
    }
}

/// Minimal placeholder for the not-yet-ported `ghidra.pcode.emu.jit.analysis.JitTypeBehavior`,
/// referenced by [`unify`](crate::pcode::emu::jit::analysis::jit_type::unify) and
/// [`unify_least`](crate::pcode::emu::jit::analysis::jit_type::unify_least).
///
/// The real Java type is an enum of four behaviors -- `ANY`, `INTEGER`, `FLOAT`, and `COPY` --
/// each with a `type(int)` and a `resolve(JitType)`, plus the static `compare` and `forJavaType`.
/// `JitType` itself only ever reaches for `INTEGER.type(size)`, so that is the only variant and
/// the only method modeled here. Replace with the real port when `JitTypeBehavior.java` is ported.
///
/// Grown (see `STUBS.tsv`) with the `Copy` variant that [`JitPhiOp`](crate::pcode::emu::jit::op::jit_phi_op::JitPhiOp)
/// and `JitCopyOp` (not yet ported) report: no type requirement of their own, but an implication
/// that the output shares the inputs' interpretation. Unlike `Integer`/`Float`, `Copy.type(int)`
/// throws `AssertionError` in Java, since a copy has no type of its own to compute -- modeled here
/// by [`type_of`](Self::type_of) panicking for that variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitTypeBehavior {
    /// The bits are interpreted as an integer.
    Integer,
    /// The bits are interpreted as a float.
    Float,
    /// No type requirement of its own; the output shares the inputs' interpretation.
    Copy,
}

impl JitTypeBehavior {
    /// Apply this behavior to a value of the given size to determine its type.
    ///
    /// Port of `JitTypeBehavior.INTEGER.type(int)`.
    ///
    /// # Panics
    ///
    /// If `self` is [`JitTypeBehavior::Copy`], matching Java's `COPY.type(int)`.
    pub fn type_of(&self, size: i32) -> AnyJitType {
        if matches!(self, JitTypeBehavior::Copy) {
            panic!("AssertionError: JitTypeBehavior::Copy has no type");
        }
        debug_assert!(size > 0);
        match size {
            1..=4 => AnyJitType::Int(IntJitType::for_size(size)),
            5..=8 => AnyJitType::Long(LongJitType::for_size(size)),
            _ => AnyJitType::MpInt(MpIntJitType::for_size(size)),
        }
    }
}

/// Placeholder for the unported Java type `Scope`, referenced by `SubScope`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait Scope: Send + Sync {
    // (no public methods parsed from the Java source)
}

/// Minimal placeholder for the not-yet-ported `ghidra.pcode.emu.jit.gen.util.ChildScope`,
/// referenced by [`RootScope::sub`](crate::pcode::emu::jit::gen::util::root_scope::RootScope::sub).
///
/// In Java, `ChildScope` extends `RootScope` and holds a back-reference to its parent scope so
/// that closing it clears the parent's active-child marker. This stub provides only what
/// `RootScope::sub` needs today: an owned, self-contained [`SubScope`] backed by its own
/// `RootScope` that continues the parent's local-variable numbering. It does not yet wire the
/// parent-notification-on-close behavior -- that bookkeeping belongs to the real `ChildScope`.
/// Replace with the real port (including the parent link) when `ChildScope.java` is ported.
pub struct ChildScope<N> {
    inner: crate::pcode::emu::jit::gen::util::root_scope::RootScope<N>,
}

impl<N> ChildScope<N> {
    /// Wrap an already-constructed child `RootScope`.
    pub(crate) fn new(inner: crate::pcode::emu::jit::gen::util::root_scope::RootScope<N>) -> Self {
        Self { inner }
    }
}

impl<N: Send + Sync> Scope for ChildScope<N> {}

impl<N: Send + Sync + Next> crate::pcode::emu::jit::gen::util::sub_scope::SubScope for ChildScope<N> {
    fn close(&mut self) {
        self.inner.close();
    }
}

/// Placeholder for ASM's `org.objectweb.asm.Label`, wrapped by
/// [`Lbl`](crate::pcode::emu::jit::gen::util::lbl::Lbl) and visited by [`Emitter`] before the real
/// type-checked JVM bytecode emitter is ported. ASM's `Label` is an opaque, mutable marker for a
/// bytecode position; only its identity is observable outside the (also unported) `MethodVisitor`,
/// so this stub models identity alone via a monotonic id -- mirroring how
/// [`crate::pcode::emu::jit::gen::util::types`] already replaces ASM's `Type` with a plain JVM
/// descriptor string in lieu of a full ASM port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Label {
    id: u64,
}

impl Label {
    /// Port of `new Label()`. Each call yields a label distinct from every other, matching ASM's
    /// reference-identity semantics.
    pub fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        Self { id: NEXT_ID.fetch_add(1, Ordering::Relaxed) }
    }
}

impl Default for Label {
    fn default() -> Self {
        Self::new()
    }
}

/// Placeholder for ASM's `org.objectweb.asm.MethodVisitor`, the sink wrapped by
/// [`Emitter`](crate::pcode::emu::jit::gen::util::emitter::Emitter). ASM is an external library
/// with no Rust equivalent in this crate, so -- as [`Label`] models ASM's `Label` by identity
/// alone -- this models the visitor by *recording* the visits the ported code makes, which also
/// lets callers (including tests) observe generated code without a class writer. Only the visits
/// the ported package makes today are modelled; ASM's `signature`/`exceptions` arguments are
/// always `null` at those call sites and so are omitted.
#[derive(Debug, Clone, Default)]
pub struct MethodVisitor {
    code_started: bool,
    last_visited: Option<Label>,
    local_variables: Vec<(String, String, Label, Label, i32)>,
}

impl MethodVisitor {
    /// A visitor that has recorded nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stands in for `visitCode()`.
    pub fn visit_code(&mut self) {
        self.code_started = true;
    }

    /// Whether [`visit_code`](Self::visit_code) has been called.
    pub fn code_started(&self) -> bool {
        self.code_started
    }

    /// Stands in for `visitLabel(Label)`.
    pub fn visit_label(&mut self, label: Label) {
        self.last_visited = Some(label);
    }

    /// The label most recently passed to [`visit_label`](Self::visit_label), if any.
    pub fn last_visited(&self) -> Option<Label> {
        self.last_visited
    }

    /// Stands in for `visitLocalVariable(name, descriptor, signature, start, end, index)`.
    pub fn visit_local_variable(
        &mut self,
        name: &str,
        descriptor: &str,
        start: Label,
        end: Label,
        index: i32,
    ) {
        self.local_variables.push((name.to_string(), descriptor.to_string(), start, end, index));
    }

    /// Every local variable declaration recorded so far.
    pub fn local_variables(&self) -> &[(String, String, Label, Label, i32)] {
        &self.local_variables
    }
}

/// A method visited on a [`ClassVisitor`], recorded in lieu of a real class file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisitedMethod {
    /// The access flags, after the caller has forced `ACC_STATIC` on or off.
    pub access: i32,
    /// The name of the method.
    pub name: String,
    /// The JVM method descriptor.
    pub descriptor: String,
}

/// Placeholder for ASM's `org.objectweb.asm.ClassVisitor`, the class-level sink passed to
/// [`start_static`](crate::pcode::emu::jit::gen::util::emitter::start_static) and
/// [`start_instance`](crate::pcode::emu::jit::gen::util::emitter::start_instance). Like
/// [`MethodVisitor`], it records rather than writes.
#[derive(Debug, Clone, Default)]
pub struct ClassVisitor {
    methods: Vec<VisitedMethod>,
}

impl ClassVisitor {
    /// A visitor that has recorded nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stands in for `visitMethod(access, name, descriptor, signature, exceptions)`, which returns
    /// the visitor for the new method's body. The ported call sites always pass `null` for
    /// `signature` and `exceptions`.
    pub fn visit_method(&mut self, access: i32, name: &str, descriptor: &str) -> MethodVisitor {
        self.methods.push(VisitedMethod {
            access,
            name: name.to_string(),
            descriptor: descriptor.to_string(),
        });
        MethodVisitor::new()
    }

    /// Every method visited so far.
    pub fn methods(&self) -> &[VisitedMethod] {
        &self.methods
    }
}

/// Minimal placeholder for the not-yet-ported `ghidra.pcode.emu.jit.gen.util.Methods.MthDesc`, the
/// type-checked descriptor of a method, consumed by
/// [`start_static`](crate::pcode::emu::jit::gen::util::emitter::start_static) and
/// [`start_instance`](crate::pcode::emu::jit::gen::util::emitter::start_instance). Java's record
/// wraps exactly one value -- the JVM descriptor string -- and derives its type parameters (`MR`,
/// the return type; `N`, the parameter types) from the builder that produced it. This stub keeps
/// the field and the parameters, but not the builder API. Replace with the real port when
/// `Methods.java` is ported.
pub struct MthDesc<MR, N> {
    /// The JVM method descriptor, e.g. `"(I)I"`.
    pub desc: String,
    _marker: PhantomData<(MR, N)>,
}

impl<MR, N> MthDesc<MR, N> {
    /// Wrap a JVM method descriptor. The real port builds these through `MthDesc.derive(..)` so
    /// that the descriptor and the type parameters cannot disagree.
    pub fn new(desc: impl Into<String>) -> Self {
        Self { desc: desc.into(), _marker: PhantomData }
    }

    /// The JVM method descriptor. Port of the record accessor `desc()`.
    pub fn desc(&self) -> &str {
        &self.desc
    }
}

/// Minimal placeholder for the not-yet-ported `ghidra.pcode.emu.jit.gen.util.Methods.MthParam`, a
/// parameter accumulated while defining a method. Java's record is generic in the parameter's
/// machine type; a `Vec` cannot hold varying type parameters, so this projects out what the
/// declaration needs, as `RootScope` already does for its variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MthParam {
    /// The JVM descriptor of the parameter's type.
    pub descriptor: String,
    /// The name of the parameter.
    pub name: String,
}

/// Minimal placeholder for the not-yet-ported `ghidra.pcode.emu.jit.gen.util.Methods.Def`, the
/// handle to a static method under definition, returned by
/// [`start_static`](crate::pcode::emu::jit::gen::util::emitter::start_static). Java's record is
/// `Def<MR, N>(Emitter<Bot> em, List<MthParam<?>> params)`; this stub keeps the components and the
/// constructor `Emitter.start` calls, but not the `param`/`done` API. Replace with the real port
/// when `Methods.java` is ported.
pub struct Def<MR, N> {
    /// The emitter for the method body.
    pub em: Emitter<Bot>,
    /// The parameters declared so far, in reverse declaration order, as in Java.
    pub params: Vec<MthParam>,
    _marker: PhantomData<(MR, N)>,
}

impl<MR, N> Def<MR, N> {
    /// Port of the canonical record constructor `new Def<>(em, params)`.
    pub fn new(em: Emitter<Bot>, params: Vec<MthParam>) -> Self {
        Self { em, params, _marker: PhantomData }
    }
}

/// Minimal placeholder for the not-yet-ported `ghidra.pcode.emu.jit.gen.util.Methods.ObjDef`, the
/// handle to an instance method under definition, returned by
/// [`start_instance`](crate::pcode::emu::jit::gen::util::emitter::start_instance). Java's record is
/// `ObjDef<MR, OT, N>(Emitter<Bot> em, List<MthParam<?>> params)`; the `OT` (owner type) parameter
/// is dropped here because [`TRef`](crate::pcode::emu::jit::gen::util::types::TRef) is not generic
/// in this port. Replace with the real port when `Methods.java` is ported.
pub struct ObjDef<MR, N> {
    /// The emitter for the method body.
    pub em: Emitter<Bot>,
    /// The parameters declared so far, in reverse declaration order, as in Java.
    pub params: Vec<MthParam>,
    _marker: PhantomData<(MR, N)>,
}

impl<MR, N> ObjDef<MR, N> {
    /// Port of the canonical record constructor `new ObjDef<>(em, params)`.
    pub fn new(em: Emitter<Bot>, params: Vec<MthParam>) -> Self {
        Self { em, params, _marker: PhantomData }
    }
}

/// Placeholder for the unported Java type `JitVal`, referenced by `JitBinOp`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait JitVal: Send + Sync {
    fn size(&self) -> i32;
    fn add_use(&self, op: &dyn JitOp, position: i32);
    fn remove_use(&self, op: &dyn JitOp, position: i32);

    /// Whether this value is a `JitInputVar`, i.e., an input to the passage.
    ///
    /// Grown (see `STUBS.tsv`) to stand in for Java's `instanceof JitInputVar` check in
    /// `JitPhiOp.hasInputOption()`, since `JitInputVar` is not a downcast target here. Defaulted
    /// to `false` so existing `impl JitVal for Foo` blocks keep compiling; only
    /// [`JitInputVar`] overrides it.
    fn is_input_var(&self) -> bool {
        false
    }

    /// Double-dispatch hook standing in for Java's `switch (v) { case JitConstVal ... }` in
    /// `JitOpVisitor.visitVal`.
    ///
    /// Grown (see `STUBS.tsv`) for
    /// [`JitOpVisitor`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor): a
    /// sealed-interface `switch` has no Rust equivalent over a `dyn` trait, so each concrete
    /// `JitVal` overrides this to call back into its matching `JitOpVisitor::visit_*` method.
    /// Defaulted so existing `impl JitVal for Foo` blocks keep compiling; the default mirrors
    /// Java's unreachable `default -> throw new AssertionError()` arm.
    fn accept_val(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        let _ = visitor;
        panic!("AssertionError: unrecognized JitVal");
    }
}

/// Placeholder for the unported Java type `JitOutVar`, referenced by `JitDefOp`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
///
/// Grown (see `STUBS.tsv`) for `JitPhiOp`, the first real (non-test-mock) implementor: Java's
/// `setDefinition`/`definition` are nullable (`JitDefOp definition`), so `set_definition` takes
/// `Option<&dyn JitDefOp>` rather than a bare reference, and `definition()` returns
/// `Option<Arc<dyn JitDefOp>>` -- `Arc` rather than `Box` because the defining op's identity must
/// be comparable against a live `&self` elsewhere (see `JitPhiOp::unlink`'s port of
/// `out().definition() == this`), which a freshly-boxed copy could never satisfy.
pub trait JitOutVar: Send + Sync {
    fn set_definition(&self, definition: Option<&dyn JitDefOp>);
    fn definition(&self) -> Option<Arc<dyn JitDefOp>>;
    fn varnode(&self) -> Varnode;
}

/// Placeholder for the unported Java type `JitOp`, referenced by `JitBinOp`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait JitOp: Send + Sync {
    fn type_for(&self, position: i32) -> JitTypeBehavior;
    fn link(&self);
    fn unlink(&self);

    /// Double-dispatch hook standing in for Java's `switch (op) { case JitUnOp ... }` in
    /// `JitOpVisitor.visitOp`.
    ///
    /// Grown (see `STUBS.tsv`) for
    /// [`JitOpVisitor`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor): a
    /// sealed-interface `switch` has no Rust equivalent over a `dyn` trait, so each concrete
    /// `JitOp` overrides this to call back into its matching `JitOpVisitor::visit_*` method.
    /// Defaulted so existing `impl JitOp for Foo` blocks keep compiling; the default mirrors
    /// Java's unreachable `default -> throw new AssertionError(...)` arm. Leaf types under the
    /// still-interface-level `JitUnOp`/`JitBinOp` cases have no concrete implementor in this
    /// crate yet, so they too fall back to this default until one is ported.
    fn accept(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        let _ = visitor;
        panic!("AssertionError: Unrecognized op");
    }
}

/// Placeholder for the unported Java type `JitDefOp`, referenced by `JitBinOp`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
///
/// Grown (see `STUBS.tsv`): `out()` returns `Arc<dyn JitOutVar>` rather than `Box`, matching the
/// change to [`JitOutVar`] -- the output var is a shared node in the use-def graph (also reachable
/// via, e.g., the data-flow model), not a value uniquely owned by one op.
pub trait JitDefOp: JitOp {
    fn out(&self) -> Arc<dyn JitOutVar>;

    fn type_(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }
}

/// Placeholder for the unported Java type `JitUnOp`, referenced by `JitFloatUnOp`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait JitUnOp: JitDefOp {
    fn u(&self) -> Box<dyn JitVal>;

    fn u_type(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }
}

/// Placeholder for the unported Java type `JitBinOp`, referenced by `JitBoolBinOp`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait JitBinOp: JitDefOp {
    fn l(&self) -> Box<dyn JitVal>;
    fn r(&self) -> Box<dyn JitVal>;
    fn l_type(&self) -> JitTypeBehavior;
    fn r_type(&self) -> JitTypeBehavior;
}

/// Placeholder for the unported Java type `ghidra.pcode.emu.jit.analysis.JitDataFlowState.MiniDFState`,
/// referenced by [`JitCallOtherOpIf`](crate::pcode::emu::jit::op::jit_call_other_op_if::JitCallOtherOpIf).
///
/// Java's `MiniDFState` is a non-static inner class of the also-unported `JitDataFlowState`: a
/// minimal snapshot of the data-flow machine state (per-address-space maps of offset to defining
/// [`JitVal`]) captured at a `CALLOTHER` call site. Nothing in `JitCallOtherOpIf` inspects the
/// snapshot's contents -- it only stores and returns the value obtained from `captureState()` --
/// so this stub carries no fields. Replace with the real port (including `mapFor`/`getDefinitions`)
/// when `JitDataFlowState.java` is ported.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MiniDFState;

/// Placeholder for the unported Java type `JitMemoryVar`, referenced by `JitDirectMemoryVar`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait JitMemoryVar: Send + Sync {
    // (no public methods parsed from the Java source)
}

/// Placeholder for the unported Java type
/// `ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock`, referenced by
/// [`JitPhiOp`](crate::pcode::emu::jit::op::jit_phi_op::JitPhiOp). Java's class extends
/// `PcodeProgram` and carries the passage's basic-block analysis; `JitPhiOp` only stores which
/// block produced it and uses it to build a [`BlockFlow`], so this stub models reference identity
/// alone -- as [`Label`] already does for ASM's `Label`. Replace with the real port when
/// `JitControlFlowModel.java` is ported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JitBlock {
    id: u64,
}

impl JitBlock {
    /// A block distinct from every other, standing in for Java reference identity.
    pub fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        Self { id: NEXT_ID.fetch_add(1, Ordering::Relaxed) }
    }
}

impl Default for JitBlock {
    fn default() -> Self {
        Self::new()
    }
}

/// Placeholder for the unported Java type
/// `ghidra.pcode.emu.jit.analysis.JitControlFlowModel.BlockFlow`, referenced by
/// [`JitPhiOp`](crate::pcode::emu::jit::op::jit_phi_op::JitPhiOp). Java's record also carries an
/// `IntBranch` (the p-code branch op that produced the flow), not yet ported and not needed by any
/// current call site -- `JitPhiOp` only builds flows via [`BlockFlow::entry`]. Replace with the
/// real port (including `branch`) when `JitControlFlowModel.java` is ported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockFlow {
    /// The source block, or `None` for a flow entering the passage from outside.
    pub from: Option<JitBlock>,
    /// The destination block.
    pub to: JitBlock,
}

impl BlockFlow {
    /// Port of `BlockFlow.entry(JitBlock)`: a flow representing passage entry into `to`.
    pub fn entry(to: JitBlock) -> Self {
        Self { from: None, to }
    }
}

/// Placeholder for the unported Java type `ghidra.pcode.emu.jit.var.JitInputVar`, referenced by
/// [`JitPhiOp::add_input_option`](crate::pcode::emu::jit::op::jit_phi_op::JitPhiOp::add_input_option).
/// Java's class extends `AbstractJitVal` (not yet ported, so use tracking is a no-op here, matching
/// [`JitDirectMemoryVar`](crate::pcode::emu::jit::var::jit_direct_memory_var::JitDirectMemoryVar)'s
/// [`JitVal`] impl) and adds no members of its own beyond the varnode passed to its constructor.
/// [`JitVal::is_input_var`] distinguishes it from other values, standing in for Java's
/// `instanceof JitInputVar` check. Replace with the real port when `JitInputVar.java` is ported.
pub struct JitInputVar {
    varnode: Varnode,
}

impl JitInputVar {
    /// Port of `new JitInputVar(Varnode)`.
    pub fn new(varnode: Varnode) -> Self {
        Self { varnode }
    }
}

impl JitVal for JitInputVar {
    fn size(&self) -> i32 {
        self.varnode.get_size()
    }

    fn add_use(&self, _op: &dyn JitOp, _position: i32) {}

    fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}

    fn is_input_var(&self) -> bool {
        true
    }

    /// `JitInputVar` does not implement the real [`JitVar`](crate::pcode::emu::jit::var::JitVar)
    /// trait in this port (see the type-level doc), so unlike the other `JitVar`-flavored
    /// `JitVal`s this routes straight to `visit_input_var` rather than through `visit_var`.
    fn accept_val(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_input_var(self);
    }
}

/// Placeholder for the unported Java record `ghidra.pcode.emu.jit.op.JitStoreOp`, referenced by
/// [`JitOpVisitor::visit_store_op`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_store_op).
///
/// Grown (see `STUBS.tsv`) with the `offset`/`value` record components for
/// [`JitOpUpwardVisitor`](crate::pcode::emu::jit::analysis::jit_op_upward_visitor::JitOpUpwardVisitor),
/// which visits both. `link`/`unlink`/`type_for` remain unimplemented since nothing needs them yet.
pub struct JitStoreOp {
    offset: Box<dyn JitVal>,
    value: Box<dyn JitVal>,
}

impl JitStoreOp {
    /// Port of `new JitStoreOp(PcodeOp, AddressSpace, JitVal, JitVal)`, restricted to the
    /// `offset`/`value` components this crate currently needs.
    pub fn new(offset: Box<dyn JitVal>, value: Box<dyn JitVal>) -> Self {
        Self { offset, value }
    }

    /// Port of the record accessor `offset()`.
    pub fn offset(&self) -> &dyn JitVal {
        self.offset.as_ref()
    }

    /// Port of the record accessor `value()`.
    pub fn value(&self) -> &dyn JitVal {
        self.value.as_ref()
    }
}

impl JitOp for JitStoreOp {
    fn type_for(&self, _position: i32) -> JitTypeBehavior {
        unimplemented!("JitStoreOp not yet ported")
    }

    fn link(&self) {}

    fn unlink(&self) {}

    fn accept(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_store_op(self);
    }
}

/// Placeholder for the unported Java record `ghidra.pcode.emu.jit.op.JitLoadOp`, referenced by
/// [`JitOpVisitor::visit_load_op`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_load_op).
///
/// Grown (see `STUBS.tsv`) with the `offset` record component for
/// [`JitOpUpwardVisitor`](crate::pcode::emu::jit::analysis::jit_op_upward_visitor::JitOpUpwardVisitor),
/// which visits it. `link`/`unlink`/`type_for` remain unimplemented since nothing needs them yet.
pub struct JitLoadOp {
    offset: Box<dyn JitVal>,
}

impl JitLoadOp {
    /// Port of `new JitLoadOp(PcodeOp, JitOutVar, AddressSpace, JitVal)`, restricted to the
    /// `offset` component this crate currently needs.
    pub fn new(offset: Box<dyn JitVal>) -> Self {
        Self { offset }
    }

    /// Port of the record accessor `offset()`.
    pub fn offset(&self) -> &dyn JitVal {
        self.offset.as_ref()
    }
}

impl JitOp for JitLoadOp {
    fn type_for(&self, _position: i32) -> JitTypeBehavior {
        unimplemented!("JitLoadOp not yet ported")
    }

    fn link(&self) {}

    fn unlink(&self) {}

    fn accept(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_load_op(self);
    }
}

/// Placeholder for the unported Java record `ghidra.pcode.emu.jit.op.JitCallOtherOp`, referenced
/// by [`JitOpVisitor::visit_call_other_op`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_call_other_op).
///
/// Grown (see `STUBS.tsv`) with the `args` record component for
/// [`JitOpUpwardVisitor`](crate::pcode::emu::jit::analysis::jit_op_upward_visitor::JitOpUpwardVisitor),
/// which visits each argument. `link`/`unlink`/`type_for` remain unimplemented since nothing
/// needs them yet.
pub struct JitCallOtherOp {
    args: Vec<Box<dyn JitVal>>,
}

impl JitCallOtherOp {
    /// Port of `new JitCallOtherOp(PcodeOp, PcodeUseropDefinition, List, List, MiniDFState)`,
    /// restricted to the `args` component this crate currently needs.
    pub fn new(args: Vec<Box<dyn JitVal>>) -> Self {
        Self { args }
    }

    /// Port of the record accessor `args()`.
    pub fn args(&self) -> &[Box<dyn JitVal>] {
        &self.args
    }
}

impl JitOp for JitCallOtherOp {
    fn type_for(&self, _position: i32) -> JitTypeBehavior {
        unimplemented!("JitCallOtherOp not yet ported")
    }

    fn link(&self) {}

    fn unlink(&self) {}

    fn accept(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_call_other_op(self);
    }
}

/// Placeholder for the unported Java record `ghidra.pcode.emu.jit.op.JitCallOtherDefOp`,
/// referenced by [`JitOpVisitor::visit_call_other_def_op`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_call_other_def_op).
///
/// Grown (see `STUBS.tsv`) with the `args` record component for
/// [`JitOpUpwardVisitor`](crate::pcode::emu::jit::analysis::jit_op_upward_visitor::JitOpUpwardVisitor),
/// which visits each argument. `link`/`unlink`/`type_for` remain unimplemented since nothing
/// needs them yet.
pub struct JitCallOtherDefOp {
    args: Vec<Box<dyn JitVal>>,
}

impl JitCallOtherDefOp {
    /// Port of `new JitCallOtherDefOp(PcodeOp, JitOutVar, JitTypeBehavior,
    /// PcodeUseropDefinition, List, List, MiniDFState)`, restricted to the `args` component this
    /// crate currently needs.
    pub fn new(args: Vec<Box<dyn JitVal>>) -> Self {
        Self { args }
    }

    /// Port of the record accessor `args()`.
    pub fn args(&self) -> &[Box<dyn JitVal>] {
        &self.args
    }
}

impl JitOp for JitCallOtherDefOp {
    fn type_for(&self, _position: i32) -> JitTypeBehavior {
        unimplemented!("JitCallOtherDefOp not yet ported")
    }

    fn link(&self) {}

    fn unlink(&self) {}

    fn accept(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_call_other_def_op(self);
    }
}

/// Placeholder for the unported Java record `ghidra.pcode.emu.jit.op.JitCallOtherMissingOp`,
/// referenced by [`JitOpVisitor::visit_call_other_missing_op`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_call_other_missing_op).
/// No fields: nothing in this crate yet inspects a call-other-missing op's contents. Replace
/// with the real port when `JitCallOtherMissingOp.java` is ported.
pub struct JitCallOtherMissingOp;

impl JitOp for JitCallOtherMissingOp {
    fn type_for(&self, _position: i32) -> JitTypeBehavior {
        unimplemented!("JitCallOtherMissingOp not yet ported")
    }

    fn link(&self) {}

    fn unlink(&self) {}

    fn accept(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_call_other_missing_op(self);
    }
}

/// Placeholder for the unported Java record `ghidra.pcode.emu.jit.op.JitCatenateOp`, referenced
/// by [`JitOpVisitor::visit_catenate_op`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_catenate_op).
///
/// Grown (see `STUBS.tsv`) with the `parts` record component for
/// [`JitOpUpwardVisitor`](crate::pcode::emu::jit::analysis::jit_op_upward_visitor::JitOpUpwardVisitor),
/// which visits each part. `link`/`unlink`/`type_for` remain unimplemented since nothing needs
/// them yet.
pub struct JitCatenateOp {
    parts: Vec<Box<dyn JitVal>>,
}

impl JitCatenateOp {
    /// Port of `new JitCatenateOp(JitOutVar, List)`, restricted to the `parts` component this
    /// crate currently needs.
    pub fn new(parts: Vec<Box<dyn JitVal>>) -> Self {
        Self { parts }
    }

    /// Port of the record accessor `parts()`.
    pub fn parts(&self) -> &[Box<dyn JitVal>] {
        &self.parts
    }
}

impl JitOp for JitCatenateOp {
    fn type_for(&self, _position: i32) -> JitTypeBehavior {
        unimplemented!("JitCatenateOp not yet ported")
    }

    fn link(&self) {}

    fn unlink(&self) {}

    fn accept(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_catenate_op(self);
    }
}

/// Placeholder for the unported Java record `ghidra.pcode.emu.jit.op.JitSynthSubPieceOp`,
/// referenced by [`JitOpVisitor::visit_sub_piece_op`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_sub_piece_op).
///
/// Grown (see `STUBS.tsv`) with the `v` record component for
/// [`JitOpUpwardVisitor`](crate::pcode::emu::jit::analysis::jit_op_upward_visitor::JitOpUpwardVisitor),
/// which visits it. `out`/`offset`/`link`/`unlink`/`type_for` remain unimplemented since nothing
/// needs them yet.
pub struct JitSynthSubPieceOp {
    v: Box<dyn JitVal>,
}

impl JitSynthSubPieceOp {
    /// Port of `new JitSynthSubPieceOp(JitOutVar, int, JitVal)`, restricted to the `v` component
    /// this crate currently needs.
    pub fn new(v: Box<dyn JitVal>) -> Self {
        Self { v }
    }

    /// Port of the record accessor `v()`.
    pub fn v(&self) -> &dyn JitVal {
        self.v.as_ref()
    }
}

impl JitOp for JitSynthSubPieceOp {
    fn type_for(&self, _position: i32) -> JitTypeBehavior {
        unimplemented!("JitSynthSubPieceOp not yet ported")
    }

    fn link(&self) {}

    fn unlink(&self) {}

    fn accept(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_sub_piece_op(self);
    }
}

/// Placeholder for the unported Java record `ghidra.pcode.emu.jit.op.JitBranchOp`, referenced by
/// [`JitOpVisitor::visit_branch_op`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_branch_op).
/// No fields: nothing in this crate yet inspects a branch op's contents. Replace with the real
/// port when `JitBranchOp.java` is ported.
pub struct JitBranchOp;

impl JitOp for JitBranchOp {
    fn type_for(&self, _position: i32) -> JitTypeBehavior {
        unimplemented!("JitBranchOp not yet ported")
    }

    fn link(&self) {}

    fn unlink(&self) {}

    fn accept(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_branch_op(self);
    }
}

/// Placeholder for the unported Java record `ghidra.pcode.emu.jit.op.JitCBranchOp`, referenced
/// by [`JitOpVisitor::visit_c_branch_op`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_c_branch_op).
///
/// Grown (see `STUBS.tsv`) with the `cond` record component for
/// [`JitOpUpwardVisitor`](crate::pcode::emu::jit::analysis::jit_op_upward_visitor::JitOpUpwardVisitor),
/// which visits it. `op`/`branch`/`link`/`unlink`/`type_for` remain unimplemented since nothing
/// needs them yet.
pub struct JitCBranchOp {
    cond: Box<dyn JitVal>,
}

impl JitCBranchOp {
    /// Port of `new JitCBranchOp(PcodeOp, RBranch, JitVal)`, restricted to the `cond` component
    /// this crate currently needs.
    pub fn new(cond: Box<dyn JitVal>) -> Self {
        Self { cond }
    }

    /// Port of the record accessor `cond()`.
    pub fn cond(&self) -> &dyn JitVal {
        self.cond.as_ref()
    }
}

impl JitOp for JitCBranchOp {
    fn type_for(&self, _position: i32) -> JitTypeBehavior {
        unimplemented!("JitCBranchOp not yet ported")
    }

    fn link(&self) {}

    fn unlink(&self) {}

    fn accept(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_c_branch_op(self);
    }
}

/// Placeholder for the unported Java record `ghidra.pcode.emu.jit.op.JitBranchIndOp`, referenced
/// by [`JitOpVisitor::visit_branch_ind_op`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_branch_ind_op).
///
/// Grown (see `STUBS.tsv`) with the `target` record component for
/// [`JitOpUpwardVisitor`](crate::pcode::emu::jit::analysis::jit_op_upward_visitor::JitOpUpwardVisitor),
/// which visits it. `op`/`branch`/`link`/`unlink`/`type_for` remain unimplemented since nothing
/// needs them yet.
pub struct JitBranchIndOp {
    target: Box<dyn JitVal>,
}

impl JitBranchIndOp {
    /// Port of `new JitBranchIndOp(PcodeOp, JitVal, RIndBranch)`, restricted to the `target`
    /// component this crate currently needs.
    pub fn new(target: Box<dyn JitVal>) -> Self {
        Self { target }
    }

    /// Port of the record accessor `target()`.
    pub fn target(&self) -> &dyn JitVal {
        self.target.as_ref()
    }
}

impl JitOp for JitBranchIndOp {
    fn type_for(&self, _position: i32) -> JitTypeBehavior {
        unimplemented!("JitBranchIndOp not yet ported")
    }

    fn link(&self) {}

    fn unlink(&self) {}

    fn accept(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_branch_ind_op(self);
    }
}

/// Placeholder for the unported Java record `ghidra.pcode.emu.jit.op.JitUnimplementedOp`,
/// referenced by [`JitOpVisitor::visit_unimplemented_op`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_unimplemented_op).
/// No fields: nothing in this crate yet inspects an unimplemented op's contents. Replace with
/// the real port when `JitUnimplementedOp.java` is ported.
pub struct JitUnimplementedOp;

impl JitOp for JitUnimplementedOp {
    fn type_for(&self, _position: i32) -> JitTypeBehavior {
        unimplemented!("JitUnimplementedOp not yet ported")
    }

    fn link(&self) {}

    fn unlink(&self) {}

    fn accept(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_unimplemented_op(self);
    }
}

/// Placeholder for the unported Java record `ghidra.pcode.emu.jit.op.JitNopOp`, referenced by
/// [`JitOpVisitor::visit_nop_op`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_nop_op).
/// No fields: nothing in this crate yet inspects a nop op's contents. Replace with the real port
/// when `JitNopOp.java` is ported.
pub struct JitNopOp;

impl JitOp for JitNopOp {
    fn type_for(&self, _position: i32) -> JitTypeBehavior {
        unimplemented!("JitNopOp not yet ported")
    }

    fn link(&self) {}

    fn unlink(&self) {}

    fn accept(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_nop_op(self);
    }
}

/// Placeholder for the unported Java class `ghidra.pcode.emu.jit.var.JitConstVal`, referenced by
/// [`JitOpVisitor::visit_const_val`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_const_val).
/// No fields: nothing in this crate yet inspects a constant value's contents. Replace with the
/// real port (including the `BigInteger` value) when `JitConstVal.java` is ported.
pub struct JitConstVal;

impl JitVal for JitConstVal {
    fn size(&self) -> i32 {
        0
    }

    fn add_use(&self, _op: &dyn JitOp, _position: i32) {}

    fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}

    fn accept_val(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_const_val(self);
    }
}

/// Placeholder for the unported Java enum `ghidra.pcode.emu.jit.var.JitFailVal`, referenced by
/// [`JitOpVisitor::visit_fail_val`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_fail_val).
/// No fields: nothing in this crate yet inspects a fail value's contents. Replace with the real
/// port when `JitFailVal.java` is ported.
pub struct JitFailVal;

impl JitVal for JitFailVal {
    fn size(&self) -> i32 {
        0
    }

    fn add_use(&self, _op: &dyn JitOp, _position: i32) {}

    fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}

    fn accept_val(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_fail_val(self);
    }
}

/// Placeholder for the unported Java class `ghidra.pcode.emu.jit.var.JitMissingVar`, referenced
/// by [`JitOpVisitor::visit_missing_var`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_missing_var).
/// No fields: nothing in this crate yet inspects a missing var's contents (Java's
/// `generatePhi(JitDataFlowModel, JitBlock)` needs the also-unported `JitDataFlowModel`).
/// Replace with the real port when `JitMissingVar.java` is ported.
pub struct JitMissingVar;

impl JitVal for JitMissingVar {
    fn size(&self) -> i32 {
        0
    }

    fn add_use(&self, _op: &dyn JitOp, _position: i32) {}

    fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}

    fn accept_val(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        // Route through `JitVar::accept_var` (a plain method call on the concrete `Self`, not
        // through `visitor`) since `JitOpVisitor::visit_var` itself is `Self: Sized`-bounded and
        // so isn't callable on the `dyn JitOpVisitor` this method is given.
        crate::pcode::emu::jit::var::JitVar::accept_var(self, visitor);
    }
}

impl crate::pcode::emu::jit::var::JitVar for JitMissingVar {
    fn id(&self) -> i32 {
        unimplemented!("JitMissingVar not yet ported")
    }

    fn space(&self) -> Arc<AddressSpace> {
        unimplemented!("JitMissingVar not yet ported")
    }

    fn accept_var(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_missing_var(self);
    }
}

/// Placeholder for the unported Java enum `ghidra.pcode.emu.jit.var.JitIndirectMemoryVar`,
/// referenced by [`JitOpVisitor::visit_indirect_memory_var`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_indirect_memory_var).
/// Java has only the one enum constant `INSTANCE`, "used as a temporary dummy" (see that
/// visitor method's docs) -- mirrored here by [`INSTANCE`](Self::INSTANCE). No fields: nothing
/// in this crate yet inspects this type's contents. Replace with the real port when
/// `JitIndirectMemoryVar.java` is ported.
pub struct JitIndirectMemoryVar;

impl JitIndirectMemoryVar {
    /// Port of the enum constant `JitIndirectMemoryVar.INSTANCE`.
    pub const INSTANCE: JitIndirectMemoryVar = JitIndirectMemoryVar;
}

impl JitVal for JitIndirectMemoryVar {
    fn size(&self) -> i32 {
        0
    }

    fn add_use(&self, _op: &dyn JitOp, _position: i32) {}

    fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}

    fn accept_val(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        crate::pcode::emu::jit::var::JitVar::accept_var(self, visitor);
    }
}

impl crate::pcode::emu::jit::var::JitVar for JitIndirectMemoryVar {
    fn id(&self) -> i32 {
        unimplemented!("JitIndirectMemoryVar not yet ported")
    }

    fn space(&self) -> Arc<AddressSpace> {
        unimplemented!("JitIndirectMemoryVar not yet ported")
    }

    fn accept_var(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_indirect_memory_var(self);
    }
}

/// Placeholder for `ghidra.pcode.exec.trace.TraceMemoryStatePcodeArithmetic`, referenced by
/// [`WatchValuePcodeArithmetic`](crate::pcode::exec::debugger_pcode_utils::WatchValuePcodeArithmetic)
/// before the real class is ported. Java's version is an enum with a single `INSTANCE` constant,
/// so this mirrors it as a one-variant enum. Its whole body is short and endian-agnostic, so
/// unlike most stubs it carries real behavior: a rudimentary taint analysis in which any input
/// that is not [`TraceMemoryState::Known`] taints the result to
/// [`TraceMemoryState::Unknown`].
///
/// Java's `T` is `TraceMemoryState`, whose references may be `null`; as with
/// [`LocationPcodeArithmetic`](crate::pcode::exec::location_pcode_arithmetic::LocationPcodeArithmetic),
/// the Rust port uses `Option<TraceMemoryState>` for `T` to carry that nullability through the
/// generic [`PcodeArithmetic`] trait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraceMemoryStatePcodeArithmetic {
    /// The singleton instance.
    Instance,
}

impl PcodeArithmetic<Option<TraceMemoryState>> for TraceMemoryStatePcodeArithmetic {
    fn get_domain(&self) -> &'static str {
        "TraceMemoryState"
    }

    fn get_endian(&self) -> Option<Endian> {
        None
    }

    fn unary_op(
        &self,
        _opcode: OpCode,
        _sizeout: i32,
        _sizein1: i32,
        in1: &Option<TraceMemoryState>,
    ) -> Option<TraceMemoryState> {
        *in1
    }

    fn binary_op(
        &self,
        _opcode: OpCode,
        _sizeout: i32,
        _sizein1: i32,
        in1: &Option<TraceMemoryState>,
        _sizein2: i32,
        in2: &Option<TraceMemoryState>,
    ) -> Option<TraceMemoryState> {
        if *in1 == Some(TraceMemoryState::Known) && *in2 == Some(TraceMemoryState::Known) {
            Some(TraceMemoryState::Known)
        }
        else {
            Some(TraceMemoryState::Unknown)
        }
    }

    /// Shouldn't see STORE during Sleigh eval, anyway.
    fn mod_before_store(
        &self,
        _sizein_offset: i32,
        _space: &AddressSpace,
        _in_offset: &Option<TraceMemoryState>,
        _sizein_value: i32,
        in_value: &Option<TraceMemoryState>,
    ) -> Option<TraceMemoryState> {
        *in_value
    }

    fn mod_after_load(
        &self,
        _sizein_offset: i32,
        _space: &AddressSpace,
        in_offset: &Option<TraceMemoryState>,
        _sizein_value: i32,
        in_value: &Option<TraceMemoryState>,
    ) -> Option<TraceMemoryState> {
        if *in_offset == Some(TraceMemoryState::Known)
            && *in_value == Some(TraceMemoryState::Known)
        {
            Some(TraceMemoryState::Known)
        }
        else {
            Some(TraceMemoryState::Unknown)
        }
    }

    fn from_const_bytes(&self, _value: &[u8]) -> Option<TraceMemoryState> {
        Some(TraceMemoryState::Known)
    }

    fn from_const_u64(&self, _value: u64, _size: i32) -> Option<TraceMemoryState> {
        Some(TraceMemoryState::Known)
    }

    fn from_const_big_int(
        &self,
        _value: i128,
        _size: i32,
        _is_contextreg: bool,
    ) -> Option<TraceMemoryState> {
        Some(TraceMemoryState::Known)
    }

    fn to_concrete(
        &self,
        _value: &Option<TraceMemoryState>,
        purpose: Purpose,
    ) -> Result<Vec<u8>, ConcretionError> {
        Err(ConcretionError::new("Cannot make TraceMemoryState concrete", purpose))
    }

    fn size_of(&self, _value: &Option<TraceMemoryState>) -> i64 {
        panic!("Cannot get size of a TraceMemoryState")
    }
}

/// Placeholder for `ghidra.pcode.exec.AddressesReadPcodeArithmetic`, referenced by
/// [`WatchValuePcodeArithmetic`](crate::pcode::exec::debugger_pcode_utils::WatchValuePcodeArithmetic)
/// before the real class is ported. Java's version is an enum with a single `INSTANCE` constant,
/// so this mirrors it as a one-variant enum, and, its body being short and endian-agnostic, it
/// carries real behavior: it reports the union of all addresses read.
///
/// Java's `T` is the `AddressSetView` interface, whose references may be `null`. Since every value
/// this arithmetic produces is either a fresh `AddressSet` or a union of two, the Rust port uses
/// the concrete `Option<AddressSet>` rather than a trait object, again carrying nullability in the
/// `Option`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressesReadPcodeArithmetic {
    /// The singleton instance.
    Instance,
}

impl PcodeArithmetic<Option<AddressSet>> for AddressesReadPcodeArithmetic {
    fn get_domain(&self) -> &'static str {
        "AddressSetView"
    }

    fn get_endian(&self) -> Option<Endian> {
        None
    }

    fn unary_op(
        &self,
        _opcode: OpCode,
        _sizeout: i32,
        _sizein1: i32,
        in1: &Option<AddressSet>,
    ) -> Option<AddressSet> {
        in1.clone()
    }

    fn binary_op(
        &self,
        _opcode: OpCode,
        _sizeout: i32,
        _sizein1: i32,
        in1: &Option<AddressSet>,
        _sizein2: i32,
        in2: &Option<AddressSet>,
    ) -> Option<AddressSet> {
        Some(in1.as_ref()?.union(in2.as_ref()?))
    }

    fn mod_before_store(
        &self,
        _sizein_offset: i32,
        _space: &AddressSpace,
        _in_offset: &Option<AddressSet>,
        _sizein_value: i32,
        in_value: &Option<AddressSet>,
    ) -> Option<AddressSet> {
        in_value.clone()
    }

    fn mod_after_load(
        &self,
        _sizein_address: i32,
        _space: &AddressSpace,
        in_offset: &Option<AddressSet>,
        _sizein_value: i32,
        in_value: &Option<AddressSet>,
    ) -> Option<AddressSet> {
        Some(in_value.as_ref()?.union(in_offset.as_ref()?))
    }

    fn from_const_bytes(&self, _value: &[u8]) -> Option<AddressSet> {
        Some(AddressSet::new())
    }

    fn from_const_u64(&self, _value: u64, _size: i32) -> Option<AddressSet> {
        Some(AddressSet::new())
    }

    fn from_const_big_int(
        &self,
        _value: i128,
        _size: i32,
        _is_contextreg: bool,
    ) -> Option<AddressSet> {
        Some(AddressSet::new())
    }

    fn to_concrete(
        &self,
        _value: &Option<AddressSet>,
        purpose: Purpose,
    ) -> Result<Vec<u8>, ConcretionError> {
        Err(ConcretionError::new("Cannot make 'addresses read' concrete", purpose))
    }

    fn size_of(&self, _value: &Option<AddressSet>) -> i64 {
        unimplemented!("Cannot get size of an 'addresses read' set")
    }
}

/// Placeholder for the unported Java type `JitCodeGenerator`, referenced by `InstanceFieldReq`.
/// Generated stub: only a shape hint. This type is passed through to implementors of
/// `InstanceFieldReq` without calling its methods in the type itself, so no methods are exposed.
/// Replace with the real port when available.
pub trait JitCodeGenerator: Send + Sync {
    /// Request the field backing the direct-array block for the given space, starting at the
    /// given block offset.
    ///
    /// Port of `JitCodeGenerator.requestFieldForArrDirect(Address)`, referenced by
    /// [`IntAccessGen`](crate::pcode::emu::jit::gen::access::int_access_gen::IntAccessGen).
    /// Java passes an `Address`; that requires an owning `Arc<AddressSpace>` this trait's callers
    /// do not have, so this stub takes the `(space, offset)` pair an `Address` wraps instead.
    /// Defaulted (rather than required) so the existing marker implementors of this trait, which
    /// predate this method, keep compiling.
    fn request_field_for_arr_direct(
        &self,
        space: &crate::program::model::address::AddressSpace,
        offset: i64,
    ) -> FieldForArrDirect {
        let _ = space;
        unimplemented!("JitCodeGenerator::request_field_for_arr_direct stub: offset {offset}")
    }

    /// Get the context of the current analysis.
    ///
    /// Port of `JitCodeGenerator.getAnalysisContext()`, referenced by
    /// [`MemoryVarGen`](crate::pcode::emu::jit::gen::var::memory_var_gen::MemoryVarGen). Defaulted
    /// (rather than required) so the existing marker implementors of this trait, which predate
    /// this method, keep compiling.
    fn get_analysis_context(&self) -> JitAnalysisContext {
        unimplemented!("JitCodeGenerator::get_analysis_context stub")
    }
}

/// Placeholder for the unported Java type `JitAnalysisContext`
/// (`ghidra.pcode.emu.jit.analysis.JitAnalysisContext`), referenced by
/// [`JitCodeGenerator::get_analysis_context`]. Java's class also carries the data-flow, type, and
/// scope models built during passage analysis; only the one member downstream code currently
/// needs -- the target's endianness -- is modeled here.
#[derive(Debug, Clone, Copy)]
pub struct JitAnalysisContext {
    endian: Endian,
}

impl JitAnalysisContext {
    /// Construct a context for the given endianness.
    pub fn new(endian: Endian) -> Self {
        Self { endian }
    }

    /// Port of `JitAnalysisContext.getEndian()`.
    pub fn get_endian(&self) -> Endian {
        self.endian
    }
}

/// Placeholder for the unported Java type `JitDataFlowArithmetic`
/// (`ghidra.pcode.emu.jit.analysis.JitDataFlowArithmetic`), referenced by
/// [`MemoryVarGen`](crate::pcode::emu::jit::gen::var::memory_var_gen::MemoryVarGen). Only the one
/// static member downstream code needs -- computing the varnode for a byte-aligned subpiece -- is
/// modeled; the rest of the class (a `PcodeArithmetic<JitVal>` implementation) is unported.
pub struct JitDataFlowArithmetic;

impl JitDataFlowArithmetic {
    /// Port of the static `JitDataFlowArithmetic.subPieceVn(Endian, Varnode, int, int)`.
    ///
    /// # Panics
    ///
    /// If `offset` and `size` would leave a non-positive size, mirroring Java's `AssertionError`.
    pub fn sub_piece_vn(endian: Endian, whole: &Varnode, offset: i32, size: i32) -> Varnode {
        let min_size = (whole.get_size() - offset).min(size);
        assert!(min_size >= 1, "AssertionError: subpiece would have non-positive size");
        let addr_offset = match endian {
            Endian::Big => whole.get_size() - offset - min_size,
            Endian::Little => offset,
        };
        Varnode::new(
            whole.get_address().add(addr_offset as i64).expect("address overflow"),
            min_size,
        )
    }
}

/// Placeholder for the unported Java record `ghidra.pcode.emu.jit.gen.FieldForArrDirect`,
/// referenced by
/// [`IntAccessGen`](crate::pcode::emu::jit::gen::access::int_access_gen::IntAccessGen). Real
/// `genLoad` bytecode emission depends on `Op`/`Methods`
/// (`ghidra.pcode.emu.jit.gen.util.Op`/`Methods`), unported namespace interfaces of JVM opcode
/// helpers, so this stub only records the block offset it was requested for and performs no real
/// bytecode emission. Replace with the real port when available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldForArrDirect {
    /// The offset, within its space, of the block this field backs.
    pub offset: i64,
}

impl FieldForArrDirect {
    /// Emit code to load this field's array reference onto the stack.
    ///
    /// Port of `FieldForArrDirect.genLoad(Emitter, Local, JitCodeGenerator)`. A stub: pushes no
    /// real value, since the opcode it would emit (`Op::getfield`) is not yet ported.
    pub fn gen_load<N: Next>(
        &self,
        em: Emitter<N>,
        _local_this: &Local<crate::pcode::emu::jit::gen::util::types::TRef>,
        _gen: &dyn JitCodeGenerator,
    ) -> Emitter<Ent<N, crate::pcode::emu::jit::gen::util::types::TRef>> {
        em.recast()
    }
}

/// Placeholder for the unported Java type `JitCompiledPassage`, referenced by `InstanceFieldReq`.
/// Generated stub: only a shape hint. This type is used as a bound on the generic type parameter
/// in methods of `InstanceFieldReq` without calling its methods in the type itself, so no methods
/// are exposed. Replace with the real port when available.
pub trait JitCompiledPassage: Send + Sync {}

/// Placeholder for the unported Java enum `ghidra.pcode.emu.jit.gen.access.FloatAccessGen`,
/// referenced by
/// [`AccessGen::lookup`/`AccessGen::lookup_simple`](crate::pcode::emu::jit::gen::access::access_gen).
/// Mirrors the shape of the already-ported
/// [`IntAccessGen`](crate::pcode::emu::jit::gen::access::int_access_gen::IntAccessGen) (BE/LE
/// constants only); its real `genReadToStack`/`genWriteFromStack` bodies belong to its own port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatAccessGen {
    /// The big-endian instance. Port of the `FloatAccessGen.BE` constant.
    Be,
    /// The little-endian instance. Port of the `FloatAccessGen.LE` constant.
    Le,
}

/// Placeholder for the unported Java enum `ghidra.pcode.emu.jit.gen.access.DoubleAccessGen`; see
/// [`FloatAccessGen`] docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoubleAccessGen {
    /// The big-endian instance. Port of the `DoubleAccessGen.BE` constant.
    Be,
    /// The little-endian instance. Port of the `DoubleAccessGen.LE` constant.
    Le,
}

/// Placeholder for the unported Java enum `ghidra.pcode.emu.jit.gen.access.MpIntAccessGen`; see
/// [`FloatAccessGen`] docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpIntAccessGen {
    /// The big-endian instance. Port of the `MpIntAccessGen.BE` constant.
    Be,
    /// The little-endian instance. Port of the `MpIntAccessGen.LE` constant.
    Le,
}

/// Placeholder for the unported Java type `Opnd<T>`, referenced by
/// [`MpAccessGen`](crate::pcode::emu::jit::gen::access::mp_access_gen::MpAccessGen). Generated
/// stub: only a shape hint. `MpAccessGen` only passes an `Opnd<MpIntJitType>` through
/// (`genWriteFromOpnd`), so no methods are exposed yet. Replace with the real port -- `type()`,
/// `name()`, and `legsLE()` -- when available.
pub trait Opnd<T>: Send + Sync {}

/// Placeholder for the unported Java nested record `Opnd.OpndEm<T, N>`: an operand paired with the
/// emitter after reading it. Mirrors the already-ported
/// [`SimpleOpndEm`](crate::pcode::emu::jit::gen::opnd::SimpleOpndEm), but keeps the operand boxed
/// since [`Opnd`] is known only as a trait object until the real port narrows it.
pub struct OpndEm<T, N> {
    /// The operand.
    pub opnd: Box<dyn Opnd<T>>,
    /// The emitter after writing the operand's read.
    pub em: Emitter<N>,
}

impl<T, N> OpndEm<T, N> {
    /// Port of the canonical record constructor `new OpndEm<>(opnd, em)`.
    pub fn new(opnd: Box<dyn Opnd<T>>, em: Emitter<N>) -> Self {
        Self { opnd, em }
    }
}

/// Placeholder for the unported Java nested enum `Opnd.Ext`: the kind of extension to apply when
/// converting between operand types.
///
/// Port of `ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ext {
    /// Zero extension.
    Zero,
    /// Sign extension.
    Sign,
}

impl Ext {
    /// Port of `Ext.forSigned(boolean)`.
    pub fn for_signed(signed: bool) -> Self {
        if signed { Ext::Sign } else { Ext::Zero }
    }
}

/// A stand-in operand returned by [`MpIntAccessGen`]'s stub [`MpAccessGen`] impl. Carries no
/// state, since the real bytecode-generation logic (and thus any real operand data) is not yet
/// ported.
#[derive(Debug, Clone, Copy)]
pub struct StubMpOpnd;

impl Opnd<MpIntJitType> for StubMpOpnd {}

/// Minimal stub implementation of [`MpAccessGen`] for the placeholder [`MpIntAccessGen`], in the
/// same spirit as [`FieldForArrDirect::gen_load`]: it preserves the type-level stack-shape
/// plumbing but performs no real bytecode emission, since that depends on `Op`/`Methods`, which
/// are not yet ported. Referenced by
/// [`MemoryVarGen`](crate::pcode::emu::jit::gen::var::memory_var_gen::MemoryVarGen).
impl MpAccessGen for MpIntAccessGen {
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
        OpndEm::new(Box::new(StubMpOpnd), em)
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

/// Placeholder for the unported Java type `VarGen` (`ghidra.pcode.emu.jit.gen.var.VarGen`),
/// referenced by [`MemoryVarGen`](crate::pcode::emu::jit::gen::var::memory_var_gen::MemoryVarGen)
/// and [`DirectMemoryVarGen`](crate::pcode::emu::jit::gen::var::direct_memory_var_gen::DirectMemoryVarGen)
/// to break the dependency cycle that file sits on (`MemoryVarGen` is a forward reference from
/// `VarGen`'s own package).
///
/// Generated stub: covers the six methods `MemoryVarGen`'s defaults implement (Java's `ValGen<V>`
/// abstract methods, inherited unchanged by `VarGen<V> extends ValGen<V>`), plus the three
/// `genWriteFromStack`/`genWriteFromOpnd`/`genWriteFromArray` methods `VarGen<V>` itself declares
/// abstract, which `DirectMemoryVarGen` overrides with panicking defaults. Java's `ValGen` also
/// declares `subpiece`; neither `MemoryVarGen` nor `DirectMemoryVarGen` calls or overrides it, so
/// it remains omitted per the "only the methods this type needs" stubbing rule -- a concrete
/// implementor ported later (e.g. `WholeDirectMemoryVarGen`) will need to grow this stub with it.
///
/// Java's `<THIS extends JitCompiledPassage>` type parameter, repeated on every method, is
/// dropped in favor of a non-generic `Local<TRef>` and `&dyn JitCodeGenerator`, matching the
/// convention set by [`MpAccessGen`].
pub trait VarGen<V: JitVar>: Send + Sync {
    /// Port of the inherited `ValGen.genValInit`.
    fn gen_val_init<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
    ) -> Emitter<N>;

    /// Port of the inherited `ValGen.genReadToStack`.
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
        JT: crate::pcode::emu::jit::analysis::jit_type::SimpleJitType,
        N: Next;

    /// Port of the inherited `ValGen.genReadToOpnd`.
    fn gen_read_to_opnd<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
    ) -> OpndEm<MpIntJitType, N>;

    /// Port of the inherited `ValGen.genReadLegToStack`.
    fn gen_read_leg_to_stack<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: MpIntJitType,
        leg: i32,
        ext: Ext,
    ) -> Emitter<Ent<N, TInt>>;

    /// Port of the inherited `ValGen.genReadToArray`.
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
    ) -> Emitter<Ent<N, TRef>>;

    /// Port of the inherited `ValGen.genReadToBool`.
    fn gen_read_to_bool<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
    ) -> Emitter<Ent<N, TInt>>;

    /// Port of `VarGen.genWriteFromStack`.
    fn gen_write_from_stack<JT, N1>(
        &self,
        em: Emitter<Ent<N1, JT::B>>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: JT,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N1>
    where
        JT: crate::pcode::emu::jit::analysis::jit_type::SimpleJitType,
        N1: Next;

    /// Port of `VarGen.genWriteFromOpnd`.
    fn gen_write_from_opnd<N: Next>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        opnd: &dyn Opnd<MpIntJitType>,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N>;

    /// Port of `VarGen.genWriteFromArray`.
    fn gen_write_from_array<N1: Next>(
        &self,
        em: Emitter<Ent<N1, TRef>>,
        local_this: &Local<TRef>,
        gen: &dyn JitCodeGenerator,
        v: &V,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N1>;
}

