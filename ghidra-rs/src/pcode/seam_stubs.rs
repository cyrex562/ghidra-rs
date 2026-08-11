//! Minimal placeholder types for core types that a ported interface under [`crate::pcode`]
//! references before the real Rust port of that type exists yet. Each stub exposes only the
//! members needed by the interface(s) that currently reference it, and is expected to be
//! replaced (or grown into a supertrait/struct of) the real port once that Java class is ported.
//! See `STUBS.tsv` for provenance.

use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
use crate::pcode::exec::abstract_sleigh_pcode_userop_definition::AbstractSleighPcodeUseropDefinitionBase;
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
    Address, AddressRange, AddressSetView, AddressSpace, AddressSpaceType,
};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::listing::default_program_context::DefaultProgramContext;
use crate::program::model::mem::mem_buffer::MemBuffer;
use crate::program::model::pcode::Varnode;
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
/// arithmetic from a language alone. No other member is referenced.
pub struct BytesPcodeArithmetic;

impl BytesPcodeArithmetic {
    /// Port of the static factory `BytesPcodeArithmetic.forLanguage(Language)`.
    pub fn for_language(_language: &Arc<dyn Language>) -> Arc<dyn PcodeArithmetic<Vec<u8>>> {
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

/// Placeholder for the unported Java type `Scope`, referenced by `SubScope`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait Scope: Send + Sync {
    // (no public methods parsed from the Java source)
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

/// Placeholder for `ghidra.pcode.emu.jit.gen.util.Emitter.Next`, referenced as the bound on
/// [`Lbl`](crate::pcode::emu::jit::gen::util::lbl::Lbl)'s stack-shape type parameter before the
/// real `Emitter` (and its `Ent`/`Bot` stack-content encoding) is ported. Marker only, as in Java.
pub trait Next {}

/// Placeholder for `ghidra.pcode.emu.jit.gen.util.Emitter.Dead`, the phantom stack-shape marking
/// an [`Emitter`] as unreachable. Java documents this interface as having no implementation --
/// i.e. no instance of it is ever constructed -- so an uninhabited enum is the faithful Rust
/// equivalent.
pub enum Dead {}

/// Placeholder for `ghidra.pcode.emu.jit.gen.util.Emitter`, referenced by
/// [`Lbl`](crate::pcode::emu::jit::gen::util::lbl::Lbl) and [`Local`](crate::pcode::emu::jit::gen::util::local::Local)
/// before the real type-checked JVM bytecode emitter (and its wrapped ASM `MethodVisitor`) is ported.
/// Java's class is unbounded in its stack type parameter `N` (only individual operations, like those in
/// the not-yet-ported `Op`, bound it via `Ent`/`Bot`), so this stub carries `N` as a plain phantom marker too.
///
/// Exposes operations for visiting labels (standing in for `this.mv.visitLabel(label)`) and declaring
/// local variables (standing in for `this.mv.visitLocalVariable(...)`), plus [`recast`](Self::recast),
/// standing in for the unchecked `(Emitter) em` cast `Lbl.placeDead` uses to resurrect a dead
/// emitter. Records the last-visited label and local variable declarations so callers (including tests)
/// can observe them without a real `MethodVisitor`.
#[derive(Clone)]
pub struct Emitter<N> {
    last_visited: Option<Label>,
    local_variables: Vec<(String, String, Label, Label, i32)>,
    _marker: PhantomData<N>,
}

impl<N> Emitter<N> {
    /// Placeholder for `new Emitter(MethodVisitor)`, without a real `MethodVisitor` to wrap.
    pub fn new() -> Self {
        Self {
            last_visited: None,
            local_variables: Vec::new(),
            _marker: PhantomData,
        }
    }

    /// Stands in for `this.mv.visitLabel(label)`.
    pub fn visit_label(&mut self, label: &Label) {
        self.last_visited = Some(*label);
    }

    /// The label most recently passed to [`visit_label`](Self::visit_label), if any.
    pub fn last_visited(&self) -> Option<Label> {
        self.last_visited
    }

    /// Stands in for `this.mv.visitLocalVariable(name, descriptor, signature, start, end, index)`.
    /// Records the local variable declaration for testing and observation without a real `MethodVisitor`.
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

    /// Retrieve all recorded local variable declarations.
    pub fn local_variables(&self) -> &[(String, String, Label, Label, i32)] {
        &self.local_variables
    }

    /// Stands in for the unchecked cast `(Emitter) em` in `Lbl.placeDead`, which reinterprets an
    /// `Emitter<Dead>` as an `Emitter<M>` once a label makes the code that follows reachable
    /// again. Carries over every real (non-phantom) field, so this stays correct as `Emitter`
    /// grows toward the real port.
    pub fn recast<M>(self) -> Emitter<M> {
        Emitter {
            last_visited: self.last_visited,
            local_variables: self.local_variables,
            _marker: PhantomData,
        }
    }
}

impl<N> Default for Emitter<N> {
    fn default() -> Self {
        Self::new()
    }
}

