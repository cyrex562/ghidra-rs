//! Minimal placeholder types for core types that a ported interface under [`crate::pcode`]
//! references before the real Rust port of that type exists yet. Each stub exposes only the
//! members needed by the interface(s) that currently reference it, and is expected to be
//! replaced (or grown into a supertrait/struct of) the real port once that Java class is ported.
//! See `STUBS.tsv` for provenance.

use std::collections::HashSet;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::pcode::emu::jit::alloc::jvm_local::JvmLocal;
use crate::pcode::emu::jit::alloc::var_handler::VarHandler;
use crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic::JitDataFlowArithmetic;
use crate::pcode::emu::jit::analysis::jit_data_flow_block_analyzer::JitDataFlowBlockAnalyzer;
use crate::pcode::emu::jit::analysis::jit_type::{
    AnyJitType, AnySimpleJitType, IntJitType, JitType, LongJitType, MpIntJitType, SimpleJitType,
};
use crate::pcode::emu::jit::analysis::jit_var_scope_model::JitVarScopeModel;
use crate::pcode::emu::jit::gen::access::mp_access_gen::MpAccessGen;
use crate::pcode::emu::jit::gen::util::emitter::{Bot, Ent, Emitter, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{BPrim, TInt, TRef};
use crate::pcode::emu::jit::op::{JitOp, JitPhiOp};
use crate::pcode::emu::jit::var::{JitVal, JitVarnodeVar};
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
use crate::program::model::pcode::{OpCode, PcodeOp, Varnode};
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
///
/// Grown (see `STUBS.tsv`) with the [`JitVal`] supertrait for
/// [`JitDataFlowArithmetic`](crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic::JitDataFlowArithmetic),
/// which returns generated output variables where a `JitVal` is expected (e.g.
/// `dfm.notifyOp(..).out()` as the result of an arithmetic op). This matches Java, where
/// `JitOutVar extends JitVarnodeVar extends JitVar extends JitVal`; only the `JitVal` link is
/// modeled here, since no call site yet needs an out var's `id()`/`space()`.
pub trait JitOutVar: JitVal {
    fn set_definition(&self, definition: Option<&dyn JitDefOp>);
    fn definition(&self) -> Option<Arc<dyn JitDefOp>>;
    fn varnode(&self) -> Varnode;

    /// The retaining form of [`Self::set_definition`].
    ///
    /// Grown (see `STUBS.tsv`) for
    /// [`JitDataFlowArithmetic`](crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic::JitDataFlowArithmetic),
    /// which builds op nodes whose outputs must later report them back through
    /// [`Self::definition`]. Java does this wiring in `AbstractJitDefOp.link()`, as
    /// `out.setDefinition(this)`; `link(&self)` here cannot produce the `Arc<Self>` an out var
    /// has to keep, so the shared handle is passed in explicitly at the construction site (see
    /// [`JitDataFlowModel::notify_def_op`]). Defaults to a no-op so existing `impl JitOutVar`
    /// blocks -- which model no definition storage at all -- keep compiling.
    fn set_definition_arc(&self, definition: Option<Arc<dyn JitDefOp>>) {
        let _ = definition;
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

    /// Stand-in for Java's `definition instanceof JitSynthSubPieceOp subsub` in
    /// `JitDataFlowArithmetic.trySimplifiedSubPiece`.
    ///
    /// Grown (see `STUBS.tsv`): `dyn JitDefOp` carries no downcast facility, so -- as
    /// [`JitVal::is_input_var`] already does for `instanceof JitInputVar` -- the check is modeled
    /// as a defaulted query that only the matching type overrides.
    fn as_synth_sub_piece_op(&self) -> Option<&JitSynthSubPieceOp> {
        None
    }

    /// Stand-in for Java's `definition instanceof JitCatenateOp cat` in
    /// `JitDataFlowArithmetic.trySimplifiedSubPiece`. See [`Self::as_synth_sub_piece_op`].
    fn as_catenate_op(&self) -> Option<&JitCatenateOp> {
        None
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

/// Placeholder for the unported Java type `OpGen`, referenced by
/// [`BinOpGen`](crate::pcode::emu::jit::gen::op::bin_op_gen::BinOpGen).
/// Generated stub: only a shape hint. Java's `OpGen<T extends JitOp>` also declares an abstract
/// `genRun` and a static `lookup`, but `BinOpGen`'s default methods call neither, so this is a
/// marker bound only. Replace with the real port (including `lookup`/`genRun`) when available.
pub trait OpGen<T: JitOp>: Send + Sync {}

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

/// Placeholder for the unported Java type `ghidra.pcode.emu.jit.analysis.JitControlFlowModel`,
/// referenced by
/// [`JitVarScopeModel`](crate::pcode::emu::jit::analysis::jit_var_scope_model::JitVarScopeModel),
/// which is constructed from one and walks its blocks and their flows. Java's class performs the
/// whole basic-block analysis of a passage -- splitting the op sequence into [`JitBlock`]s and
/// wiring them with `IntBranch`es -- which is far beyond a stub; this models only the *result*:
/// the block list and the flow graph over it, which is all the scope analysis reads.
///
/// The `flowsFrom`/`flowsTo` accessors live here rather than on [`JitBlock`] (where Java puts
/// them) because this crate's `JitBlock` is deliberately identity-only -- see that type's doc.
/// Java keys both maps by the `IntBranch` producing the flow; nothing here looks up a flow by its
/// branch, so these are plain lists (Java's call sites take `.values()`).
///
/// Note [`JitDataFlowModel::flows_to`] carries the same "inward flows of a block" question for
/// [`JitDataFlowBlockAnalyzer`], which has no control-flow model to ask. Both are stand-ins for
/// the one real `JitBlock.flowsTo()` and collapse into it when `JitControlFlowModel.java` is
/// ported.
#[derive(Default)]
pub struct JitControlFlowModel {
    blocks: Vec<JitBlock>,
    flows_from: HashMap<JitBlock, Vec<BlockFlow>>,
    flows_to: HashMap<JitBlock, Vec<BlockFlow>>,
    language: Option<Arc<dyn Language>>,
}

impl JitControlFlowModel {
    /// Build a model over the given blocks, deriving each block's inward and outward flow lists
    /// from `flows`. Stands in for Java's constructor, which computes both from the passage.
    pub fn new(blocks: Vec<JitBlock>, flows: impl IntoIterator<Item = BlockFlow>) -> Self {
        let mut flows_from: HashMap<JitBlock, Vec<BlockFlow>> = HashMap::new();
        let mut flows_to: HashMap<JitBlock, Vec<BlockFlow>> = HashMap::new();
        for flow in flows {
            if let Some(from) = flow.from {
                flows_from.entry(from).or_default().push(flow);
            }
            flows_to.entry(flow.to).or_default().push(flow);
        }
        Self { blocks, flows_from, flows_to, language: None }
    }

    /// Attach the passage's language, used only by
    /// [`JitVarScopeModel::dump_result`](crate::pcode::emu::jit::analysis::jit_var_scope_model::JitVarScopeModel::dump_result)
    /// to name live varnodes. See [`Self::get_register_name`].
    pub fn with_language(mut self, language: Arc<dyn Language>) -> Self {
        self.language = Some(language);
        self
    }

    /// Port of `JitControlFlowModel.getBlocks()`.
    pub fn get_blocks(&self) -> &[JitBlock] {
        &self.blocks
    }

    /// Stand-in for `JitBlock.flowsFrom()`: the flows leaving `block`. See the type-level doc.
    pub fn flows_from(&self, block: JitBlock) -> &[BlockFlow] {
        self.flows_from.get(&block).map_or(&[], Vec::as_slice)
    }

    /// Stand-in for `JitBlock.flowsTo()`: the flows entering `block`. See the type-level doc.
    pub fn flows_to(&self, block: JitBlock) -> &[BlockFlow] {
        self.flows_to.get(&block).map_or(&[], Vec::as_slice)
    }

    /// Stand-in for `block.getLanguage().getRegister(address, size).getName()`, the only use any
    /// call site makes of a block's language. Returns `None` when no language is attached or no
    /// register covers exactly that location, matching Java's null return.
    pub fn get_register_name(&self, block: JitBlock, address: &Address, size: i32) -> Option<String> {
        let _ = block; // Java reads the language off the block; every block shares the passage's.
        let language = self.language.as_ref()?;
        let register = language.get_register_at(address, size)?;
        let name = register.borrow().name().to_owned();
        Some(name)
    }
}

/// Placeholder for the unported Java type `ghidra.pcode.emu.jit.var.JitInputVar`, referenced by
/// [`JitPhiOp::add_input_option`](crate::pcode::emu::jit::op::jit_phi_op::JitPhiOp::add_input_option).
/// Java's class extends `AbstractJitVal` (not yet ported, so use tracking is a no-op here, matching
/// [`JitDirectMemoryVar`](crate::pcode::emu::jit::var::jit_direct_memory_var::JitDirectMemoryVar)'s
/// [`JitVal`] impl) and adds no members of its own beyond the varnode passed to its constructor.
/// [`JitVal::is_input_var`] distinguishes it from other values, standing in for Java's
/// `instanceof JitInputVar` check. Replace with the real port when `JitInputVar.java` is ported.
///
/// Grown (see `STUBS.tsv`) with [`JitVar`](crate::pcode::emu::jit::var::JitVar) and
/// [`JitVarnodeVar`](crate::pcode::emu::jit::var::JitVarnodeVar) impls for
/// [`InputVarGen`](crate::pcode::emu::jit::gen::var::input_var_gen::InputVarGen), whose Java
/// counterpart binds `LocalVarGen<JitInputVar>` and so requires `JitInputVar: JitVarnodeVar`.
/// This matches the real `JitInputVar extends AbstractJitVarnodeVar`, whose constructor passes a
/// fixed `id` of `-1` (see `AbstractJitVarnodeVar`'s module docs) and derives `space()` from the
/// varnode's address.
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

    fn as_varnode_var(&self) -> Option<&dyn crate::pcode::emu::jit::var::JitVarnodeVar> {
        Some(self)
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

impl crate::pcode::emu::jit::var::JitVar for JitInputVar {
    /// Port of `AbstractJitVarnodeVar`'s fixed `id` of `-1` passed by `JitInputVar`'s constructor.
    fn id(&self) -> i32 {
        -1
    }

    /// Port of `AbstractJitVarnodeVar.space()`.
    fn space(&self) -> Arc<AddressSpace> {
        Arc::clone(self.varnode.get_address().space())
    }
}

impl crate::pcode::emu::jit::var::JitVarnodeVar for JitInputVar {
    /// Port of `AbstractJitVarnodeVar.varnode()`.
    fn varnode(&self) -> Varnode {
        self.varnode.clone()
    }
}

/// Placeholder for the unported Java type `ghidra.pcode.emu.jit.var.JitLocalOutVar`, referenced by
/// [`LocalOutVarGen`](crate::pcode::emu::jit::gen::var::local_out_var_gen::LocalOutVarGen). Java's
/// class extends `AbstractJitOutVar extends AbstractJitVarnodeVar`, so, like [`JitInputVar`], use
/// tracking is a no-op here. Unlike `JitInputVar`'s fixed `id` of `-1`, this type's `id` is
/// caller-supplied, matching `AbstractJitOutVar`'s constructor.
///
/// Grown (see `STUBS.tsv`) with [`JitVar`](crate::pcode::emu::jit::var::JitVar) and
/// [`JitVarnodeVar`](crate::pcode::emu::jit::var::JitVarnodeVar) impls for
/// [`LocalOutVarGen`](crate::pcode::emu::jit::gen::var::local_out_var_gen::LocalOutVarGen), whose
/// Java counterpart binds `LocalVarGen<JitLocalOutVar>` and so requires
/// `JitLocalOutVar: JitVarnodeVar`; and with `AbstractJitOutVar`'s `definition` bookkeeping (a
/// [`JitOutVar`] impl) for
/// [`JitDataFlowArithmetic`](crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic::JitDataFlowArithmetic),
/// which generates these as the outputs of use-def op nodes and later reads back their defining
/// op. The field is a [`Mutex`] because Java mutates it through a shared reference.
pub struct JitLocalOutVar {
    id: i32,
    varnode: Varnode,
    definition: Mutex<Option<Arc<dyn JitDefOp>>>,
}

impl JitLocalOutVar {
    /// Port of `new JitLocalOutVar(int, Varnode)`.
    pub fn new(id: i32, varnode: Varnode) -> Self {
        Self { id, varnode, definition: Mutex::new(None) }
    }
}

impl JitVal for JitLocalOutVar {
    fn size(&self) -> i32 {
        self.varnode.get_size()
    }

    fn add_use(&self, _op: &dyn JitOp, _position: i32) {}

    fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}

    fn as_varnode_var(&self) -> Option<&dyn crate::pcode::emu::jit::var::JitVarnodeVar> {
        Some(self)
    }

    fn as_out_var(&self) -> Option<&dyn JitOutVar> {
        Some(self)
    }
}

impl JitOutVar for JitLocalOutVar {
    /// A no-op: a borrowed `&dyn JitDefOp` cannot be retained past the call. See
    /// [`JitOutVar::set_definition_arc`], which this stub implements for real.
    fn set_definition(&self, _definition: Option<&dyn JitDefOp>) {}

    fn set_definition_arc(&self, definition: Option<Arc<dyn JitDefOp>>) {
        *self.definition.lock().unwrap() = definition;
    }

    /// Port of `AbstractJitOutVar.definition()`.
    fn definition(&self) -> Option<Arc<dyn JitDefOp>> {
        self.definition.lock().unwrap().clone()
    }

    fn varnode(&self) -> Varnode {
        self.varnode.clone()
    }
}

impl crate::pcode::emu::jit::var::JitVar for JitLocalOutVar {
    /// Port of `AbstractJitVarnodeVar`'s caller-supplied `id`, as passed by `JitLocalOutVar`'s
    /// constructor.
    fn id(&self) -> i32 {
        self.id
    }

    /// Port of `AbstractJitVarnodeVar.space()`.
    fn space(&self) -> Arc<AddressSpace> {
        Arc::clone(self.varnode.get_address().space())
    }
}

impl crate::pcode::emu::jit::var::JitVarnodeVar for JitLocalOutVar {
    /// Port of `AbstractJitVarnodeVar.varnode()`.
    fn varnode(&self) -> Varnode {
        self.varnode.clone()
    }
}

/// Placeholder for the unported Java type `ghidra.pcode.emu.jit.var.JitMemoryOutVar`, referenced
/// by [`MemoryOutVarGen`](crate::pcode::emu::jit::gen::var::memory_out_var_gen::MemoryOutVarGen).
/// Java's class extends `AbstractJitOutVar extends AbstractJitVarnodeVar` and implements the
/// marker `JitMemoryVar`, exactly as [`JitDirectMemoryVar`](
/// crate::pcode::emu::jit::var::jit_direct_memory_var::JitDirectMemoryVar) does -- but unlike that
/// type (and like [`JitLocalOutVar`]), this one is not ported as a top-level module yet, so it
/// stays here as a stub, grown (see `STUBS.tsv`) with the same `JitVal`/`JitVar`/`JitVarnodeVar`
/// impls `JitLocalOutVar` has, plus `JitMemoryVar` -- and, like `JitLocalOutVar`,
/// `AbstractJitOutVar`'s `definition` bookkeeping.
pub struct JitMemoryOutVar {
    id: i32,
    varnode: Varnode,
    definition: Mutex<Option<Arc<dyn JitDefOp>>>,
}

impl JitMemoryOutVar {
    /// Port of `new JitMemoryOutVar(int, Varnode)`.
    pub fn new(id: i32, varnode: Varnode) -> Self {
        Self { id, varnode, definition: Mutex::new(None) }
    }
}

impl JitVal for JitMemoryOutVar {
    fn size(&self) -> i32 {
        self.varnode.get_size()
    }

    /// Port of `JitMemoryOutVar.addUse`, which unconditionally throws: these variables are never
    /// used by downstream p-code ops in the use-def graph (see the type's Java doc comment).
    fn add_use(&self, _op: &dyn JitOp, _position: i32) {
        panic!("AssertionError: JitMemoryOutVar.addUse")
    }

    fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}

    fn as_varnode_var(&self) -> Option<&dyn crate::pcode::emu::jit::var::JitVarnodeVar> {
        Some(self)
    }

    fn as_out_var(&self) -> Option<&dyn JitOutVar> {
        Some(self)
    }
}

impl JitOutVar for JitMemoryOutVar {
    /// A no-op, like [`JitLocalOutVar`]'s: see [`JitOutVar::set_definition_arc`].
    fn set_definition(&self, _definition: Option<&dyn JitDefOp>) {}

    fn set_definition_arc(&self, definition: Option<Arc<dyn JitDefOp>>) {
        *self.definition.lock().unwrap() = definition;
    }

    /// Port of `AbstractJitOutVar.definition()`.
    fn definition(&self) -> Option<Arc<dyn JitDefOp>> {
        self.definition.lock().unwrap().clone()
    }

    fn varnode(&self) -> Varnode {
        self.varnode.clone()
    }
}

impl crate::pcode::emu::jit::var::JitVar for JitMemoryOutVar {
    /// Port of `AbstractJitVarnodeVar`'s caller-supplied `id`, as passed by `JitMemoryOutVar`'s
    /// constructor.
    fn id(&self) -> i32 {
        self.id
    }

    /// Port of `AbstractJitVarnodeVar.space()`.
    fn space(&self) -> Arc<AddressSpace> {
        Arc::clone(self.varnode.get_address().space())
    }
}

impl crate::pcode::emu::jit::var::JitVarnodeVar for JitMemoryOutVar {
    /// Port of `AbstractJitVarnodeVar.varnode()`.
    fn varnode(&self) -> Varnode {
        self.varnode.clone()
    }
}

impl JitMemoryVar for JitMemoryOutVar {}

/// Placeholder for the unported Java record `ghidra.pcode.emu.jit.op.JitStoreOp`, referenced by
/// [`JitOpVisitor::visit_store_op`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_store_op).
///
/// Grown (see `STUBS.tsv`) with the `offset`/`value` record components for
/// [`JitOpUpwardVisitor`](crate::pcode::emu::jit::analysis::jit_op_upward_visitor::JitOpUpwardVisitor),
/// which visits both; and then with the full record header (`op`/`space`, and `Arc` rather than
/// `Box` operands, since the use-def graph shares its values) for
/// [`JitDataFlowArithmetic::mod_before_store_from_pcode_op`](crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic::JitDataFlowArithmetic),
/// which constructs these. `link`/`unlink`/`type_for` remain unimplemented since nothing needs
/// them yet.
pub struct JitStoreOp {
    op: PcodeOp,
    space: AddressSpace,
    offset: Arc<dyn JitVal>,
    value: Arc<dyn JitVal>,
}

impl JitStoreOp {
    /// Port of `new JitStoreOp(PcodeOp, AddressSpace, JitVal, JitVal)`.
    pub fn new(
        op: PcodeOp,
        space: AddressSpace,
        offset: Arc<dyn JitVal>,
        value: Arc<dyn JitVal>,
    ) -> Self {
        Self { op, space, offset, value }
    }

    /// Port of the record accessor `op()`.
    pub fn op(&self) -> &PcodeOp {
        &self.op
    }

    /// Port of the record accessor `space()`.
    pub fn space(&self) -> &AddressSpace {
        &self.space
    }

    /// Port of the record accessor `offset()`.
    pub fn offset(&self) -> &Arc<dyn JitVal> {
        &self.offset
    }

    /// Port of the record accessor `value()`.
    pub fn value(&self) -> &Arc<dyn JitVal> {
        &self.value
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
/// which visits it; and then with the full record header (`op`/`out`/`space`) for
/// [`JitDataFlowArithmetic::mod_after_load_from_pcode_op`](crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic::JitDataFlowArithmetic),
/// which constructs these and reads back `out()`. `link`/`unlink`/`type_for` remain unimplemented
/// since nothing needs them yet.
pub struct JitLoadOp {
    op: PcodeOp,
    out: Arc<dyn JitOutVar>,
    space: AddressSpace,
    offset: Arc<dyn JitVal>,
}

impl JitLoadOp {
    /// Port of `new JitLoadOp(PcodeOp, JitOutVar, AddressSpace, JitVal)`.
    pub fn new(
        op: PcodeOp,
        out: Arc<dyn JitOutVar>,
        space: AddressSpace,
        offset: Arc<dyn JitVal>,
    ) -> Self {
        Self { op, out, space, offset }
    }

    /// Port of the record accessor `op()`.
    pub fn op(&self) -> &PcodeOp {
        &self.op
    }

    /// Port of the record accessor `space()`.
    pub fn space(&self) -> &AddressSpace {
        &self.space
    }

    /// Port of the record accessor `offset()`.
    pub fn offset(&self) -> &Arc<dyn JitVal> {
        &self.offset
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

impl JitDefOp for JitLoadOp {
    fn out(&self) -> Arc<dyn JitOutVar> {
        Arc::clone(&self.out)
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
/// which visits each part; and then with the `out` component (and `Arc` rather than `Box` parts,
/// since [`JitDataFlowArithmetic`](crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic::JitDataFlowArithmetic)
/// re-catenates a *copy* of an existing op's part list when simplifying a subpiece).
/// `link`/`unlink`/`type_for` remain unimplemented since nothing needs them yet.
pub struct JitCatenateOp {
    out: Arc<dyn JitOutVar>,
    parts: Vec<Arc<dyn JitVal>>,
}

impl JitCatenateOp {
    /// Port of `new JitCatenateOp(JitOutVar, List)`.
    pub fn new(out: Arc<dyn JitOutVar>, parts: Vec<Arc<dyn JitVal>>) -> Self {
        Self { out, parts }
    }

    /// Port of the record accessor `parts()`.
    pub fn parts(&self) -> &[Arc<dyn JitVal>] {
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

impl JitDefOp for JitCatenateOp {
    fn out(&self) -> Arc<dyn JitOutVar> {
        Arc::clone(&self.out)
    }

    fn as_catenate_op(&self) -> Option<&JitCatenateOp> {
        Some(self)
    }
}

/// Placeholder for the unported Java record `ghidra.pcode.emu.jit.op.JitSynthSubPieceOp`,
/// referenced by [`JitOpVisitor::visit_sub_piece_op`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_sub_piece_op).
///
/// Grown (see `STUBS.tsv`) with the `v` record component for
/// [`JitOpUpwardVisitor`](crate::pcode::emu::jit::analysis::jit_op_upward_visitor::JitOpUpwardVisitor),
/// which visits it; and then with the `out`/`offset` components for
/// [`JitDataFlowArithmetic`](crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic::JitDataFlowArithmetic),
/// which constructs these and folds a subpiece-of-a-subpiece by adding the two offsets.
/// `link`/`unlink`/`type_for` remain unimplemented since nothing needs them yet.
pub struct JitSynthSubPieceOp {
    out: Arc<dyn JitOutVar>,
    offset: i32,
    v: Arc<dyn JitVal>,
}

impl JitSynthSubPieceOp {
    /// Port of `new JitSynthSubPieceOp(JitOutVar, int, JitVal)`.
    pub fn new(out: Arc<dyn JitOutVar>, offset: i32, v: Arc<dyn JitVal>) -> Self {
        Self { out, offset, v }
    }

    /// Port of the record accessor `offset()`: the number of bytes shifted right.
    pub fn offset(&self) -> i32 {
        self.offset
    }

    /// Port of the record accessor `v()`.
    pub fn v(&self) -> &Arc<dyn JitVal> {
        &self.v
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

impl JitDefOp for JitSynthSubPieceOp {
    fn out(&self) -> Arc<dyn JitOutVar> {
        Arc::clone(&self.out)
    }

    fn as_synth_sub_piece_op(&self) -> Option<&JitSynthSubPieceOp> {
        Some(self)
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
/// [`JitOpVisitor::visit_const_val`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_const_val)
/// and [`JitVal::constant`](crate::pcode::emu::jit::var::jit_val::constant).
///
/// Grown (see `STUBS.tsv`) with the `size`/`value` fields for `JitVal.constant(int, BigInteger)`:
/// `BigInteger` is stood in for by `i128` since no arbitrary-precision integer type exists in this
/// crate yet. `to_string`/`value` accessors and the rest of the real class body remain unported.
/// Replace with the real port when `JitConstVal.java` is ported.
pub struct JitConstVal {
    size: i32,
    value: i128,
}

impl JitConstVal {
    /// Port of `new JitConstVal(int, BigInteger)`.
    pub fn new(size: i32, value: i128) -> Self {
        Self { size, value }
    }

    /// Port of `JitConstVal.value()`.
    pub fn value(&self) -> i128 {
        self.value
    }
}

impl JitVal for JitConstVal {
    fn size(&self) -> i32 {
        self.size
    }

    fn add_use(&self, _op: &dyn JitOp, _position: i32) {}

    fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}

    fn as_const_val(&self) -> Option<&JitConstVal> {
        Some(self)
    }

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
/// by [`JitOpVisitor::visit_missing_var`](crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor::visit_missing_var)
/// and by [`JitDataFlowBlockAnalyzer`](crate::pcode::emu::jit::analysis::jit_data_flow_block_analyzer::JitDataFlowBlockAnalyzer),
/// which downcasts a definition to this type (via [`JitVal::as_missing_var`]) and calls
/// [`Self::generate_phi`] on it. Java's class extends `AbstractJitVarnodeVar` with a fixed `id` of
/// `-1` -- mirrored here exactly as [`JitInputVar`] already does.
///
/// Grown (see `STUBS.tsv`) with the `varnode` field, [`JitVar`](crate::pcode::emu::jit::var::JitVar)/
/// [`JitVarnodeVar`](crate::pcode::emu::jit::var::JitVarnodeVar) impls, and
/// [`Self::generate_phi`] for `JitDataFlowBlockAnalyzer`.
pub struct JitMissingVar {
    varnode: Varnode,
}

impl JitMissingVar {
    /// Port of `new JitMissingVar(Varnode)`.
    pub fn new(varnode: Varnode) -> Self {
        Self { varnode }
    }

    /// Create the phi node for this missing variable.
    ///
    /// Port of `JitMissingVar.generatePhi(JitDataFlowModel, JitBlock)`.
    pub fn generate_phi(&self, dfm: &Arc<dyn JitDataFlowModel>, block: JitBlock) -> Arc<JitPhiOp> {
        let out = dfm.generate_out_var(&self.varnode);
        let phi = Arc::new(JitPhiOp::new(block, out));
        dfm.notify_op(Arc::clone(&phi) as Arc<dyn JitOp>);
        phi
    }
}

impl JitVal for JitMissingVar {
    fn size(&self) -> i32 {
        self.varnode.get_size()
    }

    fn add_use(&self, _op: &dyn JitOp, _position: i32) {}

    fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}

    /// Grown (see `STUBS.tsv`) to stand in for Java's `instanceof JitMissingVar` check in
    /// `JitDataFlowBlockAnalyzer.fillPhiFromBlock` and `MiniDFState.generatePhis`.
    fn as_missing_var(&self) -> Option<&JitMissingVar> {
        Some(self)
    }

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
    /// Port of `AbstractJitVarnodeVar`'s fixed `id` of `-1` passed by `JitMissingVar`'s
    /// constructor.
    fn id(&self) -> i32 {
        -1
    }

    /// Port of `AbstractJitVarnodeVar.space()`.
    fn space(&self) -> Arc<AddressSpace> {
        Arc::clone(self.varnode.get_address().space())
    }

    fn accept_var(
        &self,
        visitor: &mut dyn crate::pcode::emu::jit::analysis::jit_op_visitor::JitOpVisitor,
    ) {
        visitor.visit_missing_var(self);
    }
}

impl crate::pcode::emu::jit::var::JitVarnodeVar for JitMissingVar {
    /// Port of `AbstractJitVarnodeVar.varnode()`.
    fn varnode(&self) -> Varnode {
        self.varnode.clone()
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

    /// Get the allocation model for the current analysis.
    ///
    /// Port of `JitCodeGenerator.getAllocationModel()`, referenced by
    /// [`LocalVarGen`](crate::pcode::emu::jit::gen::var::local_var_gen::LocalVarGen). Defaulted
    /// (rather than required) so the existing marker implementors of this trait, which predate
    /// this method, keep compiling.
    fn get_allocation_model(&self) -> Box<dyn JitAllocationModel> {
        unimplemented!("JitCodeGenerator::get_allocation_model stub")
    }

    /// Get the variable scope (liveness) model for the current analysis.
    ///
    /// Port of `JitCodeGenerator.getVariableScopeModel()`, referenced by
    /// [`compute_block_transition`](crate::pcode::emu::jit::gen::var::var_gen::compute_block_transition).
    /// Unlike its neighbors here, the model itself *is* ported, so this returns the real type.
    /// Defaulted (rather than required) so the existing marker implementors of this trait, which
    /// predate this method, keep compiling.
    fn get_variable_scope_model(&self) -> Arc<JitVarScopeModel> {
        unimplemented!("JitCodeGenerator::get_variable_scope_model stub")
    }

    /// Emit bytecode to load a p-code value into a fresh multi-precision operand.
    ///
    /// Port of `JitCodeGenerator.genReadToOpnd(Emitter, Local, JitVal, MpIntJitType, Ext, Scope)`,
    /// referenced by
    /// [`IntBitwiseBinOpGen`](crate::pcode::emu::jit::gen::op::int_bitwise_bin_op_gen::IntBitwiseBinOpGen).
    /// Java's real body dispatches to the also-unported `ValGen.lookup(v)`. Like
    /// [`MpIntAccessGen`]'s stub impl of the analogous [`MpAccessGen::gen_read_to_opnd`], this
    /// preserves only the type-level stack-shape plumbing -- the incoming stack is untouched --
    /// and hands back a stand-in [`StubMpOpnd`]. Defaulted (rather than required) so the existing
    /// marker implementors of this trait, which predate this method, keep compiling.
    fn gen_read_to_opnd(
        &self,
        em: Emitter<Bot>,
        local_this: &Local<TRef>,
        v: &dyn JitVal,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
    ) -> OpndEm<MpIntJitType, Bot> {
        let _ = (local_this, v, type_, ext, scope);
        OpndEm::new(Box::new(StubMpOpnd), em)
    }

    /// Emit bytecode to store a multi-precision operand's legs into a p-code variable.
    ///
    /// Port of `JitCodeGenerator.genWriteFromOpnd(Emitter, Local, JitVar, Opnd, Ext, Scope)`,
    /// referenced by
    /// [`IntBitwiseBinOpGen`](crate::pcode::emu::jit::gen::op::int_bitwise_bin_op_gen::IntBitwiseBinOpGen).
    /// Java's `v` parameter is `JitVar`; this narrows it to `&dyn JitOutVar` -- the only concrete
    /// source this trait's callers have (`JitDefOp::out()`), since this crate's [`JitOutVar`] stub
    /// does not (yet) extend the real [`JitVar`](crate::pcode::emu::jit::var::JitVar) port. Java's
    /// real body dispatches to the also-unported `VarGen.lookup(v)`; per the same convention as
    /// [`gen_read_to_opnd`](Self::gen_read_to_opnd), this only preserves the stack shape -- the
    /// incoming stack passes through unchanged. Defaulted (rather than required) so the existing
    /// marker implementors of this trait, which predate this method, keep compiling.
    fn gen_write_from_opnd(
        &self,
        em: Emitter<Bot>,
        local_this: &Local<TRef>,
        v: &dyn JitOutVar,
        opnd: &dyn Opnd<MpIntJitType>,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<Bot> {
        let _ = (local_this, v, opnd, ext, scope);
        em
    }

    /// Emit bytecode to read the given value onto the top of the operand stack.
    ///
    /// Port of `JitCodeGenerator.genReadToStack(Emitter<N>, Local<TRef<THIS>>, JitVal, JT, Ext)`,
    /// referenced by
    /// [`FloatConvertUnOpGen`](crate::pcode::emu::jit::gen::op::float_convert_un_op_gen::FloatConvertUnOpGen).
    /// Java's real body dispatches to the also-unported `ValGen.lookup(v)`. Like
    /// [`Self::gen_read_to_opnd`], this preserves only the type-level stack-shape plumbing -- the
    /// incoming stack passes through unchanged, recast with the new entry on top -- since no real
    /// value is pushed. Requires `Self: Sized` (the type parameters `UT`/`UJT` make this method
    /// generic, which is incompatible with `dyn` dispatch), so it drops out of the vtable instead
    /// of making the trait as a whole object-unsafe, the same technique
    /// [`VarHandler`](crate::pcode::emu::jit::alloc::var_handler::VarHandler) already uses.
    fn gen_read_to_stack<UT, UJT, N>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        v: &dyn JitVal,
        type_: UJT,
        ext: Ext,
    ) -> Emitter<Ent<N, UT>>
    where
        Self: Sized,
        UT: BPrim,
        UJT: SimpleJitType<B = UT>,
        N: Next,
    {
        let _ = (local_this, v, type_, ext);
        em.recast()
    }

    /// Emit bytecode to store the value on top of the operand stack into the given variable.
    ///
    /// Port of `JitCodeGenerator.genWriteFromStack(Emitter<N0>, Local<TRef<THIS>>, JitVar, JT,
    /// Ext, Scope)`, referenced by
    /// [`FloatConvertUnOpGen`](crate::pcode::emu::jit::gen::op::float_convert_un_op_gen::FloatConvertUnOpGen).
    /// Java's `v` parameter is `JitVar`; narrowed to `&dyn JitOutVar` here, per the same
    /// convention as [`Self::gen_write_from_opnd`]. See [`Self::gen_read_to_stack`] on why this
    /// only preserves stack shape and requires `Self: Sized`.
    fn gen_write_from_stack<OT, OJT, N>(
        &self,
        em: Emitter<Ent<N, OT>>,
        local_this: &Local<TRef>,
        v: &dyn JitOutVar,
        type_: OJT,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N>
    where
        Self: Sized,
        OT: BPrim,
        OJT: SimpleJitType<B = OT>,
        N: Next,
    {
        let _ = (local_this, v, type_, ext, scope);
        em.recast()
    }

    /// Emit bytecode to load a p-code value into a fresh `int[]` on top of the operand stack.
    ///
    /// Port of `JitCodeGenerator.genReadToArray(Emitter, Local, JitVal, MpIntJitType, Ext, Scope,
    /// int)`, referenced by
    /// [`IntShiftBinOpGen`](crate::pcode::emu::jit::gen::op::int_shift_bin_op_gen::IntShiftBinOpGen).
    /// Java's real body allocates the array and dispatches to the also-unported `ValGen.lookup(v)`
    /// to fill it. Like [`Self::gen_read_to_stack`], this preserves only the type-level
    /// stack-shape plumbing -- the incoming stack passes through unchanged, recast with an
    /// `int[]` reference on top -- since no real array is allocated. Defaulted (rather than
    /// required) so the existing marker implementors of this trait, which predate this method,
    /// keep compiling.
    #[allow(clippy::too_many_arguments)]
    fn gen_read_to_array<N>(
        &self,
        em: Emitter<N>,
        local_this: &Local<TRef>,
        v: &dyn JitVal,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
        slack: i32,
    ) -> Emitter<Ent<N, TRef>>
    where
        Self: Sized,
        N: Next,
    {
        let _ = (local_this, v, type_, ext, scope, slack);
        em.recast()
    }

    /// Emit bytecode to store the `int[]` on top of the operand stack into the given variable.
    ///
    /// Port of `JitCodeGenerator.genWriteFromArray(Emitter, Local, JitVar, MpIntJitType, Ext,
    /// Scope)`, referenced by
    /// [`IntShiftBinOpGen`](crate::pcode::emu::jit::gen::op::int_shift_bin_op_gen::IntShiftBinOpGen).
    /// Java's `v` parameter is `JitVar`; narrowed to `&dyn JitOutVar` here, per the same
    /// convention as [`Self::gen_write_from_stack`]. Java's real body dispatches to the
    /// also-unported `VarGen.lookup(v)`; this only preserves the stack shape -- the `int[]`
    /// reference on top is popped, and the incoming tail passes through unchanged. Defaulted
    /// (rather than required) so the existing marker implementors of this trait, which predate
    /// this method, keep compiling.
    fn gen_write_from_array<N>(
        &self,
        em: Emitter<Ent<N, TRef>>,
        local_this: &Local<TRef>,
        v: &dyn JitOutVar,
        type_: MpIntJitType,
        ext: Ext,
        scope: &dyn Scope,
    ) -> Emitter<N>
    where
        Self: Sized,
        N: Next,
    {
        let _ = (local_this, v, type_, ext, scope);
        em.recast()
    }
}

/// Placeholder for the unported Java type `JitAllocationModel`
/// (`ghidra.pcode.emu.jit.analysis.JitAllocationModel`), referenced by
/// [`LocalVarGen`](crate::pcode::emu::jit::gen::var::local_var_gen::LocalVarGen) through
/// [`JitCodeGenerator::get_allocation_model`]. Java's class tracks the complete allocation plan
/// (which varnodes get which JVM locals, and by what strategy); only the one member
/// `LocalVarGen::get_handler` needs -- looking up the handler for a given value -- is modeled
/// here. The default panics: [`VarHandler`]'s `gen_load_*` methods require `Self: Sized` (see
/// that trait's module docs), so no real allocation model can be plugged in here until either
/// `JitAllocationModel` itself is ported (with a way to recover the concrete handler type per
/// value) or `VarHandler` grows a dyn-safe path.
pub trait JitAllocationModel: Send + Sync {
    /// Port of `JitAllocationModel.getHandler(JitVal)`.
    fn get_handler(&self, v: &dyn JitVal) -> Box<dyn VarHandler> {
        let _ = v;
        unimplemented!("JitAllocationModel::get_handler stub")
    }

    /// Get every JVM local allocated within the given varnode's extent.
    ///
    /// Port of `JitAllocationModel.localsForVn(Varnode)`, referenced by
    /// [`gen_birth`](crate::pcode::emu::jit::gen::var::var_gen::gen_birth)/
    /// [`gen_retire`](crate::pcode::emu::jit::gen::var::var_gen::gen_retire). Java returns the
    /// values of a sorted-map submap, i.e. the locals in address order; a [`Vec`] carries the
    /// same guarantee.
    fn locals_for_vn(&self, vn: &Varnode) -> Vec<JvmLocal> {
        let _ = vn;
        unimplemented!("JitAllocationModel::locals_for_vn stub")
    }
}

/// Placeholder for the unported Java type `JitAnalysisContext`
/// (`ghidra.pcode.emu.jit.analysis.JitAnalysisContext`), referenced by
/// [`JitCodeGenerator::get_analysis_context`]. Java's class also carries the data-flow, type, and
/// scope models built during passage analysis; only the members downstream code currently needs
/// are modeled here.
///
/// Grown (see `STUBS.tsv`) with `entry_blocks` for
/// [`JitDataFlowBlockAnalyzer`](crate::pcode::emu::jit::analysis::jit_data_flow_block_analyzer::JitDataFlowBlockAnalyzer),
/// which computes `isEntry` from `context.getOpEntry(block.first()) != null`. Java's `getOpEntry`
/// takes a `PcodeOp` looked up via the also-identity-only [`JitBlock`] (see that type's doc for
/// why it carries no op list), so this collapses the `block.first()` + `getOpEntry()` chain into
/// one query -- "is `block` a passage entry" -- directly against a set of known entry blocks.
/// No longer `Copy` (a `HashSet` isn't), but every existing call site already constructs a fresh
/// context rather than copying one.
#[derive(Debug, Clone)]
pub struct JitAnalysisContext {
    endian: Endian,
    entry_blocks: HashSet<JitBlock>,
}

impl JitAnalysisContext {
    /// Construct a context for the given endianness, with no known entry blocks.
    pub fn new(endian: Endian) -> Self {
        Self { endian, entry_blocks: HashSet::new() }
    }

    /// Construct a context for the given endianness and set of passage-entry blocks.
    pub fn with_entry_blocks(endian: Endian, entry_blocks: HashSet<JitBlock>) -> Self {
        Self { endian, entry_blocks }
    }

    /// Port of `JitAnalysisContext.getEndian()`.
    pub fn get_endian(&self) -> Endian {
        self.endian
    }

    /// Stand-in for `getOpEntry(block.first()) != null`. See the type-level doc.
    pub fn is_block_entry(&self, block: JitBlock) -> bool {
        self.entry_blocks.contains(&block)
    }
}

/// Placeholder for the unported Java type `ghidra.pcode.emu.jit.analysis.JitDataFlowModel`,
/// referenced by
/// [`JitDataFlowArithmetic`](crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic::JitDataFlowArithmetic),
/// which owns one and routes every use-def node it builds through it. Java's class carries the
/// whole intra-block data-flow analysis (the value/op tables, phi and synthetic node lists, the
/// per-block analyzers, Graphviz export...); only the two members the arithmetic actually calls
/// are modeled here. It is a trait rather than a struct because the real model is the forward edge
/// of a dependency cycle -- it constructs the arithmetic, and the arithmetic calls back into it.
/// Replace with the real port when `JitDataFlowModel.java` is ported.
pub trait JitDataFlowModel: Send + Sync {
    /// Port of `JitDataFlowModel.generateOutVar(Varnode)`: allocate the SSA output variable for a
    /// p-code op writing `out`.
    fn generate_out_var(&self, out: &Varnode) -> Arc<dyn JitOutVar>;

    /// Port of `JitDataFlowModel.notifyOp(JitOp)`: link the op into the use-def graph and record
    /// it in the model.
    ///
    /// Java's version is generic and returns its argument; callers here already hold the op, so
    /// this returns nothing. See [`Self::notify_def_op`] for the `notifyOp(..).out()` shape that
    /// every `JitDataFlowArithmetic` call site uses.
    fn notify_op(&self, op: Arc<dyn JitOp>);

    /// Port of the `dfm.notifyOp(op).out()` idiom: notify, then hand back the op's output
    /// variable.
    ///
    /// This also performs the `out.setDefinition(this)` wiring that Java does inside
    /// `AbstractJitDefOp.link()` -- see [`JitOutVar::set_definition_arc`] for why it cannot happen
    /// in [`JitOp::link`] here.
    fn notify_def_op(&self, op: Arc<dyn JitDefOp>) -> Arc<dyn JitOutVar> {
        let out = op.out();
        out.set_definition_arc(Some(Arc::clone(&op)));
        self.notify_op(op);
        out
    }

    /// Port of `JitDataFlowModel.getArithmetic()`.
    ///
    /// Grown (see `STUBS.tsv`) for
    /// [`JitDataFlowBlockAnalyzer`](crate::pcode::emu::jit::analysis::jit_data_flow_block_analyzer::JitDataFlowBlockAnalyzer),
    /// which stores the model's arithmetic in its constructor, same as Java. Defaulted so
    /// existing implementors (which predate this port) keep compiling.
    fn get_arithmetic(&self) -> JitDataFlowArithmetic {
        unimplemented!("JitDataFlowModel::get_arithmetic stub")
    }

    /// Port of `JitDataFlowModel.getLibrary()`. See [`Self::get_arithmetic`].
    fn get_library(&self) -> JitDataFlowUseropLibrary {
        unimplemented!("JitDataFlowModel::get_library stub")
    }

    /// Port of `JitDataFlowModel.getOrCreateAnalyzer(JitBlock)`. See [`Self::get_arithmetic`].
    fn get_or_create_analyzer(&self, block: JitBlock) -> Arc<JitDataFlowBlockAnalyzer> {
        let _ = block;
        unimplemented!("JitDataFlowModel::get_or_create_analyzer stub")
    }

    /// Port of `JitDataFlowModel.getAnalyzer(JitBlock)` (`analyzers.get(block)`), used by
    /// [`JitVarScopeModel`](crate::pcode::emu::jit::analysis::jit_var_scope_model::JitVarScopeModel).
    ///
    /// Grown (see `STUBS.tsv`). Defaults to [`Self::get_or_create_analyzer`]: every consumer of
    /// this method runs after `JitDataFlowModel.analyze()`, by which point each block already has
    /// an analyzer, so the lookup and the get-or-create coincide.
    fn get_analyzer(&self, block: JitBlock) -> Arc<JitDataFlowBlockAnalyzer> {
        self.get_or_create_analyzer(block)
    }

    /// Stand-in for `block.flowsTo()`, a method Java puts on the also-unported
    /// `JitControlFlowModel.JitBlock` -- which this crate's [`JitBlock`] cannot carry, being
    /// deliberately identity-only (see that type's doc). Relocated here since `JitDataFlowModel`
    /// is the nearest already-stubbed type with a plausible view of the control-flow graph (real
    /// Java's `JitDataFlowModel` holds the `JitControlFlowModel` that backs this data). Defaults
    /// to no known inward flows, the conservative/honest answer until
    /// `JitControlFlowModel.java` is ported.
    fn flows_to(&self, block: JitBlock) -> Vec<BlockFlow> {
        let _ = block;
        Vec::new()
    }

    /// Port of enqueuing into `JitDataFlowModel.phiQueue` (`dfm.phiQueue.add(phi)`). See
    /// [`Self::get_arithmetic`].
    fn phi_queue_add(&self, phi: Arc<JitPhiOp>) {
        let _ = phi;
        unimplemented!("JitDataFlowModel::phi_queue_add stub")
    }

    /// Port of `JitDataFlowModel.generateDirectMemoryVar(Varnode)`. See [`Self::get_arithmetic`].
    fn generate_direct_memory_var(&self, vn: &Varnode) -> Arc<dyn JitVal> {
        let _ = vn;
        unimplemented!("JitDataFlowModel::generate_direct_memory_var stub")
    }
}

/// Placeholder for the unported Java type
/// `ghidra.pcode.emu.jit.analysis.JitDataFlowUseropLibrary`, referenced by
/// [`JitDataFlowModel::get_library`] and passed opaquely to [`JitDataFlowExecutor::execute`].
/// Java's class wraps every userop, routing `CALLOTHER` handling into the use-def graph; nothing
/// in this crate yet calls any of its members, so this stub carries none. Replace with the real
/// port when `JitDataFlowUseropLibrary.java` is ported.
#[derive(Debug, Clone, Copy, Default)]
pub struct JitDataFlowUseropLibrary;

/// Placeholder for the unported Java type `ghidra.pcode.emu.jit.analysis.JitDataFlowExecutor`,
/// referenced by
/// [`JitDataFlowBlockAnalyzer::do_intrablock`](crate::pcode::emu::jit::analysis::jit_data_flow_block_analyzer::JitDataFlowBlockAnalyzer::do_intrablock).
/// Java's class extends `PcodeExecutor<JitVal>`, overriding branch/call handling to keep
/// control-flow ops out of the use-def graph. Actually interpreting a block's p-code is far
/// beyond what a stub can model (it is the entire abstract interpreter), so
/// [`Self::execute`] panics; only the constructor shape is modeled, to keep
/// `do_intrablock`'s call faithful to Java's `new JitDataFlowExecutor(context, dfm,
/// state).execute(block, library)`. Replace with the real port when
/// `JitDataFlowExecutor.java` is ported.
pub struct JitDataFlowExecutor<'a> {
    context: &'a JitAnalysisContext,
    dfm: Arc<dyn JitDataFlowModel>,
    state: &'a JitDataFlowState,
}

impl<'a> JitDataFlowExecutor<'a> {
    /// Port of `new JitDataFlowExecutor(JitAnalysisContext, JitDataFlowModel, JitDataFlowState)`.
    pub fn new(
        context: &'a JitAnalysisContext,
        dfm: Arc<dyn JitDataFlowModel>,
        state: &'a JitDataFlowState,
    ) -> Self {
        Self { context, dfm, state }
    }

    /// Port of the inherited `PcodeExecutor.execute(PcodeProgram, PcodeUseropLibrary)`, as called
    /// on a block (`JitBlock` extends `PcodeProgram` in Java).
    pub fn execute(&self, block: JitBlock, library: &JitDataFlowUseropLibrary) {
        let _ = (self.context, &self.dfm, self.state, block, library);
        unimplemented!(
            "JitDataFlowExecutor::execute stub: full p-code interpretation requires \
             JitDataFlowExecutor.java"
        )
    }
}

/// Placeholder for the unported Java type `ghidra.pcode.emu.jit.analysis.JitDataFlowState`,
/// referenced by
/// [`JitDataFlowBlockAnalyzer`](crate::pcode::emu::jit::analysis::jit_data_flow_block_analyzer::JitDataFlowBlockAnalyzer),
/// which owns one per block. Java's class tracks, per address space, an interval map from byte
/// offset to defining [`JitVal`], resolving overlapping/adjacent pieces via
/// [`JitDataFlowArithmetic`]'s truncation helpers, and generating [`JitMissingVar`]s for gaps
/// (`MiniDFState.doGetDefinitions`).
///
/// This stub models only the exact-match case: [`Self::get_definitions`] returns the single
/// definition recorded for the exact varnode requested, or a single whole-varnode
/// [`JitMissingVar`] if none was recorded -- never the multi-piece overlapping case, which needs
/// `MiniDFState`'s real interval algorithm. [`Self::get_var`] and [`Self::generate_phis`] mirror
/// `JitDataFlowState.getVar`/`MiniDFState.generatePhis` otherwise faithfully (constant-space and
/// memory-space branches, missing-var-to-phi substitution, catenate fallback). Replace with the
/// real port when `JitDataFlowState.java` is ported.
pub struct JitDataFlowState {
    dfm: Arc<dyn JitDataFlowModel>,
    block: JitBlock,
    definitions: Mutex<Vec<(Varnode, Arc<dyn JitVal>)>>,
    varnodes_read: Mutex<Vec<Varnode>>,
    varnodes_written: Mutex<Vec<Varnode>>,
}

impl JitDataFlowState {
    /// Port of `new JitDataFlowState(JitAnalysisContext, JitDataFlowModel, JitBlock)`.
    pub fn new(_context: &JitAnalysisContext, dfm: Arc<dyn JitDataFlowModel>, block: JitBlock) -> Self {
        Self {
            dfm,
            block,
            definitions: Mutex::new(Vec::new()),
            varnodes_read: Mutex::new(Vec::new()),
            varnodes_written: Mutex::new(Vec::new()),
        }
    }

    /// Port of `JitDataFlowState.getDefinitions(Varnode)`. See the type-level doc for how this
    /// stub simplifies `MiniDFState.doGetDefinitions`.
    pub fn get_definitions(&self, varnode: &Varnode) -> Vec<Arc<dyn JitVal>> {
        let defs = self.definitions.lock().unwrap();
        if let Some((_, v)) = defs.iter().rev().find(|(vn, _)| vn == varnode) {
            return vec![Arc::clone(v)];
        }
        vec![Arc::new(JitMissingVar::new(varnode.clone()))]
    }

    /// Port of `MiniDFState.generatePhis(List<JitVal>, Collection<JitPhiOp>)`: replace each
    /// missing variable in `defs` with the output of a freshly generated phi node, enqueueing
    /// that phi if `enqueue` is given.
    pub fn generate_phis(
        &self,
        defs: Vec<Arc<dyn JitVal>>,
        enqueue: Option<&dyn Fn(Arc<JitPhiOp>)>,
    ) -> Vec<Arc<dyn JitVal>> {
        defs.into_iter()
            .map(|v| {
                if let Some(missing) = v.as_missing_var() {
                    let phi = missing.generate_phi(&self.dfm, self.block);
                    if let Some(enqueue) = enqueue {
                        enqueue(Arc::clone(&phi));
                    }
                    let varnode = missing.varnode();
                    let out: Arc<dyn JitVal> = phi.out();
                    self.set_var(&varnode, Arc::clone(&out));
                    out
                }
                else {
                    v
                }
            })
            .collect()
    }

    /// Port of `PcodeExecutorStatePiece.setVar(Varnode, JitVal)` (the varnode-level convenience
    /// over `JitDataFlowState.setVar(AddressSpace, JitVal, int, boolean, JitVal)`, restricted --
    /// as every call site here is -- to a concrete varnode rather than a computed address).
    pub fn set_var(&self, varnode: &Varnode, val: Arc<dyn JitVal>) {
        self.varnodes_written.lock().unwrap().push(varnode.clone());
        let mut defs = self.definitions.lock().unwrap();
        if let Some(entry) = defs.iter_mut().find(|(vn, _)| vn == varnode) {
            entry.1 = val;
        }
        else {
            defs.push((varnode.clone(), val));
        }
    }

    /// Port of `JitDataFlowState.getVar(AddressSpace, JitVal, int, boolean, Reason)`, as called
    /// via the varnode-level convenience `getVar(Varnode, Reason)` -- see [`Self::set_var`] for
    /// why the space/offset/size form is skipped.
    pub fn get_var(&self, varnode: &Varnode, reason: Reason) -> Arc<dyn JitVal> {
        let _ = reason;
        let space = varnode.get_address().space();
        if space.space_type() == AddressSpaceType::Constant {
            return Arc::new(JitConstVal::new(varnode.get_size(), varnode.get_offset() as i128));
        }
        if space.is_memory_space() {
            return self.dfm.generate_direct_memory_var(varnode);
        }
        self.varnodes_read.lock().unwrap().push(varnode.clone());
        let defs = self.generate_phis(self.get_definitions(varnode), None);
        if defs.len() == 1 {
            return defs.into_iter().next().unwrap();
        }
        self.dfm.get_arithmetic().catenate(varnode, defs)
    }

    /// Port of `JitDataFlowState.getVarnodesRead()`.
    pub fn get_varnodes_read(&self) -> Vec<Varnode> {
        self.varnodes_read.lock().unwrap().clone()
    }

    /// Port of `JitDataFlowState.getVarnodesWritten()`.
    pub fn get_varnodes_written(&self) -> Vec<Varnode> {
        self.varnodes_written.lock().unwrap().clone()
    }
}

/// Placeholder for the unported Java type `ghidra.pcode.opbehavior.OpBehaviorSubpiece`, referenced
/// by
/// [`JitDataFlowArithmetic::subpiece`](crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic::JitDataFlowArithmetic::subpiece)
/// to fold a subpiece of a constant. `ghidra.pcode.opbehavior` is ported only as far as the
/// `OpBehavior` traits, with no per-opcode behaviors and no `OpBehaviorFactory`, so this stub
/// carries the one method that call site needs -- and carries it for real, since the semantics
/// (eliminating the sign-extension bits `BigInteger.shiftRight` would produce) are not obvious.
pub struct OpBehaviorSubpiece;

impl OpBehaviorSubpiece {
    /// Port of `OpBehaviorSubpiece.evaluateBinary(int, int, BigInteger, BigInteger)`, with `i128`
    /// standing in for `BigInteger` as it does throughout this crate.
    pub fn evaluate_binary_big(_sizeout: i32, sizein: i32, in1: i128, in2: i128) -> i128 {
        // Must eliminate the sign-extension bits an arithmetic shift right would produce.
        let mut signbit = sizein * 8 - 1;
        let mut res = in1;
        let negative = signbit >= 0 && signbit < 128 && (res >> signbit) & 1 != 0;
        if negative {
            res &= crate::pcode::utils::calc_bigmask(sizein);
            res &= !(1i128 << signbit);
        }
        let shift = in2 as i32 * 8;
        if shift >= 128 {
            return 0;
        }
        res >>= shift;
        signbit -= shift;
        if negative && signbit >= 0 {
            res |= 1i128 << signbit; // restore shifted sign bit
        }
        res
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

/// Placeholder for the unported Java static dispatch `Opnd.convertToOpnd`/`Opnd.getStackToMp`
/// (`ghidra.pcode.emu.jit.gen.opnd.Opnd`), referenced by
/// [`SubVarHandler`](crate::pcode::emu::jit::alloc::sub_var_handler::SubVarHandler)'s default
/// `genLoadToOpnd`. The real dispatch looks up one of `IntToMpInt`/`LongToMpInt`/`FloatToMpInt`/
/// `DoubleToMpInt` and builds a real `MpIntLocalOpnd`; none of that machinery is ported, and the
/// marker-only [`Opnd`] stub exposes no way to construct one, so this only preserves the
/// type-level stack-shape plumbing -- dropping the value on the JVM stack and returning a
/// stand-in [`StubMpOpnd`] -- without emitting real bytecode, mirroring [`MpIntAccessGen`]'s stub
/// methods above.
pub fn convert_to_opnd<FT: BPrim, FJT: SimpleJitType<B = FT>, N: Next>(
    em: Emitter<Ent<N, FT>>,
    from: FJT,
    name: &str,
    to: MpIntJitType,
    ext: Ext,
    scope: &dyn Scope,
) -> OpndEm<MpIntJitType, N> {
    let _ = (from, name, to, ext, scope);
    OpndEm::new(Box::new(StubMpOpnd), em.recast())
}

/// Placeholder for the unported Java static dispatch `Opnd.convertToArray`/`Opnd.getStackToMp`
/// (`ghidra.pcode.emu.jit.gen.opnd.Opnd`), referenced by
/// [`SubVarHandler`](crate::pcode::emu::jit::alloc::sub_var_handler::SubVarHandler)'s default
/// `genLoadToArray`. See [`convert_to_opnd`] for why this only preserves stack shape.
#[allow(clippy::too_many_arguments)]
pub fn convert_to_array<FT: BPrim, FJT: SimpleJitType<B = FT>, N: Next>(
    em: Emitter<Ent<N, FT>>,
    from: FJT,
    name: &str,
    to: MpIntJitType,
    ext: Ext,
    scope: &dyn Scope,
    slack: i32,
) -> Emitter<Ent<N, TRef>> {
    let _ = (from, name, to, ext, scope, slack);
    em.recast()
}

/// Placeholder for the unported Java interface `Opnd.MpToStackConv<FT, FLT, FJT, TT, TJT>`
/// (`ghidra.pcode.emu.jit.gen.opnd.Opnd.MpToStackConv`), referenced by
/// [`SubVarHandler::get_conv_to_sub`](crate::pcode::emu::jit::alloc::sub_var_handler::SubVarHandler::get_conv_to_sub).
/// Java's `FT`/`FLT`/`FJT` are fixed to `int`/`IntJitType`/`MpIntJitType` at every call site
/// `SubVarHandler` makes, so only the "to" side (`TT`/`TJT`) stays generic here. The real
/// implementors (`MpIntToInt`, `MpIntToLong`, `MpIntToFloat`, `MpIntToDouble` in Java) read an
/// [`Opnd`]'s legs, which the marker-only [`Opnd`] stub cannot yet expose, so both methods here
/// only preserve the type-level stack-shape plumbing, per the same convention as
/// [`convert_to_opnd`].
pub trait MpToStackConv: Send + Sync {
    /// Port of `MpToStackConv.convertOpndToStack(Emitter<N>, Opnd<FJT>, TJT, Ext)`.
    fn convert_opnd_to_stack<TT: BPrim, TJT: SimpleJitType<B = TT>, N: Next>(
        &self,
        em: Emitter<N>,
        from: &dyn Opnd<MpIntJitType>,
        to: TJT,
        ext: Ext,
    ) -> Emitter<Ent<N, TT>>;

    /// Port of `MpToStackConv.convertArrayToStack(Emitter<N0>, FJT, TJT, Ext)`.
    fn convert_array_to_stack<TT: BPrim, TJT: SimpleJitType<B = TT>, N: Next>(
        &self,
        em: Emitter<Ent<N, TRef>>,
        from: MpIntJitType,
        to: TJT,
        ext: Ext,
    ) -> Emitter<Ent<N, TT>>;
}

/// Placeholder for the unported Java record `MpIntLocalOpnd`
/// (`ghidra.pcode.emu.jit.gen.opnd.MpIntLocalOpnd`), referenced by
/// [`AlignedMpIntHandler`](crate::pcode::emu::jit::alloc::aligned_mp_int_handler::AlignedMpIntHandler).
///
/// Java's record is `MpIntLocalOpnd(MpIntJitType type, String name,
/// List<? extends SimpleOpnd<TInt, IntJitType>> legsLE)`. The `legsLE` member is *not* carried
/// here, for the same reason [`JvmLocal`] omits its own `opnd`: every way to build a
/// [`SimpleOpnd`](crate::pcode::emu::jit::gen::opnd::simple_opnd::SimpleOpnd) value goes through
/// `SimpleOpnd.of`/`SimpleOpnd.ofIntReadOnly`, which dispatch to `IntLocalOpnd`/`LongLocalOpnd`/
/// `FloatLocalOpnd`/`DoubleLocalOpnd`/`IntReadOnlyLocalOpnd` -- none of which are ported -- and
/// `SimpleOpnd` is not object-safe (its `read`/`write_direct` are generic over the stack shape),
/// so the legs cannot even be held as trait objects. Callers that need the *number* of legs, or a
/// leg's p-code type, read them off [`type_`](Self::type_) instead, which is equivalent by
/// construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpIntLocalOpnd {
    /// The p-code type. Port of `MpIntLocalOpnd.type()`.
    pub type_: MpIntJitType,
    /// A name (prefix) to use for generated temporary legs. Port of `MpIntLocalOpnd.name()`.
    pub name: String,
}

impl MpIntLocalOpnd {
    /// Create a multi-precision integer operand of the given type and name.
    ///
    /// Port of `MpIntLocalOpnd.of(MpIntJitType, String, List)`, minus the `legsLE` argument this
    /// port does not carry (see the [type docs](Self)).
    pub fn of(type_: MpIntJitType, name: impl Into<String>) -> Self {
        Self { type_, name: name.into() }
    }
}

impl Opnd<MpIntJitType> for MpIntLocalOpnd {}

/// Placeholder for the unported Java static `Opnd.MpIntToMpInt.INSTANCE.convertOpndToOpnd`
/// (`ghidra.pcode.emu.jit.gen.opnd.Opnd`), referenced by
/// [`AlignedMpIntHandler`](crate::pcode::emu::jit::alloc::aligned_mp_int_handler::AlignedMpIntHandler)'s
/// `genLoadToOpnd`. The real conversion reads the source operand's legs and writes converted legs
/// into a freshly declared `MpIntLocalOpnd`; the marker-only [`Opnd`] stub exposes no legs, so
/// this only preserves the type-level stack-shape plumbing -- the stack is untouched -- and hands
/// back a stand-in [`StubMpOpnd`], mirroring [`convert_to_opnd`].
pub fn convert_opnd_to_opnd<N: Next>(
    em: Emitter<N>,
    from: &dyn Opnd<MpIntJitType>,
    to: MpIntJitType,
    ext: Ext,
    scope: &dyn Scope,
) -> OpndEm<MpIntJitType, N> {
    let _ = (from, to, ext, scope);
    OpndEm::new(Box::new(StubMpOpnd), em)
}

/// Placeholder for the unported Java static `Opnd.MpIntToMpInt.INSTANCE.convertOpndToArray`
/// (`ghidra.pcode.emu.jit.gen.opnd.Opnd`), referenced by
/// [`AlignedMpIntHandler`](crate::pcode::emu::jit::alloc::aligned_mp_int_handler::AlignedMpIntHandler)'s
/// `genLoadToArray`. See [`convert_opnd_to_opnd`] for why this only preserves stack shape.
pub fn convert_opnd_to_array<N: Next>(
    em: Emitter<N>,
    from: &dyn Opnd<MpIntJitType>,
    to: MpIntJitType,
    ext: Ext,
    scope: &dyn Scope,
    slack: i32,
) -> Emitter<Ent<N, TRef>> {
    let _ = (from, to, ext, scope, slack);
    em.recast()
}

/// Emit the body shared by every unported-handler placeholder's [`VarHandler`] generator methods.
///
/// Each placeholder below stands in for a Java handler whose generators emit real JVM bytecode via
/// `Op`/`Opnd`, neither of which is ported. Rather than silently returning a stack-shape recast --
/// which would read as "this generates correct (if empty) code" -- they panic, so a caller that
/// actually reaches one gets pointed at the missing port.
macro_rules! unported_handler_var_handler_impl {
    ($ty:ident, $java:literal, $variant:path) => {
        impl VarHandler for $ty {
            fn vn(&self) -> Varnode {
                self.vn.clone()
            }

            fn type_(&self) -> AnyJitType {
                $variant(self.type_.clone())
            }

            fn gen_load_to_stack<TT, TJT, N>(
                &self,
                _em: Emitter<N>,
                _gen: &dyn JitCodeGenerator,
                _type_: TJT,
                _ext: Ext,
            ) -> Emitter<Ent<N, TT>>
            where
                TT: BPrim,
                TJT: SimpleJitType<B = TT>,
                N: Next,
            {
                unimplemented!(concat!($java, "::genLoadToStack is not ported yet"))
            }

            fn gen_load_to_opnd<N: Next>(
                &self,
                _em: Emitter<N>,
                _gen: &dyn JitCodeGenerator,
                _type_: MpIntJitType,
                _ext: Ext,
                _scope: &dyn Scope,
            ) -> OpndEm<MpIntJitType, N> {
                unimplemented!(concat!($java, "::genLoadToOpnd is not ported yet"))
            }

            fn gen_load_leg_to_stack<N: Next>(
                &self,
                _em: Emitter<N>,
                _gen: &dyn JitCodeGenerator,
                _type_: MpIntJitType,
                _leg: i32,
                _ext: Ext,
            ) -> Emitter<Ent<N, TInt>> {
                unimplemented!(concat!($java, "::genLoadLegToStack is not ported yet"))
            }

            fn gen_load_to_array<N: Next>(
                &self,
                _em: Emitter<N>,
                _gen: &dyn JitCodeGenerator,
                _type_: MpIntJitType,
                _ext: Ext,
                _scope: &dyn Scope,
                _slack: i32,
            ) -> Emitter<Ent<N, TRef>> {
                unimplemented!(concat!($java, "::genLoadToArray is not ported yet"))
            }

            fn gen_load_to_bool<N: Next>(
                &self,
                _em: Emitter<N>,
                _gen: &dyn JitCodeGenerator,
            ) -> Emitter<Ent<N, TInt>> {
                unimplemented!(concat!($java, "::genLoadToBool is not ported yet"))
            }

            fn gen_store_from_stack<FT, FJT, N1>(
                &self,
                _em: Emitter<Ent<N1, FT>>,
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
                unimplemented!(concat!($java, "::genStoreFromStack is not ported yet"))
            }

            fn gen_store_from_opnd<N: Next>(
                &self,
                _em: Emitter<N>,
                _gen: &dyn JitCodeGenerator,
                _opnd: &dyn Opnd<MpIntJitType>,
                _ext: Ext,
                _scope: &dyn Scope,
            ) -> Emitter<N> {
                unimplemented!(concat!($java, "::genStoreFromOpnd is not ported yet"))
            }

            fn gen_store_from_array<N1: Next>(
                &self,
                _em: Emitter<Ent<N1, TRef>>,
                _gen: &dyn JitCodeGenerator,
                _type_: MpIntJitType,
                _ext: Ext,
                _scope: &dyn Scope,
            ) -> Emitter<N1> {
                unimplemented!(concat!($java, "::genStoreFromArray is not ported yet"))
            }

            fn subpiece(
                &self,
                _endian: Endian,
                _byte_offset: i32,
                _max_byte_size: i32,
            ) -> Box<dyn VarHandler> {
                unimplemented!(concat!($java, "::subpiece is not ported yet"))
            }
        }
    };
}

/// Placeholder for the unported Java record `IntVarAlloc`
/// (`ghidra.pcode.emu.jit.alloc.IntVarAlloc`): the handler for a p-code variable allocated in one
/// JVM `int`. Referenced by
/// [`sub_handler`](crate::pcode::emu::jit::alloc::aligned_mp_int_handler::sub_handler), which sits
/// on a dependency cycle with it.
///
/// Java's record is `IntVarAlloc(JvmLocal<TInt, IntJitType> local, IntJitType type)`; `vn()` comes
/// from `SimpleVarHandler`, i.e., `local.vn()`. Both members are carried, so `vn()`/`type_()`/
/// `name()` are real; the generators are not (see
/// [`unported_handler_var_handler_impl`]).
#[derive(Debug, Clone)]
pub struct IntVarAlloc {
    /// The JVM local. Port of `IntVarAlloc.local()`.
    pub local: JvmLocal,
    /// The p-code type. Port of `IntVarAlloc.type()`.
    pub type_: IntJitType,
    /// The complete varnode, i.e., `local.vn()`, which is what `SimpleVarHandler.vn()` returns.
    pub vn: Varnode,
}

impl IntVarAlloc {
    /// Port of the canonical record constructor `new IntVarAlloc(local, type)`.
    pub fn new(local: JvmLocal, type_: IntJitType) -> Self {
        let vn = local.vn.clone();
        Self { local, type_, vn }
    }
}

unported_handler_var_handler_impl!(IntVarAlloc, "IntVarAlloc", AnyJitType::Int);

/// Placeholder for the unported Java record `IntInIntHandler`
/// (`ghidra.pcode.emu.jit.alloc.IntInIntHandler`): the handler for an `int` p-code variable stored
/// in part of a JVM `int`. Referenced by
/// [`sub_handler`](crate::pcode::emu::jit::alloc::aligned_mp_int_handler::sub_handler), which sits
/// on a dependency cycle with it.
///
/// Java's record is `IntInIntHandler(JvmLocal<TInt, IntJitType> local, IntJitType type, Varnode vn,
/// int byteShift)`, whose compact constructor calls `SubVarHandler.assertShiftFits`; this
/// placeholder keeps that check by calling the already-ported
/// [`assert_shift_fits`](crate::pcode::emu::jit::alloc::sub_var_handler::assert_shift_fits).
#[derive(Debug, Clone)]
pub struct IntInIntHandler {
    /// The containing JVM local. Port of `IntInIntHandler.local()`.
    pub local: JvmLocal,
    /// The p-code type of the sub variable. Port of `IntInIntHandler.type()`.
    pub type_: IntJitType,
    /// The sub variable's varnode. Port of `IntInIntHandler.vn()`.
    pub vn: Varnode,
    /// The number of unused bytes to the right of the sub variable. Port of
    /// `IntInIntHandler.byteShift()`.
    pub byte_shift: i32,
}

impl IntInIntHandler {
    /// Port of the canonical record constructor `new IntInIntHandler(local, type, vn, byteShift)`,
    /// including its compact constructor's `assertShiftFits`.
    pub fn new(local: JvmLocal, type_: IntJitType, vn: Varnode, byte_shift: i32) -> Self {
        crate::pcode::emu::jit::alloc::sub_var_handler::assert_shift_fits(
            byte_shift,
            type_.erase_simple(),
            &local,
        );
        Self { local, type_, vn, byte_shift }
    }
}

unported_handler_var_handler_impl!(IntInIntHandler, "IntInIntHandler", AnyJitType::Int);

/// Placeholder for the unported Java record `ShiftedMpIntHandler`
/// (`ghidra.pcode.emu.jit.alloc.ShiftedMpIntHandler`): the handler for a multi-precision integer
/// whose legs are *not* aligned to the legs of the JVM locals holding it. Referenced by
/// [`sub_handler`](crate::pcode::emu::jit::alloc::aligned_mp_int_handler::sub_handler), which sits
/// on a dependency cycle with it.
///
/// Java's record is `ShiftedMpIntHandler(List<JvmLocal<TInt, IntJitType>> parts, MpIntJitType type,
/// Varnode vn, int byteShift)`, whose compact constructor asserts `0 < byteShift < 4` and
/// `parts.size() > 1`; both are kept here as debug assertions, matching how
/// [`assert_shift_fits`](crate::pcode::emu::jit::alloc::sub_var_handler::assert_shift_fits) models
/// a Java `assert`.
#[derive(Debug, Clone)]
pub struct ShiftedMpIntHandler {
    /// The JVM locals holding the value, in little-endian order. Port of
    /// `ShiftedMpIntHandler.parts()`.
    pub parts: Vec<JvmLocal>,
    /// The p-code type of the full variable. Port of `ShiftedMpIntHandler.type()`.
    pub type_: MpIntJitType,
    /// The complete varnode. Port of `ShiftedMpIntHandler.vn()`.
    pub vn: Varnode,
    /// The number of bytes to shift right when loading the value. Port of
    /// `ShiftedMpIntHandler.byteShift()`.
    pub byte_shift: i32,
}

impl ShiftedMpIntHandler {
    /// Port of the canonical record constructor
    /// `new ShiftedMpIntHandler(parts, type, vn, byteShift)`, including its compact constructor's
    /// assertions.
    pub fn new(parts: Vec<JvmLocal>, type_: MpIntJitType, vn: Varnode, byte_shift: i32) -> Self {
        debug_assert!(byte_shift > 0 && byte_shift < 4);
        debug_assert!(parts.len() > 1);
        Self { parts, type_, vn, byte_shift }
    }
}

unported_handler_var_handler_impl!(ShiftedMpIntHandler, "ShiftedMpIntHandler", AnyJitType::MpInt);

/// Placeholder for the unported Java type `IntZExtOpGen`, referenced by `CopyOpGen`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait IntZExtOpGen: Send + Sync {
    fn is_signed(&self) -> bool;
}

/// Placeholder for the unported Java type `JitCopyOp`, referenced by `CopyOpGen`.
/// Port of `ghidra.pcode.emu.jit.op.JitCopyOp` (record type).
pub struct JitCopyOp {
    u: std::sync::Arc<dyn crate::pcode::emu::jit::var::JitVal>,
}

impl JitCopyOp {
    /// Port of the canonical record constructor.
    pub fn new(u: std::sync::Arc<dyn crate::pcode::emu::jit::var::JitVal>) -> Self {
        Self { u }
    }
}

impl JitOp for JitCopyOp {
    fn type_for(&self, _position: i32) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }

    fn link(&self) {}

    fn unlink(&self) {}
}

impl JitDefOp for JitCopyOp {
    fn out(&self) -> std::sync::Arc<dyn JitOutVar> {
        unimplemented!()
    }
}

impl crate::pcode::emu::jit::op::jit_un_op::JitUnOp for JitCopyOp {
    fn u(&self) -> std::sync::Arc<dyn crate::pcode::emu::jit::var::JitVal> {
        self.u.clone()
    }

    fn u_type(&self) -> JitTypeBehavior {
        JitTypeBehavior::Integer
    }
}

