//! Minimal placeholder types for core types that a ported interface under [`crate::pcode`]
//! references before the real Rust port of that type exists yet. Each stub exposes only the
//! members needed by the interface(s) that currently reference it, and is expected to be
//! replaced (or grown into a supertrait/struct of) the real port once that Java class is ported.
//! See `STUBS.tsv` for provenance.

use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::pcode::emu::jit::analysis::jit_analysis_context::JitAnalysisContext;
use crate::pcode::emu::jit::analysis::jit_type_behavior::JitTypeBehavior;

use crate::pcode::emu::jit::alloc::jvm_local::JvmLocal;
use crate::pcode::emu::jit::alloc::var_handler::VarHandler;
use crate::pcode::emu::jit::analysis::jit_control_flow_model::{BlockFlow, JitBlock};
use crate::pcode::emu::jit::analysis::jit_data_flow_arithmetic::JitDataFlowArithmetic;
use crate::pcode::emu::jit::analysis::jit_data_flow_block_analyzer::JitDataFlowBlockAnalyzer;
use crate::pcode::emu::jit::analysis::jit_type::{
    AnyJitType, AnySimpleJitType, DoubleJitType, FloatJitType, IntJitType, JitType, LongJitType,
    MpFloatJitType, MpIntJitType, SimpleJitType,
};
use crate::pcode::emu::jit::analysis::jit_var_scope_model::JitVarScopeModel;
use crate::pcode::emu::jit::gen::access::mp_access_gen::MpAccessGen;
use crate::pcode::emu::jit::gen::util::emitter::{Bot, Ent, Emitter, Next};
use crate::pcode::emu::jit::gen::util::local::Local;
use crate::pcode::emu::jit::gen::util::types::{BPrim, TInt, TRef};
use crate::pcode::emu::jit::op::{JitDefOp, JitOp, JitPhiOp};
use crate::pcode::emu::jit::var::{JitVal, JitVarnodeVar, JitOutVar};
use crate::pcode::emu::instruction_decoder::InstructionDecoder;
use crate::pcode::emu::jit::decode::decoder_userop_library::DecoderUseropLibrary;
use crate::pcode::emu::pcode_thread::ErasedPcodeThread;
use crate::pcode::emu::thread_pcode_executor_state::ThreadPcodeExecutorState;
use crate::pcode::emu::sys::emu_syscall_library::EmuSyscallDefinition;
use crate::pcode::exec::abstract_sleigh_pcode_userop_definition::AbstractSleighPcodeUseropDefinitionBase;
use crate::pcode::exec::concretion_error::ConcretionError;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_execution_exception::PcodeExecutionException;
use crate::pcode::exec::pcode_executor::PcodeExecutor;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::{
    ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
};
use crate::pcode::exec::pcode_frame::PcodeFrame;
use crate::pcode::exec::pcode_program::PcodeProgram;
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::pcode::exec::pcode_userop_library::{
    ErasedPcodeUseropLibrary, PcodeUseropDefinition, PcodeUseropLibrary, UseropMap,
};
use crate::pcode::exec::sleigh_pcode_userop_definition::{SignatureDef, SleighPcodeUseropDefinition};
use crate::pcode::exec::trace::data::pcode_trace_data_access::PcodeTraceDataAccess;
use crate::pcode::floatformat::big_float::{BigFloat, MathContext};
use crate::program::model::address::{
    Address, AddressRange, AddressSet, AddressSetView, AddressSpace, AddressSpaceType,
    SpecialAddress,
};
use crate::pcode::r#struct::lval_internal::LValInternal;
use crate::pcode::r#struct::rval_internal::RValInternal;
use crate::pcode::r#struct::string_tree::StringTree;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::prototype_model::PrototypeModel;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::listing::default_program_context::DefaultProgramContext;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::program_context::ProgramContext;
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::mem::mem_buffer::MemBuffer;
use crate::program::model::pcode::{OpCode, PcodeOp, SequenceNumber, Varnode};
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
///
/// Grown (see `STUBS.tsv`) with the two members
/// [`DecoderExecutor`](crate::pcode::emu::jit::decode::decoder_executor::DecoderExecutor) reads off
/// a decoded instruction. Both are defaulted so pre-existing bare
/// `impl PseudoInstruction for Foo {}` blocks keep compiling.
pub trait PseudoInstruction: Send + Sync {
    /// Stands in for the inherited `CodeUnit.getMaxAddress()`: the address of this instruction's
    /// last byte. Panics by default, since this stub carries neither the address nor the length
    /// the real class derives it from.
    fn get_max_address(&self) -> Address {
        unimplemented!("PseudoInstruction not yet ported")
    }

    /// Stands in for `instruction instanceof DecodeErrorInstruction err ? err.getMessage() : null`,
    /// which `DecoderExecutor` performs twice (once to skip flow-context computation, once to
    /// phrase the error branch's message). Rust has no downcast from a bare `dyn` trait object, so
    /// the test is folded into the accessor: [`DecodeErrorInstruction`] returns its message, and
    /// every normally-decoded instruction returns `None`.
    fn decode_error_message(&self) -> Option<&str> {
        None
    }
}

/// Placeholder for `ghidra.program.model.lang.RegisterValue`, referenced by
/// [`InstructionDecoder`](crate::pcode::emu::instruction_decoder::InstructionDecoder) before the
/// real class is ported. This is a minimal interface stub exposing only the methods needed by
/// existing references.
///
/// Grown (see `STUBS.tsv`) with the five members
/// [`DefaultPcodeThread`](crate::pcode::emu::default_pcode_thread::DefaultPcodeThread)'s context
/// handling and [`JitPassageDecoder`](crate::pcode::emu::jit::decode::jit_passage_decoder::JitPassageDecoder)'s
/// `AddrCtx` construction need. All five are defaulted so pre-existing bare
/// `impl RegisterValue for Foo {}` blocks keep compiling; the defaults panic, since the real class
/// carries the value and mask this stub does not.
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

    /// Stands in for `RegisterValue.getUnsignedValue()`: this value as an unsigned integer
    /// (`BigInteger` in Java, `i128` here per the crate-wide convention).
    fn get_unsigned_value(&self) -> i128 {
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
    try_catch_blocks: Vec<(Label, Label, Label, String)>,
    line_numbers: Vec<(i32, Label)>,
    maxs: Option<(i32, i32)>,
    ended: bool,
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

    /// Stands in for `visitTryCatchBlock(start, end, handler, type)`.
    pub fn visit_try_catch_block(&mut self, start: Label, end: Label, handler: Label, ty: &str) {
        self.try_catch_blocks.push((start, end, handler, ty.to_string()));
    }

    /// Every `try`-`catch` block recorded so far.
    pub fn try_catch_blocks(&self) -> &[(Label, Label, Label, String)] {
        &self.try_catch_blocks
    }

    /// Stands in for `visitLineNumber(line, start)`.
    pub fn visit_line_number(&mut self, line: i32, start: Label) {
        self.line_numbers.push((line, start));
    }

    /// Every line-number entry recorded so far.
    pub fn line_numbers(&self) -> &[(i32, Label)] {
        &self.line_numbers
    }

    /// Stands in for `visitMaxs(maxStack, maxLocals)`.
    pub fn visit_maxs(&mut self, max_stack: i32, max_locals: i32) {
        self.maxs = Some((max_stack, max_locals));
    }

    /// The arguments most recently passed to [`visit_maxs`](Self::visit_maxs), if any.
    pub fn maxs(&self) -> Option<(i32, i32)> {
        self.maxs
    }

    /// Stands in for `visitEnd()`.
    pub fn visit_end(&mut self) {
        self.ended = true;
    }

    /// Whether [`visit_end`](Self::visit_end) has been called.
    pub fn ended(&self) -> bool {
        self.ended
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

    /// Stand-in for `block.flowsTo()`, a method Java puts on `JitControlFlowModel.JitBlock` --
    /// which this crate's [`JitBlock`] cannot carry, being deliberately identity-only (see that
    /// type's doc; the flows live in
    /// [`BlockTable`](crate::pcode::emu::jit::analysis::BlockTable)). Relocated here since
    /// `JitDataFlowModel` is the nearest already-stubbed type with a view of the control-flow
    /// graph: real Java's `JitDataFlowModel` holds the
    /// [`JitControlFlowModel`](crate::pcode::emu::jit::analysis::JitControlFlowModel) that backs
    /// this data, and this collapses into `cfm.flows_to(block)` once `JitDataFlowModel.java` is
    /// ported. Defaults to no known inward flows.
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

    /// Port of `JitDataFlowModel.allValues()`: every value (variable or constant) in the use-def
    /// graph.
    ///
    /// Grown (see `STUBS.tsv`) for
    /// [`JitTypeModel`](crate::pcode::emu::jit::analysis::jit_type_model::JitTypeModel), which
    /// seeds its voting queue with it. Java's `Set<JitVal>` is a `Vec` here: the type model only
    /// iterates it, and the elements are already distinct by identity. See
    /// [`Self::get_arithmetic`] for why this defaults to `unimplemented!`.
    fn all_values(&self) -> Vec<Arc<dyn JitVal>> {
        unimplemented!("JitDataFlowModel::all_values stub")
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

/// Placeholder for the unported Java type `JitCompiledPassage`, referenced by `InstanceFieldReq`
/// and by [`EntryPoint`]. Generated stub: only a shape hint. Implementations are generated
/// classfiles, so the one method declared here -- the generated `run(int)` that
/// [`EntryPoint::run`] invokes -- has no body to port and panics by default.
pub trait JitCompiledPassage: Send + Sync {
    /// Run the compiled passage of code, entering at the given block.
    ///
    /// Placeholder for `JitCompiledPassage.run(int)`. Except during testing, this is ordinarily
    /// called by [`EntryPoint::run`]. It returns the next entry point, at which execution left this
    /// passage, and throws `SuspendedPcodeExecutionException` when
    /// [`JitPcodeThread::count`](crate::pcode::emu::jit::jit_pcode_thread::JitPcodeThread::count)
    /// interrupts it.
    fn run(&self, block_id: i32) -> Result<EntryPoint, SuspendedPcodeExecutionException> {
        let _ = block_id;
        unimplemented!("JitCompiledPassage implementations are generated code; not yet ported")
    }
}

/// Placeholder for the unported nested Java type `JitCompiledPassage.EntryPointPrototype`,
/// referenced by
/// [`JitCompiledPassageClass::get_block_entries`](crate::pcode::emu::jit::gen::tgt::JitCompiledPassageClass::get_block_entries)
/// as the value type of the map it builds from the passage's entry list. The real class also
/// caches a bound `EntryPoint` per thread (`createInstance`), but that cache and its `EntryPoint`
/// companion belong to the (also unported) enclosing `JitCompiledPassage`, so this stub carries
/// only the two identity fields `get_block_entries` sets: the owning class and the target block
/// id. Replace with the real port when `JitCompiledPassage.java` lands.
#[derive(Clone)]
pub struct EntryPointPrototype {
    /// The compiled passage class this prototype belongs to. Port of
    /// `EntryPointPrototype.cls`.
    pub cls: crate::pcode::emu::jit::gen::tgt::JitCompiledPassageClass,
    /// The block at which to enter the passage. Port of `EntryPointPrototype.blockId`.
    pub block_id: i32,
}

impl EntryPointPrototype {
    /// Port of `new EntryPointPrototype(JitCompiledPassageClass, int)`.
    pub fn new(
        cls: crate::pcode::emu::jit::gen::tgt::JitCompiledPassageClass,
        block_id: i32,
    ) -> Self {
        Self { cls, block_id }
    }

    /// Create the entry point for the given thread, by instantiating this prototype's compiled
    /// passage class for it.
    ///
    /// Placeholder for `EntryPointPrototype.createInstance(JitPcodeThread)`, called from
    /// [`JitPcodeThread::get_entry`](crate::pcode::emu::jit::jit_pcode_thread::JitPcodeThread::get_entry).
    /// Java also memoizes the result in a per-thread map on the prototype; that cache is dropped
    /// here, since the calling thread caches the same entry point by `AddrCtx` itself. Keying a map
    /// by thread would additionally need an identity for
    /// [`JitPcodeThread`](crate::pcode::emu::jit::jit_pcode_thread::JitPcodeThread), which is a
    /// value here, not a reference.
    pub fn create_instance(
        &self,
        thread: &crate::pcode::emu::jit::jit_pcode_thread::JitPcodeThread,
    ) -> EntryPoint {
        EntryPoint::new(self.clone(), Arc::from(self.cls.create_instance(thread)), self.block_id)
    }
}

/// Placeholder for the unported nested Java record `JitCompiledPassage.EntryPoint`, the translated
/// passage instantiated for one thread together with the index of the block at which to enter it.
/// Produced by [`EntryPointPrototype::create_instance`] and cached by
/// [`JitPcodeThread`](crate::pcode::emu::jit::jit_pcode_thread::JitPcodeThread), whose execution
/// loop drives it. Its own body is fully ported -- [`run`](Self::run) is a one-line delegation --
/// but it belongs to the unported enclosing `JitCompiledPassage`, whose generated `run(int)` it
/// calls. Replace with the real port when `JitCompiledPassage.java` lands.
#[derive(Clone)]
pub struct EntryPoint {
    /// The entry point prototype (passage class and blockId without bound thread). Port of
    /// `EntryPoint.prototype`.
    pub prototype: EntryPointPrototype,
    /// The compiled passage, instantiated for the bound thread. Port of `EntryPoint.passage`,
    /// shared rather than owned because a thread's code cache and its caller both hold the entry.
    pub passage: Arc<dyn JitCompiledPassage>,
    /// An index identifying the block at the target address and contextreg value of this entry
    /// point. Port of `EntryPoint.blockId`.
    pub block_id: i32,
}

impl EntryPoint {
    /// Port of the record constructor `new EntryPoint(EntryPointPrototype, JitCompiledPassage,
    /// int)`.
    pub fn new(
        prototype: EntryPointPrototype,
        passage: Arc<dyn JitCompiledPassage>,
        block_id: i32,
    ) -> Self {
        Self { prototype, passage, block_id }
    }

    /// Start/resume execution of the bound thread at this entry point.
    ///
    /// Port of `EntryPoint.run()`, i.e. `passage.run(blockId)`. Java's thrown
    /// `SuspendedPcodeExecutionException` is an `Err` here.
    pub fn run(&self) -> Result<EntryPoint, SuspendedPcodeExecutionException> {
        self.passage.run(self.block_id)
    }
}

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

/// Placeholder for `ghidra.pcode.exec.DecodePcodeExecutionException`, referenced by
/// [`JitPassageDecoder`](crate::pcode::emu::jit::decode::jit_passage_decoder::JitPassageDecoder),
/// which catches it specifically (letting any other exception from decode propagate) and converts
/// it into a [`DecodeErrorInstruction`]. Real class also carries the program counter where decode
/// was attempted; not needed by that catch site, so only the message is kept.
#[derive(Debug)]
pub struct DecodePcodeExecutionException {
    message: String,
}

impl DecodePcodeExecutionException {
    /// Construct an exception with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }

    /// Stands in for the inherited `Throwable.getMessage()`.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for DecodePcodeExecutionException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for DecodePcodeExecutionException {}

/// Placeholder for `ghidra.app.util.PseudoInstruction`'s subtype
/// `ghidra.pcode.emu.jit.JitPassage.DecodeErrorInstruction`, returned by
/// [`JitPassage::decode_error`] and, in turn, by
/// [`JitPassageDecoder::decode_instruction`](crate::pcode::emu::jit::decode::jit_passage_decoder::JitPassageDecoder::decode_instruction)
/// when the underlying decoder reports a [`DecodePcodeExecutionException`]. Real class builds a
/// single-byte "instruction" whose translated p-code throws
/// [`DecodePcodeExecutionException`] with `message` if ever executed; that translation isn't
/// ported, so this stub keeps only the message the real constructor also just stores.
#[derive(Debug, Clone)]
pub struct DecodeErrorInstruction {
    message: String,
}

impl DecodeErrorInstruction {
    /// Port of `new DecodeErrorInstruction(Language, Address, RegisterValue, String)`. The
    /// language, address, and context select the (unported) translated p-code and are not needed
    /// to answer [`message`](Self::message), the only member any current call site reads.
    pub fn new(
        _language: Arc<dyn Language>,
        _address: Address,
        _ctx: Option<&dyn RegisterValue>,
        message: impl Into<String>,
    ) -> Self {
        Self { message: message.into() }
    }

    /// Port of `DecodeErrorInstruction.getMessage()`.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl PseudoInstruction for DecodeErrorInstruction {
    /// This *is* the `DecodeErrorInstruction` case of the `instanceof` test
    /// [`PseudoInstruction::decode_error_message`] stands in for, so it always reports a message.
    fn decode_error_message(&self) -> Option<&str> {
        Some(&self.message)
    }
}

/// Placeholder for the unported Java type `ghidra.pcode.emu.jit.JitPassage`, the decoded output of
/// [`JitPassageDecoder::decode_passage`](crate::pcode::emu::jit::decode::jit_passage_decoder::JitPassageDecoder::decode_passage).
/// Real class holds every instruction, p-code op, and branch record of a decoded passage -- far
/// beyond a stub -- built by the also-unported [`DecoderForOnePassage`]. This models only what
/// `JitPassageDecoder` itself references directly: the nested [`AddrCtx`] address-context pair and
/// the [`decode_error`](Self::decode_error) factory. Replace with the real port (and drop this
/// placeholder) when `JitPassage.java` lands.
///
/// Grown (see `STUBS.tsv`) with an optional `language` for
/// [`JitAnalysisContext`](crate::pcode::emu::jit::analysis::jit_analysis_context::JitAnalysisContext),
/// whose real constructor reads `passage.getLanguage()`. `None` (via [`Self::placeholder`]) for
/// every current caller, since nothing yet builds a `JitPassage` outside a panicking stub path;
/// `Some` (via [`Self::for_language`]) once a caller actually has one.
#[derive(Clone)]
pub struct JitPassage {
    language: Option<Arc<SleighLanguage>>,
}

impl JitPassage {
    /// A `JitPassage` carrying only the given language, for callers (such as
    /// [`JitAnalysisContext`](crate::pcode::emu::jit::analysis::jit_analysis_context::JitAnalysisContext))
    /// that need `getLanguage()` to answer before the rest of this type is ported.
    pub fn for_language(language: Arc<SleighLanguage>) -> Self {
        Self { language: Some(language) }
    }

    /// A `JitPassage` carrying no data at all, for callers that need *a* passage value but never
    /// read anything back out of it.
    pub fn placeholder() -> Self {
        Self { language: None }
    }

    /// Check if the given op has fall-through.
    ///
    /// Port of the static `JitPassage.hasFallthrough(PcodeOp)`. Grown (see `STUBS.tsv`) for
    /// [`BlockSplitter`](crate::pcode::emu::jit::analysis::BlockSplitter), which asks it of each
    /// block's last op to decide whether to synthesize a fall-through branch.
    ///
    /// Java answers `true` for a `NopPcodeOp` before consulting the opcode, because a synthetic nop
    /// carries the `UNIMPLEMENTED` opcode but does fall through. This crate builds nops as plain
    /// [`PcodeOp`]s (see [`nop_pcode_op`]), so there is nothing to distinguish one from a genuinely
    /// unimplemented instruction, and a nop reports no fall-through here. That resolves once
    /// `JitPassage`'s op hierarchy is ported.
    pub fn has_fallthrough(op: &PcodeOp) -> bool {
        !matches!(
            op.opcode,
            OpCode::Branch
                | OpCode::BranchInd
                | OpCode::Call
                | OpCode::CallInd
                | OpCode::Return
                | OpCode::Unimplemented
        )
    }

    /// Port of the static factory `JitPassage.decodeError(Language, Address, RegisterValue,
    /// String)`: build the "instruction" standing in for a decode failure at `address`.
    pub fn decode_error(
        language: Arc<dyn Language>,
        address: Address,
        ctx: Option<&dyn RegisterValue>,
        message: impl Into<String>,
    ) -> DecodeErrorInstruction {
        DecodeErrorInstruction::new(language, address, ctx, message)
    }

    /// Port of `JitPassage.getLanguage()`. Panics if built via [`Self::placeholder`]; every current
    /// caller instead builds via [`Self::for_language`]. See the type-level doc.
    pub fn get_language(&self) -> Arc<SleighLanguage> {
        self.language
            .clone()
            .expect("JitPassage::get_language: placeholder built without a language")
    }

    /// Port of `JitPassage.getOpEntry(PcodeOp)`: the address-context pair at which `op`'s
    /// instruction begins, or the passage's own entry if `op` opens the passage. Not yet ported --
    /// real answer depends on the decoded op/instruction data this stub does not carry.
    pub fn get_op_entry(&self, _op: &PcodeOp) -> AddrCtx {
        unimplemented!("JitPassage::get_op_entry not yet ported")
    }

    /// Port of `JitPassage.getErrorMessage(PcodeOp)`: the message of the decode error `op`
    /// represents. Not yet ported -- real answer depends on the decoded error-instruction data this
    /// stub does not carry.
    pub fn get_error_message(&self, _op: &PcodeOp) -> String {
        unimplemented!("JitPassage::get_error_message not yet ported")
    }
}

/// Port of the nested `ghidra.pcode.emu.jit.JitPassage.AddrCtx` record: an address paired with the
/// contextreg value in effect when decode reaches it. Modelled as a free-standing type here since
/// Rust has no static nested class; see [`JitPassage`] for the type it nests under in Java.
///
/// Not `Debug`: `rv_ctx` is `Option<Arc<dyn RegisterValue>>`, and the stub trait doesn't require
/// `Debug` of its implementors.
#[derive(Clone)]
pub struct AddrCtx {
    /// The contextreg value as an unsigned integer, or `0` when `rv_ctx` is `None`. Port of
    /// `AddrCtx.biCtx`.
    pub bi_ctx: i128,
    /// The contextreg value, or `None` when the language has no context register. Port of
    /// `AddrCtx.rvCtx`.
    pub rv_ctx: Option<Arc<dyn RegisterValue>>,
    /// The address. Port of `AddrCtx.address`.
    pub address: Address,
}

impl AddrCtx {
    /// Port of `new AddrCtx(RegisterValue, Address)`.
    pub fn new(ctx: Option<Arc<dyn RegisterValue>>, address: Address) -> Self {
        let bi_ctx = ctx.as_deref().map(RegisterValue::get_unsigned_value).unwrap_or(0);
        Self { bi_ctx, rv_ctx: ctx, address }
    }

    /// The address-context pair standing for "no target at all", used to probe an instruction
    /// step's control flow for fall through. Port of the constant
    /// `AddrCtx.NOWHERE = new AddrCtx(null, Address.NO_ADDRESS)`; a function rather than a `const`
    /// because [`Address`] owns an `Arc<AddressSpace>`.
    pub fn nowhere() -> Self {
        Self::new(None, SpecialAddress::no_address())
    }
}

/// Port of `AddrCtx.equals(Object)`: compares `biCtx` and `address` only, ignoring `rvCtx` (the
/// `RegisterValue` the context was derived from -- `biCtx` already captures its value).
impl PartialEq for AddrCtx {
    fn eq(&self, other: &Self) -> bool {
        self.bi_ctx == other.bi_ctx && self.address == other.address
    }
}

impl Eq for AddrCtx {}

/// Port of `AddrCtx.toString()`: `"AddrCtx[ctx=%s,addr=%s]".formatted(rvCtx, address)`. `rvCtx` is
/// an `Option<Arc<dyn RegisterValue>>` and the stub trait doesn't require `Display` of its
/// implementors, so the context prints as `bi_ctx`, the value `rvCtx` was reduced to -- or as
/// `null`, matching Java's rendering of a null `rvCtx`, when there is none.
impl std::fmt::Display for AddrCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.rv_ctx {
            Some(_) => write!(f, "AddrCtx[ctx={},addr={}]", self.bi_ctx, self.address),
            None => write!(f, "AddrCtx[ctx=null,addr={}]", self.address),
        }
    }
}

/// Port of `AddrCtx.hashCode()`: `Objects.hash(biCtx, address)`.
impl std::hash::Hash for AddrCtx {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.bi_ctx.hash(state);
        self.address.hash(state);
    }
}

/// Placeholder for ASM's `org.objectweb.asm.MethodTooLargeException`, raised when a generated
/// method exceeds the JVM's 64KiB code limit. Its only role here is to be the error
/// [`JitCompiler::compile_passage`](crate::pcode::emu::jit::jit_compiler::JitCompiler::compile_passage)
/// reports so that
/// [`JitPcodeEmulator`](crate::pcode::emu::jit::jit_pcode_emulator::JitPcodeEmulator)'s backoff
/// loop can retry with half the op budget, so it carries no payload; ASM's `methodName`,
/// `descriptor`, and `codeSize` are not consulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodTooLargeException;

impl std::fmt::Display for MethodTooLargeException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Method too large")
    }
}

impl std::error::Error for MethodTooLargeException {}

/// Placeholder for the unported Java class `ghidra.pcode.emu.jit.JitDefaultBytesPcodeExecutorState`,
/// the state
/// [`JitPcodeEmulator`](crate::pcode::emu::jit::jit_pcode_emulator::JitPcodeEmulator) creates for
/// both its shared and its per-thread states. The real class is a `DefaultPcodeExecutorState`
/// wrapping a `JitBytesPcodeExecutorStatePiece`, whose per-address-space
/// `JitBytesPcodeExecutorStateSpace`s the generated code pre-fetches directly; none of that is
/// ported, so, exactly as with [`BytesPcodeExecutorState`], only the language is retained and every
/// operation needing real storage panics.
pub struct JitDefaultBytesPcodeExecutorState {
    language: Arc<SleighLanguage>,
}

impl JitDefaultBytesPcodeExecutorState {
    /// Placeholder for `new JitDefaultBytesPcodeExecutorState(Language, PcodeStateCallbacks)`. As
    /// with [`BytesPcodeExecutorState::new`], the callbacks aren't retained: without real
    /// per-address-space storage to read or write, there is nothing to forward them to.
    pub fn new<C: PcodeStateCallbacks>(language: Arc<SleighLanguage>, _cb: C) -> Self {
        Self { language }
    }

    /// The language this state was created for. Java gets at it through the wrapped piece.
    pub fn language(&self) -> &Arc<SleighLanguage> {
        &self.language
    }
}

impl PcodeExecutorStatePiece<Vec<u8>, Vec<u8>> for JitDefaultBytesPcodeExecutorState {
    fn get_language(&self) -> Box<dyn Language> {
        unimplemented!("JitDefaultBytesPcodeExecutorState not yet ported")
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
        unimplemented!("JitDefaultBytesPcodeExecutorState not yet ported")
    }

    fn set_var_internal_abstract(
        &mut self,
        _space: &Arc<AddressSpace>,
        _offset: &Vec<u8>,
        _size: i32,
        _val: &Vec<u8>,
    ) {
        unimplemented!("JitDefaultBytesPcodeExecutorState not yet ported")
    }

    fn get_var_abstract(
        &self,
        _space: &Arc<AddressSpace>,
        _offset: &Vec<u8>,
        _size: i32,
        _quantize: bool,
        _reason: Reason,
    ) -> Vec<u8> {
        unimplemented!("JitDefaultBytesPcodeExecutorState not yet ported")
    }

    fn get_var_internal_abstract(
        &self,
        _space: &Arc<AddressSpace>,
        _offset: &Vec<u8>,
        _size: i32,
        _reason: Reason,
    ) -> Vec<u8> {
        unimplemented!("JitDefaultBytesPcodeExecutorState not yet ported")
    }

    fn get_register_values(&self) -> Vec<(RegisterRef, Vec<u8>)> {
        vec![]
    }

    fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
        unimplemented!("JitDefaultBytesPcodeExecutorState not yet ported")
    }

    fn clear(&mut self) {}
}

impl PcodeExecutorState<Vec<u8>> for JitDefaultBytesPcodeExecutorState {}

/// Placeholder for the unported Java class `ghidra.pcode.emu.jit.JitThreadBytesPcodeExecutorState`,
/// the state
/// [`JitPcodeThread::create_thread_state`](crate::pcode::emu::jit::jit_pcode_thread::JitPcodeThread::create_thread_state)
/// multiplexes for a thread. Java `extends ThreadPcodeExecutorState<byte[]>`, narrowing both halves
/// to [`JitDefaultBytesPcodeExecutorState`], which is exactly what this stub wraps. Its remaining
/// method, `getForSpace(AddressSpace)`, routes to the local or shared half by whether the space is
/// thread-local; it needs `JitBytesPcodeExecutorStateSpace`, which is not ported, so it is left to
/// the real port.
pub struct JitThreadBytesPcodeExecutorState {
    inner: ThreadPcodeExecutorState<
        Vec<u8>,
        JitDefaultBytesPcodeExecutorState,
        JitDefaultBytesPcodeExecutorState,
    >,
}

impl JitThreadBytesPcodeExecutorState {
    /// Placeholder for `new JitThreadBytesPcodeExecutorState(JitDefaultBytesPcodeExecutorState,
    /// JitDefaultBytesPcodeExecutorState)`, whose body is `super(sharedState, localState)`.
    pub fn new(
        shared_state: JitDefaultBytesPcodeExecutorState,
        local_state: JitDefaultBytesPcodeExecutorState,
    ) -> Self {
        Self { inner: ThreadPcodeExecutorState::new(shared_state, local_state) }
    }

    /// Placeholder for `getSharedState()`, narrowed from the superclass's.
    pub fn get_shared_state(&self) -> &JitDefaultBytesPcodeExecutorState {
        self.inner.get_shared_state()
    }

    /// Placeholder for `getLocalState()`, narrowed from the superclass's.
    pub fn get_local_state(&self) -> &JitDefaultBytesPcodeExecutorState {
        self.inner.get_local_state()
    }
}

/// Placeholder for the unported Java class `ghidra.pcode.emu.jit.decode.DecoderForOnePassage`,
/// referenced by
/// [`JitPassageDecoder::decode_passage`](crate::pcode::emu::jit::decode::jit_passage_decoder::JitPassageDecoder::decode_passage)
/// and by
/// [`DecoderForOneStride`](crate::pcode::emu::jit::decode::decoder_for_one_stride::DecoderForOneStride),
/// which reads/writes `otherBranches` and `firstOps` directly (they're package-private fields in
/// Java). Real class implements the whole fetch-decode-translate seed-queue algorithm described on
/// `JitPassageDecoder`'s docs -- far beyond a stub -- so
/// [`decode_passage`](Self::decode_passage)/[`finish`](Self::finish) panic if actually invoked.
/// Replace with the real port when `DecoderForOnePassage.java` lands.
pub struct DecoderForOnePassage<'a> {
    #[allow(dead_code)]
    decoder: &'a crate::pcode::emu::jit::decode::jit_passage_decoder::JitPassageDecoder,
    #[allow(dead_code)]
    seed: AddrCtx,
    #[allow(dead_code)]
    max_ops: i32,
    /// Port of `DecoderForOnePassage.otherBranches` (`Map<PcodeOp, PBranch>`).
    pub(crate) other_branches: HashMap<PcodeOp, PBranch>,
    /// Port of `DecoderForOnePassage.internalBranches` (`Map<PcodeOp, RIntBranch>`).
    pub(crate) internal_branches: HashMap<PcodeOp, RIntBranch>,
    /// Port of `DecoderForOnePassage.externalBranches` (`Map<PcodeOp, RExtBranch>`), the queue of
    /// not-yet-decoded seeds. Only [`flow_to`](Self::flow_to) writes it here; the real class also
    /// drains it, which is part of the unported passage algorithm.
    pub(crate) external_branches: HashMap<PcodeOp, RExtBranch>,
    /// Port of `DecoderForOnePassage.firstOps` (`Map<AddrCtx, PcodeOp>`).
    pub(crate) first_ops: HashMap<AddrCtx, PcodeOp>,
}

impl<'a> DecoderForOnePassage<'a> {
    /// Port of `new DecoderForOnePassage(JitPassageDecoder, AddrCtx, int)`.
    pub fn new(
        decoder: &'a crate::pcode::emu::jit::decode::jit_passage_decoder::JitPassageDecoder,
        seed: AddrCtx,
        max_ops: i32,
    ) -> Self {
        Self {
            decoder,
            seed,
            max_ops,
            other_branches: HashMap::new(),
            internal_branches: HashMap::new(),
            external_branches: HashMap::new(),
            first_ops: HashMap::new(),
        }
    }

    /// Port of `DecoderForOnePassage.decodePassage()`.
    pub fn decode_passage(&mut self) {
        unimplemented!("DecoderForOnePassage not yet ported")
    }

    /// Port of `DecoderForOnePassage.finish()`.
    pub fn finish(self) -> JitPassage {
        unimplemented!("DecoderForOnePassage not yet ported")
    }

    /// Record an external branch, converting it to an internal one if its target has already been
    /// decoded into this passage, or queueing the target as a new seed if not. A branch that can
    /// only be reached through a dynamic context modification is never resolved internally: the
    /// context-modifying userop will already have retired and rewritten the context.
    ///
    /// Port of `DecoderForOnePassage.flowTo(RExtBranch)` -- real code, not a stub: it needs only
    /// the three maps above.
    pub(crate) fn flow_to(&mut self, eb: RExtBranch) {
        if !eb.reach.can_reach_without_ctx_mod() {
            self.other_branches.insert(eb.from.clone(), PBranch::Ext(eb));
            return;
        }
        match self.first_ops.get(&eb.to) {
            Some(to) => {
                let to = to.clone();
                self.internal_branches.insert(eb.from.clone(), eb.to_int_branch(to));
            }
            None => {
                self.external_branches.insert(eb.from.clone(), eb);
            }
        }
    }

    /// Get the decoder-wrapped userop library.
    ///
    /// Port of `DecoderForOnePassage.library()`, which returns `decoder.library` -- the passage
    /// decoder's one wrapped library, not a per-passage object.
    pub(crate) fn library(&self) -> &DecoderUseropLibrary {
        self.decoder.library()
    }
}

/// Port of the nested `ghidra.pcode.emu.jit.JitPassage.Reachability` enum: describes how a block
/// is reachable wrt. dynamic (userop-driven) context modifications within an instruction step.
/// Referenced by
/// [`DecoderForOneStride`](crate::pcode::emu::jit::decode::decoder_for_one_stride::DecoderForOneStride),
/// which only matches on the three variants. Replace with the real port when `JitPassage.java`
/// lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reachability {
    /// There is at least one path to reach it. None of them modify the context dynamically. Port
    /// of `Reachability.WITHOUT_CTXMOD`.
    WithoutCtxmod,
    /// There are at least two paths to reach it. Some modify the context dynamically, and some do
    /// not. Port of `Reachability.MAYBE_CTXMOD`.
    MaybeCtxmod,
    /// There is at least one path to reach it. All of them modify the context dynamically. Port of
    /// `Reachability.WITH_CTXMOD`.
    WithCtxmod,
}

impl Reachability {
    /// Consider this and another reachability as "or".
    ///
    /// Port of the abstract `Reachability.combine(Reachability)`, whose three per-constant bodies
    /// collapse into this one match. `that` is `Option` because Java's `case null` arm is
    /// load-bearing: `DecoderExecutor` combines against a map lookup that may miss.
    pub fn combine(self, that: Option<Reachability>) -> Reachability {
        let Some(that) = that else {
            return self;
        };
        match (self, that) {
            (Reachability::WithoutCtxmod, Reachability::WithoutCtxmod) => {
                Reachability::WithoutCtxmod
            }
            (Reachability::WithCtxmod, Reachability::WithCtxmod) => Reachability::WithCtxmod,
            _ => Reachability::MaybeCtxmod,
        }
    }

    /// Check if it is possible for this block to be reached without a context modification, i.e.
    /// whether there exists *any* path to it that doesn't include a possible context modification.
    ///
    /// Port of the abstract `Reachability.canReachWithoutCtxMod()`.
    pub fn can_reach_without_ctx_mod(self) -> bool {
        !matches!(self, Reachability::WithCtxmod)
    }
}

/// Port of the nested `ghidra.pcode.emu.jit.JitPassage.RExtBranch` record: an [`ExtBranch`] (a
/// branch to an address-context pair outside the current step) as added to the passage, i.e. with
/// its intra-instruction [`Reachability`] resolved. Modelled as a free-standing type here since
/// Rust has no static nested class; see [`JitPassage`] for the type it nests under in Java.
pub struct RExtBranch {
    /// The op performing the branch. Port of `RExtBranch.from()`.
    pub from: PcodeOp,
    /// The target address-context pair. Port of `RExtBranch.to()`.
    pub to: AddrCtx,
    /// The intra-instruction reachability. Port of `RExtBranch.reach()`.
    pub reach: Reachability,
}

impl RExtBranch {
    /// Port of `new RExtBranch(PcodeOp, AddrCtx, Reachability)`.
    pub fn new(from: PcodeOp, to: AddrCtx, reach: Reachability) -> Self {
        Self { from, to, reach }
    }

    /// Convert this external branch into an internal one, for when its target turns out to have
    /// been decoded into this very passage. Port of `RExtBranch.toIntBranch(PcodeOp)`.
    pub fn to_int_branch(self, to: PcodeOp) -> RIntBranch {
        RIntBranch { from: self.from, to, is_fall: false, reach: self.reach }
    }
}

/// Port of the nested `ghidra.pcode.emu.jit.JitPassage.SExtBranch` record: an [`RExtBranch`] as
/// analyzed during one instruction step, i.e. before its intra-instruction [`Reachability`] is
/// known. See [`RExtBranch`] for the type both nest under in Java.
#[derive(Clone)]
pub struct SExtBranch {
    /// The op performing the branch. Port of `SExtBranch.from()`.
    pub from: PcodeOp,
    /// The target address-context pair. Port of `SExtBranch.to()`.
    pub to: AddrCtx,
}

impl SExtBranch {
    /// Port of `new SExtBranch(PcodeOp, AddrCtx)`.
    pub fn new(from: PcodeOp, to: AddrCtx) -> Self {
        Self { from, to }
    }

    /// Upgrade this branch to an [`RExtBranch`] for inclusion in the passage. Port of
    /// `SExtBranch.withReach(Reachability)`.
    pub fn with_reach(self, reach: Reachability) -> RExtBranch {
        RExtBranch::new(self.from, self.to, reach)
    }
}

/// Port of the nested `ghidra.pcode.emu.jit.JitPassage.SIntBranch` record: a branch to another
/// p-code op in the same passage, as analyzed during one instruction step.
#[derive(Clone)]
pub struct SIntBranch {
    /// The op performing the branch. Port of `SIntBranch.from()`.
    pub from: PcodeOp,
    /// The target op. Port of `SIntBranch.to()`.
    pub to: PcodeOp,
    /// Whether this branch represents a fall-through case. Port of `SIntBranch.isFall()`.
    pub is_fall: bool,
}

impl SIntBranch {
    /// Port of `new SIntBranch(PcodeOp, PcodeOp, boolean)`.
    pub fn new(from: PcodeOp, to: PcodeOp, is_fall: bool) -> Self {
        Self { from, to, is_fall }
    }

    /// Upgrade this branch to an [`RIntBranch`] for inclusion in the passage. Port of
    /// `SIntBranch.withReach(Reachability)`.
    pub fn with_reach(self, reach: Reachability) -> RIntBranch {
        RIntBranch { from: self.from, to: self.to, is_fall: self.is_fall, reach }
    }
}

/// Port of the nested `ghidra.pcode.emu.jit.JitPassage.RIntBranch` record: an [`SIntBranch`] as
/// added to the passage, i.e. with its intra-instruction [`Reachability`] resolved.
pub struct RIntBranch {
    /// The op performing the branch. Port of `RIntBranch.from()`.
    pub from: PcodeOp,
    /// The target op. Port of `RIntBranch.to()`.
    pub to: PcodeOp,
    /// Whether this branch represents a fall-through case. Port of `RIntBranch.isFall()`.
    pub is_fall: bool,
    /// The intra-instruction reachability. Port of `RIntBranch.reach()`.
    pub reach: Reachability,
}

/// Port of the nested `ghidra.pcode.emu.jit.JitPassage.SIndBranch` record: a branch to a dynamic
/// address, as analyzed during one instruction step.
#[derive(Clone)]
pub struct SIndBranch {
    /// The op performing the branch. Port of `SIndBranch.from()`.
    pub from: PcodeOp,
    /// The decode context after the branch is taken, or `None` when the language has no context
    /// register. Port of `SIndBranch.flowCtx()`.
    pub flow_ctx: Option<Arc<dyn RegisterValue>>,
}

impl SIndBranch {
    /// Port of `new SIndBranch(PcodeOp, RegisterValue)`.
    pub fn new(from: PcodeOp, flow_ctx: Option<Arc<dyn RegisterValue>>) -> Self {
        Self { from, flow_ctx }
    }

    /// Upgrade this branch to an [`RIndBranch`] for inclusion in the passage. Port of
    /// `SIndBranch.withReach(Reachability)`.
    pub fn with_reach(self, reach: Reachability) -> RIndBranch {
        RIndBranch { from: self.from, flow_ctx: self.flow_ctx, reach }
    }
}

/// Port of the nested `ghidra.pcode.emu.jit.JitPassage.RIndBranch` record: an [`SIndBranch`] as
/// added to the passage.
pub struct RIndBranch {
    /// The op performing the branch. Port of `RIndBranch.from()`.
    pub from: PcodeOp,
    /// The decode context after the branch is taken. Port of `RIndBranch.flowCtx()`.
    pub flow_ctx: Option<Arc<dyn RegisterValue>>,
    /// The intra-instruction reachability. Port of `RIndBranch.reach()`.
    pub reach: Reachability,
}

/// Port of the nested `ghidra.pcode.emu.jit.JitPassage.ErrBranch` record: a "branch" representing
/// an error -- a decode error, an unimplemented instruction, or a call to an undefined userop. The
/// error is only thrown if execution actually reaches it, so the decoder merely notes it here.
///
/// Unlike its siblings, this record needs no reachability upgrade: it implements both `SBranch` and
/// `PBranch` in Java, so it passes into the passage unchanged.
#[derive(Clone)]
pub struct ErrBranch {
    /// The op that would raise the error. Port of `ErrBranch.from()`.
    pub from: PcodeOp,
    /// The error message for the exception. Port of `ErrBranch.message()`.
    pub message: String,
}

impl ErrBranch {
    /// Port of `new ErrBranch(PcodeOp, String)`.
    pub fn new(from: PcodeOp, message: impl Into<String>) -> Self {
        Self { from, message: message.into() }
    }
}

/// Port of the nested `ghidra.pcode.emu.jit.JitPassage.SBranch` interface: a branch as analyzed
/// within an instruction step, before it is "upgraded" to a [`PBranch`] and added to the passage.
///
/// Java's sealed-by-convention interface hierarchy becomes an enum, since every consumer switches
/// over the concrete record types anyway. Enumerating them here also discharges Java's
/// `default -> throw new AssertionError()` arms.
#[derive(Clone)]
pub enum SBranch {
    /// An [`SIntBranch`].
    Int(SIntBranch),
    /// An [`SExtBranch`].
    Ext(SExtBranch),
    /// An [`SIndBranch`].
    Ind(SIndBranch),
    /// An [`ErrBranch`].
    Err(ErrBranch),
}

impl SBranch {
    /// Port of `Branch.from()`: the op performing the branch.
    pub fn from(&self) -> &PcodeOp {
        match self {
            SBranch::Int(b) => &b.from,
            SBranch::Ext(b) => &b.from,
            SBranch::Ind(b) => &b.from,
            SBranch::Err(b) => &b.from,
        }
    }

    /// Port of `Branch.isFall()`: whether this branch represents a fall-through case. Only
    /// [`SIntBranch`] can, matching Java, where the default is `false` and `SIntBranch` is the one
    /// record carrying the flag.
    pub fn is_fall(&self) -> bool {
        match self {
            SBranch::Int(b) => b.is_fall,
            _ => false,
        }
    }
}

/// Port of the nested `ghidra.pcode.emu.jit.JitPassage.PBranch` interface: a branch as analyzed
/// within a passage. See [`SBranch`] for why this is an enum.
pub enum PBranch {
    /// An [`RExtBranch`].
    Ext(RExtBranch),
    /// An [`RIndBranch`].
    Ind(RIndBranch),
    /// An [`ErrBranch`], which is already passage-level in Java.
    Err(ErrBranch),
}

impl PBranch {
    /// Port of `Branch.from()`: the op performing the branch.
    pub fn from(&self) -> &PcodeOp {
        match self {
            PBranch::Ext(b) => &b.from,
            PBranch::Ind(b) => &b.from,
            PBranch::Err(b) => &b.from,
        }
    }
}

/// Port of the nested `ghidra.pcode.emu.jit.JitPassage.ExitPcodeOp` class's `exit` factory: a
/// synthetic unconditional-branch op used to exit a translated passage at `at`. `ExitPcodeOp`
/// itself adds no state or behavior beyond its constructor, so it isn't modelled as a distinct
/// Rust type -- this just builds the equivalent [`PcodeOp`] directly. Port of `ExitPcodeOp.exit`.
pub fn exit_pcode_op(at: &AddrCtx) -> PcodeOp {
    PcodeOp::new(
        OpCode::Branch,
        SequenceNumber::new(at.address.clone(), 0),
        vec![Varnode::new(at.address.clone(), 0)],
        None,
    )
}

/// Port of `ExitPcodeOp.cond`: a synthetic conditional-branch op used where the decoder can't
/// statically resolve whether a context-modifying path was taken. See [`exit_pcode_op`].
pub fn cond_pcode_op(at: &AddrCtx) -> PcodeOp {
    PcodeOp::new(
        OpCode::CBranch,
        SequenceNumber::new(at.address.clone(), 0),
        vec![Varnode::new(at.address.clone(), 0)],
        None,
    )
}

/// Port of the nested `ghidra.pcode.emu.jit.JitPassage.NopPcodeOp` class's constructor: a
/// synthetic no-op used to hold a bookkeeping position (e.g. an instruction, or inject, that
/// emits no p-code). Like [`exit_pcode_op`], `NopPcodeOp` adds no state beyond its constructor,
/// so this just builds the equivalent [`PcodeOp`] directly. Port of `new NopPcodeOp(AddrCtx, int)`.
pub fn nop_pcode_op(at: &AddrCtx, seq: i32) -> PcodeOp {
    PcodeOp::new(OpCode::Unimplemented, SequenceNumber::new(at.address.clone(), seq), Vec::new(), None)
}

/// Placeholder for the unported Java type `ghidra.pcode.emu.jit.decode.DecodedStride`, referenced
/// by
/// [`DecoderForOneStride`](crate::pcode::emu::jit::decode::decoder_for_one_stride::DecoderForOneStride),
/// which builds and returns it. Java declares `instructions` as `List<Instruction>`, but the only
/// instructions `DecoderForOneStride` actually has on hand are the `PseudoInstruction`s it decodes
/// (`PseudoInstruction` doesn't yet implement the ported `Instruction` trait), so this stub uses
/// that instead. Replace with the real port (and the `Instruction` list) when `DecodedStride.java`
/// lands and `PseudoInstruction` is a real port.
pub struct DecodedStride {
    /// The address-context pair that seeded this stride. Port of `DecodedStride.start()`.
    pub start: AddrCtx,
    /// The instructions in decode order. Port of `DecodedStride.instructions()`. `Arc`, not `Box`,
    /// because Java hands the very same instruction object to both this list and the
    /// [`DecoderExecutor`](crate::pcode::emu::jit::decode::decoder_executor::DecoderExecutor) that
    /// decoded it.
    pub instructions: Vec<Arc<dyn PseudoInstruction>>,
    /// The p-code ops in decode/emit order. Port of `DecodedStride.ops()`.
    pub ops: Vec<PcodeOp>,
}

/// Placeholder for the unported Java type `ghidra.pcode.emu.sys.EmuInvalidSystemCallException`,
/// referenced by
/// [`EmuSyscallLibrary::syscall`](crate::pcode::emu::sys::emu_syscall_library::EmuSyscallLibrary::syscall),
/// which raises it when the emulated program requests a syscall number the library does not
/// define.
///
/// Java's class extends `EmuSystemException`, which extends `PcodeExecutionException`; neither
/// intermediate class is ported yet. Rust has no exception subtyping, so this carries only the
/// message Java's `EmuInvalidSystemCallException(long)` constructor builds, and converts into a
/// [`PcodeExecutionException`] at the throw site. Replace with the real port -- and its place in
/// whatever shape the `Emu*Exception` hierarchy takes -- when it lands.
pub struct EmuInvalidSystemCallException {
    message: String,
}

impl EmuInvalidSystemCallException {
    /// Port of `EmuInvalidSystemCallException(long number)`.
    pub fn for_number(number: i64) -> Self {
        Self { message: format!("Invalid system call number: {}", number) }
    }

    /// The detail message, as Java's `Throwable.getMessage()` would report it.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl From<EmuInvalidSystemCallException> for PcodeExecutionException {
    fn from(err: EmuInvalidSystemCallException) -> Self {
        PcodeExecutionException::with_message(err.message)
    }
}

/// Placeholder for the unported Java type `ghidra.pcode.emu.sys.EmuIOException`, referenced by
/// [`EmuUnixFileDescriptor`](crate::pcode::emu::unix::emu_unix_file_descriptor::EmuUnixFileDescriptor)'s
/// `seek`, `read`, and `write` methods, which raise it on a simulated I/O error.
///
/// Java's class extends `EmuInvalidSystemCallException` (see above), whose own base,
/// `EmuSystemException` / `PcodeExecutionException`, is not yet ported. This carries only the
/// message Java's `EmuIOException(String)` constructor sets; the `EmuIOException(String,
/// Throwable)` overload's cause is dropped, matching this crate's other exception placeholders.
/// Replace with the real port once the `Emu*Exception` hierarchy lands.
#[derive(Debug, Clone)]
pub struct EmuIOException {
    message: String,
}

impl EmuIOException {
    /// Port of `EmuIOException(String message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }

    /// The detail message, as Java's `Throwable.getMessage()` would report it.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for EmuIOException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for EmuIOException {}

impl From<EmuIOException> for PcodeExecutionException {
    fn from(err: EmuIOException) -> Self {
        // Java's `EmuIOException` *is* a `PcodeExecutionException`; here it becomes the converted
        // exception's cause, so a handler can still recover it by downcasting `source()`.
        PcodeExecutionException::with_cause(err.message.clone(), err)
    }
}

/// Placeholder for the unported Java type `ghidra.pcode.emu.sys.UseropEmuSyscallDefinition`,
/// referenced by
/// [`AnnotatedEmuSyscallUseropLibrary`](crate::pcode::emu::sys::annotated_emu_syscall_userop_library::AnnotatedEmuSyscallUseropLibrary).
/// Java's class is concrete (not an interface), so, per the crate's convention for such
/// placeholders, this is a struct rather than a trait object: it implements the already-ported
/// [`EmuSyscallDefinition`] directly, carrying only the constructor logic and fields
/// `AnnotatedEmuSyscallUseropLibrary` needs -- wrapping a p-code userop as a system call by
/// aliasing each parameter's storage to the userop's respective input, per the platform's syscall
/// calling convention. Replace with the real port once `UseropEmuSyscallDefinition.java` lands.
pub struct UseropEmuSyscallDefinition<T: 'static> {
    op: PcodeOp,
    opdef: Arc<dyn PcodeUseropDefinition<T>>,
    in_vars: Vec<Varnode>,
    out_var: Option<Varnode>,
}

impl<T: 'static> UseropEmuSyscallDefinition<T> {
    /// Port of `UseropEmuSyscallDefinition.requirePointerDataType`: the program's "pointer" data
    /// type.
    ///
    /// # Panics
    ///
    /// If the program has no data type manager, or the manager has no "pointer" data type --
    /// mirroring Java's `IllegalArgumentException("No 'pointer' data type in " + program")`.
    pub fn require_pointer_data_type(program: &dyn Program) -> Arc<dyn DataType> {
        let dtm = program.get_data_type_manager().expect("program has no data type manager");
        let pointer =
            dtm.get_data_type("/pointer").expect("No 'pointer' data type in program");
        Arc::from(pointer)
    }

    /// Port of the constructor: alias each syscall parameter's storage to the wrapped userop's
    /// respective input, per `convention`, and fabricate the `CALLOTHER` op the wrapped userop is
    /// invoked through.
    ///
    /// # Panics
    ///
    /// If `opdef` is variadic (Java: `IllegalArgumentException`), if `convention` does not assign
    /// storage for every parameter, or if any assigned storage is not a single varnode (Java:
    /// `Unfinished.TODO()`).
    pub fn new(
        number: i64,
        opdef: Arc<dyn PcodeUseropDefinition<T>>,
        program: &dyn Program,
        convention: &dyn PrototypeModel,
        dt_machine_word: Arc<dyn DataType>,
    ) -> Self {
        let input_count = opdef.get_input_count();
        if input_count < 0 {
            panic!(
                "Variadic sleigh userop {} cannot be used as a syscall",
                opdef.get_name()
            );
        }
        let input_count = input_count as usize;

        let locs: Vec<Arc<dyn DataType>> =
            std::iter::repeat_with(|| Arc::clone(&dt_machine_word)).take(input_count + 1).collect();
        let storages = convention.get_storage_locations(program, &locs, false, false);
        assert_eq!(
            storages.len(),
            input_count + 1,
            "syscall calling convention did not assign storage for every parameter"
        );

        let out_var = Self::single_varnode(&*storages[0]);

        let number_addr = program
            .get_address_factory()
            .and_then(|factory| factory.get_constant_address(number))
            .expect("program has no address factory");
        let mut op_ins = Vec::with_capacity(input_count + 1);
        op_ins.push(Varnode::new(number_addr, 4));

        let mut in_vars = Vec::with_capacity(input_count);
        for storage in &storages[1..] {
            let vn = Self::single_varnode(&**storage);
            in_vars.push(vn.clone());
            op_ins.push(vn);
        }

        let op = PcodeOp::new(
            OpCode::CallOther,
            SequenceNumber::new(SpecialAddress::no_address(), 0),
            op_ins,
            Some(out_var.clone()),
        );

        Self { op, opdef, in_vars, out_var: Some(out_var) }
    }

    /// Port of `getSingleVnStorage`.
    fn single_varnode(storage: &dyn VariableStorage) -> Varnode {
        let varnodes = storage.get_varnodes();
        assert_eq!(varnodes.len(), 1, "expected a single varnode for syscall parameter storage");
        varnodes.into_iter().next().unwrap()
    }
}

impl<T: 'static> EmuSyscallDefinition<T> for UseropEmuSyscallDefinition<T> {
    fn invoke(
        &self,
        executor: &PcodeExecutor<T>,
        library: &dyn PcodeUseropLibrary<T>,
    ) -> Result<(), PcodeExecutionException> {
        // Java wraps every non-`PcodeExecutionException` throwable from `opdef.execute` in an
        // `EmuSystemException`; the already-ported `PcodeUseropDefinition::execute` has no
        // `Result` return, so (as with `AnnotatedPcodeUseropDefinition::execute`) a failure
        // inside it panics rather than returning here.
        self.opdef.execute(executor, library, &self.op, self.out_var.as_ref(), &self.in_vars);
        Ok(())
    }
}

/// Placeholder for the unported Java type `ghidra.pcode.struct.StructuredSleigh`, referenced by
/// [`AnnotatedEmuSyscallUseropLibrary::new_structured_part`](crate::pcode::emu::sys::annotated_emu_syscall_userop_library::AnnotatedEmuSyscallUseropLibrary::new_structured_part).
///
/// Minimal: only the one method that call site invokes, `generate`, which files the
/// structured-sleigh part's generated userops into the caller's userop map. The rest of the real
/// class's surface (`StructuredSleigh.s()`/`e()`/control-flow builders, etc.) has no in-repo
/// caller yet and is left out rather than guessed at; add it, and the `Label`/`StringTree`/
/// `Stmt`/`Expr` types it needs, when a real implementor requires them.
pub trait StructuredSleigh<T: 'static>: Send + Sync {
    /// Port of `StructuredSleigh.generate(Map<String, SleighPcodeUseropDefinition>)`.
    fn generate(&self, into: &mut UseropMap<T>);
}

/// Placeholder for the unported Java type `ghidra.pcode.emu.unix.EmuUnixException`, referenced by
/// [`AbstractEmuUnixSyscallUseropLibrary`](crate::pcode::emu::unix::abstract_emu_unix_syscall_userop_library::AbstractEmuUnixSyscallUseropLibrary).
///
/// Java's class extends `EmuSystemException` -> `PcodeExecutionException`, so a raised
/// `EmuUnixException` is catchable as the latter and `handleError` recovers it with `instanceof`.
/// Rust models that with [`From<EmuUnixException>`](PcodeExecutionException), which nests this
/// value as the converted exception's *cause*; the `instanceof` check becomes a
/// `source().downcast_ref::<EmuUnixException>()` (see
/// [`AbstractEmuUnixSyscallUseropLibrary::handle_unix_error`](crate::pcode::emu::unix::abstract_emu_unix_syscall_userop_library::AbstractEmuUnixSyscallUseropLibrary::handle_unix_error)).
/// The `(String, Throwable)` overloads' cause is dropped, matching this crate's other exception
/// placeholders. Replace with the real port once the `Emu*Exception` hierarchy lands.
#[derive(Debug, Clone)]
pub struct EmuUnixException {
    message: String,
    errno: Option<i32>,
}

impl EmuUnixException {
    /// Port of `EmuUnixException(String message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), errno: None }
    }

    /// Port of `EmuUnixException(String message, Integer errno)`. Providing an errno lets the
    /// syscall dispatcher communicate it to the target program instead of interrupting.
    pub fn with_errno(message: impl Into<String>, errno: i32) -> Self {
        Self { message: message.into(), errno: Some(errno) }
    }

    /// The detail message, as Java's `Throwable.getMessage()` would report it.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Port of `getErrno()`: the errno, or `None`.
    pub fn get_errno(&self) -> Option<i32> {
        self.errno
    }
}

impl std::fmt::Display for EmuUnixException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for EmuUnixException {}

impl From<EmuUnixException> for PcodeExecutionException {
    fn from(err: EmuUnixException) -> Self {
        PcodeExecutionException::with_cause(err.message.clone(), err)
    }
}

/// Placeholder for the unported Java type `ghidra.pcode.emu.sys.EmuProcessExitedException`,
/// referenced by
/// [`AbstractEmuUnixSyscallUseropLibrary`](crate::pcode::emu::unix::abstract_emu_unix_syscall_userop_library::AbstractEmuUnixSyscallUseropLibrary)'s
/// `exit`/`group_exit` system calls.
///
/// Java's `status` field is an untyped `Object` that callers cast back to the throwing machine's
/// `T`; this stub is generic instead, so the status comes back typed. Replace with the real port
/// once the `Emu*Exception` hierarchy lands.
pub struct EmuProcessExitedException<T> {
    message: String,
    status: T,
}

impl<T> EmuProcessExitedException<T> {
    /// Port of `EmuProcessExitedException(PcodeArithmetic<T>, T)`, which formats the status for
    /// display but keeps the original for [`get_status`](Self::get_status).
    pub fn new(arithmetic: &dyn PcodeArithmetic<T>, status: T) -> Self
    where
        T: std::fmt::Debug,
    {
        let message =
            format!("Process exited with status {}", Self::try_concrete_to_string(arithmetic, &status));
        Self { message, status }
    }

    /// Port of the static `tryConcereteToString`: concretize the status for display, falling back
    /// to the value's own rendering (Java: `toString()`, here `Debug`) if it cannot be concretized.
    pub fn try_concrete_to_string(arithmetic: &dyn PcodeArithmetic<T>, status: &T) -> String
    where
        T: std::fmt::Debug,
    {
        match arithmetic.to_big_integer(status, Purpose::Inspect) {
            Ok(value) => value.to_string(),
            Err(_) => format!("{:?}", status),
        }
    }

    /// The detail message, as Java's `Throwable.getMessage()` would report it.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Port of `getStatus()`.
    pub fn get_status(&self) -> &T {
        &self.status
    }
}

impl<T> std::fmt::Debug for EmuProcessExitedException<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmuProcessExitedException").field("message", &self.message).finish()
    }
}

impl<T> std::fmt::Display for EmuProcessExitedException<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl<T> std::error::Error for EmuProcessExitedException<T> {}

impl<T> From<EmuProcessExitedException<T>> for PcodeExecutionException {
    fn from(err: EmuProcessExitedException<T>) -> Self {
        // Not `with_cause`: the nested exception would have to be `Send + Sync + 'static`, which
        // would push those bounds onto every `T` a syscall library processes. The message already
        // carries the concretized status, which is all the Java supertype exposes.
        PcodeExecutionException::with_message(err.message)
    }
}

/// Placeholder for the unported Java type `ghidra.docking.settings.SettingsImpl`, referenced by
/// [`AbstractEmuUnixSyscallUseropLibrary`](crate::pcode::emu::unix::abstract_emu_unix_syscall_userop_library::AbstractEmuUnixSyscallUseropLibrary)'s
/// `open` system call, which constructs a `new SettingsImpl()` purely to hand default string
/// settings to a [`StringDataInstance`](crate::program::model::data::string_data_instance::StringDataInstance).
///
/// That call site never stores or reads a setting, so this carries no map: it is exactly the
/// empty, all-defaults [`Settings`] Java's no-arg constructor produces. Replace with the real port
/// once `SettingsImpl.java` lands.
#[derive(Debug, Clone, Copy, Default)]
pub struct SettingsImpl;

impl SettingsImpl {
    /// Port of `SettingsImpl()`.
    pub fn new() -> Self {
        Self
    }
}

impl crate::docking::settings::settings::Settings for SettingsImpl {}

/// Placeholder for the unported Java type `ghidra.program.model.data.StringDataType`, referenced
/// by [`AbstractEmuUnixSyscallUseropLibrary`](crate::pcode::emu::unix::abstract_emu_unix_syscall_userop_library::AbstractEmuUnixSyscallUseropLibrary)'s
/// `open` system call via the `StringDataType.dataType` singleton.
///
/// [`AbstractStringDataType`] -- the real base class -- is already ported, so this stub supplies
/// only the constructor arguments Java's `StringDataType` passes to `super(...)` that its one
/// in-repo call site reaches: the name, mnemonic, labels, and the `FIXED_LEN` layout that
/// [`AbstractStringDataType::get_string_data_instance`] consults. The members that call site never
/// touches -- cloning, C-type declaration, the `char` replacement base type -- would need
/// `BuiltIn`/`CharDataType` and are left `unimplemented!` rather than guessed at. Replace with the
/// real port once `StringDataType.java` lands.
#[derive(Debug, Clone, Copy, Default)]
pub struct StringDataType;

impl StringDataType {
    /// Port of the `StringDataType.dataType` singleton.
    pub const DATA_TYPE: Self = Self;
}

impl DataType for StringDataType {
    fn get_name(&self) -> String {
        "string".to_string()
    }
}

impl crate::program::model::data::built_in_data_type::BuiltInDataType for StringDataType {
    fn get_c_type_declaration(
        &self,
        _data_organization: Option<&dyn crate::program::model::data::data_organization::DataOrganization>,
    ) -> Option<String> {
        unimplemented!("not reachable from this stub's one call site")
    }

    fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {
        unimplemented!("not reachable from this stub's one call site")
    }
}

impl crate::program::model::data::dynamic::Dynamic for StringDataType {
    fn get_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
        use crate::program::model::data::abstract_string_data_type::AbstractStringDataType;
        self.string_dynamic_length(buf, max_length)
    }

    fn can_specify_length(&self) -> bool {
        true
    }

    fn get_replacement_base_type(&self) -> Box<dyn DataType> {
        unimplemented!("needs CharDataType, which is not ported yet")
    }
}

impl crate::program::model::data::data_type_with_charset::DataTypeWithCharset for StringDataType {
    fn string_data_instance(
        &self,
        _settings: &dyn crate::docking::settings::settings::Settings,
        _buf: &dyn MemBuffer,
    ) -> Box<dyn crate::program::model::data::string_data_instance::StringDataInstance> {
        // `AbstractStringDataType::get_string_data_instance` borrows its buffer, so it cannot
        // satisfy this `'static` box; the one call site uses that borrowing form directly.
        unimplemented!("use AbstractStringDataType::get_string_data_instance instead")
    }

    fn get_charset_name(&self, settings: &dyn crate::docking::settings::settings::Settings) -> String {
        use crate::program::model::data::abstract_string_data_type::AbstractStringDataType;
        self.string_charset_name(settings)
    }
}

impl crate::program::model::data::abstract_string_data_type::AbstractStringDataType
    for StringDataType
{
    fn mnemonic(&self) -> String {
        "ds".to_string()
    }

    fn description(&self) -> String {
        "String (fixed length)".to_string()
    }

    fn default_label(&self) -> String {
        "STRING".to_string()
    }

    fn default_label_prefix(&self) -> String {
        "STR".to_string()
    }

    fn default_abbrev_label_prefix(&self) -> String {
        "s".to_string()
    }

    fn get_string_layout(&self) -> crate::program::model::data::string_layout_enum::StringLayoutEnum {
        crate::program::model::data::string_layout_enum::StringLayoutEnum::FixedLen
    }

    fn string_replacement_base_type(&self) -> Option<Box<dyn DataType>> {
        None
    }
}

/// Placeholder for the unported Java type `RVal`, referenced by `LValInternal`.
/// A value which can be used on the RHS of an assignment.
pub trait RVal: Send + Sync {
    fn get_type(&self) -> Box<dyn DataType>;
    fn cast(&self, type_: &dyn DataType) -> Box<dyn RVal>;
}

/// Placeholder for the unported Java type `LVal`, referenced by `LValInternal`.
/// A value which can be used on either side of an assignment.
pub trait LVal: RVal {
    fn field(&self, name: &str) -> Box<dyn LVal>;
    fn index(&self, index: &dyn RVal) -> Box<dyn LVal>;
    fn index_long(&self, index: i64) -> Box<dyn LVal>;
    fn set(&self, rhs: &dyn RVal) -> Box<dyn StmtWithVal>;
    fn set_long(&self, rhs: i64) -> Box<dyn StmtWithVal>;
    fn addi(&self, rhs: &dyn RVal) -> Box<dyn RVal>;
}

/// Placeholder for the unported Java type `AssignStmt`, referenced by `LValInternal`.
pub trait AssignStmtType: Send + Sync {
    fn cast(&self, type_: &dyn DataType) -> Box<dyn RVal>;
    fn to_string(&self) -> String;
    fn get_type(&self) -> Box<dyn DataType>;
}

/// Placeholder for the unported Java type `FieldExprType`, referenced by `LValInternal`.
pub trait FieldExprType: Send + Sync {
    fn cast(&self, type_: &dyn DataType) -> Box<dyn LVal>;
    fn to_string(&self) -> String;
}

/// Placeholder for the unported Java type `IndexExprType`, referenced by `LValInternal`.
pub trait IndexExprType: Send + Sync {
    fn cast(&self, type_: &dyn DataType) -> Box<dyn LVal>;
    fn to_string(&self) -> String;
}

/// Placeholder for the unported Java type `Stmt`, referenced by `LVal`.
pub trait Stmt: Send + Sync {}

/// Placeholder for the unported Java type `StmtWithVal`, referenced by `LVal`.
pub trait StmtWithVal: Stmt + RVal {}

// ---------------------------------------------------------------------------
// The `ghidra.pcode.struct` expression seam, referenced by
// [`RValInternal`](crate::pcode::r#struct::rval_internal::RValInternal). Each of these is a node
// `RValInternal`'s combinators construct; every one is a Java *class*, so these are concrete
// structs rather than traits. They carry only what those combinators need -- construction plus
// `generate` -- and leave `cast` (which has to re-resolve a `DataType`) unimplemented. Replace
// them as `ArithBinExpr.java`, `CmpExpr.java`, `NotExpr.java`, `InvExpr.java`, and
// `DerefExpr.java` land.
// ---------------------------------------------------------------------------

/// Placeholder for the expression-building half of the unported Java class
/// `ghidra.pcode.struct.StructuredSleigh`, referenced by
/// [`RValInternal`](crate::pcode::r#struct::rval_internal::RValInternal).
///
/// The generic [`StructuredSleigh`] trait above models the *same* Java class, but from the
/// userop-library side; its type parameter is an artifact of the one method it carries
/// (`generate(Map<String, SleighPcodeUseropDefinition<T>>)`). `RValInternal` needs the
/// non-generic expression-factory members instead, and cannot pick a `T` for them, so they live
/// here until the real port unifies the two halves.
pub trait StructuredSleighContext: Send + Sync {
    /// Port of the `ctx.language.getDefaultSpace()` chain `RValInternal.deref()` walks.
    fn default_space(&self) -> Arc<AddressSpace>;

    /// Port of `StructuredSleigh.lit(long val, int size)`.
    fn lit(&self, val: i64, size: i32) -> Arc<dyn RValInternal>;

    /// Port of `StructuredSleigh.computeDerefType(RVal addr)`.
    fn compute_deref_type(&self, addr: &dyn RValInternal) -> Box<dyn DataType>;
}

/// Port of `BinExpr.generate`: `"(" lhs " " op " " rhs ")"`.
fn bin_expr_tree(
    this: &dyn RValInternal,
    lhs: &dyn RValInternal,
    op: &str,
    rhs: &dyn RValInternal,
) -> StringTree {
    let mut st = StringTree::new();
    st.append("(");
    st.append_tree(lhs.generate(Some(this)));
    st.append(" ");
    st.append(op);
    st.append(" ");
    st.append_tree(rhs.generate(Some(this)));
    st.append(")");
    st
}

/// Port of `UnExpr.generate`: `"(" op u ")"`.
fn un_expr_tree(this: &dyn RValInternal, op: &str, u: &dyn RValInternal) -> StringTree {
    let mut st = StringTree::new();
    st.append("(");
    st.append(op);
    st.append_tree(u.generate(Some(this)));
    st.append(")");
    st
}

/// Port of `ArithBinExpr.Op`. Rust has no nested enums, hence the flattened name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithBinExprOp {
    Orb,
    Ori,
    Xorb,
    Xori,
    Andb,
    Andi,
    Shli,
    Shriu,
    Shris,
    Addi,
    Addf,
    Subi,
    Subf,
    Muli,
    Mulf,
    Diviu,
    Divis,
    Divf,
    Remiu,
    Remis,
}

impl ArithBinExprOp {
    /// The Sleigh operator text; Java stores it in the enum's `str` field.
    pub fn sleigh(self) -> &'static str {
        match self {
            Self::Orb => "||",
            Self::Ori => "|",
            Self::Xorb => "^^",
            Self::Xori => "^",
            Self::Andb => "&&",
            Self::Andi => "&",
            Self::Shli => "<<",
            Self::Shriu => ">>",
            Self::Shris => "s>>",
            Self::Addi => "+",
            Self::Addf => "f+",
            Self::Subi => "-",
            Self::Subf => "f-",
            Self::Muli => "*",
            Self::Mulf => "f*",
            Self::Diviu => "/",
            Self::Divis => "s/",
            Self::Divf => "f/",
            Self::Remiu => "%",
            Self::Remis => "s%",
        }
    }
}

/// Placeholder for the unported Java class `ghidra.pcode.struct.ArithBinExpr`.
pub struct ArithBinExpr {
    ctx: Arc<dyn StructuredSleighContext>,
    lhs: Arc<dyn RValInternal>,
    op: ArithBinExprOp,
    rhs: Arc<dyn RValInternal>,
}

impl ArithBinExpr {
    /// Port of `ArithBinExpr(StructuredSleigh, RVal, Op, RVal)`.
    pub fn new(
        ctx: Arc<dyn StructuredSleighContext>,
        lhs: Arc<dyn RValInternal>,
        op: ArithBinExprOp,
        rhs: Arc<dyn RValInternal>,
    ) -> Self {
        Self { ctx, lhs, op, rhs }
    }
}

impl RVal for ArithBinExpr {
    fn get_type(&self) -> Box<dyn DataType> {
        // Java: `super(ctx, lhs, op.str, rhs, lhs.getType())`.
        self.lhs.get_type()
    }

    fn cast(&self, _type_: &dyn DataType) -> Box<dyn RVal> {
        unimplemented!("BinExpr.cast has to store the new DataType; needs the real port")
    }
}

impl RValInternal for ArithBinExpr {
    fn get_context(&self) -> Arc<dyn StructuredSleighContext> {
        Arc::clone(&self.ctx)
    }

    fn generate(&self, _parent: Option<&dyn RValInternal>) -> StringTree {
        bin_expr_tree(self, &*self.lhs, self.op.sleigh(), &*self.rhs)
    }

    fn as_rval_internal(self: Arc<Self>) -> Arc<dyn RValInternal> {
        self
    }
}

/// Port of `CmpExpr.Op`. Rust has no nested enums, hence the flattened name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpExprOp {
    Eq,
    Neq,
    Eqf,
    Neqf,
    Ltiu,
    Ltis,
    Ltf,
    Lteiu,
    Lteis,
    Ltef,
    Gtiu,
    Gtis,
    Gtf,
    Gteiu,
    Gteis,
    Gtef,
}

impl CmpExprOp {
    /// The Sleigh operator text; Java stores it in the enum's `str` field.
    pub fn sleigh(self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Neq => "!=",
            Self::Eqf => "f==",
            Self::Neqf => "f!=",
            Self::Ltiu => "<",
            Self::Ltis => "s<",
            Self::Ltf => "f<",
            Self::Lteiu => "<=",
            Self::Lteis => "s<=",
            Self::Ltef => "f<=",
            Self::Gtiu => ">",
            Self::Gtis => "s>",
            Self::Gtf => "f>",
            Self::Gteiu => ">=",
            Self::Gteis => "s>=",
            Self::Gtef => "f>=",
        }
    }

    /// Port of `CmpExpr.Op.not()`: the operator that tests the complementary condition.
    pub fn not(self) -> Self {
        match self {
            Self::Eq => Self::Neq,
            Self::Neq => Self::Eq,
            Self::Eqf => Self::Neqf,
            Self::Neqf => Self::Eqf,
            Self::Ltiu => Self::Gteiu,
            Self::Ltis => Self::Gteis,
            Self::Ltf => Self::Gtef,
            Self::Lteiu => Self::Gtiu,
            Self::Lteis => Self::Gtis,
            Self::Ltef => Self::Gtf,
            Self::Gtiu => Self::Lteiu,
            Self::Gtis => Self::Lteis,
            Self::Gtf => Self::Ltef,
            Self::Gteiu => Self::Ltiu,
            Self::Gteis => Self::Ltis,
            Self::Gtef => Self::Ltf,
        }
    }
}

/// Placeholder for the unported Java class `ghidra.pcode.struct.CmpExpr`.
pub struct CmpExpr {
    ctx: Arc<dyn StructuredSleighContext>,
    lhs: Arc<dyn RValInternal>,
    op: CmpExprOp,
    rhs: Arc<dyn RValInternal>,
}

impl CmpExpr {
    /// Port of `CmpExpr(StructuredSleigh, RVal, Op, RVal)`.
    pub fn new(
        ctx: Arc<dyn StructuredSleighContext>,
        lhs: Arc<dyn RValInternal>,
        op: CmpExprOp,
        rhs: Arc<dyn RValInternal>,
    ) -> Self {
        Self { ctx, lhs, op, rhs }
    }
}

impl RVal for CmpExpr {
    fn get_type(&self) -> Box<dyn DataType> {
        unimplemented!("Java uses BooleanDataType.dataType, which is not ported yet")
    }

    fn cast(&self, _type_: &dyn DataType) -> Box<dyn RVal> {
        unimplemented!("BinExpr.cast has to store the new DataType; needs the real port")
    }
}

impl RValInternal for CmpExpr {
    fn get_context(&self) -> Arc<dyn StructuredSleighContext> {
        Arc::clone(&self.ctx)
    }

    fn generate(&self, _parent: Option<&dyn RValInternal>) -> StringTree {
        bin_expr_tree(self, &*self.lhs, self.op.sleigh(), &*self.rhs)
    }

    fn as_rval_internal(self: Arc<Self>) -> Arc<dyn RValInternal> {
        self
    }

    fn notb(self: Arc<Self>) -> Arc<dyn RValInternal> {
        // Java: `new CmpExpr(ctx, lhs, op.not(), rhs, type)` -- negate in place, no `NotExpr`.
        Arc::new(CmpExpr::new(
            Arc::clone(&self.ctx),
            Arc::clone(&self.lhs),
            self.op.not(),
            Arc::clone(&self.rhs),
        ))
    }
}

/// Placeholder for the unported Java class `ghidra.pcode.struct.NotExpr`.
pub struct NotExpr {
    ctx: Arc<dyn StructuredSleighContext>,
    u: Arc<dyn RValInternal>,
}

impl NotExpr {
    /// Port of `NotExpr(StructuredSleigh, RVal)`.
    pub fn new(ctx: Arc<dyn StructuredSleighContext>, u: Arc<dyn RValInternal>) -> Self {
        Self { ctx, u }
    }
}

impl RVal for NotExpr {
    fn get_type(&self) -> Box<dyn DataType> {
        // Java: `super(ctx, "!", u, u.getType())`.
        self.u.get_type()
    }

    fn cast(&self, _type_: &dyn DataType) -> Box<dyn RVal> {
        unimplemented!("UnExpr.cast has to store the new DataType; needs the real port")
    }
}

impl RValInternal for NotExpr {
    fn get_context(&self) -> Arc<dyn StructuredSleighContext> {
        Arc::clone(&self.ctx)
    }

    fn generate(&self, _parent: Option<&dyn RValInternal>) -> StringTree {
        un_expr_tree(self, "!", &*self.u)
    }

    fn as_rval_internal(self: Arc<Self>) -> Arc<dyn RValInternal> {
        self
    }

    fn notb(self: Arc<Self>) -> Arc<dyn RValInternal> {
        // Java: `return u` -- double negation collapses.
        Arc::clone(&self.u)
    }
}

/// Placeholder for the unported Java class `ghidra.pcode.struct.InvExpr`.
pub struct InvExpr {
    ctx: Arc<dyn StructuredSleighContext>,
    u: Arc<dyn RValInternal>,
}

impl InvExpr {
    /// Port of `InvExpr(StructuredSleigh, RVal)`.
    pub fn new(ctx: Arc<dyn StructuredSleighContext>, u: Arc<dyn RValInternal>) -> Self {
        Self { ctx, u }
    }
}

impl RVal for InvExpr {
    fn get_type(&self) -> Box<dyn DataType> {
        // Java: `super(ctx, "~", u, u.getType())`.
        self.u.get_type()
    }

    fn cast(&self, _type_: &dyn DataType) -> Box<dyn RVal> {
        unimplemented!("UnExpr.cast has to store the new DataType; needs the real port")
    }
}

impl RValInternal for InvExpr {
    fn get_context(&self) -> Arc<dyn StructuredSleighContext> {
        Arc::clone(&self.ctx)
    }

    fn generate(&self, _parent: Option<&dyn RValInternal>) -> StringTree {
        un_expr_tree(self, "~", &*self.u)
    }

    fn as_rval_internal(self: Arc<Self>) -> Arc<dyn RValInternal> {
        self
    }

    fn noti(self: Arc<Self>) -> Arc<dyn RValInternal> {
        // Java: `return u` -- double inversion collapses.
        Arc::clone(&self.u)
    }
}

/// Placeholder for the unported Java class `ghidra.pcode.struct.DerefExpr`.
///
/// Java's `generate` drops the parentheses when the parent is the `AssignStmt` this node is the
/// left-hand side of. `AssignStmt` is not ported, so this stub always parenthesizes; the real
/// port restores that case.
pub struct DerefExpr {
    ctx: Arc<dyn StructuredSleighContext>,
    space: Arc<AddressSpace>,
    addr: Arc<dyn RValInternal>,
}

impl DerefExpr {
    /// Port of `DerefExpr(StructuredSleigh, AddressSpace, RValInternal)`.
    pub fn new(
        ctx: Arc<dyn StructuredSleighContext>,
        space: Arc<AddressSpace>,
        addr: Arc<dyn RValInternal>,
    ) -> Self {
        Self { ctx, space, addr }
    }
}

impl RVal for DerefExpr {
    fn get_type(&self) -> Box<dyn DataType> {
        // Java: `this(ctx, space, addr, ctx.computeDerefType(addr))`.
        self.ctx.compute_deref_type(&*self.addr)
    }

    fn cast(&self, _type_: &dyn DataType) -> Box<dyn RVal> {
        unimplemented!("DerefExpr.cast has to store the new DataType; needs the real port")
    }
}

impl RValInternal for DerefExpr {
    fn get_context(&self) -> Arc<dyn StructuredSleighContext> {
        Arc::clone(&self.ctx)
    }

    fn generate(&self, _parent: Option<&dyn RValInternal>) -> StringTree {
        let mut st = StringTree::new();
        st.append("(*");
        if *self.ctx.default_space() != *self.space {
            st.append("[");
            st.append(self.space.name());
            st.append("]");
        }
        let length = self.get_type().get_length();
        if length != 0 {
            st.append(":");
            st.append(&length.to_string());
        }
        st.append(" ");
        st.append_tree(self.addr.generate(Some(self)));
        st.append(")");
        st
    }

    fn as_rval_internal(self: Arc<Self>) -> Arc<dyn RValInternal> {
        self
    }
}

impl LVal for DerefExpr {
    fn field(&self, _name: &str) -> Box<dyn LVal> {
        unimplemented!("needs FieldExpr, which is not ported yet")
    }

    fn index(&self, _index: &dyn RVal) -> Box<dyn LVal> {
        unimplemented!("needs IndexExpr, which is not ported yet")
    }

    fn index_long(&self, _index: i64) -> Box<dyn LVal> {
        unimplemented!("needs IndexExpr, which is not ported yet")
    }

    fn set(&self, _rhs: &dyn RVal) -> Box<dyn StmtWithVal> {
        unimplemented!("needs AssignStmt, which is not ported yet")
    }

    fn set_long(&self, _rhs: i64) -> Box<dyn StmtWithVal> {
        unimplemented!("needs AssignStmt, which is not ported yet")
    }

    fn addi(&self, _rhs: &dyn RVal) -> Box<dyn RVal> {
        unimplemented!("use RValInternal::addi, which takes the shared-ownership operands")
    }
}

impl LValInternal for DerefExpr {}

