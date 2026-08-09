//! Minimal placeholder types for core types that a ported interface under [`crate::pcode`]
//! references before the real Rust port of that type exists yet. Each stub exposes only the
//! members needed by the interface(s) that currently reference it, and is expected to be
//! replaced (or grown into a supertrait/struct of) the real port once that Java class is ported.
//! See `STUBS.tsv` for provenance.

use std::sync::{Arc, Mutex, OnceLock};

use crate::pcode::exec::abstract_sleigh_pcode_userop_definition::AbstractSleighPcodeUseropDefinitionBase;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::Reason;
use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
use crate::pcode::exec::pcode_userop_library::{
    ErasedPcodeUseropLibrary, PcodeUseropLibrary, UseropMap,
};
use crate::pcode::exec::sleigh_pcode_userop_definition::{SignatureDef, SleighPcodeUseropDefinition};
use crate::pcode::floatformat::big_float::{BigFloat, MathContext};
use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::lang::sleigh::SleighLanguage;
use crate::program::model::mem::mem_buffer::MemBuffer;
use crate::program::model::pcode::Varnode;
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
/// [`BreakTable`](crate::pcode::emulate::break_table::BreakTable) before the real class is ported.
pub trait PcodeOpRaw: Send + Sync {}

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

/// Placeholder for `ghidra.pcode.exec.PcodeProgram`, referenced by
/// [`SleighPcodeUseropDefinition::program_for`](crate::pcode::exec::sleigh_pcode_userop_definition::SleighPcodeUseropDefinition::program_for)
/// before the real class is ported. Used there only as an opaque return type, so no members are
/// exposed yet.
pub trait PcodeProgram: Send + Sync {}

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

/// Placeholder for `ghidra.pcode.exec.PcodeExecutor`, referenced by
/// [`AbstractSleighPcodeUseropDefinitionBase::execute`](crate::pcode::exec::abstract_sleigh_pcode_userop_definition::AbstractSleighPcodeUseropDefinitionBase::execute),
/// by [`PcodeUseropDefinition`](crate::pcode::exec::pcode_userop_library::PcodeUseropDefinition),
/// and by
/// [`AnnotatedPcodeUseropDefinition`](crate::pcode::exec::annotated_pcode_userop_library::AnnotatedPcodeUseropDefinition)
/// before the real class is ported. Exposes only the members those call sites need.
/// `T` is Java's `PcodeExecutor<T>` type parameter: the type of values in the executor's state.
pub trait PcodeExecutor<T: 'static>: Send + Sync {
    /// Placeholder for `PcodeExecutor.execute(PcodeProgram, PcodeUseropLibrary)`.
    fn execute(&self, program: &dyn PcodeProgram, library: &dyn PcodeUseropLibrary<T>);

    /// Placeholder for `PcodeExecutor.getArithmetic()`.
    ///
    /// Returns an owned `Arc` rather than a borrow, matching
    /// [`PcodeExecutorStatePiece::get_arithmetic`].
    fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<T>>;

    /// Placeholder for `PcodeExecutor.getState()`.
    ///
    /// Java hands back the state and lets callers both read and write it (a userop, for example,
    /// reads its inputs and writes its output through it). Writing needs `&mut`, which a
    /// `&dyn PcodeExecutor` cannot produce, so the state is shared behind a `Mutex`: the executor
    /// and the userops it runs genuinely share mutable access to it.
    fn get_state(&self) -> &Mutex<dyn PcodeExecutorState<T>>;

    /// Placeholder for `PcodeExecutor.getReason()`.
    fn get_reason(&self) -> Reason;
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
    ) -> Box<dyn PcodeProgram> {
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
    ) -> Box<dyn PcodeProgram> {
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
pub trait RegisterValue: Send + Sync {}

/// Placeholder for `ghidra.pcode.emu.PcodeThread`, referenced by
/// [`PcodeStateInitializer`](crate::pcode::emu::pcode_state_initializer::PcodeStateInitializer)
/// before the real class is ported. This is a minimal interface stub exposing only the methods
/// needed by existing references.
pub trait PcodeThread: Send + Sync {}

/// Placeholder for `ghidra.pcode.exec.BytesPcodeExecutorStateSpace`, referenced by
/// [`AbstractBytesPcodeExecutorStatePiece`](crate::pcode::exec::abstract_bytes_pcode_executor_state_piece::AbstractBytesPcodeExecutorStatePiece)
/// as the internal per-address-space byte store. Only the members that class needs are declared
/// (Java's `fork`, which forward-references the owning piece, is the cycle edge this stub breaks
/// -- it is unused by `AbstractBytesPcodeExecutorStatePiece` itself, so it is omitted here).
///
/// Every real implementation must be internally mutable and cheaply [`Clone`]:
/// `getConcreteBuffer` hands out a live, shared view of a space that must outlive the owning
/// piece's borrow (Java shares the same mutable object reference across the state and any
/// buffers bound to it; Rust needs an owned, thread-safe handle instead).
pub trait BytesPcodeExecutorStateSpace: Clone + Send + Sync {
    /// Port of `BytesPcodeExecutorStateSpace.write(long, byte[], int, int, PcodeStateCallbacks)`.
    fn write<C: PcodeStateCallbacks>(
        &self,
        offset: i64,
        val: &[u8],
        src_offset: i32,
        length: i32,
        cb: &C,
    );

    /// Port of `BytesPcodeExecutorStateSpace.read(long, int, Reason, PcodeStateCallbacks)`.
    fn read<C: PcodeStateCallbacks>(&self, offset: i64, size: i32, reason: Reason, cb: &C) -> Vec<u8>;

    /// Port of `BytesPcodeExecutorStateSpace.getRegisterValues(List<Register>)`.
    fn get_register_values(&self, registers: &[RegisterRef]) -> Vec<(RegisterRef, Vec<u8>)>;

    /// Port of `BytesPcodeExecutorStateSpace.clear()`.
    fn clear(&self);
}

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
}
