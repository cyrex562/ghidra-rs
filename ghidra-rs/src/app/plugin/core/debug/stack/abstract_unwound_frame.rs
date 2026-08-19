//! An abstract implementation of [`UnwoundFrame`].
//!
//! Port of `ghidra.app.plugin.core.debug.stack.AbstractUnwoundFrame<T>`.
//!
//! This generally contains all the methods for interpreting and retrieving higher-level variables
//! once the frame context is known. It doesn't contain the mechanisms for creating or reading
//! annotations.
//!
//! # Shape
//!
//! The Java abstract class carries both state and behavior, so it is split in two:
//! [`AbstractUnwoundFrameBase`] holds the ten instance fields, and [`AbstractUnwoundFrame`]
//! declares the three abstract methods (`computeRegisterMap`, `computeAddressOfReturnAddress` and
//! `applyBase`) and supplies the concrete ones as defaults. A concrete frame owns a base,
//! implements the trait, and forwards [`UnwoundFrame`] to the trait's defaults.
//!
//! # Deviations
//!
//! * `PcodeExecutorState<T>` is not object-safe here, so the state is a type parameter `S` rather
//!   than a `dyn` field. This is the same treatment
//!   [`StackUnwinder`](crate::app::plugin::core::debug::stack::stack_unwinder) gives it.
//! * Java's constructor takes a `PluginTool` and resolves the mapping service through
//!   `tool.getService(...)`. [`PluginTool::get_service`](crate::framework::seam_stubs::PluginTool)
//!   hands back an `Arc<dyn Any + Send + Sync>` and [`DebuggerStaticMappingService`] is not
//!   `Send + Sync`, so that downcast can never succeed; the service is a constructor parameter
//!   instead, `None` reproducing a tool that provides no such service. Again, as `StackUnwinder`.
//! * The concrete methods take `Arc<dyn Program>` rather than `&dyn Program`. Java's
//!   `translateMemory` builds a `ProgramLocation` and, when the mapping fails, a
//!   [`DynamicMappingException`]; both hold the program, and both of this crate's ports need it
//!   owned.
//! * The nested evaluator classes (`ArithmeticFrameVarnodeEvaluator`,
//!   `AbstractFrameVarnodeEvaluator`, `FrameVarnodeEvaluator`, `FrameVarnodeValueGetter` and
//!   `FrameVarnodeValueSetter`) collapse into one [`FrameVarnodeEvaluator`], whose
//!   `symbol_storage` selects between the leaf-only behavior of the getter/setter (`None`) and the
//!   symbol-storage-terminated behavior of the evaluator (`Some`). Their common base,
//!   `ghidra.pcode.eval.AbstractVarnodeEvaluator`, is not ported: [`Varnode`] here models low
//!   p-code and has no `getDef()`, so the ascent to a varnode's defining op has nothing to walk.
//!   Everything the ascent is not needed for -- leaf evaluation, storage concatenation, and value
//!   setting, i.e. `getValue` and `setValue` -- is implemented; the three `evaluate` entry points
//!   panic once they reach a non-leaf varnode.

use std::marker::PhantomData;
use std::sync::Arc;

use crate::app::plugin::core::debug::stack::dynamic_mapping_exception::DynamicMappingException;
use crate::app::seam_stubs::{ArithmeticVarnodeEvaluator, SavedRegisterMap};
use crate::app::services::debugger_control_service::{StateEditFuture, StateEditor};
use crate::app::services::debugger_static_mapping_service::DebuggerStaticMappingService;
use crate::debug::api::tracemgr::debugger_coordinates::DebuggerCoordinates;
use crate::pcode::eval::varnode_evaluator::VarnodeEvaluator;
use crate::pcode::exec::pcode_arithmetic::PcodeArithmetic;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::pcode::exec::pcode_executor_state_piece::Reason;
use crate::pcode::seam_stubs::BytesPcodeArithmetic;
use crate::pcode::utils::utils::big_integer_to_bytes;
use crate::program::model::address::{Address, AddressSetView, AddressSpace};
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::listing::program::Program;
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::pcode::{OpCode, PcodeOp, Varnode};
use crate::program::util::program_location::ProgramLocation;
use crate::trace::model::guest::trace_platform::TracePlatform;
use crate::trace::model::trace::Trace;

/// The `new ProgramLocation(program, address)` the nested evaluators' `translateMemory` builds to
/// ask the mapping service where a static address lives in the trace.
struct FrameProgramLocation {
    program: Arc<dyn Program>,
    address: Address,
}

impl ProgramLocation for FrameProgramLocation {
    fn get_program(&self) -> Arc<dyn Program> {
        Arc::clone(&self.program)
    }

    fn get_address(&self) -> Address {
        self.address.clone()
    }

    fn get_byte_address(&self) -> Address {
        self.address.clone()
    }
}

/// The shared state of an unwound frame: the ten fields Java's abstract class declares
/// `protected final`.
///
/// `T` is the type of values retrievable from the frame; `S` is the machine state they are read
/// from.
pub struct AbstractUnwoundFrameBase<T, S> {
    /// The coordinates (trace, thread, snap, etc.) this frame was examined at.
    pub coordinates: DebuggerCoordinates,
    /// The trace being examined, `None` when the coordinates name none.
    pub trace: Option<Arc<dyn Trace>>,
    /// The platform whose language, code space and program counter the frame is read against.
    pub platform: Arc<dyn TracePlatform>,
    /// The snapshot key.
    pub snap: i64,
    /// The snapshot key of the view, which may differ from [`snap`](Self::snap) when the
    /// coordinates carry an emulation schedule.
    pub view_snap: i64,
    /// The platform's language.
    pub language: Arc<dyn Language>,
    /// The language's default space, i.e. where code lives.
    pub code_space: Arc<AddressSpace>,
    /// The language's program counter.
    pub pc: RegisterRef,
    /// The machine state, typically the watch-value state for the same coordinates.
    pub state: S,
    /// The service that maps trace addresses onto open programs, `None` when the tool provides
    /// none.
    pub mapping_service: Option<Arc<dyn DebuggerStaticMappingService>>,
    _value: PhantomData<fn() -> T>,
}

impl<T, S> AbstractUnwoundFrameBase<T, S>
where
    S: PcodeExecutorState<T>,
{
    /// Construct an unwound frame.
    ///
    /// * `coordinates` -- the coordinates (trace, thread, snap, etc.) to examine
    /// * `state` -- the machine state, typically the watch value state for the same coordinates.
    ///   It is the caller's (i.e., subclass') responsibility to ensure the given state corresponds
    ///   to the given coordinates.
    /// * `mapping_service` -- the static mapping service; Java reads it from the tool
    ///
    /// # Panics
    ///
    /// Panics when the coordinates name no platform, where Java throws `NullPointerException`
    /// dereferencing it, and when the language declares no program counter.
    pub fn new(
        coordinates: DebuggerCoordinates,
        state: S,
        mapping_service: Option<Arc<dyn DebuggerStaticMappingService>>,
    ) -> Self {
        let platform = coordinates
            .get_platform()
            .expect("Coordinates must name a platform");
        Self::with_platform(coordinates, platform, state, mapping_service)
    }

    /// Construct an unwound frame from a platform supplied directly.
    ///
    /// Java's constructor takes the platform out of the coordinates, and so does
    /// [`new`](Self::new). But [`DebuggerCoordinates::platform`] will only attach a platform that
    /// can hand back its own `Trace`, which is more than a caller holding just a platform can
    /// always supply, so this entry point accepts one alongside the coordinates.
    ///
    /// # Panics
    ///
    /// Panics when the platform's language declares no program counter, where Java's later use of
    /// the field throws `NullPointerException`.
    pub fn with_platform(
        coordinates: DebuggerCoordinates,
        platform: Arc<dyn TracePlatform>,
        state: S,
        mapping_service: Option<Arc<dyn DebuggerStaticMappingService>>,
    ) -> Self {
        let trace = coordinates.get_trace();
        let snap = coordinates.get_snap();
        let view_snap = coordinates.get_view_snap();
        let language: Arc<dyn Language> = Arc::from(platform.platform_language());
        let code_space = language.get_default_space();
        let pc = language
            .get_program_counter()
            .expect("Language must have a program counter");

        AbstractUnwoundFrameBase {
            coordinates,
            trace,
            platform,
            snap,
            view_snap,
            language,
            code_space,
            pc,
            state,
            mapping_service,
            _value: PhantomData,
        }
    }

    /// The arithmetic the frame's state evaluates values with.
    pub fn arithmetic(&self) -> Arc<dyn PcodeArithmetic<T>> {
        self.state.get_arithmetic()
    }

    /// Match `value`'s length to `length` by zero extension or truncation.
    ///
    /// Port of `UnwoundFrame.zext(T, int)`, whose only implementation is this one.
    pub fn zext(&self, value: T, length: i32) -> T {
        let arithmetic = self.arithmetic();
        let size_in = arithmetic.size_of(&value) as i32;
        arithmetic.unary_op(OpCode::IntZext, length, size_in, &value)
    }

    /// Map a static address in the given program to its address in the trace.
    ///
    /// Port of the `translateMemory(Program, Address)` override both nested evaluator bases share.
    ///
    /// # Panics
    ///
    /// Panics with [`DynamicMappingException`]'s message when the address is not mapped into the
    /// trace, or when there is no mapping service to ask. Java throws that (unchecked) exception.
    pub fn translate_memory(&self, program: &Arc<dyn Program>, address: &Address) -> Address {
        let location = FrameProgramLocation {
            program: Arc::clone(program),
            address: address.clone(),
        };
        let mapped = self.mapping_service.as_ref().and_then(|service| {
            service.get_open_mapped_trace_location(
                self.trace
                    .as_deref()
                    .expect("Coordinates must name a trace to map an address into it"),
                &location,
                self.snap,
            )
        });
        match mapped {
            Some(location) => location.get_address(),
            None => panic!(
                "{}",
                DynamicMappingException::new(Arc::clone(program), address.clone()).message()
            ),
        }
    }
}

/// An evaluator of high p-code varnodes in the context of an unwound frame.
///
/// This stands in for Java's nested `FrameVarnodeEvaluator<U>`, `FrameVarnodeValueGetter<U>` and
/// `FrameVarnodeValueSetter<U>`, which differ only in what they treat as a leaf and what they do
/// once they reach one. `symbol_storage` selects between them: `None` is the getter/setter, for
/// which every varnode is a leaf, and `Some` is the evaluator, which descends to symbol storage.
pub struct FrameVarnodeEvaluator<'a, T, S, F: ?Sized> {
    frame: &'a F,
    program: Arc<dyn Program>,
    register_map: SavedRegisterMap,
    symbol_storage: Option<&'a dyn AddressSetView>,
    _value: PhantomData<fn() -> (T, S)>,
}

impl<'a, T, S, F> FrameVarnodeEvaluator<'a, T, S, F>
where
    F: AbstractUnwoundFrame<T, S> + ?Sized,
    S: PcodeExecutorState<T>,
{
    /// Port of `FrameVarnodeEvaluator.isLeaf(Varnode)` and of the `FrameVarnodeValueGetter`'s and
    /// `FrameVarnodeValueSetter`'s, which always answer `true`.
    ///
    /// Java also treats a register or memory varnode with no defining op as a leaf. Low p-code
    /// [`Varnode`]s carry no defining op at all, so that clause would swallow every such varnode
    /// and is left out; what remains is the constant and symbol-storage test.
    pub fn is_leaf(&self, vn: &Varnode) -> bool {
        let Some(symbol_storage) = self.symbol_storage else {
            return true;
        };
        if vn.is_constant() {
            return true;
        }
        let start = vn.get_address();
        match start.add(i64::from(vn.get_size()) - 1) {
            Ok(end) => symbol_storage.contains_range(start, &end),
            Err(_) => false,
        }
    }

    /// The address a leaf varnode is actually read from or written to in the trace.
    ///
    /// Port of the address dispatch in `AbstractVarnodeEvaluator.evaluateLeaf(Program, Varnode)`,
    /// less the constant and unique cases, which have no address.
    ///
    /// # Panics
    ///
    /// Panics for a constant or unique varnode, and for one in a space of no recognized type,
    /// where Java throws `PcodeExecutionException`.
    pub fn leaf_address(&self, vn: &Varnode) -> Address {
        let address = vn.get_address();
        if address.is_constant_address() {
            panic!("Cannot take the address of the constant {vn:?}");
        } else if address.is_register_address() {
            address.clone()
        } else if address.is_stack_address() {
            self.frame.apply_base(address.offset())
        } else if address.is_memory_address() {
            self.frame
                .frame_base()
                .translate_memory(&self.program, address)
        } else if address.is_unique_address() {
            panic!(
                "Cannot evaluate unique $U{:x}:{}",
                vn.get_offset(),
                vn.get_size()
            );
        } else {
            panic!("Unrecognized address space in {vn:?}");
        }
    }

    /// Read a variable from the frame's state, redirecting register reads to wherever this frame
    /// saved them.
    ///
    /// Port of the `evaluateMemory(Address, int)` the concrete frames supply to their evaluators.
    pub fn evaluate_memory(&self, address: &Address, size: i32) -> T {
        self.register_map
            .get_var(&self.frame.frame_base().state, address, size, Reason::Inspect)
    }

    /// Port of `AbstractVarnodeEvaluator.evaluateLeaf(Program, Varnode)`.
    pub fn evaluate_leaf(&self, vn: &Varnode) -> T {
        if vn.get_address().is_constant_address() {
            return self
                .frame
                .frame_base()
                .arithmetic()
                .from_const_u64(vn.get_offset() as u64, vn.get_size());
        }
        let at = self.leaf_address(vn);
        self.evaluate_memory(&at, vn.get_size())
    }

    /// Evaluate a varnode, which could be either a leaf or a branch.
    ///
    /// Port of `AbstractVarnodeEvaluator.doEvaluateVarnode(Program, Varnode, Map)`. Java memoizes
    /// each varnode's value across one evaluation; with the branch case unavailable there is
    /// nothing left to memoize.
    ///
    /// # Panics
    ///
    /// Panics for a non-leaf varnode: the ascent to its defining p-code op is not ported.
    pub fn value_of_varnode(&self, vn: &Varnode) -> T {
        if self.is_leaf(vn) {
            return self.evaluate_leaf(vn);
        }
        unimplemented!(
            "AbstractVarnodeEvaluator's ascent to a varnode's defining p-code op needs high \
             p-code, which Varnode does not model here"
        )
    }

    /// Evaluate variable storage, concatenating its varnodes with the lower-indexed ones the more
    /// significant, as in big endian.
    ///
    /// Port of `AbstractVarnodeEvaluator.evaluateStorage(Program, VariableStorage, T)` with
    /// `ArithmeticVarnodeEvaluator`'s identity, `arithmetic.fromConst(0, storage.size())`.
    pub fn value_of_storage(&self, storage: &dyn VariableStorage) -> T {
        let arithmetic = self.frame.frame_base().arithmetic();
        let total = storage.size();
        let mut value = arithmetic.from_const_u64(0, total);
        for vn in storage.get_varnodes() {
            let piece = self.value_of_varnode(&vn);
            value = ArithmeticVarnodeEvaluator::catenate(
                arithmetic.as_ref(),
                total,
                &value,
                &piece,
                vn.get_size(),
            );
        }
        value
    }

    /// Write `bytes` (big endian, as `Utils.bigIntegerToBytes(value, size, true)` produces them)
    /// across the given storage's varnodes.
    ///
    /// Port of the anonymous `FrameVarnodeValueSetter<ByteBuffer>` in `setValue`: each varnode
    /// consumes its own width from the front of the buffer, which is byte-swapped for a
    /// little-endian language before being written.
    ///
    /// # Panics
    ///
    /// Panics when `bytes` is shorter than the storage, where Java's `ByteBuffer.get` throws
    /// `BufferUnderflowException`.
    pub fn set_storage(
        &self,
        editor: &dyn StateEditor,
        storage: &dyn VariableStorage,
        bytes: &[u8],
    ) -> StateEditFuture {
        let big_endian = self.frame.frame_base().language.is_big_endian();
        let mut edits = Vec::new();
        let mut pos = 0usize;
        for vn in storage.get_varnodes() {
            let size = vn.get_size().max(0) as usize;
            if pos + size > bytes.len() {
                panic!(
                    "Value of {} bytes is too short for storage of {} bytes",
                    bytes.len(),
                    storage.size()
                );
            }
            let mut piece = bytes[pos..pos + size].to_vec();
            pos += size;
            if !big_endian {
                piece.reverse();
            }
            let at = self.leaf_address(&vn);
            edits.push(self.register_map.set_var(editor, &at, &piece));
        }
        Box::pin(async move {
            for edit in edits {
                edit.await;
            }
        })
    }
}

/// The evaluators are constructed already bound to a program, since they need it owned; the
/// program each of these methods is handed is therefore redundant and ignored.
impl<T, S, F> VarnodeEvaluator<T> for FrameVarnodeEvaluator<'_, T, S, F>
where
    F: AbstractUnwoundFrame<T, S> + ?Sized,
    S: PcodeExecutorState<T>,
{
    fn evaluate_varnode(&self, _program: &dyn Program, vn: &Varnode) -> T {
        self.value_of_varnode(vn)
    }

    fn evaluate_storage(&self, _program: &dyn Program, storage: &dyn VariableStorage) -> T {
        self.value_of_storage(storage)
    }

    fn evaluate_op(&self, _program: &dyn Program, _op: &PcodeOp) -> T {
        unimplemented!(
            "AbstractVarnodeEvaluator's p-code op dispatch needs high p-code, which PcodeOp does \
             not model here"
        )
    }
}

/// The behavior of an unwound frame, once its context is known.
///
/// The three required methods are Java's abstract ones; the rest are its concrete ones, which a
/// concrete frame's [`UnwoundFrame`](super::unwound_frame::UnwoundFrame) implementation forwards
/// to.
pub trait AbstractUnwoundFrame<T, S>
where
    S: PcodeExecutorState<T>,
{
    /// The frame's shared state.
    fn frame_base(&self) -> &AbstractUnwoundFrameBase<T, S>;

    /// Get or recover the saved register map, which indicates the location of saved registers on
    /// the stack that apply to this frame.
    ///
    /// Port of the abstract `computeRegisterMap()`.
    fn compute_register_map(&self) -> SavedRegisterMap;

    /// Compute the *address of* the return address.
    ///
    /// Port of the abstract `computeAddressOfReturnAddress()`.
    fn compute_address_of_return_address(&self) -> Address;

    /// Compute the address (in physical stack space) of the given stack offset, which is relative
    /// to the stack pointer at the entry to the function that allocated this frame.
    ///
    /// Port of the abstract `applyBase(long)`.
    fn apply_base(&self, offset: i64) -> Address;

    /// Build an evaluator over this frame's current register map.
    ///
    /// Port of `newEvaluator(AddressSetView)`; `symbol_storage` of `None` builds the
    /// `FrameVarnodeValueGetter` the plain value accessors use instead.
    fn new_evaluator<'a>(
        &'a self,
        program: Arc<dyn Program>,
        symbol_storage: Option<&'a dyn AddressSetView>,
    ) -> FrameVarnodeEvaluator<'a, T, S, Self> {
        FrameVarnodeEvaluator {
            frame: self,
            program,
            register_map: self.compute_register_map(),
            symbol_storage,
            _value: PhantomData,
        }
    }

    /// The value of the given storage, each varnode simply read from the state.
    ///
    /// Port of `getValue(Program, VariableStorage)`.
    fn get_value(&self, program: Arc<dyn Program>, storage: &dyn VariableStorage) -> T {
        self.new_evaluator(program, None).value_of_storage(storage)
    }

    /// The value of the given register, read from wherever this frame saved it.
    ///
    /// Port of `getValue(Register)`.
    fn get_register_value(&self, register: &Register) -> T {
        self.compute_register_map().get_var(
            &self.frame_base().state,
            register.address(),
            register.num_bytes(),
            Reason::Inspect,
        )
    }

    /// Evaluate the given storage, descending to defining p-code ops until symbol storage is
    /// reached.
    ///
    /// Port of `evaluate(Program, VariableStorage, AddressSetView)`.
    fn evaluate<'a>(
        &'a self,
        program: Arc<dyn Program>,
        storage: &dyn VariableStorage,
        symbol_storage: &'a dyn AddressSetView,
    ) -> T {
        self.new_evaluator(program, Some(symbol_storage))
            .value_of_storage(storage)
    }

    /// Evaluate the given varnode, descending to defining p-code ops until symbol storage is
    /// reached.
    ///
    /// Port of `evaluate(Program, Varnode, AddressSetView)`.
    fn evaluate_varnode<'a>(
        &'a self,
        program: Arc<dyn Program>,
        varnode: &Varnode,
        symbol_storage: &'a dyn AddressSetView,
    ) -> T {
        self.new_evaluator(program, Some(symbol_storage))
            .value_of_varnode(varnode)
    }

    /// Evaluate the output of the given p-code op.
    ///
    /// Port of `evaluate(Program, PcodeOp, AddressSetView)`.
    fn evaluate_op<'a>(
        &'a self,
        program: Arc<dyn Program>,
        op: &PcodeOp,
        symbol_storage: &'a dyn AddressSetView,
    ) -> T {
        let evaluator = self.new_evaluator(program, Some(symbol_storage));
        let program = Arc::clone(&evaluator.program);
        VarnodeEvaluator::evaluate_op(&evaluator, program.as_ref(), op)
    }

    /// Set the value of the given storage, redirecting register writes to the location where the
    /// register's current value was saved to the stack, if it was.
    ///
    /// Port of `setValue(StateEditor, Program, VariableStorage, BigInteger)`.
    fn set_value(
        &self,
        editor: &dyn StateEditor,
        program: Arc<dyn Program>,
        storage: &dyn VariableStorage,
        value: i128,
    ) -> StateEditFuture {
        let bytes = big_integer_to_bytes(value, storage.size().max(0) as usize, true);
        self.new_evaluator(program, None)
            .set_storage(editor, storage, &bytes)
    }

    /// Set the return address of this frame.
    ///
    /// Port of `setReturnAddress(StateEditor, Address)`.
    ///
    /// # Panics
    ///
    /// Panics when the address is not in the frame's code space, where Java throws
    /// `IllegalArgumentException`.
    fn set_return_address(&self, editor: &dyn StateEditor, addr: &Address) -> StateEditFuture {
        let base = self.frame_base();
        if !Arc::ptr_eq(addr.space(), &base.code_space) {
            panic!("Return address must be in {}", base.code_space.name());
        }
        let arithmetic = BytesPcodeArithmetic::for_language(&base.language);
        let bytes =
            arithmetic.from_const_u64(addr.offset() as u64, base.pc.borrow().num_bytes());
        editor.set_variable(&self.compute_address_of_return_address(), &bytes)
    }

    /// Match `value`'s length to `length` by zero extension or truncation.
    ///
    /// Port of `zext(T, int)`.
    fn zext(&self, value: T, length: i32) -> T {
        self.frame_base().zext(value, length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};
    use std::rc::Rc;

    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::pcode::exec::pcode_arithmetic::Purpose;
    use crate::pcode::exec::pcode_executor_state_piece::{
        ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece,
    };
    use crate::pcode::exec::ConcretionError;
    use crate::program::model::address::{
        AddressFactory, AddressRange, AddressSet, AddressSpaceType,
    };
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::language::ParseError;
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::mem::mem_buffer::MemBuffer;
    use crate::program::seam_stubs::{AddressLabelInfo, Processor, VarnodeListStorage};
    use crate::util::task::TaskMonitor;

    /// The address spaces every double shares. [`Address`] equality includes the space, and
    /// `AddressSpace::new` mints a fresh space per call, so they are built once and cloned.
    #[derive(Clone)]
    struct TestSpaces {
        register: Arc<AddressSpace>,
        ram: Arc<AddressSpace>,
    }

    impl TestSpaces {
        fn new() -> Self {
            TestSpaces {
                register: AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1),
                ram: AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 2),
            }
        }
    }

    fn registers(register_space: &Arc<AddressSpace>) -> Vec<RegisterRef> {
        vec![
            Register::new(
                "RBX",
                "callee-saved",
                register_space.address(0x08),
                8,
                true,
                0,
            ),
            Register::new(
                "PC",
                "program counter",
                register_space.address(0x30),
                8,
                true,
                Register::TYPE_PC,
            ),
        ]
    }

    fn register_named(spaces: &TestSpaces, name: &str) -> RegisterRef {
        registers(&spaces.register)
            .into_iter()
            .find(|r| r.borrow().name() == name)
            .expect("test register")
    }

    /// Little-endian `i64` arithmetic with the three ops the frame actually performs --
    /// `INT_ZEXT`, `INT_LEFT` and `INT_OR` -- implemented for real, so `zext` and the storage
    /// concatenation can be checked against the values Java would produce.
    #[derive(Debug, Clone, Copy)]
    struct I64Arithmetic;

    impl PcodeArithmetic<i64> for I64Arithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }

        fn unary_op(&self, opcode: OpCode, sizeout: i32, _sizein1: i32, in1: &i64) -> i64 {
            match opcode {
                OpCode::IntZext => mask(*in1, sizeout),
                _ => unimplemented!("not exercised by these tests"),
            }
        }

        fn binary_op(
            &self,
            opcode: OpCode,
            sizeout: i32,
            _sizein1: i32,
            in1: &i64,
            _sizein2: i32,
            in2: &i64,
        ) -> i64 {
            match opcode {
                OpCode::IntLeft => {
                    let shift = *in2 as u32;
                    let shifted = if shift >= 64 {
                        0
                    } else {
                        ((*in1 as u64) << shift) as i64
                    };
                    mask(shifted, sizeout)
                }
                OpCode::IntOr => mask(in1 | in2, sizeout),
                _ => unimplemented!("not exercised by these tests"),
            }
        }

        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &i64,
            _sizein_value: i32,
            in_value: &i64,
        ) -> i64 {
            *in_value
        }

        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &i64,
            _sizein_value: i32,
            in_value: &i64,
        ) -> i64 {
            *in_value
        }

        fn from_const_bytes(&self, value: &[u8]) -> i64 {
            let mut out: u64 = 0;
            for &b in value.iter().rev() {
                out = (out << 8) | u64::from(b);
            }
            out as i64
        }

        fn to_concrete(&self, value: &i64, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(value.to_le_bytes().to_vec())
        }

        fn size_of(&self, _value: &i64) -> i64 {
            8
        }
    }

    fn mask(value: i64, size: i32) -> i64 {
        if size >= 8 || size <= 0 {
            value
        } else {
            value & ((1i64 << (size * 8)) - 1)
        }
    }

    /// A state that answers reads out of a map keyed by address, so a redirected register read can
    /// be told apart from a straight-through one.
    struct MapState {
        cells: RefCell<HashMap<(i32, i64), i64>>,
    }

    impl MapState {
        fn new(cells: &[(&Address, i64)]) -> Self {
            MapState {
                cells: RefCell::new(
                    cells
                        .iter()
                        .map(|(a, v)| ((a.space().space_id(), a.offset()), *v))
                        .collect(),
                ),
            }
        }
    }

    impl ErasedPcodeExecutorStatePiece for MapState {}

    impl PcodeExecutorStatePiece<i64, i64> for MapState {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }
        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            vec![self]
        }
        fn set_var_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            _offset: &i64,
            _size: i32,
            _quantize: bool,
            _val: &i64,
        ) {
            unimplemented!("not exercised by these tests")
        }
        fn set_var_internal_abstract(
            &mut self,
            _space: &Arc<AddressSpace>,
            _offset: &i64,
            _size: i32,
            _val: &i64,
        ) {
            unimplemented!("not exercised by these tests")
        }
        fn get_var_abstract(
            &self,
            space: &Arc<AddressSpace>,
            offset: &i64,
            _size: i32,
            _quantize: bool,
            _reason: Reason,
        ) -> i64 {
            *self
                .cells
                .borrow()
                .get(&(space.space_id(), *offset))
                .unwrap_or(&0)
        }
        fn get_var_internal_abstract(
            &self,
            space: &Arc<AddressSpace>,
            offset: &i64,
            size: i32,
            reason: Reason,
        ) -> i64 {
            self.get_var_abstract(space, offset, size, false, reason)
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, i64)> {
            vec![]
        }
        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by these tests")
        }
        fn clear(&mut self) {
            self.cells.borrow_mut().clear();
        }
    }

    impl PcodeExecutorState<i64> for MapState {}

    /// A language just complete enough for the constructor: it answers the default space and the
    /// program counter, and its endianness drives `setValue`'s byte swap.
    struct TestLanguage {
        spaces: TestSpaces,
        registers: Vec<RegisterRef>,
        has_pc: bool,
    }

    impl TestLanguage {
        fn new(spaces: TestSpaces, has_pc: bool) -> Self {
            let registers = registers(&spaces.register);
            TestLanguage {
                spaces,
                registers,
                has_pc,
            }
        }
    }

    impl Language for TestLanguage {
        fn get_language_id(&self) -> LanguageID {
            unimplemented!("not exercised by these tests")
        }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn ParallelInstructionLanguageHelper>> {
            None
        }
        fn get_processor(&self) -> Box<dyn Processor> {
            unimplemented!("not exercised by these tests")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.spaces.ram)
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.spaces.ram)
        }
        fn is_big_endian(&self) -> bool {
            false
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
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<Box<dyn InstructionPrototype>, ParseError> {
            Err(ParseError::UnknownInstruction(
                UnknownInstructionException::new(),
            ))
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, address: &Address) -> Vec<RegisterRef> {
            self.registers
                .iter()
                .filter(|r| r.borrow().address() == address)
                .cloned()
                .collect()
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
            self.registers.clone()
        }
        fn get_register_names(&self) -> Vec<String> {
            self.registers
                .iter()
                .map(|r| r.borrow().name().to_string())
                .collect()
        }
        fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
            self.registers
                .iter()
                .find(|r| r.borrow().name() == name)
                .cloned()
        }
        fn get_register_at(&self, addr: &Address, size: i32) -> Option<RegisterRef> {
            self.registers
                .iter()
                .find(|r| {
                    let r = r.borrow();
                    r.address() == addr && (size == 0 || r.minimum_byte_size() == size)
                })
                .cloned()
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            if self.has_pc {
                self.get_register_by_name("PC")
            } else {
                None
            }
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn reload_language(&self, _task_monitor: &dyn TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &CompilerSpecID,
        ) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
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
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    /// A platform that answers only the language question the constructor asks.
    struct TestPlatform {
        spaces: TestSpaces,
        has_pc: bool,
    }

    impl TracePlatform for TestPlatform {
        fn is_guest(&self) -> bool {
            false
        }
        fn is_host(&self) -> bool {
            true
        }
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("these tests never reach the trace")
        }
        fn platform_language(&self) -> Box<dyn Language> {
            Box::new(TestLanguage::new(self.spaces.clone(), self.has_pc))
        }
        fn platform_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by these tests")
        }
        fn platform_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by these tests")
        }
        fn get_data_type_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceBasedDataTypeManager> {
            unimplemented!("not exercised by these tests")
        }
        fn get_host_address_set(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_guest_address_set(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn map_host_to_guest(&self, host_address: Address) -> Option<Address> {
            Some(host_address)
        }
        fn map_host_to_guest_range(&self, host_range: &AddressRange) -> Option<AddressRange> {
            Some(host_range.clone())
        }
        fn map_host_to_guest_set(&self, _host_set: &dyn AddressSetView) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn map_guest_to_host(&self, address: Address) -> Option<Address> {
            Some(address)
        }
        fn map_guest_to_host_range(&self, range: &AddressRange) -> Option<AddressRange> {
            Some(range.clone())
        }
        fn map_guest_to_host_set(&self, _guest_set: &dyn AddressSetView) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_conventional_register_range(
            &self,
            overlay: &Arc<AddressSpace>,
            register: &Register,
        ) -> AddressRange {
            let min = overlay.address(register.address().offset());
            let max = overlay.address(
                register.address().offset() + i64::from(register.minimum_byte_size()) - 1,
            );
            AddressRange::new(min, max)
        }
        fn get_mapped_mem_buffer(&self, _snap: i64, _guest_address: Address) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by these tests")
        }
        fn map_guest_instruction_addresses_to_host(
            &self,
            set: Box<dyn crate::program::seam_stubs::InstructionSet>,
        ) -> Box<dyn crate::program::seam_stubs::InstructionSet> {
            set
        }
    }

    /// A concrete frame, modeled on Java's `ListingUnwoundFrame`: the base pointer and the
    /// register map are recovered once and handed back on demand.
    struct TestFrame {
        base: AbstractUnwoundFrameBase<i64, MapState>,
        base_pointer: Address,
        register_map: SavedRegisterMap,
        of_return: Address,
    }

    impl AbstractUnwoundFrame<i64, MapState> for TestFrame {
        fn frame_base(&self) -> &AbstractUnwoundFrameBase<i64, MapState> {
            &self.base
        }

        fn compute_register_map(&self) -> SavedRegisterMap {
            self.register_map.clone()
        }

        fn compute_address_of_return_address(&self) -> Address {
            self.of_return.clone()
        }

        fn apply_base(&self, offset: i64) -> Address {
            self.base_pointer.add_wrap(offset)
        }
    }

    /// Build a frame whose `RBX` was saved 8 bytes below the base pointer, over a state seeded
    /// with `cells`.
    fn frame(spaces: &TestSpaces, cells: &[(&Address, i64)]) -> TestFrame {
        let base_pointer = spaces.ram.address(0x7fff_0000);
        let mut register_map = SavedRegisterMap::new();
        register_map.put(
            register_named(spaces, "RBX"),
            base_pointer.add_wrap(-8),
        );
        TestFrame {
            base: AbstractUnwoundFrameBase::with_platform(
                DebuggerCoordinates::nowhere(),
                Arc::new(TestPlatform {
                    spaces: spaces.clone(),
                    has_pc: true,
                }),
                MapState::new(cells),
                None,
            ),
            base_pointer,
            register_map,
            of_return: spaces.ram.address(0x7fff_0008),
        }
    }

    #[test]
    fn the_constructor_takes_the_language_code_space_and_pc_from_the_platform() {
        let spaces = TestSpaces::new();
        let frame = frame(&spaces, &[]);
        let base = frame.frame_base();

        // Java: language = platform.getLanguage(); codeSpace = language.getDefaultSpace();
        // pc = language.getProgramCounter().
        assert_eq!(base.code_space.name(), "ram");
        assert_eq!(base.pc.borrow().name(), "PC");
        assert_eq!(base.snap, DebuggerCoordinates::nowhere().get_snap());
        assert_eq!(base.view_snap, DebuggerCoordinates::nowhere().get_view_snap());
        assert!(base.trace.is_none());
        assert!(base.mapping_service.is_none());
    }

    #[test]
    #[should_panic(expected = "Language must have a program counter")]
    fn a_language_without_a_program_counter_is_rejected() {
        let spaces = TestSpaces::new();
        AbstractUnwoundFrameBase::with_platform(
            DebuggerCoordinates::nowhere(),
            Arc::new(TestPlatform {
                spaces: spaces.clone(),
                has_pc: false,
            }),
            MapState::new(&[]),
            None,
        );
    }

    #[test]
    fn a_register_read_is_redirected_to_where_the_frame_saved_it() {
        let spaces = TestSpaces::new();
        let rbx = register_named(&spaces, "RBX");
        let saved_at = spaces.ram.address(0x7fff_0000 - 8);
        // The live register bank still holds the callee's value; the stack holds the caller's.
        let live = spaces.register.address(0x08);
        let frame = frame(&spaces, &[(&live, 0x1111), (&saved_at, 0x2222)]);

        // getValue(Register) reads through the SavedRegisterMap, so it sees the saved value, not
        // the one still in the register bank.
        assert_eq!(frame.get_register_value(&rbx.borrow()), 0x2222);

        // A register the frame never saved reads straight through.
        let pc = register_named(&spaces, "PC");
        assert_eq!(frame.get_register_value(&pc.borrow()), 0);
    }

    #[test]
    fn storage_pieces_are_concatenated_with_the_first_varnode_most_significant() {
        let spaces = TestSpaces::new();
        // Register varnodes, so the read needs no static mapping; neither lies inside a saved
        // register, so both read straight through.
        let hi = spaces.register.address(0x100);
        let lo = spaces.register.address(0x200);
        let frame = frame(&spaces, &[(&hi, 0xaa), (&lo, 0xbbbb)]);
        let program: Arc<dyn Program> = Arc::new(MockProgram);

        // Java concatenates lower-indexed varnodes as the more significant, like big endian:
        // (0xaa << 16) | 0xbbbb.
        let storage = VarnodeListStorage(vec![
            Varnode::new(hi.clone(), 1),
            Varnode::new(lo.clone(), 2),
        ]);
        assert_eq!(frame.get_value(program, &storage), 0x00aa_bbbb);
    }

    #[test]
    #[should_panic(expected = "Cannot map mock_program:ram:0x1000 to dynamic adress")]
    fn a_memory_varnode_that_does_not_map_into_the_trace_is_rejected() {
        let spaces = TestSpaces::new();
        let frame = frame(&spaces, &[]);
        let program: Arc<dyn Program> = Arc::new(MockProgram);

        // Java's `translateMemory` throws DynamicMappingException when the mapping service has no
        // trace location for the static address; with no mapping service at all, there is
        // likewise nowhere to read from.
        let storage = VarnodeListStorage(vec![Varnode::new(spaces.ram.address(0x1000), 4)]);
        frame.get_value(program, &storage);
    }

    #[test]
    fn a_stack_varnode_is_read_through_apply_base() {
        let spaces = TestSpaces::new();
        // applyBase(0x10) lands at basePointer + 0x10.
        let at = spaces.ram.address(0x7fff_0010);
        let frame = frame(&spaces, &[(&at, 0x1234)]);
        let program: Arc<dyn Program> = Arc::new(MockProgram);

        let stack = AddressSpace::new("stack", 64, 1, AddressSpaceType::Stack, 3);
        let storage = VarnodeListStorage(vec![Varnode::new(stack.address(0x10), 8)]);
        assert_eq!(frame.get_value(program, &storage), 0x1234);
    }

    #[test]
    fn zext_matches_int_zext_to_the_requested_length() {
        let spaces = TestSpaces::new();
        let frame = frame(&spaces, &[]);

        // Java: arithmetic.unaryOp(INT_ZEXT, length, sizeOf(value), value).
        assert_eq!(frame.zext(0x1122_3344, 8), 0x1122_3344);
        assert_eq!(frame.zext(0x1122_3344, 2), 0x3344);
        assert_eq!(frame.zext(0x1122_3344, 1), 0x44);
    }

    #[test]
    #[should_panic(expected = "Return address must be in ram")]
    fn a_return_address_outside_the_code_space_is_rejected() {
        let spaces = TestSpaces::new();
        let frame = frame(&spaces, &[]);
        let elsewhere = AddressSpace::new("other", 64, 1, AddressSpaceType::Ram, 4);

        let _ = frame.set_return_address(&NoopEditor, &elsewhere.address(0x400000));
    }

    #[test]
    fn set_value_writes_each_varnode_little_endian_through_the_saved_register_map() {
        let spaces = TestSpaces::new();
        let frame = frame(&spaces, &[]);
        let program: Arc<dyn Program> = Arc::new(MockProgram);
        let editor = RecordingEditor::default();

        // Java: bigIntegerToBytes(value, storage.size(), true) is big endian, then each piece is
        // reversed for a little-endian language.
        let rbx = register_named(&spaces, "RBX");
        let scratch = spaces.register.address(0x100);
        let storage = VarnodeListStorage(vec![
            Varnode::new(scratch.clone(), 2),
            Varnode::new(rbx.borrow().address().clone(), 2),
        ]);
        let _ = frame.set_value(&editor, program, &storage, 0x1122_3344);

        let edits = editor.edits.borrow();
        assert_eq!(edits.len(), 2);
        // First varnode takes the most significant half, 0x1122, written little endian.
        assert_eq!(edits[0], (scratch, vec![0x22, 0x11]));
        // The second is a saved register, so its write is redirected to the stack slot.
        assert_eq!(
            edits[1],
            (spaces.ram.address(0x7fff_0000 - 8), vec![0x44, 0x33])
        );
    }

    /// A program that answers only its name; nothing here reaches further into it.
    struct MockProgram;

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock_program".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86:LE:64:default".to_string()
        }
    }

    /// An editor that records every write instead of performing one.
    #[derive(Default)]
    struct RecordingEditor {
        edits: RefCell<Vec<(Address, Vec<u8>)>>,
    }

    impl StateEditor for RecordingEditor {
        fn get_service(
            &self,
        ) -> Box<dyn crate::app::services::debugger_control_service::DebuggerControlService> {
            unimplemented!("not exercised by these tests")
        }
        fn get_coordinates(&self) -> DebuggerCoordinates {
            DebuggerCoordinates::nowhere()
        }
        fn is_variable_editable(&self, _address: &Address, _length: i32) -> bool {
            true
        }
        fn set_variable(&self, address: &Address, data: &[u8]) -> StateEditFuture {
            self.edits
                .borrow_mut()
                .push((address.clone(), data.to_vec()));
            Box::pin(async {})
        }
    }

    /// An editor that accepts and discards writes.
    struct NoopEditor;

    impl StateEditor for NoopEditor {
        fn get_service(
            &self,
        ) -> Box<dyn crate::app::services::debugger_control_service::DebuggerControlService> {
            unimplemented!("not exercised by these tests")
        }
        fn get_coordinates(&self) -> DebuggerCoordinates {
            DebuggerCoordinates::nowhere()
        }
        fn is_variable_editable(&self, _address: &Address, _length: i32) -> bool {
            true
        }
        fn set_variable(&self, _address: &Address, _data: &[u8]) -> StateEditFuture {
            Box::pin(async {})
        }
    }

    /// Keeps the unused-import checker honest about `Rc`, which the register refs are built from.
    #[test]
    fn saved_register_map_entries_are_shared_register_refs() {
        let spaces = TestSpaces::new();
        let rbx = register_named(&spaces, "RBX");
        let mut map = SavedRegisterMap::new();
        map.put(Rc::clone(&rbx), spaces.ram.address(0x7fff_0000));
        assert_eq!(map.size(), 1);
        // The map redirects a read of the whole register, and nothing else.
        assert_eq!(
            map.redirect(rbx.borrow().address(), 8),
            Some(spaces.ram.address(0x7fff_0000))
        );
        assert_eq!(map.redirect(&spaces.ram.address(0x1000), 8), None);
    }
}
