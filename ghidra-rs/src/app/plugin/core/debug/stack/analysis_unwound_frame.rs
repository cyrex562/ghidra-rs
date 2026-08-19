//! A frame recovered from analysis of a thread's register bank and stack segment.
//!
//! Port of `ghidra.app.plugin.core.debug.stack.AnalysisUnwoundFrame<T>`.
//!
//! The typical pattern for invoking analysis to unwind an entire stack is to use
//! [`StackUnwinder::get_frames`].
//!
//! # Shape
//!
//! Java's class extends `AbstractUnwoundFrame<T>`, which this crate splits into
//! [`AbstractUnwoundFrameBase`] (the state) and [`AbstractUnwoundFrame`] (the behavior). So the
//! frame owns a base and implements the trait; `S`, the type of the machine state, is a type
//! parameter for the same reason it is one there: [`PcodeExecutorState`] is not stored `dyn`.
//!
//! # Deviations
//!
//! * Java's constructor takes a `PluginTool` and reads the platform out of the coordinates. As in
//!   [`AbstractUnwoundFrameBase::with_platform`] and [`StackUnwinder`], the platform and the
//!   mapping service are passed directly: `tool.getService(...)` cannot resolve
//!   [`DebuggerStaticMappingService`] through this crate's [`PluginTool`], and
//!   [`DebuggerCoordinates::platform`] will only attach a platform that can hand back its own
//!   trace.
//! * Java keeps a back-reference to the `StackUnwinder` that produced the frame, purely so
//!   [`unwind_next`](AnalysisUnwoundFrame::unwind_next) can ask it for the next frame up. Holding
//!   the unwinder here would be a reference cycle (the unwinder caches its frames), so
//!   `unwind_next` takes the unwinder as a parameter instead.
//! * The frame does not implement [`UnwoundFrame`](super::unwound_frame::UnwoundFrame). That
//!   trait's value accessors take `&dyn Program` while [`AbstractUnwoundFrame`]'s take
//!   `Arc<dyn Program>` (see that module's docs), and a borrow cannot be widened back into an
//!   `Arc`, so the abstract class's behavior cannot be forwarded to the interface. Java's
//!   overrides of the interface are inherent methods here, under the same names.
//! * `generateStructure` and everything downstream of it depend on `FrameStructureBuilder`, which
//!   is [not ported](crate::app::seam_stubs::FrameStructureBuilder). The error path -- which is
//!   the one the unwinder currently reaches, since it can only produce error-carrying
//!   [`UnwindInfo`] -- is implemented in full.

use std::rc::Rc;
use std::sync::Arc;

use crate::app::plugin::core::debug::stack::abstract_unwound_frame::{
    AbstractUnwoundFrame, AbstractUnwoundFrameBase,
};
use crate::app::plugin::core::debug::stack::stack_unwinder::{
    frames_path, StackUnwinder, BASE_OP_INDEX, PC_OP_INDEX,
};
use crate::app::plugin::core::debug::stack::unwind_exception::UnwindException;
use crate::app::seam_stubs::{
    BookmarkNavigator, FrameStructureBuilder, SavedRegisterMap, StackUnwindWarningSet, UnwindInfo,
};
use crate::app::services::debugger_static_mapping_service::DebuggerStaticMappingService;
use crate::debug::api::tracemgr::debugger_coordinates::DebuggerCoordinates;
use crate::pcode::exec::debugger_pcode_utils::WatchValue;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::program::model::address::{Address, AddressRange};
use crate::program::model::data::structure::Structure;
use crate::program::model::listing::bookmark_type;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::comment_type::CommentType;
use crate::program::model::listing::function::Function;
use crate::program::model::symbol::{RefType, SourceType};
use crate::trace::model::bookmark::trace_bookmark::TraceBookmark;
use crate::trace::model::guest::trace_platform::TracePlatform;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::listing::trace_code_unit::TraceCodeUnit;
use crate::trace::model::listing::trace_data::TraceData;
use crate::trace::model::trace::Trace;
use crate::trace::seam_stubs::TraceBookmarkType;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// A frame recovered from analysis of a thread's register bank and stack segment.
///
/// `T` is the type of values retrievable from the frame; `S` is the machine state they are read
/// from.
pub struct AnalysisUnwoundFrame<T, S> {
    base: AbstractUnwoundFrameBase<T, S>,
    level: i32,
    pc_val: Address,
    sp_val: Address,
    static_pc_val: Option<Address>,
    info: UnwindInfo,
    /// The map of registers saved by the frames nearer the target than this one.
    ///
    /// Java declares this field package-private and `StackUnwinder` reads it directly.
    pub register_map: SavedRegisterMap,
    /// `info.computeBase(spVal)`, i.e. the stack pointer at entry to the allocating function.
    /// `None` when the frame's depth was never recovered.
    frame_base: Option<Address>,
}

impl<T, S> AnalysisUnwoundFrame<T, S>
where
    S: PcodeExecutorState<T>,
{
    /// Construct an unwound frame.
    ///
    /// Clients should instead use [`StackUnwinder::start`] or similar, or
    /// [`unwind_next`](Self::unwind_next).
    ///
    /// * `coordinates` -- the coordinates (trace, thread, snap, etc.) to examine
    /// * `platform` -- the platform to read the frame against; Java takes the coordinates'
    /// * `state` -- the machine state, typically the watch value state for the same coordinates.
    ///   It is the caller's responsibility to ensure the given state corresponds to the given
    ///   coordinates.
    /// * `mapping_service` -- the static mapping service; Java reads it from the tool
    /// * `pc_val` -- the (dynamic) address of the next instruction when this frame becomes the
    ///   current frame
    /// * `sp_val` -- the address of the top of the stack when this frame becomes the current frame
    /// * `static_pc_val` -- the (static) address of the next instruction
    /// * `info` -- the information used to unwind this frame
    /// * `register_map` -- a map from registers to the offsets of their saved values on the stack
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        coordinates: DebuggerCoordinates,
        platform: Arc<dyn TracePlatform>,
        state: S,
        mapping_service: Option<Arc<dyn DebuggerStaticMappingService>>,
        pc_val: Address,
        sp_val: Address,
        static_pc_val: Option<Address>,
        info: UnwindInfo,
        register_map: SavedRegisterMap,
    ) -> Self {
        let level = coordinates.get_frame();
        let frame_base = info.compute_base(&sp_val);
        AnalysisUnwoundFrame {
            base: AbstractUnwoundFrameBase::with_platform(
                coordinates,
                platform,
                state,
                mapping_service,
            ),
            level,
            pc_val,
            sp_val,
            static_pc_val,
            info,
            register_map,
            frame_base,
        }
    }

    /// The coordinates this frame was unwound at.
    pub fn coordinates(&self) -> &DebuggerCoordinates {
        &self.base.coordinates
    }

    /// Checks whether this is an actual frame, as opposed to the fake frame used to evaluate
    /// variables that need no frame at all.
    ///
    /// Port of `isFake()`, which is always `false` for an analyzed frame.
    pub fn is_fake(&self) -> bool {
        false
    }

    /// The level of this frame, 0 being the innermost.
    pub fn get_level(&self) -> i32 {
        self.level
    }

    /// A description of this frame, for display purposes.
    ///
    /// Port of `getDescription()`. Java interpolates `null` for a missing component and prints the
    /// function via its `toString`, i.e. its name.
    pub fn get_description(&self) -> String {
        fn show(address: Option<&Address>) -> String {
            match address {
                // `Address.toString(false)`, i.e. `toString("")`.
                Some(address) => address.to_string_with_prefix(""),
                None => "null".to_string(),
            }
        }
        format!(
            "{} {} pc={} sp={} base={}",
            self.level,
            match self.info.function.as_ref() {
                Some(function) => Function::get_name(function.as_ref()),
                None => "null".to_string(),
            },
            show(Some(&self.pc_val)),
            show(Some(&self.sp_val)),
            show(self.frame_base.as_ref()),
        )
    }

    /// The frame's program counter.
    ///
    /// Port of `getProgramCounter()`. Unlike the interface's contract, an analyzed frame always
    /// has one: it is what the unwind started from.
    pub fn get_program_counter(&self) -> &Address {
        &self.pc_val
    }

    /// The address of the top of the stack when this frame becomes the current frame.
    ///
    /// Port of `getStackPointer()`.
    pub fn get_stack_pointer(&self) -> &Address {
        &self.sp_val
    }

    /// The program counter mapped into the static (program database) image, if it mapped.
    pub fn get_static_pc(&self) -> Option<&Address> {
        self.static_pc_val.as_ref()
    }

    /// The base pointer for this frame, or `None` if it could not be recovered.
    ///
    /// Port of `getBasePointer()`.
    pub fn get_base_pointer(&self) -> Option<&Address> {
        self.frame_base.as_ref()
    }

    /// The function that allocated this frame, or `None` if it could not be identified.
    ///
    /// Port of `getFunction()`.
    pub fn get_function(&self) -> Option<&Arc<dyn Function>> {
        self.info.function.as_ref()
    }

    /// The unwind information from the analysis used to unwind this frame.
    ///
    /// Port of `getUnwindInfo()`.
    pub fn get_unwind_info(&self) -> &UnwindInfo {
        &self.info
    }

    /// The warnings generated during analysis.
    ///
    /// Port of `getWarnings()`.
    pub fn get_warnings(&self) -> &StackUnwindWarningSet {
        &self.info.warnings
    }

    /// The error explaining why the unwind is in error or incomplete, if it is.
    ///
    /// Port of `getError()`.
    pub fn get_error(&self) -> Option<&Arc<dyn std::error::Error + Send + Sync>> {
        self.info.error.as_ref()
    }

    /// The frame's return address, or `None` if it could not be recovered.
    ///
    /// Port of `getReturnAddress()`.
    pub fn get_return_address(&self) -> Option<Address> {
        let base = self.frame_base.as_ref()?;
        self.info
            .compute_next_pc(base, &self.base.state, &self.base.code_space, &self.base.pc)
    }

    /// The trace this frame was unwound from.
    ///
    /// # Panics
    ///
    /// Panics when the coordinates name no trace, where Java dereferences `null`.
    fn trace(&self) -> &Arc<dyn Trace> {
        self.base
            .trace
            .as_ref()
            .expect("An analyzed frame's coordinates must name a trace")
    }

    /// Generate the structure for [`resolve_structure`](Self::resolve_structure).
    ///
    /// * `prev_param_size` -- the number of bytes occupied by the parameters for the next frame
    ///   down
    ///
    /// Returns the generated structure, or `None` if [`UnwindInfo`] contains an error.
    ///
    /// Port of the protected `generateStructure(int)`.
    pub fn generate_structure(&self, prev_param_size: i32) -> Option<Box<dyn Structure>> {
        if self.info.error.is_some() {
            return None;
        }
        let builder = FrameStructureBuilder::new(
            Arc::clone(&self.base.language),
            self.static_pc_val.clone(),
            UnwindInfo::new(
                self.info.function.clone(),
                self.info.depth,
                self.info.adjust,
                self.info.of_return.clone(),
                self.info.mask_of_return,
                self.info.saved.clone(),
                self.info.warnings.clone(),
                self.info.error.clone(),
            ),
            prev_param_size,
        );
        let mut dtm = self.trace().get_base_data_type_manager();
        Some(builder.build(
            &frames_path(),
            &format!("frame_{}", self.pc_val.to_string_with_prefix("")),
            &mut *dtm,
        ))
    }

    /// Create or resolve the structure data type representing this frame.
    ///
    /// The structure composes a variety of information: 1) The stack variables (locals and
    /// parameters) of the function that allocated the frame. Note that some variables may be
    /// omitted if the function has not allocated them or has already freed them relative to the
    /// frame's program counter. 2) Saved registers. Callee-saved registers will typically appear
    /// closer to the next frame up. Caller-saved registers, assuming Ghidra hasn't already
    /// assigned the stack offset to a local variable, will typically appear close to the next
    /// frame down. 3) The return address, if on the stack.
    ///
    /// * `prev_param_size` -- the number of bytes occupied by the parameters for the next frame
    ///   down. Parameters are pushed by the caller, and so appear to be allocated by the caller;
    ///   however, they really belong to the callee, so this specifies the number of bytes to
    ///   "donate" to the callee's frame.
    ///
    /// Returns the structure, to be placed `prev_param_size` bytes after the frame's stack
    /// pointer.
    ///
    /// # Deviations
    ///
    /// Java adds the generated structure to the trace's data type manager and casts the resolved
    /// type back to `Structure`. [`DataTypeManager::resolve`] hands back a `Box<dyn DataType>`,
    /// which this crate cannot narrow back to a [`Structure`], so the generated structure is
    /// returned as is.
    ///
    /// [`DataTypeManager::resolve`]: crate::program::model::data::data_type_manager::DataTypeManager::resolve
    pub fn resolve_structure(&self, prev_param_size: i32) -> Option<Box<dyn Structure>> {
        self.generate_structure(prev_param_size)
    }

    /// Get or create the bookmark type for warnings.
    ///
    /// Port of the protected `getWarningBookmarkType()`.
    pub fn get_warning_bookmark_type(&self) -> Box<dyn TraceBookmarkType> {
        let trace = self.trace();
        if let Some(type_) = trace.get_bookmark_manager().get_bookmark_type(bookmark_type::WARNING)
        {
            return type_;
        }
        BookmarkNavigator::define_bookmark_types(&*trace.get_program_view());
        trace
            .get_bookmark_manager()
            .get_bookmark_type(bookmark_type::WARNING)
            .expect("BookmarkNavigator defines the warning bookmark type")
    }

    /// Remove `remove` from the bookmark's lifespan, deleting it if nothing is left.
    ///
    /// Port of the protected static `truncateOrDelete(TraceBookmark, Lifespan)`. Java takes the
    /// first of the (at most two) remaining spans, and so does this.
    pub fn truncate_or_delete(tb: &mut dyn TraceBookmark, remove: Lifespan) {
        let new_lifespan = tb.get_lifespan().subtract(remove);
        match new_lifespan.first() {
            Some(span) => tb.set_lifespan(*span),
            None => tb.delete(),
        }
    }

    /// Apply this unwound frame to the trace's listing.
    ///
    /// This performs the following, establishing some conventions for trace stack analysis:
    ///
    /// * Places a bookmark at the frame start indicating any warnings encountered while analyzing
    ///   it.
    /// * Places a structure at (or near) the derived stack pointer whose fields denote the various
    ///   stack entries: local variables, saved registers, return address, parameters. The
    ///   structure may be placed a little after the derived stack pointer to accommodate the
    ///   parameters of an inner stack frame. The structure data type will have the category path
    ///   [`frames_path`]. This allows follow-on analysis to identify data units representing
    ///   unwound frames.
    /// * Places a comment at the start of the frame. This is meant for human consumption, so
    ///   follow-on analysis should not attempt to parse or otherwise interpret it. It indicates
    ///   the frame level (0 being the innermost), the function name, the program counter, the
    ///   stack pointer, and the frame base pointer.
    /// * Places a [`RefType::Data`] reference from the frame start to its own base address. This
    ///   permits follow-on analysis to derive variable values stored on the stack.
    /// * Places a [`RefType::Data`] reference from the program counter to the frame start. This
    ///   allows follow-on analysis to determine the function for the frame.
    ///
    /// The resulting data unit can be retrieved from the trace database and later used to
    /// construct a `ListingUnwoundFrame`. If the frame structure would have length 0 it is not
    /// applied.
    ///
    /// * `prev_param_size` -- the number of bytes occupied by the parameters for the next frame
    ///   down. See [`resolve_structure`](Self::resolve_structure).
    ///
    /// Returns the data unit for the frame structure applied, or `None`.
    ///
    /// # Panics
    ///
    /// Panics where Java throws `AssertionError` wrapping a `CodeUnitInsertionException`, and
    /// where the stack pointer plus `prev_param_size` (or the structure's length) runs off the end
    /// of its address space, where Java's `Address.add` throws.
    pub fn apply_to_listing(
        &self,
        prev_param_size: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<Option<Box<dyn TraceData>>, CancelledException> {
        // TODO: Positive stack growth
        let sp_plus_params = self
            .sp_val
            .add(i64::from(prev_param_size))
            .expect("The frame's parameters must fit in the stack's address space");
        let trace = Arc::clone(self.trace());
        let mut bm = trace.get_bookmark_manager();
        let bt_warn = self.get_warning_bookmark_type();
        let span = Lifespan::now_on_maybe_scratch(self.base.view_snap);
        let warnings = self.info.warnings.summarize().join("\n");
        let structure = self.resolve_structure(prev_param_size);
        let structure = match structure {
            Some(structure) if !structure.is_zero_length() => structure,
            _ => {
                for mut existing in bm.get_bookmarks_at(self.base.view_snap, &sp_plus_params) {
                    Self::truncate_or_delete(&mut *existing, span);
                }
                bm.add_bookmark(
                    span,
                    sp_plus_params,
                    &*bt_warn,
                    "Stack Unwind",
                    // Java's typo, kept so the annotation reads the same either way.
                    &format!("Frame {} has lenght 0", self.level),
                );
                return Ok(None);
            }
        };

        let end = sp_plus_params
            .add(i64::from(structure.get_length()) - 1)
            .expect("The frame's structure must fit in the stack's address space");
        let range = AddressRange::new(sp_plus_params.clone(), end);

        for mut existing in bm.get_bookmarks_intersecting(span, &range) {
            Self::truncate_or_delete(&mut *existing, span);
        }
        if !warnings.trim().is_empty() {
            bm.add_bookmark(
                span,
                sp_plus_params.clone(),
                &*bt_warn,
                "Unwind Stack",
                &warnings,
            );
        }

        let code_manager = trace.get_code_manager();
        code_manager.defined_units().clear(
            Lifespan::at(self.base.view_snap),
            &range,
            false,
            monitor,
        )?;
        let mut frame = code_manager
            .defined_data()
            .create_unsized_on_platform(
                span,
                &sp_plus_params,
                &*self.base.platform,
                &*structure,
            )
            .expect("Java asserts the frame's units were just cleared");
        frame.set_comment(CommentType::Pre, Some(self.get_description()));
        let mut refs = trace.get_reference_manager();
        let frame_range = frame.get_range();
        refs.clear_references_from(span, &frame_range);
        refs.clear_references_to(span, &frame_range);
        if let Some(base) = self.frame_base.as_ref() {
            frame.add_operand_reference(
                BASE_OP_INDEX,
                base.clone(),
                RefType::Data,
                SourceType::Analysis,
            );
        }
        refs.add_memory_reference_to_address(
            span,
            &self.pc_val,
            &sp_plus_params,
            RefType::Data,
            SourceType::Analysis,
            PC_OP_INDEX,
        );
        Ok(Some(frame))
    }
}

impl<S> AnalysisUnwoundFrame<WatchValue, S>
where
    S: PcodeExecutorState<WatchValue>,
{
    /// Unwind the next frame up.
    ///
    /// Unwind the frame that would become current if the function that allocated this frame were
    /// to return. For example, if this frame is at level 3, `unwind_next` will attempt to unwind
    /// the frame at level 4.
    ///
    /// The program counter and stack pointer for the next frame are computed using the state
    /// originally given to [`StackUnwinder::start`] and this frame's unwind information. The
    /// program counter is evaluated like any other variable. The stack pointer is computed by
    /// removing the depth of this frame. Then registers are restored and unwinding proceeds the
    /// same as the starting frame.
    ///
    /// `unwinder` and `states` stand in for the back-reference Java holds and for the state
    /// factory [`StackUnwinder`] needs; see the module docs and [`StackUnwinder`]'s.
    ///
    /// # Panics
    ///
    /// Panics where Java throws `NoSuchElementException`, i.e. when this frame's unwind info
    /// records no return location, so there is no next frame to unwind to.
    pub fn unwind_next<F>(
        &self,
        unwinder: &mut StackUnwinder<S>,
        monitor: &dyn TaskMonitor,
        states: F,
    ) -> Option<Rc<AnalysisUnwoundFrame<WatchValue, S>>>
    where
        F: FnMut(&DebuggerCoordinates) -> S,
    {
        if self.info.of_return.is_none() {
            panic!("This frame records no return location, so there is no next frame");
        }
        unwinder.get_frame(
            &self.base.coordinates,
            self.level + 1,
            None,
            monitor,
            states,
        )
    }
}

impl<T, S> AbstractUnwoundFrame<T, S> for AnalysisUnwoundFrame<T, S>
where
    S: PcodeExecutorState<T>,
{
    fn frame_base(&self) -> &AbstractUnwoundFrameBase<T, S> {
        &self.base
    }

    fn compute_register_map(&self) -> SavedRegisterMap {
        self.register_map.clone()
    }

    /// Port of `computeAddressOfReturnAddress()`, i.e. `info.ofReturn(base)`.
    ///
    /// # Panics
    ///
    /// Panics when the base pointer or the return location was never recovered, where Java
    /// returns `null` and its callers dereference it.
    fn compute_address_of_return_address(&self) -> Address {
        let base = self
            .frame_base
            .as_ref()
            .expect("Cannot locate the return address without the frame's base pointer");
        self.info
            .of_return_at(base)
            .expect("This frame records no return location")
    }

    /// Port of `applyBase(long)`.
    ///
    /// # Panics
    ///
    /// Panics with [`UnwindException`]'s message when the base pointer was never recovered, where
    /// Java throws that (unchecked) exception.
    fn apply_base(&self, offset: i64) -> Address {
        match self.frame_base.as_ref() {
            Some(base) => base.add_wrap(offset),
            None => panic!(
                "{}",
                UnwindException::new(format!(
                    "Cannot compute stack address for offset {offset}.\nFrame error: {}",
                    match self.info.error.as_ref() {
                        Some(error) => error.to_string(),
                        None => "null".to_string(),
                    }
                ))
                .message()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Mutex;

    use crate::app::plugin::core::debug::stack::stack_unwind_warning::CustomStackUnwindWarning;
    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
    use crate::pcode::exec::pcode_executor_state_piece::{
        ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
    };
    use crate::pcode::exec::ConcretionError;
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::pcode::OpCode;
    use crate::program::model::address::{
        AddressFactory, AddressSet, AddressSetView, AddressSpace, AddressSpaceType,
    };
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::language::{Language, ParseError};
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::mem::mem_buffer::MemBuffer;
    use crate::program::seam_stubs::{AddressLabelInfo, Processor};
    use std::collections::HashSet;

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

    /// Little-endian `i64` arithmetic, enough for the concretion `computeNextPc` performs when it
    /// reads the return address back out of the state.
    ///
    /// The frame is generic in its value type; `i64` stands in for `WatchValue` here because
    /// [`WatchValuePcodeArithmetic`](crate::pcode::exec::debugger_pcode_utils::WatchValuePcodeArithmetic)
    /// concretizes through `BytesPcodeArithmetic`, which is not ported.
    #[derive(Debug, Clone, Copy)]
    struct I64Arithmetic;

    impl PcodeArithmetic<i64> for I64Arithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }
        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, in1: &i64) -> i64 {
            *in1
        }
        fn binary_op(
            &self,
            _opcode: OpCode,
            _sizeout: i32,
            _sizein1: i32,
            in1: &i64,
            _sizein2: i32,
            _in2: &i64,
        ) -> i64 {
            *in1
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

    /// A state whose cells are seeded by address, so the return-address read can be checked
    /// against a known value.
    struct MapState {
        cells: Mutex<Vec<(Address, i64)>>,
    }

    impl MapState {
        fn new(cells: &[(&Address, i64)]) -> Self {
            MapState {
                cells: Mutex::new(cells.iter().map(|(a, v)| ((*a).clone(), *v)).collect()),
            }
        }
    }

    impl ErasedPcodeExecutorStatePiece for MapState {}

    impl PcodeExecutorStatePiece<i64, i64> for MapState {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            self.get_arithmetic()
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
            let at = space.address(*offset);
            self.cells
                .lock()
                .unwrap()
                .iter()
                .find(|(a, _)| *a == at)
                .map_or(0, |(_, v)| *v)
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
            self.cells.lock().unwrap().clear();
        }
    }

    impl PcodeExecutorState<i64> for MapState {}

    /// A language just complete enough for the frame's constructor: it answers the default space
    /// and the program counter.
    struct TestLanguage {
        spaces: TestSpaces,
        registers: Vec<RegisterRef>,
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
            self.get_register_by_name("PC")
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
            Box::new(TestLanguage {
                spaces: self.spaces.clone(),
                registers: registers(&self.spaces.register),
            })
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
        fn map_host_to_guest_range(
            &self,
            host_range: &AddressRange,
        ) -> Option<AddressRange> {
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

    /// Build a frame at `sp_val` whose info reports the given depth, return-address offset and
    /// warnings, over a state seeded with `cells`.
    fn frame(
        spaces: &TestSpaces,
        depth: Option<i64>,
        of_return: Option<Address>,
        warnings: &[&str],
        cells: &[(&Address, i64)],
    ) -> AnalysisUnwoundFrame<i64, MapState> {
        let mut warning_set = StackUnwindWarningSet::new();
        for message in warnings {
            warning_set.add(Arc::new(CustomStackUnwindWarning {
                message: (*message).to_string(),
            }));
        }
        let info = UnwindInfo::new(
            None,
            depth,
            None,
            of_return,
            -1,
            Vec::new(),
            warning_set,
            None,
        );
        AnalysisUnwoundFrame::new(
            DebuggerCoordinates::nowhere(),
            Arc::new(TestPlatform {
                spaces: spaces.clone(),
            }),
            MapState::new(cells),
            None,
            spaces.ram.address(0x0040_0123),
            spaces.ram.address(0x7fff_0000),
            None,
            info,
            SavedRegisterMap::new(),
        )
    }

    #[test]
    fn the_base_pointer_is_the_stack_pointer_less_the_frames_depth() {
        let spaces = TestSpaces::new();
        // Java: base = info.computeBase(spVal) = spVal.add(-depth).
        let f = frame(&spaces, Some(-0x20), None, &[], &[]);
        assert_eq!(f.get_base_pointer(), Some(&spaces.ram.address(0x7fff_0020)));
        assert!(!f.is_fake());
        assert_eq!(f.get_level(), DebuggerCoordinates::nowhere().get_frame());
        assert_eq!(*f.get_program_counter(), spaces.ram.address(0x0040_0123));
        assert_eq!(*f.get_stack_pointer(), spaces.ram.address(0x7fff_0000));

        // With no depth recovered there is no base pointer at all.
        let f = frame(&spaces, None, None, &[], &[]);
        assert_eq!(f.get_base_pointer(), None);
    }

    #[test]
    fn apply_base_offsets_from_the_base_pointer() {
        let spaces = TestSpaces::new();
        let f = frame(&spaces, Some(-0x20), None, &[], &[]);
        // Java: base.add(offset).
        assert_eq!(f.apply_base(0x10), spaces.ram.address(0x7fff_0030));
        assert_eq!(f.apply_base(-8), spaces.ram.address(0x7fff_0018));
    }

    #[test]
    #[should_panic(expected = "Cannot compute stack address for offset 16.")]
    fn apply_base_without_a_base_pointer_is_an_unwind_error() {
        let spaces = TestSpaces::new();
        // Java throws UnwindException("Cannot compute stack address for offset %d....").
        frame(&spaces, None, None, &[], &[]).apply_base(0x10);
    }

    #[test]
    fn the_return_address_is_read_from_where_the_frame_stored_it() {
        let spaces = TestSpaces::new();
        // The return address sits 8 bytes above the base pointer, which is 0x20 above the stack
        // pointer, i.e. at 0x7fff0028; the language is little endian.
        let at = spaces.ram.address(0x7fff_0028);
        let f = frame(
            &spaces,
            Some(-0x20),
            Some(spaces.ram.address(8)),
            &[],
            &[(&at, 0x0065_4321)],
        );

        // Java: info.computeNextPc(base, state, codeSpace, pc), masked by maskOfReturn (-1 here).
        assert_eq!(
            f.compute_address_of_return_address(),
            spaces.ram.address(0x7fff_0028)
        );
        assert_eq!(f.get_return_address(), Some(spaces.ram.address(0x0065_4321)));

        // Without a return location there is no return address to read.
        let f = frame(&spaces, Some(-0x20), None, &[], &[]);
        assert_eq!(f.get_return_address(), None);
    }

    #[test]
    fn the_description_names_the_level_function_and_the_three_addresses() {
        let spaces = TestSpaces::new();
        let f = frame(&spaces, Some(-0x20), None, &[], &[]);

        // Java: String.format("%s %s pc=%s sp=%s base=%s", level, info.function(),
        // pcVal.toString(false), spVal.toString(false), base.toString(false)), with a null
        // function printing as "null".
        assert_eq!(
            f.get_description(),
            "0 null pc=00400123 sp=7fff0000 base=7fff0020"
        );

        // A frame with no recovered depth prints a null base.
        let f = frame(&spaces, None, None, &[], &[]);
        assert_eq!(f.get_description(), "0 null pc=00400123 sp=7fff0000 base=null");
    }

    #[test]
    fn the_warnings_and_error_come_from_the_unwind_info() {
        let spaces = TestSpaces::new();
        let f = frame(
            &spaces,
            Some(-0x20),
            None,
            &["Cannot unwind", "Non-returning function"],
            &[],
        );

        assert_eq!(f.get_warnings().size(), 2);
        // Java joins summarize() with newlines when bookmarking the frame.
        assert_eq!(
            f.get_warnings().summarize().join("\n"),
            "Cannot unwind\nNon-returning function"
        );
        assert!(f.get_error().is_none());
        assert!(f.get_unwind_info().of_return.is_none());
    }

    #[test]
    fn a_frame_in_error_generates_no_structure() {
        let spaces = TestSpaces::new();
        let info = UnwindInfo::error_only(UnwindException::new("Cannot find static program"));
        let f = AnalysisUnwoundFrame::new(
            DebuggerCoordinates::nowhere(),
            Arc::new(TestPlatform {
                spaces: spaces.clone(),
            }),
            MapState::new(&[]),
            None,
            spaces.ram.address(0x0040_0123),
            spaces.ram.address(0x7fff_0000),
            None,
            info,
            SavedRegisterMap::new(),
        );

        // Java: `if (info.error() != null) return null;` -- and resolveStructure passes the null
        // straight through.
        assert!(f.generate_structure(0).is_none());
        assert!(f.resolve_structure(0).is_none());
        assert!(f.get_error().is_some());
    }
}
