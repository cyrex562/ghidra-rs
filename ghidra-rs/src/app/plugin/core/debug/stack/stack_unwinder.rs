//! A mechanism for unwinding the stack or parts of it.
//!
//! Port of `ghidra.app.plugin.core.debug.stack.StackUnwinder`.
//!
//! # Deviations forced by unported seams
//!
//! * Java's `getState(PluginTool, DebuggerCoordinates)` delegates to
//!   `DebuggerPcodeUtils.buildWatchState`, which
//!   [is deliberately not ported](crate::pcode::exec::debugger_pcode_utils) (it hinges on a
//!   `SleighLanguage` narrowing that this crate cannot express). Since it is the only way to
//!   obtain the state, the unwinder cannot build one itself: every entry point that Java would
//!   have serviced with `getState(tool, coord)` instead takes a `states` closure of the same
//!   shape, `FnMut(&DebuggerCoordinates) -> S`, and calls it exactly where Java calls
//!   `getState`. `PcodeExecutorState` is not object-safe here, so `S` is a type parameter on the
//!   methods rather than a `dyn` field.
//! * `tool.getService(...)` cannot resolve either of the two services this class uses:
//!   [`PluginTool::get_service`] hands back an `Arc<dyn Any + Send + Sync>`, and neither
//!   [`DebuggerStaticMappingService`] nor [`VariableValueHoverService`] is `Send + Sync`, so the
//!   downcast can never succeed. Both are therefore constructor parameters. `None` reproduces
//!   Java's behavior when the tool provides no such service.
//! * Java caches `platform.getTrace()` in a field. [`TracePlatform::get_trace`] returns an owned
//!   `Box<dyn Trace>`, which cannot be stored and handed out repeatedly, so [`StackUnwinder::trace`]
//!   re-fetches it from the platform instead.

use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use std::sync::Arc;

use crate::app::plugin::core::debug::stack::stack_unwind_warning::CustomStackUnwindWarning;
use crate::app::plugin::core::debug::stack::unwind_exception::UnwindException;
use crate::app::seam_stubs::{
    AnalysisUnwoundFrame, SavedRegisterMap, StackUnwindWarningSet, UnwindInfo,
    VariableValueHoverService,
};
use crate::app::services::debugger_static_mapping_service::DebuggerStaticMappingService;
use crate::debug::api::tracemgr::debugger_coordinates::DebuggerCoordinates;
use crate::framework::seam_stubs::PluginTool;
use crate::pcode::exec::debugger_pcode_utils::WatchValue;
use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
use crate::program::model::address::{Address, AddressSpace};
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::listing::function::Function;
use crate::program::model::symbol::reference;
use crate::program::util::program_location::ProgramLocation;
use crate::trace::model::guest::trace_platform::TracePlatform;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::memory::trace_memory_state::TraceMemoryState;
use crate::trace::model::thread::TraceThread;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_location::TraceLocation;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// The operand index that stack-frame annotations use for the program counter.
///
/// Port of `StackUnwinder.PC_OP_INDEX`, which is `Reference.MNEMONIC`.
pub const PC_OP_INDEX: i32 = reference::MNEMONIC;

/// The operand index that stack-frame annotations use for the base pointer.
///
/// Port of `StackUnwinder.BASE_OP_INDEX`.
pub const BASE_OP_INDEX: i32 = 0;

/// The category the synthesized frame structures are filed under.
///
/// Port of `StackUnwinder.FRAMES_PATH`. Java's is a `static final` field;
/// [`CategoryPath`] is not `const`-constructible, so this is a function.
pub fn frames_path() -> CategoryPath {
    CategoryPath::parse("/Frames").expect("\"/Frames\" is a well-formed category path")
}

/// Why an unwind could not produce information for a frame.
///
/// Java's `computeUnwindInfo` throws `CancelledException` (checked) or `UnwindException`
/// (unchecked); this is the union of the two.
#[derive(Debug)]
pub enum UnwindFailure {
    /// The monitor was cancelled.
    Cancelled(CancelledException),
    /// The program counter could not be located in any open program.
    Unwind(UnwindException),
}

impl std::fmt::Display for UnwindFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnwindFailure::Cancelled(e) => write!(f, "{e}"),
            UnwindFailure::Unwind(e) => write!(f, "{}", e.message()),
        }
    }
}

impl std::error::Error for UnwindFailure {}

/// A thread and a snapshot: the identity under which unwound frames are cached.
///
/// Port of the package-private record `StackUnwinder.ThreadAndSnap`. Java keys on the
/// `TraceThread` itself; `dyn TraceThread` is neither `Eq` nor `Hash`, so the thread's key stands
/// in for it. `None` reproduces Java's null thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ThreadAndSnap {
    /// [`TraceThread::get_key`] of the thread, or `None` when there is no thread.
    pub thread_key: Option<i64>,
    /// The view snapshot, i.e. [`DebuggerCoordinates::get_view_snap`].
    pub view_snap: i64,
}

/// A dynamic program counter mapped into a program database, with the unwind info computed there.
///
/// Port of the package-private record `StackUnwinder.StaticAndUnwind`.
pub struct StaticAndUnwind {
    /// The program counter, translated into the static (program database) image.
    pub static_pc: Address,
    /// The unwind info computed at [`Self::static_pc`], possibly incomplete.
    pub info: UnwindInfo,
}

/// The trace location Java builds with a null thread, to ask the mapping service which program a
/// dynamic address belongs to.
///
/// [`DefaultTraceLocation`](crate::trace::model::default_trace_location::DefaultTraceLocation)
/// requires a thread, so it cannot stand in. The platform (which is `Send + Sync`) is held rather
/// than the trace, since [`TraceLocation`] requires `Send + Sync` while `dyn Trace` does not
/// promise either.
struct PcTraceLocation {
    platform: Arc<dyn TracePlatform>,
    lifespan: Lifespan,
    address: Address,
}

impl TraceLocation for PcTraceLocation {
    fn get_trace(&self) -> Box<dyn Trace> {
        self.platform.get_trace()
    }

    /// Java passes `null` for the thread here, so there is nothing to return.
    fn get_thread(&self) -> Box<dyn TraceThread> {
        unimplemented!("StackUnwinder builds this location with a null thread")
    }

    fn get_lifespan(&self) -> Lifespan {
        self.lifespan
    }

    fn get_address(&self) -> Address {
        self.address.clone()
    }
}

/// A mechanism for unwinding the stack or parts of it.
///
/// It can start at any frame for which the program counter and stack pointer are known. The
/// choice of starting frame is informed by some tradeoffs. For making sense of a specific frame,
/// it might be best to start at the nearest frame with confidently recorded PC and SP values.
/// This will ensure there is little room for error unwinding from the known frame to the desired
/// frame. For retrieving variable values, esp. variables stored in registers, it might be best to
/// start at the innermost frame, unless all registers in a nearer frame are confidently recorded.
/// The registers in frame 0 are typically recorded with highest confidence. This will ensure that
/// all saved register values are properly restored from the stack into the desired frame.
///
/// The iterator unwinds each frame lazily. If [`get_frames`](Self::get_frames) stops sooner than
/// expected, consider using [`start`](Self::start) directly to get better diagnostics.
pub struct StackUnwinder {
    tool: Arc<dyn PluginTool>,
    mappings: Option<Arc<dyn DebuggerStaticMappingService>>,
    service: Option<Arc<dyn VariableValueHoverService>>,
    platform: Arc<dyn TracePlatform>,

    /// The platform's program counter. Java declares this field package-private.
    pub(crate) pc: RegisterRef,
    /// The platform's default code space. Java declares this field package-private.
    pub(crate) code_space: Arc<AddressSpace>,
    sp: RegisterRef,

    unwound: HashMap<ThreadAndSnap, BTreeMap<i32, Rc<AnalysisUnwoundFrame>>>,
    return_error_frame: bool,
}

impl StackUnwinder {
    /// Construct an unwinder.
    ///
    /// * `tool` -- the tool with applicable modules opened as programs
    /// * `platform` -- the trace platform (for registers, spaces, and stack conventions)
    /// * `mappings` -- the static mapping service; Java reads it from the tool
    /// * `service` -- the variable-value hover service; Java reads it from the tool
    ///
    /// # Panics
    ///
    /// Panics where Java's `Objects.requireNonNull` throws, i.e. when the platform's language
    /// declares no program counter, or its compiler spec declares no stack pointer.
    pub fn new(
        tool: Arc<dyn PluginTool>,
        platform: Arc<dyn TracePlatform>,
        mappings: Option<Arc<dyn DebuggerStaticMappingService>>,
        service: Option<Arc<dyn VariableValueHoverService>>,
    ) -> Self {
        let language = platform.platform_language();
        let pc = language
            .get_program_counter()
            .expect("Platform must have a program counter");
        let code_space = language.get_default_space();
        let sp = platform
            .platform_compiler_spec()
            .get_stack_pointer()
            .expect("Platform must have a stack pointer");

        StackUnwinder {
            tool,
            mappings,
            service,
            platform,
            pc,
            code_space,
            sp,
            unwound: HashMap::new(),
            return_error_frame: false,
        }
    }

    /// The tool this unwinder resolves programs and services through.
    pub fn tool(&self) -> &Arc<dyn PluginTool> {
        &self.tool
    }

    /// The trace being unwound.
    ///
    /// Java caches `platform.getTrace()` in a package-private field; the Rust accessor returns an
    /// owned box, so this re-fetches instead of caching.
    pub(crate) fn trace(&self) -> Box<dyn Trace> {
        self.platform.get_trace()
    }

    /// Begin unwinding frames that can evaluate variables from the given state.
    ///
    /// The starting frame's program counter and stack pointer are derived from the trace (in
    /// coordinates), not the state. The program counter will be retrieved from the
    /// [`TraceStackFrame`](crate::trace::model::stack::trace_stack_frame::TraceStackFrame) if
    /// available. Otherwise, it will use the value in the register bank for the starting frame
    /// level. If it is not known, the unwind fails. The static (module) mappings are used to find
    /// the function containing the program counter, and that function is analyzed for its unwind
    /// info, wrt. the mapped program counter. Depending on the complexity of the function, that
    /// analysis may be expensive. If the function cannot be found, the unwind fails. If analysis
    /// fails, the resulting frame may be incomplete, or the unwind may fail.
    ///
    /// `states` stands in for Java's `getState(tool, coordinates)`; see the module docs.
    ///
    /// # Panics
    ///
    /// Panics where Java throws `IllegalArgumentException`, i.e. when the coordinates name a
    /// different platform than this unwinder was built for.
    pub fn start<S, F>(
        &mut self,
        coordinates: &DebuggerCoordinates,
        monitor: &dyn TaskMonitor,
        states: F,
    ) -> Option<Rc<AnalysisUnwoundFrame>>
    where
        S: PcodeExecutorState<WatchValue>,
        F: FnMut(&DebuggerCoordinates) -> S,
    {
        match coordinates.get_platform() {
            Some(p) if Arc::ptr_eq(&p, &self.platform) => {}
            _ => panic!("Not same platform"),
        }
        self.return_error_frame = true;
        self.get_frame(coordinates, coordinates.get_frame(), None, monitor, states)
    }

    /// Unwind up to the given frame level.
    ///
    /// Java also takes the starting state here and ignores it; the state is obtained per level
    /// from `states` instead. The current strategy is to save the [`UnwindInfo`], not the frames.
    pub fn get_frame<S, F>(
        &mut self,
        coordinates: &DebuggerCoordinates,
        level: i32,
        warnings: Option<&mut StackUnwindWarningSet>,
        monitor: &dyn TaskMonitor,
        states: F,
    ) -> Option<Rc<AnalysisUnwoundFrame>>
    where
        S: PcodeExecutorState<WatchValue>,
        F: FnMut(&DebuggerCoordinates) -> S,
    {
        self.unwind_stack(coordinates, level, warnings, monitor, states)
    }

    /// Unwind from the coordinates' frame level out to `target_level`, or until the unwind fails
    /// when `target_level` is negative.
    fn unwind_stack<S, F>(
        &mut self,
        coordinates: &DebuggerCoordinates,
        target_level: i32,
        mut warnings: Option<&mut StackUnwindWarningSet>,
        monitor: &dyn TaskMonitor,
        mut states: F,
    ) -> Option<Rc<AnalysisUnwoundFrame>>
    where
        S: PcodeExecutorState<WatchValue>,
        F: FnMut(&DebuggerCoordinates) -> S,
    {
        let mut state: Option<S> = None;
        let mut register_map = SavedRegisterMap::new();
        let mut frame: Option<Rc<AnalysisUnwoundFrame>> = None;

        let mut level = coordinates.get_frame();
        while level <= target_level || target_level < 0 {
            let coord = coordinates.frame(level);
            if frame.as_ref().is_none_or(|f| f.get_error().is_some()) {
                state = Some(states(&coord));
                register_map = SavedRegisterMap::new();
                frame = None;
            }

            let tas = Self::thread_and_snap(&coord);
            if let Some(saved_frame) = self.unwound.get(&tas).and_then(|m| m.get(&coord.get_frame()))
            {
                // Short circuit here if possible to avoid recomputing UnwindInfo
                let saved_frame = Rc::clone(saved_frame);
                register_map = saved_frame.register_map.clone();
                frame = Some(saved_frame);
                level += 1;
                continue;
            }

            let state_ref = state.as_ref().expect("a state is set on the first pass");
            let pc_val = self.pc_or_sp(frame.as_deref(), &coord, state_ref, true)?;

            // Java computes this only to prime the hover service's unwind-info cache; the result
            // is deliberately discarded.
            if let (Some(loc), Some(service)) =
                (self.get_program_location(coord.get_snap(), &pc_val), self.service.as_ref())
            {
                if service
                    .get_unwind_info(&*loc.get_program(), &loc.get_address(), monitor)
                    .is_none()
                {
                    // Continue here to generate a frame and prevent recalculating info
                    if let Err(UnwindFailure::Cancelled(_)) =
                        self.compute_unwind_info(coord.get_snap(), &pc_val, monitor)
                    {
                        if let Some(warnings) = warnings.as_deref_mut() {
                            warnings.add(Arc::new(CustomStackUnwindWarning {
                                message: format!("Unwind cancelled for frame {level}"),
                            }));
                        }
                    }
                }
            }

            let sp_val = self.pc_or_sp(frame.as_deref(), &coord, state_ref, false)?;

            let next_register_map = Self::update_map(frame.as_deref(), &register_map);
            frame = self
                .unwind(&coord, pc_val, sp_val, next_register_map, monitor)
                .map(Rc::new);
            match frame.as_ref() {
                Some(f) => {
                    register_map = f.register_map.clone();
                    self.unwound
                        .entry(tas)
                        .or_default()
                        .insert(coord.get_frame(), Rc::clone(f));
                }
                None if target_level < 0 => break,
                None => {}
            }
            level += 1;
        }
        frame
    }

    /// Extend the register map with the registers the given frame saved.
    ///
    /// Port of the private `updateMap`.
    fn update_map(
        frame: Option<&AnalysisUnwoundFrame>,
        register_map: &SavedRegisterMap,
    ) -> SavedRegisterMap {
        match frame {
            Some(frame) => {
                let mut next_register_map = register_map.fork();
                if let Some(base) = frame.get_base_pointer() {
                    frame
                        .get_unwind_info()
                        .map_saved_registers(&base, &mut next_register_map);
                }
                next_register_map
            }
            None => register_map.clone(),
        }
    }

    /// Find the frame's program counter (`get_pc`) or stack pointer, trying, in order: the
    /// recorded stack frame, the recorded register bank, unwinding from the previous frame, and
    /// finally the state's own register value.
    ///
    /// Port of the private `pcOrSp`. Returns `None` where Java would have thrown a
    /// `NullPointerException` or failed to concretize the fall-back register.
    fn pc_or_sp<S>(
        &self,
        frame: Option<&AnalysisUnwoundFrame>,
        coordinates: &DebuggerCoordinates,
        state: &S,
        get_pc: bool,
    ) -> Option<Address>
    where
        S: PcodeExecutorState<WatchValue>,
    {
        let thread = coordinates.get_thread();
        let level = coordinates.get_frame();
        let view_snap = coordinates.get_view_snap();
        let register = if get_pc { &self.pc } else { &self.sp };
        let trace = self.trace();

        if let Some(thread) = thread.as_deref() {
            // Try asking the stack
            if let Some(stack) = trace.get_stack_manager().get_stack(thread, view_snap, false) {
                if let Some(frame_for_level) = stack.get_frame(view_snap, level, false) {
                    return Some(if get_pc {
                        frame_for_level.get_program_counter(view_snap)
                    } else {
                        frame_for_level.get_stack_pointer(view_snap)
                    });
                }
            }

            // Try asking the registers
            if let Some(regs) = trace
                .get_memory_manager()
                .get_memory_register_space_at_frame(thread, level, false)
            {
                let range = self
                    .platform
                    .get_conventional_register_range(&regs.address_space(), &register.borrow());
                if TraceMemoryState::Known == regs.get_state(view_snap, range.min_address()) {
                    let mut buf = vec![0u8; range.length() as usize];
                    regs.get_bytes(view_snap, range.min_address(), &mut buf);
                    return Some(self.code_space.address(self.bytes_to_offset(&buf)));
                }
            }
        }

        // Try unwinding the stack
        if let Some(frame) = frame {
            let prev_info = frame.get_unwind_info();
            if let Some(base) = frame.get_base_pointer() {
                let unwound = if get_pc {
                    prev_info.compute_next_pc(&base, state, &self.code_space, &self.pc)
                } else {
                    prev_info.compute_next_sp(&base)
                };
                if unwound.is_some() {
                    return unwound;
                }
            }
        }

        // Fall-back to current frame
        let (_, value) = state.inspect_register_value(register).ok()?;
        Some(self.code_space.address(value as i64))
    }

    /// Read a register's recorded bytes as an offset, honoring the platform's byte order.
    fn bytes_to_offset(&self, bytes: &[u8]) -> i64 {
        let big_endian = self.platform.platform_language().is_big_endian();
        let mut value: u64 = 0;
        if big_endian {
            for &b in bytes {
                value = (value << 8) | u64::from(b);
            }
        } else {
            for &b in bytes.iter().rev() {
                value = (value << 8) | u64::from(b);
            }
        }
        value as i64
    }

    /// Compute the unwind information for the given program counter and context.
    ///
    /// For the most part, this just translates the dynamic program counter to a static program
    /// address and then asks the hover service's analysis for the info at that address. When the
    /// analysis found no return path, it retries at the function's entry point and grafts that
    /// result's return location onto the info for this program counter.
    ///
    /// * `snap` -- the snapshot key (used for mapping the program counter to a program database)
    /// * `pc_val` -- the program counter (dynamic)
    pub fn compute_unwind_info(
        &self,
        snap: i64,
        pc_val: &Address,
        monitor: &dyn TaskMonitor,
    ) -> Result<StaticAndUnwind, UnwindFailure> {
        if monitor.is_cancelled() {
            return Err(UnwindFailure::Cancelled(CancelledException::default()));
        }
        // TODO: Try markup in trace first?
        let Some(static_pc_loc) = self.get_program_location(snap, pc_val) else {
            return Err(UnwindFailure::Unwind(UnwindException::new(format!(
                "Cannot find static program for frame  ({}={})",
                self.pc.borrow().name(),
                pc_val
            ))));
        };
        let program = static_pc_loc.get_program();
        let static_pc = static_pc_loc.get_address();

        // Java wraps the remainder in `catch (Exception e)`, returning `errorOnly(e)`. A missing
        // service, or analysis that yields no info, is where that catch fires here.
        let Some(service) = self.service.as_ref() else {
            return Ok(StaticAndUnwind {
                static_pc,
                info: UnwindInfo::error_only(UnwindException::new(
                    "No VariableValueHoverService to compute unwind info",
                )),
            });
        };
        let Some(info) = service.get_unwind_info(&*program, &static_pc, monitor) else {
            let info = UnwindInfo::error_only(UnwindException::new(format!(
                "No unwind info at {static_pc}"
            )));
            return Ok(StaticAndUnwind { static_pc, info });
        };
        if info.of_return.is_some() {
            return Ok(StaticAndUnwind { static_pc, info });
        }
        let Some(function) = info.function.as_ref() else {
            return Ok(StaticAndUnwind { static_pc, info });
        };
        let ep = function.get_entry_point();
        let Some(ep_info) = service.get_unwind_info(&*program, &ep, monitor) else {
            return Ok(StaticAndUnwind {
                static_pc,
                info: UnwindInfo::error_only(UnwindException::new(format!(
                    "No unwind info at entry point {ep}"
                ))),
            });
        };
        let info = UnwindInfo::new(
            info.function,
            info.depth,
            info.adjust,
            ep_info.of_return,
            ep_info.mask_of_return,
            info.saved,
            info.warnings,
            info.error,
        );
        Ok(StaticAndUnwind { static_pc, info })
    }

    /// Map a dynamic address to the program database it came from.
    ///
    /// Port of the private `getProgramLocation`.
    fn get_program_location(&self, snap: i64, pc_val: &Address) -> Option<Box<dyn ProgramLocation>> {
        let mappings = self.mappings.as_ref()?;
        mappings.get_open_mapped_location(&PcTraceLocation {
            platform: Arc::clone(&self.platform),
            lifespan: Lifespan::at(snap),
            address: pc_val.clone(),
        })
    }

    /// Build one frame at the given coordinates.
    ///
    /// Java also threads the p-code state into the frame; the
    /// [`AnalysisUnwoundFrame`] placeholder cannot hold one, so it is omitted here. Java declares
    /// this method package-private.
    pub(crate) fn unwind(
        &self,
        coordinates: &DebuggerCoordinates,
        pc_val: Address,
        sp_val: Address,
        register_map: SavedRegisterMap,
        monitor: &dyn TaskMonitor,
    ) -> Option<AnalysisUnwoundFrame> {
        match self.compute_unwind_info(coordinates.get_snap(), &pc_val, monitor) {
            Ok(sau) => Some(AnalysisUnwoundFrame::new(
                coordinates.clone(),
                pc_val,
                sp_val,
                Some(sau.static_pc),
                sau.info,
                register_map,
            )),
            Err(e) if self.return_error_frame => Some(AnalysisUnwoundFrame::new(
                coordinates.clone(),
                pc_val,
                sp_val,
                None,
                UnwindInfo::error_only(e),
                register_map,
            )),
            Err(_) => None,
        }
    }

    /// A convenience method: how many thread-and-snapshot frame sets have been recovered.
    ///
    /// Port of `getRecoveredFrameCount()`, whose Javadoc claims "the deepest level" but whose
    /// body returns the cache's size.
    pub fn get_recovered_frame_count(&self) -> usize {
        self.unwound.len()
    }

    /// Discard every cached frame.
    pub fn invalidate_cache(&mut self) {
        self.unwound.clear();
    }

    /// Unwind every frame the target reports for the given coordinates, keyed by level.
    pub fn get_frames<S, F>(
        &mut self,
        coordinates: &DebuggerCoordinates,
        monitor: &dyn TaskMonitor,
        states: F,
    ) -> Option<&BTreeMap<i32, Rc<AnalysisUnwoundFrame>>>
    where
        S: PcodeExecutorState<WatchValue>,
        F: FnMut(&DebuggerCoordinates) -> S,
    {
        let max = self.get_target_reported_max_frame(coordinates);
        self.unwind_stack(coordinates, max, None, monitor, states);
        self.unwound.get(&Self::thread_and_snap(coordinates))
    }

    /// Find the outermost unwound frame for the given function at or beyond the coordinates'
    /// level, falling back to the nearest match at a shallower level.
    ///
    /// Java compares functions by reference identity, so this uses [`Arc::ptr_eq`].
    pub fn find_match_for_function<S, F>(
        &mut self,
        function: &Arc<dyn Function>,
        coordinates: &DebuggerCoordinates,
        warnings: &mut StackUnwindWarningSet,
        monitor: &dyn TaskMonitor,
        states: F,
    ) -> Option<Rc<AnalysisUnwoundFrame>>
    where
        S: PcodeExecutorState<WatchValue>,
        F: FnMut(&DebuggerCoordinates) -> S,
    {
        let max = self.get_target_reported_max_frame(coordinates);
        self.unwind_stack(coordinates, max, Some(warnings), monitor, states);

        let mut candidate = None;
        let frames = self.unwound.get(&Self::thread_and_snap(coordinates))?;
        for (level, frame) in frames {
            if !frame.get_function().is_some_and(|f| Arc::ptr_eq(f, function)) {
                continue;
            }
            warnings.add_all(frame.get_warnings());
            candidate = Some(Rc::clone(frame));
            if *level >= coordinates.get_frame() {
                return candidate;
            }
        }
        candidate
    }

    /// The deepest frame level the target reports for these coordinates, or -1 when it reports no
    /// stack at all.
    fn get_target_reported_max_frame(&self, coordinates: &DebuggerCoordinates) -> i32 {
        let Some(thread) = coordinates.get_thread() else {
            return -1;
        };
        let snap = coordinates.get_view_snap();
        match self
            .trace()
            .get_stack_manager()
            .get_stack(&*thread, snap, false)
        {
            Some(stack) => stack.get_depth(snap) - 1,
            None => -1,
        }
    }

    /// The cache key for the given coordinates.
    fn thread_and_snap(coordinates: &DebuggerCoordinates) -> ThreadAndSnap {
        ThreadAndSnap {
            thread_key: coordinates.get_thread().map(|t| t.get_key()),
            view_snap: coordinates.get_view_snap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;
    use std::sync::Mutex;

    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::program::model::address::{
        AddressFactory, AddressRange, AddressSet, AddressSetView, AddressSpaceType,
    };
    use crate::program::model::lang::compiler_spec::{CompilerSpec, EvaluationModelType};
    use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
    use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
    use crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException;
    use crate::program::model::lang::decompiler_language::DecompilerLanguage;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::language::{Language, ParseError};
    use crate::program::model::lang::language_description::LanguageDescription;
    use crate::program::model::lang::language_id::LanguageID;
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::lang::prototype_model::PrototypeModel;
    use crate::program::model::lang::register::Register;
    use crate::program::model::lang::unknown_instruction_exception::UnknownInstructionException;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::model::listing::parameter::Parameter;
    use crate::program::model::mem::mem_buffer::MemBuffer;
    use crate::program::model::pcode::Encoder;
    use crate::program::seam_stubs::{AddressLabelInfo, PcodeInjectLibrary, Processor};

    /// The register file shared by the test language and compiler spec.
    fn test_registers(register_space: &Arc<AddressSpace>) -> Vec<RegisterRef> {
        vec![
            Register::new(
                "SP",
                "stack pointer",
                register_space.address(0x10),
                8,
                true,
                Register::TYPE_SP,
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

    /// The address spaces every test double shares. [`Address`] equality includes the space, and
    /// `AddressSpace::new` mints a fresh space per call, so they must be built once and cloned.
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

    struct TestLanguage {
        spaces: TestSpaces,
        registers: Vec<RegisterRef>,
        /// When false, [`Language::get_program_counter`] returns `None`, as it does for a
        /// language whose sleigh spec never marks a register `pc`.
        has_pc: bool,
    }

    impl TestLanguage {
        fn new(spaces: TestSpaces, has_pc: bool) -> Self {
            let registers = test_registers(&spaces.register);
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

    struct TestCompilerSpec {
        spaces: TestSpaces,
        registers: Vec<RegisterRef>,
        /// When false, [`CompilerSpec::get_stack_pointer`] returns `None`.
        has_sp: bool,
    }

    impl TestCompilerSpec {
        fn new(spaces: TestSpaces, has_sp: bool) -> Self {
            let registers = test_registers(&spaces.register);
            TestCompilerSpec {
                spaces,
                registers,
                has_sp,
            }
        }
    }

    impl CompilerSpec for TestCompilerSpec {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(TestLanguage::new(self.spaces.clone(), true))
        }
        fn get_compiler_spec_description(&self) -> Box<dyn CompilerSpecDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_compiler_spec_id(&self) -> CompilerSpecID {
            CompilerSpecID::new(Some("default"))
        }
        fn get_stack_pointer(&self) -> Option<RegisterRef> {
            if self.has_sp {
                self.registers
                    .iter()
                    .find(|r| r.borrow().name() == "SP")
                    .cloned()
            } else {
                None
            }
        }
        fn is_stack_right_justified(&self) -> bool {
            false
        }
        fn get_address_space(&self, _space_name: &str) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_stack_space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.spaces.ram)
        }
        fn get_stack_base_space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.spaces.ram)
        }
        fn stack_grows_negative(&self) -> bool {
            true
        }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) {}
        fn get_calling_conventions(&self) -> Vec<Box<dyn PrototypeModel>> {
            Vec::new()
        }
        fn get_calling_convention(&self, _name: &str) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_all_models(&self) -> Vec<Box<dyn PrototypeModel>> {
            Vec::new()
        }
        fn get_default_calling_convention(&self) -> Option<Box<dyn PrototypeModel>> {
            None
        }
        fn get_decompiler_output_language(&self) -> DecompilerLanguage {
            unimplemented!("not exercised by these tests")
        }
        fn get_prototype_evaluation_model(
            &self,
            _model_type: EvaluationModelType,
        ) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by these tests")
        }
        fn is_global(&self, _addr: &Address) -> bool {
            false
        }
        fn get_data_organization(
            &self,
        ) -> Box<dyn crate::program::model::data::data_organization::DataOrganization> {
            unimplemented!("not exercised by these tests")
        }
        fn get_pcode_inject_library(&self) -> Box<dyn PcodeInjectLibrary> {
            unimplemented!("not exercised by these tests")
        }
        fn match_convention(&self, _convention_name: &str) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by these tests")
        }
        fn find_best_calling_convention(
            &self,
            _params: &[&dyn Parameter],
        ) -> Box<dyn PrototypeModel> {
            unimplemented!("not exercised by these tests")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn does_c_data_type_conversions(&self) -> bool {
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
        fn encode(&self, _encoder: &mut dyn Encoder) -> std::io::Result<()> {
            Ok(())
        }
        fn is_equivalent(&self, _other: &dyn CompilerSpec) -> bool {
            false
        }
    }

    /// A platform that answers only the language and compiler-spec questions the constructor and
    /// `computeUnwindInfo` ask. Everything reachable only through the trace is left unimplemented,
    /// since these tests never touch a recorded stack.
    struct TestPlatform {
        spaces: TestSpaces,
        has_pc: bool,
        has_sp: bool,
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
            Box::new(TestCompilerSpec::new(self.spaces.clone(), self.has_sp))
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

    struct TestTool;
    impl PluginTool for TestTool {}

    fn unwinder(has_pc: bool, has_sp: bool) -> StackUnwinder {
        let spaces = TestSpaces::new();
        StackUnwinder::new(
            Arc::new(TestTool),
            Arc::new(TestPlatform {
                spaces,
                has_pc,
                has_sp,
            }),
            None,
            None,
        )
    }

    /// A monitor that reports whatever cancellation state it was built with.
    struct TestMonitor {
        cancelled: bool,
        message: Mutex<String>,
    }

    impl TestMonitor {
        fn new(cancelled: bool) -> Self {
            TestMonitor {
                cancelled,
                message: Mutex::new(String::new()),
            }
        }
    }

    impl TaskMonitor for TestMonitor {
        fn is_cancelled(&self) -> bool {
            self.cancelled
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, message: &str) {
            *self.message.lock().unwrap() = message.to_string();
        }
        fn get_message(&self) -> String {
            self.message.lock().unwrap().clone()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            if self.cancelled {
                Err(CancelledException::default())
            } else {
                Ok(())
            }
        }
        fn increment_progress(&self, _increment_amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(
            &self,
            _listener: &dyn crate::util::task::CancelledListener,
        ) {
        }
        fn set_cancel_enabled(&self, _enable: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    #[test]
    fn the_constructor_takes_the_pc_and_code_space_from_the_language_and_the_sp_from_the_spec() {
        let u = unwinder(true, true);
        assert_eq!(u.pc.borrow().name(), "PC");
        assert_eq!(u.sp.borrow().name(), "SP");
        // Java uses `platform.getLanguage().getDefaultSpace()` for the code space, not the
        // compiler spec's stack space.
        assert_eq!(u.code_space.name(), "ram");
        assert_eq!(u.get_recovered_frame_count(), 0);
    }

    #[test]
    #[should_panic(expected = "Platform must have a program counter")]
    fn a_language_without_a_program_counter_is_rejected() {
        unwinder(false, true);
    }

    #[test]
    #[should_panic(expected = "Platform must have a stack pointer")]
    fn a_compiler_spec_without_a_stack_pointer_is_rejected() {
        unwinder(true, false);
    }

    #[test]
    fn the_java_constants_are_carried_over() {
        // Java: PC_OP_INDEX = Reference.MNEMONIC (-1), BASE_OP_INDEX = 0.
        assert_eq!(PC_OP_INDEX, -1);
        assert_eq!(BASE_OP_INDEX, 0);
        assert_eq!(frames_path().get_path(), "/Frames");
        assert_eq!(frames_path().get_name(), "Frames");
    }

    #[test]
    fn computing_unwind_info_without_a_mapping_service_reports_the_missing_static_program() {
        let u = unwinder(true, true);
        let monitor = TestMonitor::new(false);
        let pc_val = u.code_space.address(0x400123);

        let err = u
            .compute_unwind_info(0, &pc_val, &monitor)
            .err()
            .expect("no mappings means no static program");
        // Java's message, including its double space after "frame".
        assert_eq!(
            err.to_string(),
            format!("Cannot find static program for frame  (PC={pc_val})")
        );
    }

    #[test]
    fn a_cancelled_monitor_stops_the_unwind() {
        let u = unwinder(true, true);
        let monitor = TestMonitor::new(true);
        let pc_val = u.code_space.address(0x400123);

        assert!(matches!(
            u.compute_unwind_info(0, &pc_val, &monitor),
            Err(UnwindFailure::Cancelled(_))
        ));
    }

    #[test]
    fn unwind_yields_a_frame_only_once_start_has_asked_for_error_frames() {
        let mut u = unwinder(true, true);
        let monitor = TestMonitor::new(false);
        let coords = DebuggerCoordinates::nowhere();
        let pc_val = u.code_space.address(0x400123);
        let sp_val = u.code_space.address(0x7fff0000);

        // Java's `returnErrorFrame` starts false, so a failed unwind yields no frame at all.
        assert!(u
            .unwind(
                &coords,
                pc_val.clone(),
                sp_val.clone(),
                SavedRegisterMap::new(),
                &monitor
            )
            .is_none());

        u.return_error_frame = true;
        let frame = u
            .unwind(
                &coords,
                pc_val.clone(),
                sp_val.clone(),
                SavedRegisterMap::new(),
                &monitor,
            )
            .expect("an error frame is returned once requested");
        assert_eq!(*frame.get_program_counter(), pc_val);
        assert_eq!(*frame.get_stack_pointer(), sp_val);
        // The frame carries the failure and nothing else, and its PC never mapped statically.
        assert!(frame.get_static_pc().is_none());
        assert_eq!(
            frame.get_error().expect("errorOnly info").to_string(),
            format!("Cannot find static program for frame  (PC={pc_val})")
        );
        assert!(frame.get_base_pointer().is_none());
    }

    #[test]
    fn updating_the_map_forks_it_and_adds_the_frames_saved_registers() {
        let spaces = TestSpaces::new();
        let sp_reg = test_registers(&spaces.register)
            .into_iter()
            .find(|r| r.borrow().name() == "SP")
            .unwrap();
        let stack = spaces.ram.address(0x7fff0000);

        let mut base_map = SavedRegisterMap::new();
        base_map.put(Rc::clone(&sp_reg), stack.clone());

        // With no frame, Java returns the very same map.
        assert_eq!(
            StackUnwinder::update_map(None, &base_map).size(),
            base_map.size()
        );

        // The frame's info says SP was saved 8 bytes below the base pointer; a depth of 0x20 puts
        // the base pointer 0x20 above the stack pointer.
        let info = UnwindInfo::new(
            None,
            Some(-0x20),
            None,
            None,
            -1,
            vec![(Rc::clone(&sp_reg), spaces.ram.address(-8))],
            StackUnwindWarningSet::new(),
            None,
        );
        let frame = AnalysisUnwoundFrame::new(
            DebuggerCoordinates::nowhere(),
            spaces.ram.address(0x400000),
            stack.clone(),
            None,
            info,
            SavedRegisterMap::new(),
        );

        let next = StackUnwinder::update_map(Some(&frame), &base_map);
        assert_eq!(next.size(), 2);
        // The fork left the original alone.
        assert_eq!(base_map.size(), 1);
        // base = sp - depth = 0x7fff0000 + 0x20; the register was saved 8 below that.
        assert_eq!(next.entries()[1].1, spaces.ram.address(0x7fff0018));
    }
}
