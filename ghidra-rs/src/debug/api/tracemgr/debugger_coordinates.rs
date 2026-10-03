//! The "coordinates" of the Debugger UI: which trace, platform, target, thread, point in time,
//! stack frame, and object are current.
//!
//! Port of `ghidra.debug.api.tracemgr.DebuggerCoordinates`.
//!
//! # Identity
//!
//! Java compares every field with `Objects.equals`. For `Trace`, `TracePlatform`, `Target`,
//! `TraceThread`, and `TraceProgramView` -- none of which override `equals` -- that is reference
//! identity, so the Rust port holds each as an `Option<Arc<dyn _>>` and compares with
//! [`Arc::ptr_eq`]. The "with" methods thread the same `Arc` through, exactly as Java threads the
//! same reference, so derived coordinates keep comparing equal. `TraceSchedule` and `KeyPath` are
//! value classes in Java and are compared by value here too; a schedule's value is its
//! [`schedule_string`](TraceSchedule::schedule_string), which is the round-trippable spec Java's
//! `equals` is defined over.
//!
//! # What is not ported
//!
//! `writeDataState`, `readDataState`, and `getDomainFile` persist coordinates into a tool's saved
//! state. They are built on `SaveState` (JDOM-backed XML persistence), `PluginTool`, and
//! `DBTraceContentHandler`, none of which are ported; standing all three up would mean inventing
//! most of the plugin framework here. They are omitted rather than stubbed, and belong with the
//! trace-manager plugin that drives them.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::app::seam_stubs::Target;
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::Language;
use crate::trace::model::guest::trace_platform::TracePlatform;
use crate::trace::model::lifespan::{self, Lifespan};
use crate::trace::model::program::TraceProgramView;
use crate::trace::model::stack::trace_stack_frame::{KEY_PC, KEY_SP};
use crate::trace::model::target::iface::trace_object_interface::{KEY_COMMENT, KEY_DISPLAY};
use crate::trace::model::target::info::trace_object_info::TraceObjectInfo;
use crate::trace::model::target::path::KeyPath;
use crate::trace::model::target::trace_object::TraceObject;
use crate::trace::model::thread::TraceThread;
use crate::trace::model::thread::trace_thread::KEY_TID;
use crate::trace::model::trace::Trace;
use crate::trace::seam_stubs::{TraceSchedule, trace_schedule_snap};
use crate::util::msg::Msg;

/// The reasons a coordinate transition can be rejected.
///
/// Java throws `IllegalArgumentException` for each of these; the Rust port makes them part of the
/// signature so callers must decide what to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinatesError {
    /// The requested trace differs from the one already fixed by these coordinates.
    ///
    /// Mirrors `IllegalArgumentException("Cannot change trace")`.
    CannotChangeTrace,
    /// A path or object was requested, but these coordinates have no trace to resolve it in.
    ///
    /// Mirrors `IllegalArgumentException("No trace")`.
    NoTrace,
    /// [`DebuggerCoordinates::path_non_canonical`] found no object at the given path.
    ///
    /// Mirrors `IllegalArgumentException("No such object at path " + newPath)`.
    NoSuchObject(KeyPath),
}

impl fmt::Display for CoordinatesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CannotChangeTrace => f.write_str("Cannot change trace"),
            Self::NoTrace => f.write_str("No trace"),
            Self::NoSuchObject(path) => write!(f, "No such object at path {path}"),
        }
    }
}

impl std::error::Error for CoordinatesError {}

/// The `@TraceObjectInfo` of `TraceThread`.
///
/// Mirrors the annotation on `ghidra.trace.model.thread.TraceThread`; the interface's own
/// [`trace_object_info`](TraceThread::trace_object_info) requires `Self: Sized` and so cannot be
/// reached from a `dyn TraceObject`. Same reasoning as
/// [`TraceObject::get_execution_state`]'s inline `ExecutionStateful` info.
fn thread_object_info() -> TraceObjectInfo {
    TraceObjectInfo::new("Thread", "thread", [KEY_TID], [KEY_DISPLAY, KEY_COMMENT])
}

/// The `@TraceObjectInfo` of `TraceStackFrame`, inlined for the same reason as
/// [`thread_object_info`].
fn stack_frame_object_info() -> TraceObjectInfo {
    TraceObjectInfo::new("StackFrame", "frame", [KEY_PC, KEY_SP], [] as [&str; 0])
}

/// Reads a frame level out of a stack frame object's canonical path: the innermost index key that
/// decodes as an integer.
///
/// Mirrors `DBTraceStackFrame.getLevel()`, the only implementation of `TraceStackFrame.getLevel()`.
/// The path scan lives here because [`DebuggerCoordinates::path`] resolves a frame from a bare
/// `dyn TraceObject`, which has no `getLevel`. Java uses `Integer.decode`, hence the `0x`/`#`
/// prefixes.
fn frame_level_of_object_path(path: &KeyPath) -> Option<i32> {
    for i in (0..path.size()).rev() {
        let key = path.key(i);
        if !KeyPath::is_index(key) {
            continue;
        }
        if let Some(level) = decode_int(KeyPath::parse_if_index(key)) {
            return Some(level);
        }
    }
    None
}

/// Mirrors `Integer.decode(String)`: an optional sign, then a `0x`/`0X`/`#` hex, `0` octal, or
/// plain decimal magnitude.
fn decode_int(text: &str) -> Option<i32> {
    let (negative, magnitude) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    let (radix, digits) = if let Some(rest) = magnitude
        .strip_prefix("0x")
        .or_else(|| magnitude.strip_prefix("0X"))
        .or_else(|| magnitude.strip_prefix('#'))
    {
        (16, rest)
    } else if magnitude.len() > 1 && magnitude.starts_with('0') {
        (8, &magnitude[1..])
    } else {
        (10, magnitude)
    };
    let value = i64::from_str_radix(digits, radix).ok()?;
    i32::try_from(if negative { -value } else { value }).ok()
}

/// Java's `Objects.equals` over two references that do not override `equals`.
fn same_ref<T: ?Sized>(a: Option<&Arc<T>>, b: Option<&Arc<T>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    }
}

/// Feeds a reference's identity into a hasher, consistently with [`same_ref`].
fn hash_ref<T: ?Sized, H: Hasher>(value: Option<&Arc<T>>, state: &mut H) {
    match value {
        None => 0usize.hash(state),
        Some(arc) => (Arc::as_ptr(arc) as *const () as usize).hash(state),
    }
}

/// Java's `Objects.equals` over two schedules, which are value classes.
fn same_time(a: Option<&Arc<dyn TraceSchedule>>, b: Option<&Arc<dyn TraceSchedule>>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.schedule_string() == b.schedule_string(),
        _ => false,
    }
}

/// The coordinates of the Debugger UI.
///
/// Port of `ghidra.debug.api.tracemgr.DebuggerCoordinates`. Every "with" method returns fresh
/// coordinates; none mutate the receiver.
#[derive(Clone, Default)]
pub struct DebuggerCoordinates {
    trace: Option<Arc<dyn Trace>>,
    platform: Option<Arc<dyn TracePlatform>>,
    target: Option<Arc<dyn Target>>,
    thread: Option<Arc<dyn TraceThread>>,
    view: Option<Arc<dyn TraceProgramView>>,
    time: Option<Arc<dyn TraceSchedule>>,
    frame: Option<i32>,
    path: Option<KeyPath>,
}

impl DebuggerCoordinates {
    /// Coordinates that indicate no trace is active in the Debugger UI.
    ///
    /// Typically, that only happens when no trace is open. Telling the trace manager to activate
    /// these will cause it to instead activate the most recently active trace, which may very well
    /// be the current trace, resulting in no change. Internally, the trace manager activates them
    /// whenever the current trace is closed, effectively activating the most recent trace other
    /// than the one just closed.
    ///
    /// Port of the `NOWHERE` constant. It is a function rather than a constant because the fields
    /// are heap-allocatable `Option<Arc<_>>`s; every call returns an equal value.
    pub fn nowhere() -> Self {
        Self::default()
    }

    /// True if these are the [`nowhere`](Self::nowhere) coordinates.
    ///
    /// Java tests `this == NOWHERE` by identity, which a value type cannot reproduce; every field
    /// being absent is the same condition.
    pub fn is_nowhere(&self) -> bool {
        self.trace.is_none()
            && self.platform.is_none()
            && self.target.is_none()
            && self.thread.is_none()
            && self.view.is_none()
            && self.time.is_none()
            && self.frame.is_none()
            && self.path.is_none()
    }

    /// Compare two coordinates on everything except the target and the view, taking defaults into
    /// account.
    ///
    /// Port of `equalsIgnoreTargetAndView`.
    pub fn equals_ignore_target_and_view(a: &Self, b: &Self) -> bool {
        if !same_ref(a.trace.as_ref(), b.trace.as_ref()) {
            return false;
        }
        if !same_ref(a.platform.as_ref(), b.platform.as_ref()) {
            return false;
        }
        if !same_ref(a.thread.as_ref(), b.thread.as_ref()) {
            return false;
        }
        // Consider defaults
        if a.get_time().schedule_string() != b.get_time().schedule_string() {
            return false;
        }
        if a.get_frame() != b.get_frame() {
            return false;
        }
        if a.object_key() != b.object_key() {
            return false;
        }
        true
    }

    /// The key of the current object, standing in for Java's reference comparison of
    /// `getObject()`.
    ///
    /// The object is looked up in the trace by canonical path, so within a single trace its key
    /// identifies it exactly as its reference does in Java. Callers of this always compare the
    /// traces first.
    fn object_key(&self) -> Option<i64> {
        self.get_object().map(|o| o.get_key())
    }

    fn resolve_platform(trace: &dyn Trace) -> Arc<dyn TracePlatform> {
        Arc::from(trace.get_platform_manager().get_host_platform())
    }

    /// The live thread with the lowest key at the schedule's snap.
    ///
    /// Port of `resolveThread(Trace, TraceSchedule)`.
    fn resolve_thread_in(
        trace: &dyn Trace,
        time: &dyn TraceSchedule,
    ) -> Option<Arc<dyn TraceThread>> {
        let mut live = trace.get_thread_manager().get_live_threads(time.get_snap());
        live.sort_by_key(|t| t.get_key());
        live.into_iter().next().map(Arc::from)
    }

    /// Port of `resolveThread(Trace)`, which resolves at `TraceSchedule.ZERO`.
    fn resolve_thread_at_zero(trace: &dyn Trace) -> Option<Arc<dyn TraceThread>> {
        Self::resolve_thread_in(trace, trace_schedule_snap(0).as_ref())
    }

    /// Port of `resolveThread(Target, TraceSchedule)`: defer to the target's focus when it is both
    /// focusable and looking at the same snap.
    fn resolve_thread_of_target(
        target: &dyn Target,
        time: &dyn TraceSchedule,
    ) -> Option<Arc<dyn TraceThread>> {
        if target.get_snap() != time.get_snap() || !target.is_supports_focus() {
            return Self::resolve_thread_in(target.get_trace().as_ref(), time);
        }
        let focus = target.get_focus()?;
        target.get_thread_for_successor(&focus).map(Arc::from)
    }

    /// Port of `resolveThread(Trace, Target, TraceSchedule)`.
    fn resolve_thread(
        trace: Option<&Arc<dyn Trace>>,
        target: Option<&Arc<dyn Target>>,
        time: &dyn TraceSchedule,
    ) -> Option<Arc<dyn TraceThread>> {
        match target {
            None => Self::resolve_thread_in(trace?.as_ref(), time),
            Some(target) => Self::resolve_thread_of_target(target.as_ref(), time),
        }
    }

    /// Port of `resolveFrame(TraceThread, TraceSchedule)`.
    ///
    /// Java returns `null` to allow later resolution; [`get_frame`](Self::get_frame) defaults it
    /// to 0.
    fn resolve_frame_default() -> Option<i32> {
        None
    }

    /// Port of `resolveFrame(Target, TraceThread, TraceSchedule)`.
    fn resolve_frame_of_target(
        target: Option<&Arc<dyn Target>>,
        time: &dyn TraceSchedule,
    ) -> Option<i32> {
        let Some(target) = target else {
            return Self::resolve_frame_default();
        };
        if target.get_snap() != time.get_snap() || !target.is_supports_focus() {
            return Self::resolve_frame_default();
        }
        let focus = target.get_focus()?;
        Self::resolve_frame_by_path_of_target(target.as_ref(), &focus)
    }

    /// Port of `resolvePath(TraceThread, Integer, TraceSchedule)`: the thread's object path, or
    /// the requested frame's if the thread has a stack with one.
    fn resolve_path_of_thread(
        thread: Option<&Arc<dyn TraceThread>>,
        frame_level: Option<i32>,
        time: &dyn TraceSchedule,
    ) -> KeyPath {
        let Some(thread) = thread else {
            return KeyPath::root();
        };
        let obj_thread = thread.get_object();
        let Some(frame_level) = frame_level else {
            return obj_thread.get_canonical_path();
        };
        let snap = time.get_snap();
        // Java catches the IllegalStateException raised when the schema specifies no stack and
        // falls back to the thread; the Rust manager reports that absence as `None` instead.
        let stack = thread.get_trace().get_stack_manager().get_stack(thread.as_ref(), snap, false);
        let Some(stack) = stack else {
            return obj_thread.get_canonical_path();
        };
        match stack.get_frame(snap, frame_level, false) {
            None => obj_thread.get_canonical_path(),
            Some(frame) => frame.get_object().get_canonical_path(),
        }
    }

    /// Port of `resolvePath(Target, TraceThread, Integer, TraceSchedule)`.
    fn resolve_path_of_target(
        target: &dyn Target,
        thread: Option<&Arc<dyn TraceThread>>,
        frame_level: Option<i32>,
        time: &dyn TraceSchedule,
    ) -> KeyPath {
        if target.get_snap() != time.get_snap() || !target.is_supports_focus() {
            return Self::resolve_path_of_thread(thread, frame_level, time);
        }
        target.get_focus().unwrap_or_else(KeyPath::root)
    }

    /// Port of `resolveView(Trace, TraceSchedule)`.
    ///
    /// The trace manager adjusts the view's snap to match the coordinates, so the schedule plays
    /// no part.
    fn resolve_view(trace: &dyn Trace) -> Arc<dyn TraceProgramView> {
        Arc::from(trace.get_program_view() as Box<dyn TraceProgramView>)
    }

    /// Port of `resolveTime(TraceProgramView)`: the schedule the view is showing, which for a
    /// scratch snap is the schedule recorded on its snapshot.
    fn resolve_time_of_view(view: Option<&Arc<dyn TraceProgramView>>) -> Option<Arc<dyn TraceSchedule>> {
        let view = view?;
        let snap = view.get_snap();
        if !lifespan::is_scratch(snap) {
            return Some(trace_schedule_snap(snap));
        }
        let snapshot = view.get_trace().get_time_manager().get_snapshot(snap, false);
        match snapshot.and_then(|s| s.get_schedule()) {
            Some(schedule) => Some(schedule),
            None => Some(trace_schedule_snap(snap)),
        }
    }

    /// Port of `choose(KeyPath, KeyPath)`: keep the current path when the newly-resolved one is
    /// merely an ancestor of it, since the current path is the more specific.
    fn choose(cur_path: Option<&KeyPath>, new_path: KeyPath) -> KeyPath {
        let Some(cur_path) = cur_path else {
            return new_path;
        };
        if new_path.is_ancestor(cur_path) {
            cur_path.clone()
        } else {
            new_path
        }
    }

    /// Port of `resolveThread(Trace, KeyPath)`: the thread the object at the path belongs to.
    fn resolve_thread_by_path(trace: &dyn Trace, path: &KeyPath) -> Option<Arc<dyn TraceThread>> {
        let object = trace.get_object_manager().get_object_by_canonical_path(path)?;
        let thread_object = object
            .find_canonical_ancestors_interface(&thread_object_info())
            .into_iter()
            .next()?;
        // `queryCanonicalAncestorsInterface(TraceThread.class)` reifies the ancestor object as its
        // thread; the object-backed `TraceThread` shares the object's key, so the thread manager
        // is the way back to it from a bare `dyn TraceObject`.
        trace.get_thread_manager().get_thread(thread_object.get_key()).map(Arc::from)
    }

    /// Port of `resolveFrame(Trace, KeyPath)`: the level of the stack frame the object at the path
    /// belongs to.
    fn resolve_frame_by_path(trace: &dyn Trace, path: &KeyPath) -> Option<i32> {
        let object = trace.get_object_manager().get_object_by_canonical_path(path)?;
        let frame_object = object
            .find_canonical_ancestors_interface(&stack_frame_object_info())
            .into_iter()
            .next()?;
        frame_level_of_object_path(&frame_object.get_canonical_path())
    }

    /// Port of `resolveThread(Target, KeyPath)`.
    fn resolve_thread_by_path_of_target(
        target: &dyn Target,
        object_path: &KeyPath,
    ) -> Option<Arc<dyn TraceThread>> {
        target.get_thread_for_successor(object_path).map(Arc::from)
    }

    /// Port of `resolveFrame(Target, KeyPath)`.
    fn resolve_frame_by_path_of_target(target: &dyn Target, object_path: &KeyPath) -> Option<i32> {
        target.get_stack_frame_for_successor(object_path).map(|f| f.get_level())
    }

    /// Get these coordinates with the given trace, resolving everything else from it.
    ///
    /// Port of `trace(Trace)`. Passing `None` yields [`nowhere`](Self::nowhere).
    pub fn trace(&self, new_trace: Option<Arc<dyn Trace>>) -> Result<Self, CoordinatesError> {
        let Some(new_trace) = new_trace else {
            return Ok(Self::nowhere());
        };
        if same_ref(self.trace.as_ref(), Some(&new_trace)) {
            return Ok(self.clone());
        }
        if self.trace.is_some() {
            return Err(CoordinatesError::CannotChangeTrace);
        }
        let new_platform = Self::resolve_platform(new_trace.as_ref());
        let new_thread = Self::resolve_thread_at_zero(new_trace.as_ref());
        let new_view = Self::resolve_view(new_trace.as_ref());
        // Leave the time unset to allow later resolution.
        let new_frame = Self::resolve_frame_default();
        let new_path = Self::resolve_path_of_thread(
            new_thread.as_ref(),
            new_frame,
            trace_schedule_snap(0).as_ref(),
        );
        Ok(Self {
            trace: Some(new_trace),
            platform: Some(new_platform),
            target: None,
            thread: new_thread,
            view: Some(new_view),
            time: None,
            frame: new_frame,
            path: Some(new_path),
        })
    }

    /// Get these coordinates with the given platform.
    ///
    /// Port of `platform(TracePlatform)`. Passing `None` restores the trace's host platform.
    pub fn platform(
        &self,
        new_platform: Option<Arc<dyn TracePlatform>>,
    ) -> Result<Self, CoordinatesError> {
        if same_ref(self.platform.as_ref(), new_platform.as_ref()) {
            return Ok(self.clone());
        }
        let Some(new_platform) = new_platform else {
            let Some(trace) = self.trace.as_ref() else {
                return Ok(Self::nowhere());
            };
            return Ok(Self { platform: Some(Self::resolve_platform(trace.as_ref())), ..self.clone() });
        };
        let platform_trace: Arc<dyn Trace> = Arc::from(new_platform.get_trace());
        if self.trace.is_none() {
            let new_thread = Self::resolve_thread_at_zero(platform_trace.as_ref());
            let new_view = Self::resolve_view(platform_trace.as_ref());
            let new_frame = Self::resolve_frame_default();
            let new_path = Self::resolve_path_of_thread(
                new_thread.as_ref(),
                new_frame,
                trace_schedule_snap(0).as_ref(),
            );
            return Ok(Self {
                trace: Some(platform_trace),
                platform: Some(new_platform),
                target: None,
                thread: new_thread,
                view: Some(new_view),
                time: None,
                frame: new_frame,
                path: Some(new_path),
            });
        }
        if !same_ref(self.trace.as_ref(), Some(&platform_trace)) {
            return Err(CoordinatesError::CannotChangeTrace);
        }
        Ok(Self { platform: Some(new_platform), ..self.clone() })
    }

    /// Get these coordinates with the given target, resolving anything still unset from it.
    ///
    /// Port of `target(Target)`.
    pub fn target(&self, new_target: Option<Arc<dyn Target>>) -> Result<Self, CoordinatesError> {
        if same_ref(self.target.as_ref(), new_target.as_ref()) {
            return Ok(self.clone());
        }
        let Some(new_target) = new_target else {
            return Ok(Self { target: None, ..self.clone() });
        };
        let target_trace: Arc<dyn Trace> = Arc::from(new_target.get_trace());
        if self.trace.is_some() && !same_ref(self.trace.as_ref(), Some(&target_trace)) {
            return Err(CoordinatesError::CannotChangeTrace);
        }
        let new_trace = self.trace.clone().unwrap_or(target_trace);
        let new_platform = self
            .platform
            .clone()
            .unwrap_or_else(|| Self::resolve_platform(new_trace.as_ref()));
        let new_time =
            self.time.clone().unwrap_or_else(|| trace_schedule_snap(new_target.get_snap()));
        let new_thread = match self.thread.clone() {
            Some(thread) => Some(thread),
            None => Self::resolve_thread_of_target(new_target.as_ref(), new_time.as_ref()),
        };
        let new_view =
            self.view.clone().unwrap_or_else(|| Self::resolve_view(new_trace.as_ref()));
        let new_frame = match self.frame {
            Some(frame) => Some(frame),
            None => Self::resolve_frame_of_target(Some(&new_target), new_time.as_ref()),
        };
        let thread_or_frame_path = Self::resolve_path_of_target(
            new_target.as_ref(),
            new_thread.as_ref(),
            new_frame,
            new_time.as_ref(),
        );
        Ok(Self {
            trace: Some(new_trace),
            platform: Some(new_platform),
            target: Some(new_target),
            thread: new_thread,
            view: Some(new_view),
            time: Some(new_time),
            frame: new_frame,
            path: Some(Self::choose(self.path.as_ref(), thread_or_frame_path)),
        })
    }

    /// Re-resolve the current thread by key, e.g., after the trace was re-opened.
    ///
    /// Port of `reFindThread()`.
    pub fn re_find_thread(&self) -> Result<Self, CoordinatesError> {
        let (Some(trace), Some(thread)) = (self.trace.as_ref(), self.thread.as_ref()) else {
            return Ok(self.clone());
        };
        let found = trace.get_thread_manager().get_thread(thread.get_key());
        self.thread(found.map(Arc::from))
    }

    /// Get these coordinates with the given thread.
    ///
    /// Port of `thread(TraceThread)`. Passing `None` re-resolves the default thread. Note that
    /// changing threads resets the frame to the default, unless the target says otherwise.
    pub fn thread(
        &self,
        new_thread: Option<Arc<dyn TraceThread>>,
    ) -> Result<Self, CoordinatesError> {
        if same_ref(self.thread.as_ref(), new_thread.as_ref()) {
            return Ok(self.clone());
        }
        if let (Some(new_thread), Some(trace)) = (new_thread.as_ref(), self.trace.as_ref()) {
            let thread_trace: Arc<dyn Trace> = Arc::from(new_thread.get_trace());
            if !Arc::ptr_eq(trace, &thread_trace) {
                return Err(CoordinatesError::CannotChangeTrace);
            }
        }
        let new_thread = match new_thread {
            Some(thread) => Some(thread),
            None => Self::resolve_thread(
                self.trace.as_ref(),
                self.target.as_ref(),
                self.get_time().as_ref(),
            ),
        };
        let new_trace = match (self.trace.clone(), new_thread.as_ref()) {
            (Some(trace), _) => Some(trace),
            (None, Some(thread)) => Some(Arc::from(thread.get_trace())),
            (None, None) => None,
        };
        let Some(new_trace) = new_trace else {
            return Ok(Self::nowhere());
        };
        let new_platform = self
            .platform
            .clone()
            .unwrap_or_else(|| Self::resolve_platform(new_trace.as_ref()));
        let new_time = match self.time.clone() {
            Some(time) => time,
            None => Self::resolve_time_of_view(self.view.as_ref())
                .unwrap_or_else(|| trace_schedule_snap(0)),
        };
        let new_view =
            self.view.clone().unwrap_or_else(|| Self::resolve_view(new_trace.as_ref()));
        // Yes, override frame with the default on thread changes, unless the target says
        // otherwise. Yes, a forced frame change may also force an object change.
        let new_frame = Self::resolve_frame_of_target(self.target.as_ref(), new_time.as_ref());
        let thread_or_frame_path =
            Self::resolve_path_of_thread(new_thread.as_ref(), new_frame, new_time.as_ref());
        Ok(Self {
            trace: Some(new_trace),
            platform: Some(new_platform),
            target: self.target.clone(),
            thread: new_thread,
            view: Some(new_view),
            time: Some(new_time),
            frame: new_frame,
            path: Some(Self::choose(self.path.as_ref(), thread_or_frame_path)),
        })
    }

    /// Get these same coordinates with time replaced by the given snap-only schedule.
    ///
    /// Port of `snap(long)`.
    pub fn snap(&self, snap: i64) -> Self {
        self.time(trace_schedule_snap(snap))
    }

    /// Get these same coordinates with time replaced by the given snap-only schedule, and DO NOT
    /// resolve or adjust anything else.
    ///
    /// Port of `snapNoResolve(long)`.
    pub fn snap_no_resolve(&self, snap: i64) -> Self {
        if let Some(time) = self.time.as_ref() {
            if time.is_snap_only() && time.get_snap() == snap {
                return self.clone();
            }
        }
        Self { time: Some(trace_schedule_snap(snap)), ..self.clone() }
    }

    /// Get these same coordinates with time replaced by the given schedule.
    ///
    /// Port of `time(TraceSchedule)`. The frame resets to the default on every snap change.
    pub fn time(&self, new_time: Arc<dyn TraceSchedule>) -> Self {
        if same_time(self.time.as_ref(), Some(&new_time)) {
            return self.clone();
        }
        let Some(trace) = self.trace.clone() else {
            return Self::nowhere();
        };
        let snap = new_time.get_snap();
        let is_thread_valid = self.thread.as_ref().is_some_and(|t| t.is_valid(snap));
        let new_thread = if is_thread_valid {
            self.thread.clone()
        } else {
            Self::resolve_thread(Some(&trace), self.target.as_ref(), new_time.as_ref())
        };
        let new_frame = Self::resolve_frame_default();
        let thread_or_frame_path =
            Self::resolve_path_of_thread(new_thread.as_ref(), new_frame, new_time.as_ref());
        Self {
            trace: Some(trace),
            platform: self.platform.clone(),
            target: self.target.clone(),
            thread: new_thread,
            view: self.view.clone(),
            time: Some(new_time),
            frame: new_frame,
            path: Some(Self::choose(self.path.as_ref(), thread_or_frame_path)),
        }
    }

    /// Check if the given coordinates are the same as these but with an extra or differing patch.
    ///
    /// Port of `differsOnlyByPatch(DebuggerCoordinates)`.
    pub fn differs_only_by_patch(&self, that: &Self) -> bool {
        if !same_ref(self.trace.as_ref(), that.trace.as_ref()) {
            return false;
        }
        if !same_ref(self.platform.as_ref(), that.platform.as_ref()) {
            return false;
        }
        if !same_ref(self.thread.as_ref(), that.thread.as_ref()) {
            return false;
        }
        // Consider defaults
        if self.get_frame() != that.get_frame() {
            return false;
        }
        if self.object_key() != that.object_key() {
            return false;
        }
        self.get_time().differs_only_by_patch(that.get_time().as_ref())
    }

    /// Get these same coordinates with the given stack frame level.
    ///
    /// Port of `frame(int)`.
    pub fn frame(&self, new_frame: i32) -> Self {
        if self.trace.is_none() {
            return Self::nowhere();
        }
        if self.frame == Some(new_frame) {
            return self.clone();
        }
        let thread_or_frame_path = Self::resolve_path_of_thread(
            self.thread.as_ref(),
            Some(new_frame),
            self.get_time().as_ref(),
        );
        Self {
            frame: Some(new_frame),
            path: Some(Self::choose(self.path.as_ref(), thread_or_frame_path)),
            ..self.clone()
        }
    }

    /// Get these same coordinates with the given stack frame level, if one is given.
    ///
    /// Port of `frame(Integer)`, whose `null` case is a no-op.
    pub fn frame_opt(&self, new_frame: Option<i32>) -> Self {
        match new_frame {
            None => self.clone(),
            Some(frame) => self.frame(frame),
        }
    }

    /// Port of the private `replaceView(TraceProgramView)`.
    fn replace_view(&self, new_view: Arc<dyn TraceProgramView>) -> Self {
        Self { view: Some(new_view), ..self.clone() }
    }

    /// Get these coordinates with the given view, taking the time from it.
    ///
    /// Port of `view(TraceProgramView)`.
    pub fn view(
        &self,
        new_view: Option<Arc<dyn TraceProgramView>>,
    ) -> Result<Self, CoordinatesError> {
        if same_ref(self.view.as_ref(), new_view.as_ref()) {
            return Ok(self.clone());
        }
        let Some(new_view) = new_view else {
            // Java would dereference `newView` below when a trace is already set; only the
            // no-trace case is reachable with a null view.
            return Ok(Self::nowhere());
        };
        let view_trace: Arc<dyn Trace> = Arc::from(new_view.get_trace());
        let time = Self::resolve_time_of_view(Some(&new_view))
            .unwrap_or_else(|| trace_schedule_snap(new_view.get_snap()));
        if self.trace.is_none() {
            return Ok(Self::nowhere()
                .trace(Some(view_trace))?
                .time(time)
                .replace_view(new_view));
        }
        if !same_ref(self.trace.as_ref(), Some(&view_trace)) {
            return Err(CoordinatesError::CannotChangeTrace);
        }
        Ok(self.time(time).replace_view(new_view))
    }

    /// Get these coordinates with the given canonical object path, re-resolving the thread and
    /// frame from it.
    ///
    /// Port of `path(KeyPath)`.
    pub fn path(&self, new_path: Option<KeyPath>) -> Result<Self, CoordinatesError> {
        let Some(trace) = self.trace.clone() else {
            return match new_path {
                None => Ok(Self::nowhere()),
                Some(_) => Err(CoordinatesError::NoTrace),
            };
        };
        let Some(new_path) = new_path else {
            return Ok(Self { path: None, ..self.clone() });
        };
        let (new_thread, new_frame) = match self.target.as_ref() {
            Some(target) => (
                Self::resolve_thread_by_path_of_target(target.as_ref(), &new_path),
                Self::resolve_frame_by_path_of_target(target.as_ref(), &new_path),
            ),
            None => (
                Self::resolve_thread_by_path(trace.as_ref(), &new_path),
                Self::resolve_frame_by_path(trace.as_ref(), &new_path),
            ),
        };
        Ok(Self {
            trace: Some(trace),
            platform: self.platform.clone(),
            target: self.target.clone(),
            thread: new_thread,
            view: self.view.clone(),
            time: self.time.clone(),
            frame: new_frame,
            path: Some(new_path),
        })
    }

    /// Get these coordinates with the given object path, which need not be the object's canonical
    /// one.
    ///
    /// Port of `pathNonCanonical(KeyPath)`.
    pub fn path_non_canonical(&self, new_path: Option<KeyPath>) -> Result<Self, CoordinatesError> {
        let Some(trace) = self.trace.clone() else {
            return match new_path {
                None => Ok(Self::nowhere()),
                Some(_) => Err(CoordinatesError::NoTrace),
            };
        };
        let Some(new_path) = new_path else {
            return Ok(Self { path: None, ..self.clone() });
        };
        let objects = trace.get_object_manager();
        if objects.get_object_by_canonical_path(&new_path).is_some() {
            return self.path(Some(new_path));
        }
        match objects.get_objects_by_path(Lifespan::at(self.get_snap()), &new_path).into_iter().next()
        {
            Some(object) => self.path(Some(object.get_canonical_path())),
            None => Err(CoordinatesError::NoSuchObject(new_path)),
        }
    }

    /// Get these coordinates with the given object.
    ///
    /// Port of `object(TraceObject)`.
    pub fn object(&self, new_object: Option<&dyn TraceObject>) -> Result<Self, CoordinatesError> {
        let Some(new_object) = new_object else {
            return self.path(None);
        };
        self.trace(Some(Arc::from(new_object.get_trace())))?
            .path(Some(new_object.get_canonical_path()))
    }

    /// Get the current trace, if any.
    pub fn get_trace(&self) -> Option<Arc<dyn Trace>> {
        self.trace.clone()
    }

    /// Get the current platform, if any.
    pub fn get_platform(&self) -> Option<Arc<dyn TracePlatform>> {
        self.platform.clone()
    }

    /// Get the current platform's language, if any.
    pub fn get_language(&self) -> Option<Box<dyn Language>> {
        self.platform.as_ref().map(|p| p.platform_language())
    }

    /// Get the current target, if any.
    pub fn get_target(&self) -> Option<Arc<dyn Target>> {
        self.target.clone()
    }

    /// Get the current thread, if any.
    pub fn get_thread(&self) -> Option<Arc<dyn TraceThread>> {
        self.thread.clone()
    }

    /// Get the current view, defaulting to the trace's own variable-snap view.
    pub fn get_view(&self) -> Option<Arc<dyn TraceProgramView>> {
        match (self.view.clone(), self.trace.as_ref()) {
            (Some(view), _) => Some(view),
            // Probably `None`: without a trace there is nothing to default to.
            (None, None) => None,
            (None, Some(trace)) => Some(Self::resolve_view(trace.as_ref())),
        }
    }

    /// Get the current snap, i.e., the snap of the current schedule.
    pub fn get_snap(&self) -> i64 {
        self.get_time().get_snap()
    }

    /// Get the current schedule, defaulting to `TraceSchedule.ZERO`.
    pub fn get_time(&self) -> Arc<dyn TraceSchedule> {
        self.time.clone().unwrap_or_else(|| trace_schedule_snap(0))
    }

    /// Get the current stack frame level, defaulting to 0.
    pub fn get_frame(&self) -> i32 {
        self.frame.unwrap_or(0)
    }

    /// Get the current object's canonical path, if any.
    pub fn get_path(&self) -> Option<&KeyPath> {
        self.path.as_ref()
    }

    /// Get the current object, i.e., the one at [`get_path`](Self::get_path) in the current trace.
    ///
    /// Java memoizes this; the memo is a pure optimization and is dropped here, since the lookup
    /// hands back a fresh handle either way.
    pub fn get_object(&self) -> Option<Box<dyn TraceObject>> {
        let trace = self.trace.as_ref()?;
        let path = self.path.as_ref()?;
        trace.get_object_manager().get_object_by_canonical_path(path)
    }

    /// Get the register container for the current object and frame, if any.
    pub fn get_register_container(&self) -> Option<Box<dyn TraceObject>> {
        self.get_object()?.find_register_container(self.get_frame())
    }

    /// Check whether the given address space is the current object's register space.
    pub fn is_register_space(&self, space: &AddressSpace) -> bool {
        self.get_register_container()
            .is_some_and(|c| c.get_canonical_path().to_string() == space.name())
    }

    /// Get the snap the view should display for these coordinates.
    ///
    /// For a snap-only schedule that is just the snap; otherwise it is the key of the (scratch)
    /// snapshot the emulation service materialized the schedule into.
    pub fn get_view_snap(&self) -> i64 {
        let defaulted_time = self.get_time();
        if defaulted_time.is_snap_only() {
            return defaulted_time.get_snap();
        }
        let snapshots = match self.trace.as_ref() {
            None => Vec::new(),
            Some(trace) => {
                trace.get_time_manager().get_snapshots_with_schedule(defaulted_time.as_ref())
            }
        };
        match snapshots.first() {
            Some(snapshot) => snapshot.get_key(),
            None => {
                Msg::warn(
                    "DebuggerCoordinates",
                    &"Seems the emulation service did not create the requested snapshot, yet",
                );
                defaulted_time.get_snap()
            }
        }
    }

    /// Check whether the given target is live.
    ///
    /// Port of the static `isAlive(Target)`.
    pub fn is_target_alive(target: Option<&dyn Target>) -> bool {
        target.is_some_and(|t| t.is_valid())
    }

    /// Check whether the current target is live.
    pub fn is_alive(&self) -> bool {
        Self::is_target_alive(self.target.as_deref())
    }

    /// Check whether the given target is live and looking at the same snap as the given view.
    ///
    /// Port of the static `isAliveAndPresent(TraceProgramView, Target)`.
    pub fn is_view_alive_and_present(view: &dyn TraceProgramView, target: Option<&dyn Target>) -> bool {
        match target {
            Some(target) if target.is_valid() => target.get_snap() == view.get_snap(),
            _ => false,
        }
    }

    /// Check whether these coordinates are at the target's present, i.e., the target's snap with
    /// no emulated steps.
    ///
    /// Java dereferences the target unconditionally; with no target this reports `false`, which is
    /// what the `isAlive() && isPresent()` guards in [`is_alive_and_present`](Self::is_alive_and_present)
    /// and [`is_dead_or_present`](Self::is_dead_or_present) already ensure.
    pub fn is_present(&self) -> bool {
        let Some(target) = self.target.as_ref() else {
            return false;
        };
        let defaulted_time = self.get_time();
        target.get_snap() == defaulted_time.get_snap() && defaulted_time.is_snap_only()
    }

    /// Check whether reads at these coordinates come from the target's present, ignoring any
    /// emulated steps.
    pub fn is_reads_present(&self) -> bool {
        self.target.as_ref().is_some_and(|t| t.get_snap() == self.get_time().get_snap())
    }

    /// Check whether the target is live and these coordinates are at its present.
    pub fn is_alive_and_present(&self) -> bool {
        self.is_alive() && self.is_present()
    }

    /// Check whether the target is dead, or these coordinates are at its present.
    pub fn is_dead_or_present(&self) -> bool {
        !self.is_alive() || self.is_present()
    }

    /// Check whether the target is live and reads at these coordinates come from its present.
    pub fn is_alive_and_reads_present(&self) -> bool {
        self.is_alive() && self.is_reads_present()
    }
}

impl fmt::Debug for DebuggerCoordinates {
    /// Port of `toString()`, which renders each reference by its own `toString`. The Rust seams
    /// hand back trait objects with no `Debug`, so the identity-bearing fields are rendered as
    /// present/absent instead.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn mark<T: ?Sized>(value: Option<&Arc<T>>) -> &'static str {
            if value.is_some() { "some" } else { "null" }
        }
        write!(
            f,
            "Coords(trace={},target={},thread={},view={},time={},frame={},path={})",
            mark(self.trace.as_ref()),
            mark(self.target.as_ref()),
            mark(self.thread.as_ref()),
            mark(self.view.as_ref()),
            match self.time.as_ref() {
                Some(time) => time.schedule_string(),
                None => "null".to_string(),
            },
            match self.frame {
                Some(frame) => frame.to_string(),
                None => "null".to_string(),
            },
            match self.path.as_ref() {
                Some(path) => path.to_string(),
                None => "null".to_string(),
            },
        )
    }
}

impl PartialEq for DebuggerCoordinates {
    /// Port of `equals(Object)`. Unlike
    /// [`equals_ignore_target_and_view`](DebuggerCoordinates::equals_ignore_target_and_view), this
    /// does *not* consider defaults: unset time and `TraceSchedule.ZERO` are different here.
    fn eq(&self, other: &Self) -> bool {
        same_ref(self.trace.as_ref(), other.trace.as_ref())
            && same_ref(self.platform.as_ref(), other.platform.as_ref())
            && same_ref(self.target.as_ref(), other.target.as_ref())
            && same_ref(self.thread.as_ref(), other.thread.as_ref())
            && same_ref(self.view.as_ref(), other.view.as_ref())
            && same_time(self.time.as_ref(), other.time.as_ref())
            && self.frame == other.frame
            && self.path == other.path
    }
}

impl Eq for DebuggerCoordinates {}

impl Hash for DebuggerCoordinates {
    /// Port of `hashCode()`, which caches `Objects.hash(trace, target, thread, view, time, frame,
    /// path)`. The platform is left out here too.
    fn hash<H: Hasher>(&self, state: &mut H) {
        hash_ref(self.trace.as_ref(), state);
        hash_ref(self.target.as_ref(), state);
        hash_ref(self.thread.as_ref(), state);
        hash_ref(self.view.as_ref(), state);
        self.time.as_ref().map(|t| t.schedule_string()).hash(state);
        self.frame.hash(state);
        self.path.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    /// A target that reports a fixed liveness and snap, like the plugin's real one does once it
    /// has stopped following the target's focus.
    struct MockTarget {
        valid: bool,
        snap: i64,
    }

    impl Target for MockTarget {
        fn is_valid(&self) -> bool {
            self.valid
        }

        fn get_snap(&self) -> i64 {
            self.snap
        }
    }

    fn target(valid: bool, snap: i64) -> Arc<dyn Target> {
        Arc::new(MockTarget { valid, snap })
    }

    fn hash_of(coords: &DebuggerCoordinates) -> u64 {
        let mut hasher = DefaultHasher::new();
        coords.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn nowhere_defaults_match_java_getters() {
        let nowhere = DebuggerCoordinates::nowhere();
        assert!(nowhere.is_nowhere());
        assert!(nowhere.get_trace().is_none());
        assert!(nowhere.get_platform().is_none());
        assert!(nowhere.get_target().is_none());
        assert!(nowhere.get_thread().is_none());
        assert!(nowhere.get_view().is_none());
        assert!(nowhere.get_path().is_none());
        assert!(nowhere.get_object().is_none());
        // getTime() defaults to TraceSchedule.ZERO, getFrame() to 0, getSnap() to ZERO's snap.
        assert_eq!(nowhere.get_time().get_snap(), 0);
        assert!(nowhere.get_time().is_snap_only());
        assert_eq!(nowhere.get_frame(), 0);
        assert_eq!(nowhere.get_snap(), 0);
        assert_eq!(nowhere.get_view_snap(), 0);
    }

    #[test]
    fn to_string_matches_java_format() {
        assert_eq!(
            format!("{:?}", DebuggerCoordinates::nowhere()),
            "Coords(trace=null,target=null,thread=null,view=null,time=null,frame=null,path=null)"
        );
    }

    #[test]
    fn trace_of_none_is_nowhere() {
        let coords = DebuggerCoordinates::nowhere().snap_no_resolve(7);
        assert_eq!(coords.trace(None).unwrap(), DebuggerCoordinates::nowhere());
    }

    #[test]
    fn snap_no_resolve_sets_only_the_time() {
        let nowhere = DebuggerCoordinates::nowhere();
        let at7 = nowhere.snap_no_resolve(7);
        assert_eq!(at7.get_snap(), 7);
        assert!(at7.get_time().is_snap_only());
        assert!(at7.get_trace().is_none());
        assert_eq!(at7.get_frame(), 0);
        assert_ne!(at7, nowhere);
        // Already snap-only at that snap: returns the same coordinates.
        assert_eq!(at7.snap_no_resolve(7), at7);
        assert_eq!(at7.snap_no_resolve(8).get_snap(), 8);
    }

    #[test]
    fn equals_considers_unset_time_distinct_from_zero() {
        let nowhere = DebuggerCoordinates::nowhere();
        let at0 = nowhere.snap_no_resolve(0);
        // getTime() defaults both to ZERO ...
        assert_eq!(nowhere.get_time().get_snap(), at0.get_time().get_snap());
        // ... but equals() does not consider defaults, while equalsIgnoreTargetAndView does.
        assert_ne!(nowhere, at0);
        assert!(DebuggerCoordinates::equals_ignore_target_and_view(&nowhere, &at0));
    }

    #[test]
    fn equal_coordinates_hash_equally() {
        let a = DebuggerCoordinates::nowhere().snap_no_resolve(5);
        let b = DebuggerCoordinates::nowhere().snap_no_resolve(5);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
        assert_ne!(hash_of(&a), hash_of(&DebuggerCoordinates::nowhere().snap_no_resolve(6)));
    }

    #[test]
    fn target_identity_is_by_reference() {
        let one = target(true, 0);
        let two = target(true, 0);
        let with_one = DebuggerCoordinates { target: Some(one.clone()), ..Default::default() };
        let with_same = DebuggerCoordinates { target: Some(one), ..Default::default() };
        let with_other = DebuggerCoordinates { target: Some(two), ..Default::default() };
        assert_eq!(with_one, with_same);
        // Java's Target does not override equals; two distinct targets are never equal.
        assert_ne!(with_one, with_other);
        // equalsIgnoreTargetAndView looks past exactly that difference.
        assert!(DebuggerCoordinates::equals_ignore_target_and_view(&with_one, &with_other));
    }

    #[test]
    fn frame_without_a_trace_is_nowhere() {
        // Java: `frame(int)` short-circuits to NOWHERE when there is no trace.
        let coords = DebuggerCoordinates::nowhere().snap_no_resolve(3);
        assert_eq!(coords.frame(2), DebuggerCoordinates::nowhere());
        // `frame(Integer)` with null is a no-op, even without a trace.
        assert_eq!(coords.frame_opt(None), coords);
    }

    #[test]
    fn time_without_a_trace_is_nowhere() {
        let coords = DebuggerCoordinates::nowhere().snap_no_resolve(3);
        assert_eq!(coords.time(trace_schedule_snap(4)), DebuggerCoordinates::nowhere());
        // An unchanged schedule short-circuits before the no-trace check.
        assert_eq!(coords.time(trace_schedule_snap(3)), coords);
    }

    #[test]
    fn path_without_a_trace_is_nowhere_or_an_error() {
        let nowhere = DebuggerCoordinates::nowhere();
        assert_eq!(nowhere.path(None).unwrap(), nowhere);
        assert_eq!(
            nowhere.path(Some(KeyPath::parse("Processes[0]").unwrap())),
            Err(CoordinatesError::NoTrace)
        );
        assert_eq!(nowhere.object(None).unwrap(), nowhere);
    }

    #[test]
    fn liveness_and_presence_follow_the_target() {
        let nowhere = DebuggerCoordinates::nowhere();
        assert!(!nowhere.is_alive());
        assert!(!nowhere.is_present());
        // Dead (here: absent) targets are vacuously "present".
        assert!(nowhere.is_dead_or_present());
        assert!(!nowhere.is_alive_and_present());
        assert!(!nowhere.is_alive_and_reads_present());

        let live_at_5 =
            DebuggerCoordinates { target: Some(target(true, 5)), ..Default::default() }
                .snap_no_resolve(5);
        assert!(live_at_5.is_alive());
        assert!(live_at_5.is_present());
        assert!(live_at_5.is_reads_present());
        assert!(live_at_5.is_alive_and_present());
        assert!(live_at_5.is_alive_and_reads_present());

        let live_at_5_viewing_4 = live_at_5.snap_no_resolve(4);
        assert!(live_at_5_viewing_4.is_alive());
        assert!(!live_at_5_viewing_4.is_present());
        assert!(!live_at_5_viewing_4.is_dead_or_present());

        let dead = DebuggerCoordinates { target: Some(target(false, 5)), ..Default::default() }
            .snap_no_resolve(5);
        assert!(!dead.is_alive());
        assert!(dead.is_dead_or_present());
        assert!(!dead.is_alive_and_present());
        assert!(!DebuggerCoordinates::is_target_alive(Some(&MockTarget {
            valid: false,
            snap: 0
        })));
    }

    #[test]
    fn choose_keeps_the_more_specific_path() {
        let thread = KeyPath::parse("Processes[0].Threads[1]").unwrap();
        let frame = KeyPath::parse("Processes[0].Threads[1].Stack[0]").unwrap();
        let other = KeyPath::parse("Processes[0].Threads[2]").unwrap();
        // No current path: take the new one.
        assert_eq!(DebuggerCoordinates::choose(None, frame.clone()), frame);
        // The new path is an ancestor of the current one: keep the current, more specific one.
        assert_eq!(DebuggerCoordinates::choose(Some(&frame), thread.clone()), frame);
        // Otherwise the new path wins.
        assert_eq!(DebuggerCoordinates::choose(Some(&thread), frame.clone()), frame);
        assert_eq!(DebuggerCoordinates::choose(Some(&thread), other.clone()), other);
    }

    #[test]
    fn frame_level_comes_from_the_innermost_decodable_index() {
        let path = KeyPath::parse("Processes[0].Threads[1].Stack[2]").unwrap();
        assert_eq!(frame_level_of_object_path(&path), Some(2));
        // Attribute keys are skipped; the scan runs innermost-first.
        let with_attr = KeyPath::parse("Processes[0].Threads[1].Stack[3].Registers").unwrap();
        assert_eq!(frame_level_of_object_path(&with_attr), Some(3));
        // Java uses Integer.decode, so hex indices work.
        let hexed = KeyPath::parse("Stack[0x10]").unwrap();
        assert_eq!(frame_level_of_object_path(&hexed), Some(16));
        // No index at all.
        assert_eq!(frame_level_of_object_path(&KeyPath::parse("Processes").unwrap()), None);
    }

    #[test]
    fn decode_int_matches_java_integer_decode() {
        assert_eq!(decode_int("12"), Some(12));
        assert_eq!(decode_int("-12"), Some(-12));
        assert_eq!(decode_int("0x1f"), Some(31));
        assert_eq!(decode_int("#1F"), Some(31));
        assert_eq!(decode_int("010"), Some(8));
        assert_eq!(decode_int("0"), Some(0));
        assert_eq!(decode_int("main"), None);
    }
}
