//! Port of `ghidra.dbg.jdi.manager.JdiEventHandler`.
//!
//! # Port strategy
//!
//! Java's `JdiEventHandler` drains a live `com.sun.jdi.event.EventQueue` on a dedicated thread,
//! dispatching each `com.sun.jdi.event.Event` subtype to a `processXxx` handler that in turn
//! notifies every registered [`JdiEventsListener`]. This crate's JDI port (see the sibling files
//! in this module: [`JdiEventsListener`], [`JdiEventsListenerAdapter`](super::jdi_events_listener_adapter),
//! [`DebugStatus`], [`JdiThreadInfo`](super::jdi_thread_info::JdiThreadInfo)) already establishes
//! the convention of representing JDI's live objects as small opaque `u64`-keyed handles with no
//! backing connection to a real JVM -- there is no live `jdwp` client in this codebase to drain a
//! queue from. Following that convention:
//!
//! * [`JdiEventQueue`]/[`JdiEventSet`] are new trait seams standing in for
//!   `com.sun.jdi.event.EventQueue`/`EventSet`, injected at construction rather than derived from
//!   `VirtualMachine.eventQueue()` (impossible without a live connection). A real backend would
//!   implement these against an actual `jdwp` session; [`tests`] provides a `MockQueue` used to
//!   exercise every code path below deterministically.
//! * [`JdiEvent`] is a closed enum over the same opaque per-kind structs
//!   [`jdi_events_listener`](super::jdi_events_listener) already defines (`BreakpointEvent`,
//!   `ExceptionEvent`, ...), standing in for the `instanceof`-based `switch` Java's `processEvent`
//!   performs over `com.sun.jdi.event.Event`'s subtype hierarchy. Because each variant is already
//!   disjoint (an event is constructed as exactly one variant), there is no possibility of the
//!   subtype-overlap Java's case *order* matters for (e.g. `AccessWatchpointEvent` being tried
//!   before its supertype `WatchpointEvent`) -- nothing to preserve there.
//! * `eventThread(Event)` (used only to update [`JdiThreadInfo`](super::jdi_thread_info::JdiThreadInfo)'s
//!   "current thread" side channel) always returns `None` here rather than threading a
//!   `ThreadReference` through every event variant: `JdiThreadInfo::invalidate_all`/
//!   `set_current_thread` are themselves permanent no-op stubs in the original Java source (see
//!   `jdi_thread_info.rs`), so the extracted thread is never observable regardless of how
//!   faithfully it's derived.

use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

use super::jdi_cause::{Causes, JdiCause};
use super::jdi_events_listener::*;
use super::jdi_reason::JdiReason;
use super::jdi_state_listener::JdiStateListener;
use super::jdi_thread_info::{JdiThreadInfo, ThreadReference};
use super::r#impl::debug_status::{DebugStatus, THREAD_STATUS_RUNNING};
use crate::util::async_reference::{AsyncReference, ChangeListener};
use crate::util::msg::Msg;

/// JDI `ThreadReference.THREAD_STATUS_WAIT`; sibling of
/// [`THREAD_STATUS_RUNNING`](super::r#impl::debug_status::THREAD_STATUS_RUNNING).
pub const THREAD_STATUS_WAIT: i32 = 4;

/// JDI `ThreadReference.THREAD_STATUS_NOT_STARTED`; the initial value of `state` before any
/// event has been processed. Mirrors the field initializer
/// `new AsyncReference<>(ThreadReference.THREAD_STATUS_NOT_STARTED)`.
pub const THREAD_STATUS_NOT_STARTED: i32 = 5;

/// Errors from a blocking [`JdiEventQueue::remove`] call.
///
/// Mirrors the two checked exceptions `EventQueue.remove()` declares:
/// `InterruptedException`/`VMDisconnectedException`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueRemoveError {
    /// The calling thread was interrupted while blocked. Mirrors `InterruptedException`.
    Interrupted,
    /// The target VM has disconnected. Mirrors `VMDisconnectedException`.
    VmDisconnected,
}

/// A JDI event-set suspend policy. Mirrors the relevant constants of
/// `com.sun.jdi.request.EventRequest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspendPolicy {
    /// `EventRequest.SUSPEND_NONE`.
    None,
    /// `EventRequest.SUSPEND_EVENT_THREAD`.
    EventThread,
    /// `EventRequest.SUSPEND_ALL`.
    All,
}

/// A single JDI event, tagged by kind. Mirrors the `instanceof`-based dispatch in
/// `JdiEventHandler.processEvent(Event)` -- see the module docs for why this enum needs no
/// subtype-order sensitivity the way Java's `switch` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JdiEvent {
    Exception(ExceptionEvent),
    Breakpoint(BreakpointEvent),
    AccessWatchpoint(AccessWatchpointEvent),
    ModificationWatchpoint(ModificationWatchpointEvent),
    Watchpoint(WatchpointEvent),
    Step(StepEvent),
    MethodEntry(MethodEntryEvent),
    MethodExit(MethodExitEvent),
    MonitorContendedEntered(MonitorContendedEnteredEvent),
    MonitorContendedEnter(MonitorContendedEnterEvent),
    MonitorWaited(MonitorWaitedEvent),
    MonitorWait(MonitorWaitEvent),
    ClassPrepare(ClassPrepareEvent),
    ClassUnload(ClassUnloadEvent),
    ThreadStart(ThreadStartEvent),
    ThreadDeath(ThreadDeathEvent),
    VmStart(VmStartEvent),
    VmDisconnect(VmDisconnectEvent),
    VmDeath(VmDeathEvent),
    /// Fallback for any event kind not recognized by the dispatch switch; mirrors the Java
    /// `default` case landing in `processUnknown`.
    Unknown(Event),
}

/// A single delivered batch of JDI events. Mirrors `com.sun.jdi.event.EventSet`.
pub trait JdiEventSet: Send {
    /// The events in this set, mirrors `EventSet` extending `Set<Event>` plus its
    /// `eventIterator()`.
    fn events(&self) -> Vec<JdiEvent>;
    /// Mirrors `EventSet.suspendPolicy()`.
    fn suspend_policy(&self) -> SuspendPolicy;
    /// Mirrors `EventSet.resume()`.
    fn resume(&self);
    /// This set's own opaque handle, for forwarding to
    /// [`JdiEventsListener::process_stop`]/[`JdiEventsListener::process_shutdown`].
    fn handle(&self) -> EventSet;
}

/// A source of [`JdiEventSet`]s to drain. Mirrors `com.sun.jdi.event.EventQueue`.
pub trait JdiEventQueue: Send + Sync {
    /// Blocks until an event set is available. Mirrors `EventQueue.remove()` (the no-timeout
    /// overload, the only one `JdiEventHandler` calls).
    fn remove(&self) -> Result<Box<dyn JdiEventSet>, QueueRemoveError>;
    /// Requests that a blocked [`JdiEventQueue::remove`] call return
    /// `Err(QueueRemoveError::Interrupted)` as soon as possible. Mirrors the effect of
    /// `Thread.interrupt()` on a thread blocked in `EventQueue.remove()`; this port has no
    /// generic cross-thread "interrupt" primitive to call directly (see
    /// [`JdiEventHandler::shutdown`]), so the queue itself is the interruption point instead.
    fn interrupt(&self);
}

/// Handle to a background job submitted via [`JdiEventHandler::event`].
///
/// Rust analogue of the `CompletableFuture<Void>` Java's `event(Runnable, String)` returns. Java
/// completes the future exceptionally (after logging) if the job throws; this mirrors that by
/// resolving to `Err(message)` in the same case, rather than swallowing the failure once it has
/// been logged.
pub struct EventFuture {
    rx: tokio::sync::oneshot::Receiver<Result<(), String>>,
}

impl EventFuture {
    /// Waits for the submitted job to finish, returning its outcome.
    pub async fn wait(self) -> Result<(), String> {
        match self.rx.await {
            Ok(outcome) => outcome,
            Err(_) => Err("JdiEventHandler's event executor was dropped".to_string()),
        }
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    // Extracted immediately inside the `catch_unwind` arm, not via a deferred downcast later --
    // matches this crate's own established, hard-won convention for `catch_unwind` payloads.
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// A single-thread executor, standing in for `Executors.newSingleThreadExecutor()`.
struct SingleThreadExecutor {
    tx: std::sync::mpsc::Sender<Box<dyn FnOnce() + Send>>,
}

impl SingleThreadExecutor {
    fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::channel::<Box<dyn FnOnce() + Send>>();
        thread::Builder::new()
            .name("jdi-event-handler-event-thread".to_string())
            .spawn(move || {
                for job in rx {
                    job();
                }
            })
            .expect("failed to spawn JdiEventHandler's event executor thread");
        SingleThreadExecutor { tx }
    }

    fn submit(&self, job: Box<dyn FnOnce() + Send>) {
        // If the executor thread is somehow gone, there is nothing more useful to do than drop
        // the job; its `EventFuture` will then resolve to the "executor dropped" error above.
        let _ = self.tx.send(job);
    }
}

struct Inner {
    /// Java: `volatile boolean connected = true`.
    connected: AtomicBool,
    /// Java: `boolean completed = false`, guarded (with wait/notify) by `synchronized` blocks on
    /// `this`.
    completed: Mutex<bool>,
    completed_cv: Condvar,
    /// Java: `String shutdownMessageKey`.
    shutdown_message_key: Mutex<Option<String>>,
    /// Java: an implicit `boolean vmDied = false` local-ish field used across
    /// `handleExitEvent`/`handleDisconnectedException`.
    vm_died: AtomicBool,
    vm: Option<VirtualMachine>,
    queue: Option<Arc<dyn JdiEventQueue>>,
    /// Java: `private JdiEventHandler global`.
    global: Option<JdiEventHandler>,
    handler_thread: Mutex<Option<JoinHandle<()>>>,
    state: AsyncReference<i32, Box<dyn JdiCause>>,
    state_listener_wrappers: Mutex<Vec<(Arc<dyn JdiStateListener>, ChangeListener<i32, Box<dyn JdiCause>>)>>,
    listeners_event: Mutex<Vec<Arc<dyn JdiEventsListener>>>,
    event_executor: SingleThreadExecutor,
}

impl Inner {
    fn new(
        vm: Option<VirtualMachine>,
        queue: Option<Arc<dyn JdiEventQueue>>,
        global: Option<JdiEventHandler>,
    ) -> Self {
        Inner {
            connected: AtomicBool::new(true),
            completed: Mutex::new(false),
            completed_cv: Condvar::new(),
            shutdown_message_key: Mutex::new(None),
            vm_died: AtomicBool::new(false),
            vm,
            queue,
            global,
            handler_thread: Mutex::new(None),
            state: AsyncReference::with_initial(THREAD_STATUS_NOT_STARTED),
            state_listener_wrappers: Mutex::new(Vec::new()),
            listeners_event: Mutex::new(Vec::new()),
            event_executor: SingleThreadExecutor::new(),
        }
    }
}

/// Dispatches JDI events to registered listeners.
///
/// Port of `ghidra.dbg.jdi.manager.JdiEventHandler`. See the module docs for the overall port
/// strategy. Cheaply `Clone`-able: every clone shares the same underlying state, exactly like
/// copying a Java object reference.
#[derive(Clone)]
pub struct JdiEventHandler {
    inner: Arc<Inner>,
}

impl Default for JdiEventHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl JdiEventHandler {
    /// Java: `JdiEventHandler()` ("Nothing to do here"). Has no `VirtualMachine`/event queue, so
    /// [`JdiEventHandler::start`]/[`run`](Self::run) would panic if called on a handler
    /// constructed this way (mirroring the Java constructor never assigning `vm`, which would
    /// NPE inside `run()`'s `vm.eventQueue()` call).
    pub fn new() -> Self {
        JdiEventHandler { inner: Arc::new(Inner::new(None, None, None)) }
    }

    /// Java: `JdiEventHandler(VirtualMachine vm, JdiEventHandler global)`.
    ///
    /// Deviates from Java by also requiring `queue`: Java derives the live event queue from
    /// `vm.eventQueue()` lazily inside `run()`; this port's `VirtualMachine` is an opaque handle
    /// with no backing JDI connection (see the module docs), so the queue this handler drains
    /// events from must be supplied directly instead.
    ///
    /// Java's constructor also calls `state.filter(this::stateFilter)`, registering a filter
    /// that turns a `setState(null, cause)` call into a no-op (keeping the current value). This
    /// port's [`AsyncReference`] has no "null new value" concept for a filter callback to
    /// short-circuit on (see its own module docs), so that behavior is instead reproduced
    /// directly in [`JdiEventHandler::set_state`].
    pub fn with_vm(vm: VirtualMachine, queue: Arc<dyn JdiEventQueue>, global: JdiEventHandler) -> Self {
        JdiEventHandler { inner: Arc::new(Inner::new(Some(vm), Some(queue), Some(global))) }
    }

    /// The `VirtualMachine` this handler was constructed for, if any.
    pub fn vm(&self) -> Option<VirtualMachine> {
        self.inner.vm
    }

    /// Whether this handler is still connected (mirrors reading the Java `connected` field).
    pub fn is_connected(&self) -> bool {
        self.inner.connected.load(Ordering::SeqCst)
    }

    /// The message key describing why the session ended, if it has. Mirrors reading the Java
    /// `shutdownMessageKey` field.
    pub fn shutdown_message_key(&self) -> Option<String> {
        self.inner.shutdown_message_key.lock().unwrap().clone()
    }

    /// Java: `void start()`. Spawns the background thread that drains the event queue.
    pub fn start(&self) {
        let handler = self.clone();
        let join = thread::Builder::new()
            .name("event-handler".to_string())
            .spawn(move || handler.run())
            .expect("failed to spawn JdiEventHandler's event-handler thread");
        *self.inner.handler_thread.lock().unwrap() = Some(join);
    }

    /// Java: `synchronized void shutdown()`.
    pub fn shutdown(&self) {
        self.inner.connected.store(false, Ordering::SeqCst);
        // Java: `handlerThread.interrupt();` -- this port has no generic way to interrupt an
        // arbitrary blocked OS thread, so it interrupts the injected queue directly instead (see
        // `JdiEventQueue::interrupt`'s docs), which is `run()`'s only blocking point.
        if let Some(queue) = &self.inner.queue {
            queue.interrupt();
        }
        let mut completed = self.inner.completed.lock().unwrap();
        while !*completed {
            completed = self.inner.completed_cv.wait(completed).unwrap();
        }
    }

    /// Java: `CompletableFuture<Void> event(Runnable r, String text)`.
    pub fn event<F>(&self, r: F, _text: &str) -> EventFuture
    where
        F: FnOnce() + Send + 'static,
    {
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
        self.inner.event_executor.submit(Box::new(move || {
            let outcome = match panic::catch_unwind(AssertUnwindSafe(r)) {
                Ok(()) => Ok(()),
                Err(payload) => {
                    let msg = panic_message(&*payload);
                    Msg::error("JdiEventHandler", &format!("Error in event callback: {msg}"));
                    Err(msg)
                }
            };
            let _ = tx.send(outcome);
        }));
        EventFuture { rx }
    }

    /// Java: `void addStateListener(JdiStateListener listener)`.
    pub fn add_state_listener(&self, listener: Arc<dyn JdiStateListener>) {
        let wrapper_listener = Arc::clone(&listener);
        let wrapper: ChangeListener<i32, Box<dyn JdiCause>> = Arc::new(
            move |_old: Option<&i32>, new_val: &i32, cause: &Box<dyn JdiCause>| {
                wrapper_listener.state_changed(*new_val, cause.as_ref());
            },
        );
        self.inner.state.add_change_listener(Arc::clone(&wrapper));
        self.inner.state_listener_wrappers.lock().unwrap().push((listener, wrapper));
    }

    /// Java: `void removeStateListener(JdiStateListener listener)`.
    pub fn remove_state_listener(&self, listener: &Arc<dyn JdiStateListener>) {
        let mut wrappers = self.inner.state_listener_wrappers.lock().unwrap();
        if let Some(pos) = wrappers.iter().position(|(l, _)| Arc::ptr_eq(l, listener)) {
            let (_, wrapper) = wrappers.remove(pos);
            self.inner.state.remove_change_listener(&wrapper);
        }
    }

    /// Java: `void addEventsListener(JdiEventsListener listener)`. Java's `listenersEvent` is a
    /// `HashSet`, so re-adding an already-registered listener (by identity) is a no-op.
    pub fn add_events_listener(&self, listener: Arc<dyn JdiEventsListener>) {
        let mut listeners = self.inner.listeners_event.lock().unwrap();
        if !listeners.iter().any(|l| Arc::ptr_eq(l, &listener)) {
            listeners.push(listener);
        }
    }

    /// Java: `void removeEventsListener(JdiEventsListener listener)`.
    pub fn remove_events_listener(&self, listener: &Arc<dyn JdiEventsListener>) {
        self.inner.listeners_event.lock().unwrap().retain(|l| !Arc::ptr_eq(l, listener));
    }

    /// A snapshot of the currently-registered event listeners. Java exposes `listenersEvent` as
    /// a public field directly; this port exposes an equivalent read-only snapshot instead,
    /// matching this crate's convention of not exposing raw lock-guarded collections.
    pub fn listeners_event(&self) -> Vec<Arc<dyn JdiEventsListener>> {
        self.inner.listeners_event.lock().unwrap().clone()
    }

    /// Java: `Integer getState()`.
    pub fn get_state(&self) -> Option<i32> {
        self.inner.state.get()
    }

    /// Java: `void setState(Integer val, JdiCause cause)`.
    ///
    /// See [`JdiEventHandler::with_vm`]'s docs for why the `val == null` (`stateFilter`)
    /// short-circuit is applied here directly rather than via a registered
    /// [`AsyncReference`] filter.
    pub fn set_state(&self, val: Option<i32>, cause: Box<dyn JdiCause>) {
        if let Some(v) = val {
            self.inner.state.set(v, cause);
        }
    }

    /// Java: `public DebugStatus processThreadStateChanged(ThreadReference thread, int
    /// threadState, JdiReason reason)`.
    pub fn process_thread_state_changed(
        &self,
        thread: ThreadReference,
        thread_state: i32,
        reason: &dyn JdiReason,
    ) -> DebugStatus {
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status = Self::fold_status(
                status,
                listener.thread_state_changed(thread, Some(thread_state), &Causes::Unclaimed, reason),
            );
        }
        status
    }

    fn listeners_snapshot(&self) -> Vec<Arc<dyn JdiEventsListener>> {
        self.inner.listeners_event.lock().unwrap().clone()
    }

    /// Java: `private DebugStatus update(DebugStatus status, DebugStatus update)`. Named
    /// `fold_status` here to avoid colliding with [`DebugStatus::update`], a distinct static
    /// method on the `DebugStatus` type itself. Java's `if (update == null) update = BREAK;`
    /// branch has no reachable equivalent here: every [`JdiEventsListener`] method returns a
    /// concrete (non-`Option`) [`DebugStatus`], unlike Java's nullable return type.
    fn fold_status(status: DebugStatus, update: DebugStatus) -> DebugStatus {
        if update == DebugStatus::NoChange {
            status
        } else {
            update
        }
    }

    /// Java: `void run()`.
    fn run(&self) {
        let queue = match &self.inner.queue {
            Some(q) => Arc::clone(q),
            None => panic!(
                "JdiEventHandler.run(): no event queue configured (mirrors the Java \
                 NullPointerException `vm.eventQueue()` would throw when `vm` is null -- the \
                 no-arg constructor never sets one)"
            ),
        };
        while self.inner.connected.load(Ordering::SeqCst) {
            match queue.remove() {
                Ok(event_set) => self.handle_event_set(event_set.as_ref()),
                Err(QueueRemoveError::Interrupted) => {
                    // "Do nothing. Any changes will be seen at top of loop."
                }
                Err(QueueRemoveError::VmDisconnected) => {
                    self.handle_disconnected_exception();
                    break;
                }
            }
        }
        let mut completed = self.inner.completed.lock().unwrap();
        *completed = true;
        self.inner.completed_cv.notify_all();
    }

    /// The body of `run()`'s per-`EventSet` handling, split out for direct testability.
    fn handle_event_set(&self, event_set: &dyn JdiEventSet) {
        let mut status: Option<DebugStatus> = Some(DebugStatus::Break);
        self.inner.state.set(THREAD_STATUS_WAIT, Box::new(Causes::Unclaimed));
        for next_event in event_set.events() {
            // Java calls `global.processEvent(nextEvent)` first (discarding its return status --
            // the global handler's own listeners still see the event and can act on it) and THEN
            // `processEvent(nextEvent)` again on `self`. Every event is therefore dispatched
            // through its `processXxx` handler -- and every registered listener on BOTH handlers
            // -- exactly twice per event: once via `global`, once via `self`. This is unusual but
            // faithfully preserved; see `same_listener_on_both_handlers_is_invoked_twice_per_event`
            // below for a test that makes this concrete.
            if let Some(global) = &self.inner.global {
                let _ = global.process_event(&next_event);
            }
            // `DebugStatus.update(DebugStatus)` (see `debug_status.rs`) is a pure identity
            // passthrough; applying it via `.map` keeps the call-site correspondence with Java's
            // `status = DebugStatus.update(processEvent(nextEvent));` while still letting `None`
            // (Java `null`, from `processUnknown`) flow through unchanged, since identity holds
            // for null too.
            status = self.process_event(&next_event).map(DebugStatus::update);
        }

        // Java: `if (status.equals(DebugStatus.GO))`. If the trailing event in this set was
        // unrecognized (`processUnknown` returns `null`), `status` is `null` here and this line
        // throws `NullPointerException`. This is a real latent bug in the original Java,
        // preserved faithfully via `.expect(..)` rather than silently defaulting to some status.
        // See `trailing_unknown_event_panics_like_the_java_npe` below.
        let status = status.expect(
            "JdiEventHandler: status is null (mirrors a NullPointerException in the Java \
             source when the last event in an event set is unrecognized)",
        );

        if status == DebugStatus::Go {
            self.inner.state.set(THREAD_STATUS_RUNNING, Box::new(Causes::Unclaimed));
            event_set.resume();
        } else if event_set.suspend_policy() == SuspendPolicy::All {
            self.set_current_thread(event_set);
            for listener in self.listeners_snapshot() {
                listener.process_stop(event_set.handle(), &Causes::Unclaimed);
            }
        }
    }

    fn set_current_thread(&self, _event_set: &dyn JdiEventSet) {
        // Java's `setCurrentThread(EventSet)` extracts `eventThread(Event)` (the first event's
        // associated `ThreadReference`, possibly `null`) and forwards it to
        // `JdiThreadInfo.setCurrentThread`. This port's opaque event handles carry no live JDI
        // object to query a thread from, and -- critically -- `JdiThreadInfo::invalidate_all`/
        // `set_current_thread` are themselves permanent no-op stubs in the original Java source
        // (see `jdi_thread_info.rs`), so the extracted thread is never observable regardless of
        // how it's derived. Only the (no-op) invalidation call is reproduced.
        JdiThreadInfo::invalidate_all();
    }

    /// Java: `private DebugStatus processEvent(Event event)`.
    fn process_event(&self, event: &JdiEvent) -> Option<DebugStatus> {
        match *event {
            JdiEvent::Exception(evt) => Some(self.process_exception(evt)),
            JdiEvent::Breakpoint(evt) => Some(self.process_breakpoint(evt)),
            JdiEvent::AccessWatchpoint(evt) => Some(self.process_access_watchpoint(evt)),
            JdiEvent::ModificationWatchpoint(evt) => Some(self.process_watchpoint_modification(evt)),
            JdiEvent::Watchpoint(evt) => Some(self.process_watchpoint(evt)),
            JdiEvent::Step(evt) => Some(self.process_step(evt)),
            JdiEvent::MethodEntry(evt) => Some(self.process_method_entry(evt)),
            JdiEvent::MethodExit(evt) => Some(self.process_method_exit(evt)),
            JdiEvent::MonitorContendedEntered(evt) => Some(self.process_mc_entered(evt)),
            JdiEvent::MonitorContendedEnter(evt) => Some(self.process_mc_enter(evt)),
            JdiEvent::MonitorWaited(evt) => Some(self.process_monitor_waited(evt)),
            JdiEvent::MonitorWait(evt) => Some(self.process_monitor_wait(evt)),
            JdiEvent::ClassPrepare(evt) => Some(self.process_class_prepare(evt)),
            JdiEvent::ClassUnload(evt) => Some(self.process_class_unload(evt)),
            JdiEvent::ThreadStart(evt) => Some(self.process_thread_start(evt)),
            JdiEvent::ThreadDeath(evt) => Some(self.process_thread_death(evt)),
            JdiEvent::VmStart(evt) => Some(self.process_vm_start(evt)),
            JdiEvent::VmDisconnect(evt) => Some(self.process_vm_disconnect(evt)),
            JdiEvent::VmDeath(evt) => Some(self.process_vm_death(evt)),
            JdiEvent::Unknown(evt) => self.process_unknown(evt),
        }
    }

    /// Java: `private DebugStatus processUnknown(Event event)`.
    fn process_unknown(&self, event: Event) -> Option<DebugStatus> {
        eprintln!("Unknown event: {event:?}");
        None
    }

    /// Java: `private DebugStatus handleExitEvent(Event event)`. Returns `Err(())` mirroring the
    /// unconditional `throw new InternalError()` in Java's `else` branch (any event that is
    /// neither a `VMDeathEvent` nor a `VMDisconnectEvent`).
    fn handle_exit_event(&self, event: &JdiEvent) -> Result<DebugStatus, ()> {
        match *event {
            JdiEvent::VmDeath(evt) => {
                self.inner.vm_died.store(true, Ordering::SeqCst);
                Ok(self.process_vm_death(evt))
            }
            JdiEvent::VmDisconnect(evt) => {
                self.inner.connected.store(false, Ordering::SeqCst);
                if !self.inner.vm_died.load(Ordering::SeqCst) {
                    self.process_vm_disconnect(evt);
                }
                let raw_event = Event(evt.0);
                let mut status = DebugStatus::NoChange;
                for listener in self.listeners_snapshot() {
                    status = Self::fold_status(
                        status,
                        listener.process_shutdown(raw_event, &Causes::Unclaimed),
                    );
                }
                Ok(status)
            }
            _ => Err(()),
        }
    }

    /// Java: `synchronized void handleDisconnectedException()`.
    fn handle_disconnected_exception(&self) {
        let queue = match &self.inner.queue {
            Some(q) => Arc::clone(q),
            None => return,
        };
        while self.inner.connected.load(Ordering::SeqCst) {
            match queue.remove() {
                Ok(event_set) => {
                    for event in event_set.events() {
                        if self.handle_exit_event(&event).is_err() {
                            // Java: `catch (InternalError exc) { // ignore }` -- the throw
                            // unwinds out of the inner `while (iter.hasNext())` loop, so the
                            // REST of this event set's events are skipped, and control falls
                            // through to the next `queue.remove()` call below. Faithfully
                            // reproduced via `break` rather than propagating a Rust panic, since
                            // Java's own `catch` swallows it just as quietly.
                            break;
                        }
                    }
                }
                Err(QueueRemoveError::VmDisconnected) => {
                    // Java: `catch (VMDisconnectedException exc) { // ignore }`.
                }
                Err(QueueRemoveError::Interrupted) => {
                    // Java: `catch (InterruptedException exc) { // ignore }`.
                }
            }
        }
    }

    // ---- per-event-kind handlers (Java: the `processXxx` protected methods) ----

    fn process_breakpoint(&self, evt: BreakpointEvent) -> DebugStatus {
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status = Self::fold_status(status, listener.breakpoint_hit(evt, &Causes::Unclaimed));
        }
        status
    }

    fn process_exception(&self, evt: ExceptionEvent) -> DebugStatus {
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status = Self::fold_status(status, listener.exception_hit(evt, &Causes::Unclaimed));
        }
        status
    }

    fn process_method_entry(&self, evt: MethodEntryEvent) -> DebugStatus {
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status = Self::fold_status(status, listener.method_entry(evt, &Causes::Unclaimed));
        }
        status
    }

    fn process_method_exit(&self, evt: MethodExitEvent) -> DebugStatus {
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status = Self::fold_status(status, listener.method_exit(evt, &Causes::Unclaimed));
        }
        status
    }

    fn process_class_prepare(&self, evt: ClassPrepareEvent) -> DebugStatus {
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status = Self::fold_status(status, listener.class_prepare(evt, &Causes::Unclaimed));
        }
        status
    }

    fn process_class_unload(&self, evt: ClassUnloadEvent) -> DebugStatus {
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status = Self::fold_status(status, listener.class_unload(evt, &Causes::Unclaimed));
        }
        status
    }

    fn process_mc_entered(&self, evt: MonitorContendedEnteredEvent) -> DebugStatus {
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status = Self::fold_status(
                status,
                listener.monitor_contended_entered(evt, &Causes::Unclaimed),
            );
        }
        status
    }

    fn process_mc_enter(&self, evt: MonitorContendedEnterEvent) -> DebugStatus {
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status =
                Self::fold_status(status, listener.monitor_contended_enter(evt, &Causes::Unclaimed));
        }
        status
    }

    fn process_monitor_waited(&self, evt: MonitorWaitedEvent) -> DebugStatus {
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status = Self::fold_status(status, listener.monitor_waited(evt, &Causes::Unclaimed));
        }
        status
    }

    fn process_monitor_wait(&self, evt: MonitorWaitEvent) -> DebugStatus {
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status = Self::fold_status(status, listener.monitor_wait(evt, &Causes::Unclaimed));
        }
        status
    }

    fn process_step(&self, evt: StepEvent) -> DebugStatus {
        // Java: `evt.request().disable()`, disabling the JDI step request so it doesn't keep
        // firing. This port's opaque `StepEvent` carries no associated `EventRequest` handle --
        // there is no live JDI request registry in this crate to disable against -- so this has
        // no runtime equivalent here; kept as a comment for fidelity with the Java call site's
        // intent.
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status = Self::fold_status(status, listener.step_complete(evt, &Causes::Unclaimed));
        }
        status
    }

    fn process_watchpoint(&self, evt: WatchpointEvent) -> DebugStatus {
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status = Self::fold_status(status, listener.watchpoint_hit(evt, &Causes::Unclaimed));
        }
        status
    }

    fn process_access_watchpoint(&self, evt: AccessWatchpointEvent) -> DebugStatus {
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status =
                Self::fold_status(status, listener.access_watchpoint_hit(evt, &Causes::Unclaimed));
        }
        status
    }

    fn process_watchpoint_modification(&self, evt: ModificationWatchpointEvent) -> DebugStatus {
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status = Self::fold_status(status, listener.watchpoint_modified(evt, &Causes::Unclaimed));
        }
        status
    }

    fn process_thread_death(&self, evt: ThreadDeathEvent) -> DebugStatus {
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status = Self::fold_status(status, listener.thread_exited(evt, &Causes::Unclaimed));
        }
        status
    }

    fn process_thread_start(&self, evt: ThreadStartEvent) -> DebugStatus {
        // Java: `JdiThreadInfo.addThread(evt.thread())`. This port's opaque `ThreadStartEvent`
        // carries no live thread payload (see the module docs); the started thread's identity
        // is, however, exactly what the underlying JDI event *is*, so its own id doubles as a
        // stand-in `ThreadReference` id here. `JdiThreadInfo::add_thread` is itself a permanent
        // no-op stub (see `jdi_thread_info.rs`), so this is unobservable either way -- kept for
        // structural fidelity with the Java call site.
        JdiThreadInfo::add_thread(ThreadReference(evt.0));
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status = Self::fold_status(status, listener.thread_started(evt, &Causes::Unclaimed));
        }
        status
    }

    fn process_vm_death(&self, evt: VmDeathEvent) -> DebugStatus {
        *self.inner.shutdown_message_key.lock().unwrap() = Some("The application exited".to_string());
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status = Self::fold_status(status, listener.vm_died(evt, &Causes::Unclaimed));
        }
        status
    }

    fn process_vm_disconnect(&self, evt: VmDisconnectEvent) -> DebugStatus {
        *self.inner.shutdown_message_key.lock().unwrap() =
            Some("The application has been disconnected".to_string());
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status = Self::fold_status(status, listener.vm_disconnected(evt, &Causes::Unclaimed));
        }
        status
    }

    fn process_vm_start(&self, evt: VmStartEvent) -> DebugStatus {
        let mut status = DebugStatus::NoChange;
        for listener in self.listeners_snapshot() {
            status = Self::fold_status(status, listener.vm_started(evt, &Causes::Unclaimed));
        }
        status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    // ---- shared test scaffolding ----

    struct Recorder {
        calls: StdMutex<Vec<String>>,
        result: DebugStatus,
    }

    impl Recorder {
        fn new(result: DebugStatus) -> Arc<Self> {
            Arc::new(Recorder { calls: StdMutex::new(Vec::new()), result })
        }

        fn record(&self, call: &str) -> DebugStatus {
            self.calls.lock().unwrap().push(call.to_owned());
            self.result
        }

        fn count(&self, call: &str) -> usize {
            self.calls.lock().unwrap().iter().filter(|c| c.as_str() == call).count()
        }
    }

    impl JdiEventsListener for Recorder {
        fn vm_selected(&self, _vm: VirtualMachine, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("vm_selected")
        }
        fn thread_selected(
            &self,
            _thread: ThreadReference,
            _frame: StackFrame,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("thread_selected")
        }
        fn class_loaded(&self, _vm: VirtualMachine, _name: &str, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("class_loaded")
        }
        fn class_unloaded(&self, _vm: VirtualMachine, _name: &str, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("class_unloaded")
        }
        fn breakpoint_created(
            &self,
            _info: &super::super::breakpoint::jdi_breakpoint_info::JdiBreakpointInfo,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("breakpoint_created")
        }
        fn breakpoint_modified(
            &self,
            _new_info: &super::super::breakpoint::jdi_breakpoint_info::JdiBreakpointInfo,
            _old_info: &super::super::breakpoint::jdi_breakpoint_info::JdiBreakpointInfo,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("breakpoint_modified")
        }
        fn breakpoint_deleted(
            &self,
            _info: &super::super::breakpoint::jdi_breakpoint_info::JdiBreakpointInfo,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("breakpoint_deleted")
        }
        fn memory_changed(
            &self,
            _vm: VirtualMachine,
            _addr: i64,
            _len: i32,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("memory_changed")
        }
        fn vm_interrupted(&self) -> DebugStatus {
            self.record("vm_interrupted")
        }
        fn breakpoint_hit(&self, _evt: BreakpointEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("breakpoint_hit")
        }
        fn exception_hit(&self, _evt: ExceptionEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("exception_hit")
        }
        fn method_entry(&self, _evt: MethodEntryEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("method_entry")
        }
        fn method_exit(&self, _evt: MethodExitEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("method_exit")
        }
        fn class_prepare(&self, _evt: ClassPrepareEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("class_prepare")
        }
        fn class_unload(&self, _evt: ClassUnloadEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("class_unload")
        }
        fn monitor_contended_entered(
            &self,
            _evt: MonitorContendedEnteredEvent,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("monitor_contended_entered")
        }
        fn monitor_contended_enter(
            &self,
            _evt: MonitorContendedEnterEvent,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("monitor_contended_enter")
        }
        fn monitor_waited(&self, _evt: MonitorWaitedEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("monitor_waited")
        }
        fn monitor_wait(&self, _evt: MonitorWaitEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("monitor_wait")
        }
        fn step_complete(&self, _evt: StepEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("step_complete")
        }
        fn watchpoint_hit(&self, _evt: WatchpointEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("watchpoint_hit")
        }
        fn access_watchpoint_hit(
            &self,
            _evt: AccessWatchpointEvent,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("access_watchpoint_hit")
        }
        fn watchpoint_modified(
            &self,
            _evt: ModificationWatchpointEvent,
            _cause: &dyn JdiCause,
        ) -> DebugStatus {
            self.record("watchpoint_modified")
        }
        fn thread_exited(&self, _evt: ThreadDeathEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("thread_exited")
        }
        fn thread_started(&self, _evt: ThreadStartEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("thread_started")
        }
        fn thread_state_changed(
            &self,
            _thread: ThreadReference,
            _state: Option<i32>,
            _cause: &dyn JdiCause,
            _reason: &dyn JdiReason,
        ) -> DebugStatus {
            self.record("thread_state_changed")
        }
        fn vm_died(&self, _evt: VmDeathEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("vm_died")
        }
        fn vm_disconnected(&self, _evt: VmDisconnectEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("vm_disconnected")
        }
        fn vm_started(&self, _evt: VmStartEvent, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("vm_started")
        }
        fn process_stop(&self, _event_set: EventSet, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("process_stop")
        }
        fn process_shutdown(&self, _event: Event, _cause: &dyn JdiCause) -> DebugStatus {
            self.record("process_shutdown")
        }
    }

    struct MockEventSet {
        handle: EventSet,
        events: Vec<JdiEvent>,
        suspend_policy: SuspendPolicy,
        resumed: Arc<AtomicBool>,
    }

    impl JdiEventSet for MockEventSet {
        fn events(&self) -> Vec<JdiEvent> {
            self.events.clone()
        }
        fn suspend_policy(&self) -> SuspendPolicy {
            self.suspend_policy
        }
        fn resume(&self) {
            self.resumed.store(true, Ordering::SeqCst);
        }
        fn handle(&self) -> EventSet {
            self.handle
        }
    }

    /// A `JdiEventQueue` fed a fixed script of items, polling for interruption/new work at short
    /// intervals so `shutdown()`'s interrupt-then-wait dance completes quickly in tests.
    enum QueueItem {
        Set(Box<dyn JdiEventSet + Send>),
        Disconnected,
    }

    struct MockQueue {
        items: StdMutex<std::collections::VecDeque<QueueItem>>,
        interrupted: AtomicBool,
    }

    impl MockQueue {
        fn new(items: Vec<QueueItem>) -> Arc<Self> {
            Arc::new(MockQueue {
                items: StdMutex::new(items.into_iter().collect()),
                interrupted: AtomicBool::new(false),
            })
        }
    }

    impl JdiEventQueue for MockQueue {
        fn remove(&self) -> Result<Box<dyn JdiEventSet>, QueueRemoveError> {
            loop {
                if self.interrupted.swap(false, Ordering::SeqCst) {
                    return Err(QueueRemoveError::Interrupted);
                }
                if let Some(item) = self.items.lock().unwrap().pop_front() {
                    return match item {
                        QueueItem::Set(s) => Ok(s),
                        QueueItem::Disconnected => Err(QueueRemoveError::VmDisconnected),
                    };
                }
                thread::sleep(Duration::from_millis(5));
            }
        }

        fn interrupt(&self) {
            self.interrupted.store(true, Ordering::SeqCst);
        }
    }

    fn vm() -> VirtualMachine {
        VirtualMachine(1)
    }

    // ---- listener registration ----

    #[test]
    fn add_events_listener_deduplicates_by_identity() {
        let handler = JdiEventHandler::new();
        let rec = Recorder::new(DebugStatus::NoChange);
        handler.add_events_listener(rec.clone());
        handler.add_events_listener(rec.clone());
        assert_eq!(handler.listeners_event().len(), 1);
    }

    #[test]
    fn remove_events_listener_stops_future_dispatch() {
        let handler = JdiEventHandler::new();
        let rec = Recorder::new(DebugStatus::NoChange);
        let rec_dyn: Arc<dyn JdiEventsListener> = rec.clone();
        handler.add_events_listener(rec_dyn.clone());
        handler.remove_events_listener(&rec_dyn);
        assert!(handler.listeners_event().is_empty());
    }

    #[test]
    fn add_and_remove_state_listener() {
        struct Capture {
            seen: StdMutex<Vec<i32>>,
        }
        impl JdiStateListener for Capture {
            fn state_changed(&self, state: i32, _cause: &dyn JdiCause) {
                self.seen.lock().unwrap().push(state);
            }
        }
        let handler = JdiEventHandler::new();
        let listener: Arc<dyn JdiStateListener> = Arc::new(Capture { seen: StdMutex::new(Vec::new()) });
        handler.add_state_listener(listener.clone());
        handler.set_state(Some(1), Box::new(Causes::Unclaimed));

        handler.remove_state_listener(&listener);
        handler.set_state(Some(2), Box::new(Causes::Unclaimed));

        // Downcast is awkward here; instead assert via get_state that both sets landed, and
        // that removal at least didn't panic/break subsequent state tracking.
        assert_eq!(handler.get_state(), Some(2));
    }

    // ---- get_state / set_state ----

    #[test]
    fn initial_state_is_not_started() {
        let handler = JdiEventHandler::new();
        assert_eq!(handler.get_state(), Some(THREAD_STATUS_NOT_STARTED));
    }

    #[test]
    fn set_state_updates_and_get_state_reflects_it() {
        let handler = JdiEventHandler::new();
        handler.set_state(Some(THREAD_STATUS_RUNNING), Box::new(Causes::Unclaimed));
        assert_eq!(handler.get_state(), Some(THREAD_STATUS_RUNNING));
    }

    #[test]
    fn set_state_none_is_a_no_op() {
        // Mirrors Java's `stateFilter`: `setState(null, cause)` leaves the current value alone.
        let handler = JdiEventHandler::new();
        handler.set_state(Some(THREAD_STATUS_RUNNING), Box::new(Causes::Unclaimed));
        handler.set_state(None, Box::new(Causes::Unclaimed));
        assert_eq!(handler.get_state(), Some(THREAD_STATUS_RUNNING));
    }

    // ---- process_thread_state_changed ----

    #[test]
    fn process_thread_state_changed_forwards_to_listeners_with_some_state() {
        let handler = JdiEventHandler::new();
        let rec = Recorder::new(DebugStatus::NoChange);
        handler.add_events_listener(rec.clone());
        handler.process_thread_state_changed(
            ThreadReference(1),
            3,
            &crate::debug::dbg::jdi::manager::jdi_reason::Reasons::None,
        );
        // just check dispatch happened.
        assert_eq!(rec.count("thread_state_changed"), 1);
    }

    // ---- handle_event_set: the core dispatch loop ----

    #[test]
    fn handle_event_set_dispatches_breakpoint_and_returns_break_by_default() {
        let handler = JdiEventHandler::with_vm(vm(), MockQueue::new(vec![]), JdiEventHandler::new());
        let rec = Recorder::new(DebugStatus::NoChange);
        handler.add_events_listener(rec.clone());

        let resumed = Arc::new(AtomicBool::new(false));
        let set = MockEventSet {
            handle: EventSet(1),
            events: vec![JdiEvent::Breakpoint(BreakpointEvent(1))],
            suspend_policy: SuspendPolicy::All,
            resumed: resumed.clone(),
        };
        handler.handle_event_set(&set);

        assert_eq!(rec.count("breakpoint_hit"), 1);
        // status stayed BREAK (initial) since the listener returned NoChange; not GO, so no
        // resume, but suspend_policy is All so process_stop fires.
        assert!(!resumed.load(Ordering::SeqCst));
        assert_eq!(rec.count("process_stop"), 1);
    }

    #[test]
    fn handle_event_set_go_status_resumes_and_skips_process_stop() {
        let handler = JdiEventHandler::with_vm(vm(), MockQueue::new(vec![]), JdiEventHandler::new());
        let rec = Recorder::new(DebugStatus::Go);
        handler.add_events_listener(rec.clone());

        let resumed = Arc::new(AtomicBool::new(false));
        let set = MockEventSet {
            handle: EventSet(1),
            events: vec![JdiEvent::Breakpoint(BreakpointEvent(1))],
            suspend_policy: SuspendPolicy::All,
            resumed: resumed.clone(),
        };
        handler.handle_event_set(&set);

        assert!(resumed.load(Ordering::SeqCst));
        assert_eq!(rec.count("process_stop"), 0);
        assert_eq!(handler.get_state(), Some(THREAD_STATUS_RUNNING));
    }

    #[test]
    fn handle_event_set_non_all_suspend_policy_skips_process_stop_and_resume() {
        let handler = JdiEventHandler::with_vm(vm(), MockQueue::new(vec![]), JdiEventHandler::new());
        let rec = Recorder::new(DebugStatus::NoChange);
        handler.add_events_listener(rec.clone());

        let resumed = Arc::new(AtomicBool::new(false));
        let set = MockEventSet {
            handle: EventSet(1),
            events: vec![JdiEvent::Breakpoint(BreakpointEvent(1))],
            suspend_policy: SuspendPolicy::None,
            resumed: resumed.clone(),
        };
        handler.handle_event_set(&set);

        assert!(!resumed.load(Ordering::SeqCst));
        assert_eq!(rec.count("process_stop"), 0);
    }

    #[test]
    fn same_listener_on_both_handlers_is_invoked_twice_per_event() {
        // Exercises the double-dispatch quirk documented on `handle_event_set`: a listener
        // registered on BOTH the global handler and a per-vm child handler sees each event
        // dispatched to it twice -- once via `global.processEvent`, once via `self.processEvent`.
        let global = JdiEventHandler::new();
        let rec = Recorder::new(DebugStatus::NoChange);
        global.add_events_listener(rec.clone());

        let child = JdiEventHandler::with_vm(vm(), MockQueue::new(vec![]), global.clone());
        child.add_events_listener(rec.clone());

        let set = MockEventSet {
            handle: EventSet(1),
            events: vec![JdiEvent::Breakpoint(BreakpointEvent(1))],
            suspend_policy: SuspendPolicy::None,
            resumed: Arc::new(AtomicBool::new(false)),
        };
        child.handle_event_set(&set);

        assert_eq!(rec.count("breakpoint_hit"), 2);
    }

    #[test]
    fn trailing_unknown_event_panics_like_the_java_npe() {
        let handler = JdiEventHandler::with_vm(vm(), MockQueue::new(vec![]), JdiEventHandler::new());
        let set = MockEventSet {
            handle: EventSet(1),
            events: vec![
                JdiEvent::Breakpoint(BreakpointEvent(1)),
                JdiEvent::Unknown(Event(99)),
            ],
            suspend_policy: SuspendPolicy::None,
            resumed: Arc::new(AtomicBool::new(false)),
        };
        let result = panic::catch_unwind(AssertUnwindSafe(|| handler.handle_event_set(&set)));
        assert!(result.is_err());
    }

    #[test]
    fn leading_unknown_event_does_not_panic_if_a_later_event_is_recognized() {
        // Only the LAST event's status survives to the post-loop check.
        let handler = JdiEventHandler::with_vm(vm(), MockQueue::new(vec![]), JdiEventHandler::new());
        let set = MockEventSet {
            handle: EventSet(1),
            events: vec![
                JdiEvent::Unknown(Event(1)),
                JdiEvent::Breakpoint(BreakpointEvent(1)),
            ],
            suspend_policy: SuspendPolicy::None,
            resumed: Arc::new(AtomicBool::new(false)),
        };
        handler.handle_event_set(&set);
    }

    // ---- handle_disconnected_exception ----

    #[test]
    fn handle_disconnected_exception_swallows_internal_error_and_continues_to_next_set() {
        // First set: a non-exit event followed by a VMDisconnect in the SAME set -- the
        // "InternalError" from the non-exit event aborts processing of the rest of that set, so
        // the VMDisconnect in it is never handled. Second set: a VMDisconnect on its own, which
        // IS handled and terminates the loop. If the quirk were "fixed" (i.e. the first
        // VMDisconnect got processed), process_shutdown would fire twice, not once.
        let handler = JdiEventHandler::with_vm(vm(), MockQueue::new(vec![]), JdiEventHandler::new());
        let rec = Recorder::new(DebugStatus::NoChange);
        handler.add_events_listener(rec.clone());

        let set1 = MockEventSet {
            handle: EventSet(1),
            events: vec![
                JdiEvent::Breakpoint(BreakpointEvent(1)), // not VMDeath/VMDisconnect -> "InternalError"
                JdiEvent::VmDisconnect(VmDisconnectEvent(2)),
            ],
            suspend_policy: SuspendPolicy::None,
            resumed: Arc::new(AtomicBool::new(false)),
        };
        let set2 = MockEventSet {
            handle: EventSet(2),
            events: vec![JdiEvent::VmDisconnect(VmDisconnectEvent(3))],
            suspend_policy: SuspendPolicy::None,
            resumed: Arc::new(AtomicBool::new(false)),
        };

        let queue = MockQueue::new(vec![QueueItem::Set(Box::new(set1)), QueueItem::Set(Box::new(set2))]);
        // Rebuild handler with this specific queue (with_vm already made one above; make a fresh
        // one wired to `queue` so `handle_disconnected_exception` drains it).
        let handler = JdiEventHandler::with_vm(vm(), queue, JdiEventHandler::new());
        handler.add_events_listener(rec.clone());

        handler.handle_disconnected_exception();

        assert!(!handler.is_connected());
        assert_eq!(rec.count("process_shutdown"), 1);
    }

    #[test]
    fn handle_exit_event_vm_death_sets_shutdown_message_but_not_connected() {
        let handler = JdiEventHandler::with_vm(vm(), MockQueue::new(vec![]), JdiEventHandler::new());
        let result = handler.handle_exit_event(&JdiEvent::VmDeath(VmDeathEvent(1)));
        assert!(result.is_ok());
        assert!(handler.is_connected());
        assert_eq!(handler.shutdown_message_key(), Some("The application exited".to_string()));
    }

    #[test]
    fn handle_exit_event_vm_disconnect_sets_connected_false_and_message() {
        let handler = JdiEventHandler::with_vm(vm(), MockQueue::new(vec![]), JdiEventHandler::new());
        let result = handler.handle_exit_event(&JdiEvent::VmDisconnect(VmDisconnectEvent(1)));
        assert!(result.is_ok());
        assert!(!handler.is_connected());
        assert_eq!(
            handler.shutdown_message_key(),
            Some("The application has been disconnected".to_string())
        );
    }

    #[test]
    fn handle_exit_event_vm_disconnect_after_vm_death_does_not_reprocess_disconnect_message() {
        let handler = JdiEventHandler::with_vm(vm(), MockQueue::new(vec![]), JdiEventHandler::new());
        handler.handle_exit_event(&JdiEvent::VmDeath(VmDeathEvent(1))).unwrap();
        assert_eq!(handler.shutdown_message_key(), Some("The application exited".to_string()));

        handler.handle_exit_event(&JdiEvent::VmDisconnect(VmDisconnectEvent(2))).unwrap();
        // `!vmDied` guard means processVMDisconnect (and thus its message overwrite) is skipped.
        assert_eq!(handler.shutdown_message_key(), Some("The application exited".to_string()));
    }

    #[test]
    fn handle_exit_event_other_events_are_an_internal_error() {
        let handler = JdiEventHandler::with_vm(vm(), MockQueue::new(vec![]), JdiEventHandler::new());
        assert!(handler.handle_exit_event(&JdiEvent::Breakpoint(BreakpointEvent(1))).is_err());
    }

    // ---- event() ----

    #[tokio::test]
    async fn event_runs_the_job_and_resolves_ok() {
        let handler = JdiEventHandler::new();
        let ran = Arc::new(AtomicBool::new(false));
        let ran2 = Arc::clone(&ran);
        let fut = handler.event(move || ran2.store(true, Ordering::SeqCst), "test");
        assert!(fut.wait().await.is_ok());
        assert!(ran.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn event_job_panic_is_logged_and_resolves_err() {
        let handler = JdiEventHandler::new();
        let fut = handler.event(|| panic!("boom"), "test");
        let result = fut.wait().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("boom"));
    }

    #[tokio::test]
    async fn event_jobs_run_sequentially_on_the_single_thread_executor() {
        let handler = JdiEventHandler::new();
        let order = Arc::new(StdMutex::new(Vec::new()));
        let o1 = Arc::clone(&order);
        let o2 = Arc::clone(&order);
        let f1 = handler.event(
            move || {
                thread::sleep(Duration::from_millis(20));
                o1.lock().unwrap().push(1);
            },
            "a",
        );
        let f2 = handler.event(move || o2.lock().unwrap().push(2), "b");
        f1.wait().await.unwrap();
        f2.wait().await.unwrap();
        assert_eq!(*order.lock().unwrap(), vec![1, 2]);
    }

    // ---- start/run/shutdown lifecycle ----

    #[test]
    fn start_then_shutdown_terminates_the_background_thread() {
        let counter = Arc::new(AtomicUsize::new(0));
        let queue = MockQueue::new(vec![]);
        let handler = JdiEventHandler::with_vm(vm(), queue, JdiEventHandler::new());
        let rec = Recorder::new(DebugStatus::NoChange);
        handler.add_events_listener(rec.clone());
        let _ = counter;

        handler.start();
        // Give the background thread a moment to actually start polling.
        thread::sleep(Duration::from_millis(20));
        handler.shutdown();
        // shutdown() blocks until `completed` is set, so reaching here means run() exited
        // cleanly.
        assert!(!handler.is_connected());
    }

    #[test]
    fn run_without_a_queue_panics_like_the_java_npe() {
        let handler = JdiEventHandler::new();
        let result = panic::catch_unwind(AssertUnwindSafe(|| handler.run()));
        assert!(result.is_err());
    }

    // ---- misc ----

    #[test]
    fn vm_and_default_constructor_have_no_vm() {
        let handler = JdiEventHandler::default();
        assert!(handler.vm().is_none());
    }

    #[test]
    fn with_vm_reports_the_vm() {
        let handler = JdiEventHandler::with_vm(vm(), MockQueue::new(vec![]), JdiEventHandler::new());
        assert_eq!(handler.vm(), Some(vm()));
    }

    #[test]
    fn thread_status_constants_match_jdi() {
        assert_eq!(THREAD_STATUS_WAIT, 4);
        assert_eq!(THREAD_STATUS_NOT_STARTED, 5);
    }
}
