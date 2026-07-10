//! A service for accessing managed emulators.
//!
//! Port of `ghidra.app.services.DebuggerEmulationService`. The Java `@ServiceInfo` annotation
//! (default provider `DebuggerEmulationServicePlugin`) has no Rust equivalent and is omitted.
//!
//! Managed emulators are employed by the UI and trace manager to perform emulation requested by
//! the user. Scripts may interact with these managed emulators, or they may instantiate their
//! own unmanaged emulators, without using this service.
//!
//! Java's overloaded `emulate(TracePlatform, ...)`/`emulate(Trace, ...)` methods are given
//! distinct Rust names, since Rust traits cannot overload on parameter type alone: the
//! `TracePlatform` overload stays `emulate`, while the `Trace` overload becomes `emulate_trace`.
//! Java's default `emulate(Trace, TraceSchedule, TaskMonitor)` delegates via
//! `trace.getPlatformManager().getHostPlatform()`, but
//! [`crate::trace::seam_stubs::TracePlatformManager`] does not yet expose `getHostPlatform`
//! (it is still an empty placeholder), so `emulate_trace` is declared as a required method here
//! rather than a default one; implementors should replicate that delegation once
//! `TracePlatformManager` grows the real method.

use std::future::Future;
use std::io;
use std::pin::Pin;

use crate::app::seam_stubs::{
    EmulatorFactory, PcodeMachine, RunResult, Scheduler, TracePlatform, TraceSchedule, Writer,
};
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::trace::model::trace::Trace;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// A future representing the asynchronous result of [`DebuggerEmulationService::emulate`].
///
/// Port of Java's `CompletableFuture<Long>` return type used by
/// [`DebuggerEmulationService::background_emulate`].
pub type EmulateFuture = Pin<Box<dyn Future<Output = Result<i64, CancelledException>> + Send>>;

/// A future representing the asynchronous result of [`DebuggerEmulationService::run`].
///
/// Port of Java's `CompletableFuture<EmulationResult>` return type used by
/// [`DebuggerEmulationService::background_run`].
pub type RunFuture =
    Pin<Box<dyn Future<Output = Result<Box<dyn EmulationResult>, CancelledException>> + Send>>;

/// The result of letting the emulator "run free".
///
/// Port of `DebuggerEmulationService.EmulationResult`.
pub trait EmulationResult: RunResult {
    /// Get the (scratch) snapshot where the emulated state is stored.
    fn snapshot(&self) -> i64;
}

/// The result of letting the emulator "run free", holding the schedule that was emulated, the
/// snapshot where the final state was written down, and the error, if any, that occurred.
///
/// Port of `DebuggerEmulationService.RecordEmulationResult`.
pub struct RecordEmulationResult {
    schedule: Box<dyn TraceSchedule>,
    snapshot: i64,
    error: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl RecordEmulationResult {
    /// Creates a new result for the given schedule, snapshot, and optional error.
    pub fn new(
        schedule: Box<dyn TraceSchedule>,
        snapshot: i64,
        error: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self { schedule, snapshot, error }
    }
}

impl RunResult for RecordEmulationResult {
    fn schedule(&self) -> &dyn TraceSchedule {
        self.schedule.as_ref()
    }

    fn error(&self) -> Option<&(dyn std::error::Error + Send + Sync)> {
        self.error.as_deref()
    }
}

impl EmulationResult for RecordEmulationResult {
    fn snapshot(&self) -> i64 {
        self.snapshot
    }
}

/// An emulator managed by this service.
///
/// Port of `DebuggerEmulationService.CachedEmulator`.
pub struct CachedEmulator {
    trace: Box<dyn Trace>,
    emulator: Box<dyn PcodeMachine>,
    writer: Box<dyn Writer>,
    version: i64,
}

impl CachedEmulator {
    /// Creates a cached emulator, capturing the trace's current emulator cache version.
    ///
    /// Port of `CachedEmulator(Trace, PcodeMachine<?>, Writer)`.
    pub fn new(trace: Box<dyn Trace>, emulator: Box<dyn PcodeMachine>, writer: Box<dyn Writer>) -> Self {
        let version = trace.get_emulator_cache_version();
        Self { trace, emulator, writer, version }
    }

    /// Creates a cached emulator with an explicit cache version.
    ///
    /// Port of the canonical `CachedEmulator(Trace, PcodeMachine<?>, Writer, long)` constructor.
    pub fn with_version(
        trace: Box<dyn Trace>,
        emulator: Box<dyn PcodeMachine>,
        writer: Box<dyn Writer>,
        version: i64,
    ) -> Self {
        Self { trace, emulator, writer, version }
    }

    /// Get the trace to which the emulator is bound.
    pub fn trace(&self) -> &dyn Trace {
        self.trace.as_ref()
    }

    /// Get the emulator.
    ///
    /// **WARNING:** This emulator belongs to this service. You may interrupt it, but stepping
    /// it, or otherwise manipulating it without the service's knowledge can lead to unintended
    /// consequences.
    pub fn emulator(&self) -> &dyn PcodeMachine {
        self.emulator.as_ref()
    }

    /// Get the callbacks with delayed writes for trace/UI integration.
    pub fn writer(&self) -> &dyn Writer {
        self.writer.as_ref()
    }

    /// Get the cache version this emulator was captured at. See [`CachedEmulator::is_valid`].
    pub fn version(&self) -> i64 {
        self.version
    }

    /// Check if this cached emulator is still valid.
    pub fn is_valid(&self) -> bool {
        self.version >= self.trace.get_emulator_cache_version()
    }
}

/// A listener for changes in emulator state.
///
/// Port of `DebuggerEmulationService.EmulatorStateListener`.
pub trait EmulatorStateListener {
    /// An emulator is running.
    fn running(&self, _emu: &CachedEmulator) {}

    /// An emulator has stopped.
    fn stopped(&self, _emu: &CachedEmulator) {}
}

/// A service for accessing managed emulators.
///
/// Port of `ghidra.app.services.DebuggerEmulationService`.
pub trait DebuggerEmulationService {
    /// Get the available emulator factories.
    fn get_emulator_factories(&self) -> Vec<Box<dyn EmulatorFactory>>;

    /// Set the current emulator factory.
    fn set_emulator_factory(&mut self, factory: Box<dyn EmulatorFactory>);

    /// Get the current emulator factory.
    fn get_emulator_factory(&self) -> Box<dyn EmulatorFactory>;

    /// Load the given program into a trace suitable for emulation in the UI, starting at the
    /// given address.
    ///
    /// Note that the program bytes are not actually loaded into the trace. Rather a static
    /// mapping is generated, allowing the emulator to load bytes from the target program lazily.
    /// The trace is automatically loaded into the UI (trace manager).
    fn launch_program(&self, program: &dyn Program, address: &Address) -> io::Result<Box<dyn Trace>>;

    /// Perform emulation to realize the machine state of the given time coordinates.
    ///
    /// Only those address ranges actually modified during emulation are written into the
    /// scratch space. It is the responsibility of anyone reading from scratch space to retrieve
    /// state and/or annotations from the initial snap, when needed. The scratch snapshot is
    /// given the description `emu:[time]`, where `[time]` is the given time parameter as a
    /// string.
    ///
    /// The service may use a cached emulator in order to realize the requested machine state.
    /// This is especially important to ensure that a user stepping forward does not incur ever
    /// increasing costs. On the other hand, the service should be careful to invalidate cached
    /// results when the recorded machine state in a trace changes.
    ///
    /// Returns the snap in the trace's scratch space where the realized state is stored.
    fn emulate(
        &self,
        platform: &dyn TracePlatform,
        time: &dyn TraceSchedule,
        monitor: &dyn TaskMonitor,
    ) -> Result<i64, CancelledException>;

    /// Emulate using the trace's "host" platform.
    ///
    /// See [`DebuggerEmulationService::emulate`].
    fn emulate_trace(
        &self,
        trace: &dyn Trace,
        time: &dyn TraceSchedule,
        monitor: &dyn TaskMonitor,
    ) -> Result<i64, CancelledException>;

    /// Allow the emulator to "run free" until it is interrupted or encounters an error.
    ///
    /// The service may perform some preliminary emulation to realize the machine's initial
    /// state. If the monitor cancels during preliminary emulation, this method returns a
    /// [`CancelledException`]. If the monitor cancels the emulation during the run, it is
    /// treated the same as interruption. The machine state will be written to the trace in a
    /// scratch snap and the result returned. Note that the machine could be interrupted having
    /// only partially executed an instruction. Thus, the schedule may specify p-code operations.
    /// The schedule will place the program counter on the instruction (or p-code op) causing the
    /// interruption. Thus, except for breakpoints, attempting to step again will interrupt the
    /// emulator again.
    fn run(
        &self,
        platform: &dyn TracePlatform,
        from: &dyn TraceSchedule,
        monitor: &dyn TaskMonitor,
        scheduler: &dyn Scheduler,
    ) -> Result<Box<dyn EmulationResult>, CancelledException>;

    /// Invoke [`DebuggerEmulationService::emulate_trace`] in the background.
    ///
    /// This is the preferred means of performing definite emulation. Because the underlying
    /// emulator may request a *blocking* read from a target, it is important that
    /// [`DebuggerEmulationService::emulate`] is *never* called by the UI thread.
    fn background_emulate(&self, platform: &dyn TracePlatform, time: &dyn TraceSchedule) -> EmulateFuture;

    /// Invoke [`DebuggerEmulationService::run`] in the background.
    ///
    /// This is the preferred means of performing indefinite emulation, for the same reasons as
    /// [`DebuggerEmulationService::background_emulate`].
    fn background_run(
        &self,
        platform: &dyn TracePlatform,
        from: &dyn TraceSchedule,
        scheduler: &dyn Scheduler,
    ) -> RunFuture;

    /// Get the cached emulator for the given trace and time.
    ///
    /// To guarantee the emulator is present, call
    /// [`DebuggerEmulationService::background_emulate`] first.
    ///
    /// **WARNING:** This emulator belongs to this service. Stepping it, or otherwise
    /// manipulating it without the service's knowledge can lead to unintended consequences.
    fn get_cached_emulator(&self, trace: &dyn Trace, time: &dyn TraceSchedule) -> Box<dyn PcodeMachine>;

    /// Get the emulators which are currently executing.
    fn get_busy_emulators(&self) -> Vec<CachedEmulator>;

    /// Invalidate the trace's cache of emulated states.
    fn invalidate_cache(&mut self);

    /// Add a listener for emulator state changes.
    fn add_state_listener(&mut self, listener: Box<dyn EmulatorStateListener>);

    /// Remove a listener for emulator state changes.
    fn remove_state_listener(&mut self, listener: &dyn EmulatorStateListener);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    struct MockEmulatorFactory;
    impl EmulatorFactory for MockEmulatorFactory {}

    struct MockPcodeMachine;
    impl PcodeMachine for MockPcodeMachine {}

    struct MockTraceSchedule;
    impl TraceSchedule for MockTraceSchedule {}

    struct MockTracePlatform;
    impl TracePlatform for MockTracePlatform {}

    struct MockScheduler;
    impl Scheduler for MockScheduler {}

    struct MockService {
        listener_count: usize,
    }

    impl DebuggerEmulationService for MockService {
        fn get_emulator_factories(&self) -> Vec<Box<dyn EmulatorFactory>> {
            vec![Box::new(MockEmulatorFactory)]
        }

        fn set_emulator_factory(&mut self, _factory: Box<dyn EmulatorFactory>) {}

        fn get_emulator_factory(&self) -> Box<dyn EmulatorFactory> {
            Box::new(MockEmulatorFactory)
        }

        fn launch_program(
            &self,
            _program: &dyn Program,
            _address: &Address,
        ) -> io::Result<Box<dyn Trace>> {
            unimplemented!("not exercised by this smoke test")
        }

        fn emulate(
            &self,
            _platform: &dyn TracePlatform,
            _time: &dyn TraceSchedule,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i64, CancelledException> {
            Ok(0)
        }

        fn emulate_trace(
            &self,
            _trace: &dyn Trace,
            _time: &dyn TraceSchedule,
            _monitor: &dyn TaskMonitor,
        ) -> Result<i64, CancelledException> {
            Ok(0)
        }

        fn run(
            &self,
            _platform: &dyn TracePlatform,
            _from: &dyn TraceSchedule,
            _monitor: &dyn TaskMonitor,
            _scheduler: &dyn Scheduler,
        ) -> Result<Box<dyn EmulationResult>, CancelledException> {
            Ok(Box::new(RecordEmulationResult::new(Box::new(MockTraceSchedule), 0, None)))
        }

        fn background_emulate(
            &self,
            _platform: &dyn TracePlatform,
            _time: &dyn TraceSchedule,
        ) -> EmulateFuture {
            Box::pin(std::future::ready(Ok(0)))
        }

        fn background_run(
            &self,
            _platform: &dyn TracePlatform,
            _from: &dyn TraceSchedule,
            _scheduler: &dyn Scheduler,
        ) -> RunFuture {
            Box::pin(std::future::ready(Ok(
                Box::new(RecordEmulationResult::new(Box::new(MockTraceSchedule), 0, None))
                    as Box<dyn EmulationResult>,
            )))
        }

        fn get_cached_emulator(&self, _trace: &dyn Trace, _time: &dyn TraceSchedule) -> Box<dyn PcodeMachine> {
            Box::new(MockPcodeMachine)
        }

        fn get_busy_emulators(&self) -> Vec<CachedEmulator> {
            vec![]
        }

        fn invalidate_cache(&mut self) {}

        fn add_state_listener(&mut self, _listener: Box<dyn EmulatorStateListener>) {
            self.listener_count += 1;
        }

        fn remove_state_listener(&mut self, _listener: &dyn EmulatorStateListener) {
            self.listener_count -= 1;
        }
    }

    struct RecordingListener;
    impl EmulatorStateListener for RecordingListener {}

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let mut service: Box<dyn DebuggerEmulationService> = Box::new(MockService { listener_count: 0 });

        assert_eq!(service.get_emulator_factories().len(), 1);

        let monitor = DummyMonitor;
        assert_eq!(
            service.emulate(&MockTracePlatform, &MockTraceSchedule, &monitor).unwrap(),
            0
        );

        let result = service
            .run(&MockTracePlatform, &MockTraceSchedule, &monitor, &MockScheduler)
            .unwrap();
        assert_eq!(result.snapshot(), 0);
        assert!(result.error().is_none());

        assert!(service.get_busy_emulators().is_empty());

        service.add_state_listener(Box::new(RecordingListener));
        service.remove_state_listener(&RecordingListener);
    }

    #[tokio::test]
    async fn background_futures_resolve() {
        let service = MockService { listener_count: 0 };

        let snap = service
            .background_emulate(&MockTracePlatform, &MockTraceSchedule)
            .await
            .unwrap();
        assert_eq!(snap, 0);

        let result = service
            .background_run(&MockTracePlatform, &MockTraceSchedule, &MockScheduler)
            .await
            .unwrap();
        assert_eq!(result.snapshot(), 0);
    }
}
