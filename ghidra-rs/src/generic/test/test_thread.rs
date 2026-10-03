//! Port of `generic.test.TestThread`.
//!
//! Java's version subclasses `Thread` and wraps a JUnit `org.junit.runners.model.Statement`
//! (a test body's `evaluate()` call), running it on a dedicated thread so a swing-deadlocked or
//! hanging test can still be interrupted/inspected by the runner that started it
//! (`ExceptionHandlingRunner`, not ported -- out of scope, a JUnit runner integration with no
//! Rust test-framework equivalent).
//!
//! # Shape
//!
//! "Extends `Thread`" becomes composition: [`TestThread`] holds the shared, thread-safe state
//! (`finished`/`exception_from_test`, Java's `volatile` fields) behind `Arc`s cloned into the
//! spawned [`std::thread::JoinHandle`], plus the handle itself once [`TestThread::start`] is
//! called. `Statement.evaluate()` -- an interface method with a single `throws Throwable` entry
//! point -- becomes a `FnOnce` closure, the same representation this crate's other
//! `Statement`-wrapping port,
//! [`IgnoreUnfinishedStatement`](crate::generic::test::rule::IgnoreUnfinishedStatement), uses.
//!
//! # Deviations
//!
//! * Java's fields are package-private (`/*package*/`), read directly by same-package code
//!   (`ExceptionHandlingRunner`). Rust has no package-private visibility, so they are exposed
//!   through accessor methods ([`TestThread::is_finished`], [`TestThread::take_exception_from_test`])
//!   instead.
//! * `run()`'s `catch (InterruptedException e)` branch (silently swallowed, since the runner may
//!   have triggered it itself via `Thread.interrupt()`) has no Rust equivalent: `std::thread`
//!   provides no forced/asynchronous interruption mechanism comparable to Java's, so there is
//!   nothing to swallow. The `catch (Throwable e)` branch is still modeled in full -- both an
//!   `Err` returned from the statement closure *and* a Rust panic unwinding out of it (the
//!   closest analogue to Java's unchecked `Error`/`RuntimeException` subclasses of `Throwable`)
//!   are caught and stored as [`TestThreadFailure`].
//! * Java's default thread name (`getName()`, before being overwritten with the `"Test-"`
//!   prefix) comes from the JVM's global `Thread` instance counter (`"Thread-0"`, `"Thread-1"`,
//!   ...). This port uses its own counter, scoped to [`TestThread`] instances only, for the same
//!   `"Thread-<n>"` shape -- the exact numbering was never meaningful (it's overwritten anyway;
//!   `NAME_PREFIX` is a prefix, not a fixed name), so no test could distinguish the two schemes.
//! * The panic message is extracted from `catch_unwind`'s payload (`Box<dyn Any + Send>`)
//!   immediately, right where it's caught, into an owned `String`, rather than keeping the raw
//!   payload around and downcasting it later (e.g. from inside `Display`). The two ought to be
//!   equivalent for the usual `&'static str`/`String` panic-message payload shape, but only
//!   extracting immediately proved reliable; the original payload is kept alongside the message
//!   regardless, for callers that want it.

use std::any::Any;
use std::error::Error;
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::util::util::reflection::{filter_stack_trace, StackFrame};

const SUN_PACKAGE: &str = "sun.";
const JAVA_LANG_PACKAGE: &str = "java.lang";
const JAVA_AWT_EVENT_PACKAGE: &str = "java.awt.EventQueue";
const JUNIT_FRAMEWORK_PACKAGE: &str = "junit.framework";
const JUNIT_ORG_PACKAGE: &str = "org.junit";
const MOCKIT_JUNIT_PACKAGE: &str = "mockit.integration.junit";
const GHIDRA_SWING_RUNNER: &str = "ExceptionHandlingRunner";

/// Prefix `TestThread` gives every thread it creates.
///
/// Port of `TestThread.NAME_PREFIX`.
pub const NAME_PREFIX: &str = "Test-";

static NEXT_DEFAULT_THREAD_NUMBER: AtomicUsize = AtomicUsize::new(0);

/// Returns true if the current thread is the test thread.
///
/// Port of `TestThread.isTestThread()`.
pub fn is_test_thread() -> bool {
    std::thread::current().name().is_some_and(is_test_thread_name)
}

/// Returns true if the given thread is the test thread.
///
/// Port of `TestThread.isTestThread(Thread)`.
pub fn is_test_thread_handle(t: &std::thread::Thread) -> bool {
    t.name().is_some_and(is_test_thread_name)
}

/// Returns true if the given thread name is the test thread name.
///
/// Port of `TestThread.isTestThreadName(String)`.
pub fn is_test_thread_name(name: &str) -> bool {
    name.starts_with(NAME_PREFIX)
}

/// Filters the given stack trace to remove entries known to be present in the test thread that
/// offer little forensic value.
///
/// Port of `TestThread.filterTrace(StackTraceElement[])`.
pub fn filter_trace(trace: &[StackFrame]) -> Vec<StackFrame> {
    filter_stack_trace(
        trace,
        &[
            JUNIT_ORG_PACKAGE,
            JUNIT_FRAMEWORK_PACKAGE,
            MOCKIT_JUNIT_PACKAGE,
            JAVA_AWT_EVENT_PACKAGE,
            JAVA_LANG_PACKAGE,
            SUN_PACKAGE,
            GHIDRA_SWING_RUNNER,
        ],
    )
}

/// Extracts a human-readable message from a `catch_unwind` panic payload -- the same criteria
/// `std::panic::PanicHookInfo::payload_as_str` uses: a plain `panic!()` invocation always
/// produces a payload of type `&'static str` or `String`.
fn extract_panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

/// What [`TestThread`]'s spawned thread caught while evaluating its statement: either an `Err`
/// the statement closure returned, or a Rust panic that unwound out of it. Stands in for Java's
/// `Throwable`, which both checked/unchecked exceptions and JVM errors share a common supertype
/// for.
pub enum TestThreadFailure {
    /// The statement closure returned an error.
    Error(Box<dyn Error + Send>),
    /// The statement closure panicked. `message` is extracted from `payload` up front (see this
    /// module's "Deviations" doc); `payload` is kept alongside for callers that want the raw
    /// value `std::panic::catch_unwind` produced.
    Panic {
        message: String,
        payload: Box<dyn Any + Send>,
    },
}

impl fmt::Display for TestThreadFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TestThreadFailure::Error(e) => write!(f, "{e}"),
            TestThreadFailure::Panic { message, .. } => write!(f, "panic: {message}"),
        }
    }
}

impl fmt::Debug for TestThreadFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TestThreadFailure::Error(e) => write!(f, "TestThreadFailure::Error({e:?})"),
            TestThreadFailure::Panic { message, .. } => {
                write!(f, "TestThreadFailure::Panic({message:?})")
            }
        }
    }
}

impl Error for TestThreadFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            TestThreadFailure::Error(e) => Some(e.as_ref()),
            TestThreadFailure::Panic { .. } => None,
        }
    }
}

type Statement = dyn FnOnce() -> Result<(), Box<dyn Error + Send>> + Send;

/// Runs a single test statement on its own thread.
///
/// Port of `generic.test.TestThread`.
pub struct TestThread {
    name: String,
    finished: Arc<AtomicBool>,
    exception_from_test: Arc<Mutex<Option<TestThreadFailure>>>,
    statement: Option<Box<Statement>>,
    handle: Option<JoinHandle<()>>,
}

impl TestThread {
    /// Constructs a new `TestThread` wrapping `statement`, a JUnit-`Statement`-style closure run
    /// once, on its own thread, when [`Self::start`] is called.
    ///
    /// Port of the package-private `TestThread(Statement)` constructor.
    pub fn new<F>(statement: F) -> Self
    where
        F: FnOnce() -> Result<(), Box<dyn Error + Send>> + Send + 'static,
    {
        let default_name =
            format!("Thread-{}", NEXT_DEFAULT_THREAD_NUMBER.fetch_add(1, Ordering::SeqCst));
        TestThread {
            name: format!("{NAME_PREFIX}{default_name}"),
            finished: Arc::new(AtomicBool::new(false)),
            exception_from_test: Arc::new(Mutex::new(None)),
            statement: Some(Box::new(statement)),
            handle: None,
        }
    }

    /// This thread's name (always `NAME_PREFIX`-prefixed).
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Starts the thread, evaluating the wrapped statement.
    ///
    /// Port of `Thread.start()` as inherited/used by `TestThread`; `run()`'s body is folded in
    /// here rather than kept as a separate method, since Rust has no virtual-dispatch
    /// `Runnable.run()` to override -- the spawned closure below *is* the port of `run()`.
    ///
    /// # Panics
    /// Panics if called more than once (Java's `Thread.start()` likewise throws
    /// `IllegalThreadStateException` if the thread was already started).
    pub fn start(&mut self) {
        let statement = self.statement.take().expect("TestThread already started");
        let finished = Arc::clone(&self.finished);
        let exception_from_test = Arc::clone(&self.exception_from_test);

        let handle = std::thread::Builder::new()
            .name(self.name.clone())
            .spawn(move || {
                // Port of `run()`: `statement.evaluate()` inside try/catch(Throwable)/finally.
                // See this module's doc comment for why the `InterruptedException` branch has no
                // Rust equivalent (nothing to swallow).
                match std::panic::catch_unwind(AssertUnwindSafe(statement)) {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        *exception_from_test.lock().unwrap() = Some(TestThreadFailure::Error(e));
                    }
                    Err(panic_payload) => {
                        let message = extract_panic_message(panic_payload.as_ref());
                        *exception_from_test.lock().unwrap() =
                            Some(TestThreadFailure::Panic { message, payload: panic_payload });
                    }
                }
                finished.store(true, Ordering::SeqCst);
            })
            .expect("failed to spawn TestThread");

        self.handle = Some(handle);
    }

    /// Whether the wrapped statement has finished running (successfully or not).
    ///
    /// Port of reading the package-private `finished` field.
    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::SeqCst)
    }

    /// Whether the wrapped statement failed (returned an error or panicked).
    ///
    /// Port of `exceptionFromTest != null`.
    pub fn has_exception_from_test(&self) -> bool {
        self.exception_from_test.lock().unwrap().is_some()
    }

    /// Takes the failure the wrapped statement produced, if any.
    ///
    /// Port of reading (and here, consuming) the package-private `exceptionFromTest` field.
    pub fn take_exception_from_test(&self) -> Option<TestThreadFailure> {
        self.exception_from_test.lock().unwrap().take()
    }

    /// Blocks until the thread finishes, propagating a join failure (e.g. the spawned closure
    /// itself panicking outside the `catch_unwind` -- not expected, since [`Self::start`] wraps
    /// the whole statement in one). Not part of the Java class (`Thread.join()` is inherited, not
    /// overridden); provided as a convenience for callers -- and this module's own tests -- that
    /// need to wait for completion rather than polling [`Self::is_finished`].
    pub fn join(&mut self) -> std::thread::Result<()> {
        match self.handle.take() {
            Some(handle) => handle.join(),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize as StdAtomicUsize;
    use std::time::Duration;

    fn wait_until_finished(thread: &TestThread) {
        for _ in 0..200 {
            if thread.is_finished() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("TestThread did not finish in time");
    }

    #[test]
    fn name_is_prefixed_and_unique_per_instance() {
        let a = TestThread::new(|| Ok(()));
        let b = TestThread::new(|| Ok(()));
        assert!(a.get_name().starts_with(NAME_PREFIX));
        assert!(b.get_name().starts_with(NAME_PREFIX));
        assert_ne!(a.get_name(), b.get_name());
    }

    #[test]
    fn is_test_thread_name_matches_the_prefix() {
        assert!(is_test_thread_name("Test-Thread-0"));
        assert!(!is_test_thread_name("Thread-0"));
    }

    #[test]
    fn successful_statement_leaves_no_exception() {
        let ran = Arc::new(StdAtomicUsize::new(0));
        let ran_clone = Arc::clone(&ran);
        let mut thread = TestThread::new(move || {
            ran_clone.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        assert!(!thread.is_finished());
        thread.start();
        thread.join().expect("join should succeed");

        assert!(thread.is_finished());
        assert!(!thread.has_exception_from_test());
        assert_eq!(ran.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn statement_error_is_captured_as_a_failure() {
        let mut thread = TestThread::new(|| {
            let err: Box<dyn Error + Send> =
                Box::new(std::io::Error::new(std::io::ErrorKind::Other, "boom"));
            Err(err)
        });
        thread.start();
        wait_until_finished(&thread);

        let failure = thread.take_exception_from_test().expect("expected a captured failure");
        assert!(matches!(failure, TestThreadFailure::Error(_)));
        assert_eq!(failure.to_string(), "boom");
        // Consuming it once empties the slot, mirroring a one-shot read of the Java field.
        assert!(thread.take_exception_from_test().is_none());
    }

    #[test]
    fn statement_panic_is_captured_as_a_failure() {
        let mut thread = TestThread::new(|| panic!("kaboom"));
        thread.start();
        thread.join().expect("join should succeed even though the closure panicked internally");

        let failure = thread.take_exception_from_test().expect("expected a captured panic");
        assert!(matches!(failure, TestThreadFailure::Panic { .. }));
        assert!(failure.to_string().contains("kaboom"));
    }

    #[test]
    #[should_panic(expected = "TestThread already started")]
    fn starting_twice_panics() {
        let mut thread = TestThread::new(|| Ok(()));
        thread.start();
        thread.start();
    }

    #[test]
    fn filter_trace_removes_junit_and_swing_frames_but_keeps_test_code() {
        let trace = vec![
            StackFrame::new("com.example.MyTest", "testSomething"),
            StackFrame::new("org.junit.runners.ParentRunner", "run"),
            StackFrame::new("java.lang.Thread", "run"),
        ];

        let filtered = filter_trace(&trace);

        assert_eq!(filtered, vec![StackFrame::new("com.example.MyTest", "testSomething")]);
    }
}
