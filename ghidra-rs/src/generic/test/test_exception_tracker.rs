//! Port of `generic.test.TestExceptionTracker`.
//!
//! A class to take an exception and capture test system state for later reporting.
//!
//! # Deviations from Java
//!
//! Java's constructor calls a private `recordTestThreadState()`, which walks
//! `Thread.getAllStackTraces()` (a snapshot of *every* live thread's current call stack) looking
//! for the one satisfying `TestThread.isTestThread(thread)`, then filters that thread's trace via
//! `TestThread.filterTrace`. Stable Rust has no equivalent capability to inspect another live
//! thread's call stack -- the same limitation already documented on
//! [`TestReportingException::from_swing_thread`](crate::generic::test::test_reporting_exception::TestReportingException::from_swing_thread)
//! and on [`reflection_utilities`](crate::util::util::reflection::reflection_utilities) -- so this
//! port follows `from_swing_thread`'s own precedent exactly: the caller supplies the current call
//! stack explicitly via `current_trace`, and [`TestExceptionTracker::new`] only consults (and
//! filters) it when [`is_test_thread`] reports that the *calling* thread is itself the test
//! thread, mirroring Java's `TestThread.isTestThread` guard. When it is not, Java's loop falls
//! through every live thread without a match and returns `new StackTraceElement[0]` (an empty,
//! non-null array); this port matches that by storing an empty `Vec` rather than `None`.

use std::io;

use crate::generic::test::test_reporting_exception::{TestReportingException, WrappedThrowable};
use crate::generic::test::test_thread::{filter_trace, is_test_thread};
use crate::util::util::reflection::reflection_utilities::StackFrame;

/// A class to take an exception and capture test system state for later reporting.
///
/// Port of `generic.test.TestExceptionTracker`. See the module docs for how this port supplies
/// the test thread's stack trace, since Rust cannot capture it the way Java does.
#[derive(Debug, Clone)]
pub struct TestExceptionTracker {
    thread_name: String,
    t: WrappedThrowable,
    test_thread_trace: Vec<StackFrame>,
}

impl TestExceptionTracker {
    /// Port of `TestExceptionTracker(String threadName, Throwable t)`, which internally calls the
    /// now-inlined `recordTestThreadState()`. See the module docs for why the caller must supply
    /// `current_trace` explicitly (standing in for the trace Java itself finds by inspecting live
    /// threads) rather than it being captured implicitly.
    pub fn new(
        thread_name: impl Into<String>,
        t: WrappedThrowable,
        current_trace: &[StackFrame],
    ) -> Self {
        let test_thread_trace = if is_test_thread() { filter_trace(current_trace) } else { Vec::new() };
        TestExceptionTracker { thread_name: thread_name.into(), t, test_thread_trace }
    }

    /// Port of `getException()`.
    pub fn get_exception(&self) -> &WrappedThrowable {
        &self.t
    }

    /// Port of `getCombinedException()`.
    ///
    /// Java always passes its (possibly empty, but never `null`) `testThreadTrace` field to the
    /// three-argument `TestReportingException` constructor, so this always supplies `Some(..)` --
    /// even when [`Self::test_thread_trace`] is empty -- matching Java's behavior of always
    /// printing the "Test thread stack at that time:" section once routed through a
    /// [`TestExceptionTracker`], regardless of whether anything actually landed in it.
    pub fn get_combined_exception(&self) -> TestReportingException {
        TestReportingException::with_test_thread_trace(
            self.thread_name.clone(),
            self.t.clone(),
            Some(self.test_thread_trace.clone()),
        )
    }

    /// Port of `printStackTrace()`.
    pub fn print_stack_trace(&self, w: &mut dyn io::Write) -> io::Result<()> {
        self.get_combined_exception().print_stack_trace(w)
    }

    /// Port of `getStackTrace()`.
    pub fn get_stack_trace(&self) -> &[StackFrame] {
        &self.test_thread_trace
    }

    /// Port of `getExceptionMessage()`.
    pub fn get_exception_message(&self) -> String {
        match &self.t.message {
            Some(message) => message.clone(),
            None => self.t.class_name.clone(),
        }
    }

    /// Port of `getThreadName()`.
    pub fn get_thread_name(&self) -> &str {
        &self.thread_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(class_name: &str, method_name: &str) -> StackFrame {
        StackFrame::new(class_name, method_name)
    }

    fn throwable(class_name: &str, message: Option<&str>) -> WrappedThrowable {
        WrappedThrowable::new(class_name, message.map(str::to_string))
    }

    #[test]
    fn off_the_test_thread_the_test_thread_trace_is_empty() {
        // A plain `#[test]` thread's name doesn't match `is_test_thread`'s `"Test-"` prefix
        // convention, so this exercises Java's "no matching thread found" fallback path, which
        // returns an empty (not null) trace array.
        assert!(!is_test_thread());

        let current_trace = vec![frame("com.example.MyTest", "testSomething")];
        let tracker =
            TestExceptionTracker::new("main", throwable("RuntimeException", Some("boom")), &current_trace);

        assert_eq!(tracker.get_stack_trace(), &[] as &[StackFrame]);
    }

    #[test]
    fn on_the_test_thread_the_trace_is_captured_and_filtered() {
        // `TestThread::filter_trace`'s own patterns strip `org.junit.*`, but not an arbitrary
        // frame like `java.awt.WaitDispatchSupport` (that pattern belongs to
        // `TestReportingException`'s own, different, filter list -- see that module's tests for
        // the same distinction).
        let current_trace =
            vec![frame("org.junit.runners.ParentRunner", "run"), frame("com.example.MyTest", "testSomething")];

        let result = std::thread::Builder::new()
            .name("Test-worker".to_string())
            .spawn(move || {
                TestExceptionTracker::new("main", throwable("RuntimeException", Some("boom")), &current_trace)
            })
            .unwrap()
            .join()
            .unwrap();

        assert_eq!(result.get_stack_trace(), &[frame("com.example.MyTest", "testSomething")]);
    }

    #[test]
    fn get_exception_returns_the_wrapped_throwable() {
        let t = throwable("IllegalStateException", Some("bad state"));
        let tracker = TestExceptionTracker::new("main", t.clone(), &[]);
        assert_eq!(tracker.get_exception(), &t);
    }

    #[test]
    fn get_exception_message_prefers_the_throwables_message() {
        let tracker = TestExceptionTracker::new("main", throwable("RuntimeException", Some("boom")), &[]);
        assert_eq!(tracker.get_exception_message(), "boom");
    }

    #[test]
    fn get_exception_message_falls_back_to_the_class_name_when_there_is_no_message() {
        let tracker = TestExceptionTracker::new("main", throwable("NullPointerException", None), &[]);
        assert_eq!(tracker.get_exception_message(), "NullPointerException");
    }

    #[test]
    fn get_thread_name_returns_the_recorded_name() {
        let tracker = TestExceptionTracker::new("AWT-EventQueue-0", throwable("X", None), &[]);
        assert_eq!(tracker.get_thread_name(), "AWT-EventQueue-0");
    }

    #[test]
    fn get_combined_exception_always_includes_the_test_thread_stack_section_even_when_empty() {
        // Off the test thread, `test_thread_trace` is empty -- but Java still always passes its
        // (non-null) array through to `TestReportingException`'s three-arg constructor, so the
        // "Test thread stack at that time:" section is still printed, just with no frames under
        // it. This is the behavior this test locks down.
        let tracker = TestExceptionTracker::new("AWT-EventQueue-0", throwable("X", Some("boom")), &[]);
        let combined = tracker.get_combined_exception();

        let mut buf = Vec::new();
        combined.print_stack_trace(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("\nTest thread stack at that time:\n"));
    }

    #[test]
    fn get_combined_exception_carries_the_filtered_test_thread_frames() {
        let current_trace = vec![frame("com.example.MyTest", "testSomething")];
        let tracker = std::thread::Builder::new()
            .name("Test-worker".to_string())
            .spawn(move || {
                TestExceptionTracker::new("AWT-EventQueue-0", throwable("X", Some("boom")), &current_trace)
            })
            .unwrap()
            .join()
            .unwrap();

        let combined = tracker.get_combined_exception();
        let mut buf = Vec::new();
        combined.print_stack_trace(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("\tat com.example.MyTest.testSomething\n"));
    }

    #[test]
    fn print_stack_trace_writes_the_combined_exceptions_rendering() {
        let tracker = TestExceptionTracker::new("AWT-EventQueue-0", throwable("RuntimeException", Some("x")), &[]);
        let mut direct = Vec::new();
        tracker.print_stack_trace(&mut direct).unwrap();

        let mut via_combined = Vec::new();
        tracker.get_combined_exception().print_stack_trace(&mut via_combined).unwrap();

        assert_eq!(direct, via_combined);
    }
}
