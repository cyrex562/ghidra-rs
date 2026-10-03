//! An exception that prints a custom, filtered stack trace -- including, when raised while on the
//! test thread, a second trace for the test thread itself at the time of the (usually Swing-side)
//! failure being reported.
//!
//! Java source: `generic.test.TestReportingException`.
//!
//! # Shape
//!
//! * **`extends RuntimeException`** becomes composition, per this crate's convention: no base
//!   exception type to hold; [`TestReportingException`] is its own free-standing struct
//!   implementing [`std::error::Error`]/[`std::fmt::Display`]/[`std::fmt::Debug`] directly.
//! * **The wrapped `Throwable t`.** Java's field can hold *any* exception object, and this class
//!   reads exactly four things from it: `getMessage()`, `getClass().getSimpleName()`,
//!   `getStackTrace()`/`setStackTrace()`, and `getCause()` (recursively, for the "Caused By"
//!   chain). There is no single Rust trait exposing that exact quartet -- `std::error::Error`
//!   gives `Display`/`source()` but no structured stack trace and no reflective "simple class
//!   name" for an arbitrary `&dyn Error` -- so [`WrappedThrowable`] models precisely that shape
//!   instead of holding a generic `Box<dyn Error>`.
//! * **Capturing "the current call stack."** `fromSwingThread` calls
//!   `ReflectionUtilities.createThrowableWithStackOlderThan(TestReportingException.class)`, which
//!   captures the *caller's own* call stack via `new Throwable().getStackTrace()`. As documented on
//!   [`reflection_utilities`](crate::util::util::reflection::reflection_utilities) (see its module
//!   docs: stable Rust exposes no structured, per-frame backtrace API), there is no way to capture
//!   this implicitly. [`TestReportingException::from_swing_thread`] therefore takes the caller's
//!   current trace as an explicit `current_trace: &[StackFrame]` parameter -- the same tradeoff
//!   `reflection_utilities` itself already makes for the identical reason -- rather than capturing
//!   it internally. [`SELF_CLASS_NAME`] stands in for `TestReportingException.class.getName()`,
//!   the same way `reflection_utilities::SELF_MARKER` stands in for `ReflectionUtilities.class
//!   .getName()`.
//! * **`printStackTrace(PrintStream)` / `printStackTrace(PrintWriter)`.** Both Java overloads
//!   delegate to the same `buildStackTraceString()` and then `println`; `std::io::Write` covers
//!   both a stream and an in-memory buffer, so [`TestReportingException::print_stack_trace`] is a
//!   single method for both.
use std::io;

use crate::generic::test::test_thread::{filter_trace as test_thread_filter_trace, is_test_thread};
use crate::util::util::reflection::reflection_utilities::{
    filter_stack_trace, frames_after_exact, StackFrame,
};

/// Stand-in for `TestReportingException.class.getName()`. See this module's docs (and
/// [`reflection_utilities::SELF_MARKER`](crate::util::util::reflection::reflection_utilities))
/// for why Rust has no reflective equivalent and a fully-qualified path is used in its place.
pub const SELF_CLASS_NAME: &str =
    "ghidra_rs::generic::test::test_reporting_exception::TestReportingException";

const GENERAL_USELESS_STACK_ELEMENT_PATTERNS: &[&str] = &["java.awt.WaitDispatchSupport"];

const SWING_STACK_ELEMENT_PATTERNS: &[&str] =
    &["java.awt.WaitDispatchSupport", "java.awt.Event", "java.security", "java.awt.event"];

/// The minimal shape of a wrapped Java `Throwable` this exception needs. See this module's docs
/// for why a dedicated struct stands in for a generic `Box<dyn Error>`.
///
/// Port of the fields of `t: Throwable` that `TestReportingException` actually reads:
/// `getMessage()` (-> `message`), `getClass().getSimpleName()` (-> `class_name`),
/// `getStackTrace()`/`setStackTrace()` (-> `stack_trace`, mutable), and `getCause()` (->
/// `cause`, recursively).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedThrowable {
    pub class_name: String,
    pub message: Option<String>,
    pub stack_trace: Vec<StackFrame>,
    pub cause: Option<Box<WrappedThrowable>>,
}

impl WrappedThrowable {
    /// Constructs a wrapped throwable with no stack trace or cause yet; see
    /// [`Self::with_stack_trace`]/[`Self::with_cause`] to add them.
    pub fn new(class_name: impl Into<String>, message: Option<String>) -> Self {
        WrappedThrowable { class_name: class_name.into(), message, stack_trace: Vec::new(), cause: None }
    }

    /// Builder-style setter for [`Self::stack_trace`].
    pub fn with_stack_trace(mut self, stack_trace: Vec<StackFrame>) -> Self {
        self.stack_trace = stack_trace;
        self
    }

    /// Builder-style setter for [`Self::cause`].
    pub fn with_cause(mut self, cause: WrappedThrowable) -> Self {
        self.cause = Some(Box::new(cause));
        self
    }
}

/// A [`std::error::Error`] that prints a custom stack trace.
///
/// This prints not only the trace info for the exception passed at construction time, but also a
/// trace for the test thread at the time of the exception. The trace information printed is
/// filtered of entries that are not useful for debugging, like JVM-internal entries.
///
/// Port of `generic.test.TestReportingException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestReportingException {
    user_message: Option<String>,
    thread_name: String,
    t: WrappedThrowable,
    test_thread_trace: Option<Vec<StackFrame>>,
}

impl TestReportingException {
    /// Port of the package-private `TestReportingException(String, Throwable)`, which delegates to
    /// the three-argument constructor with a `null` trace.
    pub fn new(thread_name: impl Into<String>, t: WrappedThrowable) -> Self {
        Self::with_test_thread_trace(thread_name, t, None)
    }

    /// Port of the package-private `TestReportingException(String, Throwable,
    /// StackTraceElement[])`.
    pub fn with_test_thread_trace(
        thread_name: impl Into<String>,
        t: WrappedThrowable,
        test_thread_trace: Option<Vec<StackFrame>>,
    ) -> Self {
        TestReportingException { user_message: None, thread_name: thread_name.into(), t, test_thread_trace }
    }

    /// Creates a new [`TestReportingException`] using an exception that was generated on the
    /// Swing thread.
    ///
    /// `current_trace` stands in for the call stack Java captures implicitly via `new
    /// Throwable().getStackTrace()` at the call site -- see this module's docs for why Rust cannot
    /// capture that internally, and why it must be supplied by the caller instead. It is only
    /// consulted (and `t`'s own stack trace only filtered in place) when the *calling* thread is
    /// the test thread, exactly mirroring Java's `TestThread.isTestThread()` guard.
    ///
    /// Port of `TestReportingException.fromSwingThread(String, Throwable)`.
    pub fn from_swing_thread(
        message: Option<String>,
        mut t: WrappedThrowable,
        current_trace: &[StackFrame],
    ) -> Self {
        let mut test_thread_trace = None;
        if is_test_thread() {
            let older = frames_after_exact(current_trace, &[SELF_CLASS_NAME.to_string()]);
            test_thread_trace = Some(test_thread_filter_trace(&older));

            t.stack_trace = test_thread_filter_trace(&t.stack_trace);
        }

        let mut e = Self::with_test_thread_trace("AWT-EventQueue-0", t, test_thread_trace);
        e.user_message = message;
        e
    }

    /// Renders `throwable`'s stack trace the way it would appear if raised on the Swing thread:
    /// `"{ClassName}: {message}\n"` (or just `"{ClassName}\n"` with no message), followed by one
    /// `\tat Class.method` line per frame, filtered of Swing/AWT/security noise.
    ///
    /// Port of the static `getSwingThreadTraceString(Throwable)`.
    pub fn get_swing_thread_trace_string(throwable: &WrappedThrowable) -> String {
        let filtered = filter_stack_trace(&throwable.stack_trace, SWING_STACK_ELEMENT_PATTERNS);

        let message = match &throwable.message {
            Some(m) => format!("{}: {m}", throwable.class_name),
            None => throwable.class_name.clone(),
        };

        let mut out = String::new();
        out.push_str(&message);
        out.push('\n');
        Self::print_trace(&filtered, &mut out);
        out
    }

    /// Writes this exception's full custom trace (see [`Self::build_stack_trace_string`]) to `w`.
    ///
    /// Port of `printStackTrace(PrintStream)`/`printStackTrace(PrintWriter)`; see the module docs
    /// for why one method suffices for both Java overloads.
    pub fn print_stack_trace(&self, w: &mut dyn io::Write) -> io::Result<()> {
        writeln!(w, "{}", self.build_stack_trace_string())
    }

    /// This exception's filtered stack trace.
    ///
    /// Port of the overridden `getStackTrace()`, provided for callers that don't call
    /// [`Self::print_stack_trace`].
    pub fn get_stack_trace(&self) -> Vec<StackFrame> {
        self.filter_trace_for_thread(&self.t.stack_trace)
    }

    /// This exception's custom message, prefixed with a pointer to the fuller trace available via
    /// [`Self::print_stack_trace`].
    ///
    /// Port of the overridden `getMessage()`, provided for callers that don't call
    /// [`Self::print_stack_trace`].
    pub fn get_message(&self) -> String {
        format!("(See log for more stack trace info)\n\n{}", self.generate_message())
    }

    fn build_stack_trace_string(&self) -> String {
        let mut out = self.generate_message();
        out.push('\n');

        let trace = self.filter_trace_for_thread(&self.t.stack_trace);
        Self::print_trace(&trace, &mut out);

        self.add_all_cause_exceptions(&mut out);

        if let Some(test_thread_trace) = &self.test_thread_trace {
            out.push_str("\nTest thread stack at that time:\n");
            Self::print_trace(test_thread_trace, &mut out);
        }

        out
    }

    fn add_all_cause_exceptions(&self, out: &mut String) {
        self.add_cause_exception(&self.t, out);
    }

    fn add_cause_exception(&self, current_throwable: &WrappedThrowable, out: &mut String) {
        let Some(the_cause) = current_throwable.cause.as_deref() else {
            return;
        };

        let default_message = the_cause.class_name.clone();
        let message = the_cause.message.clone().unwrap_or(default_message);
        out.push_str("\nCaused By:\n");
        out.push('\t');
        out.push_str(&message);
        out.push('\n');

        let cause_by_trace = self.filter_trace_for_thread(&the_cause.stack_trace);
        Self::print_trace(&cause_by_trace, out);

        self.add_cause_exception(the_cause, out);
    }

    fn generate_message(&self) -> String {
        let message = self.t.message.as_deref().unwrap_or("");
        let message_with_name =
            format!("{}: {message} (thread '{}')", self.t.class_name, self.thread_name);

        match &self.user_message {
            Some(user_message) => format!("{user_message}\n\n{message_with_name}"),
            None => message_with_name,
        }
    }

    /// Port of the private instance method `filterTrace(StackTraceElement[])` -- distinct from
    /// [`crate::generic::test::test_thread::filter_trace`] (a same-named but unrelated static
    /// method on `TestThread`), despite the coincidental name collision in Java too.
    fn filter_trace_for_thread(&self, trace: &[StackFrame]) -> Vec<StackFrame> {
        if self.thread_name.contains("AWT-EventQueue") {
            filter_stack_trace(trace, SWING_STACK_ELEMENT_PATTERNS)
        } else {
            filter_stack_trace(trace, GENERAL_USELESS_STACK_ELEMENT_PATTERNS)
        }
    }

    fn print_trace(trace: &[StackFrame], out: &mut String) {
        for element in trace {
            out.push_str("\tat ");
            out.push_str(&element.to_string());
            out.push('\n');
        }
    }
}

impl std::fmt::Display for TestReportingException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_message())
    }
}

impl std::error::Error for TestReportingException {}

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
    fn get_message_combines_the_log_pointer_class_name_message_and_thread_name() {
        let e = TestReportingException::new(
            "AWT-EventQueue-0",
            throwable("NullPointerException", Some("boom")),
        );
        assert_eq!(
            e.get_message(),
            "(See log for more stack trace info)\n\nNullPointerException: boom (thread 'AWT-EventQueue-0')"
        );
    }

    #[test]
    fn get_message_prepends_the_user_message_when_present() {
        let mut e =
            TestReportingException::new("AWT-EventQueue-0", throwable("RuntimeException", None));
        e.user_message = Some("custom context".to_string());
        assert_eq!(
            e.get_message(),
            "(See log for more stack trace info)\n\ncustom context\n\nRuntimeException:  (thread 'AWT-EventQueue-0')"
        );
    }

    #[test]
    fn display_matches_get_message() {
        let e =
            TestReportingException::new("AWT-EventQueue-0", throwable("RuntimeException", Some("x")));
        assert_eq!(e.to_string(), e.get_message());
    }

    #[test]
    fn filter_trace_for_thread_uses_swing_patterns_only_for_an_awt_event_queue_thread_name() {
        let trace = vec![
            frame("java.awt.WaitDispatchSupport", "run"),
            frame("java.awt.event.InvocationEvent", "dispatch"),
            frame("com.example.MyCode", "doWork"),
        ];

        let awt = TestReportingException::new(
            "AWT-EventQueue-0",
            throwable("X", None).with_stack_trace(trace.clone()),
        );
        // Both the general-useless and the AWT-event pattern are stripped for an AWT thread name.
        assert_eq!(awt.get_stack_trace(), vec![frame("com.example.MyCode", "doWork")]);

        let other = TestReportingException::new("Test-Thread-0", throwable("X", None).with_stack_trace(trace));
        // Off the AWT thread, only the general-useless pattern is stripped; the AWT-event frame
        // survives.
        assert_eq!(
            other.get_stack_trace(),
            vec![frame("java.awt.event.InvocationEvent", "dispatch"), frame("com.example.MyCode", "doWork")]
        );
    }

    #[test]
    fn build_stack_trace_string_includes_message_and_filtered_frames() {
        let t = throwable("RuntimeException", Some("kaboom")).with_stack_trace(vec![
            frame("java.awt.WaitDispatchSupport", "run"),
            frame("com.example.MyCode", "doWork"),
        ]);
        let e = TestReportingException::new("AWT-EventQueue-0", t);

        let mut buf = Vec::new();
        e.print_stack_trace(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.starts_with("RuntimeException: kaboom (thread 'AWT-EventQueue-0')\n"));
        assert!(output.contains("\tat com.example.MyCode.doWork\n"));
        // The filtered-out frame never appears.
        assert!(!output.contains("WaitDispatchSupport"));
    }

    #[test]
    fn build_stack_trace_string_includes_the_test_thread_stack_when_present() {
        let e = TestReportingException::with_test_thread_trace(
            "AWT-EventQueue-0",
            throwable("X", None),
            Some(vec![frame("com.example.TestClass", "testSomething")]),
        );
        let output = e.build_stack_trace_string();
        assert!(output.contains("\nTest thread stack at that time:\n"));
        assert!(output.contains("\tat com.example.TestClass.testSomething\n"));
    }

    #[test]
    fn build_stack_trace_string_omits_the_test_thread_stack_section_when_absent() {
        let e = TestReportingException::new("AWT-EventQueue-0", throwable("X", None));
        assert!(!e.build_stack_trace_string().contains("Test thread stack at that time"));
    }

    #[test]
    fn cause_chain_is_rendered_recursively_with_a_class_name_fallback_message() {
        let root_cause = throwable("IllegalStateException", None); // no message -> falls back to class name
        let middle_cause = throwable("IOException", Some("disk full")).with_cause(root_cause);
        let t = throwable("RuntimeException", Some("top")).with_cause(middle_cause);
        let e = TestReportingException::new("AWT-EventQueue-0", t);

        let output = e.build_stack_trace_string();
        // Both levels of "Caused By:" appear, in order, and the messageless root cause falls back
        // to its class name (Java: `defaultMessage = theCause.getClass().getSimpleName()`).
        let first = output.find("Caused By:\n\tdisk full").expect("expected the IOException cause");
        let second = output
            .find("Caused By:\n\tIllegalStateException")
            .expect("expected the IllegalStateException cause with its class-name fallback");
        assert!(first < second);
    }

    #[test]
    fn get_swing_thread_trace_string_formats_class_and_message_then_filtered_frames() {
        let t = throwable("NullPointerException", Some("npe")).with_stack_trace(vec![
            frame("java.security.AccessController", "doPrivileged"),
            frame("com.example.MyCode", "doWork"),
        ]);
        let s = TestReportingException::get_swing_thread_trace_string(&t);
        assert!(s.starts_with("NullPointerException: npe\n"));
        assert!(s.contains("\tat com.example.MyCode.doWork\n"));
        assert!(!s.contains("AccessController"));
    }

    #[test]
    fn get_swing_thread_trace_string_omits_the_colon_when_there_is_no_message() {
        let t = throwable("RuntimeException", None);
        let s = TestReportingException::get_swing_thread_trace_string(&t);
        assert!(s.starts_with("RuntimeException\n"));
    }

    #[test]
    fn from_swing_thread_off_the_test_thread_leaves_the_test_thread_trace_none_and_stack_unfiltered() {
        // A plain `#[test]` thread is not named with the `Test-` prefix `is_test_thread` checks
        // for, so this exercises the "off the test thread" branch without any special setup.
        assert!(!is_test_thread());

        let t = throwable("RuntimeException", Some("x"))
            .with_stack_trace(vec![frame("java.awt.WaitDispatchSupport", "run")]);
        let current_trace = vec![frame(SELF_CLASS_NAME, "from_swing_thread")];
        let e = TestReportingException::from_swing_thread(None, t, &current_trace);

        assert!(e.test_thread_trace.is_none());
        // `t`'s own stack trace is untouched (still contains the frame that filtering would have
        // removed), since the filtering only happens when on the test thread.
        assert_eq!(e.t.stack_trace, vec![frame("java.awt.WaitDispatchSupport", "run")]);
    }

    #[test]
    fn from_swing_thread_on_the_test_thread_computes_and_filters_the_test_thread_trace() {
        let current_trace = vec![
            frame(SELF_CLASS_NAME, "from_swing_thread"),
            frame("com.example.MyTest", "testSomething"),
        ];
        let t = throwable("RuntimeException", Some("x"))
            .with_stack_trace(vec![frame("java.awt.WaitDispatchSupport", "run"), frame("com.example.Awt", "go")]);

        let result = std::thread::Builder::new()
            .name("Test-worker".to_string())
            .spawn(move || TestReportingException::from_swing_thread(Some("ctx".to_string()), t, &current_trace))
            .unwrap()
            .join()
            .unwrap();

        // `current_trace` is stripped down to what comes after the SELF_CLASS_NAME frame, then
        // run through `TestThread::filter_trace` (which, per that module's own patterns, doesn't
        // touch a plain `com.example.*` frame).
        assert_eq!(
            result.test_thread_trace,
            Some(vec![frame("com.example.MyTest", "testSomething")])
        );
        // `t`'s own stack trace was filtered in place too (though by `TestThread::filter_trace`'s
        // patterns, not this exception's own `filter_trace_for_thread` -- `WaitDispatchSupport`
        // survives here since it isn't one of `TestThread::filter_trace`'s patterns).
        assert_eq!(
            result.t.stack_trace,
            vec![frame("java.awt.WaitDispatchSupport", "run"), frame("com.example.Awt", "go")]
        );
        assert_eq!(result.user_message, Some("ctx".to_string()));
        assert_eq!(result.thread_name, "AWT-EventQueue-0");
    }
}
