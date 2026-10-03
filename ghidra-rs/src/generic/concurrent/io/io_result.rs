//! Port of `generic.concurrent.io.IOResult`.
//!
//! A `Runnable` that consumes all text output from an [`std::io::Read`] tied to an external
//! process (stdout/stderr). The output can be inspected line-by-line by providing a consumer
//! closure, or the entire output can be inspected afterward via
//! [`get_output`](IOResult::get_output)/[`get_output_as_string`](IOResult::get_output_as_string).
//!
//! # `Throwable inception` becomes a pre-rendered `String`
//!
//! Java's `inception` field is a `Throwable` captured (via `ReflectionUtilities`) purely so, on a
//! later read failure, its stack trace can be logged as "where this `IOResult` was created" --
//! it is never inspected structurally. This crate's port of `ReflectionUtilities` operates on an
//! explicit `&[StackFrame]` (see `crate::util::util::reflection::reflection_utilities`), not a
//! live, walkable JVM call stack, so there is nothing to auto-capture equivalent to Java's
//! `new Throwable()` at just any call site in general. Rust *does* have a real, portable
//! call-stack capture mechanism in [`std::backtrace::Backtrace`], though, and
//! [`IOResult::new`] (mirroring the one-arg `IOResult(InputStream)`) uses
//! `Backtrace::force_capture()` to genuinely capture the current stack, rendered to a `String` --
//! the closest faithful equivalent available. The other constructors accept an already-rendered
//! `inception: impl Into<String>` directly, mirroring Java's `Throwable inception` parameter
//! (whose only use is also just being rendered to a string on error).
//!
//! # Preserved quirk: a null consumer with `retainLines = false` throws (and is silently logged)
//!
//! Java's fully-general constructor lets a caller pass `lineConsumer = null` together with
//! `retainLines = false`; `run()`'s `consumer.accept(line)` then throws a
//! `NullPointerException` on the very first line read, which `run()`'s own
//! `catch (Exception e)` catches and logs via `Msg.debug(...)` -- the read loop then simply stops,
//! with no panic escaping `run()` and (since `retainLines` is `false`) no lines recorded either.
//! This port reproduces that exact externally-observable behavior (see
//! [`run_logs_and_stops_immediately_when_no_consumer_and_lines_not_retained`] below) via a small
//! [`NullConsumerError`] stand-in for the `NullPointerException`, rather than "fixing" the
//! combination to silently do nothing more gracefully.
//!
//! # `getOutput()` returns a snapshot, not Java's live list reference
//!
//! Java's `getOutput()` returns the actual backing `List<String>` (a caller could, in principle,
//! mutate it further). [`IOResult::get_output`] instead returns a cloned `Vec<String>` snapshot,
//! since the backing storage is behind a [`Mutex`] here (needed so [`IOResult::run`] can mutate it
//! from `&self`, matching this crate's `Job`/`JobBase` convention for `Runnable`-shaped types run
//! on a background thread while polled concurrently).

use std::io::{BufRead, BufReader, Read};
use std::sync::Mutex;

use crate::util::msg::Msg;

/// Port of `IOResult.THREAD_POOL_NAME`.
pub const THREAD_POOL_NAME: &str = "I/O Thread Pool";

/// Stands in for the `NullPointerException` Java's `consumer.accept(line)` throws when `consumer`
/// is `null`. See the module docs on the quirk this reproduces.
#[derive(Debug)]
struct NullConsumerError;

impl std::fmt::Display for NullConsumerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NullPointerException: consumer is null")
    }
}

impl std::error::Error for NullConsumerError {}

/// Strips a trailing `\n` or `\r\n`, matching `BufferedReader.readLine()`'s line-terminator
/// stripping (Rust's [`BufRead::read_line`] keeps the terminator in the returned buffer).
fn strip_line_ending(line: &str) -> String {
    let without_lf = line.strip_suffix('\n').unwrap_or(line);
    let without_crlf = without_lf.strip_suffix('\r').unwrap_or(without_lf);
    without_crlf.to_string()
}

/// A `Runnable` that consumes all text output from an [`Read`] tied to an external process
/// (stdout/stderr).
///
/// Port of `generic.concurrent.io.IOResult`.
pub struct IOResult {
    output_lines: Mutex<Vec<String>>,
    retain_lines: bool,
    command_output: Mutex<Box<dyn BufRead + Send>>,
    inception: String,
    consumer: Option<Mutex<Box<dyn FnMut(String) + Send>>>,
}

impl IOResult {
    /// Creates an `IOResult` that consumes the specified input, saving it as text lines, with an
    /// automatically-captured "created from" backtrace.
    ///
    /// Port of `IOResult(InputStream)`. See the module docs on why a genuine
    /// [`std::backtrace::Backtrace`] capture is used in place of Java's
    /// `ReflectionUtilities.createThrowableWithStackOlderThan(IOResult.class)`.
    pub fn from_input(input: Box<dyn Read + Send>) -> Self {
        let inception = std::backtrace::Backtrace::force_capture().to_string();
        Self::full(input, None, true, inception)
    }

    /// Creates an `IOResult` that consumes the specified input, saving it as text lines.
    ///
    /// Port of `IOResult(InputStream, Throwable inception)`.
    pub fn with_inception(input: Box<dyn Read + Send>, inception: impl Into<String>) -> Self {
        Self::full(input, None, true, inception.into())
    }

    /// Creates an `IOResult` that consumes the specified input, handing each line to
    /// `line_consumer`.
    ///
    /// Port of `IOResult(InputStream, Consumer<String>, Throwable inception)`.
    pub fn with_consumer(
        input: Box<dyn Read + Send>,
        line_consumer: Box<dyn FnMut(String) + Send>,
        inception: impl Into<String>,
    ) -> Self {
        Self::full(input, Some(line_consumer), false, inception.into())
    }

    /// Creates an `IOResult` that consumes the specified input, handing each line to
    /// `line_consumer` (if any) and optionally storing each line for later retrieval.
    ///
    /// Port of `IOResult(InputStream, Consumer<String>, boolean, Throwable)`, the constructor
    /// every other constructor delegates to.
    pub fn new(
        input: Box<dyn Read + Send>,
        line_consumer: Option<Box<dyn FnMut(String) + Send>>,
        retain_lines: bool,
        inception: impl Into<String>,
    ) -> Self {
        Self::full(input, line_consumer, retain_lines, inception.into())
    }

    fn full(
        input: Box<dyn Read + Send>,
        line_consumer: Option<Box<dyn FnMut(String) + Send>>,
        retain_lines: bool,
        inception: String,
    ) -> Self {
        IOResult {
            output_lines: Mutex::new(Vec::new()),
            retain_lines,
            command_output: Mutex::new(Box::new(BufReader::new(input))),
            inception,
            consumer: line_consumer.map(Mutex::new),
        }
    }

    /// Port of `getOutputAsString()`.
    pub fn get_output_as_string(&self) -> String {
        let mut buffy = String::new();
        for line in self.output_lines.lock().unwrap().iter() {
            buffy.push_str(line);
            buffy.push('\n');
        }
        buffy
    }

    /// Port of `getOutput()`. See the module docs on why this is a snapshot rather than a live
    /// reference.
    pub fn get_output(&self) -> Vec<String> {
        self.output_lines.lock().unwrap().clone()
    }

    /// Port of `run()`. See the module docs for the preserved null-consumer quirk.
    pub fn run(&self) {
        let mut reader = self.command_output.lock().unwrap();
        let mut raw_line = String::new();
        loop {
            raw_line.clear();
            match reader.read_line(&mut raw_line) {
                Ok(0) => break,
                Ok(_) => {
                    let line = strip_line_ending(&raw_line);
                    if self.consumer.is_none() && !self.retain_lines {
                        self.log_exception(&NullConsumerError);
                        return;
                    }
                    if let Some(consumer) = &self.consumer {
                        (*consumer.lock().unwrap())(line.clone());
                    }
                    if self.retain_lines {
                        self.output_lines.lock().unwrap().push(line);
                    }
                }
                Err(e) => {
                    self.log_exception(&e);
                    return;
                }
            }
        }
    }

    /// Port of the `catch (Exception e)` block's body: `Msg.debug(IOResult.class, "Exception
    /// reading output from process.  Created from:\n" + inceptionString, e)`.
    fn log_exception(&self, error: &dyn std::error::Error) {
        let message =
            format!("Exception reading output from process.  Created from:\n{}", self.inception);
        Msg::debug_with_error("IOResult", &message, error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex};

    fn input(text: &str) -> Box<dyn Read + Send> {
        Box::new(std::io::Cursor::new(text.as_bytes().to_vec()))
    }

    #[test]
    fn from_input_retains_lines_by_default() {
        let result = IOResult::from_input(input("one\ntwo\nthree\n"));
        result.run();
        assert_eq!(result.get_output(), vec!["one", "two", "three"]);
    }

    #[test]
    fn get_output_as_string_joins_with_trailing_newlines() {
        let result = IOResult::from_input(input("a\nb\n"));
        result.run();
        assert_eq!(result.get_output_as_string(), "a\nb\n");
    }

    #[test]
    fn handles_a_final_line_without_a_trailing_newline() {
        let result = IOResult::from_input(input("a\nb"));
        result.run();
        assert_eq!(result.get_output(), vec!["a", "b"]);
    }

    #[test]
    fn handles_crlf_line_endings() {
        let result = IOResult::from_input(input("a\r\nb\r\n"));
        result.run();
        assert_eq!(result.get_output(), vec!["a", "b"]);
    }

    #[test]
    fn empty_input_produces_no_lines() {
        let result = IOResult::from_input(input(""));
        result.run();
        assert!(result.get_output().is_empty());
        assert_eq!(result.get_output_as_string(), "");
    }

    #[test]
    fn with_consumer_invokes_consumer_and_does_not_retain_lines() {
        let seen: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let seen_clone = seen.clone();

        let result = IOResult::with_consumer(
            input("x\ny\n"),
            Box::new(move |line| seen_clone.lock().unwrap().push(line)),
            "test inception",
        );
        result.run();

        assert_eq!(*seen.lock().unwrap(), vec!["x".to_string(), "y".to_string()]);
        // retainLines was false for this constructor, so getOutput() stays empty.
        assert!(result.get_output().is_empty());
    }

    #[test]
    fn new_with_consumer_and_retain_lines_does_both() {
        let seen: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let seen_clone = seen.clone();

        let result = IOResult::new(
            input("x\ny\n"),
            Some(Box::new(move |line| seen_clone.lock().unwrap().push(line))),
            true,
            "test inception",
        );
        result.run();

        assert_eq!(*seen.lock().unwrap(), vec!["x".to_string(), "y".to_string()]);
        assert_eq!(result.get_output(), vec!["x".to_string(), "y".to_string()]);
    }

    #[test]
    fn run_logs_and_stops_immediately_when_no_consumer_and_lines_not_retained() {
        // Faithful reproduction of the Java NullPointerException quirk described in the module
        // docs: no consumer AND retainLines == false means the very first line "fails" (logged,
        // not panicking) and nothing is ever recorded.
        let result = IOResult::new(input("only line\nmore\n"), None, false, "test inception");
        result.run();
        assert!(result.get_output().is_empty());
    }

    #[test]
    fn with_inception_accepts_a_pre_rendered_string() {
        let result = IOResult::with_inception(input("hello\n"), "created at some call site");
        result.run();
        assert_eq!(result.get_output(), vec!["hello"]);
    }

    #[test]
    fn thread_pool_name_matches_java_constant() {
        assert_eq!(THREAD_POOL_NAME, "I/O Thread Pool");
    }
}
