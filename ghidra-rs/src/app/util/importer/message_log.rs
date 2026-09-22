//! A simple class to handle logging messages and exceptions.
//!
//! Port of `ghidra.app.util.importer.MessageLog`.

use std::fmt;
use std::sync::Mutex;

use crate::util::msg::Msg;
use crate::util::util::reflection::{stack_trace_to_string, StackFrame};

/// The default number of messages to store before clipping.
///
/// Mirrors `MessageLog.MAX_COUNT`.
const MAX_COUNT: i32 = 500;

/// Returns `true` if `s` is empty or contains only whitespace, matching
/// `org.apache.commons.lang3.StringUtils.isBlank` (Java's version also treats `null` as blank;
/// `&str` can't be null, so that case has no Rust equivalent).
fn is_blank(s: &str) -> bool {
    s.trim().is_empty()
}

/// The mutable state behind [`MessageLog`], kept behind a single [`Mutex`] so every method can
/// take `&self` (see the struct docs for why).
#[derive(Debug, Default)]
struct Inner {
    messages: Vec<String>,
    count: i32,
    status_msg: String,
}

/// A simple class to handle logging messages and exceptions. A maximum message count size
/// constraint can be set to clip messages after a certain number, but still keep incrementing
/// a running total.
///
/// In addition to logging messages, clients can also set a status message. This message may
/// later be used as the primary error message when reporting to the user.
///
/// All mutating methods take `&self`, not `&mut self`: a log is typically threaded through
/// loaders/processors alongside the objects they mutate (see e.g.
/// [`AbstractObjcTypeMetadata`](crate::format::objc::abstract_objc_type_metadata::AbstractObjcTypeMetadata)),
/// so the mutable state lives behind an internal [`Mutex`] rather than forcing every holder to
/// take a unique borrow. This mirrors the convention independently converged on by this crate's
/// other (now-retired) `MessageLog` placeholders.
///
/// Port of `ghidra.app.util.importer.MessageLog`.
#[derive(Debug)]
pub struct MessageLog {
    inner: Mutex<Inner>,
    max_size: i32,
}

impl MessageLog {
    /// Creates a new, empty `MessageLog` with the default maximum message count ([`MAX_COUNT`]).
    ///
    /// Mirrors the field initializers of the (implicit) no-arg Java constructor.
    pub fn new() -> Self {
        Self { inner: Mutex::new(Inner::default()), max_size: MAX_COUNT }
    }

    /// Copies the contents of one message log into this one.
    ///
    /// Mirrors `copyFrom(MessageLog)`.
    pub fn copy_from(&self, log: &MessageLog) {
        let other_messages = log.inner.lock().unwrap().messages.clone();
        for other_message in other_messages {
            self.add(other_message);
        }
    }

    /// Appends the message to the log.
    ///
    /// Mirrors `appendMsg(String)`.
    pub fn append_msg(&self, message: impl Into<String>) {
        self.add(message.into());
    }

    /// Appends the message to the log, prefixed by its originator (`"<originator>> <message>"`),
    /// or bare if there is no originator.
    ///
    /// Mirrors `appendMsg(String, String)`. Java's `originator` parameter is a nullable
    /// `String`; `None` here stands in for that `null` case.
    pub fn append_msg_from(&self, originator: Option<&str>, message: &str) {
        match originator {
            None => self.add(message.to_string()),
            Some(originator) => self.add(format!("{originator}> {message}")),
        }
    }

    /// Appends the message and line number to the log.
    ///
    /// Mirrors `appendMsg(int, String)`.
    pub fn append_msg_at_line(&self, line_num: i32, message: &str) {
        self.add(format!("Line #{line_num} - {message}"));
    }

    /// Appends the exception to the log.
    ///
    /// Mirrors `appendException(Throwable)`, which renders the full stack trace via
    /// `ReflectionUtilities.stackTraceToString(t)`. Rust's `std::error::Error` carries no
    /// captured stack frames, so -- following the established convention of every other caller
    /// of [`stack_trace_to_string`] in this crate (see that function's module docs) -- the trace
    /// is supplied explicitly by the caller rather than captured internally. Callers with no
    /// captured trace on hand (e.g. those migrated off simpler placeholder seams) can pass `&[]`.
    pub fn append_exception(&self, error: &dyn std::error::Error, trace: &[StackFrame]) {
        let as_string = stack_trace_to_string(trace, Some(&error.to_string()));
        self.add(as_string);
    }

    /// Readable method for appending error messages to the log.
    ///
    /// Currently does nothing different than [`MessageLog::append_msg_from`].
    ///
    /// Mirrors the deprecated `error(String, String)`.
    #[deprecated(note = "use append_msg or append_msg_from instead")]
    pub fn error(&self, originator: Option<&str>, message: &str) {
        self.append_msg_from(originator, message);
    }

    /// Returns true if this log has messages.
    ///
    /// Mirrors `hasMessages()`.
    pub fn has_messages(&self) -> bool {
        self.inner.lock().unwrap().count > 0
    }

    /// Clears all messages from this log and resets the count.
    ///
    /// Mirrors `clear()`.
    pub fn clear(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.messages.clear();
        inner.count = 0;
    }

    /// Stores a status message that can be used elsewhere (i.e., populate warning dialogs).
    ///
    /// Mirrors `setStatus(String)`.
    pub fn set_status(&self, status: impl Into<String>) {
        self.inner.lock().unwrap().status_msg = status.into();
    }

    /// Clears the status message.
    ///
    /// Mirrors `clearStatus()`.
    pub fn clear_status(&self) {
        self.inner.lock().unwrap().status_msg.clear();
    }

    /// Returns the stored status message.
    ///
    /// Mirrors `getStatus()`. Returns an owned `String` (rather than `&str`) since the message is
    /// held behind an internal lock that can't be borrowed out past this call.
    pub fn get_status(&self) -> String {
        self.inner.lock().unwrap().status_msg.clone()
    }

    /// Returns every message recorded so far, in append order (irrespective of the `max_size`
    /// clipping applied to [`MessageLog::to_string`]/[`MessageLog::write`]'s rendering).
    ///
    /// Not present on the original Java class; grown in to cover the accessor several of this
    /// crate's now-retired `MessageLog` placeholders offered for tests to assert against.
    pub fn messages(&self) -> Vec<String> {
        self.inner.lock().unwrap().messages.clone()
    }

    /// Writes this log's contents to the application log.
    ///
    /// `owner` is the owning entity whose name will appear in the log message, and
    /// `message_header` is the message header that will appear before the log messages.
    ///
    /// Mirrors `write(Class<?>, String)`. Java's `Class<?> owner` becomes a plain `&str` name
    /// here, matching this crate's established [`Msg::info`] convention of an `originator: &str`.
    pub fn write(&self, owner: &str, message_header: &str) {
        let header = if is_blank(message_header) {
            "Log Messages"
        } else {
            message_header
        };
        Msg::info(owner, &format!("{header}\n{}", self.to_string_with_warning()));
    }

    fn to_string_with_warning(&self) -> String {
        let inner = self.inner.lock().unwrap();
        let mut output = String::new();
        if inner.count > self.max_size {
            output.push_str("There were too many messages to display.\n");
            output.push_str(&format!(
                "{} messages have been truncated.\n",
                inner.count - self.max_size
            ));
            output.push('\n');
        }

        for s in &inner.messages {
            output.push_str(s);
            output.push('\n');
        }
        output
    }

    fn add(&self, msg: String) {
        if is_blank(&msg) {
            return;
        }

        let mut inner = self.inner.lock().unwrap();
        if inner.count < self.max_size {
            inner.messages.push(msg);
        }
        inner.count += 1;
    }
}

impl Default for MessageLog {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MessageLog {
    fn clone(&self) -> Self {
        let inner = self.inner.lock().unwrap();
        MessageLog {
            inner: Mutex::new(Inner {
                messages: inner.messages.clone(),
                count: inner.count,
                status_msg: inner.status_msg.clone(),
            }),
            max_size: self.max_size,
        }
    }
}

impl fmt::Display for MessageLog {
    /// Mirrors `toString()`, which just delegates to the same private `toStringWithWarning()`
    /// helper as [`MessageLog::write`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_with_warning())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_log_has_no_messages() {
        let log = MessageLog::new();
        assert!(!log.has_messages());
        assert_eq!(log.to_string(), "");
    }

    #[test]
    fn append_msg_adds_to_log() {
        let log = MessageLog::new();
        log.append_msg("hello");
        assert!(log.has_messages());
        assert_eq!(log.to_string(), "hello\n");
    }

    #[test]
    fn append_msg_ignores_blank_messages() {
        let log = MessageLog::new();
        log.append_msg("   ");
        log.append_msg("");
        assert!(!log.has_messages());
        assert_eq!(log.to_string(), "");
    }

    #[test]
    fn append_msg_from_with_originator_prefixes_message() {
        let log = MessageLog::new();
        log.append_msg_from(Some("Loader"), "could not parse header");
        assert_eq!(log.to_string(), "Loader> could not parse header\n");
    }

    #[test]
    fn append_msg_from_without_originator_is_bare() {
        let log = MessageLog::new();
        log.append_msg_from(None, "bare message");
        assert_eq!(log.to_string(), "bare message\n");
    }

    #[test]
    fn append_msg_at_line_includes_line_number() {
        let log = MessageLog::new();
        log.append_msg_at_line(42, "unexpected token");
        assert_eq!(log.to_string(), "Line #42 - unexpected token\n");
    }

    #[test]
    fn append_exception_renders_message_and_frames() {
        let log = MessageLog::new();
        let error = std::io::Error::new(std::io::ErrorKind::Other, "boom");
        let trace = vec![StackFrame::new("com.example.Foo", "bar")];
        log.append_exception(&error, &trace);
        let rendered = log.to_string();
        assert!(rendered.contains("boom"));
        assert!(rendered.contains("com.example.Foo.bar"));
    }

    #[allow(deprecated)]
    #[test]
    fn deprecated_error_method_matches_append_msg_from() {
        let log = MessageLog::new();
        log.error(Some("Loader"), "deprecated path");
        assert_eq!(log.to_string(), "Loader> deprecated path\n");
    }

    #[test]
    fn clear_resets_messages_and_count() {
        let log = MessageLog::new();
        log.append_msg("one");
        log.append_msg("two");
        assert!(log.has_messages());
        log.clear();
        assert!(!log.has_messages());
        assert_eq!(log.to_string(), "");
    }

    #[test]
    fn status_message_round_trip() {
        let log = MessageLog::new();
        assert_eq!(log.get_status(), "");
        log.set_status("uh oh");
        assert_eq!(log.get_status(), "uh oh");
        log.clear_status();
        assert_eq!(log.get_status(), "");
    }

    #[test]
    fn copy_from_appends_other_logs_messages() {
        let source = MessageLog::new();
        source.append_msg("first");
        source.append_msg("second");

        let dest = MessageLog::new();
        dest.append_msg("existing");
        dest.copy_from(&source);

        assert_eq!(dest.to_string(), "existing\nfirst\nsecond\n");
    }

    #[test]
    fn messages_beyond_max_size_are_clipped_but_still_counted() {
        let mut log = MessageLog::new();
        log.max_size = 2;
        log.append_msg("one");
        log.append_msg("two");
        log.append_msg("three");

        assert!(log.has_messages());
        let rendered = log.to_string_with_warning();
        assert!(rendered.contains("There were too many messages to display."));
        assert!(rendered.contains("1 messages have been truncated."));
        assert!(rendered.contains("one"));
        assert!(rendered.contains("two"));
        assert!(!rendered.contains("three"));
    }

    #[test]
    fn count_uses_post_increment_semantics_at_the_max_size_boundary() {
        // Matches Java's `if (count++ < maxSize)`: the comparison uses the value of `count`
        // *before* the increment, so exactly `max_size` messages are stored, and the boundary
        // message (the (max_size + 1)-th) is the first one clipped.
        let mut log = MessageLog::new();
        log.max_size = 1;
        log.append_msg("kept");
        log.append_msg("dropped");

        let rendered = log.to_string_with_warning();
        assert!(rendered.contains("kept"));
        assert!(!rendered.contains("dropped"));
        assert!(rendered.contains("1 messages have been truncated."));
    }

    #[test]
    fn write_uses_default_header_when_blank() {
        let log = MessageLog::new();
        // Smoke test: `write` should not panic, and falls back to "Log Messages" when the
        // supplied header is blank. There's no capturing logger wired up here (Msg is a global,
        // shared across the whole test binary), so this only exercises that the call completes.
        log.write("SomeLoader", "   ");
        log.write("SomeLoader", "Custom Header");
    }

    #[test]
    fn messages_returns_recorded_messages_in_order() {
        let log = MessageLog::new();
        log.append_msg("first");
        log.append_msg("second");
        assert_eq!(log.messages(), vec!["first".to_string(), "second".to_string()]);
    }
}
