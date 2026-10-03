//! Port of `log.Log4jDevelopmentPatternConverter`.
//!
//! Java's version is a log4j 2.x `LogEventPatternConverter` plugin (`@Plugin(name =
//! "DevPatternConverter")`, `@ConverterKeys({ "hl", "hyperlinker" })`) that, when referenced from
//! a `PatternLayout` (e.g. `%-5p %m %hl %n`), appends a `" (File.java:42)"` hyperlink naming the
//! first call site outside the logging framework itself and Ghidra's own `Msg` wrapper. This
//! crate has no log4j 2.x-equivalent logging pipeline -- no `LogEvent`, `PatternLayout`, or
//! `@Plugin`/`@ConverterKeys` machinery -- so [`Log4jDevelopmentPatternConverter::format`] takes
//! a `StringBuilder`-equivalent `&mut String` directly rather than being wired into a converter
//! registry.
//!
//! More fundamentally: Java derives everything from `new Throwable().getStackTrace()`, captured
//! fresh every time `format` runs. Stable Rust has no API that turns a captured backtrace into
//! structured per-frame class/method/file/line data the way `Throwable.getStackTrace()` does --
//! the same gap documented on
//! [`crate::util::util::reflection::reflection_utilities`], whose `movePastStackTracePattern`
//! port this file's own frame-filtering logic mirrors. So, like that module, every function here
//! takes the stack trace as an explicit `&[LogStackFrame]` parameter instead of capturing one
//! internally.

/// Stands in for Java's `StackTraceElement`.
///
/// Not [`crate::util::util::reflection::reflection_utilities::StackFrame`] (this crate's other,
/// already-ported `StackTraceElement` analogue) because that type carries only
/// `class_name`/`method_name` -- none of its existing callers needed source-location data, only
/// class/method names for filtering. [`Log4jDevelopmentPatternConverter::build_file_info`] needs
/// `getFileName()`/`getLineNumber()` too, so this is a small local frame type with those two
/// extra fields rather than a widening of the shared one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogStackFrame {
    pub class_name: String,
    pub method_name: String,
    pub file_name: String,
    pub line_number: i32,
}

impl LogStackFrame {
    pub fn new(
        class_name: impl Into<String>,
        method_name: impl Into<String>,
        file_name: impl Into<String>,
        line_number: i32,
    ) -> Self {
        Self {
            class_name: class_name.into(),
            method_name: method_name.into(),
            file_name: file_name.into(),
            line_number,
        }
    }

    /// `StackTraceElement.toString()`'s format (`"{class}.{method}({file}:{line})"`), which is
    /// what Java's `String.indexOf`/`String.contains` pattern matching throughout this class
    /// actually searches against (via the printed stack trace text).
    fn to_trace_string(&self) -> String {
        format!("{}.{}({}:{})", self.class_name, self.method_name, self.file_name, self.line_number)
    }
}

// this allows us to take advantage of refactoring (well, it would in Java -- here it's just a
// literal, since there's no `Msg.class.getName()` to reflect on).
const TOOL_MESSAGE_SERVICE_CLASSNAME: &str = "ghidra.util.Msg";

/// Port of `Log4jDevelopmentPatternConverter.TOOL_MESSAGE_SERVICE_FILENAME`. Declared in Java
/// but never actually referenced by any method there either -- a genuinely dead field, preserved
/// here rather than dropped since faithfulness to the original (including its unused leftovers)
/// is the point.
#[allow(dead_code)]
const TOOL_MESSAGE_SERVICE_FILENAME: &str = "Msg.java";

const LOGGER_PACKAGE: &str = ".logging.";
const PRINT_STACK_TRACE_METHOD_NAME: &str = "printStackTrace";

/// Port of `Log4jDevelopmentPatternConverter.KNOWN_IGNORE_METHODS`' method names (the
/// `".methodName("` search pattern each one implies is built on demand in
/// [`get_highest_level_method_name_to_ignore`], mirroring `MethodPattern`'s own constructor).
const KNOWN_IGNORE_METHOD_NAMES: &[&str] = &[
    // logging system
    "trace", "debug", "info", "warn", "error",
    // some API log utility method names
    "log",
    // scripting
    "println", "printerr", "printf",
];

/// Port of `log.Log4jDevelopmentPatternConverter`.
///
/// See the module doc for why [`Self::format`] takes an explicit stack trace instead of
/// capturing one, and why this isn't wired into an actual log4j-style converter registry.
pub struct Log4jDevelopmentPatternConverter {
    name: String,
    style: String,
}

impl Log4jDevelopmentPatternConverter {
    /// `Log4jDevelopmentPatternConverter(String name, String style)`. Java marks this
    /// constructor `protected`, only reachable through [`Self::new_instance`]; both are exposed
    /// here since Rust has no equivalent access-control story for "log4j plugin machinery calls
    /// this, nothing else should."
    pub fn new(name: impl Into<String>, style: impl Into<String>) -> Self {
        Self { name: name.into(), style: style.into() }
    }

    /// `Log4jDevelopmentPatternConverter.newInstance(String[])`. `options` is unused, matching
    /// Java (the parameter exists only to satisfy log4j's plugin-factory calling convention).
    pub fn new_instance(_options: &[String]) -> Self {
        Self::new("hyperlinker", "hyperlinker")
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn style(&self) -> &str {
        &self.style
    }

    /// `Log4jDevelopmentPatternConverter.format(LogEvent, StringBuilder)`. Java's `event`
    /// parameter is entirely unused -- the caller information comes from a freshly-captured
    /// stack trace, not from the event -- so it has no Rust-side equivalent here at all; `trace`
    /// stands in for that freshly-captured trace (see the module doc).
    pub fn format(trace: &[LogStackFrame], to_append_to: &mut String) {
        to_append_to.push_str(&Self::get_caller_information(trace));
    }

    /// `Log4jDevelopmentPatternConverter.getCallerInformation()`.
    fn get_caller_information(trace: &[LogStackFrame]) -> String {
        let filtered = move_past_stack_trace_pattern(trace, LOGGER_PACKAGE);

        // Stands in for `throwable.printStackTrace(printWriter)` writing `filtered` out and
        // `stringWriter.toString()` reading it back: Java only ever uses that text for substring
        // searches (`indexOf`) against each frame's own `toString()` rendering, so the
        // concatenation below is behaviorally equivalent for that purpose without needing an
        // actual `Throwable`/`PrintWriter` pair.
        let stack_string: String =
            filtered.iter().map(|f| format!("\tat {}\n", f.to_trace_string())).collect();

        // Don't print out locations for stack traces, as they already have that info.
        if stack_string.contains(PRINT_STACK_TRACE_METHOD_NAME) {
            return String::new();
        }

        let cutoff_name = get_highest_level_method_name_to_ignore(&stack_string);
        get_log_message_caller_information(&filtered, &cutoff_name)
    }
}

/// Port of `ReflectionUtilities.movePastStackTracePattern(StackTraceElement[], String)`,
/// specialized to [`LogStackFrame`] rather than the shared
/// [`StackFrame`](crate::util::util::reflection::reflection_utilities::StackFrame) (which lacks
/// the file/line data [`LogStackFrame::to_trace_string`] needs to match Java's real
/// `StackTraceElement.toString()`-based search).
///
/// Reproduces a real quirk of the Java original: if every frame in `trace` matches `pattern` --
/// i.e. the loop never observes a *non*-matching frame after a matching one -- `desiredStartIndex`
/// is never updated away from its initial `0`, so the *entire* original trace is returned
/// unchanged rather than being truncated (or emptied).
fn move_past_stack_trace_pattern(trace: &[LogStackFrame], pattern: &str) -> Vec<LogStackFrame> {
    let mut found_it = false;
    let mut desired_start_index = 0usize;

    for (i, frame) in trace.iter().enumerate() {
        let matches = frame.to_trace_string().contains(pattern);
        if found_it && !matches {
            desired_start_index = i;
            break;
        }
        found_it |= matches;
    }

    if !found_it {
        return trace.to_vec();
    }

    trace[desired_start_index..].to_vec()
}

/// Port of `Log4jDevelopmentPatternConverter.getHighestLevelMethodNameToIgnore(String)`.
fn get_highest_level_method_name_to_ignore(stack_string: &str) -> String {
    let mut cutoff_name = String::new();
    let mut best_index: i64 = -1;

    // 1) see if we are using a system messaging service
    if let Some(index) = stack_string.find(TOOL_MESSAGE_SERVICE_CLASSNAME) {
        best_index = index as i64;
        cutoff_name = TOOL_MESSAGE_SERVICE_CLASSNAME.to_string();
    }

    // 2) ignore any homegrown printing methods (like those found in scripting)
    for method_name in KNOWN_IGNORE_METHOD_NAMES {
        let pattern = format!(".{method_name}(");
        let index = match stack_string.find(&pattern) {
            Some(index) => index as i64,
            None => continue,
        };
        if index < best_index {
            continue;
        }
        best_index = index;
        cutoff_name = method_name.to_string();
    }

    cutoff_name
}

/// Port of `Log4jDevelopmentPatternConverter.getLogMessageCallerInformation(StackTraceElement[],
/// String)`.
fn get_log_message_caller_information(trace: &[LogStackFrame], cutoff_name: &str) -> String {
    let mut last_index_of_cutoff: i64 = -1;

    for (i, frame) in trace.iter().enumerate() {
        // assumption: we have to walk the list of elements until we get past all calls to the
        // logging API (and maybe a Ghidra API call)
        if cutoff_name == frame.class_name || cutoff_name == frame.method_name {
            last_index_of_cutoff = i as i64;
        }
    }

    // we want the first filename after the cutoff; we may not have a cutoff
    let next = last_index_of_cutoff + 1;

    if next < 0 || next as usize >= trace.len() {
        return String::new(); // shouldn't happen
    }

    build_file_info(&trace[next as usize])
}

/// Port of `Log4jDevelopmentPatternConverter.buildFileInfo(StackTraceElement)`. Java accumulates
/// this through a shared, `synchronized`-guarded instance-field `StringBuilder` to avoid
/// reallocating one per call; that's a thread-safety/allocation micro-optimization with no
/// observable effect on the resulting string, so it's simplified here to a plain owned `String`.
fn build_file_info(frame: &LogStackFrame) -> String {
    format!(" ({}:{})", frame.file_name, frame.line_number)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(class_name: &str, method_name: &str, file_name: &str, line: i32) -> LogStackFrame {
        LogStackFrame::new(class_name, method_name, file_name, line)
    }

    #[test]
    fn new_instance_matches_java_hardcoded_name_and_style() {
        let converter = Log4jDevelopmentPatternConverter::new_instance(&[]);
        assert_eq!(converter.name(), "hyperlinker");
        assert_eq!(converter.style(), "hyperlinker");
    }

    #[test]
    fn format_finds_first_caller_past_msg_class() {
        // Mirrors a call chain: application code -> Ghidra's Msg -> log4j core -> appender.
        let trace = vec![
            frame("org.apache.logging.log4j.core.appender.ConsoleAppender", "append", "ConsoleAppender.java", 50),
            frame("org.apache.logging.log4j.core.Logger", "log", "Logger.java", 10),
            frame("ghidra.util.Msg", "info", "Msg.java", 88),
            frame("my.plugin.MyAnalyzer", "analyze", "MyAnalyzer.java", 42),
            frame("my.plugin.Caller", "run", "Caller.java", 7),
        ];

        let mut buf = String::new();
        Log4jDevelopmentPatternConverter::format(&trace, &mut buf);

        // Cutoff is the *last* frame whose class/method equals "ghidra.util.Msg" -- here just the
        // one Msg frame -- so the reported caller is the frame right after it.
        assert_eq!(buf, " (MyAnalyzer.java:42)");
    }

    #[test]
    fn format_returns_empty_string_for_print_stack_trace_calls() {
        let trace = vec![
            frame("some.Logger", "printStackTrace", "Logger.java", 5),
            frame("my.plugin.Caller", "run", "Caller.java", 7),
        ];

        let mut buf = String::new();
        Log4jDevelopmentPatternConverter::format(&trace, &mut buf);

        assert_eq!(buf, "");
    }

    #[test]
    fn format_falls_back_to_known_ignore_method_pattern() {
        // No Msg frame present, so the cutoff comes from KNOWN_IGNORE_METHODS instead --
        // here, a scripting `println` call.
        let trace = vec![
            frame("ghidra.app.script.GhidraScript", "println", "GhidraScript.java", 100),
            frame("my.script.CoolScript", "run", "CoolScript.java", 3),
        ];

        let mut buf = String::new();
        Log4jDevelopmentPatternConverter::format(&trace, &mut buf);

        assert_eq!(buf, " (CoolScript.java:3)");
    }

    #[test]
    fn format_returns_empty_string_when_cutoff_is_the_last_frame() {
        let trace = vec![frame("ghidra.util.Msg", "warn", "Msg.java", 88)];

        let mut buf = String::new();
        Log4jDevelopmentPatternConverter::format(&trace, &mut buf);

        assert_eq!(buf, "");
    }

    #[test]
    fn move_past_stack_trace_pattern_strips_matching_prefix() {
        let trace = vec![
            frame("org.apache.logging.log4j.core.Logger", "log", "Logger.java", 1),
            frame("my.plugin.Caller", "run", "Caller.java", 7),
        ];

        let filtered = move_past_stack_trace_pattern(&trace, LOGGER_PACKAGE);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].class_name, "my.plugin.Caller");
    }

    #[test]
    fn move_past_stack_trace_pattern_returns_full_trace_when_pattern_never_unmatches() {
        // Real quirk of the Java original: every frame matches, so `desiredStartIndex` never
        // moves off its initial 0 and the whole trace comes back unchanged.
        let trace = vec![
            frame("org.apache.logging.log4j.core.Logger", "log", "Logger.java", 1),
            frame("org.apache.logging.log4j.core.Appender", "append", "Appender.java", 2),
        ];

        let filtered = move_past_stack_trace_pattern(&trace, LOGGER_PACKAGE);

        assert_eq!(filtered, trace);
    }

    #[test]
    fn move_past_stack_trace_pattern_returns_original_when_never_matched() {
        let trace = vec![frame("my.plugin.Caller", "run", "Caller.java", 7)];

        let filtered = move_past_stack_trace_pattern(&trace, LOGGER_PACKAGE);

        assert_eq!(filtered, trace);
    }

    #[test]
    fn get_highest_level_method_name_to_ignore_prefers_latest_occurring_pattern() {
        let stack_string = "\tat ghidra.util.Msg.warn(Msg.java:88)\n\tat my.plugin.Foo.println(Foo.java:5)\n";
        assert_eq!(get_highest_level_method_name_to_ignore(stack_string), "println");
    }

    #[test]
    fn get_highest_level_method_name_to_ignore_returns_empty_when_nothing_matches() {
        let stack_string = "\tat my.plugin.Foo.run(Foo.java:5)\n";
        assert_eq!(get_highest_level_method_name_to_ignore(stack_string), "");
    }

    #[test]
    fn build_file_info_matches_java_format() {
        let f = frame("my.plugin.Caller", "run", "Caller.java", 42);
        assert_eq!(build_file_info(&f), " (Caller.java:42)");
    }
}
