//! Port of `utilities.util.reflection.ReflectionUtilities`.
//!
//! Java's original is two largely unrelated toolkits bundled into one static-method class:
//!
//! 1. **Stack-trace filtering/formatting** (`createThrowableWithStackOlderThan`,
//!    `filterStackTrace`, `filterJavaThrowable`, `movePastStackTracePattern`,
//!    `stackTraceToString`, `getClassNameOlderThan`, ...). This operates on `StackTraceElement`
//!    purely as name/pattern data -- it's genuinely portable, and is what this module ports, using
//!    [`StackFrame`] (a plain `class_name`/`method_name` pair) as the Rust analogue of
//!    `StackTraceElement`.
//! 2. **`java.lang.reflect` introspection** (`locateFieldObjectOnClass`, `locateMethodObjectOnClass`,
//!    `locateConstructorOnClass`, `locateFieldByTypeOnClass`, `getAllParents`, `getSharedHierarchy`,
//!    `getSharedParents`, `getTypeArguments` and their private helpers). These walk `Class`/`Field`/
//!    `Method`/`Type`/`ParameterizedType` objects -- Rust has no runtime type-introspection API
//!    (no `Class<?>`, no reflected fields/methods/constructors, no generic-type-argument recovery
//!    at runtime), and no crate in this workspace provides one. There is no sane Rust analogue to
//!    adapt these to, so they are not ported; fabricating a fake reflection layer just to have
//!    *something* here would misrepresent what the port actually does.
//!
//! Also not ported: `createStackTraceForAllThreads` (`Thread.getAllStackTraces()` -- Rust has no
//! portable way to enumerate every live thread's call stack from within the process).
//!
//! A further, more fundamental gap in category 1: Java captures the *current* call stack via `new
//! Throwable().getStackTrace()`. Rust's `std::backtrace::Backtrace` can capture a backtrace, but on
//! stable Rust it exposes only a `Display`/`Debug` string, not structured per-frame class/method
//! data -- there is no stable API to turn a captured backtrace into a `&[StackFrame]`. So rather
//! than capturing (and then immediately re-parsing an opaque string), every function below takes
//! its `trace: &[StackFrame]` as a parameter -- the same trace-filtering algorithms Java uses on a
//! `Throwable`'s stack, just supplied by the caller instead of captured internally.
//!
//! Frame ordering throughout matches Java's `StackTraceElement[]`: index `0` is the innermost
//! (most recently entered) frame, and increasing indices move outward toward the program's entry
//! point -- so "older" means "at a higher index".

use crate::util::Msg;

/// The Rust analogue of `StackTraceElement`: a class name and a method name.
///
/// Java's `StackTraceElement` also carries a source file name and line number, which are only
/// ever used through `toString()`; since nothing here needs to render a truly authentic
/// `Class.method(File.java:123)` line, `StackFrame` skips them and renders as `Class.method`
/// (see [`std::fmt::Display`] below).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackFrame {
    pub class_name: String,
    pub method_name: String,
}

impl StackFrame {
    pub fn new(class_name: impl Into<String>, method_name: impl Into<String>) -> Self {
        Self {
            class_name: class_name.into(),
            method_name: method_name.into(),
        }
    }

    fn class_and_method(&self) -> String {
        format!("{} {}", self.class_name, self.method_name)
    }
}

impl std::fmt::Display for StackFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.class_name, self.method_name)
    }
}

/// Which part of a [`StackFrame`] a pattern is matched against, and whether the match is an
/// exact-equality or substring ("contains") check.
///
/// Port of the private nested class `ReflectionUtilities.StackElementMatcher` (and its nested
/// `Match`/`Content` enums, collapsed here into one small enum since Rust doesn't need the
/// indirection Java used to keep `matches`/`convert` as separate `enum`-dispatched methods).
#[derive(Clone, Copy)]
enum StackElementMatcher {
    /// Exact match against the frame's class name. Port of `EXACT_CLASS`.
    ExactClass,
    /// Substring match against `"{class} {method}"`. Port of `CONTAINS_CLASS_OR_METHOD`.
    ContainsClassOrMethod,
    /// Substring match against the frame's full `Display` rendering. Port of `CONTAINS_ANY`.
    ContainsAny,
}

impl StackElementMatcher {
    fn matches(&self, frame: &StackFrame, pattern: &str) -> bool {
        match self {
            StackElementMatcher::ExactClass => frame.class_name == pattern,
            StackElementMatcher::ContainsClassOrMethod => {
                frame.class_and_method().contains(pattern)
            }
            StackElementMatcher::ContainsAny => frame.to_string().contains(pattern),
        }
    }
}

fn matches_any_pattern(frame: &StackFrame, patterns: &[String], matcher: StackElementMatcher) -> bool {
    patterns.iter().any(|pattern| matcher.matches(frame, pattern))
}

/// Marker substituted for `patterns` when the caller passes none, mirroring Java always ignoring
/// `ReflectionUtilities.class.getName()` itself in that case. There being no Rust equivalent of
/// `ReflectionUtilities.class.getName()`, this module's own fully-qualified path stands in for it.
const SELF_MARKER: &str = "ghidra_rs::util::util::reflection::reflection_utilities";

/// Shared algorithm behind [`frames_after_patterns`]/[`frames_after_exact`], returning the suffix
/// of `trace` that comes after the last frame matched by `matcher`/`patterns` -- the part of the
/// stack "older than" (more deeply nested than) every ignored frame.
///
/// Port of the private `createThrowableWithStackOlderThan(List<String>, StackElementMatcher)`,
/// adapted to return the filtered slice directly rather than stuffing it back into a mutated
/// `Throwable`.
///
/// If `patterns` is empty, [`SELF_MARKER`] is used in its place, mirroring Java always adding
/// `ReflectionUtilities.class.getName()` to an empty pattern list.
///
/// Two diagnostic quirks are preserved from Java (as `Msg::error` calls, matching `Msg.error(...)`
/// there) along with their fallback behavior, since a caller triggering either case still gets a
/// (degenerate but non-crashing) result rather than a panic:
/// - If none of `patterns` occur anywhere in `trace`, the *entire* trace is returned unmodified
///   (Java: `lastIgnoreIndex` stays `-1`, so `startIndex = -1 + 1 = 0`).
/// - If the *last* frame in `trace` matches a pattern -- regardless of whether earlier frames also
///   match -- there is nothing left "after" it, so an *empty* trace is returned (Java:
///   `lastIgnoreIndex == trace.length - 1`, so `startIndex = trace.length`). Despite Java's log
///   message text ("Call stack contains only ignored patterns"), this fires whenever the outermost
///   captured frame happens to match, not only when literally every frame matches.
fn frames_after(trace: &[StackFrame], patterns: &[String], matcher: StackElementMatcher) -> Vec<StackFrame> {
    let owned_patterns;
    let patterns: &[String] = if patterns.is_empty() {
        owned_patterns = vec![SELF_MARKER.to_string()];
        &owned_patterns
    } else {
        patterns
    };

    let mut last_ignore_index: Option<usize> = None;
    for (i, frame) in trace.iter().enumerate() {
        if matches_any_pattern(frame, patterns, matcher) {
            last_ignore_index = Some(i);
        } else if last_ignore_index.is_some() {
            break;
        }
    }

    match last_ignore_index {
        None => {
            Msg::error(
                "utilities.util.reflection.ReflectionUtilities",
                &format!(
                    "Change call to ReflectionUtils. Did not find the following patterns in the \
                     call stack: {patterns:?}"
                ),
            );
            trace.to_vec()
        }
        Some(idx) if idx == trace.len() - 1 => {
            Msg::error(
                "utilities.util.reflection.ReflectionUtilities",
                &format!(
                    "Change call to ReflectionUtils. Call stack contains only ignored patterns: \
                     {patterns:?}"
                ),
            );
            Vec::new()
        }
        Some(idx) => trace[idx + 1..].to_vec(),
    }
}

/// Returns the suffix of `trace` that comes after the last frame matching any of `patterns`
/// (substring match against `"{class} {method}"`).
///
/// Port of the public `createThrowableWithStackOlderThan(String...)`. See [`frames_after`] for the
/// shared algorithm and its preserved quirks.
pub fn frames_after_patterns(trace: &[StackFrame], patterns: &[String]) -> Vec<StackFrame> {
    frames_after(trace, patterns, StackElementMatcher::ContainsClassOrMethod)
}

/// Like [`frames_after_patterns`], but matches `class_names` exactly against each frame's class
/// name rather than as substrings against `"{class} {method}"`.
///
/// Port of `createThrowableWithStackOlderThan(Class<?>...)`, with `class_names` standing in for
/// the reflective `Class<?>` array (each entry compared via `getName()` equality in Java).
pub fn frames_after_exact(trace: &[StackFrame], class_names: &[String]) -> Vec<StackFrame> {
    frames_after(trace, class_names, StackElementMatcher::ExactClass)
}

/// Returns the class name of the frame in `trace` that comes right after all frames matching any
/// of `patterns`. Useful for figuring out (given an already-captured trace) who called a
/// particular method.
///
/// Port of `getClassNameOlderThan(String...)`.
pub fn class_name_older_than(trace: &[StackFrame], patterns: &[String]) -> Option<String> {
    frames_after_patterns(trace, patterns)
        .first()
        .map(|f| f.class_name.clone())
}

/// Like [`class_name_older_than`], but matches `class_names` exactly.
///
/// Port of `getClassNameOlderThan(Class<?>...)`.
pub fn class_name_older_than_exact(trace: &[StackFrame], class_names: &[String]) -> Option<String> {
    frames_after_exact(trace, class_names)
        .first()
        .map(|f| f.class_name.clone())
}

/// Finds the first run of frames matching `pattern` (substring match against each frame's full
/// `Display` rendering) and returns the suffix of `trace` starting at the first frame after that
/// run. If no frame matches `pattern` at all, `trace` is returned unmodified.
///
/// Port of `movePastStackTracePattern(StackTraceElement[], String)`.
pub fn move_past_pattern(trace: &[StackFrame], pattern: &str) -> Vec<StackFrame> {
    let mut found_it = false;
    let mut desired_start_index = 0;
    let mut ever_found = false;

    for (i, frame) in trace.iter().enumerate() {
        let matches = frame.to_string().contains(pattern);
        if found_it && !matches {
            desired_start_index = i;
            ever_found = true;
            break;
        }
        found_it |= matches;
    }

    if !ever_found {
        return trace.to_vec();
    }

    trace[desired_start_index..].to_vec()
}

/// Removes every frame in `trace` whose `Display` rendering contains any of `patterns`.
///
/// Port of `filterStackTrace(StackTraceElement[], String...)`.
pub fn filter_stack_trace(trace: &[StackFrame], patterns: &[&str]) -> Vec<StackFrame> {
    let owned: Vec<String> = patterns.iter().map(|p| p.to_string()).collect();
    trace
        .iter()
        .filter(|frame| !matches_any_pattern(frame, &owned, StackElementMatcher::ContainsAny))
        .cloned()
        .collect()
}

const JAVA_AWT_PATTERN: &str = "java.awt";
const JAVA_REFLECT_PATTERN: &str = "java.lang.reflect";
const JDK_INTERNAL_REFLECT_PATTERN: &str = "jdk.internal.reflect";
const SWING_JAVA_PATTERN: &str = "java.swing";
const SWING_JAVAX_PATTERN: &str = "javax.swing";
const SUN_AWT_PATTERN: &str = "sun.awt";
const SUN_REFLECT_PATTERN: &str = "sun.reflect";
const SECURITY_PATTERN: &str = "java.security";
const JUNIT_PATTERN: &str = ".junit";
const MOCKIT_PATTERN: &str = "mockit";

/// Filters `trace` down to frames that don't look like JVM/AWT/Swing/security/test-framework
/// boilerplate, useful for emitting diagnostic stack traces with reduced noise.
///
/// Port of `filterJavaThrowable(Throwable)`. The noise patterns themselves (AWT, Swing, JDK
/// reflection internals, JUnit, Mockit, ...) are inherently JVM-specific; they're kept verbatim
/// (rather than replaced with Rust-flavored equivalents) because [`filter_stack_trace`] -- the
/// actual portable piece of behavior -- is exercised identically either way, and a caller feeding
/// this genuinely JVM-flavored `StackFrame` data (e.g. reconstructed from a Java interop log)
/// still benefits from the same filtering.
pub fn filter_java_noise(trace: &[StackFrame]) -> Vec<StackFrame> {
    filter_stack_trace(
        trace,
        &[
            JAVA_AWT_PATTERN,
            JAVA_REFLECT_PATTERN,
            JDK_INTERNAL_REFLECT_PATTERN,
            SWING_JAVA_PATTERN,
            SWING_JAVAX_PATTERN,
            SECURITY_PATTERN,
            SUN_AWT_PATTERN,
            SUN_REFLECT_PATTERN,
            MOCKIT_PATTERN,
            JUNIT_PATTERN,
        ],
    )
}

/// Renders `trace` (optionally preceded by `message`) the way `Throwable.printStackTrace()` would:
/// the message on its own line, followed by one `\tat Class.method` line per frame.
///
/// Port of `stackTraceToString(String, Throwable)`. Java falls back to `t.getMessage()` when
/// `message` is `null`; since there's no `Throwable` here to carry a message, `message` being
/// `None` here just means "no leading message line" (the closest analogue: `Throwable.getMessage()`
/// itself may return `null`, which Java also renders as no leading line, via the `if
/// (throwableMessage != null)` guard).
pub fn stack_trace_to_string(trace: &[StackFrame], message: Option<&str>) -> String {
    let mut out = String::new();
    if let Some(message) = message {
        out.push_str(message);
        out.push('\n');
    }
    for frame in trace {
        out.push('\t');
        out.push_str("at ");
        out.push_str(&frame.to_string());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(class_name: &str, method_name: &str) -> StackFrame {
        StackFrame::new(class_name, method_name)
    }

    /// A trace shaped like a real capture: index 0 is innermost (inside this module), then the
    /// frame that invoked it (`Helper`), then that frame's caller (`Caller`) -- matching Java's
    /// `StackTraceElement[]` ordering (see the module doc comment).
    fn sample_trace() -> Vec<StackFrame> {
        vec![
            frame(SELF_MARKER, "frames_after_patterns"),
            frame("com.example.Helper", "helperMethod"),
            frame("com.example.Caller", "doWork"),
        ]
    }

    #[test]
    fn frames_after_patterns_returns_suffix_after_last_match() {
        let trace = sample_trace();
        let result = frames_after_patterns(&trace, &["Helper".to_string()]);
        assert_eq!(result, vec![frame("com.example.Caller", "doWork")]);
    }

    #[test]
    fn frames_after_patterns_defaults_to_self_marker_when_empty() {
        let trace = sample_trace();
        let result = frames_after_patterns(&trace, &[]);
        assert_eq!(
            result,
            vec![
                frame("com.example.Helper", "helperMethod"),
                frame("com.example.Caller", "doWork"),
            ]
        );
    }

    #[test]
    fn frames_after_patterns_returns_full_trace_when_pattern_never_matches() {
        // Quirk (preserved from Java): when the pattern is never found, the whole trace comes
        // back unmodified rather than an empty result.
        let trace = sample_trace();
        let result = frames_after_patterns(&trace, &["NeverMatches".to_string()]);
        assert_eq!(result, trace);
    }

    #[test]
    fn frames_after_patterns_returns_empty_when_only_the_outermost_frame_matches() {
        // Quirk (preserved from Java): the "nothing left after this" case triggers whenever the
        // *last* (outermost-captured) frame matches -- not only when every frame matches. Here
        // only `Caller` (the last element) matches; `Helper` does not.
        let trace = vec![
            frame("com.example.Helper", "helperMethod"),
            frame("com.example.Caller", "doWork"),
        ];
        let result = frames_after_patterns(&trace, &["Caller".to_string()]);
        assert!(result.is_empty());
    }

    #[test]
    fn frames_after_exact_matches_full_class_name_only() {
        let trace = vec![
            frame("com.example.Inner", "go"),
            frame("com.example.OuterHelper", "help"),
            frame("com.example.Outer", "run"),
            frame("com.example.Main", "main"),
        ];
        // "com.example.OuterHelper" contains "com.example.Outer" as a substring (so
        // `frames_after_patterns` would treat it as a match), but exact matching must not.
        let result = frames_after_exact(&trace, &["com.example.Outer".to_string()]);
        assert_eq!(result, vec![frame("com.example.Main", "main")]);
    }

    #[test]
    fn class_name_older_than_returns_first_remaining_frames_class() {
        let trace = sample_trace();
        assert_eq!(
            class_name_older_than(&trace, &["Helper".to_string()]),
            Some("com.example.Caller".to_string())
        );
    }

    #[test]
    fn class_name_older_than_is_none_when_result_is_empty() {
        let trace = vec![frame("a.B", "m")];
        assert_eq!(class_name_older_than(&trace, &["a.".to_string()]), None);
    }

    #[test]
    fn move_past_pattern_skips_a_contiguous_run() {
        let trace = vec![
            frame("outer.Caller", "call"),
            frame("noise.A", "x"),
            frame("noise.B", "y"),
            frame("outer.Target", "target"),
        ];
        let result = move_past_pattern(&trace, "noise");
        assert_eq!(result, vec![frame("outer.Target", "target")]);
    }

    #[test]
    fn move_past_pattern_returns_original_when_pattern_absent() {
        let trace = sample_trace();
        assert_eq!(move_past_pattern(&trace, "NOT_PRESENT"), trace);
    }

    #[test]
    fn filter_stack_trace_removes_matching_frames_only() {
        let trace = vec![
            frame("keep.Me", "run"),
            frame("drop.This", "noisy"),
            frame("keep.MeToo", "also_run"),
        ];
        let result = filter_stack_trace(&trace, &["drop."]);
        assert_eq!(
            result,
            vec![frame("keep.Me", "run"), frame("keep.MeToo", "also_run")]
        );
    }

    #[test]
    fn filter_java_noise_removes_awt_and_reflect_frames() {
        let trace = vec![
            frame("java.awt.EventQueue", "dispatchEvent"),
            frame("jdk.internal.reflect.NativeMethodAccessorImpl", "invoke0"),
            frame("com.example.RealCode", "doTheThing"),
        ];
        let result = filter_java_noise(&trace);
        assert_eq!(result, vec![frame("com.example.RealCode", "doTheThing")]);
    }

    #[test]
    fn stack_trace_to_string_includes_message_and_at_lines() {
        let trace = vec![frame("a.B", "m"), frame("c.D", "n")];
        let s = stack_trace_to_string(&trace, Some("boom"));
        assert_eq!(s, "boom\n\tat a.B.m\n\tat c.D.n\n");
    }

    #[test]
    fn stack_trace_to_string_without_message_has_no_leading_line() {
        let trace = vec![frame("a.B", "m")];
        let s = stack_trace_to_string(&trace, None);
        assert_eq!(s, "\tat a.B.m\n");
    }

    #[test]
    fn stack_frame_display_renders_class_dot_method() {
        assert_eq!(frame("a.B", "m").to_string(), "a.B.m");
    }
}
