//! Mirrors `ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseErrorResult`.

use std::collections::BTreeSet;
use std::fmt;

use crate::app::plugin::assembler::sleigh::parse::AssemblyParseResult;

/// The maximum number of suggestions to print when describing this error, e.g., when reported in
/// exception messages.
///
/// Mirrors `AssemblyParseErrorResult.SUGGESTIONS_THRESHOLD`.
const SUGGESTIONS_THRESHOLD: usize = 10;

/// An unsuccessful result from parsing.
///
/// Port of `ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseErrorResult`, a concrete class
/// extending the already-ported [`AssemblyParseResult`] trait -- one of its two concrete
/// subclasses, alongside
/// [`AssemblyParseAcceptResult`](crate::app::plugin::assembler::sleigh::parse::AssemblyParseAcceptResult),
/// that trait's own docs anticipated porting later.
///
/// Java stores `suggestions` as a `Set<String>` with iteration order determined by whichever
/// concrete `Set` implementation the caller supplies to the (still-unported)
/// `AssemblyParseResult.error(String, Set<String>)` factory. This port uses a [`BTreeSet`] to give
/// [`describe_error`](Self::describe_error)'s truncated listing a deterministic, testable order,
/// rather than reproducing a specific Java `Set` implementation's iteration order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssemblyParseErrorResult {
    buffer: String,
    suggestions: BTreeSet<String>,
}

impl AssemblyParseErrorResult {
    /// Construct an error result.
    ///
    /// Mirrors the `protected AssemblyParseErrorResult(String got, Set<String> suggestions)`
    /// constructor, called (in Java) only via `AssemblyParseResult.error(String, Set<String>)`
    /// (not yet ported -- see this struct's own docs).
    pub fn new(got: impl Into<String>, suggestions: BTreeSet<String>) -> Self {
        AssemblyParseErrorResult { buffer: got.into(), suggestions }
    }

    /// Get a description of the error.
    ///
    /// Mirrors `AssemblyParseErrorResult.describeError()`: lists up to
    /// [`SUGGESTIONS_THRESHOLD`] suggestions verbatim, appending `"..."` when there are more.
    pub fn describe_error(&self) -> String {
        let trunc_suggestions: Vec<&str> = if self.suggestions.len() <= SUGGESTIONS_THRESHOLD {
            self.suggestions.iter().map(String::as_str).collect()
        } else {
            let mut v: Vec<&str> =
                self.suggestions.iter().take(SUGGESTIONS_THRESHOLD).map(String::as_str).collect();
            v.push("...");
            v
        };
        // Mirrors Java's implicit string concatenation of a `List<String>`, i.e.
        // `AbstractCollection.toString()`: `[a, b, c]`.
        format!("Syntax Error: Expected [{}]. Got {}", trunc_suggestions.join(", "), self.buffer)
    }

    /// Get a set of suggested tokens that would have allowed parsing to continue.
    ///
    /// Mirrors `AssemblyParseErrorResult.getSuggestions()`, returning
    /// `Collections.unmodifiableSet(suggestions)`.
    pub fn get_suggestions(&self) -> &BTreeSet<String> {
        &self.suggestions
    }

    /// Get the leftover contents of the input buffer when the error occurred.
    ///
    /// Mirrors `AssemblyParseErrorResult.getBuffer()`.
    pub fn get_buffer(&self) -> &str {
        &self.buffer
    }
}

impl fmt::Display for AssemblyParseErrorResult {
    /// Mirrors `AssemblyParseErrorResult.toString()`, which delegates to
    /// [`describe_error`](Self::describe_error).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe_error())
    }
}

impl AssemblyParseResult for AssemblyParseErrorResult {
    /// Mirrors `AssemblyParseErrorResult.isError()`, which always returns `true`.
    fn is_error(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn is_error_is_always_true() {
        let result = AssemblyParseErrorResult::new("xyz", set(&[]));
        assert!(result.is_error());
    }

    #[test]
    fn get_buffer_and_get_suggestions_round_trip() {
        let result = AssemblyParseErrorResult::new("leftover", set(&["a", "b"]));
        assert_eq!(result.get_buffer(), "leftover");
        assert_eq!(result.get_suggestions(), &set(&["a", "b"]));
    }

    #[test]
    fn describe_error_lists_all_suggestions_when_at_or_below_threshold() {
        let result = AssemblyParseErrorResult::new("rest", set(&["ADD", "SUB"]));
        let desc = result.describe_error();
        assert_eq!(desc, "Syntax Error: Expected [ADD, SUB]. Got rest");
    }

    #[test]
    fn describe_error_truncates_beyond_threshold_and_appends_ellipsis() {
        let many: Vec<String> = (0..15).map(|i| format!("TOK{i:02}")).collect();
        let set: BTreeSet<String> = many.iter().cloned().collect();
        let result = AssemblyParseErrorResult::new("rest", set);

        let desc = result.describe_error();
        // Exactly SUGGESTIONS_THRESHOLD real entries plus the "..." marker.
        let inner = desc
            .strip_prefix("Syntax Error: Expected [")
            .and_then(|s| s.strip_suffix("]. Got rest"))
            .expect("format matches");
        let parts: Vec<&str> = inner.split(", ").collect();
        assert_eq!(parts.len(), SUGGESTIONS_THRESHOLD + 1);
        assert_eq!(parts.last(), Some(&"..."));
        // BTreeSet order is lexicographic, so the first ten are TOK00..TOK09.
        assert_eq!(parts[0], "TOK00");
        assert_eq!(parts[9], "TOK09");
    }

    #[test]
    fn to_string_matches_describe_error() {
        let result = AssemblyParseErrorResult::new("q", set(&["a"]));
        assert_eq!(result.to_string(), result.describe_error());
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let result: Box<dyn AssemblyParseResult> =
            Box::new(AssemblyParseErrorResult::new("q", set(&["a"])));
        assert!(result.is_error());
        assert!(result.to_string().starts_with("Syntax Error"));
    }
}
