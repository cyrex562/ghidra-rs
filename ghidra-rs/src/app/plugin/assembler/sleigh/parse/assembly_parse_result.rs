//! Mirrors `ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult`.

use std::cmp::Ordering;

/// A result of parsing a sentence.
///
/// If the sentence was accepted, this yields a parse tree. If not, this describes the error and
/// provides suggestions to correct the error.
///
/// Mirrors `ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseResult`, an abstract class
/// implementing `Comparable<AssemblyParseResult>`. That class was chosen as the cut-point for a
/// dependency cycle running through the parser, grammar, and parse-tree types.
///
/// The static factories `accept(AssemblyParseBranch)` and `error(String, Set<String>)` each
/// construct one of this class's two concrete subclasses -- `AssemblyParseAcceptResult` and
/// `AssemblyParseErrorResult`, respectively. Neither subclass is ported yet, so constructing them
/// is left for their own future ports rather than modeled on this trait, mirroring how
/// [`AssemblyParseBranch`](crate::app::plugin::assembler::sleigh::tree::AssemblyParseBranch)
/// drops the inherited `AssemblyParseTreeNode` surface for the analogous reason: it belongs to
/// another still-unported class, not to the one actually being ported here.
///
/// `isError()` is this class's own abstract method, ported as [`is_error`](Self::is_error).
/// `compareTo` is ported as the default method [`compare_to`](Self::compare_to), mirroring
/// Java's `toString().compareTo(that.toString())` -- which is why this trait requires `Display`
/// as a supertrait bound, the same convention used by
/// [`AssemblySymbol`](crate::app::seam_stubs::AssemblySymbol).
pub trait AssemblyParseResult: std::fmt::Display {
    /// Check if the parse result is successful or an error.
    ///
    /// Mirrors `AssemblyParseResult.isError()`.
    fn is_error(&self) -> bool;

    /// Mirrors `AssemblyParseResult.compareTo(AssemblyParseResult)`.
    fn compare_to(&self, that: &dyn AssemblyParseResult) -> Ordering {
        self.to_string().cmp(&that.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stands in for `AssemblyParseAcceptResult`.
    struct MockAccept(&'static str);

    impl std::fmt::Display for MockAccept {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "tree: {}", self.0)
        }
    }

    impl AssemblyParseResult for MockAccept {
        fn is_error(&self) -> bool {
            false
        }
    }

    /// Stands in for `AssemblyParseErrorResult`.
    struct MockError(&'static str);

    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Error at '{}'", self.0)
        }
    }

    impl AssemblyParseResult for MockError {
        fn is_error(&self) -> bool {
            true
        }
    }

    #[test]
    fn is_error_distinguishes_accept_from_error() {
        assert!(!MockAccept("insn").is_error());
        assert!(MockError("bogus").is_error());
    }

    #[test]
    fn compare_to_orders_by_display_string() {
        let a = MockAccept("aaa");
        let b = MockAccept("bbb");
        assert_eq!(a.compare_to(&b), Ordering::Less);
        assert_eq!(b.compare_to(&a), Ordering::Greater);
        assert_eq!(a.compare_to(&a), Ordering::Equal);
    }

    #[test]
    fn compare_to_works_across_accept_and_error_variants() {
        let accept = MockAccept("x");
        let error = MockError("x");
        assert_eq!(accept.to_string(), "tree: x");
        assert_eq!(error.to_string(), "Error at 'x'");
        assert_eq!(accept.compare_to(&error), Ordering::Greater);
        assert_eq!(error.compare_to(&accept), Ordering::Less);
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let result: Box<dyn AssemblyParseResult> = Box::new(MockError("q"));
        assert!(result.is_error());
        assert_eq!(result.to_string(), "Error at 'q'");
    }
}
