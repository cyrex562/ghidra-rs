/// Controls traversal in a sleigh visitor pattern.
///
/// A `visit()` callback returns one of these variants to control whether traversal
/// continues. `traverse()` methods return a value indicating how traversal terminated.
///
/// Mirrors `ghidra.app.plugin.languages.sleigh.VisitorResults`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum VisitorResult {
    /// Continue traversal as usual.
    ///
    /// From `visit()`: continue traversal. Never returned by `traverse()`.
    Continue = 0,
    /// Traversal finished successfully.
    ///
    /// From `visit()`: terminate traversal with a successful result.
    /// From `traverse()`: traversal terminated successfully (either a `visit()` returned
    /// [`Finished`][Self::Finished], or all calls returned [`Continue`][Self::Continue]).
    Finished = 1,
    /// Traversal terminated unsuccessfully.
    ///
    /// From `visit()`: terminate traversal with an unsuccessful result.
    /// From `traverse()`: traversal terminated unsuccessfully, or an error occurred.
    Terminate = 2,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminants_match_java_constants() {
        assert_eq!(VisitorResult::Continue as i32, 0);
        assert_eq!(VisitorResult::Finished as i32, 1);
        assert_eq!(VisitorResult::Terminate as i32, 2);
    }

    #[test]
    fn all_variants_exist() {
        let _ = VisitorResult::Continue;
        let _ = VisitorResult::Finished;
        let _ = VisitorResult::Terminate;
    }

    #[test]
    fn equality() {
        assert_eq!(VisitorResult::Continue, VisitorResult::Continue);
        assert_ne!(VisitorResult::Continue, VisitorResult::Finished);
        assert_ne!(VisitorResult::Finished, VisitorResult::Terminate);
    }

    #[test]
    fn copy_and_clone() {
        let r = VisitorResult::Finished;
        let copied = r;
        let cloned = r.clone();
        assert_eq!(r, copied);
        assert_eq!(r, cloned);
    }

    #[test]
    fn debug_contains_variant_name() {
        assert!(format!("{:?}", VisitorResult::Continue).contains("Continue"));
        assert!(format!("{:?}", VisitorResult::Finished).contains("Finished"));
        assert!(format!("{:?}", VisitorResult::Terminate).contains("Terminate"));
    }

    #[test]
    fn hash_works_in_set() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(VisitorResult::Continue);
        set.insert(VisitorResult::Finished);
        assert!(set.contains(&VisitorResult::Continue));
        assert!(!set.contains(&VisitorResult::Terminate));
    }
}
