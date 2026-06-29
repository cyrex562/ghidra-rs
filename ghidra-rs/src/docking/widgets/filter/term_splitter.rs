/// Interface for splitting a string into individual filter terms.
///
/// Corresponds to `docking.widgets.filter.TermSplitter`.
pub trait TermSplitter {
    /// Splits the given input string into a collection of terms.
    fn split(&self, input: &str) -> Vec<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct WhitespaceSplitter;

    impl TermSplitter for WhitespaceSplitter {
        fn split(&self, input: &str) -> Vec<String> {
            input.split_whitespace().map(str::to_owned).collect()
        }
    }

    #[test]
    fn split_single_term() {
        let s = WhitespaceSplitter;
        assert_eq!(s.split("hello"), vec!["hello"]);
    }

    #[test]
    fn split_multiple_terms() {
        let s = WhitespaceSplitter;
        assert_eq!(s.split("foo bar baz"), vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn split_empty_string() {
        let s = WhitespaceSplitter;
        let result = s.split("");
        assert!(result.is_empty());
    }

    #[test]
    fn split_whitespace_only() {
        let s = WhitespaceSplitter;
        let result = s.split("   ");
        assert!(result.is_empty());
    }
}
