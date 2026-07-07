/// Handles whitespace in strings when wrapping.
pub trait WhitespaceHandler {
    /// Counts the number of contiguous space characters in `s` starting at `offset`.
    fn count_spaces(&self, s: &str, offset: usize) -> usize;

    /// Returns `s` trimmed, or unchanged, depending on the implementation.
    fn trim<'a>(&self, s: &'a str) -> &'a str;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TrimmingHandler;

    impl WhitespaceHandler for TrimmingHandler {
        fn count_spaces(&self, s: &str, offset: usize) -> usize {
            s.chars().skip(offset).take_while(|&c| c == ' ').count()
        }

        fn trim<'a>(&self, s: &'a str) -> &'a str {
            s.trim()
        }
    }

    struct PreservingHandler;

    impl WhitespaceHandler for PreservingHandler {
        fn count_spaces(&self, s: &str, offset: usize) -> usize {
            s.chars().skip(offset).take_while(|&c| c == ' ').count()
        }

        fn trim<'a>(&self, s: &'a str) -> &'a str {
            s
        }
    }

    #[test]
    fn test_count_spaces_from_offset() {
        let h = TrimmingHandler;
        assert_eq!(3, h.count_spaces("abc   def", 3));
        assert_eq!(0, h.count_spaces("abc   def", 0));
        assert_eq!(0, h.count_spaces("abc", 3));
    }

    #[test]
    fn test_count_spaces_does_not_count_tabs() {
        let h = TrimmingHandler;
        assert_eq!(0, h.count_spaces("\tabc", 0));
    }

    #[test]
    fn test_count_spaces_at_start() {
        let h = TrimmingHandler;
        assert_eq!(2, h.count_spaces("  abc", 0));
    }

    #[test]
    fn test_trim_removes_leading_and_trailing() {
        let h = TrimmingHandler;
        assert_eq!("hello", h.trim("  hello  "));
    }

    #[test]
    fn test_trim_empty() {
        let h = TrimmingHandler;
        assert_eq!("", h.trim(""));
    }

    #[test]
    fn test_trim_preserving_does_not_trim() {
        let h = PreservingHandler;
        assert_eq!("  hello  ", h.trim("  hello  "));
    }

    #[test]
    fn test_count_spaces_zero_at_non_space() {
        let h = TrimmingHandler;
        assert_eq!(0, h.count_spaces("abc", 0));
    }
}
