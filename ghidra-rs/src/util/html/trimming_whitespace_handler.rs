use super::WhitespaceHandler;

/// A whitespace handler that trims whitespace and counts space characters.
pub struct TrimmingWhitespaceHandler;

impl WhitespaceHandler for TrimmingWhitespaceHandler {
    fn count_spaces(&self, s: &str, offset: usize) -> usize {
        s.chars()
            .skip(offset)
            .take_while(|&c| c == ' ')
            .count()
    }

    fn trim<'a>(&self, s: &'a str) -> &'a str {
        s.trim()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_spaces_from_offset() {
        let h = TrimmingWhitespaceHandler;
        assert_eq!(3, h.count_spaces("abc   def", 3));
        assert_eq!(0, h.count_spaces("abc   def", 0));
        assert_eq!(0, h.count_spaces("abc", 3));
    }

    #[test]
    fn test_count_spaces_at_start() {
        let h = TrimmingWhitespaceHandler;
        assert_eq!(2, h.count_spaces("  abc", 0));
    }

    #[test]
    fn test_count_spaces_does_not_count_tabs() {
        let h = TrimmingWhitespaceHandler;
        assert_eq!(0, h.count_spaces("\tabc", 0));
    }

    #[test]
    fn test_count_spaces_zero_at_non_space() {
        let h = TrimmingWhitespaceHandler;
        assert_eq!(0, h.count_spaces("abc", 0));
    }

    #[test]
    fn test_count_spaces_all_whitespace() {
        let h = TrimmingWhitespaceHandler;
        assert_eq!(5, h.count_spaces("     ", 0));
    }

    #[test]
    fn test_trim_removes_leading_and_trailing() {
        let h = TrimmingWhitespaceHandler;
        assert_eq!("hello", h.trim("  hello  "));
    }

    #[test]
    fn test_trim_empty() {
        let h = TrimmingWhitespaceHandler;
        assert_eq!("", h.trim(""));
    }

    #[test]
    fn test_trim_no_whitespace() {
        let h = TrimmingWhitespaceHandler;
        assert_eq!("hello", h.trim("hello"));
    }

    #[test]
    fn test_trim_removes_tabs_and_newlines() {
        let h = TrimmingWhitespaceHandler;
        assert_eq!("hello", h.trim("\t\nhello\n\t"));
    }
}
