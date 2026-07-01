use super::WhitespaceHandler;

/// A whitespace handler that preserves whitespace without trimming and counts no spaces.
pub struct PreservingWhitespaceHandler;

impl WhitespaceHandler for PreservingWhitespaceHandler {
    fn count_spaces(&self, _s: &str, _offset: usize) -> usize {
        0
    }

    fn trim<'a>(&self, s: &'a str) -> &'a str {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_spaces_returns_zero() {
        let h = PreservingWhitespaceHandler;
        assert_eq!(0, h.count_spaces("abc   def", 3));
        assert_eq!(0, h.count_spaces("   hello", 0));
        assert_eq!(0, h.count_spaces("hello   ", 5));
    }

    #[test]
    fn test_trim_returns_unchanged() {
        let h = PreservingWhitespaceHandler;
        assert_eq!("  hello  ", h.trim("  hello  "));
    }

    #[test]
    fn test_trim_empty_string() {
        let h = PreservingWhitespaceHandler;
        assert_eq!("", h.trim(""));
    }

    #[test]
    fn test_trim_no_whitespace() {
        let h = PreservingWhitespaceHandler;
        assert_eq!("hello", h.trim("hello"));
    }

    #[test]
    fn test_count_spaces_with_tabs() {
        let h = PreservingWhitespaceHandler;
        assert_eq!(0, h.count_spaces("\thello", 0));
    }

    #[test]
    fn test_count_spaces_empty_string() {
        let h = PreservingWhitespaceHandler;
        assert_eq!(0, h.count_spaces("", 0));
    }
}
