//! Abstract base for parts of a comment displayed in the listing.

/// Represents a single part of a comment shown in the listing display.
///
/// Corresponds to Java `ghidra.app.util.viewer.field.CommentPart`.
///
/// In Java this is an abstract class that stores a `displayText` string and
/// requires subclasses to supply the raw (un-rendered) text.  In Rust we
/// express the same contract as a trait: implementors must provide both
/// `raw_text` (the abstract requirement) and `display_text` (the concrete
/// accessor that would have read the protected field in Java).
pub trait CommentPart {
    /// Returns the raw, un-rendered text of this comment part.
    ///
    /// Corresponds to the abstract `getRawText()` method in Java.
    fn raw_text(&self) -> &str;

    /// Returns the display text for this comment part.
    ///
    /// Corresponds to the concrete `getDisplayText()` method in Java, which
    /// returned the `displayText` field set by the constructor.
    fn display_text(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleCommentPart {
        display: String,
        raw: String,
    }

    impl SimpleCommentPart {
        fn new(display: impl Into<String>, raw: impl Into<String>) -> Self {
            Self {
                display: display.into(),
                raw: raw.into(),
            }
        }
    }

    impl CommentPart for SimpleCommentPart {
        fn raw_text(&self) -> &str {
            &self.raw
        }

        fn display_text(&self) -> &str {
            &self.display
        }
    }

    #[test]
    fn test_display_text_returned() {
        let part = SimpleCommentPart::new("Hello World", "hello world");
        assert_eq!(part.display_text(), "Hello World");
    }

    #[test]
    fn test_raw_text_returned() {
        let part = SimpleCommentPart::new("Hello World", "hello world");
        assert_eq!(part.raw_text(), "hello world");
    }

    #[test]
    fn test_display_and_raw_can_differ() {
        let part = SimpleCommentPart::new("/* comment */", "comment");
        assert_eq!(part.display_text(), "/* comment */");
        assert_eq!(part.raw_text(), "comment");
    }

    #[test]
    fn test_empty_texts() {
        let part = SimpleCommentPart::new("", "");
        assert_eq!(part.display_text(), "");
        assert_eq!(part.raw_text(), "");
    }

    #[test]
    fn test_trait_object() {
        let part: Box<dyn CommentPart> =
            Box::new(SimpleCommentPart::new("display", "raw"));
        assert_eq!(part.display_text(), "display");
        assert_eq!(part.raw_text(), "raw");
    }
}
