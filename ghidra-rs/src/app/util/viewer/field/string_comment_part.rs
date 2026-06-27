//! A comment part backed by a plain string.

use std::fmt;

use super::comment_part::CommentPart;

/// A [`CommentPart`] whose raw text is identical to its display text.
///
/// Corresponds to Java `ghidra.app.util.viewer.field.StringCommentPart`.
///
/// In Java, `StringCommentPart` extends the abstract `CommentPart` and
/// overrides `getRawText()` to simply return `getDisplayText()`.  Because
/// there is no annotation markup, the stored text is both the rendered form
/// and the raw form.
pub struct StringCommentPart {
    text: String,
}

impl StringCommentPart {
    /// Creates a new `StringCommentPart` with the given text.
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }
}

impl CommentPart for StringCommentPart {
    fn raw_text(&self) -> &str {
        &self.text
    }

    fn display_text(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for StringCommentPart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_text_equals_display_text() {
        let part = StringCommentPart::new("hello world");
        assert_eq!(part.raw_text(), part.display_text());
    }

    #[test]
    fn display_text_matches_input() {
        let part = StringCommentPart::new("some comment");
        assert_eq!(part.display_text(), "some comment");
    }

    #[test]
    fn raw_text_matches_input() {
        let part = StringCommentPart::new("some comment");
        assert_eq!(part.raw_text(), "some comment");
    }

    #[test]
    fn to_string_equals_display_text() {
        let part = StringCommentPart::new("my comment");
        assert_eq!(part.to_string(), part.display_text());
    }

    #[test]
    fn empty_string() {
        let part = StringCommentPart::new("");
        assert_eq!(part.display_text(), "");
        assert_eq!(part.raw_text(), "");
        assert_eq!(part.to_string(), "");
    }

    #[test]
    fn trait_object_usage() {
        let part: Box<dyn CommentPart> = Box::new(StringCommentPart::new("trait obj"));
        assert_eq!(part.display_text(), "trait obj");
        assert_eq!(part.raw_text(), "trait obj");
    }

    #[test]
    fn unicode_text() {
        let part = StringCommentPart::new("こんにちは");
        assert_eq!(part.raw_text(), "こんにちは");
        assert_eq!(part.display_text(), "こんにちは");
    }
}
