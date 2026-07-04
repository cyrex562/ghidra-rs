//! A comment part that wraps an annotation.

use std::fmt;

use super::annotation::Annotation;
use super::comment_part::CommentPart;

/// A [`CommentPart`] backed by an [`Annotation`].
///
/// Corresponds to Java `ghidra.app.util.viewer.field.AnnotationCommentPart`.
///
/// In Java, `AnnotationCommentPart` extends `CommentPart` and stores both
/// display text and an annotation object. The raw text is obtained from the
/// annotation, while the display text is provided at construction.
pub struct AnnotationCommentPart {
    display_text: String,
    annotation: Annotation,
}

impl AnnotationCommentPart {
    /// Creates a new `AnnotationCommentPart`.
    ///
    /// # Arguments
    ///
    /// * `display_text` - The text to display for this comment part.
    /// * `annotation` - The underlying annotation.
    pub fn new(display_text: impl Into<String>, annotation: Annotation) -> Self {
        Self {
            display_text: display_text.into(),
            annotation,
        }
    }

    /// Returns the underlying annotation.
    pub fn annotation(&self) -> &Annotation {
        &self.annotation
    }
}

impl CommentPart for AnnotationCommentPart {
    fn raw_text(&self) -> &str {
        self.annotation.annotation_text()
    }

    fn display_text(&self) -> &str {
        &self.display_text
    }
}

impl fmt::Display for AnnotationCommentPart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.annotation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_text_is_set_from_constructor() {
        let ann = Annotation::new("{@symbol addr}");
        let part = AnnotationCommentPart::new("click here", ann);
        assert_eq!(part.display_text(), "click here");
    }

    #[test]
    fn raw_text_comes_from_annotation() {
        let ann = Annotation::new("{@symbol addr}");
        let part = AnnotationCommentPart::new("display", ann);
        assert_eq!(part.raw_text(), "{@symbol addr}");
    }

    #[test]
    fn display_and_raw_can_differ() {
        let ann = Annotation::new("{@symbol addr}");
        let part = AnnotationCommentPart::new("link", ann);
        assert_eq!(part.display_text(), "link");
        assert_eq!(part.raw_text(), "{@symbol addr}");
    }

    #[test]
    fn annotation_getter_returns_correct_annotation() {
        let ann = Annotation::new("{@symbol \"multi word\"}");
        let part = AnnotationCommentPart::new("display", ann.clone());
        assert_eq!(part.annotation(), &ann);
    }

    #[test]
    fn display_impl_uses_annotation_text() {
        let ann = Annotation::new("{@symbol addr}");
        let part = AnnotationCommentPart::new("display", ann);
        assert_eq!(part.to_string(), "{@symbol addr}");
    }

    #[test]
    fn trait_object_usage() {
        let ann = Annotation::new("{@foo bar}");
        let part: Box<dyn CommentPart> =
            Box::new(AnnotationCommentPart::new("display", ann));
        assert_eq!(part.display_text(), "display");
        assert_eq!(part.raw_text(), "{@foo bar}");
    }

    #[test]
    fn empty_display_text() {
        let ann = Annotation::new("{@symbol addr}");
        let part = AnnotationCommentPart::new("", ann);
        assert_eq!(part.display_text(), "");
        assert_eq!(part.raw_text(), "{@symbol addr}");
    }

    #[test]
    fn complex_annotation_parsing() {
        let ann = Annotation::new("{@symbol \"multi word\" escaped}");
        let part = AnnotationCommentPart::new("formatted", ann);
        assert_eq!(part.display_text(), "formatted");
        assert_eq!(part.raw_text(), "{@symbol \"multi word\" escaped}");
    }
}
