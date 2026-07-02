use std::fmt;
use std::hash::{Hash, Hasher};

use super::{Color, PlaceHolderLine, ValidatableLine, INVALID_COLOR};

/// A plain text line that can be diff-compared and colored against another line.
///
/// Mirrors `ghidra.app.util.html.TextLine`.
#[derive(Debug, Clone)]
pub struct TextLine {
    text: String,
    text_color: Option<Color>,
    is_validated: bool,
}

impl TextLine {
    /// Creates a new `TextLine` with the given text.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            text_color: None,
            is_validated: false,
        }
    }

    /// Returns the optional text color.
    pub fn get_text_color(&self) -> Option<Color> {
        self.text_color
    }

    /// Returns `true` if this line's text equals `other`'s text (package-private in Java).
    pub fn matches_text_line(&self, other: &TextLine) -> bool {
        self.text == other.text
    }
}

impl ValidatableLine for TextLine {
    fn update_color(&mut self, other_line: Option<&mut dyn ValidatableLine>, invalid_color: Color) {
        match other_line {
            None => self.set_text_color(invalid_color),
            Some(other) => {
                if !self.matches_line(&*other) {
                    self.set_text_color(invalid_color);
                    other.set_text_color(invalid_color);
                }
            }
        }
    }

    fn is_diff_colored(&self) -> bool {
        self.text_color.is_some()
    }

    fn matches_line(&self, other_line: &dyn ValidatableLine) -> bool {
        self.text == other_line.get_text()
    }

    fn copy(&self) -> Box<dyn ValidatableLine> {
        Box::new(TextLine::new(self.text.clone()))
    }

    fn get_text(&self) -> &str {
        &self.text
    }

    fn set_text_color(&mut self, color: Color) {
        self.text_color = Some(color);
    }

    fn set_validation_line(&mut self, line: &mut dyn ValidatableLine) {
        if self.is_validated {
            return;
        }
        self.is_validated = true;
        self.update_color(Some(line), INVALID_COLOR);
    }

    fn is_validated(&self) -> bool {
        self.is_validated
    }
}

impl PartialEq for TextLine {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text && self.text_color == other.text_color
    }
}

impl Eq for TextLine {}

impl Hash for TextLine {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.text.hash(state);
        self.text_color.hash(state);
    }
}

impl fmt::Display for TextLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)?;
        if let Some(color) = self.text_color {
            write!(f, " {color}")?;
        }
        Ok(())
    }
}

/// A fixed-width, always-validated empty line used as a diff place holder.
///
/// Mirrors `ghidra.app.util.html.EmptyTextLine`, which extends `TextLine` and
/// implements `PlaceHolderLine`.
#[derive(Debug, Clone)]
pub struct EmptyTextLine {
    width_in_characters: usize,
    text_color: Option<Color>,
    display_text: String,
}

impl EmptyTextLine {
    /// Creates a new `EmptyTextLine` displaying `width_in_characters` spaces.
    pub fn new(width_in_characters: usize) -> Self {
        Self {
            width_in_characters,
            text_color: None,
            display_text: " ".repeat(width_in_characters),
        }
    }
}

impl ValidatableLine for EmptyTextLine {
    fn update_color(&mut self, other_line: Option<&mut dyn ValidatableLine>, invalid_color: Color) {
        // Since we are the empty line, the other line is entirely a mismatch.
        if let Some(other) = other_line {
            other.set_text_color(invalid_color);
        }
    }

    fn is_diff_colored(&self) -> bool {
        self.text_color.is_some()
    }

    fn matches_line(&self, _other_line: &dyn ValidatableLine) -> bool {
        // An empty line never matches another line.
        false
    }

    fn copy(&self) -> Box<dyn ValidatableLine> {
        Box::new(EmptyTextLine::new(self.width_in_characters))
    }

    fn get_text(&self) -> &str {
        &self.display_text
    }

    fn set_text_color(&mut self, color: Color) {
        self.text_color = Some(color);
    }

    fn set_validation_line(&mut self, _line: &mut dyn ValidatableLine) {}

    fn is_validated(&self) -> bool {
        true
    }
}

impl PlaceHolderLine for EmptyTextLine {}

impl fmt::Display for EmptyTextLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<FixedWidthEmptyTextLine>")
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::html::{validate_pair, INVALID_COLOR};

    fn red() -> Color {
        INVALID_COLOR
    }

    fn blue() -> Color {
        Color::rgb(0, 0, 255)
    }

    // ── constructor ──────────────────────────────────────────────────────────

    #[test]
    fn new_stores_text() {
        let line = TextLine::new("hello");
        assert_eq!(line.get_text(), "hello");
    }

    #[test]
    fn new_has_no_color() {
        let line = TextLine::new("hello");
        assert!(!line.is_diff_colored());
        assert_eq!(line.get_text_color(), None);
    }

    #[test]
    fn new_is_not_validated() {
        let line = TextLine::new("hello");
        assert!(!line.is_validated());
    }

    // ── copy ─────────────────────────────────────────────────────────────────

    #[test]
    fn copy_preserves_text() {
        let line = TextLine::new("abc");
        let copied = line.copy();
        assert_eq!(copied.get_text(), "abc");
    }

    #[test]
    fn copy_drops_color() {
        let mut line = TextLine::new("abc");
        line.set_text_color(red());
        let copied = line.copy();
        assert!(!copied.is_diff_colored());
    }

    // ── matches_line ─────────────────────────────────────────────────────────

    #[test]
    fn matches_line_same_text() {
        let a = TextLine::new("foo");
        let b = TextLine::new("foo");
        assert!(a.matches_line(&b));
    }

    #[test]
    fn matches_line_different_text() {
        let a = TextLine::new("foo");
        let b = TextLine::new("bar");
        assert!(!a.matches_line(&b));
    }

    #[test]
    fn matches_text_line_helper() {
        let a = TextLine::new("x");
        let b = TextLine::new("x");
        let c = TextLine::new("y");
        assert!(a.matches_text_line(&b));
        assert!(!a.matches_text_line(&c));
    }

    // ── is_diff_colored / set_text_color ────────────────────────────────────

    #[test]
    fn set_text_color_marks_diff_colored() {
        let mut line = TextLine::new("hello");
        assert!(!line.is_diff_colored());
        line.set_text_color(red());
        assert!(line.is_diff_colored());
        assert_eq!(line.get_text_color(), Some(red()));
    }

    // ── update_color: no other line ──────────────────────────────────────────

    #[test]
    fn update_color_none_colors_self() {
        let mut line = TextLine::new("x");
        line.update_color(None, red());
        assert_eq!(line.get_text_color(), Some(red()));
    }

    // ── update_color: with matching other ───────────────────────────────────

    #[test]
    fn update_color_matching_lines_no_color_change() {
        let mut a = TextLine::new("same");
        let mut b = TextLine::new("same");
        a.update_color(Some(&mut b), red());
        assert!(!a.is_diff_colored());
        assert!(!b.is_diff_colored());
    }

    // ── update_color: with non-matching other ────────────────────────────────

    #[test]
    fn update_color_different_lines_colors_both() {
        let mut a = TextLine::new("aaa");
        let mut b = TextLine::new("bbb");
        a.update_color(Some(&mut b), red());
        assert_eq!(a.get_text_color(), Some(red()));
        assert_eq!(b.get_text_color(), Some(red()));
    }

    #[test]
    fn update_color_uses_supplied_color() {
        let mut a = TextLine::new("a");
        let mut b = TextLine::new("b");
        a.update_color(Some(&mut b), blue());
        assert_eq!(a.get_text_color(), Some(blue()));
        assert_eq!(b.get_text_color(), Some(blue()));
    }

    // ── set_validation_line ──────────────────────────────────────────────────

    #[test]
    fn set_validation_line_marks_validated() {
        let mut a = TextLine::new("x");
        let mut b = TextLine::new("x");
        a.set_validation_line(&mut b);
        assert!(a.is_validated());
    }

    #[test]
    fn set_validation_line_idempotent() {
        let mut a = TextLine::new("x");
        let mut b = TextLine::new("x");
        a.set_validation_line(&mut b);
        a.set_validation_line(&mut b); // second call is a no-op
        assert!(a.is_validated());
    }

    #[test]
    fn set_validation_line_matching_lines_no_color() {
        let mut a = TextLine::new("same");
        let mut b = TextLine::new("same");
        a.set_validation_line(&mut b);
        assert!(!a.is_diff_colored());
        assert!(!b.is_diff_colored());
    }

    #[test]
    fn set_validation_line_different_lines_colors_both() {
        let mut a = TextLine::new("aaa");
        let mut b = TextLine::new("bbb");
        a.set_validation_line(&mut b);
        assert!(a.is_diff_colored());
        assert!(b.is_diff_colored());
    }

    // ── validate_pair ────────────────────────────────────────────────────────

    #[test]
    fn validate_pair_marks_both_validated() {
        let mut a = TextLine::new("x");
        let mut b = TextLine::new("x");
        validate_pair(&mut a, &mut b);
        assert!(a.is_validated());
        assert!(b.is_validated());
    }

    #[test]
    fn validate_pair_matching_no_color() {
        let mut a = TextLine::new("same");
        let mut b = TextLine::new("same");
        validate_pair(&mut a, &mut b);
        assert!(!a.is_diff_colored());
        assert!(!b.is_diff_colored());
    }

    #[test]
    fn validate_pair_different_colors_both() {
        let mut a = TextLine::new("aaa");
        let mut b = TextLine::new("bbb");
        validate_pair(&mut a, &mut b);
        assert!(a.is_diff_colored());
        assert!(b.is_diff_colored());
    }

    // ── equality and hash ────────────────────────────────────────────────────

    #[test]
    fn equal_text_same_color_are_equal() {
        let mut a = TextLine::new("hello");
        let mut b = TextLine::new("hello");
        a.set_text_color(red());
        b.set_text_color(red());
        assert_eq!(a, b);
    }

    #[test]
    fn equal_text_different_color_not_equal() {
        let mut a = TextLine::new("hello");
        let mut b = TextLine::new("hello");
        a.set_text_color(red());
        b.set_text_color(blue());
        assert_ne!(a, b);
    }

    #[test]
    fn different_text_not_equal() {
        let a = TextLine::new("foo");
        let b = TextLine::new("bar");
        assert_ne!(a, b);
    }

    #[test]
    fn same_content_same_hash() {
        use std::collections::hash_map::DefaultHasher;
        let a = TextLine::new("hi");
        let b = TextLine::new("hi");
        let hash_of = |x: &TextLine| {
            let mut h = DefaultHasher::new();
            x.hash(&mut h);
            h.finish()
        };
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    // ── Display ──────────────────────────────────────────────────────────────

    #[test]
    fn display_without_color() {
        let line = TextLine::new("hello world");
        assert_eq!(line.to_string(), "hello world");
    }

    #[test]
    fn display_with_color_appends_color_string() {
        let mut line = TextLine::new("hello");
        line.set_text_color(red());
        let s = line.to_string();
        assert!(s.starts_with("hello "));
        assert!(s.contains("Color[r=255,g=0,b=0"));
    }
}
