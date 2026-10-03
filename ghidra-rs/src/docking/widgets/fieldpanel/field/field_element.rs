//! Port of `TextFieldElement`/`AttributedString`: a run of text with a color
//! (theme `GColor` id) and style, measured with [`FontMetrics`].

use super::FontMetrics;

/// Text style of a field element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TextStyle {
    /// Regular weight.
    #[default]
    Plain,
    /// Bold weight.
    Bold,
}

/// A run of text with a theme color id and a style.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldElement {
    text: String,
    color_id: Option<String>,
    style: TextStyle,
}

impl FieldElement {
    /// A styled element.
    pub fn new(text: impl Into<String>, color_id: Option<String>, style: TextStyle) -> Self {
        Self { text: text.into(), color_id, style }
    }

    /// An unstyled element.
    pub fn plain(text: impl Into<String>) -> Self {
        Self::new(text, None, TextStyle::Plain)
    }

    /// The text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Theme color id, if any.
    pub fn color_id(&self) -> Option<&str> {
        self.color_id.as_deref()
    }

    /// Style.
    pub fn style(&self) -> TextStyle {
        self.style
    }

    /// Number of characters.
    pub fn len(&self) -> usize {
        self.text.chars().count()
    }

    /// Whether the text is empty.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    fn advance(&self, m: &FontMetrics) -> i32 {
        match self.style {
            TextStyle::Plain => m.char_width,
            TextStyle::Bold => m.bold_char_width,
        }
    }

    /// `getStringWidth()`.
    pub fn string_width(&self, m: &FontMetrics) -> i32 {
        self.advance(m) * self.len() as i32
    }

    /// `getMaxCharactersForWidth(width)`: how many characters fit entirely.
    pub fn max_characters_for_width(&self, m: &FontMetrics, width: i32) -> usize {
        let adv = self.advance(m);
        if adv <= 0 || width <= 0 {
            return 0;
        }
        ((width / adv) as usize).min(self.len())
    }

    /// `substring(start, end)` by character index, keeping color and style.
    pub fn substring(&self, start: usize, end: usize) -> FieldElement {
        let text: String = self.text.chars().skip(start).take(end.saturating_sub(start)).collect();
        FieldElement { text, color_id: self.color_id.clone(), style: self.style }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m() -> FontMetrics {
        FontMetrics::monospace(7, 11, 3)
    }

    #[test]
    fn width_and_max_chars() {
        let e = FieldElement::plain("mov eax");
        assert_eq!(e.string_width(&m()), 49);
        // getMaxCharactersForWidth: how many chars fit entirely
        assert_eq!(e.max_characters_for_width(&m(), 20), 2);
        assert_eq!(e.max_characters_for_width(&m(), 0), 0);
        assert_eq!(e.max_characters_for_width(&m(), 1000), 7);
    }

    #[test]
    fn bold_uses_bold_advance_and_substring_keeps_style() {
        let metrics = FontMetrics { char_width: 7, bold_char_width: 8, ascent: 11, descent: 3, leading: 0 };
        let e = FieldElement::new("LAB_00401000", Some("color.fg.listing.label".into()), TextStyle::Bold);
        assert_eq!(e.string_width(&metrics), 96);
        let s = e.substring(0, 3);
        assert_eq!(s.text(), "LAB");
        assert_eq!(s.style(), TextStyle::Bold);
        assert_eq!(s.color_id(), Some("color.fg.listing.label"));
    }
}
