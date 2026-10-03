//! Port of `ClippingTextField`: a one-row text field that clips its text to
//! the available width (keeping the full text for tooltips/copy).

use super::{FieldElement, FontMetrics};

/// Width Java reserves for the clipping ellipsis.
const DOT_DOT_DOT_WIDTH: i32 = 12;

/// A one-row text field clipped to its width.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClippingTextField {
    start_x: i32,
    width: i32,
    original: FieldElement,
    visible: FieldElement,
    clipped: bool,
    preferred_width: i32,
    advance: i32,
    metrics: FontMetrics,
}

impl ClippingTextField {
    /// `new ClippingTextField(startX, width, element, hlFactory)`.
    pub fn new(start_x: i32, width: i32, element: FieldElement, metrics: &FontMetrics) -> Self {
        let preferred_width = element.string_width(metrics);
        let (visible, clipped) = if preferred_width <= width {
            (element.clone(), false)
        } else {
            let keep = element.max_characters_for_width(metrics, width - DOT_DOT_DOT_WIDTH);
            (element.substring(0, keep), true)
        };
        let advance = if element.len() > 0 { preferred_width / element.len() as i32 } else { metrics.char_width };
        Self { start_x, width, original: element, visible, clipped, preferred_width, advance, metrics: *metrics }
    }

    /// Left edge in pixels.
    pub fn start_x(&self) -> i32 {
        self.start_x
    }

    /// Width in pixels.
    pub fn width(&self) -> i32 {
        self.width
    }

    /// Width the full text would need.
    pub fn preferred_width(&self) -> i32 {
        self.preferred_width
    }

    /// Whether the text was clipped.
    pub fn is_clipped(&self) -> bool {
        self.clipped
    }

    /// Full (unclipped) text — Java `getText()`.
    pub fn text(&self) -> &str {
        self.original.text()
    }

    /// The text actually shown.
    pub fn visible_text(&self) -> &str {
        self.visible.text()
    }

    /// The shown element (for painting).
    pub fn visible_element(&self) -> &FieldElement {
        &self.visible
    }

    /// `getNumCols(row)`: shown characters + 1 (cursor after the last).
    pub fn num_cols(&self) -> usize {
        self.visible.len() + 1
    }

    /// `getX(row, col)`.
    pub fn x(&self, col: usize) -> i32 {
        self.start_x + self.advance * col.min(self.visible.len()) as i32
    }

    /// `getCol(row, x)`: x relative to the field, clamped to the shown text.
    pub fn col(&self, x: i32) -> usize {
        let rel = (x - self.start_x).max(0);
        self.visible.max_characters_for_width(&self.metrics, rel)
    }

    /// `contains(x, y)` on the x axis: `[start_x, start_x + width)`.
    pub fn contains(&self, x: i32) -> bool {
        x >= self.start_x && x < self.start_x + self.width
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m() -> FontMetrics {
        FontMetrics::monospace(7, 11, 3)
    }

    #[test]
    fn unclipped_columns_and_x_positions() {
        let f = ClippingTextField::new(100, 200, FieldElement::plain("push rbp"), &m());
        assert!(!f.is_clipped());
        assert_eq!(f.num_cols(), 9); // text length + 1 (cursor after last char)
        assert_eq!(f.x(0), 100);
        assert_eq!(f.x(3), 121);
        assert_eq!(f.col(121), 3);
        assert_eq!(f.col(50), 0); // left of the field clamps to 0
        assert_eq!(f.col(10_000), 8); // past the end snaps to the last column
        assert_eq!(f.text(), "push rbp");
    }

    #[test]
    fn clipping_matches_java_dot_dot_dot_rule() {
        // width 40: text needs 56 px; Java keeps getMaxCharactersForWidth(40 - 12) = 4 chars
        let f = ClippingTextField::new(0, 40, FieldElement::plain("push rbp"), &m());
        assert!(f.is_clipped());
        assert_eq!(f.visible_text(), "push");
        assert_eq!(f.text(), "push rbp");
        assert_eq!(f.num_cols(), 5);
        assert_eq!(f.preferred_width(), 56);
    }

    #[test]
    fn contains_is_half_open_on_x() {
        let f = ClippingTextField::new(10, 20, FieldElement::plain("ab"), &m());
        assert!(f.contains(10));
        assert!(f.contains(29));
        assert!(!f.contains(30));
        assert!(!f.contains(9));
    }
}
