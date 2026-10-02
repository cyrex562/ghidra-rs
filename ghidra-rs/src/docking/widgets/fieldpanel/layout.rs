//! Port of the single-row case of `SingleRowLayout`/`RowLayout` plus
//! `FieldLocation`: an ordered set of fields on one line, and hit-testing a
//! pixel to a (field, column) the way Java's field panel snaps the cursor.

use super::field::{ClippingTextField, FontMetrics};

/// A cursor position: layout index (row of the listing), field, row within
/// the field, column within the row (Java `FieldLocation`, single-row fields).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FieldLocation {
    /// The layout's index in the model (u128: whole 64-bit address spaces).
    pub index: u128,
    /// Field number within the layout.
    pub field: usize,
    /// Row within the field (always 0 for single-row fields).
    pub row: usize,
    /// Column within the row.
    pub col: usize,
}

/// One line of fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    fields: Vec<ClippingTextField>,
    height: i32,
}

impl Layout {
    /// A layout of `fields` (in x order) one line tall.
    pub fn new(fields: Vec<ClippingTextField>, metrics: &FontMetrics) -> Self {
        Self { fields, height: metrics.line_height() }
    }

    /// Fields in x order.
    pub fn fields(&self) -> &[ClippingTextField] {
        &self.fields
    }

    /// Height in pixels.
    pub fn height(&self) -> i32 {
        self.height
    }

    /// The field containing `x`, or the nearest one (ties go left).
    pub fn field_index_at(&self, x: i32) -> Option<usize> {
        if self.fields.is_empty() {
            return None;
        }
        if let Some(i) = self.fields.iter().position(|f| f.contains(x)) {
            return Some(i);
        }
        let distance = |f: &ClippingTextField| {
            if x < f.start_x() {
                f.start_x() - x
            } else {
                x - (f.start_x() + f.width() - 1)
            }
        };
        (0..self.fields.len()).min_by_key(|&i| (distance(&self.fields[i]), i))
    }

    /// Cursor location for pixel `x` on the layout at `index`, if it has fields.
    pub fn try_cursor_location(&self, index: u128, x: i32) -> Option<FieldLocation> {
        let field = self.field_index_at(x)?;
        let col = self.fields[field].col(x);
        Some(FieldLocation { index, field, row: 0, col })
    }

    /// [`Self::try_cursor_location`] for layouts known to have fields.
    pub fn cursor_location(&self, index: u128, x: i32) -> FieldLocation {
        self.try_cursor_location(index, x).expect("layout has no fields")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::widgets::fieldpanel::field::{ClippingTextField, FieldElement, FontMetrics};

    fn m() -> FontMetrics {
        FontMetrics::monospace(7, 11, 3)
    }
    fn layout() -> Layout {
        // "00401000" at 0..80, "55" at 90..120, "??" at 130..170, "55h" at 180..240
        let f = |x, w, t: &str| ClippingTextField::new(x, w, FieldElement::plain(t), &m());
        Layout::new(vec![f(0, 80, "00401000"), f(90, 30, "55"), f(130, 40, "??"), f(180, 60, "55h")], &m())
    }

    #[test]
    fn height_is_one_line() {
        assert_eq!(layout().height(), 14);
    }

    #[test]
    fn x_inside_a_field_maps_to_that_field_and_column() {
        let l = layout();
        assert_eq!(l.cursor_location(7, 5), FieldLocation { index: 7, field: 0, row: 0, col: 0 });
        assert_eq!(l.cursor_location(7, 14), FieldLocation { index: 7, field: 0, row: 0, col: 2 });
        assert_eq!(l.cursor_location(7, 185), FieldLocation { index: 7, field: 3, row: 0, col: 0 });
    }

    #[test]
    fn x_between_fields_snaps_to_nearest() {
        let l = layout();
        assert_eq!(l.cursor_location(0, 84).field, 0); // 4px past field 0, 6px before field 1
        assert_eq!(l.cursor_location(0, 87).field, 1);
    }

    #[test]
    fn x_past_the_last_field_snaps_to_its_last_column() {
        let l = layout();
        assert_eq!(l.cursor_location(0, 10_000), FieldLocation { index: 0, field: 3, row: 0, col: 3 });
        assert_eq!(l.cursor_location(0, -50), FieldLocation { index: 0, field: 0, row: 0, col: 0 });
    }

    #[test]
    fn empty_layout_has_no_location() {
        let l = Layout::new(Vec::new(), &m());
        assert_eq!(l.try_cursor_location(0, 10), None);
    }
}
