/// Maps between view coordinates and logical indexes in an indexed scroll pane.
///
/// Corresponds to `docking.widgets.indexedscrollpane.ViewToIndexMapper`.
///
/// Only vertical coordinates are affected by this mapper.
/// Java's `BigInteger` index parameters are represented as `i128`.
/// Java's `int` pixel-offset parameters are represented as `i32`.
pub trait ViewToIndexMapper {
    /// Returns the total height of the view in pixels.
    fn get_view_height(&self) -> i32;

    /// Returns the logical index that corresponds to the given vertical pixel value.
    fn get_index(&self, value: i32) -> i128;

    /// Returns the vertical pixel offset within the row at the given pixel value.
    fn get_vertical_offset(&self, value: i32) -> i32;

    /// Notifies the mapper of the currently visible view height in pixels.
    fn set_visible_view_height(&mut self, height: i32);

    /// Returns the scroll value needed to bring the range `[start_index, end_index]`
    /// with pixel bounds `[y_start, y_end]` into view.
    fn get_scroll_value(
        &self,
        start_index: i128,
        end_index: i128,
        y_start: i32,
        y_end: i32,
    ) -> i32;

    /// Notifies the mapper that the underlying index model data changed between
    /// `start` and `end` (inclusive).
    fn index_model_data_changed(&mut self, start: i128, end: i128);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal implementation: evenly-spaced rows of fixed height.
    struct FixedRowMapper {
        row_height: i32,
        visible_height: i32,
    }

    impl FixedRowMapper {
        fn new(row_height: i32) -> Self {
            Self { row_height, visible_height: 0 }
        }
    }

    impl ViewToIndexMapper for FixedRowMapper {
        fn get_view_height(&self) -> i32 {
            // Arbitrary large view height for testing
            i32::MAX
        }

        fn get_index(&self, value: i32) -> i128 {
            if self.row_height <= 0 {
                return 0;
            }
            (value / self.row_height) as i128
        }

        fn get_vertical_offset(&self, value: i32) -> i32 {
            if self.row_height <= 0 {
                return 0;
            }
            value % self.row_height
        }

        fn set_visible_view_height(&mut self, height: i32) {
            self.visible_height = height;
        }

        fn get_scroll_value(
            &self,
            start_index: i128,
            _end_index: i128,
            y_start: i32,
            _y_end: i32,
        ) -> i32 {
            (start_index as i32) * self.row_height + y_start
        }

        fn index_model_data_changed(&mut self, _start: i128, _end: i128) {
            // no-op in the fixed mapper
        }
    }

    #[test]
    fn get_index_maps_pixel_to_row() {
        let m = FixedRowMapper::new(20);
        assert_eq!(m.get_index(0), 0);
        assert_eq!(m.get_index(19), 0);
        assert_eq!(m.get_index(20), 1);
        assert_eq!(m.get_index(39), 1);
        assert_eq!(m.get_index(40), 2);
    }

    #[test]
    fn get_vertical_offset_returns_within_row_offset() {
        let m = FixedRowMapper::new(20);
        assert_eq!(m.get_vertical_offset(0), 0);
        assert_eq!(m.get_vertical_offset(5), 5);
        assert_eq!(m.get_vertical_offset(19), 19);
        assert_eq!(m.get_vertical_offset(20), 0);
        assert_eq!(m.get_vertical_offset(25), 5);
    }

    #[test]
    fn get_view_height_returns_value() {
        let m = FixedRowMapper::new(20);
        assert_eq!(m.get_view_height(), i32::MAX);
    }

    #[test]
    fn set_visible_view_height_stores_value() {
        let mut m = FixedRowMapper::new(20);
        m.set_visible_view_height(400);
        assert_eq!(m.visible_height, 400);
    }

    #[test]
    fn get_scroll_value_uses_start_index_and_y_start() {
        let m = FixedRowMapper::new(20);
        assert_eq!(m.get_scroll_value(3, 5, 10, 50), 70); // 3*20 + 10
        assert_eq!(m.get_scroll_value(0, 1, 0, 20), 0);
    }

    #[test]
    fn index_model_data_changed_does_not_panic() {
        let mut m = FixedRowMapper::new(20);
        m.index_model_data_changed(0, 100);
        m.index_model_data_changed(i128::MAX - 1, i128::MAX);
    }

    #[test]
    fn large_index_values() {
        let m = FixedRowMapper::new(1);
        let big = i32::MAX as i128;
        assert_eq!(m.get_index(i32::MAX), big);
    }
}
