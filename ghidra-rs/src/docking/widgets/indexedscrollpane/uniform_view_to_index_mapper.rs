use super::{IndexedScrollable, ViewToIndexMapper};

/// Mapper for uniformly-spaced items where all rows have the same height.
///
/// Corresponds to `docking.widgets.indexedscrollpane.UniformViewToIndexMapper`.
///
/// This mapper assumes that all items are the same vertical size, providing fast
/// O(1) calculations for index-to-pixel and pixel-to-index conversions.
pub struct UniformViewToIndexMapper<M: IndexedScrollable> {
    view_height: i32,
    layout_height: i32,
    scrollable: M,
}

impl<M: IndexedScrollable> UniformViewToIndexMapper<M> {
    /// Creates a new mapper over `scrollable`.
    pub fn new(scrollable: M) -> Self {
        let mut mapper = Self {
            view_height: 0,
            layout_height: 0,
            scrollable,
        };
        mapper.compute_heights();
        mapper
    }

    fn compute_heights(&mut self) {
        self.layout_height = self.scrollable.get_height(0);
        if self.layout_height < 1 {
            self.layout_height = 1;
        }
        self.view_height = (self.scrollable.get_index_count() as i32) * self.layout_height;
    }
}

impl<M: IndexedScrollable> ViewToIndexMapper for UniformViewToIndexMapper<M> {
    fn get_view_height(&self) -> i32 {
        self.view_height
    }

    fn get_index(&self, value: i32) -> i128 {
        (value / self.layout_height) as i128
    }

    fn get_vertical_offset(&self, value: i32) -> i32 {
        let index = value / self.layout_height;
        (index * self.layout_height) - value
    }

    fn set_visible_view_height(&mut self, _height: i32) {
        // No-op for uniform mapper
    }

    fn get_scroll_value(
        &self,
        start_index: i128,
        _end_index: i128,
        y_start: i32,
        _y_end: i32,
    ) -> i32 {
        (start_index as i32) * self.layout_height - y_start
    }

    fn index_model_data_changed(&mut self, _start: i128, _end: i128) {
        self.compute_heights();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::IndexScrollListenerAdapter;

    struct FakeScrollable {
        index_count: i128,
        height: i32,
    }

    impl IndexedScrollable for FakeScrollable {
        fn get_index_count(&self) -> i128 {
            self.index_count
        }

        fn is_uniform_index(&self) -> bool {
            true
        }

        fn get_height(&self, _index: i128) -> i32 {
            self.height
        }

        fn show_index(&mut self, _index: i128, _vertical_offset: i32) {}

        fn get_index_after(&self, index: i128) -> i128 {
            if index + 1 < self.index_count {
                index + 1
            } else {
                -1
            }
        }

        fn get_index_before(&self, index: i128) -> i128 {
            if index > 0 {
                index - 1
            } else {
                -1
            }
        }

        fn scroll_line_up(&mut self) {}
        fn scroll_line_down(&mut self) {}
        fn scroll_page_up(&mut self) {}
        fn scroll_page_down(&mut self) {}

        fn add_index_scroll_listener(&mut self, _listener: Box<dyn IndexScrollListenerAdapter>) {}

        fn remove_index_scroll_listener(
            &mut self,
            _listener: Box<dyn IndexScrollListenerAdapter>,
        ) {
        }

        fn mouse_wheel_moved(&mut self, _precise_wheel_rotation: f64, _is_horizontal: bool) {}
    }

    fn mapper(index_count: i128, height: i32) -> UniformViewToIndexMapper<FakeScrollable> {
        UniformViewToIndexMapper::new(FakeScrollable { index_count, height })
    }

    #[test]
    fn new_computes_view_height() {
        let m = mapper(100, 20);
        assert_eq!(m.get_view_height(), 2000); // 100 * 20
    }

    #[test]
    fn new_enforces_minimum_layout_height() {
        let m = mapper(100, 0);
        assert_eq!(m.get_view_height(), 100); // 100 * 1 (minimum)
    }

    #[test]
    fn new_handles_negative_layout_height() {
        let m = mapper(100, -5);
        assert_eq!(m.get_view_height(), 100); // 100 * 1 (minimum)
    }

    #[test]
    fn get_index_maps_pixel_to_row() {
        let m = mapper(100, 20);
        assert_eq!(m.get_index(0), 0);
        assert_eq!(m.get_index(19), 0);
        assert_eq!(m.get_index(20), 1);
        assert_eq!(m.get_index(39), 1);
        assert_eq!(m.get_index(40), 2);
        assert_eq!(m.get_index(1980), 99);
    }

    #[test]
    fn get_index_with_zero_pixels() {
        let m = mapper(100, 20);
        assert_eq!(m.get_index(0), 0);
    }

    #[test]
    fn get_index_at_last_row() {
        let m = mapper(100, 20);
        assert_eq!(m.get_index(1999), 99);
    }

    #[test]
    fn get_vertical_offset_returns_within_row_offset() {
        let m = mapper(100, 20);
        assert_eq!(m.get_vertical_offset(0), 0);
        assert_eq!(m.get_vertical_offset(10), 10);
        assert_eq!(m.get_vertical_offset(19), 19);
        assert_eq!(m.get_vertical_offset(20), 0);
        assert_eq!(m.get_vertical_offset(25), 5);
        assert_eq!(m.get_vertical_offset(39), 19);
        assert_eq!(m.get_vertical_offset(40), 0);
    }

    #[test]
    fn get_vertical_offset_negative_result() {
        let m = mapper(100, 20);
        // index = value / layout_height = 25 / 20 = 1
        // result = (1 * 20) - 25 = 20 - 25 = -5
        assert_eq!(m.get_vertical_offset(25), -5);
    }

    #[test]
    fn set_visible_view_height_is_noop() {
        let mut m = mapper(100, 20);
        let original = m.get_view_height();
        m.set_visible_view_height(400);
        assert_eq!(m.get_view_height(), original);
    }

    #[test]
    fn get_scroll_value_start_at_zero() {
        let m = mapper(100, 20);
        assert_eq!(m.get_scroll_value(0, 0, 0, 0), 0);
    }

    #[test]
    fn get_scroll_value_uses_start_index_and_y_start() {
        let m = mapper(100, 20);
        // (3 as i32) * 20 - 10 = 60 - 10 = 50
        assert_eq!(m.get_scroll_value(3, 5, 10, 50), 50);
    }

    #[test]
    fn get_scroll_value_mid_range() {
        let m = mapper(100, 20);
        // (50 as i32) * 20 - 100 = 1000 - 100 = 900
        assert_eq!(m.get_scroll_value(50, 60, 100, 500), 900);
    }

    #[test]
    fn get_scroll_value_end_index_ignored() {
        let m = mapper(100, 20);
        // end_index is ignored in calculation
        assert_eq!(m.get_scroll_value(3, 5, 10, 50), m.get_scroll_value(3, 99, 10, 50));
    }

    #[test]
    fn get_scroll_value_y_end_ignored() {
        let m = mapper(100, 20);
        // y_end is ignored in calculation
        assert_eq!(m.get_scroll_value(3, 5, 10, 50), m.get_scroll_value(3, 5, 10, 200));
    }

    #[test]
    fn index_model_data_changed_recomputes_heights() {
        let mut m = mapper(100, 20);
        let original = m.get_view_height();
        // This would normally trigger a re-query of the scrollable,
        // but since our fake returns the same height, view height is stable
        m.index_model_data_changed(0, 99);
        assert_eq!(m.get_view_height(), original);
    }

    #[test]
    fn large_index_count() {
        // The model can report a huge index count, but `get_index` maps an i32 pixel
        // value, so exercise it with the largest index whose pixel offset fits in i32.
        let m = mapper(i128::MAX / 100, 20);
        let large_index = (i32::MAX / 20) as i128;
        let large_value = (large_index as i32) * 20;
        assert_eq!(m.get_index(large_value), large_index);
    }

    #[test]
    fn single_row() {
        let m = mapper(1, 20);
        assert_eq!(m.get_view_height(), 20);
        assert_eq!(m.get_index(0), 0);
        assert_eq!(m.get_index(19), 0);
    }

    #[test]
    fn zero_index_count() {
        let m = mapper(0, 20);
        assert_eq!(m.get_view_height(), 0);
        assert_eq!(m.get_index(0), 0);
    }
}
