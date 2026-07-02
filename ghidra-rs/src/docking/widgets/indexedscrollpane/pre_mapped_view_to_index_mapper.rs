use super::{IndexedScrollable, ViewToIndexMapper};

/// Implementation of [`ViewToIndexMapper`] that precomputes the pixel start position of
/// every index up front, then uses binary search over that layout to map between pixel
/// values and logical indexes.
///
/// Corresponds to `docking.widgets.indexedscrollpane.PreMappedViewToIndexMapper`.
///
/// Java's `BigInteger` index parameters are represented as `i128`.
/// Java's `int` pixel-offset parameters are represented as `i32`.
pub struct PreMappedViewToIndexMapper<M: IndexedScrollable> {
    model: M,
    view_height: i32,
    layout_starts: Vec<i32>,
}

impl<M: IndexedScrollable> PreMappedViewToIndexMapper<M> {
    /// Creates a new mapper over `model`, precomputing the pixel start position of every index.
    pub fn new(model: M) -> Self {
        let mut mapper = Self {
            model,
            view_height: 0,
            layout_starts: Vec::new(),
        };
        mapper.create_layout_starts();
        mapper
    }

    fn create_layout_starts(&mut self) {
        let n = self.model.get_index_count();
        let mut layout_starts = vec![0i32; n as usize];
        let mut y_pos = 0i32;
        for i in 0..n {
            layout_starts[i as usize] = y_pos;
            let height = self.model.get_height(i);
            y_pos += height;
        }
        self.layout_starts = layout_starts;
        self.view_height = y_pos;
    }
}

impl<M: IndexedScrollable> ViewToIndexMapper for PreMappedViewToIndexMapper<M> {
    fn get_index(&self, value: i32) -> i128 {
        match self.layout_starts.binary_search(&value) {
            Ok(index) => index as i128,
            Err(index) => index as i128 - 1,
        }
    }

    fn get_scroll_value(
        &self,
        start_index: i128,
        _end_index: i128,
        y_start: i32,
        _y_end: i32,
    ) -> i32 {
        if self.layout_starts.is_empty() {
            return 0;
        }
        self.layout_starts[start_index as usize] - y_start
    }

    fn get_vertical_offset(&self, value: i32) -> i32 {
        if self.layout_starts.is_empty() {
            return 0;
        }
        let index = match self.layout_starts.binary_search(&value) {
            Ok(_) => return 0,
            Err(index) => index as i64 - 1,
        };
        self.layout_starts[index as usize] - value
    }

    fn get_view_height(&self) -> i32 {
        self.view_height
    }

    fn set_visible_view_height(&mut self, _height: i32) {
        // height is irrelevant to us, as we map our entire layout structure ahead of time
    }

    fn index_model_data_changed(&mut self, start: i128, end: i128) {
        let start_index = start as usize;
        let end_index = std::cmp::min(self.layout_starts.len(), (end + 1) as usize);
        let mut y_pos = self.layout_starts[start_index];
        for i in start_index..end_index {
            self.layout_starts[i] = y_pos;
            let height = self.model.get_height(i as i128);
            y_pos += height;
        }
        if end_index < self.layout_starts.len() {
            let diff = y_pos - self.layout_starts[end_index];
            for i in end_index..self.layout_starts.len() {
                self.layout_starts[i] += diff;
            }
            self.view_height += diff;
        }
        else {
            self.view_height = y_pos;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::IndexScrollListenerAdapter;

    struct FakeScrollable {
        heights: Vec<i32>,
    }

    impl IndexedScrollable for FakeScrollable {
        fn get_index_count(&self) -> i128 {
            self.heights.len() as i128
        }

        fn is_uniform_index(&self) -> bool {
            false
        }

        fn get_height(&self, index: i128) -> i32 {
            self.heights[index as usize]
        }

        fn show_index(&mut self, _index: i128, _vertical_offset: i32) {}

        fn get_index_after(&self, index: i128) -> i128 {
            if index + 1 < self.heights.len() as i128 {
                index + 1
            }
            else {
                -1
            }
        }

        fn get_index_before(&self, index: i128) -> i128 {
            if index > 0 {
                index - 1
            }
            else {
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

    fn mapper(heights: Vec<i32>) -> PreMappedViewToIndexMapper<FakeScrollable> {
        PreMappedViewToIndexMapper::new(FakeScrollable { heights })
    }

    #[test]
    fn new_computes_view_height_as_sum_of_row_heights() {
        let m = mapper(vec![10, 20, 30]);
        assert_eq!(m.get_view_height(), 60);
    }

    #[test]
    fn new_handles_empty_model() {
        let m = mapper(vec![]);
        assert_eq!(m.get_view_height(), 0);
    }

    #[test]
    fn get_index_at_exact_row_start_returns_that_row() {
        let m = mapper(vec![10, 20, 30]);
        assert_eq!(m.get_index(0), 0);
        assert_eq!(m.get_index(10), 1);
        assert_eq!(m.get_index(30), 2);
    }

    #[test]
    fn get_index_within_row_returns_that_row() {
        let m = mapper(vec![10, 20, 30]);
        assert_eq!(m.get_index(5), 0);
        assert_eq!(m.get_index(25), 1);
        assert_eq!(m.get_index(59), 2);
    }

    #[test]
    fn get_scroll_value_returns_zero_for_empty_model() {
        let m = mapper(vec![]);
        assert_eq!(m.get_scroll_value(0, 0, 0, 0), 0);
    }

    #[test]
    fn get_scroll_value_uses_layout_start_of_start_index() {
        let m = mapper(vec![10, 20, 30]);
        assert_eq!(m.get_scroll_value(1, 2, 5, 100), 5); // layoutStarts[1] = 10, 10 - 5
        assert_eq!(m.get_scroll_value(2, 2, 0, 100), 30); // layoutStarts[2] = 30
    }

    #[test]
    fn get_vertical_offset_returns_zero_for_empty_model() {
        let m = mapper(vec![]);
        assert_eq!(m.get_vertical_offset(0), 0);
    }

    #[test]
    fn get_vertical_offset_at_exact_row_start_is_zero() {
        let m = mapper(vec![10, 20, 30]);
        assert_eq!(m.get_vertical_offset(10), 0);
    }

    #[test]
    fn set_visible_view_height_is_a_no_op() {
        let mut m = mapper(vec![10, 20, 30]);
        m.set_visible_view_height(500);
        assert_eq!(m.get_view_height(), 60);
    }

    #[test]
    fn index_model_data_changed_within_range_adjusts_trailing_layout() {
        let mut m = mapper(vec![10, 20, 30]);
        m.heights_mut_for_test()[1] = 50;
        m.index_model_data_changed(1, 1);
        // row 1 now starts at 10 and is 50 tall, so row 2 shifts from 30 to 60.
        assert_eq!(m.get_index(60), 2);
        assert_eq!(m.get_view_height(), 90);
    }

    #[test]
    fn index_model_data_changed_through_last_row_recomputes_view_height() {
        let mut m = mapper(vec![10, 20, 30]);
        m.heights_mut_for_test()[2] = 100;
        m.index_model_data_changed(2, 2);
        assert_eq!(m.get_view_height(), 130);
    }

    impl PreMappedViewToIndexMapper<FakeScrollable> {
        fn heights_mut_for_test(&mut self) -> &mut Vec<i32> {
            &mut self.model.heights
        }
    }
}
