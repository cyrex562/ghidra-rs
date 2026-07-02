use std::cell::Cell;

use super::{IndexedScrollable, ViewToIndexMapper};

/// At this scroll value Java has a bug, so the view height is capped below it.
const MAX_SCROLL_VALUE: i32 = i32::MAX / 2;
const AVERAGE_HEIGHT: f64 = 20.0;

/// Default implementation of [`ViewToIndexMapper`] that approximates a mapping between
/// pixel scroll values and logical indexes by assuming a fixed average row height, then
/// self-correcting as the actual visible range is reported via [`get_scroll_value`].
///
/// Corresponds to `docking.widgets.indexedscrollpane.DefaultViewToIndexMapper`.
///
/// [`get_scroll_value`]: ViewToIndexMapper::get_scroll_value
pub struct DefaultViewToIndexMapper<M: IndexedScrollable> {
    model: M,
    screen_height: i32,
    view_height: i32,
    last_index: i128,
    last_start_index: Cell<i128>,
    x_factor: Cell<f64>,
    last_start_y: Cell<i32>,
    end_validated: Cell<bool>,
}

impl<M: IndexedScrollable> DefaultViewToIndexMapper<M> {
    /// Creates a new mapper over `model`, given the current visible screen height in pixels.
    pub fn new(model: M, screen_height: i32) -> Self {
        let mut mapper = Self {
            model,
            screen_height,
            view_height: 0,
            last_index: 0,
            last_start_index: Cell::new(0),
            x_factor: Cell::new(0.0),
            last_start_y: Cell::new(0),
            end_validated: Cell::new(false),
        };
        mapper.reset_state();
        mapper
    }

    fn reset_state(&mut self) {
        let index_count = self.model.get_index_count();
        self.last_index = index_count - 1;
        let total_height = index_count as f64 * AVERAGE_HEIGHT;

        self.view_height = if total_height > MAX_SCROLL_VALUE as f64 {
            MAX_SCROLL_VALUE
        } else {
            total_height as i32
        };

        self.x_factor
            .set(self.last_index as f64 / (self.view_height - self.screen_height) as f64);
        self.last_start_index.set(self.last_index);
        self.last_start_y.set(0);
        self.end_validated.set(false);
    }
}

impl<M: IndexedScrollable> ViewToIndexMapper for DefaultViewToIndexMapper<M> {
    fn get_view_height(&self) -> i32 {
        self.view_height
    }

    fn get_index(&self, value: i32) -> i128 {
        if value == self.view_height - self.screen_height {
            return self.last_index;
        }
        let dindex = value as f64 * self.x_factor.get();
        dindex as i128
    }

    fn get_vertical_offset(&self, _value: i32) -> i32 {
        0
    }

    fn set_visible_view_height(&mut self, height: i32) {
        self.screen_height = height;
        self.reset_state();
    }

    fn get_scroll_value(
        &self,
        start_index: i128,
        end_index: i128,
        y_start: i32,
        y_end: i32,
    ) -> i32 {
        if !self.end_validated.get() && end_index == self.last_index && y_end <= self.screen_height
        {
            self.last_start_index.set(start_index);
            self.last_start_y.set(y_start);
            self.x_factor
                .set(start_index as f64 / (self.view_height - self.screen_height) as f64);
            self.end_validated.set(true);
        }

        if start_index == 0 && y_start == 0 {
            return 0;
        }

        if start_index == self.last_start_index.get() && y_start == self.last_start_y.get() {
            return self.view_height - self.screen_height;
        }

        let scroll_value = start_index as f64 / self.x_factor.get();
        let value = (scroll_value + 0.5) as i32;

        if value == 0 {
            return 1;
        }

        if value >= self.view_height - self.screen_height {
            return self.view_height - self.screen_height - 1;
        }
        value
    }

    fn index_model_data_changed(&mut self, _start: i128, end: i128) {
        if end >= self.last_index {
            self.reset_state();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::IndexScrollListenerAdapter;

    struct FakeScrollable {
        index_count: i128,
    }

    impl IndexedScrollable for FakeScrollable {
        fn get_index_count(&self) -> i128 {
            self.index_count
        }

        fn is_uniform_index(&self) -> bool {
            true
        }

        fn get_height(&self, _index: i128) -> i32 {
            20
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

    fn mapper(index_count: i128, screen_height: i32) -> DefaultViewToIndexMapper<FakeScrollable> {
        DefaultViewToIndexMapper::new(FakeScrollable { index_count }, screen_height)
    }

    #[test]
    fn new_computes_view_height_from_average_row_height() {
        let m = mapper(100, 400);
        assert_eq!(m.get_view_height(), 2000); // 100 * 20
    }

    #[test]
    fn new_caps_view_height_at_max_scroll_value() {
        let m = mapper(i128::from(i32::MAX), 400);
        assert_eq!(m.get_view_height(), MAX_SCROLL_VALUE);
    }

    #[test]
    fn get_index_at_bottom_of_view_returns_last_index() {
        let m = mapper(100, 400);
        let bottom = m.get_view_height() - 400;
        assert_eq!(m.get_index(bottom), 99);
    }

    #[test]
    fn get_index_at_top_returns_zero() {
        let m = mapper(100, 400);
        assert_eq!(m.get_index(0), 0);
    }

    #[test]
    fn get_index_scales_linearly_with_average_height() {
        let m = mapper(100, 0);
        // view_height = 2000, screen_height = 0, so x_factor = 99/2000
        assert_eq!(m.get_index(1000), 49);
    }

    #[test]
    fn get_vertical_offset_is_always_zero() {
        let m = mapper(100, 400);
        assert_eq!(m.get_vertical_offset(0), 0);
        assert_eq!(m.get_vertical_offset(12345), 0);
    }

    #[test]
    fn set_visible_view_height_updates_screen_height_and_resets() {
        let mut m = mapper(100, 400);
        m.set_visible_view_height(200);
        let bottom = m.get_view_height() - 200;
        assert_eq!(m.get_index(bottom), 99);
    }

    #[test]
    fn get_scroll_value_start_at_zero_returns_zero() {
        let m = mapper(100, 400);
        assert_eq!(m.get_scroll_value(0, 50, 0, 400), 0);
    }

    #[test]
    fn get_scroll_value_validates_end_and_caches_last_start() {
        let m = mapper(100, 400);
        // end_index == last_index (99) and y_end <= screen_height validates the end.
        let scroll = m.get_scroll_value(90, 99, 350, 400);
        assert_eq!(scroll, m.get_view_height() - 400);

        // Repeating the same validated start/y returns the cached bottom scroll value.
        let scroll_again = m.get_scroll_value(90, 99, 350, 400);
        assert_eq!(scroll_again, m.get_view_height() - 400);
    }

    #[test]
    fn get_scroll_value_mid_range_is_between_bounds() {
        let m = mapper(100, 400);
        let value = m.get_scroll_value(50, 60, 100, 500);
        assert!(value > 0 && value < m.get_view_height() - 400);
    }

    #[test]
    fn index_model_data_changed_within_range_does_not_reset_view_height() {
        let mut m = mapper(100, 400);
        let original_height = m.get_view_height();
        m.index_model_data_changed(0, 50);
        assert_eq!(m.get_view_height(), original_height);
    }

    #[test]
    fn index_model_data_changed_past_last_index_resets_state() {
        let mut m = mapper(100, 400);
        m.index_model_data_changed(50, 99);
        // resetState recomputed from the (unchanged) model, so view height is stable,
        // but the cached last-start state used for scroll-value caching is cleared.
        assert_eq!(m.get_view_height(), 2000);
        assert_eq!(m.get_scroll_value(0, 0, 0, 0), 0);
    }
}
