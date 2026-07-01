/// Interface for scrolling a FieldPanel or container of a group of FieldPanels which displays
/// a list of displayable items (layouts).
///
/// Corresponds to `docking.widgets.indexedscrollpane.IndexedScrollable`.
///
/// Java's `BigInteger` index parameters are represented as `i128`.
/// Java's `int` pixel-offset parameters are represented as `i32`.
pub trait IndexedScrollable {
    /// Returns the number individually addressable items displayed.
    fn get_index_count(&self) -> i128;

    /// Returns true if all the items are the same vertical size.
    fn is_uniform_index(&self) -> bool;

    /// Returns the height of the n'th item.
    ///
    /// # Arguments
    /// * `index` - the index of the item to get height for
    fn get_height(&self, index: i128) -> i32;

    /// Makes the item at the given index be visible on the screen at the given vertical offset.
    ///
    /// # Arguments
    /// * `index` - the index of the item to show
    /// * `vertical_offset` - the number of pixels from the top of the screen to show the item
    fn show_index(&mut self, index: i128, vertical_offset: i32);

    /// Returns the index of the next non-null item. Not all indexes have items; some items span
    /// multiple indexes.
    ///
    /// # Arguments
    /// * `index` - the index to start searching for the next non-null item
    ///
    /// # Returns
    /// The index of the next non-null item, or -1 if there is none.
    fn get_index_after(&self, index: i128) -> i128;

    /// Returns the index of the previous non-null item. Not all indexes have items; some items span
    /// multiple indexes.
    ///
    /// # Arguments
    /// * `index` - the index to start searching backwards for the previous non-null item
    ///
    /// # Returns
    /// The index of the previous non-null item, or -1 if there is none.
    fn get_index_before(&self, index: i128) -> i128;

    /// Scrolls the displayed items up by the height of one line of text.
    fn scroll_line_up(&mut self);

    /// Scrolls the displayed items down by the height of one line of text.
    fn scroll_line_down(&mut self);

    /// Scrolls the displayed items up by the height of one screen of text.
    fn scroll_page_up(&mut self);

    /// Scrolls the displayed items down by the height of one screen of text.
    fn scroll_page_down(&mut self);

    /// Adds a listener to be notified when the view is scrolled in any way.
    ///
    /// # Arguments
    /// * `listener` - the listener to be notified when the visible items change
    fn add_index_scroll_listener(&mut self, listener: Box<dyn IndexScrollListenerAdapter>);

    /// Removes the given listener from those to be notified when the view changes.
    ///
    /// # Arguments
    /// * `listener` - the listener to remove
    fn remove_index_scroll_listener(&mut self, listener: Box<dyn IndexScrollListenerAdapter>);

    /// Notify the scrollable that the mouse wheel was moved.
    ///
    /// # Arguments
    /// * `precise_wheel_rotation` - the amount of rotation of the wheel
    /// * `is_horizontal` - true if the rotation was horizontal, false for vertical
    fn mouse_wheel_moved(&mut self, precise_wheel_rotation: f64, is_horizontal: bool);
}

/// Adapter trait for adding and removing IndexScrollListener implementations.
///
/// This is used for dynamic listener management in IndexedScrollable implementations.
pub trait IndexScrollListenerAdapter: Send {
    /// Clone this listener adapter into a boxed trait object.
    fn clone_box(&self) -> Box<dyn IndexScrollListenerAdapter>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock implementation for testing.
    struct MockScrollable {
        index_count: i128,
        uniform: bool,
        heights: Vec<i32>,
        listeners_added: usize,
        listeners_removed: usize,
        last_show_index: Option<(i128, i32)>,
        scroll_calls: Vec<String>,
        wheel_calls: Vec<(f64, bool)>,
    }

    impl MockScrollable {
        fn new(index_count: i128, uniform: bool) -> Self {
            Self {
                index_count,
                uniform,
                heights: vec![20; index_count as usize],
                listeners_added: 0,
                listeners_removed: 0,
                last_show_index: None,
                scroll_calls: vec![],
                wheel_calls: vec![],
            }
        }
    }

    struct NoOpListener;
    impl IndexScrollListenerAdapter for NoOpListener {
        fn clone_box(&self) -> Box<dyn IndexScrollListenerAdapter> {
            Box::new(NoOpListener)
        }
    }

    impl IndexedScrollable for MockScrollable {
        fn get_index_count(&self) -> i128 {
            self.index_count
        }

        fn is_uniform_index(&self) -> bool {
            self.uniform
        }

        fn get_height(&self, index: i128) -> i32 {
            if index >= 0 && (index as usize) < self.heights.len() {
                self.heights[index as usize]
            } else {
                0
            }
        }

        fn show_index(&mut self, index: i128, vertical_offset: i32) {
            self.last_show_index = Some((index, vertical_offset));
        }

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

        fn scroll_line_up(&mut self) {
            self.scroll_calls.push("line_up".to_string());
        }

        fn scroll_line_down(&mut self) {
            self.scroll_calls.push("line_down".to_string());
        }

        fn scroll_page_up(&mut self) {
            self.scroll_calls.push("page_up".to_string());
        }

        fn scroll_page_down(&mut self) {
            self.scroll_calls.push("page_down".to_string());
        }

        fn add_index_scroll_listener(&mut self, _listener: Box<dyn IndexScrollListenerAdapter>) {
            self.listeners_added += 1;
        }

        fn remove_index_scroll_listener(&mut self, _listener: Box<dyn IndexScrollListenerAdapter>) {
            self.listeners_removed += 1;
        }

        fn mouse_wheel_moved(&mut self, rotation: f64, is_horizontal: bool) {
            self.wheel_calls.push((rotation, is_horizontal));
        }
    }

    #[test]
    fn get_index_count_returns_set_value() {
        let m = MockScrollable::new(100, false);
        assert_eq!(m.get_index_count(), 100);
    }

    #[test]
    fn is_uniform_index_returns_set_value() {
        let uniform = MockScrollable::new(50, true);
        let non_uniform = MockScrollable::new(50, false);
        assert!(uniform.is_uniform_index());
        assert!(!non_uniform.is_uniform_index());
    }

    #[test]
    fn get_height_returns_valid_heights() {
        let m = MockScrollable::new(5, true);
        assert_eq!(m.get_height(0), 20);
        assert_eq!(m.get_height(4), 20);
        assert_eq!(m.get_height(5), 0);
    }

    #[test]
    fn show_index_records_index_and_offset() {
        let mut m = MockScrollable::new(100, true);
        m.show_index(42, 15);
        assert_eq!(m.last_show_index, Some((42, 15)));
    }

    #[test]
    fn get_index_after_next_when_valid() {
        let m = MockScrollable::new(100, false);
        assert_eq!(m.get_index_after(0), 1);
        assert_eq!(m.get_index_after(50), 51);
    }

    #[test]
    fn get_index_after_returns_minus_one_at_end() {
        let m = MockScrollable::new(10, false);
        assert_eq!(m.get_index_after(9), -1);
    }

    #[test]
    fn get_index_before_previous_when_valid() {
        let m = MockScrollable::new(100, false);
        assert_eq!(m.get_index_before(10), 9);
        assert_eq!(m.get_index_before(50), 49);
    }

    #[test]
    fn get_index_before_returns_minus_one_at_start() {
        let m = MockScrollable::new(100, false);
        assert_eq!(m.get_index_before(0), -1);
    }

    #[test]
    fn scroll_line_up_is_recorded() {
        let mut m = MockScrollable::new(100, true);
        m.scroll_line_up();
        assert_eq!(m.scroll_calls, vec!["line_up"]);
    }

    #[test]
    fn scroll_line_down_is_recorded() {
        let mut m = MockScrollable::new(100, true);
        m.scroll_line_down();
        assert_eq!(m.scroll_calls, vec!["line_down"]);
    }

    #[test]
    fn scroll_page_up_is_recorded() {
        let mut m = MockScrollable::new(100, true);
        m.scroll_page_up();
        assert_eq!(m.scroll_calls, vec!["page_up"]);
    }

    #[test]
    fn scroll_page_down_is_recorded() {
        let mut m = MockScrollable::new(100, true);
        m.scroll_page_down();
        assert_eq!(m.scroll_calls, vec!["page_down"]);
    }

    #[test]
    fn scroll_operations_sequence() {
        let mut m = MockScrollable::new(100, true);
        m.scroll_line_up();
        m.scroll_page_down();
        m.scroll_line_down();
        assert_eq!(m.scroll_calls, vec!["line_up", "page_down", "line_down"]);
    }

    #[test]
    fn add_listener_increments_count() {
        let mut m = MockScrollable::new(100, true);
        let listener = Box::new(NoOpListener);
        m.add_index_scroll_listener(listener);
        assert_eq!(m.listeners_added, 1);
    }

    #[test]
    fn remove_listener_increments_count() {
        let mut m = MockScrollable::new(100, true);
        let listener = Box::new(NoOpListener);
        m.remove_index_scroll_listener(listener);
        assert_eq!(m.listeners_removed, 1);
    }

    #[test]
    fn mouse_wheel_moved_vertical() {
        let mut m = MockScrollable::new(100, true);
        m.mouse_wheel_moved(1.5, false);
        assert_eq!(m.wheel_calls, vec![(1.5, false)]);
    }

    #[test]
    fn mouse_wheel_moved_horizontal() {
        let mut m = MockScrollable::new(100, true);
        m.mouse_wheel_moved(2.0, true);
        assert_eq!(m.wheel_calls, vec![(2.0, true)]);
    }

    #[test]
    fn mouse_wheel_moved_multiple_calls() {
        let mut m = MockScrollable::new(100, true);
        m.mouse_wheel_moved(1.0, false);
        m.mouse_wheel_moved(2.0, true);
        m.mouse_wheel_moved(-0.5, false);
        assert_eq!(m.wheel_calls, vec![(1.0, false), (2.0, true), (-0.5, false)]);
    }

    #[test]
    fn large_index_values() {
        let m = MockScrollable::new(i128::MAX, false);
        assert_eq!(m.get_index_count(), i128::MAX);
        assert_eq!(m.get_index_after(0), 1);
    }

    #[test]
    fn negative_index_handling() {
        let m = MockScrollable::new(100, false);
        assert_eq!(m.get_index_before(-1), -1);
        assert_eq!(m.get_height(-1), 0);
    }
}
