use super::comparison_item::ComparisonItem;

/// Interface implemented by structure displays that participate in coordinated scrolling
/// and selection.
///
/// This captures the subset of `ghidra.app.merge.structures.CoordinatedStructureDisplay`
/// that [`DisplayCoordinator`] requires.  The full egui-based display will implement this
/// trait when that class is ported.
pub trait CoordinatedStructureDisplay {
    /// Respond to a selection change that originated in another display.
    ///
    /// `selected_index` is the list index of the newly selected item; `item` is the
    /// selected item, or `None` if the selection was cleared.
    fn set_selected_item(&mut self, selected_index: i32, item: Option<&dyn ComparisonItem>);

    /// Respond to a horizontal scroll change that originated in another display.
    fn set_horizontal_scroll(&mut self, value: i32);

    /// Respond to a vertical scroll change that originated in another display.
    fn set_vertical_scroll(&mut self, value: i32);
}

/// Coordinates scrolling and line selection across a set of structure comparison displays.
///
/// A re-entrancy guard prevents feedback loops: if a notification is already being
/// dispatched any nested `notify_*` call returns immediately without looping.
///
/// In the Java source `CoordinatedStructureDisplay` objects pass themselves as a parameter
/// when notifying the coordinator, and each display skips itself inside `setSelectedItem` /
/// `setHorizontalScroll` / `setVerticalScroll` via reference equality.  In Rust, each
/// display is assigned a stable index on registration; the coordinator filters by index
/// instead, which achieves the same observable behaviour.
///
/// Mirrors `ghidra.app.merge.structures.DisplayCoordinator`.
pub struct DisplayCoordinator {
    displays: Vec<Box<dyn CoordinatedStructureDisplay>>,
    is_changing: bool,
}

impl DisplayCoordinator {
    /// Creates an empty coordinator.
    pub fn new() -> Self {
        Self { displays: Vec::new(), is_changing: false }
    }

    /// Registers a display and returns its stable index.
    ///
    /// The caller must supply this index to subsequent `notify_*` calls to identify
    /// which display triggered the event.
    pub fn register_display(&mut self, display: Box<dyn CoordinatedStructureDisplay>) -> usize {
        let idx = self.displays.len();
        self.displays.push(display);
        idx
    }

    /// Notifies all displays except `source_idx` that the selection changed.
    ///
    /// Does nothing if a notification is already in progress.
    pub fn notify_selection_changed(
        &mut self,
        source_idx: usize,
        selected_index: i32,
        item: Option<&dyn ComparisonItem>,
    ) {
        if self.is_changing {
            return;
        }
        self.is_changing = true;
        for (i, display) in self.displays.iter_mut().enumerate() {
            if i != source_idx {
                display.set_selected_item(selected_index, item);
            }
        }
        self.is_changing = false;
    }

    /// Notifies all displays except `source_idx` that the horizontal scroll changed.
    ///
    /// Does nothing if a notification is already in progress.
    pub fn notify_horizontal_scroll_changed(&mut self, source_idx: usize, value: i32) {
        if self.is_changing {
            return;
        }
        self.is_changing = true;
        for (i, display) in self.displays.iter_mut().enumerate() {
            if i != source_idx {
                display.set_horizontal_scroll(value);
            }
        }
        self.is_changing = false;
    }

    /// Notifies all displays except `source_idx` that the vertical scroll changed.
    ///
    /// Does nothing if a notification is already in progress.
    pub fn notify_vertical_scroll_changed(&mut self, source_idx: usize, value: i32) {
        if self.is_changing {
            return;
        }
        self.is_changing = true;
        for (i, display) in self.displays.iter_mut().enumerate() {
            if i != source_idx {
                display.set_vertical_scroll(value);
            }
        }
        self.is_changing = false;
    }

    /// Directly sets the re-entrancy guard.
    ///
    /// Mirrors `DisplayCoordinator.setChanging()`.  Exposed for testing and for the
    /// rare case where external code must temporarily suppress notifications.
    pub fn set_changing(&mut self, changing: bool) {
        self.is_changing = changing;
    }
}

impl Default for DisplayCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    // ── test double ──────────────────────────────────────────────────────────────

    #[derive(Default)]
    struct MockState {
        selection_calls: Vec<(i32, bool)>,
        h_scroll_calls: Vec<i32>,
        v_scroll_calls: Vec<i32>,
    }

    struct SharedMock(Rc<RefCell<MockState>>);

    impl CoordinatedStructureDisplay for SharedMock {
        fn set_selected_item(&mut self, selected_index: i32, item: Option<&dyn ComparisonItem>) {
            self.0.borrow_mut().selection_calls.push((selected_index, item.is_some()));
        }
        fn set_horizontal_scroll(&mut self, value: i32) {
            self.0.borrow_mut().h_scroll_calls.push(value);
        }
        fn set_vertical_scroll(&mut self, value: i32) {
            self.0.borrow_mut().v_scroll_calls.push(value);
        }
    }

    struct MockItem;
    impl ComparisonItem for MockItem {
        fn line(&self) -> i32 { 0 }
        fn item_type(&self) -> &str { "mock" }
    }

    fn make_displays(n: usize) -> Vec<Rc<RefCell<MockState>>> {
        (0..n).map(|_| Rc::new(RefCell::new(MockState::default()))).collect()
    }

    fn build_coordinator(states: &[Rc<RefCell<MockState>>]) -> DisplayCoordinator {
        let mut coord = DisplayCoordinator::new();
        for state in states {
            coord.register_display(Box::new(SharedMock(Rc::clone(state))));
        }
        coord
    }

    // ── registration ─────────────────────────────────────────────────────────────

    #[test]
    fn new_coordinator_is_empty() {
        let coord = DisplayCoordinator::new();
        assert!(coord.displays.is_empty());
        assert!(!coord.is_changing);
    }

    #[test]
    fn register_display_returns_sequential_indices() {
        let mut coord = DisplayCoordinator::new();
        let states = make_displays(3);
        let ids: Vec<usize> = states
            .iter()
            .map(|s| coord.register_display(Box::new(SharedMock(Rc::clone(s)))))
            .collect();
        assert_eq!(ids, vec![0, 1, 2]);
    }

    // ── notify_selection_changed ─────────────────────────────────────────────────

    #[test]
    fn selection_skips_source_notifies_others() {
        let states = make_displays(3);
        let mut coord = build_coordinator(&states);
        let item = MockItem;

        coord.notify_selection_changed(1, 5, Some(&item));

        assert_eq!(states[0].borrow().selection_calls, vec![(5, true)]);
        assert!(states[1].borrow().selection_calls.is_empty()); // source skipped
        assert_eq!(states[2].borrow().selection_calls, vec![(5, true)]);
    }

    #[test]
    fn selection_with_none_item() {
        let states = make_displays(2);
        let mut coord = build_coordinator(&states);

        coord.notify_selection_changed(0, 3, None);

        assert!(states[0].borrow().selection_calls.is_empty());
        assert_eq!(states[1].borrow().selection_calls, vec![(3, false)]);
    }

    #[test]
    fn selection_reentrant_call_is_ignored() {
        let states = make_displays(2);
        let mut coord = build_coordinator(&states);
        let item = MockItem;

        coord.set_changing(true);
        coord.notify_selection_changed(0, 7, Some(&item));

        assert!(states[0].borrow().selection_calls.is_empty());
        assert!(states[1].borrow().selection_calls.is_empty());
    }

    #[test]
    fn selection_is_changing_reset_after_dispatch() {
        let states = make_displays(1);
        let mut coord = build_coordinator(&states);

        coord.notify_selection_changed(0, 0, None);
        assert!(!coord.is_changing);
    }

    // ── notify_horizontal_scroll_changed ─────────────────────────────────────────

    #[test]
    fn h_scroll_skips_source_notifies_others() {
        let states = make_displays(3);
        let mut coord = build_coordinator(&states);

        coord.notify_horizontal_scroll_changed(0, 42);

        assert!(states[0].borrow().h_scroll_calls.is_empty()); // source skipped
        assert_eq!(states[1].borrow().h_scroll_calls, vec![42]);
        assert_eq!(states[2].borrow().h_scroll_calls, vec![42]);
    }

    #[test]
    fn h_scroll_reentrant_call_is_ignored() {
        let states = make_displays(2);
        let mut coord = build_coordinator(&states);

        coord.set_changing(true);
        coord.notify_horizontal_scroll_changed(0, 99);

        assert!(states[1].borrow().h_scroll_calls.is_empty());
    }

    #[test]
    fn h_scroll_is_changing_reset_after_dispatch() {
        let states = make_displays(1);
        let mut coord = build_coordinator(&states);

        coord.notify_horizontal_scroll_changed(0, 0);
        assert!(!coord.is_changing);
    }

    // ── notify_vertical_scroll_changed ───────────────────────────────────────────

    #[test]
    fn v_scroll_skips_source_notifies_others() {
        let states = make_displays(3);
        let mut coord = build_coordinator(&states);

        coord.notify_vertical_scroll_changed(2, 100);

        assert_eq!(states[0].borrow().v_scroll_calls, vec![100]);
        assert_eq!(states[1].borrow().v_scroll_calls, vec![100]);
        assert!(states[2].borrow().v_scroll_calls.is_empty()); // source skipped
    }

    #[test]
    fn v_scroll_reentrant_call_is_ignored() {
        let states = make_displays(2);
        let mut coord = build_coordinator(&states);

        coord.set_changing(true);
        coord.notify_vertical_scroll_changed(0, 50);

        assert!(states[1].borrow().v_scroll_calls.is_empty());
    }

    #[test]
    fn v_scroll_is_changing_reset_after_dispatch() {
        let states = make_displays(1);
        let mut coord = build_coordinator(&states);

        coord.notify_vertical_scroll_changed(0, 0);
        assert!(!coord.is_changing);
    }

    // ── set_changing ─────────────────────────────────────────────────────────────

    #[test]
    fn set_changing_true_blocks_all_notifications() {
        let states = make_displays(2);
        let mut coord = build_coordinator(&states);

        coord.set_changing(true);
        coord.notify_horizontal_scroll_changed(0, 1);
        coord.notify_vertical_scroll_changed(0, 2);
        coord.notify_selection_changed(0, 3, None);

        assert!(states[1].borrow().h_scroll_calls.is_empty());
        assert!(states[1].borrow().v_scroll_calls.is_empty());
        assert!(states[1].borrow().selection_calls.is_empty());
    }

    #[test]
    fn set_changing_false_re_enables_notifications() {
        let states = make_displays(2);
        let mut coord = build_coordinator(&states);

        coord.set_changing(true);
        coord.set_changing(false);
        coord.notify_horizontal_scroll_changed(0, 7);

        assert_eq!(states[1].borrow().h_scroll_calls, vec![7]);
    }

    // ── multiple events ──────────────────────────────────────────────────────────

    #[test]
    fn multiple_scroll_events_accumulate() {
        let states = make_displays(2);
        let mut coord = build_coordinator(&states);

        coord.notify_horizontal_scroll_changed(0, 10);
        coord.notify_horizontal_scroll_changed(0, 20);
        coord.notify_horizontal_scroll_changed(0, 30);

        assert_eq!(states[1].borrow().h_scroll_calls, vec![10, 20, 30]);
    }

    #[test]
    fn default_impl_matches_new() {
        let a = DisplayCoordinator::new();
        let b = DisplayCoordinator::default();
        assert_eq!(a.displays.len(), b.displays.len());
        assert_eq!(a.is_changing, b.is_changing);
    }
}
