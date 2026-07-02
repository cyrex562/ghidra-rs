/// Listener for composite viewer model component selection changes.
///
/// Notifies observers when the composite model's component selection has changed.
pub trait CompositeModelSelectionListener {
    /// Called to indicate the model's component selection has changed.
    fn selection_changed(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCompositeModelSelectionListener {
        selection_change_count: std::cell::RefCell<u32>,
    }

    impl MockCompositeModelSelectionListener {
        fn new() -> Self {
            Self {
                selection_change_count: std::cell::RefCell::new(0),
            }
        }

        fn get_selection_change_count(&self) -> u32 {
            *self.selection_change_count.borrow()
        }
    }

    impl CompositeModelSelectionListener for MockCompositeModelSelectionListener {
        fn selection_changed(&self) {
            *self.selection_change_count.borrow_mut() += 1;
        }
    }

    #[test]
    fn test_selection_changed_single() {
        let listener = MockCompositeModelSelectionListener::new();
        listener.selection_changed();
        assert_eq!(listener.get_selection_change_count(), 1);
    }

    #[test]
    fn test_selection_changed_multiple() {
        let listener = MockCompositeModelSelectionListener::new();
        listener.selection_changed();
        listener.selection_changed();
        listener.selection_changed();
        assert_eq!(listener.get_selection_change_count(), 3);
    }

    #[test]
    fn test_selection_changed_counter_increments() {
        let listener = MockCompositeModelSelectionListener::new();
        assert_eq!(listener.get_selection_change_count(), 0);
        listener.selection_changed();
        assert_eq!(listener.get_selection_change_count(), 1);
        listener.selection_changed();
        assert_eq!(listener.get_selection_change_count(), 2);
    }
}
