/// Listener for composite model data changes.
///
/// Notifies observers when the composite model's component or composite data is changed.
pub trait CompositeModelDataListener {
    /// Called whenever the composite's component data is changed.
    fn component_data_changed(&self);

    /// Called whenever the composite's non-component data is changed.
    ///
    /// For example, the composite's name, description, size, etc.
    fn composite_info_changed(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockCompositeModelDataListener {
        component_data_changes: RefCell<u32>,
        composite_info_changes: RefCell<u32>,
    }

    impl MockCompositeModelDataListener {
        fn new() -> Self {
            Self {
                component_data_changes: RefCell::new(0),
                composite_info_changes: RefCell::new(0),
            }
        }

        fn get_component_data_change_count(&self) -> u32 {
            *self.component_data_changes.borrow()
        }

        fn get_composite_info_change_count(&self) -> u32 {
            *self.composite_info_changes.borrow()
        }
    }

    impl CompositeModelDataListener for MockCompositeModelDataListener {
        fn component_data_changed(&self) {
            *self.component_data_changes.borrow_mut() += 1;
        }

        fn composite_info_changed(&self) {
            *self.composite_info_changes.borrow_mut() += 1;
        }
    }

    #[test]
    fn test_component_data_changed_single() {
        let listener = MockCompositeModelDataListener::new();
        listener.component_data_changed();
        assert_eq!(listener.get_component_data_change_count(), 1);
    }

    #[test]
    fn test_component_data_changed_multiple() {
        let listener = MockCompositeModelDataListener::new();
        listener.component_data_changed();
        listener.component_data_changed();
        listener.component_data_changed();
        assert_eq!(listener.get_component_data_change_count(), 3);
    }

    #[test]
    fn test_composite_info_changed_single() {
        let listener = MockCompositeModelDataListener::new();
        listener.composite_info_changed();
        assert_eq!(listener.get_composite_info_change_count(), 1);
    }

    #[test]
    fn test_composite_info_changed_multiple() {
        let listener = MockCompositeModelDataListener::new();
        listener.composite_info_changed();
        listener.composite_info_changed();
        assert_eq!(listener.get_composite_info_change_count(), 2);
    }

    #[test]
    fn test_independent_change_tracking() {
        let listener = MockCompositeModelDataListener::new();
        listener.component_data_changed();
        listener.composite_info_changed();
        listener.component_data_changed();
        assert_eq!(listener.get_component_data_change_count(), 2);
        assert_eq!(listener.get_composite_info_change_count(), 1);
    }
}
