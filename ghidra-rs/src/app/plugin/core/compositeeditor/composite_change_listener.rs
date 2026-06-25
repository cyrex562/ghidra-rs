/// Listener for changes in a composite data type.
///
/// Indicates the ordinal of the component which has been added, updated or cleared.
pub trait CompositeChangeListener {
    /// Called when a component in the composite has been added, updated, or cleared.
    ///
    /// # Arguments
    /// * `ordinal` - The ordinal (index) of the component that changed
    fn component_changed(&self, ordinal: i32);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCompositeChangeListener {
        changed_ordinals: std::cell::RefCell<Vec<i32>>,
    }

    impl MockCompositeChangeListener {
        fn new() -> Self {
            Self {
                changed_ordinals: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn get_changed_ordinals(&self) -> Vec<i32> {
            self.changed_ordinals.borrow().clone()
        }
    }

    impl CompositeChangeListener for MockCompositeChangeListener {
        fn component_changed(&self, ordinal: i32) {
            self.changed_ordinals.borrow_mut().push(ordinal);
        }
    }

    #[test]
    fn test_component_changed_zero() {
        let listener = MockCompositeChangeListener::new();
        listener.component_changed(0);
        assert_eq!(listener.get_changed_ordinals(), vec![0]);
    }

    #[test]
    fn test_component_changed_positive() {
        let listener = MockCompositeChangeListener::new();
        listener.component_changed(5);
        assert_eq!(listener.get_changed_ordinals(), vec![5]);
    }

    #[test]
    fn test_component_changed_multiple() {
        let listener = MockCompositeChangeListener::new();
        listener.component_changed(0);
        listener.component_changed(1);
        listener.component_changed(5);
        assert_eq!(listener.get_changed_ordinals(), vec![0, 1, 5]);
    }

    #[test]
    fn test_component_changed_negative() {
        let listener = MockCompositeChangeListener::new();
        listener.component_changed(-1);
        assert_eq!(listener.get_changed_ordinals(), vec![-1]);
    }
}
