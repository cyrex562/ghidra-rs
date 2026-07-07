use crate::program::model::address::AddressSetView;

/// Listener for view changes in the program tree.
///
/// Implementations of this trait can register to receive notifications when the view changes
/// either because the user made a new selection or switched to a different view.
pub trait ViewChangeListener {
    /// Called when the view changes.
    ///
    /// # Arguments
    /// * `addr_set` - The new address set for the current view
    fn view_changed(&self, addr_set: &dyn AddressSetView);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSet;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct MockListener {
        calls: Rc<RefCell<Vec<bool>>>,
    }

    impl MockListener {
        fn new() -> Self {
            MockListener {
                calls: Rc::new(RefCell::new(Vec::new())),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.borrow().len()
        }
    }

    impl ViewChangeListener for MockListener {
        fn view_changed(&self, _addr_set: &dyn AddressSetView) {
            self.calls.borrow_mut().push(true);
        }
    }

    #[test]
    fn test_view_changed_called() {
        let listener = MockListener::new();
        let addr_set = AddressSet::new();
        listener.view_changed(&addr_set);
        assert_eq!(listener.call_count(), 1);
    }

    #[test]
    fn test_view_changed_multiple_calls() {
        let listener = MockListener::new();
        let addr_set = AddressSet::new();
        listener.view_changed(&addr_set);
        listener.view_changed(&addr_set);
        listener.view_changed(&addr_set);
        assert_eq!(listener.call_count(), 3);
    }

    #[test]
    fn test_empty_address_set() {
        let listener = MockListener::new();
        let empty_set = AddressSet::new();
        listener.view_changed(&empty_set);
        assert_eq!(listener.call_count(), 1);
    }

    #[test]
    fn test_multiple_listeners_independent() {
        let listener1 = MockListener::new();
        let listener2 = MockListener::new();
        let addr_set = AddressSet::new();

        listener1.view_changed(&addr_set);
        listener2.view_changed(&addr_set);
        listener1.view_changed(&addr_set);

        assert_eq!(listener1.call_count(), 2);
        assert_eq!(listener2.call_count(), 1);
    }
}
