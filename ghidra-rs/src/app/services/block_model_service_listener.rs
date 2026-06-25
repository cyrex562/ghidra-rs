/// Listener trait for `BlockModelService`.
///
/// Implementations of this trait can register with a `BlockModelService` to receive
/// notifications when block models are added or removed.
pub trait BlockModelServiceListener {
    /// Called when a model is added.
    ///
    /// # Arguments
    /// * `model_name` - The name of the block model that was added
    /// * `model_type` - The type of block model that was added
    fn model_added(&self, model_name: &str, model_type: i32);

    /// Called when a model is removed.
    ///
    /// # Arguments
    /// * `model_name` - The name of the block model that was removed
    /// * `model_type` - The type of block model that was removed
    fn model_removed(&self, model_name: &str, model_type: i32);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct MockListener {
        added_events: Rc<RefCell<Vec<(String, i32)>>>,
        removed_events: Rc<RefCell<Vec<(String, i32)>>>,
    }

    impl MockListener {
        fn new() -> Self {
            MockListener {
                added_events: Rc::new(RefCell::new(Vec::new())),
                removed_events: Rc::new(RefCell::new(Vec::new())),
            }
        }

        fn added_events(&self) -> Rc<RefCell<Vec<(String, i32)>>> {
            Rc::clone(&self.added_events)
        }

        fn removed_events(&self) -> Rc<RefCell<Vec<(String, i32)>>> {
            Rc::clone(&self.removed_events)
        }
    }

    impl BlockModelServiceListener for MockListener {
        fn model_added(&self, model_name: &str, model_type: i32) {
            self.added_events
                .borrow_mut()
                .push((model_name.to_string(), model_type));
        }

        fn model_removed(&self, model_name: &str, model_type: i32) {
            self.removed_events
                .borrow_mut()
                .push((model_name.to_string(), model_type));
        }
    }

    #[test]
    fn test_model_added_notification() {
        let listener = MockListener::new();
        listener.model_added("test_model", 1);

        let events = listener.added_events();
        assert_eq!(events.borrow().len(), 1);
        assert_eq!(events.borrow()[0].0, "test_model");
        assert_eq!(events.borrow()[0].1, 1);
    }

    #[test]
    fn test_model_removed_notification() {
        let listener = MockListener::new();
        listener.model_removed("test_model", 1);

        let events = listener.removed_events();
        assert_eq!(events.borrow().len(), 1);
        assert_eq!(events.borrow()[0].0, "test_model");
        assert_eq!(events.borrow()[0].1, 1);
    }

    #[test]
    fn test_multiple_notifications() {
        let listener = MockListener::new();

        listener.model_added("model1", 0);
        listener.model_added("model2", 1);
        listener.model_removed("model1", 0);

        let added = listener.added_events();
        assert_eq!(added.borrow().len(), 2);
        assert_eq!(added.borrow()[0], ("model1".to_string(), 0));
        assert_eq!(added.borrow()[1], ("model2".to_string(), 1));

        let removed = listener.removed_events();
        assert_eq!(removed.borrow().len(), 1);
        assert_eq!(removed.borrow()[0], ("model1".to_string(), 0));
    }

    #[test]
    fn test_model_name_preserved() {
        let listener = MockListener::new();
        let model_name = "complex_model_name_123";

        listener.model_added(model_name, 42);

        let events = listener.added_events();
        assert_eq!(events.borrow()[0].0, model_name);
    }

    #[test]
    fn test_model_type_preserved() {
        let listener = MockListener::new();
        let model_type = 12345;

        listener.model_added("model", model_type);

        let events = listener.added_events();
        assert_eq!(events.borrow()[0].1, model_type);
    }
}
