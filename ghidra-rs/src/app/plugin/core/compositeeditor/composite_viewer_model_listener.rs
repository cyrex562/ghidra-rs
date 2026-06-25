/// Listener for changes in the composite viewer model.
///
/// This trait provides notifications for various state changes in the CompositeViewerModel,
/// including component data changes, composite information changes, status updates, and
/// selection changes.
pub trait CompositeViewerModelListener {
    /// Called whenever the composite's component data is changed.
    fn component_data_changed(&self);

    /// Called whenever the composite's non-component data is changed.
    ///
    /// Examples of non-component data include the composite's name, description, size, etc.
    fn composite_info_changed(&self);

    /// Called when the composite viewer model's status information has changed.
    ///
    /// # Arguments
    /// * `message` - The information to provide to the user
    /// * `beep` - Whether an audible beep is suggested
    fn status_changed(&self, message: &str, beep: bool);

    /// Called to indicate the model's component selection has changed.
    fn selection_changed(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockCompositeViewerModelListener {
        component_data_changes: RefCell<Vec<()>>,
        composite_info_changes: RefCell<Vec<()>>,
        status_changes: RefCell<Vec<(String, bool)>>,
        selection_changes: RefCell<Vec<()>>,
    }

    impl MockCompositeViewerModelListener {
        fn new() -> Self {
            Self {
                component_data_changes: RefCell::new(Vec::new()),
                composite_info_changes: RefCell::new(Vec::new()),
                status_changes: RefCell::new(Vec::new()),
                selection_changes: RefCell::new(Vec::new()),
            }
        }

        fn component_data_change_count(&self) -> usize {
            self.component_data_changes.borrow().len()
        }

        fn composite_info_change_count(&self) -> usize {
            self.composite_info_changes.borrow().len()
        }

        fn status_changes(&self) -> Vec<(String, bool)> {
            self.status_changes.borrow().clone()
        }

        fn selection_change_count(&self) -> usize {
            self.selection_changes.borrow().len()
        }
    }

    impl CompositeViewerModelListener for MockCompositeViewerModelListener {
        fn component_data_changed(&self) {
            self.component_data_changes.borrow_mut().push(());
        }

        fn composite_info_changed(&self) {
            self.composite_info_changes.borrow_mut().push(());
        }

        fn status_changed(&self, message: &str, beep: bool) {
            self.status_changes
                .borrow_mut()
                .push((message.to_string(), beep));
        }

        fn selection_changed(&self) {
            self.selection_changes.borrow_mut().push(());
        }
    }

    #[test]
    fn test_component_data_changed() {
        let listener = MockCompositeViewerModelListener::new();
        listener.component_data_changed();
        assert_eq!(listener.component_data_change_count(), 1);
    }

    #[test]
    fn test_component_data_changed_multiple() {
        let listener = MockCompositeViewerModelListener::new();
        listener.component_data_changed();
        listener.component_data_changed();
        listener.component_data_changed();
        assert_eq!(listener.component_data_change_count(), 3);
    }

    #[test]
    fn test_composite_info_changed() {
        let listener = MockCompositeViewerModelListener::new();
        listener.composite_info_changed();
        assert_eq!(listener.composite_info_change_count(), 1);
    }

    #[test]
    fn test_composite_info_changed_multiple() {
        let listener = MockCompositeViewerModelListener::new();
        listener.composite_info_changed();
        listener.composite_info_changed();
        assert_eq!(listener.composite_info_change_count(), 2);
    }

    #[test]
    fn test_status_changed_with_beep() {
        let listener = MockCompositeViewerModelListener::new();
        listener.status_changed("Operation complete", true);
        assert_eq!(
            listener.status_changes(),
            vec![("Operation complete".to_string(), true)]
        );
    }

    #[test]
    fn test_status_changed_without_beep() {
        let listener = MockCompositeViewerModelListener::new();
        listener.status_changed("Status update", false);
        assert_eq!(
            listener.status_changes(),
            vec![("Status update".to_string(), false)]
        );
    }

    #[test]
    fn test_status_changed_empty_message() {
        let listener = MockCompositeViewerModelListener::new();
        listener.status_changed("", false);
        assert_eq!(
            listener.status_changes(),
            vec![("".to_string(), false)]
        );
    }

    #[test]
    fn test_status_changed_multiple_updates() {
        let listener = MockCompositeViewerModelListener::new();
        listener.status_changed("Status 1", true);
        listener.status_changed("Status 2", false);
        listener.status_changed("Status 3", true);
        assert_eq!(
            listener.status_changes(),
            vec![
                ("Status 1".to_string(), true),
                ("Status 2".to_string(), false),
                ("Status 3".to_string(), true),
            ]
        );
    }

    #[test]
    fn test_selection_changed() {
        let listener = MockCompositeViewerModelListener::new();
        listener.selection_changed();
        assert_eq!(listener.selection_change_count(), 1);
    }

    #[test]
    fn test_selection_changed_multiple() {
        let listener = MockCompositeViewerModelListener::new();
        listener.selection_changed();
        listener.selection_changed();
        listener.selection_changed();
        assert_eq!(listener.selection_change_count(), 3);
    }

    #[test]
    fn test_all_callbacks() {
        let listener = MockCompositeViewerModelListener::new();
        listener.component_data_changed();
        listener.composite_info_changed();
        listener.status_changed("Test status", true);
        listener.selection_changed();

        assert_eq!(listener.component_data_change_count(), 1);
        assert_eq!(listener.composite_info_change_count(), 1);
        assert_eq!(listener.status_changes(), vec![("Test status".to_string(), true)]);
        assert_eq!(listener.selection_change_count(), 1);
    }

    #[test]
    fn test_mixed_operations() {
        let listener = MockCompositeViewerModelListener::new();
        listener.component_data_changed();
        listener.component_data_changed();
        listener.composite_info_changed();
        listener.status_changed("First", false);
        listener.selection_changed();
        listener.status_changed("Second", true);
        listener.selection_changed();
        listener.composite_info_changed();

        assert_eq!(listener.component_data_change_count(), 2);
        assert_eq!(listener.composite_info_change_count(), 2);
        assert_eq!(
            listener.status_changes(),
            vec![
                ("First".to_string(), false),
                ("Second".to_string(), true),
            ]
        );
        assert_eq!(listener.selection_change_count(), 2);
    }
}
