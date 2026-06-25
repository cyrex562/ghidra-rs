/// Listener for changes in the model state of a composite data type editor.
///
/// This trait provides a notification method for edit state changes in the
/// composite data type editor. The edit state can be either started or ended.
pub trait EditorModelListener {
    /// Edit state constant indicating editing has started.
    const EDIT_STARTED: i32 = 5;

    /// Edit state constant indicating editing has ended.
    const EDIT_ENDED: i32 = 6;

    /// Called whenever the composite data type editor model edit state changes.
    ///
    /// # Arguments
    /// * `edit_type` - The type of state change: `EDIT_STARTED` or `EDIT_ENDED`
    fn edit_state_changed(&self, edit_type: i32);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockEditorModelListener {
        edit_state_changes: RefCell<Vec<i32>>,
    }

    impl MockEditorModelListener {
        fn new() -> Self {
            Self {
                edit_state_changes: RefCell::new(Vec::new()),
            }
        }

        fn get_edit_state_changes(&self) -> Vec<i32> {
            self.edit_state_changes.borrow().clone()
        }
    }

    impl EditorModelListener for MockEditorModelListener {
        fn edit_state_changed(&self, edit_type: i32) {
            self.edit_state_changes.borrow_mut().push(edit_type);
        }
    }

    #[test]
    fn test_edit_started_constant() {
        assert_eq!(MockEditorModelListener::EDIT_STARTED, 5);
    }

    #[test]
    fn test_edit_ended_constant() {
        assert_eq!(MockEditorModelListener::EDIT_ENDED, 6);
    }

    #[test]
    fn test_edit_state_changed_started() {
        let listener = MockEditorModelListener::new();
        listener.edit_state_changed(MockEditorModelListener::EDIT_STARTED);
        assert_eq!(listener.get_edit_state_changes(), vec![5]);
    }

    #[test]
    fn test_edit_state_changed_ended() {
        let listener = MockEditorModelListener::new();
        listener.edit_state_changed(MockEditorModelListener::EDIT_ENDED);
        assert_eq!(listener.get_edit_state_changes(), vec![6]);
    }

    #[test]
    fn test_edit_state_changed_multiple_transitions() {
        let listener = MockEditorModelListener::new();
        listener.edit_state_changed(MockEditorModelListener::EDIT_STARTED);
        listener.edit_state_changed(MockEditorModelListener::EDIT_ENDED);
        listener.edit_state_changed(MockEditorModelListener::EDIT_STARTED);
        assert_eq!(
            listener.get_edit_state_changes(),
            vec![5, 6, 5]
        );
    }
}
