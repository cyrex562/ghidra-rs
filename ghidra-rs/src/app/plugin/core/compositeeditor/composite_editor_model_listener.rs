use super::CompositeViewerModelListener;

/// State change type constants for composite editor model events.
pub const COMPOSITE_MODIFIED: i32 = 1;
pub const COMPOSITE_UNMODIFIED: i32 = 2;
pub const COMPOSITE_LOADED: i32 = 3;
pub const NO_COMPOSITE_LOADED: i32 = 4;
pub const EDIT_STARTED: i32 = 5;
pub const EDIT_ENDED: i32 = 6;

/// Composite Editor Model change listener.
///
/// This extends the CompositeViewerModelListener, which provides notifications for
/// composite's data changes in the model. This adds notification methods for selection
/// changes due to an edit of the editor model.
pub trait CompositeEditorModelListener: CompositeViewerModelListener {
    /// Called whenever the composite data type editor state changes for whether or not
    /// to show undefined bytes in the editor.
    ///
    /// # Arguments
    /// * `show_undefined_bytes` - true if undefined bytes should be displayed in the editor
    fn show_undefined_state_changed(&self, show_undefined_bytes: bool);

    /// Called whenever the data composite edit state changes.
    ///
    /// Examples:
    /// - Whether or not the composite being edited has been modified from the original.
    /// - Whether or not a composite is loaded in the model.
    ///
    /// # Arguments
    /// * `state_type` - the type of state change: COMPOSITE_MODIFIED, COMPOSITE_UNMODIFIED,
    ///   COMPOSITE_LOADED, NO_COMPOSITE_LOADED, EDIT_STARTED, EDIT_ENDED.
    fn composite_edit_state_changed(&self, state_type: i32);

    /// Called when the model wants to end cell editing that is in progress.
    ///
    /// This is due to an attempt to modify the composite data type in the editor while the
    /// model's field edit state indicates a field is being edited. It is up to the
    /// application to determine whether to cancel or apply the field edits.
    fn end_field_editing(&self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockCompositeEditorModelListener {
        undefined_state_changes: RefCell<Vec<bool>>,
        edit_state_changes: RefCell<Vec<i32>>,
        end_field_editing_count: RefCell<usize>,
        component_data_changes: RefCell<Vec<()>>,
        composite_info_changes: RefCell<Vec<()>>,
        status_changes: RefCell<Vec<(String, bool)>>,
        selection_changes: RefCell<Vec<()>>,
    }

    impl MockCompositeEditorModelListener {
        fn new() -> Self {
            Self {
                undefined_state_changes: RefCell::new(Vec::new()),
                edit_state_changes: RefCell::new(Vec::new()),
                end_field_editing_count: RefCell::new(0),
                component_data_changes: RefCell::new(Vec::new()),
                composite_info_changes: RefCell::new(Vec::new()),
                status_changes: RefCell::new(Vec::new()),
                selection_changes: RefCell::new(Vec::new()),
            }
        }

        fn undefined_state_changes(&self) -> Vec<bool> {
            self.undefined_state_changes.borrow().clone()
        }

        fn edit_state_changes(&self) -> Vec<i32> {
            self.edit_state_changes.borrow().clone()
        }

        fn end_field_editing_count(&self) -> usize {
            *self.end_field_editing_count.borrow()
        }
    }

    impl CompositeViewerModelListener for MockCompositeEditorModelListener {
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

    impl CompositeEditorModelListener for MockCompositeEditorModelListener {
        fn show_undefined_state_changed(&self, show_undefined_bytes: bool) {
            self.undefined_state_changes.borrow_mut().push(show_undefined_bytes);
        }

        fn composite_edit_state_changed(&self, state_type: i32) {
            self.edit_state_changes.borrow_mut().push(state_type);
        }

        fn end_field_editing(&self) {
            *self.end_field_editing_count.borrow_mut() += 1;
        }
    }

    #[test]
    fn test_show_undefined_state_changed_true() {
        let listener = MockCompositeEditorModelListener::new();
        listener.show_undefined_state_changed(true);
        assert_eq!(listener.undefined_state_changes(), vec![true]);
    }

    #[test]
    fn test_show_undefined_state_changed_false() {
        let listener = MockCompositeEditorModelListener::new();
        listener.show_undefined_state_changed(false);
        assert_eq!(listener.undefined_state_changes(), vec![false]);
    }

    #[test]
    fn test_show_undefined_state_changed_multiple() {
        let listener = MockCompositeEditorModelListener::new();
        listener.show_undefined_state_changed(true);
        listener.show_undefined_state_changed(false);
        listener.show_undefined_state_changed(true);
        assert_eq!(
            listener.undefined_state_changes(),
            vec![true, false, true]
        );
    }

    #[test]
    fn test_composite_edit_state_changed_modified() {
        let listener = MockCompositeEditorModelListener::new();
        listener.composite_edit_state_changed(COMPOSITE_MODIFIED);
        assert_eq!(listener.edit_state_changes(), vec![COMPOSITE_MODIFIED]);
    }

    #[test]
    fn test_composite_edit_state_changed_unmodified() {
        let listener = MockCompositeEditorModelListener::new();
        listener.composite_edit_state_changed(COMPOSITE_UNMODIFIED);
        assert_eq!(listener.edit_state_changes(), vec![COMPOSITE_UNMODIFIED]);
    }

    #[test]
    fn test_composite_edit_state_changed_loaded() {
        let listener = MockCompositeEditorModelListener::new();
        listener.composite_edit_state_changed(COMPOSITE_LOADED);
        assert_eq!(listener.edit_state_changes(), vec![COMPOSITE_LOADED]);
    }

    #[test]
    fn test_composite_edit_state_changed_no_composite() {
        let listener = MockCompositeEditorModelListener::new();
        listener.composite_edit_state_changed(NO_COMPOSITE_LOADED);
        assert_eq!(listener.edit_state_changes(), vec![NO_COMPOSITE_LOADED]);
    }

    #[test]
    fn test_composite_edit_state_changed_edit_started() {
        let listener = MockCompositeEditorModelListener::new();
        listener.composite_edit_state_changed(EDIT_STARTED);
        assert_eq!(listener.edit_state_changes(), vec![EDIT_STARTED]);
    }

    #[test]
    fn test_composite_edit_state_changed_edit_ended() {
        let listener = MockCompositeEditorModelListener::new();
        listener.composite_edit_state_changed(EDIT_ENDED);
        assert_eq!(listener.edit_state_changes(), vec![EDIT_ENDED]);
    }

    #[test]
    fn test_composite_edit_state_changed_multiple() {
        let listener = MockCompositeEditorModelListener::new();
        listener.composite_edit_state_changed(COMPOSITE_LOADED);
        listener.composite_edit_state_changed(COMPOSITE_MODIFIED);
        listener.composite_edit_state_changed(EDIT_STARTED);
        listener.composite_edit_state_changed(EDIT_ENDED);
        assert_eq!(
            listener.edit_state_changes(),
            vec![
                COMPOSITE_LOADED,
                COMPOSITE_MODIFIED,
                EDIT_STARTED,
                EDIT_ENDED
            ]
        );
    }

    #[test]
    fn test_end_field_editing() {
        let listener = MockCompositeEditorModelListener::new();
        listener.end_field_editing();
        assert_eq!(listener.end_field_editing_count(), 1);
    }

    #[test]
    fn test_end_field_editing_multiple() {
        let listener = MockCompositeEditorModelListener::new();
        listener.end_field_editing();
        listener.end_field_editing();
        listener.end_field_editing();
        assert_eq!(listener.end_field_editing_count(), 3);
    }

    #[test]
    fn test_all_methods_combined() {
        let listener = MockCompositeEditorModelListener::new();
        listener.show_undefined_state_changed(true);
        listener.composite_edit_state_changed(COMPOSITE_LOADED);
        listener.end_field_editing();

        assert_eq!(listener.undefined_state_changes(), vec![true]);
        assert_eq!(listener.edit_state_changes(), vec![COMPOSITE_LOADED]);
        assert_eq!(listener.end_field_editing_count(), 1);
    }

    #[test]
    fn test_state_constants_values() {
        assert_eq!(COMPOSITE_MODIFIED, 1);
        assert_eq!(COMPOSITE_UNMODIFIED, 2);
        assert_eq!(COMPOSITE_LOADED, 3);
        assert_eq!(NO_COMPOSITE_LOADED, 4);
        assert_eq!(EDIT_STARTED, 5);
        assert_eq!(EDIT_ENDED, 6);
    }
}
