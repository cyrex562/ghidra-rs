use crate::app::seam_stubs::CompositeEditorTableAction;

/// Interface implemented by classes that want to be notified when a composite editor's set of
/// table actions changes.
///
/// Port of `ghidra.app.plugin.core.compositeeditor.EditorActionListener`. Java is an `interface`
/// with 2 abstract methods and 1 in-repo implementor, so this becomes a `trait`
/// (rule R-interface-open-ext-point).
///
/// `CompositeEditorTableAction` is an abstract class (not an interface) that is not yet ported;
/// both methods here only pass it through as a slice without calling any of its members, so this
/// reuses the minimal pass-through placeholder at
/// [`crate::app::seam_stubs::CompositeEditorTableAction`].
pub trait EditorActionListener {
    /// Notification that the indicated actions were added.
    fn actions_added(&mut self, actions: &[CompositeEditorTableAction]);

    /// Notification that the indicated actions were removed.
    fn actions_removed(&mut self, actions: &[CompositeEditorTableAction]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingEditorActionListener {
        added_count: usize,
        removed_count: usize,
    }

    impl EditorActionListener for RecordingEditorActionListener {
        fn actions_added(&mut self, actions: &[CompositeEditorTableAction]) {
            self.added_count += actions.len();
        }

        fn actions_removed(&mut self, actions: &[CompositeEditorTableAction]) {
            self.removed_count += actions.len();
        }
    }

    #[test]
    fn actions_added_counts_actions() {
        let mut listener = RecordingEditorActionListener::default();
        listener.actions_added(&[CompositeEditorTableAction, CompositeEditorTableAction]);
        assert_eq!(listener.added_count, 2);
        assert_eq!(listener.removed_count, 0);
    }

    #[test]
    fn actions_removed_counts_actions() {
        let mut listener = RecordingEditorActionListener::default();
        listener.actions_removed(&[CompositeEditorTableAction]);
        assert_eq!(listener.removed_count, 1);
        assert_eq!(listener.added_count, 0);
    }

    #[test]
    fn usable_as_trait_object() {
        let mut listener: Box<dyn EditorActionListener> =
            Box::new(RecordingEditorActionListener::default());
        listener.actions_added(&[]);
        listener.actions_removed(&[]);
        // Empty slices should not affect counts, but dispatch must still succeed through `dyn`.
    }
}
