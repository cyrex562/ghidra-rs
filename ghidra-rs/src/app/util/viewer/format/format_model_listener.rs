//! Listener for format model changes.
//!
//! Port of `ghidra.app.util.viewer.format.FormatModelListener`. This is a genuine open
//! extension point (four in-repo implementors), so it is ported as a trait.

use crate::app::seam_stubs::FieldFormatModel;

/// Notifies listeners when a format model has been changed.
///
/// Port of `ghidra.app.util.viewer.format.FormatModelListener`.
pub trait FormatModelListener {
    /// Notifies that the given format model was changed.
    ///
    /// # Arguments
    /// * `model` - the model that was changed
    fn format_model_changed(&self, model: &dyn FieldFormatModel);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFieldFormatModel;

    impl FieldFormatModel for MockFieldFormatModel {}

    struct MockFormatModelListener;

    impl FormatModelListener for MockFormatModelListener {
        fn format_model_changed(&self, _model: &dyn FieldFormatModel) {}
    }

    #[test]
    fn test_format_model_listener_can_be_implemented() {
        let listener = MockFormatModelListener;
        let model = MockFieldFormatModel;
        listener.format_model_changed(&model);
    }

    #[test]
    fn test_format_model_listener_handles_trait_objects() {
        let listener: Box<dyn FormatModelListener> = Box::new(MockFormatModelListener);
        let model: Box<dyn FieldFormatModel> = Box::new(MockFieldFormatModel);
        listener.format_model_changed(&*model);
    }
}
