use super::{CompositeEditorModelListener, CompositeViewerModelListener};

/// Adapter providing default no-op implementations for all [`CompositeEditorModelListener`] methods.
///
/// This adapter allows callers to implement only the methods they care about,
/// while getting sensible defaults for the rest. All methods do nothing by default.
///
/// Mirrors `ghidra.app.plugin.core.compositeeditor.CompositeEditorModelAdapter`.
#[derive(Debug, Clone, Copy)]
pub struct CompositeEditorModelAdapter;

impl CompositeViewerModelListener for CompositeEditorModelAdapter {
    fn component_data_changed(&self) {}

    fn composite_info_changed(&self) {}

    fn status_changed(&self, _message: &str, _beep: bool) {}

    fn selection_changed(&self) {}
}

impl CompositeEditorModelListener for CompositeEditorModelAdapter {
    fn show_undefined_state_changed(&self, _show_undefined_bytes: bool) {}

    fn composite_edit_state_changed(&self, _state_type: i32) {}

    fn end_field_editing(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_instantiation() {
        let adapter = CompositeEditorModelAdapter;
        let _ = adapter;
    }

    #[test]
    fn composite_viewer_listener_methods() {
        let adapter = CompositeEditorModelAdapter;
        adapter.component_data_changed();
        adapter.composite_info_changed();
        adapter.status_changed("test", true);
        adapter.status_changed("test", false);
        adapter.status_changed("", false);
        adapter.selection_changed();
    }

    #[test]
    fn composite_editor_listener_methods() {
        let adapter = CompositeEditorModelAdapter;
        adapter.show_undefined_state_changed(true);
        adapter.show_undefined_state_changed(false);
        adapter.composite_edit_state_changed(1);
        adapter.composite_edit_state_changed(2);
        adapter.composite_edit_state_changed(3);
        adapter.composite_edit_state_changed(4);
        adapter.composite_edit_state_changed(5);
        adapter.composite_edit_state_changed(6);
        adapter.end_field_editing();
    }

    #[test]
    fn adapter_is_copy() {
        let a = CompositeEditorModelAdapter;
        let b = a;
        let _ = a;
        let _ = b;
    }

    #[test]
    fn adapter_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CompositeEditorModelAdapter>();
    }

    #[test]
    fn adapter_usable_as_composite_viewer_trait_object() {
        let adapter = CompositeEditorModelAdapter;
        let listener: &dyn CompositeViewerModelListener = &adapter;
        listener.component_data_changed();
        listener.composite_info_changed();
        listener.status_changed("test", true);
        listener.selection_changed();
    }

    #[test]
    fn adapter_usable_as_composite_editor_trait_object() {
        let adapter = CompositeEditorModelAdapter;
        let listener: &dyn CompositeEditorModelListener = &adapter;
        listener.show_undefined_state_changed(true);
        listener.composite_edit_state_changed(1);
        listener.end_field_editing();
    }
}
