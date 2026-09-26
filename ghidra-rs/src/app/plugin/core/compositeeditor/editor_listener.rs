use super::editor_provider::EditorProvider;

/// Interface used for notification when an edit session is ending.
///
/// Port of `ghidra.app.plugin.core.compositeeditor.EditorListener`. Java is an `interface` with
/// 1 abstract method and 2 in-repo implementors, so this becomes a `trait`
/// (rule R-interface-open-ext-point). It mutually references
/// [`EditorProvider`](crate::app::plugin::core::compositeeditor::editor_provider::EditorProvider)
/// -- both types are ported together in this module, so no forward-cycle stub is needed for
/// either.
pub trait EditorListener {
    /// Notification that the editor is closed.
    fn closed(&mut self, editor: &dyn EditorProvider);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::seam_stubs::ComponentProvider;
    use crate::program::model::data::category_path::ROOT;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::data_type_path::DataTypePath;
    use std::sync::Arc;

    /// Minimal `EditorProvider` stand-in used only to exercise `EditorListener::closed`.
    struct StubEditorProvider {
        name: String,
    }

    impl EditorProvider for StubEditorProvider {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_dt_path(&self) -> DataTypePath {
            DataTypePath::new(ROOT.clone(), self.name.clone())
        }
        fn get_component_provider(&self) -> Arc<dyn ComponentProvider> {
            struct Stub;
            impl ComponentProvider for Stub {}
            Arc::new(Stub)
        }
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn is_editing(&self, dt_path: &DataTypePath) -> bool {
            *dt_path == self.get_dt_path()
        }
        fn add_editor_listener(&mut self, _listener: Box<dyn EditorListener>) {}
        fn show(&mut self) {}
        fn needs_save(&self) -> bool {
            false
        }
        fn check_for_save(&mut self, _allow_cancel: bool) -> bool {
            true
        }
        fn dispose(&mut self) {}
    }

    /// Records the name of the last editor that closed.
    #[derive(Default)]
    struct RecordingEditorListener {
        last_closed_name: Option<String>,
        close_count: usize,
    }

    impl EditorListener for RecordingEditorListener {
        fn closed(&mut self, editor: &dyn EditorProvider) {
            self.last_closed_name = Some(editor.get_name());
            self.close_count += 1;
        }
    }

    #[test]
    fn closed_records_editor_name() {
        let mut listener = RecordingEditorListener::default();
        let editor = StubEditorProvider { name: "StructureEditor".to_string() };
        listener.closed(&editor);
        assert_eq!(listener.last_closed_name.as_deref(), Some("StructureEditor"));
        assert_eq!(listener.close_count, 1);
    }

    #[test]
    fn usable_as_trait_object() {
        let mut listener: Box<dyn EditorListener> = Box::new(RecordingEditorListener::default());
        let editor = StubEditorProvider { name: "UnionEditor".to_string() };
        listener.closed(&editor);
    }
}
