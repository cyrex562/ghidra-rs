use std::sync::Arc;

use crate::docking::seam_stubs::ComponentProvider;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_type_path::DataTypePath;

use super::editor_listener::EditorListener;

/// Interface implemented by data type editors.
///
/// Port of `ghidra.app.plugin.core.compositeeditor.EditorProvider`. Java is an `interface` with
/// 10 abstract methods and 9 in-repo implementors, so this becomes a `trait`
/// (rule R-interface-open-ext-point). It mutually references
/// [`EditorListener`](crate::app::plugin::core::compositeeditor::editor_listener::EditorListener)
/// (`addEditorListener`) -- both types are ported together in this module, so no forward-cycle
/// stub is needed for either.
///
/// `getComponentProvider()` returns `docking.ComponentProvider`, which is not yet ported; this
/// reuses the existing crate-wide placeholder at
/// [`crate::docking::seam_stubs::ComponentProvider`] rather than defining a second one.
pub trait EditorProvider {
    /// Get the name of this editor.
    fn get_name(&self) -> String;

    /// Get the pathname of the data type being edited.
    fn get_dt_path(&self) -> DataTypePath;

    /// Get the component provider for this editor.
    fn get_component_provider(&self) -> Arc<dyn ComponentProvider>;

    /// The edited datatype's original datatype manager.
    fn get_data_type_manager(&self) -> Box<dyn DataTypeManager>;

    /// Return whether this editor is editing the data type with the given path.
    fn is_editing(&self, dt_path: &DataTypePath) -> bool;

    /// Add an editor listener that will be notified when the edit window is closed.
    fn add_editor_listener(&mut self, listener: Box<dyn EditorListener>);

    /// Show the editor.
    fn show(&mut self);

    /// Returns whether changes need to be saved.
    fn needs_save(&self) -> bool;

    /// Prompt the user if this editor has changes that need saving.
    ///
    /// `allow_cancel` means the user can cancel the edits. Returns true if the user doesn't
    /// cancel.
    fn check_for_save(&mut self, allow_cancel: bool) -> bool;

    /// Dispose of resources that this editor may be using.
    fn dispose(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::category_path::ROOT;
    use std::cell::RefCell;

    /// Minimal recording implementation used to verify dispatch and trait-object usability.
    #[derive(Default)]
    struct RecordingEditorProvider {
        listeners_added: RefCell<usize>,
        shown: RefCell<bool>,
        disposed: RefCell<bool>,
        dirty: RefCell<bool>,
    }

    impl EditorProvider for RecordingEditorProvider {
        fn get_name(&self) -> String {
            "TestStructureEditor".to_string()
        }

        fn get_dt_path(&self) -> DataTypePath {
            DataTypePath::new(ROOT.clone(), "MyStruct")
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

        fn add_editor_listener(&mut self, _listener: Box<dyn EditorListener>) {
            *self.listeners_added.borrow_mut() += 1;
        }

        fn show(&mut self) {
            *self.shown.borrow_mut() = true;
        }

        fn needs_save(&self) -> bool {
            *self.dirty.borrow()
        }

        fn check_for_save(&mut self, allow_cancel: bool) -> bool {
            allow_cancel
        }

        fn dispose(&mut self) {
            *self.disposed.borrow_mut() = true;
        }
    }

    #[test]
    fn is_editing_matches_own_path() {
        let provider = RecordingEditorProvider::default();
        let path = DataTypePath::new(ROOT.clone(), "MyStruct");
        assert!(provider.is_editing(&path));

        let other = DataTypePath::new(ROOT.clone(), "OtherStruct");
        assert!(!provider.is_editing(&other));
    }

    #[test]
    fn show_and_dispose_mutate_state() {
        let mut provider = RecordingEditorProvider::default();
        assert!(!*provider.shown.borrow());
        provider.show();
        assert!(*provider.shown.borrow());

        assert!(!*provider.disposed.borrow());
        provider.dispose();
        assert!(*provider.disposed.borrow());
    }

    #[test]
    fn usable_as_trait_object() {
        let mut provider: Box<dyn EditorProvider> = Box::new(RecordingEditorProvider::default());
        assert_eq!(provider.get_name(), "TestStructureEditor");
        assert!(!provider.needs_save());
        assert!(provider.check_for_save(true));
    }
}
