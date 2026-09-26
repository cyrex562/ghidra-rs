//! Port of `ghidra.app.plugin.core.functiongraph.mvc.FGControllerListener`.

use std::sync::Arc;

use crate::app::seam_stubs::ProgramSelection;
use crate::program::util::program_location::ProgramLocation;

/// An open extension point for listening to changes in the Function Graph controller.
///
/// This trait is implemented by classes that want to be notified of various user-initiated
/// changes in the Function Graph UI, such as location changes, selection changes, and navigation.
pub trait FGControllerListener: Send + Sync {
    /// Called when the `FGData` for the current viewer has been set on the controller.
    fn data_changed(&self);

    /// A notification for when the user has changed the location by interacting with the Function
    /// Graph UI.
    ///
    /// # Arguments
    /// * `location` - the new location
    /// * `vertex_changed` - true if a new vertex has been selected
    fn user_changed_location(&self, location: Arc<dyn ProgramLocation + Send + Sync>, vertex_changed: bool);

    /// A notification for when the user has changed the selection by interacting with the Function
    /// Graph UI.
    ///
    /// # Arguments
    /// * `selection` - the new selection
    fn user_changed_selection(&self, selection: Arc<dyn ProgramSelection>);

    /// A notification for when the user has selected text in a vertex by interacting with the
    /// Function Graph UI.
    ///
    /// # Arguments
    /// * `s` - the selected text
    fn user_selected_text(&self, s: &str);

    /// Called when the user requests the tool to navigate to a new location, such as when
    /// double-clicking an xref.
    ///
    /// # Arguments
    /// * `location` - the location to navigate to
    fn user_navigated(&self, location: Arc<dyn ProgramLocation + Send + Sync>);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockListener {
        data_changed_count: AtomicUsize,
        user_changed_location_count: AtomicUsize,
        user_selected_text_count: AtomicUsize,
    }

    impl FGControllerListener for MockListener {
        fn data_changed(&self) {
            self.data_changed_count.fetch_add(1, Ordering::SeqCst);
        }

        fn user_changed_location(
            &self,
            _location: Arc<dyn ProgramLocation + Send + Sync>,
            _vertex_changed: bool,
        ) {
            self.user_changed_location_count.fetch_add(1, Ordering::SeqCst);
        }

        fn user_changed_selection(&self, _selection: Arc<dyn ProgramSelection>) {}

        fn user_selected_text(&self, _s: &str) {
            self.user_selected_text_count.fetch_add(1, Ordering::SeqCst);
        }

        fn user_navigated(&self, _location: Arc<dyn ProgramLocation + Send + Sync>) {}
    }

    #[test]
    fn test_listener_callback_counts() {
        let listener = Arc::new(MockListener {
            data_changed_count: AtomicUsize::new(0),
            user_changed_location_count: AtomicUsize::new(0),
            user_selected_text_count: AtomicUsize::new(0),
        });

        listener.data_changed();
        assert_eq!(listener.data_changed_count.load(Ordering::SeqCst), 1);

        listener.user_selected_text("test");
        assert_eq!(listener.user_selected_text_count.load(Ordering::SeqCst), 1);

        listener.user_changed_location_count.store(0, Ordering::SeqCst);
        assert_eq!(listener.user_changed_location_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn trait_object_dispatch_works() {
        let listener: Arc<dyn FGControllerListener> = Arc::new(MockListener {
            data_changed_count: AtomicUsize::new(0),
            user_changed_location_count: AtomicUsize::new(0),
            user_selected_text_count: AtomicUsize::new(0),
        });

        listener.data_changed();
        listener.user_selected_text("polymorphic");
    }
}
