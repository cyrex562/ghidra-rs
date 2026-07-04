use crate::program::seam_stubs::DataTypeManager;

/// Notified when a [`DataTypeManager`]'s cache has been invalidated.
///
/// Port of `ghidra.program.model.data.InvalidatedListener`.
pub trait InvalidatedListener {
    /// Called when the given `data_type_manager`'s cache has been invalidated.
    fn data_type_manager_invalidated(&self, data_type_manager: &dyn DataTypeManager);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct MockDataTypeManager;

    impl DataTypeManager for MockDataTypeManager {}

    struct RecordingListener {
        invalidated: AtomicBool,
    }

    impl InvalidatedListener for RecordingListener {
        fn data_type_manager_invalidated(&self, _data_type_manager: &dyn DataTypeManager) {
            self.invalidated.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn data_type_manager_invalidated_records_call() {
        let listener = RecordingListener { invalidated: AtomicBool::new(false) };
        let manager = MockDataTypeManager;
        listener.data_type_manager_invalidated(&manager);
        assert!(listener.invalidated.load(Ordering::SeqCst));
    }

    #[test]
    fn usable_as_trait_object() {
        let listener = RecordingListener { invalidated: AtomicBool::new(false) };
        let manager = MockDataTypeManager;
        let dyn_listener: &dyn InvalidatedListener = &listener;
        dyn_listener.data_type_manager_invalidated(&manager);
        assert!(listener.invalidated.load(Ordering::SeqCst));
    }
}
