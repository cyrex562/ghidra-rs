//! Listener interface for changes to the listing model.

/// Notified when the listing model changes size or data.
///
/// Corresponds to Java `ghidra.app.util.viewer.listingpanel.ListingModelListener`.
pub trait ListingModelListener {
    /// Called whenever the number of indexes in the model changes.
    fn model_size_changed(&mut self);

    /// Called when the data at one or more indexes changes.
    ///
    /// `update_immediately` signals that the listing should refresh without
    /// deferring to a batching/coalescing strategy.
    fn data_changed(&mut self, update_immediately: bool);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingListener {
        size_changed_count: usize,
        data_changed_calls: Vec<bool>,
    }

    impl RecordingListener {
        fn new() -> Self {
            Self {
                size_changed_count: 0,
                data_changed_calls: Vec::new(),
            }
        }
    }

    impl ListingModelListener for RecordingListener {
        fn model_size_changed(&mut self) {
            self.size_changed_count += 1;
        }

        fn data_changed(&mut self, update_immediately: bool) {
            self.data_changed_calls.push(update_immediately);
        }
    }

    #[test]
    fn test_model_size_changed_called() {
        let mut listener = RecordingListener::new();
        listener.model_size_changed();
        assert_eq!(listener.size_changed_count, 1);
    }

    #[test]
    fn test_model_size_changed_multiple_times() {
        let mut listener = RecordingListener::new();
        listener.model_size_changed();
        listener.model_size_changed();
        listener.model_size_changed();
        assert_eq!(listener.size_changed_count, 3);
    }

    #[test]
    fn test_data_changed_update_immediately_true() {
        let mut listener = RecordingListener::new();
        listener.data_changed(true);
        assert_eq!(listener.data_changed_calls, vec![true]);
    }

    #[test]
    fn test_data_changed_update_immediately_false() {
        let mut listener = RecordingListener::new();
        listener.data_changed(false);
        assert_eq!(listener.data_changed_calls, vec![false]);
    }

    #[test]
    fn test_data_changed_multiple_calls() {
        let mut listener = RecordingListener::new();
        listener.data_changed(true);
        listener.data_changed(false);
        listener.data_changed(true);
        assert_eq!(listener.data_changed_calls, vec![true, false, true]);
    }

    #[test]
    fn test_trait_object_dispatch() {
        let mut listener: Box<dyn ListingModelListener> = Box::new(RecordingListener::new());
        listener.model_size_changed();
        listener.data_changed(false);
    }
}
