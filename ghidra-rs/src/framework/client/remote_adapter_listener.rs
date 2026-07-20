use std::any::Any;

/// Provides a listener interface which facilitates notification when the connection state of a
/// remote server/repository adapter changes.
///
/// Port of `ghidra.framework.client.RemoteAdapterListener`.
pub trait RemoteAdapterListener {
    /// Callback notification indicating the remote object connection state has changed.
    ///
    /// `adapter` is the remote interface adapter (e.g. a
    /// [`RepositoryServerAdapter`](crate::framework::client::RepositoryServerAdapter) or
    /// [`RepositoryAdapter`](crate::framework::client::RepositoryAdapter)), type-erased as `dyn
    /// Any` since Java's `Object adapter` parameter is untyped and every known caller
    /// (`RepositoryAdapter.fireStateChanged()`, `RepositoryServerAdapter.fireStateChanged()`)
    /// simply passes `this`.
    fn connection_state_changed(&self, adapter: &dyn Any);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Marker;

    #[derive(Default)]
    struct RecordingListener {
        events: RefCell<Vec<&'static str>>,
    }

    impl RemoteAdapterListener for RecordingListener {
        fn connection_state_changed(&self, adapter: &dyn Any) {
            let kind = if adapter.downcast_ref::<Marker>().is_some() {
                "marker"
            }
            else {
                "unknown"
            };
            self.events.borrow_mut().push(kind);
        }
    }

    #[test]
    fn test_object_safety_and_downcast() {
        let listener: Box<dyn RemoteAdapterListener> = Box::new(RecordingListener::default());

        let marker = Marker;
        listener.connection_state_changed(&marker);
        listener.connection_state_changed(&42i32);

        let recording = RecordingListener::default();
        recording.connection_state_changed(&Marker);
        recording.connection_state_changed(&"not a marker");

        assert_eq!(recording.events.borrow().as_slice(), &["marker", "unknown"]);
    }
}
