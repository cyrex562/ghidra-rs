//! Port of `ghidra.program.model.data.DataTypeManagerChangeListenerHandler`.
//!
//! # Fidelity notes
//!
//! Java stores listeners in a `WeakSet<DataTypeManagerChangeListener>`
//! (`WeakDataStructureFactory.createCopyOnReadWeakSet()`), which holds only *weak* references so
//! a caller that forgets to unregister a listener doesn't leak it. `ghidra.util.datastruct.WeakSet`
//! itself is still `TODO` in `PORT_MANIFEST.tsv`, and this crate's placeholder for it
//! ([`crate::util::seam_stubs::WeakSet`]) is a bare marker trait with no methods at all, so it
//! cannot be used as real storage. Rather than fabricate a fake implementation of that unported
//! class, this handler builds its own listener registry directly from [`std::sync::Weak`], which
//! is actually a *more* faithful translation of "weak reference set" than any stand-in for the
//! (also incomplete) Java class could be: callers register an `Arc<dyn
//! DataTypeManagerChangeListener>` that they own, this handler stores only a [`Weak`] to it, and a
//! listener whose last `Arc` has been dropped is silently skipped -- and pruned from the list --
//! on the next notification, exactly like Java's weak set.
//!
//! Java also requires every notification to be dispatched asynchronously, "within a different
//! thread" (`SwingUtilities.invokeLater`). This crate's own established stand-in for that need,
//! [`AsyncUtils::swing_executor`](crate::util::async_utils::AsyncUtils::swing_executor), already
//! runs synchronously today since there is no UI-thread runtime yet -- but its `Box<dyn FnOnce() +
//! Send>` signature also requires `'static` captures, which the borrowed `&dyn
//! DataTypeManager`/`&CategoryPath`/`&DataTypePath` event parameters here are not `'static`. So
//! [`DataTypeManagerChangeListenerHandler::invoke_later`] is a private, synchronous, inline
//! stand-in (matching the same "no async runtime yet" gap `swing_executor` already documents)
//! rather than literally reusing that executor.
//!
//! Java's private `readObject` re-creates a fresh (empty) `listenerList` after Java-serialization
//! deserialization, since `transient` fields aren't serialized. This crate has no direct
//! equivalent of `ObjectInputStream`-based deserialization for this type, and a freshly
//! constructed [`DataTypeManagerChangeListenerHandler`] already starts with an empty listener
//! list (see [`Default`]), so there is nothing extra to port here.

use std::sync::{Arc, Mutex, Weak};

use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_type_manager_change_listener::DataTypeManagerChangeListener;
use crate::program::model::data::source_archive::SourceArchive;
use crate::program::seam_stubs::DataTypePath;

/// Default implementation for a [`DataTypeManagerChangeListener`] that sends out the events to
/// its own list of listeners.
///
/// Port of `ghidra.program.model.data.DataTypeManagerChangeListenerHandler`. See the module docs
/// for the two documented fidelity gaps (weak-set storage, asynchronous dispatch).
pub struct DataTypeManagerChangeListenerHandler {
    listener_list: Mutex<Vec<Weak<dyn DataTypeManagerChangeListener>>>,
}

impl Default for DataTypeManagerChangeListenerHandler {
    fn default() -> Self {
        DataTypeManagerChangeListenerHandler {
            listener_list: Mutex::new(Vec::new()),
        }
    }
}

impl DataTypeManagerChangeListenerHandler {
    /// Creates a new handler with no registered listeners.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the given category change listener.
    ///
    /// Only a [`Weak`] reference to `l` is retained; `l` must be kept alive elsewhere by the
    /// caller for as long as it should keep receiving notifications.
    pub fn add_data_type_manager_listener(&self, l: &Arc<dyn DataTypeManagerChangeListener>) {
        self.listener_list.lock().unwrap().push(Arc::downgrade(l));
    }

    /// Remove the category change listener.
    pub fn remove_data_type_manager_listener(&self, l: &Arc<dyn DataTypeManagerChangeListener>) {
        let target = Arc::downgrade(l);
        self.listener_list
            .lock()
            .unwrap()
            .retain(|w| w.upgrade().is_some() && !Weak::ptr_eq(w, &target));
    }

    /// Returns `true` if there are currently no live registered listeners, pruning any dead
    /// (dropped) entries in the process.
    fn is_empty(&self) -> bool {
        let mut listeners = self.listener_list.lock().unwrap();
        listeners.retain(|w| w.upgrade().is_some());
        listeners.is_empty()
    }

    /// Synchronous, inline stand-in for `SwingUtilities.invokeLater` -- see the module docs.
    /// Snapshots the currently-live listeners (pruning dead entries) and hands the snapshot to
    /// `f`.
    fn invoke_later(&self, f: impl FnOnce(&[Arc<dyn DataTypeManagerChangeListener>])) {
        let snapshot: Vec<Arc<dyn DataTypeManagerChangeListener>> = {
            let mut listeners = self.listener_list.lock().unwrap();
            listeners.retain(|w| w.upgrade().is_some());
            listeners.iter().filter_map(Weak::upgrade).collect()
        };
        f(&snapshot);
    }
}

impl DataTypeManagerChangeListener for DataTypeManagerChangeListenerHandler {
    fn category_added(&self, dtm: &dyn DataTypeManager, path: &CategoryPath) {
        if self.is_empty() {
            return;
        }
        self.invoke_later(|listeners| {
            for listener in listeners {
                listener.category_added(dtm, path);
            }
        });
    }

    fn category_removed(&self, dtm: &dyn DataTypeManager, path: &CategoryPath) {
        if self.is_empty() {
            return;
        }
        self.invoke_later(|listeners| {
            for listener in listeners {
                listener.category_removed(dtm, path);
            }
        });
    }

    fn category_renamed(
        &self,
        dtm: &dyn DataTypeManager,
        old_path: &CategoryPath,
        new_path: &CategoryPath,
    ) {
        if self.is_empty() {
            return;
        }
        self.invoke_later(|listeners| {
            for listener in listeners {
                listener.category_renamed(dtm, old_path, new_path);
            }
        });
    }

    fn category_moved(
        &self,
        dtm: &dyn DataTypeManager,
        old_path: &CategoryPath,
        new_path: &CategoryPath,
    ) {
        if self.is_empty() {
            return;
        }
        self.invoke_later(|listeners| {
            for listener in listeners {
                listener.category_moved(dtm, old_path, new_path);
            }
        });
    }

    fn data_type_added(&self, dtm: &dyn DataTypeManager, path: &DataTypePath) {
        if self.is_empty() {
            return;
        }
        self.invoke_later(|listeners| {
            for listener in listeners {
                listener.data_type_added(dtm, path);
            }
        });
    }

    fn data_type_removed(&self, dtm: &dyn DataTypeManager, path: &DataTypePath) {
        if self.is_empty() {
            return;
        }
        self.invoke_later(|listeners| {
            for listener in listeners {
                listener.data_type_removed(dtm, path);
            }
        });
    }

    fn data_type_renamed(
        &self,
        dtm: &dyn DataTypeManager,
        old_path: &DataTypePath,
        new_path: &DataTypePath,
    ) {
        if self.is_empty() {
            return;
        }
        self.invoke_later(|listeners| {
            for listener in listeners {
                listener.data_type_renamed(dtm, old_path, new_path);
                listener.favorites_changed(dtm, old_path, false);
            }
        });
    }

    fn data_type_moved(
        &self,
        dtm: &dyn DataTypeManager,
        old_path: &DataTypePath,
        new_path: &DataTypePath,
    ) {
        if self.is_empty() {
            return;
        }
        self.invoke_later(|listeners| {
            for listener in listeners {
                listener.data_type_moved(dtm, old_path, new_path);
            }
        });
    }

    fn data_type_changed(&self, dtm: &dyn DataTypeManager, path: &DataTypePath) {
        if self.is_empty() {
            return;
        }
        self.invoke_later(|listeners| {
            for listener in listeners {
                listener.data_type_changed(dtm, path);
            }
        });
    }

    fn data_type_replaced(
        &self,
        dtm: &dyn DataTypeManager,
        old_path: &DataTypePath,
        new_path: &DataTypePath,
        new_data_type: &dyn DataType,
    ) {
        if self.is_empty() {
            return;
        }
        self.invoke_later(|listeners| {
            for listener in listeners {
                listener.data_type_replaced(dtm, old_path, new_path, new_data_type);
            }
        });
    }

    fn favorites_changed(&self, dtm: &dyn DataTypeManager, path: &DataTypePath, is_favorite: bool) {
        if self.is_empty() {
            return;
        }
        self.invoke_later(|listeners| {
            for listener in listeners {
                listener.favorites_changed(dtm, path, is_favorite);
            }
        });
    }

    fn source_archive_changed(
        &self,
        data_type_manager: &dyn DataTypeManager,
        source_archive: &dyn SourceArchive,
    ) {
        if self.is_empty() {
            return;
        }
        self.invoke_later(|listeners| {
            for listener in listeners {
                listener.source_archive_changed(data_type_manager, source_archive);
            }
        });
    }

    fn source_archive_added(
        &self,
        data_type_manager: &dyn DataTypeManager,
        source_archive: &dyn SourceArchive,
    ) {
        if self.is_empty() {
            return;
        }
        self.invoke_later(|listeners| {
            for listener in listeners {
                listener.source_archive_added(data_type_manager, source_archive);
            }
        });
    }

    fn program_architecture_changed(&self, data_type_manager: &dyn DataTypeManager) {
        if self.is_empty() {
            return;
        }
        self.invoke_later(|listeners| {
            for listener in listeners {
                listener.program_architecture_changed(data_type_manager);
            }
        });
    }

    fn restored(&self, data_type_manager: &dyn DataTypeManager) {
        if self.is_empty() {
            return;
        }
        self.invoke_later(|listeners| {
            for listener in listeners {
                listener.restored(data_type_manager);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    struct MockSourceArchive;
    impl SourceArchive for MockSourceArchive {
        fn source_archive_id(&self) -> crate::util::UniversalID {
            crate::util::UniversalID::new(0)
        }

        fn domain_file_id(&self) -> String {
            String::new()
        }

        fn archive_type(&self) -> crate::program::model::data::archive_type::ArchiveType {
            crate::program::model::data::archive_type::ArchiveType::File
        }

        fn name(&self) -> String {
            "mock".to_string()
        }

        fn last_sync_time(&self) -> i64 {
            0
        }

        fn is_dirty(&self) -> bool {
            false
        }

        fn set_last_sync_time(&mut self, _time: i64) {}

        fn set_name(&mut self, _name: String) {}

        fn set_dirty_flag(&mut self, _dirty: bool) {}
    }

    struct MockDataType;
    impl DataType for MockDataType {}

    #[derive(Default)]
    struct RecordingListener {
        category_added: AtomicUsize,
        data_type_renamed: AtomicUsize,
        favorites_changed: AtomicUsize,
        restored: AtomicUsize,
        last_favorite_flag: std::sync::Mutex<Option<bool>>,
    }

    impl DataTypeManagerChangeListener for RecordingListener {
        fn category_added(&self, _dtm: &dyn DataTypeManager, _path: &CategoryPath) {
            self.category_added.fetch_add(1, Ordering::SeqCst);
        }

        fn category_removed(&self, _dtm: &dyn DataTypeManager, _path: &CategoryPath) {}

        fn category_renamed(
            &self,
            _dtm: &dyn DataTypeManager,
            _old_path: &CategoryPath,
            _new_path: &CategoryPath,
        ) {
        }

        fn category_moved(
            &self,
            _dtm: &dyn DataTypeManager,
            _old_path: &CategoryPath,
            _new_path: &CategoryPath,
        ) {
        }

        fn data_type_added(&self, _dtm: &dyn DataTypeManager, _path: &DataTypePath) {}

        fn data_type_removed(&self, _dtm: &dyn DataTypeManager, _path: &DataTypePath) {}

        fn data_type_renamed(
            &self,
            _dtm: &dyn DataTypeManager,
            _old_path: &DataTypePath,
            _new_path: &DataTypePath,
        ) {
            self.data_type_renamed.fetch_add(1, Ordering::SeqCst);
        }

        fn data_type_moved(
            &self,
            _dtm: &dyn DataTypeManager,
            _old_path: &DataTypePath,
            _new_path: &DataTypePath,
        ) {
        }

        fn data_type_changed(&self, _dtm: &dyn DataTypeManager, _path: &DataTypePath) {}

        fn data_type_replaced(
            &self,
            _dtm: &dyn DataTypeManager,
            _old_path: &DataTypePath,
            _new_path: &DataTypePath,
            _new_data_type: &dyn DataType,
        ) {
        }

        fn favorites_changed(
            &self,
            _dtm: &dyn DataTypeManager,
            _path: &DataTypePath,
            is_favorite: bool,
        ) {
            self.favorites_changed.fetch_add(1, Ordering::SeqCst);
            *self.last_favorite_flag.lock().unwrap() = Some(is_favorite);
        }

        fn source_archive_changed(
            &self,
            _data_type_manager: &dyn DataTypeManager,
            _source_archive: &dyn SourceArchive,
        ) {
        }

        fn source_archive_added(
            &self,
            _data_type_manager: &dyn DataTypeManager,
            _source_archive: &dyn SourceArchive,
        ) {
        }

        fn program_architecture_changed(&self, _data_type_manager: &dyn DataTypeManager) {}

        fn restored(&self, _data_type_manager: &dyn DataTypeManager) {
            self.restored.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn notifying_with_no_listeners_does_not_panic() {
        let handler = DataTypeManagerChangeListenerHandler::new();
        let dtm = MockDataTypeManager;
        handler.restored(&dtm);
        handler.category_added(&dtm, &crate::program::model::data::category_path::ROOT);
    }

    #[test]
    fn registered_listener_receives_notification() {
        let handler = DataTypeManagerChangeListenerHandler::new();
        let listener: Arc<dyn DataTypeManagerChangeListener> =
            Arc::new(RecordingListener::default());
        handler.add_data_type_manager_listener(&listener);

        let dtm = MockDataTypeManager;
        handler.restored(&dtm);

        let recording = listener_as_recording(&listener);
        assert_eq!(recording.restored.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn multiple_listeners_all_receive_notification() {
        let handler = DataTypeManagerChangeListenerHandler::new();
        let listener1: Arc<dyn DataTypeManagerChangeListener> =
            Arc::new(RecordingListener::default());
        let listener2: Arc<dyn DataTypeManagerChangeListener> =
            Arc::new(RecordingListener::default());
        handler.add_data_type_manager_listener(&listener1);
        handler.add_data_type_manager_listener(&listener2);

        let dtm = MockDataTypeManager;
        handler.restored(&dtm);

        assert_eq!(listener_as_recording(&listener1).restored.load(Ordering::SeqCst), 1);
        assert_eq!(listener_as_recording(&listener2).restored.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn removed_listener_stops_receiving_notifications() {
        let handler = DataTypeManagerChangeListenerHandler::new();
        let listener: Arc<dyn DataTypeManagerChangeListener> =
            Arc::new(RecordingListener::default());
        handler.add_data_type_manager_listener(&listener);
        handler.remove_data_type_manager_listener(&listener);

        let dtm = MockDataTypeManager;
        handler.restored(&dtm);

        assert_eq!(listener_as_recording(&listener).restored.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn dropping_the_owning_arc_prunes_the_weak_reference() {
        let handler = DataTypeManagerChangeListenerHandler::new();
        {
            let listener: Arc<dyn DataTypeManagerChangeListener> =
                Arc::new(RecordingListener::default());
            handler.add_data_type_manager_listener(&listener);
            // `listener` (the only strong reference) is dropped at the end of this block; the
            // handler only ever held a `Weak`, matching Java's WeakSet semantics.
        }

        let dtm = MockDataTypeManager;
        // Must not panic even though the listener is gone.
        handler.restored(&dtm);
    }

    #[test]
    fn data_type_renamed_also_fires_favorites_changed_with_old_path_and_false() {
        let handler = DataTypeManagerChangeListenerHandler::new();
        let listener: Arc<dyn DataTypeManagerChangeListener> =
            Arc::new(RecordingListener::default());
        handler.add_data_type_manager_listener(&listener);

        let dtm = MockDataTypeManager;
        let old_path = DataTypePath::parse("/old", "Foo").unwrap();
        let new_path = DataTypePath::parse("/old", "Bar").unwrap();
        handler.data_type_renamed(&dtm, &old_path, &new_path);

        let recording = listener_as_recording(&listener);
        assert_eq!(recording.data_type_renamed.load(Ordering::SeqCst), 1);
        assert_eq!(recording.favorites_changed.load(Ordering::SeqCst), 1);
        assert_eq!(*recording.last_favorite_flag.lock().unwrap(), Some(false));
    }

    #[test]
    fn usable_as_trait_object() {
        let handler: Box<dyn DataTypeManagerChangeListener> =
            Box::new(DataTypeManagerChangeListenerHandler::new());
        let dtm = MockDataTypeManager;
        handler.restored(&dtm);
    }

    /// Helper to reach into a `RecordingListener` behind `Arc<dyn
    /// DataTypeManagerChangeListener>` for assertions. Relies on `Arc::as_ptr`'s data pointer,
    /// which is sound here because every listener constructed by these tests is always actually a
    /// `RecordingListener`.
    fn listener_as_recording(
        listener: &Arc<dyn DataTypeManagerChangeListener>,
    ) -> &RecordingListener {
        let data_ptr = Arc::as_ptr(listener) as *const RecordingListener;
        unsafe { &*data_ptr }
    }
}
