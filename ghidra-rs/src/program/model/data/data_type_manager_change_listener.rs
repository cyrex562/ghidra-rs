use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::source_archive::SourceArchive;
use crate::program::seam_stubs::DataTypePath;

/// The listener interface for notification of changes to a `DataTypeManager`.
///
/// Port of `ghidra.program.model.data.DataTypeManagerChangeListener`.
pub trait DataTypeManagerChangeListener {
    /// Notification when category is added.
    fn category_added(&self, dtm: &dyn DataTypeManager, path: &CategoryPath);

    /// Notification when a category is removed.
    fn category_removed(&self, dtm: &dyn DataTypeManager, path: &CategoryPath);

    /// Notification when category is renamed.
    ///
    /// `new_path` will only differ from `old_path` in the last segment of the path.
    fn category_renamed(
        &self,
        dtm: &dyn DataTypeManager,
        old_path: &CategoryPath,
        new_path: &CategoryPath,
    );

    /// Notification when a category is reparented to a new category.
    fn category_moved(
        &self,
        dtm: &dyn DataTypeManager,
        old_path: &CategoryPath,
        new_path: &CategoryPath,
    );

    /// Notification when a data type is added to a category.
    fn data_type_added(&self, dtm: &dyn DataTypeManager, path: &DataTypePath);

    /// Notification when a data type is removed.
    fn data_type_removed(&self, dtm: &dyn DataTypeManager, path: &DataTypePath);

    /// Notification when a data type is renamed.
    fn data_type_renamed(
        &self,
        dtm: &dyn DataTypeManager,
        old_path: &DataTypePath,
        new_path: &DataTypePath,
    );

    /// Notification when a data type is moved.
    fn data_type_moved(
        &self,
        dtm: &dyn DataTypeManager,
        old_path: &DataTypePath,
        new_path: &DataTypePath,
    );

    /// Notification when a data type is changed.
    fn data_type_changed(&self, dtm: &dyn DataTypeManager, path: &DataTypePath);

    /// Notification when a data type has been replaced.
    fn data_type_replaced(
        &self,
        dtm: &dyn DataTypeManager,
        old_path: &DataTypePath,
        new_path: &DataTypePath,
        new_data_type: &dyn DataType,
    );

    /// Notification that the favorite status of a datatype has changed.
    fn favorites_changed(&self, dtm: &dyn DataTypeManager, path: &DataTypePath, is_favorite: bool);

    /// Notification that the information for a particular source archive has changed.
    /// Typically, this would be because it was renamed or moved.
    fn source_archive_changed(
        &self,
        data_type_manager: &dyn DataTypeManager,
        source_archive: &dyn SourceArchive,
    );

    /// Notification that the information for a source archive has been added. This happens when
    /// a data type from the indicated source archive is added to this data type manager.
    fn source_archive_added(
        &self,
        data_type_manager: &dyn DataTypeManager,
        source_archive: &dyn SourceArchive,
    );

    /// Notification that the program architecture associated with the specified data type
    /// manager has changed.
    fn program_architecture_changed(&self, data_type_manager: &dyn DataTypeManager);

    /// Notification that the specified data type manager has been restored to a previous state.
    fn restored(&self, data_type_manager: &dyn DataTypeManager);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockDataTypeManager;

    impl DataTypeManager for MockDataTypeManager {}

    struct RecordingListener {
        events: AtomicUsize,
    }

    impl DataTypeManagerChangeListener for RecordingListener {
        fn category_added(&self, _dtm: &dyn DataTypeManager, _path: &CategoryPath) {
            self.events.fetch_add(1, Ordering::SeqCst);
        }

        fn category_removed(&self, _dtm: &dyn DataTypeManager, _path: &CategoryPath) {
            self.events.fetch_add(1, Ordering::SeqCst);
        }

        fn category_renamed(
            &self,
            _dtm: &dyn DataTypeManager,
            _old_path: &CategoryPath,
            _new_path: &CategoryPath,
        ) {
            self.events.fetch_add(1, Ordering::SeqCst);
        }

        fn category_moved(
            &self,
            _dtm: &dyn DataTypeManager,
            _old_path: &CategoryPath,
            _new_path: &CategoryPath,
        ) {
            self.events.fetch_add(1, Ordering::SeqCst);
        }

        fn data_type_added(&self, _dtm: &dyn DataTypeManager, _path: &DataTypePath) {
            self.events.fetch_add(1, Ordering::SeqCst);
        }

        fn data_type_removed(&self, _dtm: &dyn DataTypeManager, _path: &DataTypePath) {
            self.events.fetch_add(1, Ordering::SeqCst);
        }

        fn data_type_renamed(
            &self,
            _dtm: &dyn DataTypeManager,
            _old_path: &DataTypePath,
            _new_path: &DataTypePath,
        ) {
            self.events.fetch_add(1, Ordering::SeqCst);
        }

        fn data_type_moved(
            &self,
            _dtm: &dyn DataTypeManager,
            _old_path: &DataTypePath,
            _new_path: &DataTypePath,
        ) {
            self.events.fetch_add(1, Ordering::SeqCst);
        }

        fn data_type_changed(&self, _dtm: &dyn DataTypeManager, _path: &DataTypePath) {
            self.events.fetch_add(1, Ordering::SeqCst);
        }

        fn data_type_replaced(
            &self,
            _dtm: &dyn DataTypeManager,
            _old_path: &DataTypePath,
            _new_path: &DataTypePath,
            _new_data_type: &dyn DataType,
        ) {
            self.events.fetch_add(1, Ordering::SeqCst);
        }

        fn favorites_changed(
            &self,
            _dtm: &dyn DataTypeManager,
            _path: &DataTypePath,
            _is_favorite: bool,
        ) {
            self.events.fetch_add(1, Ordering::SeqCst);
        }

        fn source_archive_changed(
            &self,
            _data_type_manager: &dyn DataTypeManager,
            _source_archive: &dyn SourceArchive,
        ) {
            self.events.fetch_add(1, Ordering::SeqCst);
        }

        fn source_archive_added(
            &self,
            _data_type_manager: &dyn DataTypeManager,
            _source_archive: &dyn SourceArchive,
        ) {
            self.events.fetch_add(1, Ordering::SeqCst);
        }

        fn program_architecture_changed(&self, _data_type_manager: &dyn DataTypeManager) {
            self.events.fetch_add(1, Ordering::SeqCst);
        }

        fn restored(&self, _data_type_manager: &dyn DataTypeManager) {
            self.events.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let listener = RecordingListener { events: AtomicUsize::new(0) };
        let manager = MockDataTypeManager;
        let dyn_listener: &dyn DataTypeManagerChangeListener = &listener;
        dyn_listener.restored(&manager);
        dyn_listener.program_architecture_changed(&manager);
        assert_eq!(listener.events.load(Ordering::SeqCst), 2);
    }
}
