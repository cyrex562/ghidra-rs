use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_type_manager_change_listener::DataTypeManagerChangeListener;
use crate::program::model::data::source_archive::SourceArchive;
use crate::program::seam_stubs::DataTypePath;

/// An adapter providing default (empty) implementations for all [`DataTypeManagerChangeListener`] methods.
///
/// Port of `ghidra.program.model.data.DataTypeManagerChangeListenerAdapter`.
/// Users can implement this trait and override only the methods they care about.
#[derive(Debug, Clone, Copy)]
pub struct DataTypeManagerChangeListenerAdapter;

impl DataTypeManagerChangeListener for DataTypeManagerChangeListenerAdapter {
    fn category_added(&self, _dtm: &dyn DataTypeManager, _path: &CategoryPath) {}

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

    fn favorites_changed(&self, _dtm: &dyn DataTypeManager, _path: &DataTypePath, _is_favorite: bool) {}

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

    fn restored(&self, _data_type_manager: &dyn DataTypeManager) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDataTypeManager;

    impl DataTypeManager for MockDataTypeManager {}

    struct MockDataType;

    impl DataType for MockDataType {}

    struct MockSourceArchive;

    impl SourceArchive for MockSourceArchive {
        fn source_archive_id(&self) -> crate::util::UniversalID {
            crate::util::UniversalID::new(0)
        }
        fn domain_file_id(&self) -> String {
            String::new()
        }
        fn archive_type(&self) -> crate::program::model::data::archive_type::ArchiveType {
            crate::program::model::data::archive_type::ArchiveType::Program
        }
        fn name(&self) -> String {
            String::new()
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

    #[test]
    fn category_added_does_nothing() {
        let adapter = DataTypeManagerChangeListenerAdapter;
        let manager = MockDataTypeManager;
        let path = CategoryPath::parse("/test").unwrap();
        adapter.category_added(&manager, &path);
    }

    #[test]
    fn category_removed_does_nothing() {
        let adapter = DataTypeManagerChangeListenerAdapter;
        let manager = MockDataTypeManager;
        let path = CategoryPath::parse("/test").unwrap();
        adapter.category_removed(&manager, &path);
    }

    #[test]
    fn category_renamed_does_nothing() {
        let adapter = DataTypeManagerChangeListenerAdapter;
        let manager = MockDataTypeManager;
        let old_path = CategoryPath::parse("/old").unwrap();
        let new_path = CategoryPath::parse("/new").unwrap();
        adapter.category_renamed(&manager, &old_path, &new_path);
    }

    #[test]
    fn category_moved_does_nothing() {
        let adapter = DataTypeManagerChangeListenerAdapter;
        let manager = MockDataTypeManager;
        let old_path = CategoryPath::parse("/old").unwrap();
        let new_path = CategoryPath::parse("/new").unwrap();
        adapter.category_moved(&manager, &old_path, &new_path);
    }

    #[test]
    fn data_type_added_does_nothing() {
        let adapter = DataTypeManagerChangeListenerAdapter;
        let manager = MockDataTypeManager;
        let path = DataTypePath::parse("/test/Foo").unwrap();
        adapter.data_type_added(&manager, &path);
    }

    #[test]
    fn data_type_removed_does_nothing() {
        let adapter = DataTypeManagerChangeListenerAdapter;
        let manager = MockDataTypeManager;
        let path = DataTypePath::parse("/test/Foo").unwrap();
        adapter.data_type_removed(&manager, &path);
    }

    #[test]
    fn data_type_renamed_does_nothing() {
        let adapter = DataTypeManagerChangeListenerAdapter;
        let manager = MockDataTypeManager;
        let old_path = DataTypePath::parse("/test/OldFoo").unwrap();
        let new_path = DataTypePath::parse("/test/NewFoo").unwrap();
        adapter.data_type_renamed(&manager, &old_path, &new_path);
    }

    #[test]
    fn data_type_moved_does_nothing() {
        let adapter = DataTypeManagerChangeListenerAdapter;
        let manager = MockDataTypeManager;
        let old_path = DataTypePath::parse("/old/Foo").unwrap();
        let new_path = DataTypePath::parse("/new/Foo").unwrap();
        adapter.data_type_moved(&manager, &old_path, &new_path);
    }

    #[test]
    fn data_type_changed_does_nothing() {
        let adapter = DataTypeManagerChangeListenerAdapter;
        let manager = MockDataTypeManager;
        let path = DataTypePath::parse("/test/Foo").unwrap();
        adapter.data_type_changed(&manager, &path);
    }

    #[test]
    fn data_type_replaced_does_nothing() {
        let adapter = DataTypeManagerChangeListenerAdapter;
        let manager = MockDataTypeManager;
        let old_path = DataTypePath::parse("/test/OldFoo").unwrap();
        let new_path = DataTypePath::parse("/test/NewFoo").unwrap();
        let mock_data_type = MockDataType;
        adapter.data_type_replaced(&manager, &old_path, &new_path, &mock_data_type);
    }

    #[test]
    fn favorites_changed_does_nothing() {
        let adapter = DataTypeManagerChangeListenerAdapter;
        let manager = MockDataTypeManager;
        let path = DataTypePath::parse("/test/Foo").unwrap();
        adapter.favorites_changed(&manager, &path, true);
    }

    #[test]
    fn source_archive_changed_does_nothing() {
        let adapter = DataTypeManagerChangeListenerAdapter;
        let manager = MockDataTypeManager;
        let archive = MockSourceArchive;
        adapter.source_archive_changed(&manager, &archive);
    }

    #[test]
    fn source_archive_added_does_nothing() {
        let adapter = DataTypeManagerChangeListenerAdapter;
        let manager = MockDataTypeManager;
        let archive = MockSourceArchive;
        adapter.source_archive_added(&manager, &archive);
    }

    #[test]
    fn program_architecture_changed_does_nothing() {
        let adapter = DataTypeManagerChangeListenerAdapter;
        let manager = MockDataTypeManager;
        adapter.program_architecture_changed(&manager);
    }

    #[test]
    fn restored_does_nothing() {
        let adapter = DataTypeManagerChangeListenerAdapter;
        let manager = MockDataTypeManager;
        adapter.restored(&manager);
    }

    #[test]
    fn adapter_is_copy() {
        let a = DataTypeManagerChangeListenerAdapter;
        let b = a;
        let _ = a;
        let _ = b;
    }

    #[test]
    fn adapter_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DataTypeManagerChangeListenerAdapter>();
    }

    #[test]
    fn adapter_usable_as_trait_object() {
        let adapter = DataTypeManagerChangeListenerAdapter;
        let manager = MockDataTypeManager;
        let listener: &dyn DataTypeManagerChangeListener = &adapter;
        let path = DataTypePath::parse("/test/Foo").unwrap();
        listener.data_type_added(&manager, &path);
    }
}
