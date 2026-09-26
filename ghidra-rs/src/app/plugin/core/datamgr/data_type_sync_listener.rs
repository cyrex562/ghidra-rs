use crate::app::seam_stubs::DataTypeSyncInfo;
use crate::program::model::data::data_type::DataType;

/// Interface to define a method that is called when the selected data type changes in
/// the data type sync table.
///
/// Corresponds to the Java interface `ghidra.app.plugin.core.datamgr.DataTypeSyncListener`.
pub trait DataTypeSyncListener: Send + Sync {
    /// Notification that the given data type was selected.
    fn data_type_selected(&self, sync_info: &dyn DataTypeSyncInfo);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSyncInfo {
        name: String,
    }

    impl DataTypeSyncInfo for MockSyncInfo {
        fn get_sync_state(&self) -> crate::app::plugin::core::datamgr::DataTypeSyncState {
            crate::app::plugin::core::datamgr::DataTypeSyncState::Unknown
        }

        fn can_update(&self) -> bool {
            true
        }

        fn can_commit(&self) -> bool {
            true
        }

        fn can_revert(&self) -> bool {
            true
        }

        fn commit(&self) {}

        fn update(&self) {}

        fn revert(&self) {}

        fn disassociate(&self) {}

        fn get_source_dt_path(&self) -> String {
            "/source/path".to_string()
        }

        fn get_ref_dt_path(&self) -> String {
            "/ref/path".to_string()
        }

        fn get_last_change_time(&self, _use_source: bool) -> i64 {
            1234567890
        }

        fn get_last_change_time_string(&self, _use_source: bool) -> String {
            "2009-02-13T23:31:30Z".to_string()
        }

        fn get_last_sync_time_string(&self) -> String {
            "2009-02-13T23:31:30Z".to_string()
        }

        fn get_last_sync_time(&self) -> i64 {
            1234567890
        }

        fn get_ref_data_type(&self) -> Box<dyn DataType> {
            unimplemented!()
        }

        fn get_source_data_type(&self) -> Box<dyn DataType> {
            unimplemented!()
        }

        fn has_change(&self) -> bool {
            false
        }

        fn sync_times(&self) {}

        fn get_name(&self) -> String {
            self.name.clone()
        }
    }

    struct MockListener;

    impl DataTypeSyncListener for MockListener {
        fn data_type_selected(&self, sync_info: &dyn DataTypeSyncInfo) {
            assert_eq!(sync_info.get_name(), "TestType");
            assert_eq!(sync_info.get_source_dt_path(), "/source/path");
            assert_eq!(sync_info.get_ref_dt_path(), "/ref/path");
            assert_eq!(sync_info.get_last_change_time(true), 1234567890);
            assert!(sync_info.can_update());
            assert!(sync_info.can_commit());
            assert!(sync_info.can_revert());
            assert!(!sync_info.has_change());
        }
    }

    #[test]
    fn test_data_type_listener_selection() {
        let listener = MockListener;
        let sync_info = MockSyncInfo {
            name: "TestType".to_string(),
        };

        listener.data_type_selected(&sync_info as &dyn DataTypeSyncInfo);
    }

    #[test]
    fn test_sync_info_properties() {
        let sync_info = MockSyncInfo {
            name: "MyDataType".to_string(),
        };

        assert_eq!(sync_info.get_name(), "MyDataType");
        assert!(sync_info.can_update());
        assert!(sync_info.can_commit());
        assert!(sync_info.can_revert());
        assert!(!sync_info.has_change());
    }
}
