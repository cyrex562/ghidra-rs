use std::path::PathBuf;

use crate::format::dwarf::external::debug_file_provider::{DebugFileProvider, FileProviderResult};
use crate::format::dwarf::external::debug_stream_provider::StreamInfo;
use crate::format::seam_stubs::ExternalDebugInfo;
use crate::util::task::TaskMonitor;

/// Mirrors `ghidra.app.util.bin.format.dwarf.external.DebugFileStorage`.
/// A provider that can not only find and provide debug files, but also store them.
///
/// Extends [`DebugFileProvider`] with the ability to store debug files.
pub trait DebugFileStorage: DebugFileProvider + Send + Sync {
    /// Stores a stream of debug information.
    ///
    /// Returns the path to the stored file if successful, or an error if storage fails.
    ///
    /// Mirrors `DebugFileStorage.putStream(ExternalDebugInfo, StreamInfo, TaskMonitor)`.
    fn put_stream(
        &self,
        id: &dyn ExternalDebugInfo,
        stream: StreamInfo,
        monitor: &dyn TaskMonitor,
    ) -> FileProviderResult<PathBuf>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::dwarf::external::debug_info_provider::DebugInfoProvider;
    use crate::format::dwarf::external::debug_info_provider_status::DebugInfoProviderStatus;
    use crate::format::dwarf::external::object_type::ObjectType;
    use crate::util::exception::CancelledException;
    use std::io::Cursor;

    struct MockDebugFileStorage {
        name: String,
        stored_path: PathBuf,
    }

    impl DebugInfoProvider for MockDebugFileStorage {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_descriptive_name(&self) -> String {
            format!("Mock Debug File Storage: {}", self.name)
        }

        fn get_status(&self, _monitor: &dyn TaskMonitor) -> DebugInfoProviderStatus {
            DebugInfoProviderStatus::Valid
        }
    }

    impl DebugFileProvider for MockDebugFileStorage {
        fn get_file(
            &self,
            _debug_info: &dyn ExternalDebugInfo,
            _monitor: &dyn TaskMonitor,
        ) -> FileProviderResult<Option<PathBuf>> {
            Ok(Some(self.stored_path.clone()))
        }
    }

    impl DebugFileStorage for MockDebugFileStorage {
        fn put_stream(
            &self,
            _id: &dyn ExternalDebugInfo,
            stream: StreamInfo,
            _monitor: &dyn TaskMonitor,
        ) -> FileProviderResult<PathBuf> {
            if stream.content_length > 0 {
                Ok(self.stored_path.clone())
            } else {
                Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "empty stream").into())
            }
        }
    }

    struct MockTaskMonitor;

    impl TaskMonitor for MockTaskMonitor {
        fn is_cancelled(&self) -> bool {
            false
        }

        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }

        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }

        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }

        fn check_cancelled(&self) -> Result<(), CancelledException> {
            Ok(())
        }

        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }

        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            false
        }

        fn clear_cancelled(&self) {}
    }

    struct MockExternalDebugInfo;

    impl ExternalDebugInfo for MockExternalDebugInfo {
        fn from_program(&self, _program: &dyn crate::format::seam_stubs::Program) -> Box<dyn ExternalDebugInfo> {
            Box::new(MockExternalDebugInfo)
        }

        fn for_build_id(&self, _build_id: &str) -> Box<dyn ExternalDebugInfo> {
            Box::new(MockExternalDebugInfo)
        }

        fn for_debug_link(&self, _debug_link_filename: &str, _crc: i32) -> Box<dyn ExternalDebugInfo> {
            Box::new(MockExternalDebugInfo)
        }

        fn has_debug_link(&self) -> bool {
            false
        }

        fn get_filename(&self) -> String {
            "test.debug".to_string()
        }

        fn get_crc(&self) -> i32 {
            0
        }

        fn get_build_id(&self) -> String {
            String::new()
        }

        fn has_build_id(&self) -> bool {
            false
        }

        fn get_object_type(&self) -> ObjectType {
            ObjectType::DebugInfo
        }

        fn get_extra(&self) -> String {
            String::new()
        }

        fn with_type(&self, _new_object_type: ObjectType, _new_extra: &str) -> Box<dyn ExternalDebugInfo> {
            Box::new(MockExternalDebugInfo)
        }

        fn to_string(&self) -> String {
            "MockExternalDebugInfo".to_string()
        }
    }

    #[test]
    fn put_stream_stores_file_successfully() {
        let storage = MockDebugFileStorage {
            name: "test_storage".to_string(),
            stored_path: PathBuf::from("/tmp/test.debug"),
        };

        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let cursor = Cursor::new(data);
        let stream_info = StreamInfo::new(cursor, 4);

        let monitor = MockTaskMonitor;
        let debug_info = MockExternalDebugInfo;

        let result = storage.put_stream(&debug_info, stream_info, &monitor);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PathBuf::from("/tmp/test.debug"));
    }

    #[test]
    fn put_stream_rejects_empty_stream() {
        let storage = MockDebugFileStorage {
            name: "test_storage".to_string(),
            stored_path: PathBuf::from("/tmp/test.debug"),
        };

        let data: Vec<u8> = vec![];
        let cursor = Cursor::new(data);
        let stream_info = StreamInfo::new(cursor, 0);

        let monitor = MockTaskMonitor;
        let debug_info = MockExternalDebugInfo;

        let result = storage.put_stream(&debug_info, stream_info, &monitor);
        assert!(result.is_err());
    }
}
