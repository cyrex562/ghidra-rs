use std::path::PathBuf;

use crate::format::dwarf::external::debug_info_provider::DebugInfoProvider;
use crate::format::dwarf::external::object_type::ObjectType;
use crate::format::seam_stubs::ExternalDebugInfo;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Represents an error that occurred during file provision.
#[derive(Debug)]
pub enum FileProviderError {
    Io(std::io::Error),
    Cancelled(CancelledException),
}

impl From<std::io::Error> for FileProviderError {
    fn from(err: std::io::Error) -> Self {
        FileProviderError::Io(err)
    }
}

impl From<CancelledException> for FileProviderError {
    fn from(err: CancelledException) -> Self {
        FileProviderError::Cancelled(err)
    }
}

impl std::fmt::Display for FileProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileProviderError::Io(err) => write!(f, "IO error: {}", err),
            FileProviderError::Cancelled(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for FileProviderError {}

pub type FileProviderResult<T> = Result<T, FileProviderError>;

/// Mirrors `ghidra.app.util.bin.format.dwarf.external.DebugFileProvider`.
/// A provider that can directly provide debug files.
///
/// Extends [`DebugInfoProvider`] with the ability to directly provide [`PathBuf`] files
/// that fulfill the criteria specified in an [`ExternalDebugInfo`].
pub trait DebugFileProvider: DebugInfoProvider + Send + Sync {
    /// Searches for a debug file that fulfills the criteria specified in the [`ExternalDebugInfo`].
    ///
    /// Returns `Ok(None)` if no matching file is found, `Ok(Some(path))` if a matching file
    /// is found, or an error if the search fails.
    ///
    /// Mirrors `DebugFileProvider.getFile(ExternalDebugInfo, TaskMonitor)`.
    fn get_file(
        &self,
        debug_info: &dyn ExternalDebugInfo,
        monitor: &dyn TaskMonitor,
    ) -> FileProviderResult<Option<PathBuf>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::dwarf::external::debug_info_provider_status::DebugInfoProviderStatus;

    struct MockDebugFileProvider {
        name: String,
        descriptive_name: String,
        status: DebugInfoProviderStatus,
        file: Option<PathBuf>,
    }

    impl DebugInfoProvider for MockDebugFileProvider {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_descriptive_name(&self) -> String {
            self.descriptive_name.clone()
        }

        fn get_status(&self, _monitor: &dyn TaskMonitor) -> DebugInfoProviderStatus {
            self.status
        }
    }

    impl DebugFileProvider for MockDebugFileProvider {
        fn get_file(
            &self,
            _debug_info: &dyn ExternalDebugInfo,
            _monitor: &dyn TaskMonitor,
        ) -> FileProviderResult<Option<PathBuf>> {
            Ok(self.file.clone())
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
    fn get_file_returns_file_when_provided() {
        let file_path = PathBuf::from("/path/to/debug/file");
        let provider = MockDebugFileProvider {
            name: "test://data".to_string(),
            descriptive_name: "Test File Provider".to_string(),
            status: DebugInfoProviderStatus::Valid,
            file: Some(file_path.clone()),
        };

        let monitor = MockTaskMonitor;
        let debug_info = MockExternalDebugInfo;

        let result = provider.get_file(&debug_info, &monitor);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(file_path));
    }

    #[test]
    fn get_file_returns_none_when_not_found() {
        let provider = MockDebugFileProvider {
            name: "test://data".to_string(),
            descriptive_name: "Test File Provider".to_string(),
            status: DebugInfoProviderStatus::Valid,
            file: None,
        };

        let monitor = MockTaskMonitor;
        let debug_info = MockExternalDebugInfo;

        let result = provider.get_file(&debug_info, &monitor);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn file_provider_error_display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let file_err: FileProviderError = io_err.into();
        let display_str = file_err.to_string();
        assert!(display_str.contains("IO error"));
    }

    #[test]
    fn file_provider_error_display_cancelled() {
        let cancelled = CancelledException::new("operation cancelled");
        let file_err: FileProviderError = cancelled.into();
        let display_str = file_err.to_string();
        assert!(display_str.contains("operation cancelled"));
    }
}
