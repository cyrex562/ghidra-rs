//! Service for opening file systems in a browser.
//!
//! Mirrors `ghidra.app.services.FileSystemBrowserService`.

use crate::filesystem::gfilesystem::fsrl::Fsrl;

/// A service to interact with file systems.
pub trait FileSystemBrowserService {
    /// Opens the given [`Fsrl`] in a file system browser.
    fn open_file_system(&self, fsrl: &dyn Fsrl);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};

    struct MockFsrl;

    impl Fsrl for MockFsrl {
        fn path(&self) -> Option<&str> {
            Some("/test/path")
        }

        fn md5(&self) -> Option<&str> {
            Some("abc123")
        }

        fn fs(&self) -> &dyn crate::filesystem::seam_stubs::FsrlRootLike {
            panic!("not implemented in test")
        }

        fn with_parts(&self, path: Option<String>, md5: Option<String>) -> Box<dyn Fsrl> {
            Box::new(MockFsrl)
        }

        fn make_nested(&self, fstype: &str) -> Box<dyn crate::filesystem::seam_stubs::FsrlRootLike> {
            panic!("not implemented in test")
        }

        fn name(&self) -> Option<String> {
            Some("test".to_string())
        }

        fn name_at_depth(&self, _nested_depth: u32) -> io::Result<Option<String>> {
            Ok(Some("test".to_string()))
        }

        fn nesting_depth(&self) -> u32 {
            0
        }

        fn is_md5_equal(&self, other_md5: Option<&str>) -> bool {
            self.md5() == other_md5
        }

        fn with_md5(&self, _new_md5: Option<String>) -> Box<dyn Fsrl> {
            Box::new(MockFsrl)
        }

        fn with_path(&self, _new_path: &str) -> Box<dyn Fsrl> {
            Box::new(MockFsrl)
        }

        fn with_path_from(&self, _copy_path: &dyn Fsrl) -> Box<dyn Fsrl> {
            Box::new(MockFsrl)
        }

        fn append_path(&self, _rel_path: &str) -> Box<dyn Fsrl> {
            Box::new(MockFsrl)
        }

        fn append_to_string_builder(&self, out: &mut String, _recurse: bool, _include_params: bool, _include_fs_root: bool) {
            out.push_str("test");
        }

        fn fsrl_string(&self) -> String {
            "test://path".to_string()
        }

        fn to_pretty_string(&self) -> String {
            "test://path".to_string()
        }

        fn to_pretty_fullpath_string(&self) -> String {
            "test://path".to_string()
        }

        fn to_string_part(&self) -> String {
            "test://path".to_string()
        }

        fn split(&self) -> Vec<&dyn Fsrl> {
            vec![self]
        }

        fn is_equivalent_str(&self, fsrl_str: Option<&str>) -> bool {
            fsrl_str == Some("test://path")
        }

        fn is_equivalent(&self, other: &dyn Fsrl) -> bool {
            other.fsrl_string() == self.fsrl_string()
        }

        fn is_descendant_of(&self, _potential_parent: &dyn Fsrl) -> bool {
            false
        }

        fn fsrl_equals(&self, other: &dyn Fsrl) -> bool {
            self.fsrl_string() == other.fsrl_string()
        }

        fn fsrl_hash(&self) -> u64 {
            42
        }
    }

    struct MockFileSystemBrowserService {
        open_count: Arc<Mutex<i32>>,
    }

    impl FileSystemBrowserService for MockFileSystemBrowserService {
        fn open_file_system(&self, _fsrl: &dyn Fsrl) {
            *self.open_count.lock().unwrap() += 1;
        }
    }

    #[test]
    fn test_open_file_system() {
        let open_count = Arc::new(Mutex::new(0));
        let service = MockFileSystemBrowserService {
            open_count: Arc::clone(&open_count),
        };

        let fsrl = MockFsrl;
        service.open_file_system(&fsrl);
        service.open_file_system(&fsrl);

        assert_eq!(*open_count.lock().unwrap(), 2);
    }

    #[test]
    fn test_service_trait_object() {
        let service: Box<dyn FileSystemBrowserService> = Box::new(MockFileSystemBrowserService {
            open_count: Arc::new(Mutex::new(0)),
        });

        let fsrl = MockFsrl;
        service.open_file_system(&fsrl);

        let open_count = Arc::new(Mutex::new(0));
        let second_service = MockFileSystemBrowserService {
            open_count: open_count.clone(),
        };
        second_service.open_file_system(&fsrl);
    }

    #[test]
    fn test_fsrl_mock_path() {
        let fsrl = MockFsrl;
        assert_eq!(fsrl.path(), Some("/test/path"));
        assert_eq!(fsrl.md5(), Some("abc123"));
        assert_eq!(fsrl.nesting_depth(), 0);
    }
}
