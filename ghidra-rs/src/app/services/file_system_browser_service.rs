//! Service for opening file systems in a browser.
//!
//! Mirrors `ghidra.app.services.FileSystemBrowserService`.

use crate::filesystem::gfilesystem::fsrl::Fsrl;

/// A service to interact with file systems.
pub trait FileSystemBrowserService {
    /// Opens the given [`Fsrl`] in a file system browser.
    fn open_file_system(&self, fsrl: &Fsrl);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn test_fsrl() -> Fsrl {
        Fsrl::from_string("file:///test/path?MD5=abc123").unwrap()
    }

    struct MockFileSystemBrowserService {
        opened: Arc<Mutex<Vec<String>>>,
    }

    impl FileSystemBrowserService for MockFileSystemBrowserService {
        fn open_file_system(&self, fsrl: &Fsrl) {
            self.opened.lock().unwrap().push(fsrl.to_string());
        }
    }

    #[test]
    fn test_open_file_system() {
        let opened = Arc::new(Mutex::new(Vec::new()));
        let service = MockFileSystemBrowserService { opened: Arc::clone(&opened) };

        let fsrl = test_fsrl();
        service.open_file_system(&fsrl);
        service.open_file_system(&fsrl);

        assert_eq!(
            *opened.lock().unwrap(),
            vec!["file:///test/path?MD5=abc123".to_string(); 2]
        );
    }

    #[test]
    fn test_service_trait_object() {
        let opened = Arc::new(Mutex::new(Vec::new()));
        let service: Box<dyn FileSystemBrowserService> =
            Box::new(MockFileSystemBrowserService { opened: Arc::clone(&opened) });

        let fsrl = test_fsrl();
        service.open_file_system(&fsrl);
        assert_eq!(opened.lock().unwrap().len(), 1);
        assert_eq!(fsrl.path(), Some("/test/path"));
        assert_eq!(fsrl.md5(), Some("abc123"));
        assert_eq!(fsrl.nesting_depth(), 1);
    }
}
