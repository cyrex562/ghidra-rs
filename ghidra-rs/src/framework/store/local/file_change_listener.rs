use std::path::Path;

/// Defines a file change listener interface.
pub trait FileChangeListener {
    /// Notifies the listener that the specified file has been modified.
    ///
    /// If the file watcher was created with a lock file, the lock will be set
    /// on behalf of the caller. Implementations must not attempt to alter the lock.
    fn file_modified(&mut self, file: &Path);

    /// Notifies the listener that the specified file has been removed.
    ///
    /// If the file watcher was created with a lock file, the lock will be set
    /// on behalf of the caller. Implementations must not attempt to alter the lock.
    fn file_removed(&mut self, file: &Path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Recorder {
        modified: Vec<PathBuf>,
        removed: Vec<PathBuf>,
    }

    impl Recorder {
        fn new() -> Self {
            Self {
                modified: Vec::new(),
                removed: Vec::new(),
            }
        }
    }

    impl FileChangeListener for Recorder {
        fn file_modified(&mut self, file: &Path) {
            self.modified.push(file.to_path_buf());
        }

        fn file_removed(&mut self, file: &Path) {
            self.removed.push(file.to_path_buf());
        }
    }

    #[test]
    fn test_file_modified_recorded() {
        let mut r = Recorder::new();
        r.file_modified(Path::new("/tmp/foo.txt"));
        assert_eq!(r.modified, vec![PathBuf::from("/tmp/foo.txt")]);
        assert!(r.removed.is_empty());
    }

    #[test]
    fn test_file_removed_recorded() {
        let mut r = Recorder::new();
        r.file_removed(Path::new("/tmp/bar.txt"));
        assert_eq!(r.removed, vec![PathBuf::from("/tmp/bar.txt")]);
        assert!(r.modified.is_empty());
    }

    #[test]
    fn test_multiple_notifications() {
        let mut r = Recorder::new();
        r.file_modified(Path::new("/a"));
        r.file_modified(Path::new("/b"));
        r.file_removed(Path::new("/c"));
        assert_eq!(r.modified.len(), 2);
        assert_eq!(r.removed.len(), 1);
        assert_eq!(r.modified[0], PathBuf::from("/a"));
        assert_eq!(r.modified[1], PathBuf::from("/b"));
        assert_eq!(r.removed[0], PathBuf::from("/c"));
    }

    #[test]
    fn test_independent_modified_and_removed() {
        let mut r = Recorder::new();
        let path = Path::new("/shared/path");
        r.file_modified(path);
        r.file_removed(path);
        assert_eq!(r.modified, vec![path.to_path_buf()]);
        assert_eq!(r.removed, vec![path.to_path_buf()]);
    }
}
