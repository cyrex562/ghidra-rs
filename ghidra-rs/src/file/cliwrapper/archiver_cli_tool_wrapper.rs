use std::io::Write;
use std::path::Path;

use crate::filesystem::gfilesystem::fileinfo::file_type::FileType;
use crate::util::task::TaskMonitor;

use super::CliToolWrapper;

/// Entry metadata within an archive.
///
/// Mirrors `ghidra.file.cliwrapper.ArchiverCliToolWrapper.Entry`.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub size: u64,
    pub file_type: FileType,
}

/// Functionality that an archiver CLI tool can expose.
///
/// Mirrors `ghidra.file.cliwrapper.ArchiverCliToolWrapper`.
pub trait ArchiverCliToolWrapper: CliToolWrapper {
    /// Lists the entries in an archive file.
    ///
    /// # Arguments
    ///
    /// * `archive_file` - Path to the archive file.
    /// * `monitor` - Task monitor for progress tracking and cancellation.
    ///
    /// # Returns
    ///
    /// A vector of entries contained in the archive, or an I/O error if listing fails.
    fn get_listing(&self, archive_file: &Path, monitor: &dyn TaskMonitor) -> std::io::Result<Vec<Entry>>;

    /// Extracts an entry from an archive to the specified output stream.
    ///
    /// # Arguments
    ///
    /// * `archive_file` - Path to the archive file.
    /// * `entry` - The entry to extract.
    /// * `os` - Output stream to write the extracted data to.
    /// * `monitor` - Task monitor for progress tracking and cancellation.
    ///
    /// # Returns
    ///
    /// `Ok(())` if extraction succeeds, or an I/O error if it fails.
    fn extract(
        &self,
        archive_file: &Path,
        entry: &Entry,
        os: &mut dyn Write,
        monitor: &dyn TaskMonitor,
    ) -> std::io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_construction() {
        let entry = Entry {
            name: "test.txt".to_string(),
            size: 1024,
            file_type: FileType::File,
        };
        assert_eq!(entry.name, "test.txt");
        assert_eq!(entry.size, 1024);
        assert_eq!(entry.file_type, FileType::File);
    }

    #[test]
    fn entry_clone() {
        let entry = Entry {
            name: "file.bin".to_string(),
            size: 2048,
            file_type: FileType::File,
        };
        let cloned = entry.clone();
        assert_eq!(entry.name, cloned.name);
        assert_eq!(entry.size, cloned.size);
        assert_eq!(entry.file_type, cloned.file_type);
    }

    #[test]
    fn entry_debug_format() {
        let entry = Entry {
            name: "test".to_string(),
            size: 512,
            file_type: FileType::Directory,
        };
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("test"));
        assert!(debug_str.contains("512"));
    }

    struct MockArchiverCliToolWrapper {
        entries: Vec<Entry>,
        should_fail: bool,
    }

    impl CliToolWrapper for MockArchiverCliToolWrapper {
        fn is_valid(&self, _monitor: &dyn TaskMonitor) -> bool {
            true
        }
    }

    impl ArchiverCliToolWrapper for MockArchiverCliToolWrapper {
        fn get_listing(&self, _archive_file: &Path, _monitor: &dyn TaskMonitor) -> std::io::Result<Vec<Entry>> {
            if self.should_fail {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "test failure",
                ))
            } else {
                Ok(self.entries.clone())
            }
        }

        fn extract(
            &self,
            _archive_file: &Path,
            _entry: &Entry,
            _os: &mut dyn Write,
            _monitor: &dyn TaskMonitor,
        ) -> std::io::Result<()> {
            if self.should_fail {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "test failure",
                ))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn trait_object_construction() {
        let mock = MockArchiverCliToolWrapper {
            entries: vec![],
            should_fail: false,
        };
        let _: &dyn ArchiverCliToolWrapper = &mock;
    }

    #[test]
    fn get_listing_success() {
        let entry = Entry {
            name: "file.txt".to_string(),
            size: 1024,
            file_type: FileType::File,
        };
        let mock = MockArchiverCliToolWrapper {
            entries: vec![entry.clone()],
            should_fail: false,
        };
        let monitor = crate::util::task::DummyMonitor;
        let result = mock.get_listing(Path::new("test.zip"), &monitor);
        assert!(result.is_ok());
        let entries = result.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "file.txt");
    }

    #[test]
    fn get_listing_failure() {
        let mock = MockArchiverCliToolWrapper {
            entries: vec![],
            should_fail: true,
        };
        let monitor = crate::util::task::DummyMonitor;
        let result = mock.get_listing(Path::new("test.zip"), &monitor);
        assert!(result.is_err());
    }

    #[test]
    fn extract_success() {
        let entry = Entry {
            name: "file.txt".to_string(),
            size: 5,
            file_type: FileType::File,
        };
        let mock = MockArchiverCliToolWrapper {
            entries: vec![],
            should_fail: false,
        };
        let monitor = crate::util::task::DummyMonitor;
        let mut output = Vec::new();
        let result = mock.extract(Path::new("test.zip"), &entry, &mut output, &monitor);
        assert!(result.is_ok());
    }

    #[test]
    fn extract_failure() {
        let entry = Entry {
            name: "file.txt".to_string(),
            size: 5,
            file_type: FileType::File,
        };
        let mock = MockArchiverCliToolWrapper {
            entries: vec![],
            should_fail: true,
        };
        let monitor = crate::util::task::DummyMonitor;
        let mut output = Vec::new();
        let result = mock.extract(Path::new("test.zip"), &entry, &mut output, &monitor);
        assert!(result.is_err());
    }
}
