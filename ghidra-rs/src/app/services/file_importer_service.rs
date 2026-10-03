//! Service for importing files into Ghidra.
//!
//! Mirrors `ghidra.app.services.FileImporterService`.

use std::path::Path;

use crate::framework::model::DomainFolder;

/// Service for importing files into Ghidra.
///
/// This trait defines the interface for importing external files into a Ghidra project folder.
pub trait FileImporterService {
    /// Imports the given file into the specified Ghidra project folder.
    ///
    /// # Arguments
    ///
    /// * `folder` - the folder to use as the destination for the import. If `None`,
    ///              then the last used folder is preferred, with the root folder being used by default.
    /// * `file` - the path to the file to import.
    fn import_file(&self, folder: Option<&dyn DomainFolder>, file: &Path);

    /// Imports the given files into the specified Ghidra project folder.
    ///
    /// # Arguments
    ///
    /// * `folder` - the folder to use as the destination for the import. If `None`,
    ///              then the last used folder is preferred, with the root folder being used by default.
    /// * `files` - the paths to the files to import.
    fn import_files(&self, folder: Option<&dyn DomainFolder>, files: &[impl AsRef<Path>]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::path::PathBuf;

    /// A test implementation of FileImporterService that tracks calls.
    struct TestFileImporterService {
        imported_files: RefCell<Vec<PathBuf>>,
        batch_imports: RefCell<Vec<Vec<PathBuf>>>,
    }

    impl TestFileImporterService {
        fn new() -> Self {
            TestFileImporterService {
                imported_files: RefCell::new(Vec::new()),
                batch_imports: RefCell::new(Vec::new()),
            }
        }

        fn imported_files_count(&self) -> usize {
            self.imported_files.borrow().len()
        }

        fn batch_imports_count(&self) -> usize {
            self.batch_imports.borrow().len()
        }
    }

    impl FileImporterService for TestFileImporterService {
        fn import_file(&self, _folder: Option<&dyn DomainFolder>, file: &Path) {
            self.imported_files.borrow_mut().push(file.to_path_buf());
        }

        fn import_files(&self, _folder: Option<&dyn DomainFolder>, files: &[impl AsRef<Path>]) {
            let paths: Vec<PathBuf> = files.iter().map(|f| f.as_ref().to_path_buf()).collect();
            self.batch_imports.borrow_mut().push(paths.clone());
            self.imported_files.borrow_mut().extend(paths);
        }
    }

    #[test]
    fn test_import_single_file() {
        let service = TestFileImporterService::new();
        let path = Path::new("/tmp/test.bin");
        service.import_file(None, path);
        assert_eq!(service.imported_files_count(), 1);
    }

    #[test]
    fn test_import_single_file_with_folder() {
        let service = TestFileImporterService::new();
        let path = Path::new("/tmp/test.bin");
        service.import_file(None, path);
        assert_eq!(service.imported_files_count(), 1);
    }

    #[test]
    fn test_import_multiple_files() {
        let service = TestFileImporterService::new();
        let files = vec![
            PathBuf::from("/tmp/test1.bin"),
            PathBuf::from("/tmp/test2.bin"),
            PathBuf::from("/tmp/test3.bin"),
        ];
        service.import_files(None, files.as_slice());
        assert_eq!(service.imported_files_count(), 3);
        assert_eq!(service.batch_imports_count(), 1);
    }

    #[test]
    fn test_import_empty_file_list() {
        let service = TestFileImporterService::new();
        let files: Vec<PathBuf> = vec![];
        service.import_files(None, files.as_slice());
        assert_eq!(service.imported_files_count(), 0);
        assert_eq!(service.batch_imports_count(), 1);
    }

    #[test]
    fn test_sequential_imports() {
        let service = TestFileImporterService::new();
        service.import_file(None, Path::new("/tmp/test1.bin"));
        service.import_file(None, Path::new("/tmp/test2.bin"));
        assert_eq!(service.imported_files_count(), 2);
    }

    #[test]
    fn test_mixed_single_and_batch_imports() {
        let service = TestFileImporterService::new();
        service.import_file(None, Path::new("/tmp/single.bin"));
        let files = vec![
            PathBuf::from("/tmp/batch1.bin"),
            PathBuf::from("/tmp/batch2.bin"),
        ];
        service.import_files(None, files.as_slice());
        assert_eq!(service.imported_files_count(), 3);
    }
}
