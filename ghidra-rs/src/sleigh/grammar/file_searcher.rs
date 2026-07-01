use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error as ThisError;

/// Exception thrown when file search operations encounter errors.
///
/// Mirrors `ghidra.sleigh.grammar.FileSearcher.FileSearcherException`.
#[derive(Debug, ThisError)]
#[error("{message}")]
pub struct FileSearcherException {
    message: String,
}

impl FileSearcherException {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Utility to search for files matching given extensions in a directory.
///
/// Mirrors `ghidra.sleigh.grammar.FileSearcher`.
pub struct FileSearcher;

impl FileSearcher {
    /// Gathers all files from the given directory that match the provided extensions.
    ///
    /// # Arguments
    /// * `curr_dir_to_search` - The directory to search
    /// * `curr_file_type_ext_list` - List of file extensions to search for (e.g., ".java", ".txt")
    /// * `use_recursion_in_search` - Whether to search recursively into subdirectories
    ///
    /// # Returns
    /// A vector of `PathBuf` entries for all matching files found
    ///
    /// # Errors
    /// Returns `FileSearcherException` if:
    /// * The directory parameter is null or not a valid directory
    /// * The extension list is null or empty
    pub fn gather_files_from_dir(
        curr_dir_to_search: &Path,
        curr_file_type_ext_list: &[String],
        use_recursion_in_search: bool,
    ) -> Result<Vec<PathBuf>, FileSearcherException> {
        let mut found_files_from_search_list = Vec::new();

        // Sanity checks before use!
        if !curr_dir_to_search.exists() {
            return Err(FileSearcherException::new(
                "The Directory to Search cannot be NULL!",
            ));
        }

        if !curr_dir_to_search.is_dir() {
            return Err(FileSearcherException::new(
                "The Directory must be a valid Directory! It currently is not!",
            ));
        }

        if curr_file_type_ext_list.is_empty() {
            return Err(FileSearcherException::new(
                "Must Provide at least 1 File Type Extension to search for!",
            ));
        }

        // Another sanity check!
        if curr_dir_to_search.is_dir() {
            Self::locate_files_from_dir_root(
                curr_dir_to_search,
                curr_file_type_ext_list,
                &mut found_files_from_search_list,
                use_recursion_in_search,
            )?;
        }

        Ok(found_files_from_search_list)
    }

    /// Recursively locates files of the given types and collects them.
    ///
    /// This is a private helper method that performs the recursive traversal.
    fn locate_files_from_dir_root(
        curr_dir: &Path,
        curr_file_type_ext_list: &[String],
        curr_files_from_search_list: &mut Vec<PathBuf>,
        recursive_search: bool,
    ) -> Result<(), FileSearcherException> {
        let entries = fs::read_dir(curr_dir).map_err(|e| {
            FileSearcherException::new(format!(
                "Failed to read directory {}: {}",
                curr_dir.display(),
                e
            ))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                FileSearcherException::new(format!("Failed to read directory entry: {}", e))
            })?;
            let path = entry.path();

            if path.is_dir() {
                if recursive_search {
                    // RECURSION!!!
                    Self::locate_files_from_dir_root(
                        &path,
                        curr_file_type_ext_list,
                        curr_files_from_search_list,
                        recursive_search,
                    )?;
                }
            } else {
                for curr_file_type_ext in curr_file_type_ext_list {
                    if let Some(file_name) = path.file_name() {
                        if let Some(file_name_str) = file_name.to_str() {
                            if file_name_str.ends_with(curr_file_type_ext) {
                                curr_files_from_search_list.push(path.clone());
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn gathers_files_with_single_extension() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create test files
        File::create(temp_path.join("file1.txt")).unwrap();
        File::create(temp_path.join("file2.txt")).unwrap();
        File::create(temp_path.join("file3.java")).unwrap();

        let extensions = vec![".txt".to_string()];
        let result =
            FileSearcher::gather_files_from_dir(temp_path, &extensions, false).unwrap();

        assert_eq!(result.len(), 2);
    }

    #[test]
    fn gathers_files_with_multiple_extensions() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create test files
        File::create(temp_path.join("file1.txt")).unwrap();
        File::create(temp_path.join("file2.java")).unwrap();
        File::create(temp_path.join("file3.rs")).unwrap();

        let extensions = vec![".txt".to_string(), ".java".to_string()];
        let result =
            FileSearcher::gather_files_from_dir(temp_path, &extensions, false).unwrap();

        assert_eq!(result.len(), 2);
    }

    #[test]
    fn recursive_search_finds_files_in_subdirectories() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create files and subdirectories
        File::create(temp_path.join("file1.txt")).unwrap();
        fs::create_dir(temp_path.join("subdir")).unwrap();
        File::create(temp_path.join("subdir").join("file2.txt")).unwrap();

        let extensions = vec![".txt".to_string()];
        let result = FileSearcher::gather_files_from_dir(temp_path, &extensions, true).unwrap();

        assert_eq!(result.len(), 2);
    }

    #[test]
    fn non_recursive_search_ignores_subdirectories() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create files and subdirectories
        File::create(temp_path.join("file1.txt")).unwrap();
        fs::create_dir(temp_path.join("subdir")).unwrap();
        File::create(temp_path.join("subdir").join("file2.txt")).unwrap();

        let extensions = vec![".txt".to_string()];
        let result =
            FileSearcher::gather_files_from_dir(temp_path, &extensions, false).unwrap();

        assert_eq!(result.len(), 1);
    }

    #[test]
    fn no_matching_extensions_returns_empty_list() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create test files
        File::create(temp_path.join("file1.txt")).unwrap();
        File::create(temp_path.join("file2.txt")).unwrap();

        let extensions = vec![".java".to_string()];
        let result =
            FileSearcher::gather_files_from_dir(temp_path, &extensions, false).unwrap();

        assert_eq!(result.len(), 0);
    }

    #[test]
    fn error_on_null_directory() {
        let extensions = vec![".txt".to_string()];
        let result = FileSearcher::gather_files_from_dir(
            Path::new("/nonexistent/directory"),
            &extensions,
            false,
        );

        assert!(result.is_err());
    }

    #[test]
    fn error_on_file_instead_of_directory() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let file_path = temp_path.join("file.txt");
        File::create(&file_path).unwrap();

        let extensions = vec![".txt".to_string()];
        let result = FileSearcher::gather_files_from_dir(&file_path, &extensions, false);

        assert!(result.is_err());
    }

    #[test]
    fn error_on_empty_extension_list() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        let extensions: Vec<String> = vec![];
        let result = FileSearcher::gather_files_from_dir(temp_path, &extensions, false);

        assert!(result.is_err());
    }

    #[test]
    fn empty_directory_returns_empty_list() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        let extensions = vec![".txt".to_string()];
        let result =
            FileSearcher::gather_files_from_dir(temp_path, &extensions, false).unwrap();

        assert_eq!(result.len(), 0);
    }

    #[test]
    fn extension_matching_is_exact() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create test files
        File::create(temp_path.join("file1.txt")).unwrap();
        File::create(temp_path.join("file2.txtbak")).unwrap();
        File::create(temp_path.join("file3.atxt")).unwrap();

        let extensions = vec![".txt".to_string()];
        let result =
            FileSearcher::gather_files_from_dir(temp_path, &extensions, false).unwrap();

        assert_eq!(result.len(), 1);
    }

    #[test]
    fn recursive_search_multiple_levels() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create nested directory structure
        fs::create_dir(temp_path.join("level1")).unwrap();
        fs::create_dir(temp_path.join("level1").join("level2")).unwrap();
        File::create(temp_path.join("file1.txt")).unwrap();
        File::create(temp_path.join("level1").join("file2.txt")).unwrap();
        File::create(temp_path.join("level1").join("level2").join("file3.txt")).unwrap();

        let extensions = vec![".txt".to_string()];
        let result = FileSearcher::gather_files_from_dir(temp_path, &extensions, true).unwrap();

        assert_eq!(result.len(), 3);
    }

    #[test]
    fn file_searcher_exception_message() {
        let exc = FileSearcherException::new("Test error message");
        assert_eq!(exc.to_string(), "Test error message");
    }
}
