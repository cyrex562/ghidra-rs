use crate::generic::jar::resource_file::ResourceFile;
use thiserror::Error;

/// An error produced during GhidraBundle::build() with a timestamp.
///
/// Port of `ghidra.app.plugin.core.osgi.BuildError`.
#[derive(Error, Debug)]
#[error("{message}")]
pub struct BuildError {
    #[from(ignore)]
    last_modified: u64,
    message: String,
}

impl BuildError {
    /// Construct an object to record error message produced for `source_file`.
    ///
    /// # Arguments
    /// * `source_file` - The file causing this error
    pub fn new(source_file: &ResourceFile) -> Self {
        Self {
            last_modified: source_file.last_modified(),
            message: String::new(),
        }
    }

    /// Append the given string to the current error message.
    ///
    /// # Arguments
    /// * `s` - The string to append
    pub fn append(&mut self, s: &str) {
        self.message.push_str(s);
    }

    /// The error message.
    pub fn get_message(&self) -> &str {
        &self.message
    }

    /// The last modified time of the source for this build error.
    pub fn get_last_modified(&self) -> u64 {
        self.last_modified
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_last_modified_from_source_file() {
        let source_file = ResourceFile::new(std::path::PathBuf::from("/tmp/test.txt"));
        let error = BuildError::new(&source_file);
        assert_eq!(error.get_last_modified(), source_file.last_modified());
    }

    #[test]
    fn new_initializes_empty_message() {
        let source_file = ResourceFile::new(std::path::PathBuf::from("/tmp/test.txt"));
        let error = BuildError::new(&source_file);
        assert_eq!(error.get_message(), "");
    }

    #[test]
    fn append_adds_to_message() {
        let source_file = ResourceFile::new(std::path::PathBuf::from("/tmp/test.txt"));
        let mut error = BuildError::new(&source_file);
        error.append("Error 1: ");
        error.append("test message");
        assert_eq!(error.get_message(), "Error 1: test message");
    }

    #[test]
    fn append_concatenates_multiple_calls() {
        let source_file = ResourceFile::new(std::path::PathBuf::from("/tmp/test.txt"));
        let mut error = BuildError::new(&source_file);
        error.append("line 1\n");
        error.append("line 2\n");
        error.append("line 3");
        assert_eq!(error.get_message(), "line 1\nline 2\nline 3");
    }

    #[test]
    fn display_shows_message() {
        let source_file = ResourceFile::new(std::path::PathBuf::from("/tmp/test.txt"));
        let mut error = BuildError::new(&source_file);
        error.append("test error");
        assert_eq!(error.to_string(), "test error");
    }

    #[test]
    fn implements_std_error() {
        let source_file = ResourceFile::new(std::path::PathBuf::from("/tmp/test.txt"));
        let error = BuildError::new(&source_file);
        let _: &dyn std::error::Error = &error;
    }

    #[test]
    fn debug_output() {
        let source_file = ResourceFile::new(std::path::PathBuf::from("/tmp/test.txt"));
        let mut error = BuildError::new(&source_file);
        error.append("debug test");
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("debug test"));
    }

    #[test]
    fn last_modified_persists_across_appends() {
        let source_file = ResourceFile::new(std::path::PathBuf::from("/tmp/test.txt"));
        let original_time = source_file.last_modified();
        let mut error = BuildError::new(&source_file);
        error.append("some error");
        assert_eq!(error.get_last_modified(), original_time);
    }
}
