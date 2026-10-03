use crate::generic::jar::ResourceFile;

/// The outcome of verifying a file's existence and proper usage of case.
///
/// Port of `utilities.util.FileResolutionResult.FileResolutionStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileResolutionStatus {
    Ok,
    FileDoesNotExist,
    NotProperlyCaseDependent,
}

/// A simple type that holds info relating to the result of verifying a file's existence and
/// proper usage of case.
///
/// Port of `utilities.util.FileResolutionResult`. Java's `createDoesNotExistResult()` is dead
/// code (`return null;`, unreferenced anywhere in the codebase) and is not ported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileResolutionResult {
    status: FileResolutionStatus,
    message: String,
}

impl FileResolutionResult {
    /// Builds a result reporting that `file` does not exist.
    ///
    /// Port of `FileResolutionResult.doesNotExist(ResourceFile)`.
    pub fn does_not_exist(file: &ResourceFile) -> Self {
        let message = format!("File does not exist: {}", file.absolute_path());
        Self {
            status: FileResolutionStatus::FileDoesNotExist,
            message,
        }
    }

    /// Builds a result reporting a case mismatch between `canonical_path` (the file system's
    /// actual, case-correct path) and `user_path` (the path as requested).
    ///
    /// Port of `FileResolutionResult.notCaseDependent(String, String)`.
    pub fn not_case_dependent(canonical_path: &str, user_path: &str) -> Self {
        let message = format!(
            "Case difference found:\n\tCanonical path: {canonical_path}\n\tUser path: {user_path}"
        );
        Self {
            status: FileResolutionStatus::NotProperlyCaseDependent,
            message,
        }
    }

    /// Builds a result reporting success, with no message.
    ///
    /// Port of `FileResolutionResult.ok()`. Java caches a single shared `OK_RESULT` instance and
    /// returns it from every call; since `FileResolutionResult` is an immutable value type here,
    /// this just builds a fresh (structurally identical) instance each time instead -- there's no
    /// observable difference, since nothing in the Java class relies on `ok()` results being
    /// reference-identical.
    pub fn ok() -> Self {
        Self {
            status: FileResolutionStatus::Ok,
            message: String::new(),
        }
    }

    /// Returns the status of this result.
    ///
    /// Port of `FileResolutionResult.getStatus()`.
    pub fn status(&self) -> FileResolutionStatus {
        self.status
    }

    /// Returns the descriptive message for this result (empty for a successful result).
    ///
    /// Port of `FileResolutionResult.getMessage()`.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns whether this result represents success.
    ///
    /// Port of `FileResolutionResult.isOk()`.
    pub fn is_ok(&self) -> bool {
        self.status == FileResolutionStatus::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn ok_result_is_ok_with_empty_message() {
        let result = FileResolutionResult::ok();
        assert!(result.is_ok());
        assert_eq!(result.status(), FileResolutionStatus::Ok);
        assert_eq!(result.message(), "");
    }

    #[test]
    fn does_not_exist_reports_status_and_path_in_message() {
        let file = ResourceFile::new(PathBuf::from("/tmp/nonexistent-file.txt"));
        let result = FileResolutionResult::does_not_exist(&file);
        assert!(!result.is_ok());
        assert_eq!(result.status(), FileResolutionStatus::FileDoesNotExist);
        assert!(result.message().contains("File does not exist"));
        assert!(result.message().contains("nonexistent-file.txt"));
    }

    #[test]
    fn not_case_dependent_reports_both_paths_in_message() {
        let result = FileResolutionResult::not_case_dependent("/Foo/Bar.txt", "/foo/bar.txt");
        assert!(!result.is_ok());
        assert_eq!(
            result.status(),
            FileResolutionStatus::NotProperlyCaseDependent
        );
        assert!(result.message().contains("/Foo/Bar.txt"));
        assert!(result.message().contains("/foo/bar.txt"));
    }

    #[test]
    fn equality_is_structural() {
        assert_eq!(FileResolutionResult::ok(), FileResolutionResult::ok());
        assert_eq!(
            FileResolutionResult::not_case_dependent("a", "b"),
            FileResolutionResult::not_case_dependent("a", "b")
        );
        assert_ne!(
            FileResolutionResult::not_case_dependent("a", "b"),
            FileResolutionResult::not_case_dependent("a", "c")
        );
    }
}
