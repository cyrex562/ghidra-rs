//! Port of `ghidra.program.model.sourcemap.SourcePathTransformRecord`.

use crate::program::database::sourcemap::SourceFile;

/// A container for a source path transformation. No validation is performed on the inputs.
///
/// # Fields
/// * `source` - A path (directory transform) or a String of the form SourceFileIdName + "#" + ID +
///   "#" + SourceFile path (file transform)
/// * `source_file` - SourceFile (None for directory transforms)
/// * `target` - transformed path
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourcePathTransformRecord {
    source: String,
    source_file: Option<SourceFile>,
    target: String,
}

impl SourcePathTransformRecord {
    /// Creates a new `SourcePathTransformRecord`.
    pub fn new(source: String, source_file: Option<SourceFile>, target: String) -> Self {
        Self { source, source_file, target }
    }

    /// Returns the source path or identifier string.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the optional SourceFile.
    pub fn source_file(&self) -> Option<&SourceFile> {
        self.source_file.as_ref()
    }

    /// Returns the target path.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns true if this is a directory transform (source ends with "/").
    pub fn is_directory_transform(&self) -> bool {
        self.source.ends_with('/')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_transform_detection() {
        let record = SourcePathTransformRecord::new(
            "/some/path/".to_string(),
            None,
            "/target/path".to_string(),
        );
        assert!(record.is_directory_transform());
    }

    #[test]
    fn file_transform_detection() {
        let record = SourcePathTransformRecord::new(
            "/some/path/file.c".to_string(),
            None,
            "/target/path/file.c".to_string(),
        );
        assert!(!record.is_directory_transform());
    }

    #[test]
    fn getter_methods() {
        let source = "/src/path/".to_string();
        let target = "/target/path/".to_string();
        let record = SourcePathTransformRecord::new(source.clone(), None, target.clone());

        assert_eq!(record.source(), source);
        assert_eq!(record.target(), target);
        assert!(record.source_file().is_none());
    }

    #[test]
    fn with_source_file() {
        let source_file = SourceFile::new("/src/file.c").unwrap();
        let record = SourcePathTransformRecord::new(
            "MyClass#1#/src/file.c".to_string(),
            Some(source_file.clone()),
            "/target/file.c".to_string(),
        );

        assert!(!record.is_directory_transform());
        assert_eq!(record.source_file(), Some(&source_file));
    }

    #[test]
    fn equality() {
        let record1 = SourcePathTransformRecord::new(
            "/src/".to_string(),
            None,
            "/target/".to_string(),
        );
        let record2 = SourcePathTransformRecord::new(
            "/src/".to_string(),
            None,
            "/target/".to_string(),
        );
        assert_eq!(record1, record2);
    }

    #[test]
    fn inequality() {
        let record1 = SourcePathTransformRecord::new(
            "/src/".to_string(),
            None,
            "/target1/".to_string(),
        );
        let record2 = SourcePathTransformRecord::new(
            "/src/".to_string(),
            None,
            "/target2/".to_string(),
        );
        assert_ne!(record1, record2);
    }

    #[test]
    fn source_ending_with_slash() {
        let record = SourcePathTransformRecord::new(
            "trailing/".to_string(),
            None,
            "target".to_string(),
        );
        assert!(record.is_directory_transform());
    }

    #[test]
    fn source_not_ending_with_slash() {
        let record = SourcePathTransformRecord::new(
            "no_trailing".to_string(),
            None,
            "target".to_string(),
        );
        assert!(!record.is_directory_transform());
    }
}
