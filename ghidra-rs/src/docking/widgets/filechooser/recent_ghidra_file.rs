use super::ghidra_file::GhidraFile;

/// A marker for a file entry in the user's 'recently used' list.
///
/// This is a newtype wrapper around `GhidraFile` that serves as a semantic marker,
/// distinguishing recently-used files from other `GhidraFile` instances.
///
/// Corresponds to `docking.widgets.filechooser.RecentGhidraFile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentGhidraFile(pub GhidraFile);

impl RecentGhidraFile {
    /// Creates a `RecentGhidraFile` from a single path string.
    pub fn from_path(path: &str, separator: char) -> Self {
        Self(GhidraFile::from_path(path, separator))
    }
}

impl std::fmt::Display for RecentGhidraFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Deref for RecentGhidraFile {
    type Target = GhidraFile;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::MAIN_SEPARATOR;

    #[test]
    fn from_path_creates_recent_ghidra_file() {
        let file = RecentGhidraFile::from_path("test/file.txt", MAIN_SEPARATOR);
        assert_eq!(file.get_path(), "test/file.txt");
    }

    #[test]
    fn from_path_with_custom_separator() {
        let custom_sep = if cfg!(windows) { '/' } else { '\\' };
        let file = RecentGhidraFile::from_path("test/file.txt", custom_sep);
        assert!(!file.get_path().contains(MAIN_SEPARATOR));
        assert!(file.get_path().contains(custom_sep));
    }

    #[test]
    fn display_delegates_to_ghidra_file() {
        let file = RecentGhidraFile::from_path("test/file.txt", MAIN_SEPARATOR);
        assert_eq!(file.to_string(), file.0.to_string());
    }

    #[test]
    fn deref_provides_access_to_ghidra_file_methods() {
        let file = RecentGhidraFile::from_path("test/file.txt", MAIN_SEPARATOR);
        // Should be able to call GhidraFile methods via Deref.
        let _ = file.get_path();
        let _ = file.get_parent();
    }

    #[test]
    fn clone_preserves_separator() {
        let file = RecentGhidraFile::from_path("test/file.txt", '/');
        let cloned = file.clone();
        assert_eq!(file, cloned);
        assert_eq!(file.0.separator, cloned.0.separator);
    }

    #[test]
    fn equality_same_path_same_sep() {
        let a = RecentGhidraFile::from_path("a/b.txt", MAIN_SEPARATOR);
        let b = RecentGhidraFile::from_path("a/b.txt", MAIN_SEPARATOR);
        assert_eq!(a, b);
    }

    #[test]
    fn equality_different_sep_not_equal() {
        let custom_sep = if cfg!(windows) { '/' } else { '\\' };
        let a = RecentGhidraFile::from_path("a/b.txt", MAIN_SEPARATOR);
        let b = RecentGhidraFile::from_path("a/b.txt", custom_sep);
        assert_ne!(a, b);
    }
}
