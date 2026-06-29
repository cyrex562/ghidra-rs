/// Modes available for selecting files in the file chooser.
///
/// Corresponds to `docking.widgets.filechooser.GhidraFileChooserMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GhidraFileChooserMode {
    /// Only files may be chosen.
    FilesOnly,
    /// Only directories may be chosen.
    DirectoriesOnly,
    /// Files and directories may be chosen.
    FilesAndDirectories,
}

impl GhidraFileChooserMode {
    /// Returns `true` if this mode allows file selection.
    pub fn supports_files(self) -> bool {
        matches!(self, Self::FilesOnly | Self::FilesAndDirectories)
    }

    /// Returns `true` if this mode allows directory selection.
    pub fn supports_directories(self) -> bool {
        matches!(self, Self::DirectoriesOnly | Self::FilesAndDirectories)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_only_supports_files() {
        assert!(GhidraFileChooserMode::FilesOnly.supports_files());
    }

    #[test]
    fn files_only_does_not_support_directories() {
        assert!(!GhidraFileChooserMode::FilesOnly.supports_directories());
    }

    #[test]
    fn directories_only_supports_directories() {
        assert!(GhidraFileChooserMode::DirectoriesOnly.supports_directories());
    }

    #[test]
    fn directories_only_does_not_support_files() {
        assert!(!GhidraFileChooserMode::DirectoriesOnly.supports_files());
    }

    #[test]
    fn files_and_directories_supports_files() {
        assert!(GhidraFileChooserMode::FilesAndDirectories.supports_files());
    }

    #[test]
    fn files_and_directories_supports_directories() {
        assert!(GhidraFileChooserMode::FilesAndDirectories.supports_directories());
    }
}
