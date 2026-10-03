use std::path::Path;

use crate::util::seam_stubs::GhidraFileChooserModelLike;

/// A filter that decides which files are shown by a file chooser.
///
/// Extensions are of the form `".foo"`, which is typically found on Windows and Unix boxes
/// but not on Macintosh; case is ignored.
///
/// Port of `ghidra.util.filechooser.GhidraFileFilter`.
pub trait GhidraFileFilter: Send + Sync {
    /// Tests whether or not the specified abstract pathname should be included in a pathname
    /// list.
    ///
    /// # Arguments
    /// * `pathname` - the abstract pathname to be tested
    /// * `model` - the underlying file chooser model
    ///
    /// # Returns
    /// `true` if and only if `pathname` should be included
    fn accept(&self, pathname: &Path, model: &dyn GhidraFileChooserModelLike) -> bool;

    /// Returns the description of this filter.
    fn description(&self) -> String;
}

/// A default filter implementation that shows all files.
///
/// Port of `GhidraFileFilter.ALL`.
pub struct AllFilesFilter;

impl GhidraFileFilter for AllFilesFilter {
    fn accept(&self, _pathname: &Path, _model: &dyn GhidraFileChooserModelLike) -> bool {
        true
    }

    fn description(&self) -> String {
        "All Files (*.*)".to_string()
    }
}

/// Creates the filter that accepts all files.
pub fn all_files_filter() -> Box<dyn GhidraFileFilter> {
    Box::new(AllFilesFilter)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockModel;
    impl GhidraFileChooserModelLike for MockModel {}

    struct ExtensionFilter {
        extension: &'static str,
    }

    impl GhidraFileFilter for ExtensionFilter {
        fn accept(&self, pathname: &Path, _model: &dyn GhidraFileChooserModelLike) -> bool {
            pathname
                .extension()
                .map(|ext| ext.eq_ignore_ascii_case(self.extension))
                .unwrap_or(false)
        }

        fn description(&self) -> String {
            format!("*.{}", self.extension)
        }
    }

    #[test]
    fn all_files_filter_accepts_everything() {
        let filter = all_files_filter();
        let model = MockModel;
        assert!(filter.accept(Path::new("foo.txt"), &model));
        assert!(filter.accept(Path::new("no_extension"), &model));
        assert_eq!(filter.description(), "All Files (*.*)");
    }

    #[test]
    fn extension_filter_accepts_matching_case_insensitive() {
        let filter: Box<dyn GhidraFileFilter> = Box::new(ExtensionFilter { extension: "gzf" });
        let model = MockModel;
        assert!(filter.accept(Path::new("program.gzf"), &model));
        assert!(filter.accept(Path::new("program.GZF"), &model));
        assert!(!filter.accept(Path::new("program.txt"), &model));
        assert!(!filter.accept(Path::new("program"), &model));
        assert_eq!(filter.description(), "*.gzf");
    }

    #[test]
    fn usable_as_trait_object() {
        let filters: Vec<Box<dyn GhidraFileFilter>> = vec![
            all_files_filter(),
            Box::new(ExtensionFilter { extension: "zip" }),
        ];
        let model = MockModel;
        let path = Path::new("archive.zip");
        assert!(filters.iter().all(|f| f.accept(path, &model)));
    }
}
