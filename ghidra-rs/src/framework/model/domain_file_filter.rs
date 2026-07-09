use crate::framework::model::domain_file::DomainFile;
use crate::framework::model::domain_folder_filter::DomainFolderFilter;

/// `DomainFileFilter` indicates whether a domain file should be included in a list or set of
/// domain files. This trait extends [`DomainFolderFilter`] which also controls the following of
/// linked-folders.
///
/// Port of `ghidra.framework.model.DomainFileFilter`.
///
/// Without specific overrides the default behavior:
/// - [`DomainFolderFilter::ignore_broken_links`] (`true`) ignores all broken links
/// - [`DomainFolderFilter::ignore_external_links`] (`true`) ignores all external links
/// - [`DomainFolderFilter::ignore_folder_links`] (`false`) will follow folder-links
/// - [`Self::follow_externally_linked_folders`] is based on NOT-`ignore_external_links()` AND
///   NOT-`ignore_folder_links()`
///
/// The specific handling of link-files is determined by the consumer of this filter.
pub trait DomainFileFilter: DomainFolderFilter {
    /// Tests whether or not the specified domain file should be included in a domain file list.
    /// Since link-files will also be subject to this constraint the ability to handle or follow
    /// such links must be considered.
    ///
    /// NOTE: File-links have the same domain-object-class as the file they refer to, while their
    /// content-type is specific to their `LinkHandler` implementation.
    ///
    /// # Arguments
    /// * `df` - the domain file to be tested
    ///
    /// # Returns
    /// `true` if and only if `df` should be accepted
    fn accept(&self, df: &dyn DomainFile) -> bool;

    /// Check if the children of an externally-linked folder should be loaded/processed.
    ///
    /// If this method is not overridden the value returned is NOT-`ignore_external_links()` AND
    /// NOT-`ignore_folder_links()`.
    ///
    /// NOTE: Following an external link utilizes the application's active project to retain and
    /// external project as one of it's viewed-projects. In the process of accessing a
    /// viewed-project the user may be required to authenticate to a remote server.
    ///
    /// # Returns
    /// `true` if children of an externally-linked folder should be traversed or displayed
    /// (subject to a successful connection to the referenced project or server-based repository).
    fn follow_externally_linked_folders(&self) -> bool {
        !self.ignore_external_links() && !self.ignore_folder_links()
    }
}

/// File filter which accepts all files, including all external file-links, and allows
/// opening/expanding of external folder-links. All broken links are ignored.
///
/// Port of `DomainFileFilter.ALL_FILES_FILTER`.
pub struct AllFilesFilter;

impl DomainFolderFilter for AllFilesFilter {
    fn ignore_external_links(&self) -> bool {
        false
    }
}

impl DomainFileFilter for AllFilesFilter {
    fn accept(&self, _df: &dyn DomainFile) -> bool {
        true
    }
}

/// File filter which accepts all files, including all external file-links, but does not allow
/// opening/expanding of external folder-links. All broken links are ignored.
///
/// Port of `DomainFileFilter.ALL_FILES_NO_EXTERNAL_FOLDERS_FILTER`.
pub struct AllFilesNoExternalFoldersFilter;

impl DomainFolderFilter for AllFilesNoExternalFoldersFilter {
    fn ignore_external_links(&self) -> bool {
        false
    }
}

impl DomainFileFilter for AllFilesNoExternalFoldersFilter {
    fn accept(&self, _df: &dyn DomainFile) -> bool {
        true
    }

    fn follow_externally_linked_folders(&self) -> bool {
        false
    }
}

/// File filter which allows all internal folders and files. All external and broken links are
/// ignored. This filter is useful when selecting a file with an arbitrary content type. If
/// targeting a specific file content type the use of `DefaultDomainFileFilter` may be preferred.
///
/// Port of `DomainFileFilter.ALL_INTERNAL_FILES_FILTER`.
pub struct AllInternalFilesFilter;

impl DomainFolderFilter for AllInternalFilesFilter {}

impl DomainFileFilter for AllInternalFilesFilter {
    fn accept(&self, _df: &dyn DomainFile) -> bool {
        true
    }
}

/// File filter which allows all non-linked internal folders and files. All links are ignored.
/// This filter is useful if code does not handle some of the implications of following links such
/// as external repository authentication, or processing the same project content more than once
/// or lack of support for link-files. If targeting a specific file content type the use of
/// `DefaultDomainFileFilter` may be preferred.
///
/// Port of `DomainFileFilter.NON_LINKED_FILE_FILTER`.
pub struct NonLinkedFileFilter;

impl DomainFolderFilter for NonLinkedFileFilter {
    fn ignore_folder_links(&self) -> bool {
        true
    }
}

impl DomainFileFilter for NonLinkedFileFilter {
    fn accept(&self, df: &dyn DomainFile) -> bool {
        // Accept all domain files which are not a link-file.
        // Processing of link-files may result in the same file being returned by the
        // iterator more than once.
        !df.is_link()
    }
}

/// Creates the filter that accepts all files, including all external file-links, and allows
/// opening/expanding of external folder-links. All broken links are ignored.
pub fn all_files_filter() -> Box<dyn DomainFileFilter> {
    Box::new(AllFilesFilter)
}

/// Creates the filter that accepts all files, including all external file-links, but does not
/// allow opening/expanding of external folder-links. All broken links are ignored.
pub fn all_files_no_external_folders_filter() -> Box<dyn DomainFileFilter> {
    Box::new(AllFilesNoExternalFoldersFilter)
}

/// Creates the filter that allows all internal folders and files. All external and broken links
/// are ignored.
pub fn all_internal_files_filter() -> Box<dyn DomainFileFilter> {
    Box::new(AllInternalFilesFilter)
}

/// Creates the filter that allows all non-linked internal folders and files. All links are
/// ignored.
pub fn non_linked_file_filter() -> Box<dyn DomainFileFilter> {
    Box::new(NonLinkedFileFilter)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDomainFile {
        is_link: bool,
    }

    impl DomainFile for MockDomainFile {
        fn is_link(&self) -> bool {
            self.is_link
        }
    }

    struct MockFilter;

    impl DomainFolderFilter for MockFilter {}

    impl DomainFileFilter for MockFilter {
        fn accept(&self, df: &dyn DomainFile) -> bool {
            !df.is_link()
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let filter: Box<dyn DomainFileFilter> = Box::new(MockFilter);
        let link_file = MockDomainFile { is_link: true };
        let plain_file = MockDomainFile { is_link: false };

        assert!(!filter.accept(&link_file));
        assert!(filter.accept(&plain_file));
        assert!(filter.follow_externally_linked_folders());
    }

    #[test]
    fn all_files_filter_accepts_everything_and_follows_external_folders() {
        let filter = all_files_filter();
        let link_file = MockDomainFile { is_link: true };
        assert!(filter.accept(&link_file));
        assert!(filter.follow_externally_linked_folders());
    }

    #[test]
    fn all_files_no_external_folders_filter_does_not_follow_external_folders() {
        let filter = all_files_no_external_folders_filter();
        let link_file = MockDomainFile { is_link: true };
        assert!(filter.accept(&link_file));
        assert!(!filter.follow_externally_linked_folders());
    }

    #[test]
    fn all_internal_files_filter_uses_default_link_behavior() {
        let filter = all_internal_files_filter();
        assert!(filter.ignore_external_links());
        assert!(!filter.ignore_folder_links());
        assert!(!filter.follow_externally_linked_folders());
    }

    #[test]
    fn non_linked_file_filter_rejects_links() {
        let filter = non_linked_file_filter();
        let link_file = MockDomainFile { is_link: true };
        let plain_file = MockDomainFile { is_link: false };
        assert!(!filter.accept(&link_file));
        assert!(filter.accept(&plain_file));
        assert!(filter.ignore_folder_links());
    }
}
