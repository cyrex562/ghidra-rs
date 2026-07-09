/// Controls the following of linked-folders.
///
/// Without specific overrides the default behavior:
/// - [`Self::ignore_broken_links`] (`true`) ignores all broken links
/// - [`Self::ignore_external_links`] (`true`) ignores all external folder-links
/// - [`Self::ignore_folder_links`] (`false`) will follow internal folder-links
///
/// Port of `ghidra.framework.model.DomainFolderFilter`.
pub trait DomainFolderFilter {
    /// Check if folder-links should be ignored (includes internal and external).
    ///
    /// # Returns
    /// `true` if all folder-links should be ignored (i.e., not followed/displayed)
    fn ignore_folder_links(&self) -> bool {
        false
    }

    /// Check if link-files should be ignored if the link is external (i.e., Ghidra-URL).
    ///
    /// Multi-level internal links are followed within the same project before a determination is made.
    ///
    /// If this method is not overridden the default behavior will ignore external links.
    /// This method should be ignored for folder-links if [`Self::ignore_folder_links`] returns `true`.
    ///
    /// # Returns
    /// `true` if external links should be ignored (i.e., not displayed)
    fn ignore_external_links(&self) -> bool {
        true
    }

    /// Check if link-files should be ignored if the link is broken.
    ///
    /// Multi-level internal links are followed within the same project before a determination is made.
    ///
    /// If this method is not overridden the default behavior will ignore broken links.
    ///
    /// # Returns
    /// `true` if broken links should be ignored (i.e., not followed/displayed)
    fn ignore_broken_links(&self) -> bool {
        true
    }
}

struct AllFoldersFilter;

impl DomainFolderFilter for AllFoldersFilter {
    fn ignore_external_links(&self) -> bool {
        false
    }
}

struct AllInternalFoldersFilter;

impl DomainFolderFilter for AllInternalFoldersFilter {}

struct NonLinkedFolderFilter;

impl DomainFolderFilter for NonLinkedFolderFilter {
    fn ignore_folder_links(&self) -> bool {
        true
    }
}

/// Filter which accepts all folders and will follow all linked folders.
/// All broken links are ignored.
pub fn all_folders_filter() -> &'static dyn DomainFolderFilter {
    &AllFoldersFilter
}

/// Filter which allows only folders and internal folder-links.
/// All external and broken links are ignored. This filter is useful when
/// selecting a folder when creating/saving a file to the active project.
pub fn all_internal_folders_filter() -> &'static dyn DomainFolderFilter {
    &AllInternalFoldersFilter
}

/// Filter which accepts only real folders and ignores all folder-links.
/// All broken links are ignored.
pub fn non_linked_folder_filter() -> &'static dyn DomainFolderFilter {
    &NonLinkedFolderFilter
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_folders_filter() {
        let filter = all_folders_filter();
        assert!(!filter.ignore_external_links());
        assert!(!filter.ignore_folder_links());
        assert!(filter.ignore_broken_links());
    }

    #[test]
    fn test_all_internal_folders_filter() {
        let filter = all_internal_folders_filter();
        assert!(filter.ignore_external_links());
        assert!(!filter.ignore_folder_links());
        assert!(filter.ignore_broken_links());
    }

    #[test]
    fn test_non_linked_folder_filter() {
        let filter = non_linked_folder_filter();
        assert!(filter.ignore_external_links());
        assert!(filter.ignore_folder_links());
        assert!(filter.ignore_broken_links());
    }

    #[test]
    fn test_default_ignore_broken_links() {
        struct TestFilter;
        impl DomainFolderFilter for TestFilter {}

        let filter = TestFilter;
        assert!(filter.ignore_broken_links());
    }

    #[test]
    fn test_default_ignore_folder_links() {
        struct TestFilter;
        impl DomainFolderFilter for TestFilter {}

        let filter = TestFilter;
        assert!(!filter.ignore_folder_links());
    }

    #[test]
    fn test_default_ignore_external_links() {
        struct TestFilter;
        impl DomainFolderFilter for TestFilter {}

        let filter = TestFilter;
        assert!(filter.ignore_external_links());
    }
}
