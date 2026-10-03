use std::io;

use crate::framework::model::domain_file::DomainFile;
use crate::framework::seam_stubs::{LinkStatus, LinkedGhidraFolder};

/// The content-type string used for folder-link files.
///
/// Stands in for `ghidra.framework.data.FolderLinkContentHandler.FOLDER_LINK_CONTENT_TYPE`
/// before that class is ported.
const FOLDER_LINK_CONTENT_TYPE: &str = "FolderLink";

/// Prefix used to recognize a possible Ghidra URL.
///
/// Stands in for `ghidra.framework.protocol.ghidra.GhidraURL.isGhidraURL(String)` before that
/// class is ported; the real implementation is exactly this prefix check.
const GHIDRA_URL_PREFIX: &str = "ghidra:";

/// `LinkFileInfo` provides access to link details for a [`DomainFile`] which is a link-file.
///
/// Port of `ghidra.framework.model.LinkFileInfo`.
///
/// This trait was promoted from a minimal placeholder (see `framework::seam_stubs`) that declared
/// no methods, so there is nothing to retain as a superset here.
pub trait LinkFileInfo {
    /// Get the file that is associated with this link information.
    fn get_file(&self) -> Box<dyn DomainFile>;

    /// If this is a folder-link file get the corresponding linked folder. Invoking this method on
    /// an [`Self::is_external_link`] external-link will cause the associated project or
    /// repository to be opened and associated with the active project as a viewed-project.
    ///
    /// Returns a linked domain folder or `None` if not a valid folder-link.
    fn get_linked_folder(&self) -> Option<Box<dyn LinkedGhidraFolder>>;

    /// Get the stored link-path. This may be either an absolute or relative path within the
    /// link-file's project or a Ghidra URL.
    fn get_link_path(&self) -> String;

    /// Get the stored link-path as a Ghidra URL or absolute normalized link-path from a link
    /// file. Path normalization eliminates any path element of "./" or "../". A local
    /// folder-link path will always end with a "/" path separator. Path normalization is not
    /// performed on Ghidra URLs.
    ///
    /// # Errors
    /// Returns `Err` if the link-file has an invalid relative link-path that failed to normalize.
    fn get_absolute_link_path(&self) -> io::Result<String>;

    /// Determine if the link "directly" refers to an external resource (i.e., URL-based
    /// [`Self::get_link_path`]).
    ///
    /// NOTE: It is important to understand that if this method returns `false` it may link to
    /// another link that is external. If the file's external status is required,
    /// [`LinkStatus::External`] should be checked via [`Self::get_link_status`].
    fn is_external_link(&self) -> bool {
        self.get_link_path().starts_with(GHIDRA_URL_PREFIX)
    }

    /// Returns true if this file is a folder-link, else false.
    fn is_folder_link(&self) -> bool {
        self.get_file().get_content_type() == FOLDER_LINK_CONTENT_TYPE
    }

    /// Determine the link status. If a status is [`LinkStatus::Broken`] and an `error_consumer`
    /// has been specified the error details will be reported.
    ///
    /// This default is a simplified stand-in for
    /// `ghidra.framework.data.LinkHandler.getLinkFileStatus`, which follows the full internal
    /// link chain; that resolution logic will move here once `LinkHandler` is ported.
    fn get_link_status(&self, error_consumer: Option<&dyn Fn(&str)>) -> LinkStatus {
        let _ = error_consumer;
        LinkStatus::NonLink
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDomainFile;
    impl DomainFile for MockDomainFile {}

    struct MockLinkFileInfo {
        link_path: String,
    }

    impl LinkFileInfo for MockLinkFileInfo {
        fn get_file(&self) -> Box<dyn DomainFile> {
            Box::new(MockDomainFile)
        }

        fn get_linked_folder(&self) -> Option<Box<dyn LinkedGhidraFolder>> {
            None
        }

        fn get_link_path(&self) -> String {
            self.link_path.clone()
        }

        fn get_absolute_link_path(&self) -> io::Result<String> {
            Ok(self.link_path.clone())
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let info = MockLinkFileInfo { link_path: "ghidra://host/repo/path".to_string() };
        let dyn_info: &dyn LinkFileInfo = &info;
        assert!(dyn_info.is_external_link());
        assert!(dyn_info.get_linked_folder().is_none());
        assert_eq!(dyn_info.get_link_status(None), LinkStatus::NonLink);
    }

    #[test]
    fn internal_link_path_is_not_external() {
        let info = MockLinkFileInfo { link_path: "/a/b/c".to_string() };
        assert!(!info.is_external_link());
    }
}
