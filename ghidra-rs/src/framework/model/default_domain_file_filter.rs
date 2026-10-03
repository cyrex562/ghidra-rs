use std::any::TypeId;

use crate::framework::model::domain_file::DomainFile;
use crate::framework::model::domain_file_filter::DomainFileFilter;
use crate::framework::model::domain_folder_filter::DomainFolderFilter;

/// A simple default domain file filter which accepts files for a specified domain object
/// interface class.
///
/// This filter provides a straightforward way to accept domain files based on their domain
/// object type. When external links are not ignored, the filter will allow following external
/// folder-links into other projects or server repositories.
///
/// Broken links are always ignored and all internal linked-folders and linked-files will be
/// followed/processed.
///
/// Port of `ghidra.framework.model.DefaultDomainFileFilter`.
pub struct DefaultDomainFileFilter {
    domain_object_class: Option<TypeId>,
    ignore_external_links: bool,
}

impl DefaultDomainFileFilter {
    /// Constructs a `DefaultDomainFileFilter` which accepts a specific domain object type and
    /// either shows or hides external links.
    ///
    /// If external links are not ignored, the filter will allow following external folder-links
    /// into other projects or server repositories. Note that this should be enabled carefully
    /// since it may require proper repository authentication support to facilitate access.
    ///
    /// Broken links are always ignored and all internal linked-folders and linked-files will be
    /// followed/processed.
    ///
    /// # Arguments
    /// * `domain_object_class` - domain object type to filter for. `None` to disallow all files
    ///   (i.e., only folders and folder-links are shown).
    /// * `ignore_external_links` - `true` to ignore/skip external links, else they will be
    ///   shown/processed and opening/following such links will be supported.
    pub fn new(domain_object_class: Option<TypeId>, ignore_external_links: bool) -> Self {
        Self {
            domain_object_class,
            ignore_external_links,
        }
    }
}

impl DomainFolderFilter for DefaultDomainFileFilter {
    fn ignore_external_links(&self) -> bool {
        self.ignore_external_links
    }
}

impl DomainFileFilter for DefaultDomainFileFilter {
    fn accept(&self, file: &dyn DomainFile) -> bool {
        self.domain_object_class.is_some()
            && self.domain_object_class == file.get_domain_object_class()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDomainFile {
        domain_object_class: Option<TypeId>,
        is_link: bool,
    }

    impl DomainFile for MockDomainFile {
        fn is_link(&self) -> bool {
            self.is_link
        }

        fn get_domain_object_class(&self) -> Option<TypeId> {
            self.domain_object_class
        }
    }

    #[test]
    fn accepts_matching_domain_object_class() {
        let type_id = TypeId::of::<String>();
        let filter = DefaultDomainFileFilter::new(Some(type_id), false);
        let file = MockDomainFile {
            domain_object_class: Some(type_id),
            is_link: false,
        };

        assert!(filter.accept(&file));
    }

    #[test]
    fn rejects_non_matching_domain_object_class() {
        let type_id1 = TypeId::of::<String>();
        let type_id2 = TypeId::of::<i32>();
        let filter = DefaultDomainFileFilter::new(Some(type_id1), false);
        let file = MockDomainFile {
            domain_object_class: Some(type_id2),
            is_link: false,
        };

        assert!(!filter.accept(&file));
    }

    #[test]
    fn rejects_when_filter_domain_class_is_none() {
        let type_id = TypeId::of::<String>();
        let filter = DefaultDomainFileFilter::new(None, false);
        let file = MockDomainFile {
            domain_object_class: Some(type_id),
            is_link: false,
        };

        assert!(!filter.accept(&file));
    }

    #[test]
    fn rejects_when_file_domain_class_is_none() {
        let type_id = TypeId::of::<String>();
        let filter = DefaultDomainFileFilter::new(Some(type_id), false);
        let file = MockDomainFile {
            domain_object_class: None,
            is_link: false,
        };

        assert!(!filter.accept(&file));
    }

    #[test]
    fn respects_ignore_external_links_setting() {
        let type_id = TypeId::of::<String>();
        let filter_ignoring = DefaultDomainFileFilter::new(Some(type_id), true);
        let filter_not_ignoring = DefaultDomainFileFilter::new(Some(type_id), false);

        assert!(filter_ignoring.ignore_external_links());
        assert!(!filter_not_ignoring.ignore_external_links());
    }

    #[test]
    fn default_folder_filter_behavior() {
        let type_id = TypeId::of::<String>();
        let filter = DefaultDomainFileFilter::new(Some(type_id), false);

        assert!(!filter.ignore_folder_links());
        assert!(!filter.ignore_external_links());
        assert!(filter.ignore_broken_links());
    }

    #[test]
    fn follow_externally_linked_folders_respects_ignore_external_links() {
        let type_id = TypeId::of::<String>();
        let filter_ignoring = DefaultDomainFileFilter::new(Some(type_id), true);
        let filter_not_ignoring = DefaultDomainFileFilter::new(Some(type_id), false);

        // When ignoring external links, should not follow them
        assert!(!filter_ignoring.follow_externally_linked_folders());
        // When not ignoring external links, should follow them
        assert!(filter_not_ignoring.follow_externally_linked_folders());
    }
}
