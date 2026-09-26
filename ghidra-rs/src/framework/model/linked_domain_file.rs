use std::io;

use crate::framework::model::domain_file::DomainFile;

/// `LinkedDomainFile` corresponds to a [`DomainFile`] contained within a `LinkedDomainFolder`.
///
/// Port of `ghidra.framework.model.LinkedDomainFile`.
pub trait LinkedDomainFile: DomainFile {
    /// Get the project file pathname relative to the linked-folder root.
    /// NOTE: It may be a link-file path.
    fn get_linked_pathname(&self) -> String;

    /// Get the real domain file which corresponds to this file contained within a linked-folder.
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs or the file is not found.
    fn get_real_file(&self) -> io::Result<Box<dyn DomainFile>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockLinkedDomainFile {
        linked_pathname: String,
    }

    impl DomainFile for MockLinkedDomainFile {
        fn get_pathname(&self) -> String {
            self.linked_pathname.clone()
        }
    }

    impl LinkedDomainFile for MockLinkedDomainFile {
        fn get_linked_pathname(&self) -> String {
            self.linked_pathname.clone()
        }

        fn get_real_file(&self) -> io::Result<Box<dyn DomainFile>> {
            Err(io::Error::new(io::ErrorKind::NotFound, "no real file"))
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let file = MockLinkedDomainFile { linked_pathname: "/a/b".to_string() };
        let dyn_file: &dyn LinkedDomainFile = &file;
        assert_eq!(dyn_file.get_linked_pathname(), "/a/b");
        assert_eq!(dyn_file.get_pathname(), "/a/b");
        assert!(dyn_file.get_real_file().is_err());
    }
}
