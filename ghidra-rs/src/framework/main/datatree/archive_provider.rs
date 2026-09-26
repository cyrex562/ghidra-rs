/// An interface to be implemented by any class that can return a list of Archives.
///
/// For example, the tool's data type manager can return a list of archives within the project.
pub trait ArchiveProvider {
    /// Gets the list of archives provided by this provider.
    fn get_archives(&self) -> Vec<Box<dyn crate::framework::seam_stubs::Archive>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::seam_stubs::Archive;
    use std::io;

    struct TestArchive {
        name: String,
    }

    impl Archive for TestArchive {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn close(&self) {}

        fn is_modifiable(&self) -> bool {
            true
        }

        fn is_savable(&self) -> bool {
            true
        }

        fn is_changed(&self) -> bool {
            false
        }

        fn save(&self) -> io::Result<()> {
            Ok(())
        }
    }

    struct TestProvider;

    impl ArchiveProvider for TestProvider {
        fn get_archives(&self) -> Vec<Box<dyn crate::framework::seam_stubs::Archive>> {
            vec![
                Box::new(TestArchive {
                    name: "archive1".to_string(),
                }),
                Box::new(TestArchive {
                    name: "archive2".to_string(),
                }),
            ]
        }
    }

    #[test]
    fn provider_returns_archives() {
        let provider = TestProvider;
        let archives = provider.get_archives();
        assert_eq!(archives.len(), 2);
        assert_eq!(archives[0].get_name(), "archive1");
        assert_eq!(archives[1].get_name(), "archive2");
    }

    #[test]
    fn archive_impl_defaults() {
        let archive = TestArchive {
            name: "test".to_string(),
        };
        assert_eq!(archive.get_name(), "test");
        assert!(archive.is_modifiable());
        assert!(archive.is_savable());
        assert!(!archive.is_changed());
        assert!(archive.save().is_ok());
    }
}
