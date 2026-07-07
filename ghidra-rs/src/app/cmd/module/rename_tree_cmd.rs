use crate::framework::cmd::Command;
use crate::program::model::listing::Program;

/// Renames a tree (module hierarchy) in a program.
pub struct RenameTreeCmd {
    old_name: String,
    new_name: String,
    status_msg: Option<String>,
}

impl RenameTreeCmd {
    /// Creates a new rename tree command.
    pub fn new(old_name: String, new_name: String) -> Self {
        Self {
            old_name,
            new_name,
            status_msg: None,
        }
    }
}

impl<T: Program + ?Sized> Command<T> for RenameTreeCmd {
    fn apply_to(&mut self, program: &mut T) -> bool {
        if let Some(listing) = program.get_listing() {
            match listing.rename_tree(&self.old_name, &self.new_name) {
                Ok(()) => true,
                Err(e) => {
                    self.status_msg = Some(e.to_string());
                    false
                }
            }
        } else {
            self.status_msg = Some("No listing available".to_string());
            false
        }
    }

    fn status_msg(&self) -> Option<String> {
        self.status_msg.clone()
    }

    fn name(&self) -> String {
        "Rename Tree View".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::util::exception::DuplicateNameException;

    struct MockListing {
        renamed_trees: Arc<std::sync::Mutex<Vec<(String, String)>>>,
        should_fail: bool,
    }

    impl crate::program::model::listing::Listing for MockListing {
        fn get_code_unit_at(
            &self,
            _addr: &crate::program::model::address::Address,
        ) -> Option<Arc<dyn crate::program::model::listing::CodeUnit>> {
            None
        }

        fn get_code_unit_containing(
            &self,
            _addr: &crate::program::model::address::Address,
        ) -> Option<Arc<dyn crate::program::model::listing::CodeUnit>> {
            None
        }

        fn get_code_unit_after(
            &self,
            _addr: &crate::program::model::address::Address,
        ) -> Option<Arc<dyn crate::program::model::listing::CodeUnit>> {
            None
        }

        fn get_code_unit_before(
            &self,
            _addr: &crate::program::model::address::Address,
        ) -> Option<Arc<dyn crate::program::model::listing::CodeUnit>> {
            None
        }

        fn get_code_unit_iterator(
            &self,
            _property: &str,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            Box::new(crate::program::model::listing::code_unit_iterator::EmptyCodeUnitIterator)
        }

        fn get_code_unit_iterator_from(
            &self,
            _property: &str,
            _addr: &crate::program::model::address::Address,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            Box::new(crate::program::model::listing::code_unit_iterator::EmptyCodeUnitIterator)
        }

        fn get_code_unit_iterator_in(
            &self,
            _property: &str,
            _addr_set: &dyn crate::program::model::address::AddressSetView,
            _forward: bool,
        ) -> Box<dyn crate::program::seam_stubs::CodeUnitIterator> {
            Box::new(crate::program::model::listing::code_unit_iterator::EmptyCodeUnitIterator)
        }

        fn rename_tree(
            &mut self,
            old_name: &str,
            new_name: &str,
        ) -> Result<(), DuplicateNameException> {
            if self.should_fail {
                Err(DuplicateNameException::with_message(format!(
                    "Tree '{}' already exists",
                    new_name
                )))
            } else {
                self.renamed_trees
                    .lock()
                    .unwrap()
                    .push((old_name.to_string(), new_name.to_string()));
                Ok(())
            }
        }
    }

    struct MockProgram {
        listing: Option<MockListing>,
    }

    impl crate::framework::model::DomainObject for MockProgram {}

    impl crate::program::model::listing::Program for MockProgram {
        fn get_name(&self) -> &str {
            "test_program"
        }

        fn get_language_id(&self) -> &str {
            "test_lang"
        }

        fn get_listing(&mut self) -> Option<&mut dyn crate::program::model::listing::Listing> {
            self.listing.as_mut().map(|l| l as &mut dyn crate::program::model::listing::Listing)
        }
    }

    #[test]
    fn test_rename_tree_applies_successfully() {
        let renamed_trees = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut cmd = RenameTreeCmd::new("OldName".to_string(), "NewName".to_string());
        let mut program = MockProgram {
            listing: Some(MockListing {
                renamed_trees: renamed_trees.clone(),
                should_fail: false,
            }),
        };

        assert!(cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), None);
        assert_eq!(
            renamed_trees.lock().unwrap().as_slice(),
            &[("OldName".to_string(), "NewName".to_string())]
        );
    }

    #[test]
    fn test_rename_tree_duplicate_name_fails() {
        let renamed_trees = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut cmd = RenameTreeCmd::new("OldName".to_string(), "DuplicateName".to_string());
        let mut program = MockProgram {
            listing: Some(MockListing {
                renamed_trees: renamed_trees.clone(),
                should_fail: true,
            }),
        };

        assert!(!cmd.apply_to(&mut program));
        assert!(cmd.status_msg().is_some());
        assert!(cmd
            .status_msg()
            .unwrap()
            .contains("already exists"));
    }

    #[test]
    fn test_rename_tree_no_listing() {
        let mut cmd = RenameTreeCmd::new("OldName".to_string(), "NewName".to_string());
        let mut program = MockProgram { listing: None };

        assert!(!cmd.apply_to(&mut program));
        assert_eq!(cmd.status_msg(), Some("No listing available".to_string()));
    }

    #[test]
    fn test_rename_tree_command_name() {
        let cmd = RenameTreeCmd::new("OldName".to_string(), "NewName".to_string());
        assert_eq!(cmd.name(), "Rename Tree View");
    }

    #[test]
    fn test_rename_tree_initial_status() {
        let cmd = RenameTreeCmd::new("OldName".to_string(), "NewName".to_string());
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn test_rename_tree_with_special_characters() {
        let renamed_trees = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut cmd = RenameTreeCmd::new("Program Tree".to_string(), "New Program Tree".to_string());
        let mut program = MockProgram {
            listing: Some(MockListing {
                renamed_trees: renamed_trees.clone(),
                should_fail: false,
            }),
        };

        assert!(cmd.apply_to(&mut program));
        assert_eq!(
            renamed_trees.lock().unwrap().as_slice(),
            &[("Program Tree".to_string(), "New Program Tree".to_string())]
        );
    }

    #[test]
    fn test_rename_tree_multiple_invocations() {
        let renamed_trees = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut cmd1 = RenameTreeCmd::new("Tree1".to_string(), "Renamed1".to_string());
        let mut cmd2 = RenameTreeCmd::new("Tree2".to_string(), "Renamed2".to_string());
        let mut program = MockProgram {
            listing: Some(MockListing {
                renamed_trees: renamed_trees.clone(),
                should_fail: false,
            }),
        };

        assert!(cmd1.apply_to(&mut program));
        assert!(cmd2.apply_to(&mut program));

        let renamed = renamed_trees.lock().unwrap();
        assert_eq!(renamed.len(), 2);
        assert_eq!(renamed[0], ("Tree1".to_string(), "Renamed1".to_string()));
        assert_eq!(renamed[1], ("Tree2".to_string(), "Renamed2".to_string()));
    }
}
