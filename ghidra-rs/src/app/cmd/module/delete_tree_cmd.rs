use crate::framework::cmd::Command;
use crate::program::model::listing::Program;

/// Deletes a tree (module hierarchy) from a program.
pub struct DeleteTreeCmd {
    tree_name: String,
}

impl DeleteTreeCmd {
    /// Creates a new delete tree command for the given tree name.
    pub fn new(tree_name: String) -> Self {
        Self { tree_name }
    }
}

impl<T: Program + ?Sized> Command<T> for DeleteTreeCmd {
    fn apply_to(&mut self, program: &mut T) -> bool {
        if let Some(listing) = program.get_listing() {
            listing.remove_tree(&self.tree_name)
        } else {
            false
        }
    }

    fn status_msg(&self) -> Option<String> {
        None
    }

    fn name(&self) -> String {
        format!("Delete {}", self.tree_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct MockListing {
        removed_trees: Arc<std::sync::Mutex<Vec<String>>>,
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

        fn remove_tree(&mut self, tree_name: &str) -> bool {
            self.removed_trees
                .lock()
                .unwrap()
                .push(tree_name.to_string());
            true
        }
    }

    struct MockProgram {
        listing: MockListing,
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
            Some(&mut self.listing)
        }
    }

    #[test]
    fn test_delete_tree_applies_successfully() {
        let removed_trees = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut cmd = DeleteTreeCmd::new("MyTree".to_string());
        let mut program = MockProgram {
            listing: MockListing {
                removed_trees: removed_trees.clone(),
            },
        };

        assert!(cmd.apply_to(&mut program));
        assert_eq!(removed_trees.lock().unwrap().as_slice(), &["MyTree"]);
    }

    #[test]
    fn test_delete_tree_command_name() {
        let cmd = DeleteTreeCmd::new("MyTree".to_string());
        assert_eq!(cmd.name(), "Delete MyTree");
    }

    #[test]
    fn test_delete_tree_status_msg() {
        let cmd = DeleteTreeCmd::new("MyTree".to_string());
        assert_eq!(cmd.status_msg(), None);
    }

    #[test]
    fn test_delete_tree_with_special_characters() {
        let removed_trees = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut cmd = DeleteTreeCmd::new("Program Tree".to_string());
        let mut program = MockProgram {
            listing: MockListing {
                removed_trees: removed_trees.clone(),
            },
        };

        assert!(cmd.apply_to(&mut program));
        assert_eq!(removed_trees.lock().unwrap().as_slice(), &["Program Tree"]);
    }

    #[test]
    fn test_delete_tree_multiple_invocations() {
        let removed_trees = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut cmd = DeleteTreeCmd::new("Tree1".to_string());
        let mut program = MockProgram {
            listing: MockListing {
                removed_trees: removed_trees.clone(),
            },
        };

        cmd.apply_to(&mut program);
        let mut cmd2 = DeleteTreeCmd::new("Tree2".to_string());
        cmd2.apply_to(&mut program);

        let removed = removed_trees.lock().unwrap();
        assert_eq!(removed.as_slice(), &["Tree1", "Tree2"]);
    }
}
