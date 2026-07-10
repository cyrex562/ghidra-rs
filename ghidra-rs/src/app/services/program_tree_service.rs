//! Service provided by the program tree plugin to get the current view (address set shown in the
//! Code Browser), and the name of the tree currently being viewed.
//!
//! Mirrors `ghidra.app.services.ProgramTreeService`. The Java `@ServiceInfo` annotation (default
//! provider `ProgramTreePlugin`) has no Rust equivalent and is omitted.

use crate::program::model::address::AddressSet;
use crate::program::seam_stubs::GroupPath;

/// Service provided by the program tree plugin to get the current view (address set shown in the
/// Code Browser), and the name of the tree currently being viewed.
pub trait ProgramTreeService {
    /// Get the name of the tree currently being viewed.
    fn get_viewed_tree_name(&self) -> String;

    /// Set the current view to that of the given name. If `tree_name` is not a known view, then
    /// nothing happens.
    fn set_viewed_tree(&self, tree_name: &str);

    /// Get the address set of the current view (what is currently being shown in the Code
    /// Browser).
    fn get_view(&self) -> AddressSet;

    /// Set the selection to the given group paths.
    fn set_group_selection(&self, group_paths: &[GroupPath]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockProgramTreeService {
        tree_name: RefCell<String>,
    }

    impl ProgramTreeService for MockProgramTreeService {
        fn get_viewed_tree_name(&self) -> String {
            self.tree_name.borrow().clone()
        }

        fn set_viewed_tree(&self, tree_name: &str) {
            *self.tree_name.borrow_mut() = tree_name.to_string();
        }

        fn get_view(&self) -> AddressSet {
            AddressSet::new()
        }

        fn set_group_selection(&self, _group_paths: &[GroupPath]) {}
    }

    #[test]
    fn test_mock_service_as_trait_object() {
        let service: Box<dyn ProgramTreeService> = Box::new(MockProgramTreeService {
            tree_name: RefCell::new("Program Tree".to_string()),
        });

        assert_eq!(service.get_viewed_tree_name(), "Program Tree");
        service.set_viewed_tree("Other Tree");
        assert_eq!(service.get_viewed_tree_name(), "Other Tree");

        let _view = service.get_view();
        service.set_group_selection(&[GroupPath::new(vec!["root".to_string()])]);
    }
}
