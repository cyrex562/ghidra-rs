use std::any::Any;

use crate::program::model::address::Address;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::seam_stubs::GroupPath;
use crate::util::exception::DuplicateNameException;

/// The interface for groupings of code units that may have attributes such as names and
/// comments.
///
/// Port of `ghidra.program.model.listing.Group`.
pub trait Group: Any {
    /// Obtains the comment that has been associated with this fragment or module, or `None`.
    fn get_comment(&self) -> Option<String>;

    /// Sets the comment to associate with this fragment.
    fn set_comment(&mut self, comment: Option<&str>);

    /// Obtains the name that has been associated with this fragment. A fragment will always
    /// have a name and it will be unique within the set of all fragment and module names.
    fn get_name(&self) -> String;

    /// Sets the name of this fragment.
    ///
    /// # Errors
    /// Returns `Err` if the name being set is already in use by another fragment or a module.
    fn set_name(&mut self, name: &str) -> Result<(), DuplicateNameException>;

    /// Returns whether this fragment contains the given code unit.
    fn contains(&self, code_unit: &dyn CodeUnit) -> bool;

    /// Obtains the number of parents of this fragment. If a fragment is in a module then the
    /// module is a parent of the fragment and the fragment is a child of the module. A fragment
    /// must have at least one parent and it may have multiple parents.
    fn get_num_parents(&self) -> i32;

    /// Returns the modules which are parents for this group.
    ///
    /// The Java signature returns `ProgramModule[]` specifically; this is widened to `Group`
    /// (as with
    /// [`ProgramModule::get_children`](crate::program::model::listing::program_module::ProgramModule::get_children))
    /// so callers don't need trait-object upcasting from `dyn ProgramModule` to `dyn Group`.
    fn get_parents(&self) -> Vec<Box<dyn Group>>;

    /// Returns the names of the modules which are parents to this fragment.
    fn get_parent_names(&self) -> Vec<String>;

    /// Returns the name of the tree that this group belongs to.
    fn get_tree_name(&self) -> String;

    /// Returns true if this group has been deleted from the program.
    fn is_deleted(&self) -> bool;

    /// The minimum address of this group, or `None`.
    fn get_min_address(&self) -> Option<Address>;

    /// The maximum address of this group, or `None`.
    fn get_max_address(&self) -> Option<Address>;

    /// Returns one of many possible group paths for this group. Since fragments can belong to
    /// more than one module, there can be multiple legitimate group paths for a group. This
    /// method arbitrarily returns one valid group path.
    fn get_group_path(&self) -> GroupPath {
        let mut names = match self.get_parents().into_iter().next() {
            Some(parent) => collect_ancestor_names(parent.as_ref()),
            None => Vec::new(),
        };
        names.push(self.get_name());
        GroupPath::new(names)
    }

    /// Returns this group viewed as a [`ProgramModule`] when it is one.
    ///
    /// Mirrors Java's `child instanceof ProgramModule` check. The default returns
    /// `None`; program-module implementations override it to return `Some(self)`.
    fn as_program_module(
        &self,
    ) -> Option<&dyn crate::program::model::listing::program_module::ProgramModule> {
        None
    }

    /// Returns this group viewed as a [`ProgramFragment`] when it is one.
    ///
    /// Mirrors Java's `child instanceof ProgramFragment` check. The default returns
    /// `None`; program-fragment implementations override it to return `Some(self)`.
    fn as_program_fragment(
        &self,
    ) -> Option<&dyn crate::program::model::listing::program_fragment::ProgramFragment> {
        None
    }
}

/// Builds the ancestor path (oldest ancestor first, this group last) by following the first
/// parent at each level. Port of `Group`'s private static `getParentNames` helper.
fn collect_ancestor_names(group: &dyn Group) -> Vec<String> {
    let parents = group.get_parents();
    let mut names = match parents.first() {
        Some(parent) => collect_ancestor_names(parent.as_ref()),
        None => Vec::new(),
    };
    names.push(group.get_name());
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MockGroup {
        name: String,
        comment: Option<String>,
        parent: Option<Box<MockGroup>>,
    }

    impl Group for MockGroup {
        fn get_comment(&self) -> Option<String> {
            self.comment.clone()
        }

        fn set_comment(&mut self, comment: Option<&str>) {
            self.comment = comment.map(|c| c.to_string());
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn set_name(&mut self, name: &str) -> Result<(), DuplicateNameException> {
            self.name = name.to_string();
            Ok(())
        }

        fn contains(&self, _code_unit: &dyn CodeUnit) -> bool {
            false
        }

        fn get_num_parents(&self) -> i32 {
            self.parent.is_some() as i32
        }

        fn get_parents(&self) -> Vec<Box<dyn Group>> {
            match &self.parent {
                Some(parent) => vec![Box::new((**parent).clone())],
                None => Vec::new(),
            }
        }

        fn get_parent_names(&self) -> Vec<String> {
            self.get_parents().iter().map(|p| p.get_name()).collect()
        }

        fn get_tree_name(&self) -> String {
            "Program Tree".to_string()
        }

        fn is_deleted(&self) -> bool {
            false
        }

        fn get_min_address(&self) -> Option<Address> {
            None
        }

        fn get_max_address(&self) -> Option<Address> {
            None
        }
    }

    #[test]
    fn object_safe_and_usable_via_trait_object() {
        let root = MockGroup { name: "root".to_string(), comment: None, parent: None };
        let child = MockGroup {
            name: "child".to_string(),
            comment: None,
            parent: Some(Box::new(root)),
        };

        let group: Box<dyn Group> = Box::new(child);

        assert_eq!(group.get_name(), "child");
        assert_eq!(group.get_num_parents(), 1);
        assert!(!group.is_deleted());
        assert_eq!(group.get_parent_names(), vec!["root".to_string()]);
    }

    #[test]
    fn get_group_path_walks_ancestors() {
        let root = MockGroup { name: "root".to_string(), comment: None, parent: None };
        let middle = MockGroup {
            name: "middle".to_string(),
            comment: None,
            parent: Some(Box::new(root)),
        };
        let leaf = MockGroup {
            name: "leaf".to_string(),
            comment: None,
            parent: Some(Box::new(middle)),
        };

        let path = leaf.get_group_path();
        assert_eq!(
            path.get_path(),
            &["root".to_string(), "middle".to_string(), "leaf".to_string()]
        );
    }

    #[test]
    fn set_name_and_comment() {
        let mut group = MockGroup { name: "a".to_string(), comment: None, parent: None };

        group.set_comment(Some("hello"));
        assert_eq!(group.get_comment(), Some("hello".to_string()));

        assert!(group.set_name("b").is_ok());
        assert_eq!(group.get_name(), "b");
    }
}
