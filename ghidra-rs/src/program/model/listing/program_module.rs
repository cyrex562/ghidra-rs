use std::any::Any;

use thiserror::Error;

use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::listing::{CircularDependencyException, DuplicateGroupException};
use crate::program::seam_stubs::{Group, ProgramFragment};
use crate::util::exception::{DuplicateNameException, NotEmptyException, NotFoundException};

/// Error produced when adding a module as a child of another module fails.
///
/// Combines the two checked exceptions declared on the Java method
/// `ProgramModule.add(ProgramModule)`.
#[derive(Error, Debug, PartialEq)]
pub enum AddModuleError {
    #[error(transparent)]
    Circular(#[from] CircularDependencyException),
    #[error(transparent)]
    Duplicate(#[from] DuplicateGroupException),
}

/// A `ProgramModule` is a group of `ProgramFragment`s and/or other `ProgramModule`s together
/// with some related information such as a name, comment, and alias. Users create modules to
/// overlay the program with a hierarchical structure. A child of a module is a fragment or
/// module which it directly contains. A parent of a module is a module which has this module as
/// a child. A module may be contained in more than one module. A `Program` always has at least
/// one module, the root module. The root module cannot be removed and is the ancestor for all
/// other modules and fragments in the program.
///
/// Port of `ghidra.program.model.listing.ProgramModule`.
///
/// The Java interface extends `Group`; since `Group` has not been ported yet, it is carried here
/// as a supertrait placeholder (see [`Group`](crate::program::seam_stubs::Group)) rather than
/// duplicating its members on this trait.
pub trait ProgramModule: Group {
    /// Returns whether this module directly contains the given fragment as a child.
    fn contains_fragment(&self, fragment: &dyn ProgramFragment) -> bool;

    /// Returns whether this module directly contains the given module as a child.
    ///
    /// Returns true if `module` is the same as this module, or if `module` is a child of this
    /// module.
    fn contains_module(&self, module: &dyn ProgramModule) -> bool;

    /// Returns the number of children of this module.
    fn get_num_children(&self) -> i32;

    /// Returns this module's children.
    fn get_children(&self) -> Vec<Box<dyn Group>>;

    /// Get the index of the child with the given name, or `-1` if this module does not have a
    /// child with the given name.
    fn get_index(&self, name: &str) -> i32;

    /// Adds the given module as a child of this module.
    fn add_module(&mut self, module: Box<dyn ProgramModule>) -> Result<(), AddModuleError>;

    /// Adds the given fragment as a child of this module.
    fn add_fragment(
        &mut self,
        fragment: Box<dyn ProgramFragment>,
    ) -> Result<(), DuplicateGroupException>;

    /// Creates a new module and makes it a child of this module, returning the newly created
    /// module.
    fn create_module(
        &mut self,
        module_name: &str,
    ) -> Result<Box<dyn ProgramModule>, DuplicateNameException>;

    /// Creates a new fragment and makes it a child of this module, returning the newly created
    /// fragment.
    fn create_fragment(
        &mut self,
        fragment_name: &str,
    ) -> Result<Box<dyn ProgramFragment>, DuplicateNameException>;

    /// Reparents child with the given name to this module; removes the child from `old_parent`.
    fn reparent(
        &mut self,
        name: &str,
        old_parent: &mut dyn ProgramModule,
    ) -> Result<(), NotFoundException>;

    /// Changes the ordering of this module's children by moving the child with the given name
    /// to the position given by `index`.
    fn move_child(&mut self, name: &str, index: i32) -> Result<(), NotFoundException>;

    /// Removes a child module or fragment from this module.
    ///
    /// Returns true if successful, false if no child in this module has the given name.
    fn remove_child(&mut self, name: &str) -> Result<bool, NotEmptyException>;

    /// Returns whether the given module is a descendant of this module.
    fn is_descendant_module(&self, module: &dyn ProgramModule) -> bool;

    /// Returns whether the given fragment is a descendant of this module.
    fn is_descendant_fragment(&self, fragment: &dyn ProgramFragment) -> bool;

    /// Returns the minimum address of this module, which will be the minimum address from the
    /// set of all fragments which are descendants of this module.
    ///
    /// `None` if all of the module's descendant fragments are empty.
    fn get_min_address(&self) -> Option<Address>;

    /// Returns the maximum address of this module, which will be the maximum address from the
    /// set of all fragments which are descendants of this module.
    ///
    /// `None` if all of the module's descendant fragments are empty.
    fn get_max_address(&self) -> Option<Address>;

    /// Returns the first address of this module, which will be the minimum address of the first
    /// descendant fragment which is non-empty, as ordered by the user's child ordering.
    ///
    /// `None` if all of the module's descendant fragments are empty.
    fn get_first_address(&self) -> Option<Address>;

    /// Returns the last address of this module, which will be the maximum address of the last
    /// descendant fragment which is non-empty, as ordered by the user's child ordering.
    ///
    /// `None` if all of the module's descendant fragments are empty.
    fn get_last_address(&self) -> Option<Address>;

    /// Returns the combined set of addresses from the set of all fragments which are
    /// descendants of this module.
    fn get_address_set(&self) -> &dyn AddressSetView;

    /// Returns an opaque token that changes identity when the module tree has been affected by
    /// an undo or redo affecting this module, standing in for the Java `Object` returned by
    /// `getVersionTag()`.
    fn get_version_tag(&self) -> Box<dyn Any>;

    /// Get the current modification number of the module tree; the number is updated whenever a
    /// change is made to any module or fragment that is part of this module's root tree.
    fn get_modification_number(&self) -> i64;

    /// Get the ID for the tree that this module belongs to.
    fn get_tree_id(&self) -> i64;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProgramModule {
        children: Vec<String>,
        tree_id: i64,
    }

    impl Group for MockProgramModule {}

    impl ProgramModule for MockProgramModule {
        fn contains_fragment(&self, _fragment: &dyn ProgramFragment) -> bool {
            false
        }

        fn contains_module(&self, module: &dyn ProgramModule) -> bool {
            module.get_tree_id() == self.tree_id
        }

        fn get_num_children(&self) -> i32 {
            self.children.len() as i32
        }

        fn get_children(&self) -> Vec<Box<dyn Group>> {
            Vec::new()
        }

        fn get_index(&self, name: &str) -> i32 {
            self.children
                .iter()
                .position(|c| c == name)
                .map(|i| i as i32)
                .unwrap_or(-1)
        }

        fn add_module(&mut self, module: Box<dyn ProgramModule>) -> Result<(), AddModuleError> {
            if module.get_tree_id() == self.tree_id {
                return Err(AddModuleError::Circular(CircularDependencyException::default()));
            }
            Ok(())
        }

        fn add_fragment(
            &mut self,
            _fragment: Box<dyn ProgramFragment>,
        ) -> Result<(), DuplicateGroupException> {
            Ok(())
        }

        fn create_module(
            &mut self,
            module_name: &str,
        ) -> Result<Box<dyn ProgramModule>, DuplicateNameException> {
            if self.children.iter().any(|c| c == module_name) {
                return Err(DuplicateNameException::default());
            }
            self.children.push(module_name.to_string());
            Ok(Box::new(MockProgramModule { children: Vec::new(), tree_id: self.tree_id }))
        }

        fn create_fragment(
            &mut self,
            _fragment_name: &str,
        ) -> Result<Box<dyn ProgramFragment>, DuplicateNameException> {
            Err(DuplicateNameException::default())
        }

        fn reparent(
            &mut self,
            name: &str,
            _old_parent: &mut dyn ProgramModule,
        ) -> Result<(), NotFoundException> {
            if self.get_index(name) < 0 {
                return Err(NotFoundException::default());
            }
            Ok(())
        }

        fn move_child(&mut self, name: &str, index: i32) -> Result<(), NotFoundException> {
            let pos = self.get_index(name);
            if pos < 0 {
                return Err(NotFoundException::default());
            }
            let child = self.children.remove(pos as usize);
            self.children.insert(index as usize, child);
            Ok(())
        }

        fn remove_child(&mut self, name: &str) -> Result<bool, NotEmptyException> {
            let pos = self.get_index(name);
            if pos < 0 {
                return Ok(false);
            }
            self.children.remove(pos as usize);
            Ok(true)
        }

        fn is_descendant_module(&self, _module: &dyn ProgramModule) -> bool {
            false
        }

        fn is_descendant_fragment(&self, _fragment: &dyn ProgramFragment) -> bool {
            false
        }

        fn get_min_address(&self) -> Option<Address> {
            None
        }

        fn get_max_address(&self) -> Option<Address> {
            None
        }

        fn get_first_address(&self) -> Option<Address> {
            None
        }

        fn get_last_address(&self) -> Option<Address> {
            None
        }

        fn get_address_set(&self) -> &dyn AddressSetView {
            use crate::program::model::address::AddressSet;
            // Leak a static empty set purely so the mock can hand back a `&dyn` reference; real
            // implementations own their address set and can borrow from `self` directly.
            static EMPTY: std::sync::OnceLock<AddressSet> = std::sync::OnceLock::new();
            EMPTY.get_or_init(AddressSet::new)
        }

        fn get_version_tag(&self) -> Box<dyn Any> {
            Box::new(self.children.len())
        }

        fn get_modification_number(&self) -> i64 {
            0
        }

        fn get_tree_id(&self) -> i64 {
            self.tree_id
        }
    }

    fn make_module(tree_id: i64) -> MockProgramModule {
        MockProgramModule { children: Vec::new(), tree_id }
    }

    #[test]
    fn object_safe_and_usable_via_trait_object() {
        let mut root: Box<dyn ProgramModule> = Box::new(make_module(1));

        assert_eq!(root.get_num_children(), 0);
        assert_eq!(root.get_index("child"), -1);

        let created = root.create_module("child").expect("create should succeed");
        assert_eq!(created.get_tree_id(), 1);
        assert_eq!(root.get_num_children(), 1);
        assert_eq!(root.get_index("child"), 0);

        assert!(root.create_module("child").is_err());

        assert!(root.remove_child("child").unwrap());
        assert!(!root.remove_child("missing").unwrap());

        let other = make_module(1);
        assert!(root.contains_module(&other));

        let sibling: Box<dyn ProgramModule> = Box::new(make_module(1));
        assert!(matches!(root.add_module(sibling), Err(AddModuleError::Circular(_))));
    }

    #[test]
    fn add_module_error_wraps_duplicate_group_exception() {
        let err = AddModuleError::Duplicate(DuplicateGroupException::default());
        assert!(matches!(err, AddModuleError::Duplicate(_)));
    }
}
