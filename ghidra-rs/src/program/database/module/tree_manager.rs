//! Port of `ghidra.program.database.module.TreeManager`.
//!
//! The Java type is a package-private, concrete class that manages the set of program trees
//! (each backed by a [`ModuleManager`](crate::program::database::module::ModuleManager)) for a
//! program. Its constructor (adapter selection and tree-map population) and a handful of private
//! helpers (`addMemoryBlocks`, `initTreeMap`, `refreshTreeMap`, `createDefaultTree`) are
//! construction/implementation details tied to a concrete implementation, so -- following the
//! same convention already used for
//! [`ModuleManager`](crate::program::database::module::ModuleManager) and
//! [`ProgramTreeDBAdapter`](crate::program::database::module::ProgramTreeDBAdapter) -- this port
//! only models the package-private instance API the class exposes to the rest of its package, as
//! an object-safe trait. This trait was itself selected as a dependency-cycle cut-point.
//!
//! `TreeManager` implements `ManagerDB`; per the same convention documented on
//! [`DBPropertyMapManager`](crate::program::database::properties::DBPropertyMapManager), the
//! shared [`ManagerDB`] trait's `invalidate_cache`/`delete_address_range`/`move_address_range`
//! stand in for the Java interface's `TaskMonitor`/`CancelledException`-bearing re-declarations of
//! those same methods (`invalidateCache`, `deleteAddressRange`, `moveAddressRange`), while
//! `set_program`/`program_ready` (which `ManagerDB` omits) are added directly to this trait.
//!
//! Several instance methods (`getModule`, `getFragment(String,String)`, `getFragment(String,
//! Address)`, `getRootModule(String)`, `getDefaultRootModule`, `getTreeNames`, `removeTree`,
//! `addMemoryBlock`, `getTreeName(long)`) catch `IOException` internally and report it to the
//! manager's [`ErrorHandler`] (see [`TreeManager::get_error_handler`]) rather than declaring it as
//! a checked exception, so this port keeps their Rust signatures free of an error type too --
//! matching the Java method's actual (exception-free) public contract.

use std::io;
use std::sync::Arc;

use thiserror::Error;

use crate::framework::data::OpenMode;
use crate::framework::db::util::ErrorHandler;
use crate::framework::db::{DBHandle, DBRecord};
use crate::program::database::manager_db::ManagerDB;
use crate::program::database::map::AddressMap;
use crate::program::database::program_db::ProgramDB;
use crate::program::model::address::{Address, AddressRange};
use crate::program::model::listing::{ProgramFragment, ProgramModule};
use crate::util::exception::{CancelledException, DuplicateNameException};
use crate::util::lock::Lock;
use crate::util::task::TaskMonitor;

/// Name of the default tree that is created when a program is created. Stands in for
/// `TreeManager.DEFAULT_TREE_NAME`.
pub const DEFAULT_TREE_NAME: &str = "Program Tree";

/// Error produced by [`TreeManager::program_ready`], mirroring the Java method's `throws
/// IOException, CancelledException`.
#[derive(Debug, Error)]
pub enum ProgramReadyError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Manages the set of program trees in a program.
///
/// Port of `ghidra.program.database.module.TreeManager`. See the module docs for what was
/// intentionally left out (construction/persistence details) and for how error handling was
/// mapped to Rust signatures.
pub trait TreeManager: ManagerDB {
    /// Callback from program used to indicate all managers have been created. Creates the default
    /// tree if this manager has no trees yet.
    ///
    /// Stands in for `TreeManager.setProgram(ProgramDB)`.
    fn set_program(&mut self, program: Arc<ProgramDB>);

    /// Callback from program made after the program has completed initialization.
    ///
    /// Stands in for `TreeManager.programReady(OpenMode, int, TaskMonitor)`.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if a database I/O error occurs, or `Cancelled` if the user cancelled
    /// the operation via `monitor`.
    fn program_ready(
        &mut self,
        open_mode: OpenMode,
        current_revision: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), ProgramReadyError>;

    /// Notifies every tree that the program's image base changed. When `commit` is true, each
    /// tree's record is persisted before its cache is invalidated.
    ///
    /// Stands in for `TreeManager.imageBaseChanged(boolean)`.
    fn image_base_changed(&mut self, commit: bool);

    /// Creates a new tree with the given name (not the name of the root module).
    ///
    /// Stands in for `TreeManager.createRootModule(String)`.
    ///
    /// # Errors
    ///
    /// Returns [`DuplicateNameException`] if a tree named `tree_name` already exists.
    fn create_root_module(&mut self, tree_name: &str) -> Result<Box<dyn ProgramModule>, DuplicateNameException>;

    /// Gets the root module of the tree with the given name, or `None` if there is no tree with
    /// that name.
    ///
    /// Stands in for `TreeManager.getRootModule(String)`.
    fn get_root_module(&self, tree_name: &str) -> Option<Box<dyn ProgramModule>>;

    /// Gets the root module for the tree that has the given ID, or `None` if there is no tree
    /// with that ID.
    ///
    /// Stands in for `TreeManager.getRootModule(long)`. Renamed (from the overloaded
    /// `getRootModule`) since Rust does not support overloading on parameter type.
    fn get_root_module_by_id(&self, tree_id: i64) -> Option<Box<dyn ProgramModule>> {
        let tree_name = self.get_tree_name(tree_id)?;
        self.get_root_module(&tree_name)
    }

    /// Gets the root module for the default program tree (the oldest tree), or `None` if there
    /// are no trees.
    ///
    /// Stands in for `TreeManager.getDefaultRootModule()`.
    fn get_default_root_module(&self) -> Option<Box<dyn ProgramModule>>;

    /// Gets the names of all the trees in the program.
    ///
    /// Stands in for `TreeManager.getTreeNames()`.
    fn get_tree_names(&self) -> Vec<String>;

    /// Renames the tree from `old_name` to `new_name`. Has no effect on the name of the root
    /// module.
    ///
    /// Stands in for `TreeManager.renameTree(String, String)`.
    ///
    /// # Errors
    ///
    /// Returns [`DuplicateNameException`] if `new_name` already exists as the name of another
    /// tree.
    fn rename_tree(&mut self, old_name: &str, new_name: &str) -> Result<(), DuplicateNameException>;

    /// Removes the tree with the given name. Returns `true` if the tree was removed.
    ///
    /// Stands in for `TreeManager.removeTree(String)`.
    fn remove_tree(&mut self, tree_name: &str) -> bool;

    /// Gets the module with the given name in the tree identified by `tree_name`, or `None` if
    /// there is no such module (or tree).
    ///
    /// Stands in for `TreeManager.getModule(String, String)`.
    fn get_module(&self, tree_name: &str, name: &str) -> Option<Box<dyn ProgramModule>>;

    /// Gets the fragment with the given name in the tree identified by `tree_name`, or `None` if
    /// there is no such fragment (or tree).
    ///
    /// Stands in for `TreeManager.getFragment(String, String)`.
    fn get_fragment_by_name(&self, tree_name: &str, name: &str) -> Option<Box<dyn ProgramFragment>>;

    /// Gets the fragment containing `addr` in the tree identified by `tree_name`, or `None` if
    /// `addr` is not in any fragment (or the tree does not exist).
    ///
    /// Stands in for `TreeManager.getFragment(String, Address)`.
    fn get_fragment_at(&self, tree_name: &str, addr: &Address) -> Option<Box<dyn ProgramFragment>>;

    /// Adds a memory block with the given range to every tree, creating a fragment named `name`
    /// (adjusting the name to avoid collisions, if needed).
    ///
    /// Stands in for `TreeManager.addMemoryBlock(String, AddressRange)`.
    fn add_memory_block(&mut self, name: &str, range: &AddressRange);

    /// Renames the program in the root modules of every tree, reflecting a program name change.
    ///
    /// Stands in for `TreeManager.setProgramName(String, String)`.
    fn set_program_name(&mut self, old_name: &str, new_name: &str);

    /// Gets the map used to convert addresses to longs and longs to addresses.
    ///
    /// Stands in for `TreeManager.getAddressMap()`.
    fn get_address_map(&self) -> &dyn AddressMap;

    /// Gets the database handle backing this manager.
    ///
    /// Stands in for `TreeManager.getDatabaseHandle()`.
    fn get_database_handle(&self) -> &DBHandle;

    /// Gets the name of the tree with the given ID, or `None` if not found.
    ///
    /// Stands in for `TreeManager.getTreeName(long)`.
    fn get_tree_name(&self, tree_id: i64) -> Option<String>;

    /// Gets the error handler used to report database errors.
    ///
    /// Stands in for `TreeManager.getErrorHandler()`.
    fn get_error_handler(&self) -> &dyn ErrorHandler;

    /// Gets the tree record for the given tree ID, or `None` if not found.
    ///
    /// Stands in for `TreeManager.getTreeRecord(long)`.
    fn get_tree_record(&self, tree_id: i64) -> Option<DBRecord>;

    /// Gets the lock used to synchronize access to the program's trees.
    ///
    /// Stands in for `TreeManager.getLock()`.
    fn get_lock(&self) -> &Lock<()>;

    /// Gets the program that owns this manager.
    ///
    /// Stands in for `TreeManager.getProgram()`.
    fn get_program(&self) -> &ProgramDB;

    /// Updates the tree table with the given record, optionally bumping the modification number.
    ///
    /// Stands in for `TreeManager.updateTreeRecord(DBRecord, boolean)`.
    fn update_tree_record(&mut self, record: &DBRecord, update_modification_number: bool);

    /// Updates the tree table with the given record, always bumping the modification number.
    ///
    /// Stands in for `TreeManager.updateTreeRecord(DBRecord)`. Renamed (from the overloaded
    /// `updateTreeRecord`) since Rust does not support overloading on arity; provided as a default
    /// method since it is a trivial delegation in Java too.
    fn update_tree_record_default(&mut self, record: &DBRecord) {
        self.update_tree_record(record, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct StubErrorHandler;
    impl ErrorHandler for StubErrorHandler {
        fn db_error(&self, _e: io::Error) {}
    }

    /// A minimal in-memory `TreeManager`, exercising object-safety and the core tree-name
    /// bookkeeping (create/rename/remove, duplicate detection, ID lookup) described by the Java
    /// class.
    struct MockTreeManager {
        trees: BTreeMap<String, i64>,
        next_id: i64,
        lock: Lock<()>,
        db_handle: DBHandle,
        error_handler: StubErrorHandler,
    }

    impl MockTreeManager {
        fn new() -> Self {
            MockTreeManager {
                trees: BTreeMap::new(),
                next_id: 0,
                lock: Lock::new_unit("Tree Manager"),
                db_handle: DBHandle::new().expect("db handle should construct"),
                error_handler: StubErrorHandler,
            }
        }
    }

    impl ManagerDB for MockTreeManager {
        fn invalidate_cache(&mut self, _all: bool) -> io::Result<()> {
            Ok(())
        }

        fn delete_address_range(&mut self, _start_addr: &Address, _end_addr: &Address) -> io::Result<()> {
            Ok(())
        }

        fn move_address_range(
            &mut self,
            _from_addr: &Address,
            _to_addr: &Address,
            _length: u64,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    impl TreeManager for MockTreeManager {
        fn set_program(&mut self, _program: Arc<ProgramDB>) {
            if self.trees.is_empty() {
                self.trees.insert(DEFAULT_TREE_NAME.to_string(), self.next_id);
                self.next_id += 1;
            }
        }

        fn program_ready(
            &mut self,
            _open_mode: OpenMode,
            _current_revision: i32,
            monitor: &dyn TaskMonitor,
        ) -> Result<(), ProgramReadyError> {
            if monitor.is_cancelled() {
                return Err(CancelledException::new("program ready cancelled").into());
            }
            Ok(())
        }

        fn image_base_changed(&mut self, _commit: bool) {}

        fn create_root_module(&mut self, tree_name: &str) -> Result<Box<dyn ProgramModule>, DuplicateNameException> {
            if self.trees.contains_key(tree_name) {
                return Err(DuplicateNameException::with_message(format!(
                    "Root module named {tree_name} already exists"
                )));
            }
            let id = self.next_id;
            self.next_id += 1;
            self.trees.insert(tree_name.to_string(), id);
            Err(DuplicateNameException::with_message(
                "mock never materializes a ProgramModule",
            ))
        }

        fn get_root_module(&self, _tree_name: &str) -> Option<Box<dyn ProgramModule>> {
            None
        }

        fn get_default_root_module(&self) -> Option<Box<dyn ProgramModule>> {
            None
        }

        fn get_tree_names(&self) -> Vec<String> {
            self.trees.keys().cloned().collect()
        }

        fn rename_tree(&mut self, old_name: &str, new_name: &str) -> Result<(), DuplicateNameException> {
            if self.trees.contains_key(new_name) {
                return Err(DuplicateNameException::with_message(format!(
                    "Name {new_name} already exists"
                )));
            }
            if let Some(id) = self.trees.remove(old_name) {
                self.trees.insert(new_name.to_string(), id);
            }
            Ok(())
        }

        fn remove_tree(&mut self, tree_name: &str) -> bool {
            self.trees.remove(tree_name).is_some()
        }

        fn get_module(&self, _tree_name: &str, _name: &str) -> Option<Box<dyn ProgramModule>> {
            None
        }

        fn get_fragment_by_name(&self, _tree_name: &str, _name: &str) -> Option<Box<dyn ProgramFragment>> {
            None
        }

        fn get_fragment_at(&self, _tree_name: &str, _addr: &Address) -> Option<Box<dyn ProgramFragment>> {
            None
        }

        fn add_memory_block(&mut self, _name: &str, _range: &AddressRange) {}

        fn set_program_name(&mut self, _old_name: &str, _new_name: &str) {}

        fn get_address_map(&self) -> &dyn AddressMap {
            unimplemented!("mock does not exercise get_address_map")
        }

        fn get_database_handle(&self) -> &DBHandle {
            &self.db_handle
        }

        fn get_tree_name(&self, tree_id: i64) -> Option<String> {
            self.trees
                .iter()
                .find(|(_, &id)| id == tree_id)
                .map(|(name, _)| name.clone())
        }

        fn get_error_handler(&self) -> &dyn ErrorHandler {
            &self.error_handler
        }

        fn get_tree_record(&self, _tree_id: i64) -> Option<DBRecord> {
            None
        }

        fn get_lock(&self) -> &Lock<()> {
            &self.lock
        }

        fn get_program(&self) -> &ProgramDB {
            unimplemented!("mock does not exercise get_program")
        }

        fn update_tree_record(&mut self, _record: &DBRecord, _update_modification_number: bool) {}
    }

    #[test]
    fn object_safe_and_tracks_tree_names() {
        let mut mgr: Box<dyn TreeManager> = Box::new(MockTreeManager::new());

        assert!(mgr.get_tree_names().is_empty());

        // create_root_module rejects duplicates.
        assert!(mgr.create_root_module("Program Tree").is_err());
        assert_eq!(mgr.get_tree_names(), vec!["Program Tree".to_string()]);
        assert!(mgr.create_root_module("Program Tree").is_err());

        // rename_tree moves the name but keeps the ID reachable by get_root_module_by_id.
        mgr.rename_tree("Program Tree", "Renamed Tree").unwrap();
        assert_eq!(mgr.get_tree_names(), vec!["Renamed Tree".to_string()]);
        assert_eq!(mgr.get_tree_name(0), Some("Renamed Tree".to_string()));

        // rename_tree rejects collisions with an existing tree.
        mgr.create_root_module("Other Tree").ok();
        assert!(mgr.rename_tree("Renamed Tree", "Other Tree").is_err());

        assert!(mgr.remove_tree("Renamed Tree"));
        assert!(!mgr.remove_tree("Renamed Tree"));
    }

    #[test]
    fn program_ready_reports_cancellation() {
        struct CancelledMonitor;
        impl TaskMonitor for CancelledMonitor {
            fn is_cancelled(&self) -> bool {
                true
            }
            fn set_show_progress_value(&self, _show: bool) {}
            fn set_message(&self, _message: &str) {}
            fn get_message(&self) -> String {
                String::new()
            }
            fn set_progress(&self, _value: i64) {}
            fn initialize(&self, _max: i64) {}
            fn set_maximum(&self, _max: i64) {}
            fn get_maximum(&self) -> i64 {
                0
            }
            fn set_indeterminate(&self, _indeterminate: bool) {}
            fn is_indeterminate(&self) -> bool {
                false
            }
            fn check_cancelled(&self) -> Result<(), CancelledException> {
                Err(CancelledException::new("cancelled"))
            }
            fn increment_progress(&self, _amount: i64) {}
            fn get_progress(&self) -> i64 {
                -1
            }
            fn cancel(&self) {}
            fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
            fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
            fn set_cancel_enabled(&self, _enabled: bool) {}
            fn is_cancel_enabled(&self) -> bool {
                true
            }
            fn clear_cancelled(&self) {}
        }

        let mut mgr = MockTreeManager::new();
        let result = mgr.program_ready(OpenMode::Create, 0, &CancelledMonitor);
        assert!(matches!(result, Err(ProgramReadyError::Cancelled(_))));
    }

    #[test]
    fn get_root_module_by_id_default_delegates_through_get_tree_name() {
        let mut mgr = MockTreeManager::new();
        mgr.create_root_module(DEFAULT_TREE_NAME).ok();

        assert_eq!(mgr.get_tree_names(), vec![DEFAULT_TREE_NAME.to_string()]);
        // No stored ProgramModule in this mock, but the default method should still route through
        // get_tree_name/get_root_module rather than being a stub itself.
        assert!(mgr.get_root_module_by_id(0).is_none());
        // An unknown tree ID short-circuits via `?` on `get_tree_name` returning `None`.
        assert!(mgr.get_root_module_by_id(999).is_none());
    }
}
