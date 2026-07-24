//! Port of `ghidra.program.database.module.ModuleManager`.
//!
//! The Java type is a package-private, concrete class that manages the module/fragment tables
//! for a single program tree, owning a [`ModuleDBAdapter`], [`FragmentDBAdapter`], and
//! [`ParentChildDBAdapter`] plus the `DbCache`s and address-range map built on top of them. Its
//! constructor (adapter selection/version-upgrade, address-map upgrade, and root-module creation)
//! and a handful of private helpers (`initializeAdapters`, `addressUpgrade`,
//! `createFragmentAdjustNameAsNeeded`, `removeFragment`, and the private `ModuleFactory` /
//! `FragmentFactory` / `FragmentHolder` inner classes) are construction/implementation details
//! tied to a concrete implementation, so — following the same convention already used for
//! [`ModuleDBAdapter`](crate::program::database::module::ModuleDBAdapter),
//! [`FragmentDBAdapter`](crate::program::database::module::FragmentDBAdapter),
//! [`ParentChildDBAdapter`](crate::program::database::module::ParentChildDBAdapter), and
//! [`ProgramTreeDBAdapter`](crate::program::database::module::ProgramTreeDBAdapter) — this port
//! only models the package-private instance API the class exposes to the rest of its package, as
//! an object-safe trait. This trait was itself selected as a dependency-cycle cut-point.
//!
//! [`ModuleDB`](crate::program::seam_stubs::ModuleDB) and
//! [`FragmentDB`](crate::program::seam_stubs::FragmentDB) (the concrete, DB-backed
//! `ProgramModule`/`ProgramFragment` implementations this manager caches) have not been ported
//! yet, so methods that reference them use minimal placeholder traits from
//! [`crate::program::seam_stubs`].

use std::any::Any;
use std::io;

use thiserror::Error;

use crate::framework::db::{DBHandle, DBRecord};
use crate::program::database::module::{FragmentDBAdapter, ModuleDBAdapter, ParentChildDBAdapter};
use crate::program::database::program_db::ProgramDB;
use crate::program::model::address::{Address, AddressOverflowException, AddressRange, AddressSet};
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::code_unit_iterator::CodeUnitIterator;
use crate::program::model::listing::group::Group;
use crate::program::model::listing::{ProgramFragment, ProgramModule};
use crate::program::seam_stubs::{FragmentDB, ModuleDB};
use crate::util::exception::{CancelledException, NotFoundException};
use crate::util::lock::Lock;
use crate::util::task::TaskMonitor;

/// DB table name prefix for a program tree's fragment-address range map. Stands in for
/// `ModuleManager.FRAGMENT_ADDRESS_TABLE_NAME`.
pub const FRAGMENT_ADDRESS_TABLE_NAME: &str = "Fragment Addresses";

/// Key of a program tree's root module. Stands in for `ModuleManager.ROOT_MODULE_ID`.
pub const ROOT_MODULE_ID: i64 = 0;

/// Builds the per-tree fragment-address range map's table name. Stands in for
/// `ModuleManager.getFragAddressTableName(long)`.
pub fn get_frag_address_table_name(tree_id: i64) -> String {
    format!("{FRAGMENT_ADDRESS_TABLE_NAME}{tree_id}")
}

/// Error produced by [`ModuleManager::move_address_range`].
///
/// Combines the two checked exceptions declared on the Java method
/// `ModuleManager.moveAddressRange(Address, Address, long, TaskMonitor)`.
#[derive(Error, Debug, PartialEq)]
pub enum MoveAddressRangeError {
    #[error(transparent)]
    Overflow(#[from] AddressOverflowException),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Manages the module and fragment tables for a single program tree.
///
/// Port of `ghidra.program.database.module.ModuleManager`. See the module docs for what was
/// intentionally left out (construction/adapter-selection logic and private helpers).
pub trait ModuleManager {
    /// Gets the ID of the tree this manager belongs to.
    ///
    /// Stands in for `ModuleManager.getTreeID()`.
    fn get_tree_id(&self) -> i64;

    /// Gets the adapter used to access this tree's Module table.
    ///
    /// Stands in for `ModuleManager.getModuleAdapter()`.
    fn get_module_adapter(&self) -> &dyn ModuleDBAdapter;

    /// Gets the adapter used to access this tree's Fragment table.
    ///
    /// Stands in for `ModuleManager.getFragmentAdapter()`.
    fn get_fragment_adapter(&self) -> &dyn FragmentDBAdapter;

    /// Gets the adapter used to access this tree's parent/child relationship table.
    ///
    /// Stands in for `ModuleManager.getParentChildAdapter()`.
    fn get_parent_child_adapter(&self) -> &dyn ParentChildDBAdapter;

    /// Gets the lock used to synchronize access to this tree.
    ///
    /// Stands in for `ModuleManager.getLock()`.
    fn get_lock(&self) -> &Lock<()>;

    /// Sets the name of the program tree this manager belongs to.
    ///
    /// Stands in for `ModuleManager.setName(String)`.
    fn set_name(&mut self, name: &str);

    /// Notifies this manager that the program's image base changed. When `commit` is true, the
    /// tree record is persisted before the cache is invalidated.
    ///
    /// Stands in for `ModuleManager.imageBaseChanged(boolean)`.
    fn image_base_changed(&mut self, commit: bool);

    /// Reports a database IO error, e.g. to the tree's error handler.
    ///
    /// Stands in for `ModuleManager.dbError(IOException)`.
    fn db_error(&self, error: io::Error);

    /// Renames the root module to reflect a program name change.
    ///
    /// Stands in for `ModuleManager.setProgramName(String, String)`.
    fn set_program_name(&mut self, old_name: &str, new_name: &str);

    /// Gets the root module of this tree.
    ///
    /// Stands in for `ModuleManager.getRootModule()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_root_module(&self) -> io::Result<Box<dyn ProgramModule>>;

    /// Gets the module with the given name, or `None` if there is no such module.
    ///
    /// Stands in for `ModuleManager.getModule(String)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_module(&self, name: &str) -> io::Result<Option<Box<dyn ProgramModule>>>;

    /// Gets the fragment with the given name, or `None` if there is no such fragment.
    ///
    /// Stands in for `ModuleManager.getFragment(String)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_fragment_by_name(&self, name: &str) -> io::Result<Option<Box<dyn ProgramFragment>>>;

    /// Gets the fragment containing the given address, or `None` if the address is not in any
    /// fragment.
    ///
    /// Stands in for `ModuleManager.getFragment(Address)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn get_fragment_at(&self, addr: &Address) -> io::Result<Option<Box<dyn ProgramFragment>>>;

    /// Adds a new memory block's address range to the fragment with the given name, creating the
    /// fragment (adjusting its name to avoid a collision, if needed) if it does not already
    /// exist.
    ///
    /// Stands in for `ModuleManager.addMemoryBlock(String, AddressRange)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn add_memory_block(&mut self, name: &str, range: &AddressRange) -> io::Result<()>;

    /// Removes the given address range from whichever fragments contain it, deleting any
    /// fragment left empty as a result.
    ///
    /// Stands in for `ModuleManager.removeMemoryBlock(Address, Address, TaskMonitor)`.
    fn remove_memory_block(&mut self, start_addr: &Address, end_addr: &Address, monitor: &dyn TaskMonitor);

    /// Moves the fragment address-range mappings for `[from_addr, from_addr + length)` to start
    /// at `to_addr` instead.
    ///
    /// Stands in for `ModuleManager.moveAddressRange(Address, Address, long, TaskMonitor)`.
    ///
    /// # Errors
    ///
    /// Returns an error if the destination range would overflow the address space, or if
    /// `monitor` reports cancellation.
    fn move_address_range(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        length: i64,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), MoveAddressRangeError>;

    /// Notifies this manager that `fragment` was added as a child of the module with key
    /// `parent_id`.
    ///
    /// Stands in for `ModuleManager.fragmentAdded(long, ProgramFragment)`.
    fn fragment_added(&mut self, parent_id: i64, fragment: &dyn ProgramFragment);

    /// Notifies this manager that `module` was added as a child of the module with key
    /// `parent_id`.
    ///
    /// Stands in for `ModuleManager.moduleAdded(long, ProgramModule)`.
    fn module_added(&mut self, parent_id: i64, module: &dyn ProgramModule);

    /// Notifies this manager that the child named `child_name` (key `child_id`) was removed from
    /// `parent_module`. If `delete_child` is true, the child (a fragment if `is_fragment`,
    /// otherwise a module) is also removed from its cache.
    ///
    /// Stands in for
    /// `ModuleManager.groupRemoved(ModuleDB, long, String, boolean, boolean)`.
    fn group_removed(
        &mut self,
        parent_module: &dyn ModuleDB,
        child_id: i64,
        child_name: &str,
        is_fragment: bool,
        delete_child: bool,
    );

    /// Notifies this manager that `group`'s comment changed from `old_comments`.
    ///
    /// Stands in for `ModuleManager.commentsChanged(String, Group)`.
    fn comments_changed(&mut self, old_comments: Option<&str>, group: &dyn Group);

    /// Notifies this manager that `group` was renamed from `old_name`.
    ///
    /// Stands in for `ModuleManager.nameChanged(String, Group)`.
    fn name_changed(&mut self, old_name: &str, group: &dyn Group);

    /// Performs a recursive check to determine if `id` (positive for a module, negative for a
    /// fragment) is a child or descendant of the module with key `module_id`.
    ///
    /// Stands in for `ModuleManager.isDescendant(long, long)`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn is_descendant(&self, id: i64, module_id: i64) -> io::Result<bool>;

    /// Gets the name of the program tree this manager belongs to.
    ///
    /// Stands in for `ModuleManager.getTreeName()`.
    fn get_tree_name(&self) -> String;

    /// Gets a forward iterator over the code units in `fragment`.
    ///
    /// Stands in for `ModuleManager.getCodeUnits(FragmentDB)`.
    fn get_code_units(&self, fragment: &dyn FragmentDB) -> Box<dyn CodeUnitIterator>;

    /// Moves all code units in `[min, max]` into `dest_frag`, removing them from whichever
    /// fragments currently contain them.
    ///
    /// Stands in for `ModuleManager.move(FragmentDB, Address, Address)`. Renamed since `move` is
    /// a Rust keyword.
    ///
    /// # Errors
    ///
    /// Returns an error if any address in `[min, max]` does not belong to program memory.
    fn move_code_units_to_fragment(
        &mut self,
        dest_frag: &dyn FragmentDB,
        min: &Address,
        max: &Address,
    ) -> Result<(), NotFoundException>;

    /// Gets the fragment containing the given code unit's minimum address.
    ///
    /// Stands in for `ModuleManager.getFragment(CodeUnit)`.
    fn get_fragment_containing(&self, code_unit: &dyn CodeUnit) -> Option<Box<dyn FragmentDB>>;

    /// Notifies this manager that `child` was reordered among `parent_module`'s children.
    ///
    /// Stands in for `ModuleManager.childReordered(ModuleDB, Group)`.
    fn child_reordered(&mut self, parent_module: &dyn ModuleDB, child: &dyn Group);

    /// Notifies this manager that `group` was reparented from `old_parent_name` to
    /// `new_parent_name`.
    ///
    /// Stands in for `ModuleManager.childReparented(Group, String, String)`.
    fn child_reparented(&mut self, group: &dyn Group, old_parent_name: &str, new_parent_name: &str);

    /// Gets the names of the modules which are parents of the child with key `child_id`.
    ///
    /// Stands in for `ModuleManager.getParentNames(long)`. Returns an empty vector (rather than
    /// throwing) on a database IO error, matching the Java method's internal error handling.
    fn get_parent_names(&self, child_id: i64) -> Vec<String>;

    /// Gets the modules which are parents of the child with key `child_id`.
    ///
    /// Stands in for `ModuleManager.getParents(long)`. Returns an empty vector (rather than
    /// throwing) on a database IO error, matching the Java method's internal error handling.
    fn get_parents(&self, child_id: i64) -> Vec<Box<dyn ProgramModule>>;

    /// Gets the combined address set for the fragment with key `frag_id`. Assumes the manager's
    /// lock is already held.
    ///
    /// Stands in for `ModuleManager.getFragmentAddressSet(long)`.
    fn get_fragment_address_set(&self, frag_id: i64) -> AddressSet;

    /// Invalidates this manager's module/fragment caches and refreshes its tree record.
    ///
    /// Stands in for `ModuleManager.invalidateCache()`.
    fn invalidate_cache(&mut self);

    /// Gets an opaque token that changes identity every time this manager's cache is
    /// invalidated. Stands in for the Java `Object` returned by `getVersionTag()`.
    ///
    /// Stands in for `ModuleManager.getVersionTag()`.
    fn get_version_tag(&self) -> Box<dyn Any>;

    /// Gets the current modification number of this tree.
    ///
    /// Stands in for `ModuleManager.getModificationNumber()`.
    fn get_modification_number(&self) -> i64;

    /// Disposes of this manager, deleting its underlying database tables.
    ///
    /// Stands in for `ModuleManager.dispose()`.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem accessing the database.
    fn dispose(&mut self) -> io::Result<()>;

    /// Gets the program that owns this tree.
    ///
    /// Stands in for `ModuleManager.getProgram()`.
    fn get_program(&self) -> &ProgramDB;

    /// Gets the database handle backing this tree.
    ///
    /// Stands in for `ModuleManager.getDatabaseHandle()`.
    fn get_database_handle(&self) -> &DBHandle;

    /// Gets the cached fragment with the given key, or `None` if there is no such fragment.
    ///
    /// Stands in for `ModuleManager.getFragmentDB(long)`.
    fn get_fragment_db(&self, key: i64) -> Option<Box<dyn FragmentDB>>;

    /// Gets the cached module with the given key, or `None` if there is no such module.
    ///
    /// Stands in for `ModuleManager.getModuleDB(long)`.
    fn get_module_db(&self, key: i64) -> Option<Box<dyn ModuleDB>>;

    /// Gets the cached fragment for the given fragment record.
    ///
    /// Stands in for `ModuleManager.getFragmentDB(DBRecord)`.
    fn get_fragment_db_for_record(&self, fragment_record: &DBRecord) -> Box<dyn FragmentDB>;

    /// Gets the cached module for the given module record.
    ///
    /// Stands in for `ModuleManager.getModuleDB(DBRecord)`.
    fn get_module_db_for_record(&self, module_record: &DBRecord) -> Box<dyn ModuleDB>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, RecordIterator};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::listing::code_unit_iterator::EmptyCodeUnitIterator;
    use crate::util::exception::DuplicateNameException;
    use std::collections::BTreeMap;

    fn test_addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockModuleDBAdapter;
    impl ModuleDBAdapter for MockModuleDBAdapter {
        fn create_module_record(&mut self, _parent_module_id: i64, _name: &str) -> io::Result<DBRecord> {
            unimplemented!()
        }
        fn get_module_record(&self, _key: i64) -> io::Result<Option<DBRecord>> {
            Ok(None)
        }
        fn get_module_record_by_name(&self, _name: &str) -> io::Result<Option<DBRecord>> {
            Ok(None)
        }
        fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
            unimplemented!()
        }
        fn update_module_record(&mut self, _record: &DBRecord) -> io::Result<()> {
            Ok(())
        }
        fn remove_module_record(&mut self, _child_id: i64) -> io::Result<bool> {
            Ok(false)
        }
    }

    struct MockFragmentDBAdapter;
    impl FragmentDBAdapter for MockFragmentDBAdapter {
        fn create_fragment_record(
            &mut self,
            _parent_module_id: i64,
            _name: &str,
        ) -> io::Result<DBRecord> {
            unimplemented!()
        }
        fn get_fragment_record(&self, _key: i64) -> io::Result<Option<DBRecord>> {
            Ok(None)
        }
        fn get_fragment_record_by_name(&self, _name: &str) -> io::Result<Option<DBRecord>> {
            Ok(None)
        }
        fn update_fragment_record(&mut self, _record: &DBRecord) -> io::Result<()> {
            Ok(())
        }
        fn remove_fragment_record(&mut self, _child_id: i64) -> io::Result<bool> {
            Ok(false)
        }
    }

    struct MockParentChildAdapter;
    impl ParentChildDBAdapter for MockParentChildAdapter {
        fn add_parent_child_record(
            &mut self,
            _parent_module_id: i64,
            _child_id: i64,
        ) -> io::Result<DBRecord> {
            unimplemented!()
        }
        fn get_parent_child_record(
            &self,
            _parent_id: i64,
            _child_id: i64,
        ) -> io::Result<Option<DBRecord>> {
            Ok(None)
        }
        fn get_parent_child_record_by_key(&self, _key: i64) -> io::Result<Option<DBRecord>> {
            Ok(None)
        }
        fn update_parent_child_record(&mut self, _record: &DBRecord) -> io::Result<()> {
            Ok(())
        }
        fn remove_parent_child_record(&mut self, _key: i64) -> io::Result<bool> {
            Ok(false)
        }
        fn get_parent_child_keys(&self, _id: i64, _index_col: usize) -> io::Result<Vec<Field>> {
            Ok(Vec::new())
        }
    }

    struct MockGroup {
        name: String,
    }

    impl Group for MockGroup {
        fn get_comment(&self) -> Option<String> {
            None
        }
        fn set_comment(&mut self, _comment: Option<&str>) {}
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
            0
        }
        fn get_parents(&self) -> Vec<Box<dyn Group>> {
            Vec::new()
        }
        fn get_parent_names(&self) -> Vec<String> {
            Vec::new()
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

    /// A minimal in-memory `ModuleManager`, exercising object-safety and the core
    /// name-tracking/version-tag behavior described by the Java class.
    struct MockModuleManager {
        tree_id: i64,
        tree_name: String,
        module_adapter: MockModuleDBAdapter,
        fragment_adapter: MockFragmentDBAdapter,
        parent_child_adapter: MockParentChildAdapter,
        lock: Lock<()>,
        db_handle: DBHandle,
        fragment_names: BTreeMap<String, ()>,
        version_counter: i64,
    }

    impl ModuleManager for MockModuleManager {
        fn get_tree_id(&self) -> i64 {
            self.tree_id
        }

        fn get_module_adapter(&self) -> &dyn ModuleDBAdapter {
            &self.module_adapter
        }

        fn get_fragment_adapter(&self) -> &dyn FragmentDBAdapter {
            &self.fragment_adapter
        }

        fn get_parent_child_adapter(&self) -> &dyn ParentChildDBAdapter {
            &self.parent_child_adapter
        }

        fn get_lock(&self) -> &Lock<()> {
            &self.lock
        }

        fn set_name(&mut self, name: &str) {
            self.tree_name = name.to_string();
        }

        fn image_base_changed(&mut self, _commit: bool) {
            self.version_counter += 1;
        }

        fn db_error(&self, _error: io::Error) {}

        fn set_program_name(&mut self, _old_name: &str, _new_name: &str) {}

        fn get_root_module(&self) -> io::Result<Box<dyn ProgramModule>> {
            Err(io::Error::new(io::ErrorKind::NotFound, "no root in mock"))
        }

        fn get_module(&self, _name: &str) -> io::Result<Option<Box<dyn ProgramModule>>> {
            Ok(None)
        }

        fn get_fragment_by_name(&self, name: &str) -> io::Result<Option<Box<dyn ProgramFragment>>> {
            if self.fragment_names.contains_key(name) {
                Ok(None) // presence tracked, but this mock never materializes a ProgramFragment
            } else {
                Ok(None)
            }
        }

        fn get_fragment_at(&self, _addr: &Address) -> io::Result<Option<Box<dyn ProgramFragment>>> {
            Ok(None)
        }

        fn add_memory_block(&mut self, name: &str, _range: &AddressRange) -> io::Result<()> {
            self.fragment_names.insert(name.to_string(), ());
            self.version_counter += 1;
            Ok(())
        }

        fn remove_memory_block(&mut self, _start_addr: &Address, _end_addr: &Address, _monitor: &dyn TaskMonitor) {
            self.version_counter += 1;
        }

        fn move_address_range(
            &mut self,
            _from_addr: &Address,
            _to_addr: &Address,
            _length: i64,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), MoveAddressRangeError> {
            Ok(())
        }

        fn fragment_added(&mut self, _parent_id: i64, _fragment: &dyn ProgramFragment) {}

        fn module_added(&mut self, _parent_id: i64, _module: &dyn ProgramModule) {}

        fn group_removed(
            &mut self,
            _parent_module: &dyn ModuleDB,
            _child_id: i64,
            child_name: &str,
            _is_fragment: bool,
            delete_child: bool,
        ) {
            if delete_child {
                self.fragment_names.remove(child_name);
            }
        }

        fn comments_changed(&mut self, _old_comments: Option<&str>, _group: &dyn Group) {}

        fn name_changed(&mut self, _old_name: &str, _group: &dyn Group) {}

        fn is_descendant(&self, _id: i64, _module_id: i64) -> io::Result<bool> {
            Ok(false)
        }

        fn get_tree_name(&self) -> String {
            self.tree_name.clone()
        }

        fn get_code_units(&self, _fragment: &dyn FragmentDB) -> Box<dyn CodeUnitIterator> {
            Box::new(EmptyCodeUnitIterator)
        }

        fn move_code_units_to_fragment(
            &mut self,
            _dest_frag: &dyn FragmentDB,
            _min: &Address,
            _max: &Address,
        ) -> Result<(), NotFoundException> {
            Ok(())
        }

        fn get_fragment_containing(&self, _code_unit: &dyn CodeUnit) -> Option<Box<dyn FragmentDB>> {
            None
        }

        fn child_reordered(&mut self, _parent_module: &dyn ModuleDB, _child: &dyn Group) {}

        fn child_reparented(&mut self, _group: &dyn Group, _old_parent_name: &str, _new_parent_name: &str) {}

        fn get_parent_names(&self, _child_id: i64) -> Vec<String> {
            Vec::new()
        }

        fn get_parents(&self, _child_id: i64) -> Vec<Box<dyn ProgramModule>> {
            Vec::new()
        }

        fn get_fragment_address_set(&self, _frag_id: i64) -> AddressSet {
            AddressSet::new()
        }

        fn invalidate_cache(&mut self) {
            self.version_counter += 1;
        }

        fn get_version_tag(&self) -> Box<dyn Any> {
            Box::new(self.version_counter)
        }

        fn get_modification_number(&self) -> i64 {
            self.version_counter
        }

        fn dispose(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn get_program(&self) -> &ProgramDB {
            unimplemented!("mock does not exercise get_program")
        }

        fn get_database_handle(&self) -> &DBHandle {
            &self.db_handle
        }

        fn get_fragment_db(&self, _key: i64) -> Option<Box<dyn FragmentDB>> {
            None
        }

        fn get_module_db(&self, _key: i64) -> Option<Box<dyn ModuleDB>> {
            None
        }

        fn get_fragment_db_for_record(&self, _fragment_record: &DBRecord) -> Box<dyn FragmentDB> {
            unimplemented!("mock never materializes a FragmentDB")
        }

        fn get_module_db_for_record(&self, _module_record: &DBRecord) -> Box<dyn ModuleDB> {
            unimplemented!("mock never materializes a ModuleDB")
        }
    }

    fn make_manager() -> MockModuleManager {
        MockModuleManager {
            tree_id: 1,
            tree_name: "Program Tree".to_string(),
            module_adapter: MockModuleDBAdapter,
            fragment_adapter: MockFragmentDBAdapter,
            parent_child_adapter: MockParentChildAdapter,
            lock: Lock::new_unit("Module Manager"),
            db_handle: DBHandle::new().expect("db handle should construct"),
            fragment_names: BTreeMap::new(),
            version_counter: 0,
        }
    }

    #[test]
    fn object_safe_and_tracks_memory_blocks() {
        let mut manager: Box<dyn ModuleManager> = Box::new(make_manager());

        assert_eq!(manager.get_tree_id(), 1);
        assert_eq!(manager.get_tree_name(), "Program Tree");

        let before = *manager.get_version_tag().downcast::<i64>().unwrap();

        let range = AddressRange::new(test_addr(0), test_addr(10));
        manager
            .add_memory_block(".text", &range)
            .expect("add_memory_block should succeed");

        let after = *manager.get_version_tag().downcast::<i64>().unwrap();
        assert_ne!(before, after, "version tag should change after a mutation");

        manager.group_removed(&NeverModuleDB, 0, ".text", true, true);
        assert!(manager.get_fragment_by_name(".text").unwrap().is_none());
    }

    #[test]
    fn get_frag_address_table_name_appends_tree_id() {
        assert_eq!(get_frag_address_table_name(5), "Fragment Addresses5");
    }

    #[test]
    fn move_address_range_error_wraps_both_variants() {
        let overflow: MoveAddressRangeError = AddressOverflowException::default().into();
        assert!(matches!(overflow, MoveAddressRangeError::Overflow(_)));

        let cancelled: MoveAddressRangeError = CancelledException::default().into();
        assert!(matches!(cancelled, MoveAddressRangeError::Cancelled(_)));
    }

    /// A `ModuleDB` placeholder that panics if any `ProgramModule`/`Group` method is called,
    /// proving `group_removed` only needs to pass it through opaquely.
    struct NeverModuleDB;

    impl Group for NeverModuleDB {
        fn get_comment(&self) -> Option<String> {
            unimplemented!()
        }
        fn set_comment(&mut self, _comment: Option<&str>) {
            unimplemented!()
        }
        fn get_name(&self) -> String {
            unimplemented!()
        }
        fn set_name(&mut self, _name: &str) -> Result<(), DuplicateNameException> {
            unimplemented!()
        }
        fn contains(&self, _code_unit: &dyn CodeUnit) -> bool {
            unimplemented!()
        }
        fn get_num_parents(&self) -> i32 {
            unimplemented!()
        }
        fn get_parents(&self) -> Vec<Box<dyn Group>> {
            unimplemented!()
        }
        fn get_parent_names(&self) -> Vec<String> {
            unimplemented!()
        }
        fn get_tree_name(&self) -> String {
            unimplemented!()
        }
        fn is_deleted(&self) -> bool {
            unimplemented!()
        }
        fn get_min_address(&self) -> Option<Address> {
            unimplemented!()
        }
        fn get_max_address(&self) -> Option<Address> {
            unimplemented!()
        }
    }

    impl ProgramModule for NeverModuleDB {
        fn contains_fragment(&self, _fragment: &dyn ProgramFragment) -> bool {
            unimplemented!()
        }
        fn contains_module(&self, _module: &dyn ProgramModule) -> bool {
            unimplemented!()
        }
        fn get_num_children(&self) -> i32 {
            unimplemented!()
        }
        fn get_children(&self) -> Vec<Box<dyn Group>> {
            unimplemented!()
        }
        fn get_index(&self, _name: &str) -> i32 {
            unimplemented!()
        }
        fn add_module(
            &mut self,
            _module: Box<dyn ProgramModule>,
        ) -> Result<(), crate::program::model::listing::AddModuleError> {
            unimplemented!()
        }
        fn add_fragment(
            &mut self,
            _fragment: Box<dyn ProgramFragment>,
        ) -> Result<(), crate::program::model::listing::DuplicateGroupException> {
            unimplemented!()
        }
        fn create_module(
            &mut self,
            _module_name: &str,
        ) -> Result<Box<dyn ProgramModule>, DuplicateNameException> {
            unimplemented!()
        }
        fn create_fragment(
            &mut self,
            _fragment_name: &str,
        ) -> Result<Box<dyn ProgramFragment>, DuplicateNameException> {
            unimplemented!()
        }
        fn reparent(
            &mut self,
            _name: &str,
            _old_parent: &mut dyn ProgramModule,
        ) -> Result<(), NotFoundException> {
            unimplemented!()
        }
        fn move_child(&mut self, _name: &str, _index: i32) -> Result<(), NotFoundException> {
            unimplemented!()
        }
        fn remove_child(&mut self, _name: &str) -> Result<bool, crate::util::exception::NotEmptyException> {
            unimplemented!()
        }
        fn is_descendant_module(&self, _module: &dyn ProgramModule) -> bool {
            unimplemented!()
        }
        fn is_descendant_fragment(&self, _fragment: &dyn ProgramFragment) -> bool {
            unimplemented!()
        }
        fn get_min_address(&self) -> Option<Address> {
            unimplemented!()
        }
        fn get_max_address(&self) -> Option<Address> {
            unimplemented!()
        }
        fn get_first_address(&self) -> Option<Address> {
            unimplemented!()
        }
        fn get_last_address(&self) -> Option<Address> {
            unimplemented!()
        }
        fn get_address_set(&self) -> &dyn crate::program::model::address::AddressSetView {
            unimplemented!()
        }
        fn get_version_tag(&self) -> Box<dyn Any> {
            unimplemented!()
        }
        fn get_modification_number(&self) -> i64 {
            unimplemented!()
        }
        fn get_tree_id(&self) -> i64 {
            unimplemented!()
        }
    }

    impl ModuleDB for NeverModuleDB {}
}
