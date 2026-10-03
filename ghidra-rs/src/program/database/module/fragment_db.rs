//! Port of `ghidra.program.database.module.FragmentDB`.
//!
//! The Java type is a package-private, concrete `DbObject` implementing `ProgramFragment`. It
//! caches a fragment's DB record plus its address set (an `AddressSet` maintained by
//! `ModuleManager`/`TreeManager` as memory blocks and code units move around), and reaches back
//! through a `ModuleManager moduleMgr` field for everything else (adapters, notifications, the
//! containing tree's name, ...).
//!
//! # Design notes shared with [`module_db`](super::module_db)
//!
//! * **No `Lock`/`Lock.Closeable`.** Java wraps almost every method body in
//!   `try (Closeable c = lock.read()) { ... }` / `lock.write()`, guarding concurrent access from
//!   multiple threads (the Swing EDT plus background analysis threads). This port is
//!   single-threaded and `Rc`/`RefCell`-based throughout (see below), so there is no concurrent
//!   access for a lock to guard; those critical sections are omitted rather than modeled, and
//!   [`ModuleManager::get_lock`](super::ModuleManager::get_lock) is never called from here. This
//!   mirrors the reasoning [`DbObjectState`] already documents for why `refreshIfNeeded`'s
//!   `synchronized` is elided.
//! * **`Rc<RefCell<dyn ModuleManager>>`, not `Arc<dyn ModuleManager>`.** Unlike
//!   [`CodeUnitOwner`](crate::program::database::code::CodeUnitOwner) (whose methods are all
//!   `&self`, so an `Arc` handle suffices), several [`ModuleManager`](super::ModuleManager)
//!   methods this type calls are declared `&mut self` (`fragment_added`, `comments_changed`,
//!   `name_changed`, ...) -- a pre-existing tension in this crate's port between Java's mutable
//!   instance methods and Rust's `&self`-only trait-object convention. Since `ModuleManager` was
//!   already committed with that shape, this port copes with it locally via a shared, interior
//!   mutable handle, rather than reopening that trait's signature.
//! * **Reentrancy hazard.** Because `RefCell` (unlike a Java intrinsic lock) is *not* reentrant,
//!   a `ModuleManager` implementation must not call back into the `&dyn FragmentDB`/`&dyn
//!   ModuleDB` argument it was just handed (e.g. from [`fragment_added`](super::ModuleManager::fragment_added)) in a way that
//!   touches that object's own `module_mgr` handle -- doing so while this crate's own call into
//!   the manager is still on the stack would panic with "already borrowed". No concrete
//!   `ModuleManager` exists yet to exercise this; a future one must respect it.
//! * **Downcasting.** Java uses `(FragmentDB) fragment`/`(ModuleDB) module` instanceof-casts to
//!   reach package-private fields (chiefly the DB key) that aren't part of the public
//!   `ProgramFragment`/`ProgramModule` API. This port does the same via `std::any::Any`, reached
//!   by upcasting `&dyn ProgramFragment`/`&dyn ProgramModule` through their `Group: Any`
//!   supertrait (Rust's trait-upcasting coercion handles the transitive hop).

use std::cell::RefCell;
use std::rc::Rc;

use crate::framework::db::DBRecord;
use crate::program::database::db_object::{DbObject, DbObjectState};
use crate::program::database::module::module_manager::ModuleManager;
use crate::program::database::module::CHILD_ID_COL;
use crate::program::database::module::{FRAGMENT_COMMENTS_COL, FRAGMENT_NAME_COL};
use crate::program::model::address::{
    Address, AddressRange, AddressRangeIterator, AddressSet, AddressSetView, BoxedAddressIterator,
};
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::code_unit_iterator::CodeUnitIterator;
use crate::program::model::listing::{Group, ProgramFragment};
use crate::util::exception::{DuplicateNameException, NotFoundException};

/// Marker trait implemented by [`FragmentDbImpl`], the concrete, DB-backed `ProgramFragment`
/// this crate's [`ModuleManager`] hands out.
///
/// Kept as its own trait (rather than having [`ModuleManager`] name `FragmentDbImpl` directly)
/// so the manager stays generic over `dyn FragmentDB`, preserving the dependency-cycle cut
/// described in [`ModuleManager`]'s module docs -- this file is the only one that needs to name
/// the concrete struct.
///
/// Port of `ghidra.program.database.module.FragmentDB`'s role as seen from outside its package
/// (i.e. from [`ModuleManager`]); [`FragmentDbImpl`] is the actual port of the class body.
pub trait FragmentDB: ProgramFragment {}

/// Database implementation of [`ProgramFragment`].
///
/// Port of `ghidra.program.database.module.FragmentDB`. See the module docs for the interior
/// mutability/locking design shared with [`ModuleDbImpl`](super::ModuleDbImpl).
pub struct FragmentDbImpl {
    state: DbObjectState,
    record: RefCell<DBRecord>,
    module_mgr: Rc<RefCell<dyn ModuleManager>>,
    addr_set: RefCell<AddressSet>,
}

impl FragmentDbImpl {
    /// Constructs a fragment view over `record`, backed by `module_mgr` and covering `addr_set`.
    ///
    /// Port of `FragmentDB(ModuleManager, DBRecord, AddressSet)`.
    pub fn new(
        module_mgr: Rc<RefCell<dyn ModuleManager>>,
        record: DBRecord,
        addr_set: AddressSet,
    ) -> Self {
        let key = record.get_key().get_long_value();
        FragmentDbImpl {
            state: DbObjectState::new(key),
            record: RefCell::new(record),
            module_mgr,
            addr_set: RefCell::new(addr_set),
        }
    }

    /// Gets the manager that owns this fragment. Stands in for the package-private
    /// `FragmentDB.getModuleManager()`.
    pub fn module_manager_handle(&self) -> &Rc<RefCell<dyn ModuleManager>> {
        &self.module_mgr
    }

    /// Adds a range to this fragment's address set. Stands in for the package-private
    /// `FragmentDB.addRange(AddressRange)`.
    pub fn add_range(&self, range: &AddressRange) {
        self.addr_set.borrow_mut().add_range_object(range);
    }

    /// Removes a range from this fragment's address set. Stands in for the package-private
    /// `FragmentDB.removeRange(AddressRange)`.
    pub fn remove_range(&self, range: &AddressRange) {
        self.addr_set.borrow_mut().delete_range_object(range);
    }

    /// Snapshot of this fragment's current (possibly stale, if not yet refreshed) DB record.
    pub fn record(&self) -> DBRecord {
        self.record.borrow().clone()
    }
}

impl DbObject for FragmentDbImpl {
    fn state(&self) -> &DbObjectState {
        &self.state
    }

    fn refresh(&self, record: Option<&DBRecord>) -> bool {
        let key = self.get_key();
        let mut mgr = self.module_mgr.borrow_mut();
        let rec = match record {
            Some(r) => Some(r.clone()),
            None => match mgr.get_fragment_adapter().get_fragment_record(key) {
                Ok(r) => r,
                Err(e) => {
                    mgr.db_error(e);
                    return false;
                }
            },
        };
        match rec {
            Some(r) => {
                *self.record.borrow_mut() = r;
                *self.addr_set.borrow_mut() = mgr.get_fragment_address_set(key);
                true
            }
            None => false,
        }
    }
}

impl Group for FragmentDbImpl {
    fn get_comment(&self) -> Option<String> {
        self.refresh_if_needed();
        self.record
            .borrow()
            .get_string(FRAGMENT_COMMENTS_COL)
            .map(|s| s.to_string())
    }

    fn set_comment(&mut self, comment: Option<&str>) {
        if self.check_deleted().is_err() {
            // TODO(port): `checkDeleted()` throws an unchecked `ConcurrentModificationException`
            // in Java; there is no unchecked-exception channel to raise across this `&mut self`
            // boundary, so a deleted fragment silently no-ops instead.
            return;
        }
        let old = self
            .record
            .borrow()
            .get_string(FRAGMENT_COMMENTS_COL)
            .map(|s| s.to_string());
        if old.as_deref() == comment {
            return;
        }
        self.record
            .borrow_mut()
            .set_string(FRAGMENT_COMMENTS_COL, comment.map(|s| s.to_string()));
        let key = self.get_key();
        let write_result = {
            let mut mgr = self.module_mgr.borrow_mut();
            let rec = self.record.borrow().clone();
            mgr.get_fragment_adapter().update_fragment_record(&rec)
        };
        match write_result {
            Ok(()) => {
                let _ = key;
                self.module_mgr
                    .borrow_mut()
                    .comments_changed(old.as_deref(), &*self);
            }
            Err(e) => self.module_mgr.borrow().db_error(e),
        }
    }

    fn get_name(&self) -> String {
        self.refresh_if_needed();
        self.record
            .borrow()
            .get_string(FRAGMENT_NAME_COL)
            .unwrap_or_default()
            .to_string()
    }

    fn set_name(&mut self, name: &str) -> Result<(), DuplicateNameException> {
        self.refresh_if_needed();
        let key = self.get_key();
        let existing = {
            let mut mgr = self.module_mgr.borrow_mut();
            match mgr.get_fragment_adapter().get_fragment_record_by_name(name) {
                Ok(r) => r,
                Err(e) => {
                    mgr.db_error(e);
                    return Ok(());
                }
            }
        };
        if let Some(r) = existing {
            if key != r.get_key().get_long_value() {
                return Err(DuplicateNameException::with_message(format!(
                    "{name} already exists"
                )));
            }
            return Ok(()); // no changes
        }
        let old_name = self
            .record
            .borrow()
            .get_string(FRAGMENT_NAME_COL)
            .unwrap_or_default()
            .to_string();
        self.record
            .borrow_mut()
            .set_string(FRAGMENT_NAME_COL, Some(name.to_string()));
        let write_result = {
            let mut mgr = self.module_mgr.borrow_mut();
            let rec = self.record.borrow().clone();
            mgr.get_fragment_adapter().update_fragment_record(&rec)
        };
        match write_result {
            Ok(()) => {
                self.module_mgr
                    .borrow_mut()
                    .name_changed(&old_name, &*self);
                Ok(())
            }
            Err(e) => {
                self.module_mgr.borrow().db_error(e);
                Ok(())
            }
        }
    }

    fn contains(&self, code_unit: &dyn CodeUnit) -> bool {
        self.refresh_if_needed();
        self.addr_set.borrow().contains(&code_unit.get_min_address())
    }

    fn get_num_parents(&self) -> i32 {
        self.refresh_if_needed();
        let key = self.get_key();
        let mut mgr = self.module_mgr.borrow_mut();
        match mgr
            .get_parent_child_adapter()
            .get_parent_child_keys(-key, CHILD_ID_COL)
        {
            Ok(keys) => keys.len() as i32,
            Err(e) => {
                mgr.db_error(e);
                0
            }
        }
    }

    fn get_parents(&self) -> Vec<Box<dyn Group>> {
        self.refresh_if_needed();
        let key = self.get_key();
        let parents = self.module_mgr.borrow().get_parents(-key);
        parents.into_iter().map(|m| m as Box<dyn Group>).collect()
    }

    fn get_parent_names(&self) -> Vec<String> {
        self.refresh_if_needed();
        let key = self.get_key();
        self.module_mgr.borrow().get_parent_names(-key)
    }

    fn get_tree_name(&self) -> String {
        self.module_mgr.borrow().get_tree_name()
    }

    fn is_deleted(&self) -> bool {
        // Mirrors `DbObject.isDeleted(Lock)`/`validate(Lock)` without the `Lock` critical
        // section -- see the module-level note on why this port omits it.
        if self.state().is_deleted_flag() {
            return true;
        }
        if self.is_valid() {
            return false;
        }
        !self.refresh_if_needed()
    }

    fn get_min_address(&self) -> Option<Address> {
        self.refresh_if_needed();
        self.addr_set.borrow().min_address()
    }

    fn get_max_address(&self) -> Option<Address> {
        self.refresh_if_needed();
        self.addr_set.borrow().max_address()
    }

    fn as_program_fragment(&self) -> Option<&dyn ProgramFragment> {
        Some(self)
    }
}

impl AddressSetView for FragmentDbImpl {
    fn contains(&self, address: &Address) -> bool {
        self.refresh_if_needed();
        self.addr_set.borrow().contains(address)
    }

    fn contains_range(&self, start: &Address, end: &Address) -> bool {
        self.refresh_if_needed();
        self.addr_set.borrow().contains_range(start, end)
    }

    fn contains_set(&self, set: &dyn AddressSetView) -> bool {
        self.refresh_if_needed();
        self.addr_set.borrow().contains_set(set)
    }

    fn is_empty(&self) -> bool {
        self.refresh_if_needed();
        self.addr_set.borrow().is_empty()
    }

    fn min_address(&self) -> Option<Address> {
        self.refresh_if_needed();
        self.addr_set.borrow().min_address()
    }

    fn max_address(&self) -> Option<Address> {
        self.refresh_if_needed();
        self.addr_set.borrow().max_address()
    }

    fn num_address_ranges(&self) -> usize {
        self.refresh_if_needed();
        self.addr_set.borrow().num_address_ranges()
    }

    fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
        self.refresh_if_needed();
        self.addr_set.borrow().address_ranges()
    }

    fn address_ranges_ordered(&self, forward: bool) -> Box<dyn AddressRangeIterator> {
        self.refresh_if_needed();
        self.addr_set.borrow().address_ranges_ordered(forward)
    }

    fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn AddressRangeIterator> {
        self.refresh_if_needed();
        self.addr_set.borrow().address_ranges_from(start, forward)
    }

    fn num_addresses(&self) -> u64 {
        self.refresh_if_needed();
        self.addr_set.borrow().num_addresses()
    }

    fn addresses(&self, forward: bool) -> BoxedAddressIterator {
        self.refresh_if_needed();
        AddressSetView::addresses(&*self.addr_set.borrow(), forward)
    }

    fn addresses_from(&self, start: &Address, forward: bool) -> BoxedAddressIterator {
        self.refresh_if_needed();
        self.addr_set.borrow().addresses_from(start, forward)
    }

    fn intersects_set(&self, set: &dyn AddressSetView) -> bool {
        self.refresh_if_needed();
        self.addr_set.borrow().intersects_set(set)
    }

    fn intersects_range(&self, start: &Address, end: &Address) -> bool {
        self.refresh_if_needed();
        self.addr_set.borrow().intersects_range(start, end)
    }

    fn intersect(&self, set: &dyn AddressSetView) -> AddressSet {
        self.refresh_if_needed();
        self.addr_set.borrow().intersect(set)
    }

    fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet {
        self.refresh_if_needed();
        self.addr_set.borrow().intersect_range(start, end)
    }

    fn union(&self, set: &dyn AddressSetView) -> AddressSet {
        self.refresh_if_needed();
        self.addr_set.borrow().union(set)
    }

    fn subtract(&self, set: &dyn AddressSetView) -> AddressSet {
        self.refresh_if_needed();
        self.addr_set.borrow().subtract(set)
    }

    fn xor(&self, set: &dyn AddressSetView) -> AddressSet {
        self.refresh_if_needed();
        self.addr_set.borrow().xor(set)
    }

    fn has_same_addresses(&self, set: &dyn AddressSetView) -> bool {
        self.refresh_if_needed();
        self.addr_set.borrow().has_same_addresses(set)
    }

    fn first_range(&self) -> Option<AddressRange> {
        self.refresh_if_needed();
        self.addr_set.borrow().first_range()
    }

    fn last_range(&self) -> Option<AddressRange> {
        self.refresh_if_needed();
        self.addr_set.borrow().last_range()
    }

    fn range_containing(&self, address: &Address) -> Option<AddressRange> {
        self.refresh_if_needed();
        self.addr_set.borrow().range_containing(address)
    }

    fn find_first_address_in_common(&self, set: &dyn AddressSetView) -> Option<Address> {
        self.refresh_if_needed();
        self.addr_set.borrow().find_first_address_in_common(set)
    }
}

impl ProgramFragment for FragmentDbImpl {
    fn get_code_units(&self) -> Box<dyn CodeUnitIterator> {
        self.refresh_if_needed();
        self.module_mgr.borrow().get_code_units(self)
    }

    fn move_code_units(&mut self, min: &Address, max: &Address) -> Result<(), NotFoundException> {
        if self.check_deleted().is_err() {
            // TODO(port): see the note in `set_comment` about `checkDeleted()`'s unchecked
            // exception.
            return Ok(());
        }
        let mut mgr = self.module_mgr.borrow_mut();
        mgr.move_code_units_to_fragment(self, min, max)
    }
}

impl FragmentDB for FragmentDbImpl {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::module::module_manager_test_support::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn test_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(test_space(), offset)
    }

    #[test]
    fn name_and_comment_round_trip() {
        let mgr = new_test_manager();
        let mut frag = new_fragment(&mgr, ".text", AddressSet::new());

        assert_eq!(frag.get_name(), ".text");
        assert_eq!(Group::get_comment(&frag), None);

        frag.set_comment(Some("hello"));
        assert_eq!(Group::get_comment(&frag), Some("hello".to_string()));

        frag.set_name("renamed").expect("rename should succeed");
        assert_eq!(frag.get_name(), "renamed");

        // Renaming to a name already in use by a different fragment must fail.
        let _other = new_fragment(&mgr, "taken", AddressSet::new());
        assert!(frag.set_name("taken").is_err());
    }

    #[test]
    fn address_set_delegation() {
        let mgr = new_test_manager();
        let mut set = AddressSet::new();
        set.add_range(&addr(0), &addr(10));
        let frag = new_fragment(&mgr, ".data", set);

        assert!(!frag.is_empty());
        assert!(AddressSetView::contains(&frag, &addr(5)));
        assert!(!AddressSetView::contains(&frag, &addr(20)));
        assert_eq!(frag.min_address(), Some(addr(0)));
        assert_eq!(frag.max_address(), Some(addr(10)));
        assert_eq!(frag.num_address_ranges(), 1);

        frag.add_range(&AddressRange::new(addr(20), addr(30)));
        assert_eq!(frag.num_address_ranges(), 2);
        assert!(AddressSetView::contains(&frag, &addr(25)));

        frag.remove_range(&AddressRange::new(addr(20), addr(30)));
        assert!(!AddressSetView::contains(&frag, &addr(25)));
    }

    #[test]
    fn as_program_fragment_returns_self() {
        let mgr = new_test_manager();
        let frag = new_fragment(&mgr, ".bss", AddressSet::new());
        let group: &dyn Group = &frag;
        assert!(group.as_program_fragment().is_some());
        assert!(group.as_program_module().is_none());
    }

    #[test]
    fn is_deleted_reflects_refresh_failure() {
        let mgr = new_test_manager();
        let frag = new_fragment(&mgr, ".rsrc", AddressSet::new());
        let key = frag.get_key();

        // Freshly constructed and never invalidated: no refresh has happened yet, so the object
        // reports itself as not deleted purely from its own cached state.
        assert!(!Group::is_deleted(&frag));

        // Force a refresh (mirrors a cache invalidation) after removing the backing row: the
        // refresh fails to find a record, so the object is marked deleted, exactly as
        // `DbObject.doRefresh` does in Java.
        remove_fragment_row(&mgr, key);
        frag.set_invalid();
        assert!(Group::is_deleted(&frag));
    }
}
