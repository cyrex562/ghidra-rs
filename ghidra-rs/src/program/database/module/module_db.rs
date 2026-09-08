//! Port of `ghidra.program.database.module.ModuleDB`.
//!
//! The Java type is a package-private, concrete `DbObject` implementing `ProgramModule`. Unlike
//! [`FragmentDbImpl`](super::fragment_db::FragmentDbImpl), it does not cache its children: every
//! child-facing method re-reads the parent/child table (through `ModuleManager`'s
//! [`ParentChildDBAdapter`]) and resolves each child (module or fragment, by the sign of the
//! stored ID) through the manager on demand. See [`fragment_db`](super::fragment_db)'s module
//! docs for the interior-mutability/locking/downcasting design shared by both types -- it is not
//! repeated here.
//!
//! # `get_address_set` and `unsafe`
//!
//! [`ProgramModule::get_address_set`] returns `&dyn AddressSetView`, tied to `&self`'s lifetime,
//! mirroring Java's `AddressSetView getAddressSet()`. In Java this is trivial: the method builds
//! a brand new `AddressSet` on every call and returns it as an object reference: garbage
//! collection means nobody worries about how long it lives. Rust has no such luxury -- a `&self`
//! method cannot return a reference to a value it just computed locally. This port resolves that
//! with a `RefCell<AddressSet>` cache field, recomputed on every call, exposed through a raw
//! pointer read (see that method's doc comment for the safety argument). Everything else that
//! only needs the *value* (not a `&dyn AddressSetView`) -- [`get_min_address`]/[`get_max_address`]
//! on both [`Group`] and [`ProgramModule`] -- sidesteps the issue entirely by calling the private
//! [`ModuleDbImpl::compute_address_set`] helper directly and reading `Option<Address>` out of the
//! owned result, needing no `unsafe` at all.
//!
//! [`get_min_address`]: crate::program::model::listing::group::Group::get_min_address
//! [`get_max_address`]: crate::program::model::listing::group::Group::get_max_address

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::io;
use std::rc::Rc;

use crate::framework::db::DBRecord;
use crate::program::database::db_object::{DbObject, DbObjectState};
use crate::program::database::module::fragment_db::FragmentDbImpl;
use crate::program::database::module::module_manager::ModuleManager;
use crate::program::database::module::{
    CHILD_ID_COL, MODULE_CHILD_COUNT_COL, MODULE_COMMENTS_COL, MODULE_NAME_COL, ORDER_COL,
    PARENT_ID_COL,
};
use crate::program::model::address::{Address, AddressSet, AddressSetView};
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::{
    AddModuleError, CircularDependencyException, DuplicateGroupException, Group, ProgramFragment,
    ProgramModule,
};
use crate::util::exception::{DuplicateNameException, NotEmptyException, NotFoundException};

/// Marker trait implemented by [`ModuleDbImpl`], the concrete, DB-backed `ProgramModule` this
/// crate's [`ModuleManager`] hands out. See [`FragmentDB`](super::fragment_db::FragmentDB) (its
/// exact counterpart) for why this stays a separate trait rather than naming the concrete struct
/// directly in [`ModuleManager`].
pub trait ModuleDB: ProgramModule {}

/// Database implementation of [`ProgramModule`].
///
/// Port of `ghidra.program.database.module.ModuleDB`. See the module docs.
pub struct ModuleDbImpl {
    state: DbObjectState,
    record: RefCell<DBRecord>,
    module_mgr: Rc<RefCell<dyn ModuleManager>>,
    /// Cached child count, mirroring the Java field of the same name (kept so callers don't have
    /// to hit the database just to size the children array).
    child_count: Cell<i32>,
    /// Backing storage for [`ProgramModule::get_address_set`]'s `&dyn AddressSetView` return
    /// value. See the module docs.
    address_set_cache: RefCell<AddressSet>,
}

impl ModuleDbImpl {
    /// Constructs a module view over `record`, backed by `module_mgr`.
    ///
    /// Port of `ModuleDB(ModuleManager, DBRecord)`.
    pub fn new(module_mgr: Rc<RefCell<dyn ModuleManager>>, record: DBRecord) -> Self {
        let key = record.get_key().get_long_value();
        let child_count = record.get_int(MODULE_CHILD_COUNT_COL).unwrap_or(0);
        ModuleDbImpl {
            state: DbObjectState::new(key),
            record: RefCell::new(record),
            module_mgr,
            child_count: Cell::new(child_count),
            address_set_cache: RefCell::new(AddressSet::new()),
        }
    }

    /// Gets the manager that owns this module. Stands in for the package-private (implicit, via
    /// the `moduleMgr` field) manager access other `ghidra.program.database.module` types use.
    pub fn module_manager_handle(&self) -> &Rc<RefCell<dyn ModuleManager>> {
        &self.module_mgr
    }

    /// Snapshot of this module's current (possibly stale, if not yet refreshed) DB record.
    pub fn record(&self) -> DBRecord {
        self.record.borrow().clone()
    }

    /// Gets sorted (by [`ORDER_COL`]) parent/child records for the module identified by `key`.
    ///
    /// Stands in for the private `ModuleDB.getParentChildRecords()`, generalized to operate on
    /// any module key (needed by [`find_first_address`]/[`find_last_address`]-equivalents, which
    /// in Java recurse over `ModuleDB` instances directly; here everything past the first level
    /// goes back through [`get_children`](ProgramModule::get_children) instead -- see the module
    /// docs). Java maintains sort order via `Collections.binarySearch` insertion; this port just
    /// collects then sorts, which is behaviorally identical and simpler.
    fn get_parent_child_records(mgr: &mut dyn ModuleManager, key: i64) -> io::Result<Vec<DBRecord>> {
        let keys = mgr.get_parent_child_adapter().get_parent_child_keys(key, PARENT_ID_COL)?;
        let mut list = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some(rec) = mgr
                .get_parent_child_adapter()
                .get_parent_child_record_by_key(k.get_long_value())?
            {
                list.push(rec);
            }
        }
        list.sort_by_key(|r| r.get_int(ORDER_COL).unwrap_or(0));
        Ok(list)
    }

    /// Renumbers `list`'s `ORDER_COL` values to match their position, writing back only the
    /// records whose stored order actually changed. Stands in for the private
    /// `ModuleDB.updateChildOrder(List<DBRecord>)`.
    fn update_child_order(mgr: &mut dyn ModuleManager, list: &[DBRecord]) -> io::Result<()> {
        for (i, rec) in list.iter().enumerate() {
            if rec.get_int(ORDER_COL) != Some(i as i32) {
                let mut updated = rec.clone();
                updated.set_int(ORDER_COL, i as i32);
                mgr.get_parent_child_adapter().update_parent_child_record(&updated)?;
            }
        }
        Ok(())
    }

    /// Stands in for the private `ModuleDB.resetChildOrder()`.
    fn reset_child_order(&self, mgr: &mut dyn ModuleManager) -> io::Result<()> {
        let key = self.get_key();
        let list = Self::get_parent_child_records(mgr, key)?;
        Self::update_child_order(mgr, &list)
    }

    /// Stands in for the private `ModuleDB.updateOrderField(DBRecord, int)`.
    fn update_order_field(mgr: &mut dyn ModuleManager, pc_rec: &DBRecord, order_value: i32) -> io::Result<()> {
        let mut rec = pc_rec.clone();
        rec.set_int(ORDER_COL, order_value);
        mgr.get_parent_child_adapter().update_parent_child_record(&rec)
    }

    /// Increments (or decrements) this module's cached child count and persists it. Stands in
    /// for the private `ModuleDB.updateChildCount(int)`.
    fn update_child_count(&self, mgr: &mut dyn ModuleManager, change: i32) -> io::Result<()> {
        let new_count = self.child_count.get() + change;
        self.child_count.set(new_count);
        self.record.borrow_mut().set_int(MODULE_CHILD_COUNT_COL, new_count);
        let rec = self.record.borrow().clone();
        mgr.get_module_adapter().update_module_record(&rec)
    }

    /// Whether this module has a parent/child row naming `child_id` as a direct child. Stands in
    /// for the private `ModuleDB.contains(long)`.
    fn contains_child_id(&self, child_id: i64) -> bool {
        let key = self.get_key();
        let mut mgr = self.module_mgr.borrow_mut();
        match mgr.get_parent_child_adapter().get_parent_child_record(key, child_id) {
            Ok(rec) => rec.is_some(),
            Err(e) => {
                mgr.db_error(e);
                false
            }
        }
    }

    /// Removes the parent/child row for `child_id`, optionally also deleting the child's own
    /// record, and renumbers this module's remaining children. Stands in for the private
    /// `ModuleDB.removeChild(long, DBRecord, boolean, boolean)`.
    fn remove_child_record(
        &self,
        mgr: &mut dyn ModuleManager,
        child_id: i64,
        pc_rec: &DBRecord,
        is_fragment: bool,
        delete_child: bool,
    ) -> io::Result<bool> {
        mgr.get_parent_child_adapter()
            .remove_parent_child_record(pc_rec.get_key().get_long_value())?;
        self.update_child_count(mgr, -1)?;

        let (name, success) = if is_fragment {
            let frag_rec = mgr
                .get_fragment_adapter()
                .get_fragment_record(child_id)?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "fragment record vanished"))?;
            let name = frag_rec
                .get_string(crate::program::database::module::FRAGMENT_NAME_COL)
                .unwrap_or_default()
                .to_string();
            let success = if delete_child {
                mgr.get_fragment_adapter().remove_fragment_record(child_id)?
            } else {
                true
            };
            (name, success)
        } else {
            let mrec = mgr
                .get_module_adapter()
                .get_module_record(child_id)?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "module record vanished"))?;
            let name = mrec.get_string(MODULE_NAME_COL).unwrap_or_default().to_string();
            let success = if delete_child {
                mgr.get_module_adapter().remove_module_record(child_id)?
            } else {
                true
            };
            (name, success)
        };

        if success {
            self.reset_child_order(mgr)?;
            mgr.group_removed(self, child_id, &name, is_fragment, delete_child);
        }
        Ok(success)
    }

    /// Stands in for the private `ModuleDB.removeModuleRecord(String)`; returns `Ok(None)` when
    /// there is no module with that name, or no parent/child row linking it to this module
    /// (mirroring Java's early `return false` in both cases), `Ok(Some(_))` on a definite
    /// outcome, and `Err` for an actual `NotEmptyException`.
    fn remove_module_record(&self, name: &str) -> Result<Option<bool>, NotEmptyException> {
        let key = self.get_key();
        // First pass: look everything up and decide whether this is a not-empty error, without
        // holding the manager borrow across the notification/mutation call below.
        let plan = {
            let mut mgr = self.module_mgr.borrow_mut();
            let mrec = match mgr.get_module_adapter().get_module_record_by_name(name) {
                Ok(Some(r)) => r,
                Ok(None) => return Ok(None),
                Err(e) => {
                    mgr.db_error(e);
                    return Ok(None);
                }
            };
            let child_id = mrec.get_key().get_long_value();
            let pc_rec = match mgr.get_parent_child_adapter().get_parent_child_record(key, child_id) {
                Ok(Some(r)) => r,
                Ok(None) => return Ok(None),
                Err(e) => {
                    mgr.db_error(e);
                    return Ok(None);
                }
            };
            let sibling_keys = match mgr
                .get_parent_child_adapter()
                .get_parent_child_keys(child_id, CHILD_ID_COL)
            {
                Ok(k) => k,
                Err(e) => {
                    mgr.db_error(e);
                    return Ok(None);
                }
            };
            let delete_child = sibling_keys.len() == 1;
            if delete_child {
                let num_children = mgr
                    .get_module_db(child_id)
                    .map(|m| m.get_num_children())
                    .unwrap_or(0);
                if num_children > 0 {
                    let self_name = self.record.borrow().get_string(MODULE_NAME_COL).unwrap_or_default().to_string();
                    return Err(NotEmptyException::with_message(format!("{self_name} is not empty")));
                }
            }
            (child_id, pc_rec, delete_child)
        };
        let (child_id, pc_rec, delete_child) = plan;
        let mut mgr = self.module_mgr.borrow_mut();
        match self.remove_child_record(&mut *mgr, child_id, &pc_rec, false, delete_child) {
            Ok(success) => Ok(Some(success)),
            Err(e) => {
                mgr.db_error(e);
                Ok(Some(false))
            }
        }
    }

    /// Computes the union of every descendant fragment's addresses. Stands in for
    /// `ModuleDB.getAddressSet()`'s body; factored out so [`get_min_address`]/[`get_max_address`]
    /// (which only need the resulting *value*, not a `&dyn AddressSetView`) can call it directly
    /// without going through the `unsafe` cache in [`ProgramModule::get_address_set`].
    fn compute_address_set(&self) -> AddressSet {
        let mut set = AddressSet::new();
        for child in ProgramModule::get_children(self) {
            if let Some(frag) = child.as_program_fragment() {
                set.add_set(frag);
            } else if let Some(m) = child.as_program_module() {
                set.add_set(m.get_address_set());
            }
        }
        set
    }
}

impl DbObject for ModuleDbImpl {
    fn state(&self) -> &DbObjectState {
        &self.state
    }

    fn refresh(&self, record: Option<&DBRecord>) -> bool {
        let key = self.get_key();
        let mut mgr = self.module_mgr.borrow_mut();
        let rec = match record {
            Some(r) => Some(r.clone()),
            None => match mgr.get_module_adapter().get_module_record(key) {
                Ok(r) => r,
                Err(e) => {
                    mgr.db_error(e);
                    return false;
                }
            },
        };
        match rec {
            Some(r) => {
                self.child_count.set(r.get_int(MODULE_CHILD_COUNT_COL).unwrap_or(0));
                *self.record.borrow_mut() = r;
                true
            }
            None => false,
        }
    }
}

impl Group for ModuleDbImpl {
    fn get_comment(&self) -> Option<String> {
        self.refresh_if_needed();
        self.record.borrow().get_string(MODULE_COMMENTS_COL).map(|s| s.to_string())
    }

    fn set_comment(&mut self, comment: Option<&str>) {
        if self.check_deleted().is_err() {
            // TODO(port): see `FragmentDbImpl::set_comment`'s note on `checkDeleted()`'s
            // unchecked exception; mirrored here as a silent no-op.
            return;
        }
        let old = self.record.borrow().get_string(MODULE_COMMENTS_COL).map(|s| s.to_string());
        if old.as_deref() == comment {
            return;
        }
        self.record
            .borrow_mut()
            .set_string(MODULE_COMMENTS_COL, comment.map(|s| s.to_string()));
        let write_result = {
            let mut mgr = self.module_mgr.borrow_mut();
            let rec = self.record.borrow().clone();
            mgr.get_module_adapter().update_module_record(&rec)
        };
        match write_result {
            Ok(()) => {
                self.module_mgr.borrow_mut().comments_changed(old.as_deref(), &*self);
            }
            Err(e) => self.module_mgr.borrow().db_error(e),
        }
    }

    fn get_name(&self) -> String {
        self.refresh_if_needed();
        self.record.borrow().get_string(MODULE_NAME_COL).unwrap_or_default().to_string()
    }

    fn set_name(&mut self, name: &str) -> Result<(), DuplicateNameException> {
        if self.check_deleted().is_err() {
            return Ok(());
        }
        let key = self.get_key();
        if key == crate::program::database::module::module_manager::ROOT_MODULE_ID {
            // TODO(port): Java delegates to `moduleMgr.getProgram().setName(name)`, which is
            // expected to loop back through `ModuleManager.setProgramName` to update the root
            // module's own record from the program-name change. The ported `Program` trait
            // exposes no `set_name` setter (only `get_name`), so that call cannot be made here;
            // renaming the root module via this path is therefore a no-op until `Program` grows
            // a setter.
            return Ok(());
        }
        let existing = {
            let mut mgr = self.module_mgr.borrow_mut();
            match mgr.get_module_adapter().get_module_record_by_name(name) {
                Ok(r) => r,
                Err(e) => {
                    mgr.db_error(e);
                    return Ok(());
                }
            }
        };
        if let Some(r) = existing {
            if key != r.get_key().get_long_value() {
                return Err(DuplicateNameException::with_message(format!("{name} already exists")));
            }
            return Ok(()); // no changes
        }
        let frag_dup = {
            let mut mgr = self.module_mgr.borrow_mut();
            match mgr.get_fragment_adapter().get_fragment_record_by_name(name) {
                Ok(r) => r,
                Err(e) => {
                    mgr.db_error(e);
                    return Ok(());
                }
            }
        };
        if frag_dup.is_some() {
            return Err(DuplicateNameException::with_message(format!("{name} already exists")));
        }
        let old_name = self.record.borrow().get_string(MODULE_NAME_COL).unwrap_or_default().to_string();
        self.record.borrow_mut().set_string(MODULE_NAME_COL, Some(name.to_string()));
        let write_result = {
            let mut mgr = self.module_mgr.borrow_mut();
            let rec = self.record.borrow().clone();
            mgr.get_module_adapter().update_module_record(&rec)
        };
        match write_result {
            Ok(()) => {
                self.module_mgr.borrow_mut().name_changed(&old_name, &*self);
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
        let frag = self.module_mgr.borrow().get_fragment_containing(code_unit);
        match frag {
            Some(f) => {
                let frag_ref: &dyn ProgramFragment = f.as_ref();
                ProgramModule::contains_fragment(self, frag_ref)
            }
            None => false,
        }
    }

    fn get_num_parents(&self) -> i32 {
        self.refresh_if_needed();
        let key = self.get_key();
        let mut mgr = self.module_mgr.borrow_mut();
        match mgr.get_parent_child_adapter().get_parent_child_keys(key, CHILD_ID_COL) {
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
        let parents = self.module_mgr.borrow().get_parents(key);
        parents.into_iter().map(|m| m as Box<dyn Group>).collect()
    }

    fn get_parent_names(&self) -> Vec<String> {
        self.refresh_if_needed();
        let key = self.get_key();
        self.module_mgr.borrow().get_parent_names(key)
    }

    fn get_tree_name(&self) -> String {
        self.module_mgr.borrow().get_tree_name()
    }

    fn is_deleted(&self) -> bool {
        // See `FragmentDbImpl::is_deleted` for why this doesn't go through `DbObject::is_deleted`
        // (which needs an actual `&ReentrantLock`).
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
        self.compute_address_set().min_address()
    }

    fn get_max_address(&self) -> Option<Address> {
        self.refresh_if_needed();
        self.compute_address_set().max_address()
    }

    fn as_program_module(&self) -> Option<&dyn ProgramModule> {
        Some(self)
    }
}

impl ProgramModule for ModuleDbImpl {
    fn contains_fragment(&self, fragment: &dyn ProgramFragment) -> bool {
        let any: &dyn Any = fragment;
        let Some(frag) = any.downcast_ref::<FragmentDbImpl>() else {
            return false;
        };
        if !Rc::ptr_eq(&self.module_mgr, frag.module_manager_handle()) {
            return false;
        }
        self.contains_child_id(-frag.get_key())
    }

    fn contains_module(&self, module: &dyn ProgramModule) -> bool {
        let any: &dyn Any = module;
        let Some(m) = any.downcast_ref::<ModuleDbImpl>() else {
            return false;
        };
        if !Rc::ptr_eq(&self.module_mgr, &m.module_mgr) {
            return false;
        }
        self.contains_child_id(m.get_key())
    }

    fn get_num_children(&self) -> i32 {
        self.refresh_if_needed();
        self.child_count.get()
    }

    fn get_children(&self) -> Vec<Box<dyn Group>> {
        self.refresh_if_needed();
        let key = self.get_key();
        let expected_count = self.child_count.get();
        let mut mgr = self.module_mgr.borrow_mut();
        let list = match Self::get_parent_child_records(&mut *mgr, key) {
            Ok(l) => l,
            Err(e) => {
                mgr.db_error(e);
                return Vec::new();
            }
        };
        if list.len() as i32 != expected_count {
            let name = self.record.borrow().get_string(MODULE_NAME_COL).unwrap_or_default().to_string();
            mgr.db_error(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Inconsistent module child count ({} vs. {}): {name}",
                    list.len(),
                    expected_count
                ),
            ));
            return Vec::new();
        }
        let mut kids: Vec<Box<dyn Group>> = Vec::with_capacity(list.len());
        for rec in list {
            let child_id = rec.get_long(CHILD_ID_COL).unwrap_or(0);
            if child_id < 0 {
                if let Some(frag) = mgr.get_fragment_db(-child_id) {
                    kids.push(frag as Box<dyn Group>);
                }
            } else if let Some(m) = mgr.get_module_db(child_id) {
                kids.push(m as Box<dyn Group>);
            }
        }
        kids
    }

    fn get_index(&self, name: &str) -> i32 {
        self.refresh_if_needed();
        let key = self.get_key();
        let mut mgr = self.module_mgr.borrow_mut();
        let pc_rec = match mgr.get_fragment_adapter().get_fragment_record_by_name(name) {
            Ok(Some(frag_rec)) => mgr
                .get_parent_child_adapter()
                .get_parent_child_record(key, -frag_rec.get_key().get_long_value())
                .ok()
                .flatten(),
            Ok(None) => match mgr.get_module_adapter().get_module_record_by_name(name) {
                Ok(Some(mod_rec)) => mgr
                    .get_parent_child_adapter()
                    .get_parent_child_record(key, mod_rec.get_key().get_long_value())
                    .ok()
                    .flatten(),
                _ => None,
            },
            Err(_) => None,
        };
        pc_rec.and_then(|r| r.get_int(ORDER_COL)).unwrap_or(-1)
    }

    fn add_module(&mut self, module: Box<dyn ProgramModule>) -> Result<(), AddModuleError> {
        if self.check_deleted().is_err() {
            return Ok(());
        }
        let any: Box<dyn Any> = module;
        let module_db = match any.downcast::<ModuleDbImpl>() {
            Ok(m) => m,
            // TODO(port): Java throws an unchecked `ClassCastException` for a foreign
            // `ProgramModule` implementation; mirrored as a silent no-op.
            Err(_) => return Ok(()),
        };
        let module_id = module_db.get_key();
        let key = self.get_key();

        let duplicate = {
            let mut mgr = self.module_mgr.borrow_mut();
            match mgr.get_parent_child_adapter().get_parent_child_record(key, module_id) {
                Ok(rec) => rec.is_some(),
                Err(e) => {
                    mgr.db_error(e);
                    return Ok(());
                }
            }
        };
        if duplicate {
            return Err(DuplicateGroupException::new(format!(
                "{} already exists a child of {}",
                module_db.get_name(),
                self.get_name()
            ))
            .into());
        }

        let is_descendant = {
            let mgr = self.module_mgr.borrow();
            match mgr.is_descendant(key, module_id) {
                Ok(v) => v,
                Err(e) => {
                    mgr.db_error(e);
                    return Ok(());
                }
            }
        };
        if is_descendant {
            return Err(CircularDependencyException::new(format!(
                "{} is already a descendant of {}",
                self.get_name(),
                module_db.get_name()
            ))
            .into());
        }

        let result: io::Result<()> = (|| {
            let mut mgr = self.module_mgr.borrow_mut();
            let pc_rec = mgr.get_parent_child_adapter().add_parent_child_record(key, module_id)?;
            self.update_child_count(&mut *mgr, 1)?;
            Self::update_order_field(&mut *mgr, &pc_rec, self.child_count.get() - 1)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.module_mgr.borrow_mut().module_added(key, module_db.as_ref());
                Ok(())
            }
            Err(e) => {
                self.module_mgr.borrow().db_error(e);
                Ok(())
            }
        }
    }

    fn add_fragment(&mut self, fragment: Box<dyn ProgramFragment>) -> Result<(), DuplicateGroupException> {
        if self.check_deleted().is_err() {
            return Ok(());
        }
        let any: Box<dyn Any> = fragment;
        let frag = match any.downcast::<FragmentDbImpl>() {
            Ok(f) => f,
            // TODO(port): see `add_module`'s note on the unchecked `ClassCastException`.
            Err(_) => return Ok(()),
        };
        let frag_id = frag.get_key();
        let key = self.get_key();

        let duplicate = {
            let mut mgr = self.module_mgr.borrow_mut();
            match mgr.get_parent_child_adapter().get_parent_child_record(key, -frag_id) {
                Ok(rec) => rec.is_some(),
                Err(e) => {
                    mgr.db_error(e);
                    return Ok(());
                }
            }
        };
        if duplicate {
            return Err(DuplicateGroupException::new(format!(
                "{} already exists a child of {}",
                frag.get_name(),
                self.get_name()
            )));
        }

        let result: io::Result<()> = (|| {
            let mut mgr = self.module_mgr.borrow_mut();
            let pc_rec = mgr.get_parent_child_adapter().add_parent_child_record(key, -frag_id)?;
            self.update_child_count(&mut *mgr, 1)?;
            Self::update_order_field(&mut *mgr, &pc_rec, self.child_count.get() - 1)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.module_mgr.borrow_mut().fragment_added(key, frag.as_ref());
                Ok(())
            }
            Err(e) => {
                self.module_mgr.borrow().db_error(e);
                Ok(())
            }
        }
    }

    fn create_module(&mut self, module_name: &str) -> Result<Box<dyn ProgramModule>, DuplicateNameException> {
        if self.check_deleted().is_err() {
            return Err(DuplicateNameException::with_message("module has been deleted"));
        }
        let key = self.get_key();
        let dup = {
            let mut mgr = self.module_mgr.borrow_mut();
            let has_module = mgr
                .get_module_adapter()
                .get_module_record_by_name(module_name)
                .unwrap_or(None)
                .is_some();
            let has_fragment = mgr
                .get_fragment_adapter()
                .get_fragment_record_by_name(module_name)
                .unwrap_or(None)
                .is_some();
            has_module || has_fragment
        };
        if dup {
            return Err(DuplicateNameException::with_message(format!("{module_name} already exists")));
        }

        let outcome: io::Result<ModuleDbImpl> = (|| {
            let mut mgr = self.module_mgr.borrow_mut();
            let module_record = mgr.get_module_adapter().create_module_record(key, module_name)?;
            let pc_rec = mgr
                .get_parent_child_adapter()
                .add_parent_child_record(key, module_record.get_key().get_long_value())?;
            let module_db = ModuleDbImpl::new(self.module_mgr.clone(), module_record);
            self.update_child_count(&mut *mgr, 1)?;
            Self::update_order_field(&mut *mgr, &pc_rec, self.child_count.get() - 1)?;
            Ok(module_db)
        })();
        match outcome {
            Ok(module_db) => {
                self.module_mgr.borrow_mut().module_added(key, &module_db);
                Ok(Box::new(module_db))
            }
            Err(e) => {
                self.module_mgr.borrow().db_error(e);
                Err(DuplicateNameException::with_message("database error creating module"))
            }
        }
    }

    fn create_fragment(&mut self, fragment_name: &str) -> Result<Box<dyn ProgramFragment>, DuplicateNameException> {
        if self.check_deleted().is_err() {
            return Err(DuplicateNameException::with_message("module has been deleted"));
        }
        let key = self.get_key();
        let dup = {
            let mut mgr = self.module_mgr.borrow_mut();
            let has_module = mgr
                .get_module_adapter()
                .get_module_record_by_name(fragment_name)
                .unwrap_or(None)
                .is_some();
            let has_fragment = mgr
                .get_fragment_adapter()
                .get_fragment_record_by_name(fragment_name)
                .unwrap_or(None)
                .is_some();
            has_module || has_fragment
        };
        if dup {
            return Err(DuplicateNameException::with_message(format!("{fragment_name} already exists")));
        }

        let outcome: io::Result<FragmentDbImpl> = (|| {
            let mut mgr = self.module_mgr.borrow_mut();
            let fragment_record = mgr.get_fragment_adapter().create_fragment_record(key, fragment_name)?;
            let frag_key = fragment_record.get_key().get_long_value();
            let pc_rec = mgr.get_parent_child_adapter().add_parent_child_record(key, -frag_key)?;
            let frag_db = FragmentDbImpl::new(self.module_mgr.clone(), fragment_record, AddressSet::new());
            self.update_child_count(&mut *mgr, 1)?;
            Self::update_order_field(&mut *mgr, &pc_rec, self.child_count.get() - 1)?;
            Ok(frag_db)
        })();
        match outcome {
            Ok(frag_db) => {
                self.module_mgr.borrow_mut().fragment_added(key, &frag_db);
                Ok(Box::new(frag_db))
            }
            Err(e) => {
                self.module_mgr.borrow().db_error(e);
                Err(DuplicateNameException::with_message("database error creating fragment"))
            }
        }
    }

    fn reparent(&mut self, name: &str, old_parent: &mut dyn ProgramModule) -> Result<(), NotFoundException> {
        if self.check_deleted().is_err() {
            return Ok(());
        }
        let old_parent_name = old_parent.get_name();
        let key = self.get_key();

        // Resolve `name` to a child ID (negative for a fragment, positive for a module), mirroring
        // Java's `moduleMgr.getModule(name)` then `moduleMgr.getFragment(name)` fallback.
        enum Found {
            Module(i64),
            Fragment(i64),
        }
        let found = {
            let mgr = self.module_mgr.borrow();
            match mgr.get_module(name) {
                Ok(Some(m)) => {
                    let any: Box<dyn Any> = m;
                    match any.downcast::<ModuleDbImpl>() {
                        Ok(m) => Some(Found::Module(m.get_key())),
                        Err(_) => None,
                    }
                }
                Ok(None) => match mgr.get_fragment_by_name(name) {
                    Ok(Some(f)) => {
                        let any: Box<dyn Any> = f;
                        any.downcast::<FragmentDbImpl>().ok().map(|f| Found::Fragment(f.get_key()))
                    }
                    _ => None,
                },
                Err(_) => None,
            }
        };
        let Some(found) = found else {
            return Err(NotFoundException::with_message(format!(
                "{name} was not found as child of {}",
                self.get_name()
            )));
        };
        let child_id = match found {
            Found::Module(k) => k,
            Found::Fragment(k) => -k,
        };

        let any: &mut dyn Any = old_parent;
        let Some(old_module_db) = any.downcast_mut::<ModuleDbImpl>() else {
            // TODO(port): Java casts `oldParent` unconditionally (`(ModuleDB) oldParent`),
            // throwing an unchecked `ClassCastException` for a foreign implementation; mirrored
            // as a silent no-op.
            return Ok(());
        };
        let old_key = old_module_db.get_key();

        let result: io::Result<()> = (|| {
            let mut mgr = self.module_mgr.borrow_mut();
            let old_pc_rec = mgr
                .get_parent_child_adapter()
                .get_parent_child_record(old_key, child_id)?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "old parent/child record missing"))?;
            mgr.get_parent_child_adapter()
                .remove_parent_child_record(old_pc_rec.get_key().get_long_value())?;
            old_module_db.update_child_count(&mut *mgr, -1)?;

            let new_pc_rec = mgr.get_parent_child_adapter().add_parent_child_record(key, child_id)?;
            self.update_child_count(&mut *mgr, 1)?;
            Self::update_order_field(&mut *mgr, &new_pc_rec, self.child_count.get() - 1)?;

            old_module_db.reset_child_order(&mut *mgr)
        })();
        match result {
            Ok(()) => {
                let new_name = self.get_name();
                self.module_mgr.borrow_mut().child_reparented(old_module_db, &old_parent_name, &new_name);
                Ok(())
            }
            Err(e) => {
                self.module_mgr.borrow().db_error(e);
                Ok(())
            }
        }
    }

    fn move_child(&mut self, name: &str, index: i32) -> Result<(), NotFoundException> {
        if self.check_deleted().is_err() {
            return Ok(());
        }
        let key = self.get_key();
        let self_name = self.record.borrow().get_string(MODULE_NAME_COL).unwrap_or_default().to_string();

        enum MoveOutcome {
            NotFound,
            Moved { child_id: i64, is_fragment: bool },
        }

        let outcome: io::Result<MoveOutcome> = (|| {
            let mut mgr = self.module_mgr.borrow_mut();
            let mut list = Self::get_parent_child_records(&mut *mgr, key)?;
            let mut current: Option<(usize, i64)> = None;
            for (i, rec) in list.iter().enumerate() {
                let child_id = rec.get_long(CHILD_ID_COL).unwrap_or(0);
                let child_name = if child_id < 0 {
                    mgr.get_fragment_adapter()
                        .get_fragment_record(-child_id)?
                        .and_then(|r| {
                            r.get_string(crate::program::database::module::FRAGMENT_NAME_COL)
                                .map(|s| s.to_string())
                        })
                } else {
                    mgr.get_module_adapter()
                        .get_module_record(child_id)?
                        .and_then(|r| r.get_string(MODULE_NAME_COL).map(|s| s.to_string()))
                };
                if child_name.as_deref() == Some(name) {
                    current = Some((i, child_id));
                }
            }
            let Some((current_index, child_id)) = current else {
                return Ok(MoveOutcome::NotFound);
            };
            let pc_rec = list.remove(current_index);
            let insert_at = (index as usize).min(list.len());
            list.insert(insert_at, pc_rec);
            Self::update_child_order(&mut *mgr, &list)?;
            Ok(MoveOutcome::Moved { child_id, is_fragment: child_id < 0 })
        })();

        match outcome {
            Ok(MoveOutcome::NotFound) => Err(NotFoundException::with_message(format!(
                "{name} is not a child of {self_name}"
            ))),
            Ok(MoveOutcome::Moved { child_id, is_fragment }) => {
                let group: Option<Box<dyn Group>> = if is_fragment {
                    self.module_mgr.borrow().get_fragment_db(-child_id).map(|f| f as Box<dyn Group>)
                } else {
                    self.module_mgr.borrow().get_module_db(child_id).map(|m| m as Box<dyn Group>)
                };
                if let Some(group) = group {
                    self.module_mgr.borrow_mut().child_reordered(self, group.as_ref());
                }
                Ok(())
            }
            Err(e) => {
                self.module_mgr.borrow().db_error(e);
                Ok(())
            }
        }
    }

    fn remove_child(&mut self, name: &str) -> Result<bool, NotEmptyException> {
        if self.check_deleted().is_err() {
            return Ok(false);
        }
        let key = self.get_key();

        // Mirrors Java's `fragmentAdapter.getFragmentRecord(name)` lookup: if `name` doesn't name
        // a fragment at all, fall straight through to the module path.
        let frag_rec = {
            let mut mgr = self.module_mgr.borrow_mut();
            match mgr.get_fragment_adapter().get_fragment_record_by_name(name) {
                Ok(r) => r,
                Err(e) => {
                    mgr.db_error(e);
                    return Ok(false);
                }
            }
        };
        let Some(frag_rec) = frag_rec else {
            return self.remove_module_record(name).map(|o| o.unwrap_or(false));
        };
        let child_id = frag_rec.get_key().get_long_value();

        let pc_rec = {
            let mut mgr = self.module_mgr.borrow_mut();
            match mgr.get_parent_child_adapter().get_parent_child_record(key, -child_id) {
                Ok(r) => r,
                Err(e) => {
                    mgr.db_error(e);
                    return Ok(false);
                }
            }
        };
        let Some(pc_rec) = pc_rec else {
            // This name is a fragment, but not a *child of this module* -- Java falls through to
            // treat it as a module name instead (which will simply come up empty).
            return self.remove_module_record(name).map(|o| o.unwrap_or(false));
        };

        let sibling_keys = {
            let mut mgr = self.module_mgr.borrow_mut();
            match mgr.get_parent_child_adapter().get_parent_child_keys(-child_id, CHILD_ID_COL) {
                Ok(k) => k,
                Err(e) => {
                    mgr.db_error(e);
                    return Ok(false);
                }
            }
        };
        let delete_child = sibling_keys.len() == 1;
        if delete_child {
            let is_empty = {
                let mgr = self.module_mgr.borrow();
                mgr.get_fragment_db(child_id).map(|f| f.is_empty()).unwrap_or(true)
            };
            if !is_empty {
                let frag_name = frag_rec
                    .get_string(crate::program::database::module::FRAGMENT_NAME_COL)
                    .unwrap_or_default()
                    .to_string();
                return Err(NotEmptyException::with_message(format!("{frag_name} is not empty")));
            }
        }

        let mut mgr = self.module_mgr.borrow_mut();
        match self.remove_child_record(&mut *mgr, child_id, &pc_rec, true, delete_child) {
            Ok(success) => Ok(success),
            Err(e) => {
                mgr.db_error(e);
                Ok(false)
            }
        }
    }

    fn is_descendant_module(&self, module: &dyn ProgramModule) -> bool {
        let any: &dyn Any = module;
        let Some(m) = any.downcast_ref::<ModuleDbImpl>() else {
            return false;
        };
        let key = self.get_key();
        let mgr = self.module_mgr.borrow();
        match mgr.is_descendant(m.get_key(), key) {
            Ok(v) => v,
            Err(e) => {
                mgr.db_error(e);
                false
            }
        }
    }

    fn is_descendant_fragment(&self, fragment: &dyn ProgramFragment) -> bool {
        let any: &dyn Any = fragment;
        let Some(frag) = any.downcast_ref::<FragmentDbImpl>() else {
            return false;
        };
        self.refresh_if_needed();
        let key = self.get_key();
        let mgr = self.module_mgr.borrow();
        match mgr.is_descendant(-frag.get_key(), key) {
            Ok(v) => v,
            Err(e) => {
                mgr.db_error(e);
                false
            }
        }
    }

    fn get_min_address(&self) -> Option<Address> {
        self.refresh_if_needed();
        self.compute_address_set().min_address()
    }

    fn get_max_address(&self) -> Option<Address> {
        self.refresh_if_needed();
        self.compute_address_set().max_address()
    }

    fn get_first_address(&self) -> Option<Address> {
        self.refresh_if_needed();
        for child in ProgramModule::get_children(self) {
            if let Some(frag) = child.as_program_fragment() {
                if !AddressSetView::is_empty(frag) {
                    return AddressSetView::min_address(frag);
                }
            } else if let Some(m) = child.as_program_module() {
                if let Some(addr) = m.get_first_address() {
                    return Some(addr);
                }
            }
        }
        None
    }

    fn get_last_address(&self) -> Option<Address> {
        self.refresh_if_needed();
        for child in ProgramModule::get_children(self).into_iter().rev() {
            if let Some(frag) = child.as_program_fragment() {
                if !AddressSetView::is_empty(frag) {
                    return AddressSetView::max_address(frag);
                }
            } else if let Some(m) = child.as_program_module() {
                if let Some(addr) = m.get_last_address() {
                    return Some(addr);
                }
            }
        }
        None
    }

    fn get_address_set(&self) -> &dyn AddressSetView {
        let set = self.compute_address_set();
        *self.address_set_cache.borrow_mut() = set;
        // SAFETY: see the module-level doc comment "`get_address_set` and `unsafe`". In short:
        // this type is single-threaded (`Rc`/`RefCell` throughout), the value was just written
        // immediately above with no other outstanding borrow of `address_set_cache`, and nothing
        // else in this type ever borrows that field, so reading it back out through a raw pointer
        // cannot alias a live `&mut`. The returned reference stays valid until the *next* call to
        // this method overwrites the cache, mirroring Java's `getAddressSet()` -- which likewise
        // makes no promise that a previously-returned view reflects later mutations.
        unsafe { &*self.address_set_cache.as_ptr() }
    }

    fn get_version_tag(&self) -> Box<dyn Any> {
        self.module_mgr.borrow().get_version_tag()
    }

    fn get_modification_number(&self) -> i64 {
        self.module_mgr.borrow().get_modification_number()
    }

    fn get_tree_id(&self) -> i64 {
        self.module_mgr.borrow().get_tree_id()
    }
}

impl ModuleDB for ModuleDbImpl {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::module::module_manager_test_support::*;
    use crate::program::model::address::{AddressRange, AddressSpace, AddressSpaceType};

    fn test_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(test_space(), offset)
    }

    #[test]
    fn add_and_navigate_fragment_child() {
        let mgr = new_test_manager();
        let mut root = new_module(&mgr, "root");
        let frag = new_fragment(&mgr, ".text", AddressSet::new());
        let frag_key = frag.get_key();

        root.add_fragment(Box::new(frag)).expect("add_fragment should succeed");

        assert_eq!(ProgramModule::get_num_children(&root), 1);
        let children = ProgramModule::get_children(&root);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].get_name(), ".text");
        assert!(children[0].as_program_fragment().is_some());

        // Fetch a fresh fragment handle for the same key and confirm the module considers it a
        // child (both directions).
        let same_frag = new_fragment_handle(&mgr, frag_key);
        assert!(root.contains_fragment(&same_frag));
        assert_eq!(same_frag.get_num_parents(), 1);
    }

    #[test]
    fn create_module_and_fragment_children() {
        let mgr = new_test_manager();
        let mut root = new_module(&mgr, "root");

        let child_module = root.create_module("child").expect("create_module should succeed");
        assert_eq!(child_module.get_name(), "child");
        assert_eq!(ProgramModule::get_num_children(&root), 1);

        let child_fragment = root.create_fragment("frag1").expect("create_fragment should succeed");
        assert_eq!(child_fragment.get_name(), "frag1");
        assert_eq!(ProgramModule::get_num_children(&root), 2);

        // Duplicate names are rejected regardless of which table they collide with.
        assert!(root.create_module("frag1").is_err());
        assert!(root.create_fragment("child").is_err());

        let names: Vec<String> = ProgramModule::get_children(&root).iter().map(|g| g.get_name()).collect();
        assert_eq!(names, vec!["child".to_string(), "frag1".to_string()]);
    }

    #[test]
    fn remove_child_deletes_only_orphaned_records() {
        let mgr = new_test_manager();
        let mut root = new_module(&mgr, "root");
        root.create_fragment("solo").unwrap();
        assert_eq!(ProgramModule::get_num_children(&root), 1);

        let removed = root.remove_child("solo").expect("remove_child should succeed");
        assert!(removed);
        assert_eq!(ProgramModule::get_num_children(&root), 0);

        // Removing something that was never a child is a no-op returning false.
        assert!(!root.remove_child("solo").unwrap());
    }

    #[test]
    fn move_child_reorders() {
        let mgr = new_test_manager();
        let mut root = new_module(&mgr, "root");
        root.create_fragment("a").unwrap();
        root.create_fragment("b").unwrap();
        root.create_fragment("c").unwrap();

        let names_before: Vec<String> = ProgramModule::get_children(&root).iter().map(|g| g.get_name()).collect();
        assert_eq!(names_before, vec!["a", "b", "c"]);

        root.move_child("c", 0).expect("move_child should succeed");
        let names_after: Vec<String> = ProgramModule::get_children(&root).iter().map(|g| g.get_name()).collect();
        assert_eq!(names_after, vec!["c", "a", "b"]);

        assert!(root.move_child("missing", 0).is_err());
    }

    #[test]
    fn address_set_and_min_max_reflect_fragment_contents() {
        let mgr = new_test_manager();
        let mut root = new_module(&mgr, "root");

        let mut set1 = AddressSet::new();
        set1.add_range(&addr(0), &addr(10));
        let frag1 = new_fragment(&mgr, "f1", set1);
        root.add_fragment(Box::new(frag1)).unwrap();

        let mut set2 = AddressSet::new();
        set2.add_range(&addr(20), &addr(30));
        let frag2 = new_fragment(&mgr, "f2", set2);
        root.add_fragment(Box::new(frag2)).unwrap();

        assert_eq!(Group::get_min_address(&root), Some(addr(0)));
        assert_eq!(Group::get_max_address(&root), Some(addr(30)));
        assert_eq!(ProgramModule::get_first_address(&root), Some(addr(0)));
        // The *last* address is the maximum address of the last non-empty child *by order*
        // (frag2, added second) -- here that happens to equal the global maximum too.
        assert_eq!(ProgramModule::get_last_address(&root), Some(addr(30)));

        let view = ProgramModule::get_address_set(&root);
        assert!(view.contains(&addr(5)));
        assert!(view.contains(&addr(25)));
        assert!(!view.contains(&addr(15)));
    }

    #[test]
    fn add_module_rejects_duplicates_and_cycles() {
        let mgr = new_test_manager();
        let mut root = new_module(&mgr, "root");
        let mut child = root.create_module("child").expect("create should succeed");

        // Adding `child` to `root` again is a duplicate.
        let dup_handle = new_module_handle(&mgr, "child");
        assert!(matches!(root.add_module(Box::new(dup_handle)), Err(AddModuleError::Duplicate(_))));

        // Adding `root` as a child of its own descendant `child` would be circular.
        let root_handle = new_module_handle(&mgr, "root");
        assert!(matches!(
            child.add_module(Box::new(root_handle)),
            Err(AddModuleError::Circular(_))
        ));
    }

    #[test]
    fn reparent_moves_child_between_modules() {
        let mgr = new_test_manager();
        let mut root = new_module(&mgr, "root");
        let mut a = root.create_module("a").expect("create a");
        let mut b = root.create_module("b").expect("create b");
        a.create_fragment("shared").expect("create fragment under a");

        assert_eq!(a.get_num_children(), 1);
        assert_eq!(b.get_num_children(), 0);

        b.reparent("shared", &mut *a).expect("reparent should succeed");

        assert_eq!(a.get_num_children(), 0);
        assert_eq!(b.get_num_children(), 1);
        assert_eq!(b.get_children()[0].get_name(), "shared");
    }

    #[test]
    fn is_deleted_reflects_refresh_failure() {
        let mgr = new_test_manager();
        let module = new_module(&mgr, "temp");
        let key = module.get_key();
        assert!(!Group::is_deleted(&module));

        remove_module_row(&mgr, key);
        module.set_invalid();
        assert!(Group::is_deleted(&module));
    }
}
