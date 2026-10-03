//! Shared `ModuleManager` test double used by [`fragment_db`](super::fragment_db)'s and
//! [`module_db`](super::module_db)'s unit tests.
//!
//! This is not itself a port of anything: it is a minimal, in-memory stand-in for the concrete
//! manager that would, in a real Ghidra program, own real `ModuleDBAdapterV1`/
//! `FragmentDBAdapterV0`/`ParentChildDBAdapterV0` instances plus a real `DbCache` (see
//! [`module_manager`](super::module_manager)'s module docs for why that concrete manager does not
//! exist yet). It exists purely so [`FragmentDbImpl`](super::fragment_db::FragmentDbImpl) and
//! [`ModuleDbImpl`](super::module_db::ModuleDbImpl) can be exercised end to end -- creating
//! fragments/modules, building a tree, navigating it -- without a real `ProgramDB`.
#![cfg(test)]

use std::any::Any;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io;
use std::rc::{Rc, Weak};

use crate::framework::db::{DBRecord, Field, FieldType, RecordIterator, Schema};
use crate::program::database::db_object::DbObject;
use crate::program::database::module::fragment_db::FragmentDbImpl;
use crate::program::database::module::module_db::ModuleDbImpl;
use crate::program::database::module::module_manager::{ModuleManager, MoveAddressRangeError};
use crate::program::database::module::{
    FragmentDB, FragmentDBAdapter, ModuleDB, ModuleDBAdapter, ParentChildDBAdapter, CHILD_ID_COL,
    FRAGMENT_COMMENTS_COL, FRAGMENT_NAME_COL, MODULE_CHILD_COUNT_COL, MODULE_COMMENTS_COL,
    MODULE_NAME_COL, ORDER_COL, PARENT_ID_COL,
};
use crate::program::database::program_db::ProgramDB;
use crate::program::model::address::{Address, AddressRange, AddressSet};
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::code_unit_iterator::{CodeUnitIterator, EmptyCodeUnitIterator};
use crate::program::model::listing::group::Group;
use crate::program::model::listing::{ProgramFragment, ProgramModule};
use crate::util::task::TaskMonitor;

/// Identifies a [`Group`] by DB key without calling any method that would touch its
/// `module_mgr` handle (i.e. not `get_name()`).
///
/// This exists because [`ModuleManager`]'s notification callbacks
/// (`fragment_added`/`comments_changed`/...) are invoked *while* this mock's own
/// `Rc<RefCell<MockModuleManager>>` is already mutably borrowed (the borrow that is the receiver
/// of the very call into the notification method). Calling back into the passed `&dyn
/// Group`/`&dyn ProgramFragment`/`&dyn ProgramModule`'s `get_name()` (or anything else that
/// reaches `refresh_if_needed`) would try to re-borrow that same `RefCell` and panic with
/// "already borrowed" -- `RefCell`, unlike a Java intrinsic lock, is not reentrant. `DbObject`'s
/// `get_key()` only reads the object's own atomics, so it is safe to call here. See
/// `fragment_db`'s module docs for the same hazard, documented for future concrete
/// `ModuleManager` implementors.
fn describe_group(group: &dyn Group) -> String {
    let any: &dyn Any = group;
    if let Some(f) = any.downcast_ref::<FragmentDbImpl>() {
        format!("fragment#{}", f.get_key())
    } else if let Some(m) = any.downcast_ref::<ModuleDbImpl>() {
        format!("module#{}", m.get_key())
    } else {
        "<unknown>".to_string()
    }
}

fn fragment_schema() -> std::sync::Arc<Schema> {
    std::sync::Arc::new(Schema::new(
        0,
        FieldType::Long,
        "Key".to_string(),
        vec![FieldType::String, FieldType::String],
        vec!["Name".to_string(), "Comments".to_string()],
        vec![],
    ))
}

fn module_schema() -> std::sync::Arc<Schema> {
    std::sync::Arc::new(Schema::new(
        1,
        FieldType::Long,
        "Key".to_string(),
        vec![FieldType::String, FieldType::String, FieldType::Int],
        vec![
            "Name".to_string(),
            "Comments".to_string(),
            "ChildCount".to_string(),
        ],
        vec![],
    ))
}

fn parent_child_schema() -> std::sync::Arc<Schema> {
    std::sync::Arc::new(Schema::new(
        0,
        FieldType::Long,
        "Key".to_string(),
        vec![FieldType::Long, FieldType::Long, FieldType::Int],
        vec!["ParentID".to_string(), "ChildID".to_string(), "Order".to_string()],
        vec![],
    ))
}

#[derive(Debug, Clone)]
struct FragmentRow {
    name: String,
    comments: Option<String>,
}

#[derive(Default)]
struct MockFragmentDBAdapter {
    rows: BTreeMap<i64, FragmentRow>,
    next_key: i64,
}

impl MockFragmentDBAdapter {
    fn build_record(&self, key: i64, row: &FragmentRow) -> DBRecord {
        let mut record = DBRecord::new(fragment_schema(), Field::Long(Some(key)));
        record.set_string(FRAGMENT_NAME_COL, Some(row.name.clone()));
        record.set_string(FRAGMENT_COMMENTS_COL, row.comments.clone());
        record
    }
}

impl FragmentDBAdapter for MockFragmentDBAdapter {
    fn create_fragment_record(&mut self, _parent_module_id: i64, name: &str) -> io::Result<DBRecord> {
        self.next_key += 1;
        let key = self.next_key;
        let row = FragmentRow { name: name.to_string(), comments: None };
        let record = self.build_record(key, &row);
        self.rows.insert(key, row);
        Ok(record)
    }

    fn get_fragment_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
        Ok(self.rows.get(&key).map(|row| self.build_record(key, row)))
    }

    fn get_fragment_record_by_name(&self, name: &str) -> io::Result<Option<DBRecord>> {
        Ok(self
            .rows
            .iter()
            .find(|(_, row)| row.name == name)
            .map(|(key, row)| self.build_record(*key, row)))
    }

    fn update_fragment_record(&mut self, record: &DBRecord) -> io::Result<()> {
        let key = record.get_key().get_long_value();
        let name = record.get_string(FRAGMENT_NAME_COL).unwrap_or_default().to_string();
        let comments = record.get_string(FRAGMENT_COMMENTS_COL).map(|s| s.to_string());
        self.rows.insert(key, FragmentRow { name, comments });
        Ok(())
    }

    fn remove_fragment_record(&mut self, child_id: i64) -> io::Result<bool> {
        Ok(self.rows.remove(&child_id).is_some())
    }
}

#[derive(Debug, Clone)]
struct ModuleRow {
    name: String,
    comments: Option<String>,
    child_count: i32,
}

#[derive(Default)]
struct MockModuleDBAdapter {
    rows: BTreeMap<i64, ModuleRow>,
    next_key: i64,
}

impl MockModuleDBAdapter {
    fn build_record(&self, key: i64, row: &ModuleRow) -> DBRecord {
        let mut record = DBRecord::new(module_schema(), Field::Long(Some(key)));
        record.set_string(MODULE_NAME_COL, Some(row.name.clone()));
        record.set_string(MODULE_COMMENTS_COL, row.comments.clone());
        record.set_int(MODULE_CHILD_COUNT_COL, row.child_count);
        record
    }
}

struct VecRecordIterator {
    records: std::vec::IntoIter<DBRecord>,
}

impl RecordIterator for VecRecordIterator {
    fn next(&mut self) -> io::Result<Option<DBRecord>> {
        Ok(self.records.next())
    }

    fn has_next(&self) -> bool {
        self.records.as_slice().first().is_some()
    }
}

impl ModuleDBAdapter for MockModuleDBAdapter {
    fn create_module_record(&mut self, _parent_module_id: i64, name: &str) -> io::Result<DBRecord> {
        self.next_key += 1;
        let key = self.next_key;
        let row = ModuleRow { name: name.to_string(), comments: None, child_count: 0 };
        let record = self.build_record(key, &row);
        self.rows.insert(key, row);
        Ok(record)
    }

    fn get_module_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
        Ok(self.rows.get(&key).map(|row| self.build_record(key, row)))
    }

    fn get_module_record_by_name(&self, name: &str) -> io::Result<Option<DBRecord>> {
        Ok(self
            .rows
            .iter()
            .find(|(_, row)| row.name == name)
            .map(|(key, row)| self.build_record(*key, row)))
    }

    fn get_records(&self) -> io::Result<Box<dyn RecordIterator + '_>> {
        let records: Vec<DBRecord> = self.rows.iter().map(|(key, row)| self.build_record(*key, row)).collect();
        Ok(Box::new(VecRecordIterator { records: records.into_iter() }))
    }

    fn update_module_record(&mut self, record: &DBRecord) -> io::Result<()> {
        let key = record.get_key().get_long_value();
        let name = record.get_string(MODULE_NAME_COL).unwrap_or_default().to_string();
        let comments = record.get_string(MODULE_COMMENTS_COL).map(|s| s.to_string());
        let child_count = record.get_int(MODULE_CHILD_COUNT_COL).unwrap_or(0);
        self.rows.insert(key, ModuleRow { name, comments, child_count });
        Ok(())
    }

    fn remove_module_record(&mut self, child_id: i64) -> io::Result<bool> {
        Ok(self.rows.remove(&child_id).is_some())
    }
}

#[derive(Debug, Clone)]
struct ParentChildRow {
    parent_id: i64,
    child_id: i64,
    order: i32,
}

#[derive(Default)]
struct MockParentChildDBAdapter {
    rows: BTreeMap<i64, ParentChildRow>,
    next_key: i64,
}

impl MockParentChildDBAdapter {
    fn build_record(&self, key: i64, row: &ParentChildRow) -> DBRecord {
        let mut record = DBRecord::new(parent_child_schema(), Field::Long(Some(key)));
        record.set_long(PARENT_ID_COL, row.parent_id);
        record.set_long(CHILD_ID_COL, row.child_id);
        record.set_int(ORDER_COL, row.order);
        record
    }
}

impl ParentChildDBAdapter for MockParentChildDBAdapter {
    fn add_parent_child_record(&mut self, parent_module_id: i64, child_id: i64) -> io::Result<DBRecord> {
        self.next_key += 1;
        let key = self.next_key;
        let order = self.rows.values().filter(|r| r.parent_id == parent_module_id).count() as i32;
        let row = ParentChildRow { parent_id: parent_module_id, child_id, order };
        let record = self.build_record(key, &row);
        self.rows.insert(key, row);
        Ok(record)
    }

    fn get_parent_child_record(&self, parent_id: i64, child_id: i64) -> io::Result<Option<DBRecord>> {
        Ok(self
            .rows
            .iter()
            .find(|(_, row)| row.parent_id == parent_id && row.child_id == child_id)
            .map(|(key, row)| self.build_record(*key, row)))
    }

    fn get_parent_child_record_by_key(&self, key: i64) -> io::Result<Option<DBRecord>> {
        Ok(self.rows.get(&key).map(|row| self.build_record(key, row)))
    }

    fn update_parent_child_record(&mut self, record: &DBRecord) -> io::Result<()> {
        let key = record.get_key().get_long_value();
        let parent_id = record.get_long(PARENT_ID_COL).unwrap_or(0);
        let child_id = record.get_long(CHILD_ID_COL).unwrap_or(0);
        let order = record.get_int(ORDER_COL).unwrap_or(0);
        self.rows.insert(key, ParentChildRow { parent_id, child_id, order });
        Ok(())
    }

    fn remove_parent_child_record(&mut self, key: i64) -> io::Result<bool> {
        Ok(self.rows.remove(&key).is_some())
    }

    fn get_parent_child_keys(&self, id: i64, index_col: usize) -> io::Result<Vec<Field>> {
        Ok(self
            .rows
            .iter()
            .filter(|(_, row)| match index_col {
                PARENT_ID_COL => row.parent_id == id,
                CHILD_ID_COL => row.child_id == id,
                _ => false,
            })
            .map(|(key, _)| Field::Long(Some(*key)))
            .collect())
    }
}

/// In-memory `ModuleManager` test double. See the module docs.
pub(crate) struct MockModuleManager {
    self_handle: Weak<RefCell<MockModuleManager>>,
    tree_id: i64,
    tree_name: String,
    module_adapter: MockModuleDBAdapter,
    fragment_adapter: MockFragmentDBAdapter,
    parent_child_adapter: MockParentChildDBAdapter,
    fragment_address_sets: BTreeMap<i64, AddressSet>,
    /// Records notifications received, for tests that want to assert on manager call-backs.
    pub(crate) notifications: Vec<String>,
    db_handle: crate::framework::db::DBHandle,
}

/// Builds a fresh manager. Returns the *concrete* type (rather than `Rc<RefCell<dyn
/// ModuleManager>>`) so test helpers below can poke its fields directly (setting up a fragment's
/// address set, removing a row to simulate deletion, ...) -- something no real `ModuleManager`
/// caller needs, so it is deliberately not part of the trait. Use [`as_manager`] to get the
/// trait-object handle [`FragmentDbImpl`]/[`ModuleDbImpl`] actually store.
pub(crate) fn new_test_manager() -> Rc<RefCell<MockModuleManager>> {
    Rc::new_cyclic(|weak| {
        RefCell::new(MockModuleManager {
            self_handle: weak.clone(),
            tree_id: 1,
            tree_name: "Program Tree".to_string(),
            module_adapter: MockModuleDBAdapter::default(),
            fragment_adapter: MockFragmentDBAdapter::default(),
            parent_child_adapter: MockParentChildDBAdapter::default(),
            fragment_address_sets: BTreeMap::new(),
            notifications: Vec::new(),
            db_handle: crate::framework::db::DBHandle::new().expect("db handle should construct"),
        })
    })
}

/// Upcasts the concrete test manager to the `Rc<RefCell<dyn ModuleManager>>` handle
/// [`FragmentDbImpl`]/[`ModuleDbImpl`] store.
pub(crate) fn as_manager(mgr: &Rc<RefCell<MockModuleManager>>) -> Rc<RefCell<dyn ModuleManager>> {
    mgr.clone() as Rc<RefCell<dyn ModuleManager>>
}

/// Creates a fresh fragment (via the manager's fragment adapter, so its key is consistent with
/// what the manager itself would look it up as) and wraps it in a [`FragmentDbImpl`].
pub(crate) fn new_fragment(
    mgr: &Rc<RefCell<MockModuleManager>>,
    name: &str,
    addr_set: AddressSet,
) -> FragmentDbImpl {
    let record = mgr
        .borrow_mut()
        .fragment_adapter
        .create_fragment_record(0, name)
        .expect("create_fragment_record should succeed");
    let key = record.get_key().get_long_value();
    mgr.borrow_mut().fragment_address_sets.insert(key, addr_set.clone());
    FragmentDbImpl::new(as_manager(mgr), record, addr_set)
}

/// Creates a fresh module (via the manager's module adapter) and wraps it in a [`ModuleDbImpl`].
pub(crate) fn new_module(mgr: &Rc<RefCell<MockModuleManager>>, name: &str) -> ModuleDbImpl {
    let record = mgr
        .borrow_mut()
        .module_adapter
        .create_module_record(0, name)
        .expect("create_module_record should succeed");
    ModuleDbImpl::new(as_manager(mgr), record)
}

/// Builds a *second* [`FragmentDbImpl`] handle over the same underlying row identified by `key`,
/// exactly as `ModuleManager.getFragmentDB(long)` hands back a (conceptually shared, cache-backed)
/// handle to callers who only know the key. Used by tests that want to confirm two independently
/// obtained handles for the same fragment agree (e.g. on parent/child membership).
pub(crate) fn new_fragment_handle(mgr: &Rc<RefCell<MockModuleManager>>, key: i64) -> FragmentDbImpl {
    let record = mgr
        .borrow_mut()
        .fragment_adapter
        .get_fragment_record(key)
        .expect("get_fragment_record should succeed")
        .expect("fragment row should exist");
    let addr_set = mgr.borrow().fragment_address_sets.get(&key).cloned().unwrap_or_default();
    FragmentDbImpl::new(as_manager(mgr), record, addr_set)
}

/// Builds a *second* [`ModuleDbImpl`] handle over the same underlying row named `name`, mirroring
/// [`new_fragment_handle`] for modules.
pub(crate) fn new_module_handle(mgr: &Rc<RefCell<MockModuleManager>>, name: &str) -> ModuleDbImpl {
    let record = mgr
        .borrow_mut()
        .module_adapter
        .get_module_record_by_name(name)
        .expect("get_module_record_by_name should succeed")
        .expect("module row should exist");
    ModuleDbImpl::new(as_manager(mgr), record)
}

/// Removes a fragment's row from the mock's storage, simulating the fragment having been deleted
/// out from under a still-live [`FragmentDbImpl`] handle.
pub(crate) fn remove_fragment_row(mgr: &Rc<RefCell<MockModuleManager>>, key: i64) {
    let _ = mgr.borrow_mut().fragment_adapter.remove_fragment_record(key);
}

/// Removes a module's row from the mock's storage, simulating the module having been deleted out
/// from under a still-live [`ModuleDbImpl`] handle.
pub(crate) fn remove_module_row(mgr: &Rc<RefCell<MockModuleManager>>, key: i64) {
    let _ = mgr.borrow_mut().module_adapter.remove_module_record(key);
}

impl MockModuleManager {
    fn upgrade(&self) -> Rc<RefCell<dyn ModuleManager>> {
        self.self_handle.upgrade().expect("manager should still be alive") as Rc<RefCell<dyn ModuleManager>>
    }
}

impl ModuleManager for MockModuleManager {
    fn get_tree_id(&self) -> i64 {
        self.tree_id
    }

    fn get_module_adapter(&mut self) -> &mut dyn ModuleDBAdapter {
        &mut self.module_adapter
    }

    fn get_fragment_adapter(&mut self) -> &mut dyn FragmentDBAdapter {
        &mut self.fragment_adapter
    }

    fn get_parent_child_adapter(&mut self) -> &mut dyn ParentChildDBAdapter {
        &mut self.parent_child_adapter
    }

    fn get_lock(&self) -> &crate::util::lock::ReentrantLock {
        unimplemented!("mock does not model ModuleManager's Lock; see fragment_db/module_db module docs")
    }

    fn set_name(&mut self, name: &str) {
        self.tree_name = name.to_string();
    }

    fn image_base_changed(&mut self, _commit: bool) {}

    fn db_error(&self, error: io::Error) {
        panic!("unexpected db_error in test: {error}");
    }

    fn set_program_name(&mut self, _old_name: &str, _new_name: &str) {}

    fn get_root_module(&self) -> io::Result<Box<dyn ProgramModule>> {
        Err(io::Error::new(io::ErrorKind::NotFound, "no root in mock"))
    }

    fn get_module(&self, name: &str) -> io::Result<Option<Box<dyn ProgramModule>>> {
        match self.module_adapter.get_module_record_by_name(name)? {
            Some(_) => Ok(self.get_module_db_by_name_hack(name)),
            None => Ok(None),
        }
    }

    fn get_fragment_by_name(&self, name: &str) -> io::Result<Option<Box<dyn ProgramFragment>>> {
        Ok(self
            .fragment_adapter
            .get_fragment_record_by_name(name)?
            .map(|rec| self.materialize_fragment(rec) as Box<dyn ProgramFragment>))
    }

    fn get_fragment_at(&self, _addr: &Address) -> io::Result<Option<Box<dyn ProgramFragment>>> {
        Ok(None)
    }

    fn add_memory_block(&mut self, _name: &str, _range: &AddressRange) -> io::Result<()> {
        Ok(())
    }

    fn remove_memory_block(&mut self, _start_addr: &Address, _end_addr: &Address, _monitor: &dyn TaskMonitor) {}

    fn move_address_range(
        &mut self,
        _from_addr: &Address,
        _to_addr: &Address,
        _length: i64,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), MoveAddressRangeError> {
        Ok(())
    }

    fn fragment_added(&mut self, parent_id: i64, fragment: &dyn ProgramFragment) {
        self.notifications
            .push(format!("fragment_added({parent_id}, {})", describe_group(fragment)));
    }

    fn module_added(&mut self, parent_id: i64, module: &dyn ProgramModule) {
        self.notifications
            .push(format!("module_added({parent_id}, {})", describe_group(module)));
    }

    fn group_removed(
        &mut self,
        _parent_module: &dyn ModuleDB,
        child_id: i64,
        child_name: &str,
        is_fragment: bool,
        delete_child: bool,
    ) {
        self.notifications
            .push(format!("group_removed({child_id}, {child_name}, {is_fragment}, {delete_child})"));
    }

    fn comments_changed(&mut self, _old_comments: Option<&str>, group: &dyn Group) {
        self.notifications.push(format!("comments_changed({})", describe_group(group)));
    }

    fn name_changed(&mut self, old_name: &str, group: &dyn Group) {
        self.notifications
            .push(format!("name_changed({old_name} -> {})", describe_group(group)));
    }

    fn is_descendant(&self, id: i64, module_id: i64) -> io::Result<bool> {
        // Minimal breadth-first search over the parent/child table, mirroring the *contract* of
        // `ModuleManager.isDescendant` without porting its private tree-walk implementation
        // (which belongs to the concrete manager, not this mock).
        let mut frontier = vec![module_id];
        let mut seen = std::collections::BTreeSet::new();
        while let Some(current) = frontier.pop() {
            if !seen.insert(current) {
                continue;
            }
            if current == id {
                return Ok(true);
            }
            for key in self.parent_child_adapter.get_parent_child_keys(current, PARENT_ID_COL)? {
                if let Some(rec) = self
                    .parent_child_adapter
                    .get_parent_child_record_by_key(key.get_long_value())?
                {
                    frontier.push(rec.get_long(CHILD_ID_COL).unwrap_or(0));
                }
            }
        }
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
    ) -> Result<(), crate::util::exception::NotFoundException> {
        Ok(())
    }

    fn get_fragment_containing(&self, _code_unit: &dyn CodeUnit) -> Option<Box<dyn FragmentDB>> {
        None
    }

    fn child_reordered(&mut self, _parent_module: &dyn ModuleDB, child: &dyn Group) {
        self.notifications.push(format!("child_reordered({})", describe_group(child)));
    }

    fn child_reparented(&mut self, group: &dyn Group, old_parent_name: &str, new_parent_name: &str) {
        self.notifications.push(format!(
            "child_reparented({}, {old_parent_name} -> {new_parent_name})",
            describe_group(group)
        ));
    }

    fn get_parent_names(&self, child_id: i64) -> Vec<String> {
        self.get_parents(child_id).iter().map(|m| m.get_name()).collect()
    }

    fn get_parents(&self, child_id: i64) -> Vec<Box<dyn ProgramModule>> {
        let mut result = Vec::new();
        let keys = self
            .parent_child_adapter
            .get_parent_child_keys(child_id, CHILD_ID_COL)
            .unwrap_or_default();
        for key in keys {
            if let Ok(Some(rec)) = self
                .parent_child_adapter
                .get_parent_child_record_by_key(key.get_long_value())
            {
                let parent_id = rec.get_long(PARENT_ID_COL).unwrap_or(0);
                if let Ok(Some(module_rec)) = self.module_adapter.get_module_record(parent_id) {
                    result.push(Box::new(ModuleDbImpl::new(self.upgrade(), module_rec)) as Box<dyn ProgramModule>);
                }
            }
        }
        result
    }

    fn get_fragment_address_set(&self, frag_id: i64) -> AddressSet {
        self.fragment_address_sets.get(&frag_id).cloned().unwrap_or_default()
    }

    fn invalidate_cache(&mut self) {}

    fn get_version_tag(&self) -> Box<dyn std::any::Any> {
        Box::new(0i64)
    }

    fn get_modification_number(&self) -> i64 {
        0
    }

    fn dispose(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn get_program(&self) -> &ProgramDB {
        unimplemented!("mock does not exercise get_program")
    }

    fn get_database_handle(&self) -> &crate::framework::db::DBHandle {
        &self.db_handle
    }

    fn get_fragment_db(&self, key: i64) -> Option<Box<dyn FragmentDB>> {
        let rec = self.fragment_adapter.get_fragment_record(key).ok().flatten()?;
        Some(self.materialize_fragment(rec))
    }

    fn get_module_db(&self, key: i64) -> Option<Box<dyn ModuleDB>> {
        let rec = self.module_adapter.get_module_record(key).ok().flatten()?;
        Some(Box::new(ModuleDbImpl::new(self.upgrade(), rec)))
    }

    fn get_fragment_db_for_record(&self, fragment_record: &DBRecord) -> Box<dyn FragmentDB> {
        self.materialize_fragment(fragment_record.clone())
    }

    fn get_module_db_for_record(&self, module_record: &DBRecord) -> Box<dyn ModuleDB> {
        Box::new(ModuleDbImpl::new(self.upgrade(), module_record.clone()))
    }
}

impl MockModuleManager {
    fn materialize_fragment(&self, record: DBRecord) -> Box<dyn FragmentDB> {
        let key = record.get_key().get_long_value();
        let addr_set = self.fragment_address_sets.get(&key).cloned().unwrap_or_default();
        Box::new(FragmentDbImpl::new(self.upgrade(), record, addr_set))
    }

    fn get_module_db_by_name_hack(&self, name: &str) -> Option<Box<dyn ProgramModule>> {
        self.module_adapter
            .get_module_record_by_name(name)
            .ok()
            .flatten()
            .map(|rec| Box::new(ModuleDbImpl::new(self.upgrade(), rec)) as Box<dyn ProgramModule>)
    }
}
