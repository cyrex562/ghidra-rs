//! Port of `ghidra.program.database.data.CategoryDB`, the database-backed implementation of
//! [`Category`].
//!
//! `CategoryDB` is a node in a data-type-manager's category tree (a "folder" for data types,
//! analogous to a filesystem directory): it has a name, a parent (`None` only for the root), and
//! children, and it holds the datatypes filed directly under it. In Java it is constructed by,
//! and calls back into, `DataTypeManagerDB` -- a class not yet ported as a concrete type in this
//! crate. [`CategoryOwner`] is the seam trait that cuts that construction cycle, following the
//! same pattern already used for
//! [`CodeUnitDbBase`](crate::program::database::code::code_unit_db::CodeUnitDbBase)/
//! [`CodeUnitOwner`](crate::program::database::code::code_unit_owner::CodeUnitOwner) and for
//! [`ModuleDbImpl`](crate::program::database::module::module_db::ModuleDbImpl)/
//! [`ModuleManager`](crate::program::database::module::module_manager::ModuleManager).
//! [`CategoryDb`] is structurally closest to `ModuleDbImpl`: both are tree nodes reached through
//! an `Rc<RefCell<dyn Owner>>` back-reference, composed (not inherited) shared state, and
//! interior mutability for the handful of fields that change after construction.
//!
//! # Design decisions and deliberate simplifications
//!
//! - **No persistent identity cache.** Java's `DataTypeManagerDB` keeps every live `CategoryDB`
//!   in a `DbObjectCache` (`catCache`) keyed by id, so two calls that resolve the same id get
//!   back the *same* object, and `CategoryDB` itself layers three more
//!   `LazyLoadingCachingMap`s on top (subcategories, datatypes, `.conflict`-name groupings) to
//!   avoid re-querying the database on every access. This port has no such shared cache to plug
//!   into (`DataTypeManagerDB` itself is not concretely ported), so [`CategoryDb`] simply
//!   recomputes everything -- children, datatypes, and its own [`CategoryPath`] -- fresh from the
//!   [`CategoryOwner`] on every call. This is always correct (there is no staleness window to
//!   reason about) at the cost of the performance optimization Java performs. The
//!   package-private `categoryAdded`/`catagoryRenamed`/`dataTypeAdded`/`dataTypeRemoved`/
//!   `dataTypeRenamed` methods that existed *solely* to keep those caches in sync are therefore
//!   not ported; this is an intentional consequence of the above, not a missing feature.
//! - **Manager-identity checks are approximated.** Java guards `moveCategory`/`copyCategory` with
//!   reference-identity checks (`mgr != category.getDataTypeManager()`) and an
//!   `instanceof CategoryDB` check. [`Category`] is a plain trait (not bounded by `Any`, unlike
//!   e.g. [`Group`](crate::program::model::listing::group::Group)), so a `Box<dyn Category>`
//!   cannot be downcast to compare identity, and adding an `Any` bound to `Category` was judged
//!   not worth doing for this alone. Instead, "does this category belong to my manager" is
//!   approximated by asking the manager to resolve the same id and comparing the resulting
//!   [`CategoryPath`] -- the operative invariant the Java check exists to protect. See
//!   [`CategoryDb::move_category`] and [`CategoryDb::copy_category`].
//! - **`checkDeleted()`'s unchecked exception.** Mirrors the convention already established in
//!   [`ModuleDbImpl`](crate::program::database::module::module_db::ModuleDbImpl): where Java
//!   would let `ConcurrentModificationException` propagate, mutating methods here silently
//!   continue on a best-effort basis (or, where the trait's return type allows it, treat it like
//!   an ordinary failure).
//! - **`Category::get_data_type_manager` returns an owned handle.** [`Category`] must hand back a
//!   `Box<dyn DataTypeManager>`, but [`CategoryDb`] only holds an `Rc<RefCell<dyn CategoryOwner>>`
//!   -- there is no borrowed `&dyn DataTypeManager` to return. Rather than reach for any
//!   `unsafe` trick to manufacture one, this port constructs a small forwarding wrapper
//!   ([`CategoryOwnerHandle`]) that owns a cloned `Rc` and forwards the handful of
//!   [`DataTypeManager`] methods actually needed; this is the same "return an owned value, not a
//!   borrowed one" fix applied to
//!   `ProgramModule::get_address_set` (see `module_db.rs`'s module docs).

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use crate::framework::db::DBRecord;
use crate::program::database::data::category_db_adapter::{CATEGORY_NAME_COL, CATEGORY_PARENT_COL};
use crate::program::database::data::category_owner::CategoryOwner;
use crate::program::database::data::data_type_utilities::DataTypeUtilities;
use crate::program::database::db_object::{DbObject, DbObjectState};
use crate::program::model::data::category::{Category, SetCategoryNameError};
use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_conflict_handler::{ConflictResult, DataTypeConflictHandler};
use crate::program::model::data::data_type_dependency_exception::DataTypeDependencyException;
use crate::program::model::data::data_type_manager::{DataTypeManager, ReplaceDataTypeError};
use crate::util::exception::{CancelledException, DuplicateNameException, InvalidNameException};
use crate::util::task::TaskMonitor;

/// The id of the root category. Stands in for `DataTypeManagerDB.ROOT_CATEGORY_ID`.
pub const ROOT_CATEGORY_ID: i64 = 0;

/// Stands in for the private `CategoryDB.testName(String)`.
fn test_name(category_name: &str) -> Result<(), InvalidNameException> {
    if category_name.is_empty() {
        return Err(InvalidNameException::with_message("Name cannot be null or zero length"));
    }
    Ok(())
}

/// A dummy zero-sized receiver used purely to invoke [`DataTypeUtilities`]'s default methods, per
/// the convention already established by
/// [`enum_data_type`](crate::program::model::data::enum_data_type)/
/// [`pointer_typedef`](crate::program::model::data::pointer_typedef)'s own `impl DataTypeUtilities
/// for Utils {}`.
struct Utils;
impl DataTypeUtilities for Utils {}

/// A small forwarding wrapper that lets [`CategoryDb::get_data_type_manager`] hand back an
/// *owned* `Box<dyn DataTypeManager>` view of its [`CategoryOwner`], rather than reaching for an
/// unsound borrowed-pointer trick. See the module documentation.
struct CategoryOwnerHandle(Rc<RefCell<dyn CategoryOwner>>);

impl DataTypeManager for CategoryOwnerHandle {
    fn get_name(&self) -> String {
        self.0.borrow().get_name()
    }

    fn set_name(&mut self, name: &str) -> Result<(), InvalidNameException> {
        self.0.borrow_mut().set_name(name)
    }

    fn resolve(
        &mut self,
        data_type: Box<dyn DataType>,
        handler: &dyn DataTypeConflictHandler,
    ) -> Box<dyn DataType> {
        self.0.borrow_mut().resolve(data_type, handler)
    }

    fn remove(&mut self, data_type: &dyn DataType) -> bool {
        self.0.borrow_mut().remove(data_type)
    }

    fn replace_data_type(
        &mut self,
        existing_dt: &dyn DataType,
        replacement_dt: Box<dyn DataType>,
        update_category_path: bool,
    ) -> Result<Box<dyn DataType>, ReplaceDataTypeError> {
        self.0.borrow_mut().replace_data_type(existing_dt, replacement_dt, update_category_path)
    }

    fn get_category(&self, category_id: i64) -> Option<Box<dyn Category>> {
        self.0.borrow().get_category(category_id)
    }

    fn create_category(&mut self, path: &CategoryPath) -> Box<dyn Category> {
        self.0.borrow_mut().create_category(path)
    }
}

/// Database implementation of [`Category`].
///
/// Port of `ghidra.program.database.data.CategoryDB`. See the module documentation for what was
/// deliberately simplified and why.
pub struct CategoryDb {
    state: DbObjectState,
    mgr: Rc<RefCell<dyn CategoryOwner>>,
    /// `None` only for the root category. Stands in for `CategoryDB.parent`, narrowed to just the
    /// parent's id: a fresh [`CategoryDb`] for the parent is constructed on demand (via
    /// [`CategoryOwner`]) rather than cached, per the module documentation.
    parent_id: Cell<Option<i64>>,
    /// Stands in for `CategoryDB.name`. Unused (but still tracked) for the root category, whose
    /// [`Category::get_name`] always defers to the manager's own name, matching Java.
    name: RefCell<String>,
}

impl CategoryDb {
    /// Constructs a category view over the category identified by `id`, backed by `mgr`.
    /// `parent_id` is `None` only for the root category.
    ///
    /// Stands in for `CategoryDB(DataTypeManagerDB, long, CategoryDB, String)`.
    pub fn new(mgr: Rc<RefCell<dyn CategoryOwner>>, id: i64, parent_id: Option<i64>, name: &str) -> Self {
        CategoryDb {
            state: DbObjectState::new(id),
            mgr,
            parent_id: Cell::new(parent_id),
            name: RefCell::new(name.to_string()),
        }
    }

    /// Constructs the root category view, backed by `mgr`.
    pub fn root(mgr: Rc<RefCell<dyn CategoryOwner>>) -> Self {
        CategoryDb::new(mgr, ROOT_CATEGORY_ID, None, "")
    }

    /// Approximates Java's `mgr != category.getDataTypeManager()` (plus `instanceof CategoryDB`)
    /// identity checks: does *this* manager resolve `category`'s own id to a category at exactly
    /// `category`'s own path? See the module documentation for why this is an approximation
    /// rather than a true identity check.
    fn belongs_to_this_manager(&self, category: &dyn Category) -> bool {
        self.mgr
            .borrow()
            .get_category(category.get_id())
            .is_some_and(|found| found.get_category_path() == category.get_category_path())
    }
}

impl DbObject for CategoryDb {
    fn state(&self) -> &DbObjectState {
        &self.state
    }

    fn refresh(&self, record: Option<&DBRecord>) -> bool {
        if self.is_root() {
            return true;
        }
        let owner = self.mgr.clone();
        let rec = match record {
            Some(r) => Some(r.clone()),
            None => {
                let result = owner.borrow_mut().get_category_adapter().get_record(self.get_key());
                match result {
                    Ok(r) => r,
                    Err(e) => {
                        owner.borrow().db_error(e);
                        return false;
                    }
                }
            }
        };
        match rec {
            Some(r) => {
                let parent = r.get_long(CATEGORY_PARENT_COL).unwrap_or(-1);
                self.parent_id.set(if parent < 0 { None } else { Some(parent) });
                *self.name.borrow_mut() = r.get_string(CATEGORY_NAME_COL).unwrap_or_default().to_string();
                true
            }
            None => false,
        }
    }
}

impl Category for CategoryDb {
    fn get_name(&self) -> String {
        self.refresh_if_needed();
        if self.is_root() {
            return self.mgr.borrow().get_name();
        }
        self.name.borrow().clone()
    }

    fn set_name(&mut self, new_name: &str) -> Result<(), SetCategoryNameError> {
        test_name(new_name)?;
        if self.check_deleted().is_err() {
            return Ok(());
        }
        let old_path = self.get_category_path();
        if self.is_root() {
            self.mgr.borrow_mut().set_name(new_name)?;
            return Ok(());
        }
        if new_name == self.name.borrow().as_str() {
            return Ok(());
        }
        if self.get_parent().and_then(|p| p.get_category(new_name)).is_some() {
            return Err(SetCategoryNameError::Duplicate(DuplicateNameException::with_message(format!(
                "Category named {new_name} already exists"
            ))));
        }
        *self.name.borrow_mut() = new_name.to_string();
        let parent_id = self.parent_id.get().expect("non-root category always has a parent id");
        let key = self.get_key();
        let owner = self.mgr.clone();
        let result = owner.borrow_mut().get_category_adapter().update_record(key, parent_id, new_name);
        if let Err(e) = result {
            owner.borrow().db_error(e);
        }
        owner.borrow_mut().category_renamed(old_path, self);
        Ok(())
    }

    fn get_categories(&self) -> Vec<Box<dyn Category>> {
        self.refresh_if_needed();
        let owner = self.mgr.clone();
        let ids = owner.borrow_mut().get_category_adapter().get_record_ids_with_parent(self.get_key());
        match ids {
            Ok(fields) => fields
                .into_iter()
                .filter_map(|f| owner.borrow().get_category(f.get_long_value()))
                .collect(),
            Err(e) => {
                owner.borrow().db_error(e);
                Vec::new()
            }
        }
    }

    fn get_data_types(&self) -> Vec<Box<dyn DataType>> {
        self.refresh_if_needed();
        self.mgr.borrow().get_data_types_for_category_id(self.get_key())
    }

    fn get_data_types_by_base_name(&self, name: &str) -> Vec<Box<dyn DataType>> {
        self.refresh_if_needed();
        let base_name = Utils.get_name_without_conflict_for_name(name);
        self.get_data_types()
            .into_iter()
            .filter(|dt| Utils.get_name_without_conflict_for_name(&dt.get_name()) == base_name)
            .collect()
    }

    fn add_data_type(
        &mut self,
        dt: Box<dyn DataType>,
        handler: &dyn DataTypeConflictHandler,
    ) -> Box<dyn DataType> {
        if self.check_deleted().is_err() {
            return dt;
        }
        let cat_path = self.get_category_path();
        let mut dt = dt;
        if cat_path != dt.get_category_path() {
            let handle = CategoryOwnerHandle(self.mgr.clone());
            dt = dt.clone_data_type(&handle);
            // Can't fail here: `dt` was just freshly cloned, so it cannot collide with itself.
            let _ = dt.set_category_path(cat_path);
        }
        self.mgr.borrow_mut().resolve(dt, handler)
    }

    fn get_category(&self, name: &str) -> Option<Box<dyn Category>> {
        self.refresh_if_needed();
        self.get_categories().into_iter().find(|c| c.get_name() == name)
    }

    fn get_category_path(&self) -> CategoryPath {
        self.refresh_if_needed();
        if self.is_root() {
            return ROOT.clone();
        }
        let parent_id = self.parent_id.get().expect("non-root category always has a parent id");
        let parent = self
            .mgr
            .borrow()
            .get_category(parent_id)
            .expect("a non-root category's parent must exist");
        let name = self.name.borrow().clone();
        parent.get_category_path().extend(&[name.as_str()])
    }

    fn get_data_type(&self, name: &str) -> Option<Box<dyn DataType>> {
        self.refresh_if_needed();
        self.get_data_types().into_iter().find(|dt| dt.get_name() == name)
    }

    fn create_category(&mut self, name: &str) -> Result<Box<dyn Category>, InvalidNameException> {
        test_name(name)?;
        if self.check_deleted().is_err() {
            // Best-effort continue, as elsewhere in this crate (see module documentation).
        }
        if let Some(existing) = self.get_category(name) {
            return Ok(existing);
        }
        let owner = self.mgr.clone();
        let key = self.get_key();
        let created = owner.borrow_mut().get_category_adapter().create_category(name, key);
        match created {
            Ok(rec) => {
                let new_id = rec.get_key().get_long_value();
                let cat: Box<dyn Category> = Box::new(CategoryDb::new(owner.clone(), new_id, Some(key), name));
                owner.borrow_mut().category_created(cat.as_ref());
                Ok(cat)
            }
            Err(e) => {
                owner.borrow().db_error(e);
                // TODO(port): Java's `CategoryDB.createCategory` returns `null` here (having
                // reported the IOException via `dbError`), but `Category::create_category`'s
                // `Result<Box<dyn Category>, InvalidNameException>` has no slot for "no category,
                // no invalid name". Panicking documents the gap explicitly rather than
                // fabricating a category or silently misreporting success.
                panic!("database error creating category {name:?} under category {key}");
            }
        }
    }

    fn remove_category(&mut self, category_name: &str, monitor: &dyn TaskMonitor) -> bool {
        if self.check_deleted().is_err() {
            return false;
        }
        let Some(mut c) = self.get_category(category_name) else {
            return false;
        };
        for cat in c.get_categories() {
            if monitor.is_cancelled() {
                return false;
            }
            c.remove_category(&cat.get_name(), monitor);
        }

        let dts = c.get_data_types();
        let refs: Vec<&dyn DataType> = dts.iter().map(|d| d.as_ref()).collect();
        let owner = self.mgr.clone();
        if owner.borrow_mut().remove_all(&refs, monitor).is_err() {
            return false;
        }

        let child_id = c.get_id();
        let removed = owner.borrow_mut().get_category_adapter().remove_category(child_id);
        match removed {
            Ok(_) => {
                owner.borrow_mut().category_removed(self, category_name, child_id);
                true
            }
            Err(e) => {
                owner.borrow().db_error(e);
                false
            }
        }
    }

    fn remove_empty_category(&mut self, category_name: &str, monitor: &dyn TaskMonitor) -> bool {
        let _ = monitor;
        if self.check_deleted().is_err() {
            return false;
        }
        let Some(cat) = self.get_category(category_name) else {
            return false;
        };
        if !cat.get_categories().is_empty() || !cat.get_data_types().is_empty() {
            return false;
        }
        let owner = self.mgr.clone();
        let child_id = cat.get_id();
        let removed = owner.borrow_mut().get_category_adapter().remove_category(child_id);
        match removed {
            Ok(_) => {
                owner.borrow_mut().category_removed(self, category_name, child_id);
                true
            }
            Err(e) => {
                owner.borrow().db_error(e);
                false
            }
        }
    }

    fn move_category(
        &mut self,
        category: Box<dyn Category>,
        _monitor: &dyn TaskMonitor,
    ) -> Result<(), DuplicateNameException> {
        assert!(
            self.belongs_to_this_manager(category.as_ref()),
            "Category does not belong to my DataTypeManager"
        );

        let category_id = category.get_id();
        let category_name = category.get_name();
        let moved_original_path = category.get_category_path();

        if self.check_deleted().is_err() {
            return Ok(());
        }
        if self.get_category(&category_name).is_some() {
            return Err(DuplicateNameException::with_message(format!(
                "Category named {category_name} already exists"
            )));
        }
        let dest_category_path = self.get_category_path();
        assert!(
            !dest_category_path.is_ancestor_or_self(&moved_original_path),
            "Moved category is an ancestor of destination category!"
        );

        let key = self.get_key();
        let owner = self.mgr.clone();
        let result = owner
            .borrow_mut()
            .get_category_adapter()
            .update_record(category_id, key, &category_name);
        if let Err(e) = result {
            owner.borrow().db_error(e);
        }

        // Bind the lookup's result before touching `owner` again: `if let Some(x) =
        // owner.borrow().foo() { owner.borrow_mut()... }` would keep the first `Ref` guard alive
        // for the whole `if let` body (temporary lifetime extension), panicking on the nested
        // `borrow_mut()`.
        let moved = owner.borrow().get_category(category_id);
        if let Some(moved) = moved {
            owner.borrow_mut().category_moved(moved_original_path, moved.as_ref());
        }
        Ok(())
    }

    fn copy_category(
        &mut self,
        category: &dyn Category,
        handler: &dyn DataTypeConflictHandler,
        monitor: &dyn TaskMonitor,
    ) -> Box<dyn Category> {
        // TODO: source archive handling is not documented (mirrors the Java comment).
        let is_in_same_archive = self.belongs_to_this_manager(category);
        if self.check_deleted().is_err() {
            // Best-effort continue, as elsewhere in this crate (see module documentation).
        }
        let mut cat = self
            .create_category(&category.get_name())
            .expect("category name came from an existing category, so it is already valid");
        for sub in category.get_categories() {
            if monitor.is_cancelled() {
                return cat;
            }
            cat.copy_category(sub.as_ref(), handler, monitor);
        }
        let handle = CategoryOwnerHandle(self.mgr.clone());
        for dt in category.get_data_types() {
            if monitor.is_cancelled() {
                break;
            }
            let new_dt = if is_in_same_archive {
                dt.copy_data_type(&handle)
            } else {
                dt.clone_data_type(&handle)
            };
            cat.add_data_type(new_dt, handler);
        }
        cat
    }

    fn get_parent(&self) -> Option<Box<dyn Category>> {
        self.refresh_if_needed();
        let parent_id = self.parent_id.get()?;
        self.mgr.borrow().get_category(parent_id)
    }

    fn is_root(&self) -> bool {
        self.parent_id.get().is_none()
    }

    fn get_category_path_name(&self) -> String {
        self.get_category_path().get_path()
    }

    fn get_root(&self) -> Box<dyn Category> {
        self.mgr
            .borrow()
            .get_category(ROOT_CATEGORY_ID)
            .expect("root category must always exist")
    }

    fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
        Box::new(CategoryOwnerHandle(self.mgr.clone()))
    }

    fn move_data_type(
        &mut self,
        dt_type: Box<dyn DataType>,
        handler: &dyn DataTypeConflictHandler,
    ) -> Result<(), DataTypeDependencyException> {
        if self.check_deleted().is_err() {
            return Ok(());
        }
        let path = self.get_category_path();
        let mut moved_data_type = dt_type;
        let existing = self.get_data_type(&moved_data_type.get_name());
        match existing {
            Some(existing) => {
                match handler.resolve_conflict(moved_data_type.as_ref(), existing.as_ref()) {
                    ConflictResult::ReplaceExisting => {
                        // Replace the existing datatype with the moved one.
                        let result = self.mgr.borrow_mut().replace_data_type(existing.as_ref(), moved_data_type, true);
                        Self::propagate_replace_error(result)?;
                    }
                    ConflictResult::UseExisting => {
                        // Discard the moved datatype in favor of the existing one.
                        let result = self.mgr.borrow_mut().replace_data_type(moved_data_type.as_ref(), existing, false);
                        Self::propagate_replace_error(result)?;
                    }
                    ConflictResult::RenameAndAdd => {
                        let unused_name =
                            self.mgr.borrow().get_unused_conflict_name_in_category(&path, moved_data_type.as_ref());
                        let _ = moved_data_type.set_name_and_category(path, &unused_name);
                    }
                }
            }
            None => {
                let _ = moved_data_type.set_category_path(path);
            }
        }
        Ok(())
    }

    fn remove(&mut self, dt_type: &dyn DataType, monitor: &dyn TaskMonitor) -> bool {
        let _ = monitor;
        let path = self.get_category_path();
        assert!(
            dt_type.get_category_path() == path,
            "can't remove dataType from category that its not a member of!"
        );
        self.mgr.borrow_mut().remove(dt_type)
    }

    fn get_id(&self) -> i64 {
        self.get_key()
    }

    fn compare_to(&self, other: &dyn Category) -> std::cmp::Ordering {
        self.get_category_path().cmp(&other.get_category_path())
    }
}

impl CategoryDb {
    /// Converts the `Result` from a [`DataTypeManager::replace_data_type`] call in
    /// [`move_data_type`](Category::move_data_type) into the trait method's own `Result`,
    /// matching how Java's `moveDataType` lets `mgr.replaceDataType`'s
    /// `DataTypeDependencyException` propagate unmodified.
    ///
    /// `ReplaceDataTypeError::InvalidArgument` has no equivalent slot in
    /// `Result<(), DataTypeDependencyException>` (Java's `IllegalArgumentException` counterpart
    /// is unchecked and not expected at this call site); it is folded into a dependency exception
    /// carrying the original message rather than silently discarded.
    fn propagate_replace_error(
        result: Result<Box<dyn DataType>, ReplaceDataTypeError>,
    ) -> Result<(), DataTypeDependencyException> {
        match result {
            Ok(_) => Ok(()),
            Err(ReplaceDataTypeError::Dependency(d)) => Err(d),
            Err(ReplaceDataTypeError::InvalidArgument(msg)) => Err(DataTypeDependencyException::with_message(msg)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::rc::Weak;

    use crate::framework::db::{Field, FieldType, Schema};
    use crate::program::database::data::category_db_adapter::CategoryDBAdapter;
    use crate::program::model::data::data_type_conflict_handler::DEFAULT_HANDLER;
    use crate::util::exception::CancelledException;
    use crate::util::task::{DummyMonitor, TaskMonitor};
    use std::io;
    use std::sync::Arc;

    // ===================================================================================
    // In-memory `CategoryDBAdapter` test double.
    // ===================================================================================

    fn category_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Category ID".to_string(),
            vec![FieldType::String, FieldType::Long],
            vec!["Name".to_string(), "Parent ID".to_string()],
            vec![],
        ))
    }

    struct TestCategoryAdapter {
        records: BTreeMap<i64, DBRecord>,
        next_key: i64,
    }

    impl TestCategoryAdapter {
        fn new() -> Self {
            let mut adapter = TestCategoryAdapter { records: BTreeMap::new(), next_key: 1 };
            let mut root = DBRecord::new(category_schema(), Field::Long(Some(ROOT_CATEGORY_ID)));
            root.set_string(CATEGORY_NAME_COL, Some(String::new()));
            root.set_long(CATEGORY_PARENT_COL, -1);
            adapter.records.insert(ROOT_CATEGORY_ID, root);
            adapter
        }
    }

    impl CategoryDBAdapter for TestCategoryAdapter {
        fn get_record(&self, category_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.records.get(&category_id).cloned())
        }

        fn update_record(&mut self, category_id: i64, parent_category_id: i64, name: &str) -> io::Result<()> {
            if let Some(rec) = self.records.get_mut(&category_id) {
                rec.set_string(CATEGORY_NAME_COL, Some(name.to_string()));
                rec.set_long(CATEGORY_PARENT_COL, parent_category_id);
            }
            Ok(())
        }

        fn get_record_ids_with_parent(&self, category_id: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .values()
                .filter(|r| r.get_long(CATEGORY_PARENT_COL) == Some(category_id))
                .map(|r| r.get_key().clone())
                .collect())
        }

        fn create_category(&mut self, name: &str, parent_id: i64) -> io::Result<DBRecord> {
            let key = self.next_key;
            self.next_key += 1;
            let mut rec = DBRecord::new(category_schema(), Field::Long(Some(key)));
            rec.set_string(CATEGORY_NAME_COL, Some(name.to_string()));
            rec.set_long(CATEGORY_PARENT_COL, parent_id);
            self.records.insert(key, rec.clone());
            Ok(rec)
        }

        fn remove_category(&mut self, category_id: i64) -> io::Result<bool> {
            Ok(self.records.remove(&category_id).is_some())
        }

        fn get_root_record(&self) -> io::Result<DBRecord> {
            Ok(self.records.get(&ROOT_CATEGORY_ID).cloned().expect("root record always present"))
        }

        fn put_record(&mut self, record: &DBRecord) -> io::Result<()> {
            self.records.insert(record.get_key().get_long_value(), record.clone());
            Ok(())
        }

        fn get_record_count(&self) -> i32 {
            self.records.len() as i32
        }
    }

    // ===================================================================================
    // In-memory `MockDataType`.
    //
    // Every handle returned for a datatype that is actually *registered* in
    // `TestCategoryManager::data_types` shares the same `Arc<Mutex<DataTypeInner>>` as the
    // registry entry itself -- this mirrors a real `DataTypeDB`, where the object handed back to
    // callers *is* the persistent record, so mutating it (e.g. `CategoryDb::move_data_type`
    // calling `set_category_path`) is immediately visible to every other holder, including this
    // manager's own category-membership queries. A freshly-constructed `MockDataType` that has
    // not yet been resolved into the registry (e.g. a brand new datatype a test is about to add)
    // owns its own independent `Arc`, exactly as a transient (not-yet-added) `DataType` would in
    // Java.
    // ===================================================================================

    struct DataTypeInner {
        name: String,
        category_path: CategoryPath,
    }

    // `DataType: Send + Sync`, so the shared cell needs to be `Sync` -- `Rc`/`RefCell` do not
    // qualify -- even though these tests are single-threaded.
    struct MockDataType(std::sync::Arc<std::sync::Mutex<DataTypeInner>>);

    impl MockDataType {
        fn new(name: &str, category_path: CategoryPath) -> Self {
            MockDataType(std::sync::Arc::new(std::sync::Mutex::new(DataTypeInner {
                name: name.to_string(),
                category_path,
            })))
        }

        /// A second handle sharing the same underlying storage as `inner` -- see the section
        /// documentation above.
        fn handle(inner: &std::sync::Arc<std::sync::Mutex<DataTypeInner>>) -> Self {
            MockDataType(inner.clone())
        }
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.0.lock().unwrap().name.clone()
        }

        fn set_name(
            &mut self,
            name: &str,
        ) -> Result<(), crate::program::model::data::data_type::SetDataTypeNameError> {
            self.0.lock().unwrap().name = name.to_string();
            Ok(())
        }

        fn get_category_path(&self) -> CategoryPath {
            self.0.lock().unwrap().category_path.clone()
        }

        fn set_category_path(&mut self, path: CategoryPath) -> Result<(), DuplicateNameException> {
            self.0.lock().unwrap().category_path = path;
            Ok(())
        }

        fn set_name_and_category(
            &mut self,
            path: CategoryPath,
            name: &str,
        ) -> Result<(), crate::program::model::data::data_type::SetDataTypeNameError> {
            let mut guard = self.0.lock().unwrap();
            guard.category_path = path;
            guard.name = name.to_string();
            Ok(())
        }

        fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
            // Java's `dt.clone(mgr)` produces a new, independent identity -- not a shared one.
            Box::new(MockDataType::new(&self.get_name(), self.get_category_path()))
        }

        fn copy_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
            self.clone_data_type(dtm)
        }
    }

    // ===================================================================================
    // In-memory `CategoryOwner`/`DataTypeManager` test double.
    // ===================================================================================

    struct TestCategoryManager {
        self_handle: Weak<RefCell<TestCategoryManager>>,
        name: String,
        adapter: TestCategoryAdapter,
        data_types: Vec<std::sync::Arc<std::sync::Mutex<DataTypeInner>>>,
        /// Logs id-only descriptions of received notifications. Only `get_id()` is called on the
        /// passed `&dyn Category` (never `get_name()`/`get_category_path()`), because those
        /// re-borrow `self.mgr`'s `RefCell` -- which is already mutably borrowed for the
        /// duration of the call into this very method. See
        /// `module_manager_test_support::describe_group` for the same hazard, documented there
        /// first.
        notifications: Vec<String>,
        errors: Vec<String>,
    }

    fn new_test_manager(name: &str) -> Rc<RefCell<TestCategoryManager>> {
        Rc::new_cyclic(|weak| {
            RefCell::new(TestCategoryManager {
                self_handle: weak.clone(),
                name: name.to_string(),
                adapter: TestCategoryAdapter::new(),
                data_types: Vec::new(),
                notifications: Vec::new(),
                errors: Vec::new(),
            })
        })
    }

    fn as_owner(mgr: &Rc<RefCell<TestCategoryManager>>) -> Rc<RefCell<dyn CategoryOwner>> {
        mgr.clone() as Rc<RefCell<dyn CategoryOwner>>
    }

    fn root_category(mgr: &Rc<RefCell<TestCategoryManager>>) -> Box<dyn Category> {
        as_owner(mgr).borrow().get_category(ROOT_CATEGORY_ID).expect("root category must exist")
    }

    impl TestCategoryManager {
        fn upgrade(&self) -> Rc<RefCell<dyn CategoryOwner>> {
            self.self_handle.upgrade().expect("manager should still be alive") as Rc<RefCell<dyn CategoryOwner>>
        }
    }

    impl DataTypeManager for TestCategoryManager {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn set_name(&mut self, name: &str) -> Result<(), InvalidNameException> {
            if name.is_empty() {
                return Err(InvalidNameException::with_message("name must not be empty"));
            }
            self.name = name.to_string();
            Ok(())
        }

        fn get_category(&self, category_id: i64) -> Option<Box<dyn Category>> {
            let rec = self.adapter.get_record(category_id).ok().flatten()?;
            let parent = rec.get_long(CATEGORY_PARENT_COL).unwrap_or(-1);
            let name = rec.get_string(CATEGORY_NAME_COL).unwrap_or_default().to_string();
            Some(Box::new(CategoryDb::new(
                self.upgrade(),
                category_id,
                if parent < 0 { None } else { Some(parent) },
                &name,
            )))
        }

        fn resolve(
            &mut self,
            data_type: Box<dyn DataType>,
            handler: &dyn DataTypeConflictHandler,
        ) -> Box<dyn DataType> {
            let mut name = data_type.get_name();
            let path = data_type.get_category_path();
            loop {
                let clash = self
                    .data_types
                    .iter()
                    .find(|inner| {
                        let g = inner.lock().unwrap();
                        g.category_path == path && g.name == name
                    })
                    .cloned();
                let Some(existing) = clash else {
                    break;
                };
                let existing_dt = MockDataType::handle(&existing);
                match handler.resolve_conflict(data_type.as_ref(), &existing_dt) {
                    ConflictResult::UseExisting => {
                        return Box::new(existing_dt);
                    }
                    ConflictResult::ReplaceExisting => {
                        self.data_types.retain(|r| !std::sync::Arc::ptr_eq(r, &existing));
                        break;
                    }
                    ConflictResult::RenameAndAdd => {
                        name = format!("{name}.conflict");
                    }
                }
            }
            let inner = std::sync::Arc::new(std::sync::Mutex::new(DataTypeInner { name, category_path: path }));
            self.data_types.push(inner.clone());
            Box::new(MockDataType::handle(&inner))
        }

        fn remove(&mut self, data_type: &dyn DataType) -> bool {
            let name = data_type.get_name();
            let path = data_type.get_category_path();
            let before = self.data_types.len();
            self.data_types.retain(|inner| {
                let g = inner.lock().unwrap();
                !(g.name == name && g.category_path == path)
            });
            self.data_types.len() != before
        }

        fn replace_data_type(
            &mut self,
            existing_dt: &dyn DataType,
            replacement_dt: Box<dyn DataType>,
            update_category_path: bool,
        ) -> Result<Box<dyn DataType>, ReplaceDataTypeError> {
            let existing_name = existing_dt.get_name();
            let existing_path = existing_dt.get_category_path();
            self.data_types.retain(|inner| {
                let g = inner.lock().unwrap();
                !(g.name == existing_name && g.category_path == existing_path)
            });
            let mut replacement = replacement_dt;
            if update_category_path {
                let _ = replacement.set_name_and_category(existing_path, &existing_name);
            }
            let inner = std::sync::Arc::new(std::sync::Mutex::new(DataTypeInner {
                name: replacement.get_name(),
                category_path: replacement.get_category_path(),
            }));
            self.data_types.push(inner.clone());
            Ok(Box::new(MockDataType::handle(&inner)))
        }
    }

    impl CategoryOwner for TestCategoryManager {
        fn get_category_adapter(&mut self) -> &mut dyn CategoryDBAdapter {
            &mut self.adapter
        }

        fn get_data_types_for_category_id(&self, category_id: i64) -> Vec<Box<dyn DataType>> {
            let Some(path) = DataTypeManager::get_category(self, category_id).map(|c| c.get_category_path()) else {
                return Vec::new();
            };
            self.data_types
                .iter()
                .filter(|inner| inner.lock().unwrap().category_path == path)
                .map(|inner| Box::new(MockDataType::handle(inner)) as Box<dyn DataType>)
                .collect()
        }

        fn get_unused_conflict_name_in_category(&self, path: &CategoryPath, dt: &dyn DataType) -> String {
            let base = dt.get_name();
            let mut candidate = format!("{base}.conflict");
            let mut n = 0;
            let taken: std::collections::HashSet<String> = self
                .data_types
                .iter()
                .filter(|inner| &inner.lock().unwrap().category_path == path)
                .map(|inner| inner.lock().unwrap().name.clone())
                .collect();
            while taken.contains(&candidate) {
                n += 1;
                candidate = format!("{base}.conflict{n}");
            }
            candidate
        }

        fn category_created(&mut self, category: &dyn Category) {
            self.notifications.push(format!("created:{}", category.get_id()));
        }

        fn category_renamed(&mut self, _old_path: CategoryPath, category: &dyn Category) {
            self.notifications.push(format!("renamed:{}", category.get_id()));
        }

        fn category_removed(&mut self, _parent: &dyn Category, name: &str, category_id: i64) {
            self.notifications.push(format!("removed:{category_id}:{name}"));
        }

        fn category_moved(&mut self, _old_path: CategoryPath, category: &dyn Category) {
            self.notifications.push(format!("moved:{}", category.get_id()));
        }

        fn db_error(&self, error: io::Error) {
            // Interior mutability isn't available here since `db_error` takes `&self` (matching
            // `ModuleManager::db_error`); tests that need to observe an error use `errors`'s
            // `RefCell` twin instead. For a plain `Vec`, this would require `&mut self`, so this
            // mock simply drops the message -- no test below exercises the error path.
            let _ = error;
        }
    }

    // ===================================================================================
    // Tests.
    // ===================================================================================

    #[test]
    fn create_and_lookup_by_name_and_path() {
        let mgr = new_test_manager("MyManager");
        let mut root = root_category(&mgr);

        let child = root.create_category("structs").expect("create should succeed");
        assert_eq!(child.get_name(), "structs");
        assert_eq!(child.get_category_path().get_path(), "/structs");
        assert_eq!(root.get_category("structs").expect("lookup should find it").get_name(), "structs");

        let mut child2 = root.get_category("structs").unwrap();
        let grandchild = child2.create_category("nested").unwrap();
        assert_eq!(grandchild.get_category_path().get_path(), "/structs/nested");

        // Creating the same name again returns the existing category (same id), not a duplicate.
        let again = root.create_category("structs").unwrap();
        assert_eq!(again.get_id(), child.get_id());
    }

    #[test]
    fn create_category_rejects_empty_name() {
        let mgr = new_test_manager("Mgr");
        let mut root = root_category(&mgr);
        assert!(root.create_category("").is_err());
    }

    #[test]
    fn parent_child_navigation_both_directions() {
        let mgr = new_test_manager("Mgr");
        let mut root = root_category(&mgr);
        let child = root.create_category("a").unwrap();

        let parent = child.get_parent().expect("non-root category has a parent");
        assert!(parent.is_root());
        assert!(!child.is_root());

        let categories = root.get_categories();
        assert_eq!(categories.len(), 1);
        assert_eq!(categories[0].get_name(), "a");
        assert_eq!(categories[0].get_id(), child.get_id());
    }

    #[test]
    fn rename_updates_name_and_rejects_duplicate() {
        let mgr = new_test_manager("Mgr");
        let mut root = root_category(&mgr);
        let mut a = root.create_category("a").unwrap();
        let _b = root.create_category("b").unwrap();

        a.set_name("renamed").expect("rename should succeed");
        assert_eq!(a.get_name(), "renamed");
        assert!(root.get_category("a").is_none());
        assert!(root.get_category("renamed").is_some());

        let mut renamed_handle = root.get_category("renamed").unwrap();
        let err = renamed_handle.set_name("b").unwrap_err();
        assert!(matches!(err, SetCategoryNameError::Duplicate(_)));
        // The rejected rename must not have taken effect.
        assert_eq!(renamed_handle.get_name(), "renamed");
    }

    #[test]
    fn rename_root_delegates_to_manager_name() {
        let mgr = new_test_manager("OldName");
        let mut root = root_category(&mgr);
        assert_eq!(root.get_name(), "OldName");
        root.set_name("NewName").unwrap();
        assert_eq!(root.get_name(), "NewName");
        assert_eq!(mgr.borrow().get_name(), "NewName");
    }

    #[test]
    fn move_category_between_parents() {
        let mgr = new_test_manager("Mgr");
        let mut root = root_category(&mgr);
        let mut src = root.create_category("src").unwrap();
        let mut dest = root.create_category("dest").unwrap();
        let child = src.create_category("child").unwrap();

        let monitor = DummyMonitor;
        dest.move_category(child, &monitor).expect("move should succeed");

        assert!(src.get_category("child").is_none());
        let moved = dest.get_category("child").expect("moved child should now be under dest");
        assert_eq!(moved.get_category_path().get_path(), "/dest/child");
    }

    #[test]
    fn move_category_rejects_duplicate_name_at_destination() {
        let mgr = new_test_manager("Mgr");
        let mut root = root_category(&mgr);
        let mut src = root.create_category("src").unwrap();
        let mut dest = root.create_category("dest").unwrap();
        let _existing = dest.create_category("child").unwrap();
        let child = src.create_category("child").unwrap();

        let monitor = DummyMonitor;
        let err = dest.move_category(child, &monitor).unwrap_err();
        let _ = err; // DuplicateNameException
        // Original child is untouched.
        assert!(src.get_category("child").is_some());
    }

    #[test]
    #[should_panic(expected = "ancestor")]
    fn move_category_rejects_moving_into_own_descendant() {
        let mgr = new_test_manager("Mgr");
        let mut root = root_category(&mgr);
        let mut a = root.create_category("a").unwrap();
        let _b = a.create_category("b").unwrap();
        let mut b_handle = a.get_category("b").unwrap();

        let monitor = DummyMonitor;
        // Moving `a` into its own descendant `b` must be rejected.
        let _ = b_handle.move_category(a, &monitor);
    }

    #[test]
    fn data_type_membership_listing() {
        let mgr = new_test_manager("Mgr");
        let mut root = root_category(&mgr);
        let mut cat = root.create_category("structs").unwrap();

        let dt = Box::new(MockDataType::new("Foo", CategoryPath::parse("/other").unwrap()));
        let added = cat.add_data_type(dt, &DEFAULT_HANDLER);
        assert_eq!(added.get_name(), "Foo");
        assert_eq!(added.get_category_path(), cat.get_category_path());

        let listed = cat.get_data_types();
        assert_eq!(listed.len(), 1);
        assert_eq!(cat.get_data_type("Foo").unwrap().get_name(), "Foo");
        assert!(cat.get_data_type("Bar").is_none());

        let by_base = cat.get_data_types_by_base_name("Foo");
        assert_eq!(by_base.len(), 1);
    }

    #[test]
    fn remove_data_type_from_category() {
        let mgr = new_test_manager("Mgr");
        let mut root = root_category(&mgr);
        let mut cat = root.create_category("structs").unwrap();
        let dt = Box::new(MockDataType::new("Foo", CategoryPath::parse("/other").unwrap()));
        let added = cat.add_data_type(dt, &DEFAULT_HANDLER);

        let monitor = DummyMonitor;
        assert!(cat.remove(added.as_ref(), &monitor));
        assert!(cat.get_data_types().is_empty());
    }

    #[test]
    fn remove_category_deletes_recursively() {
        let mgr = new_test_manager("Mgr");
        let mut root = root_category(&mgr);
        let mut parent = root.create_category("parent").unwrap();
        let _child = parent.create_category("child").unwrap();

        let monitor = DummyMonitor;
        // Not empty (has a subcategory), so `remove_empty_category` refuses.
        assert!(!root.remove_empty_category("parent", &monitor));
        assert!(root.remove_category("parent", &monitor));
        assert!(root.get_category("parent").is_none());
    }

    #[test]
    fn remove_empty_category_succeeds_when_truly_empty() {
        let mgr = new_test_manager("Mgr");
        let mut root = root_category(&mgr);
        let _leaf = root.create_category("leaf").unwrap();

        let monitor = DummyMonitor;
        assert!(root.remove_empty_category("leaf", &monitor));
        assert!(root.get_category("leaf").is_none());
    }

    #[test]
    fn remove_nonexistent_category_returns_false() {
        let mgr = new_test_manager("Mgr");
        let mut root = root_category(&mgr);
        let monitor = DummyMonitor;
        assert!(!root.remove_category("nope", &monitor));
        assert!(!root.remove_empty_category("nope", &monitor));
    }

    #[test]
    fn compare_to_orders_by_category_path() {
        let mgr = new_test_manager("Mgr");
        let mut root = root_category(&mgr);
        let a = root.create_category("a").unwrap();
        let b = root.create_category("b").unwrap();
        assert_eq!(a.compare_to(b.as_ref()), std::cmp::Ordering::Less);
        assert_eq!(b.compare_to(a.as_ref()), std::cmp::Ordering::Greater);
        assert_eq!(root.compare_to(root.as_ref()), std::cmp::Ordering::Equal);
    }

    #[test]
    fn get_root_and_get_category_path_name() {
        let mgr = new_test_manager("Mgr");
        let mut root = root_category(&mgr);
        let child = root.create_category("a").unwrap();
        let grandchild = {
            let mut c = root.get_category("a").unwrap();
            c.create_category("b").unwrap()
        };

        assert!(child.get_root().is_root());
        assert_eq!(grandchild.get_category_path_name(), "/a/b");
        assert_eq!(root.get_id(), ROOT_CATEGORY_ID);
    }

    #[test]
    fn move_data_type_renames_on_conflict() {
        let mgr = new_test_manager("Mgr");
        let mut root = root_category(&mgr);
        let mut src = root.create_category("src").unwrap();
        let mut dest = root.create_category("dest").unwrap();

        let existing = Box::new(MockDataType::new("Foo", dest.get_category_path()));
        dest.add_data_type(existing, &DEFAULT_HANDLER);

        let moved = Box::new(MockDataType::new("Foo", src.get_category_path()));
        let moved = src.add_data_type(moved, &DEFAULT_HANDLER);

        dest.move_data_type(moved, &DEFAULT_HANDLER).expect("move should succeed");

        // DEFAULT_HANDLER renames-and-adds on conflict, so both "Foo" and "Foo.conflict" exist.
        let names: Vec<String> = dest.get_data_types().iter().map(|dt| dt.get_name()).collect();
        assert!(names.contains(&"Foo".to_string()));
        assert!(names.iter().any(|n| n.starts_with("Foo.conflict")));
    }

    #[test]
    fn move_data_type_into_empty_category_just_recategorizes() {
        let mgr = new_test_manager("Mgr");
        let mut root = root_category(&mgr);
        let mut src = root.create_category("src").unwrap();
        let mut dest = root.create_category("dest").unwrap();

        let dt = Box::new(MockDataType::new("Foo", src.get_category_path()));
        let dt = src.add_data_type(dt, &DEFAULT_HANDLER);

        dest.move_data_type(dt, &DEFAULT_HANDLER).unwrap();
        assert_eq!(dest.get_data_types().len(), 1);
        assert_eq!(dest.get_data_types()[0].get_category_path(), dest.get_category_path());
    }

    #[test]
    fn copy_category_recursively_copies_children_and_data_types() {
        let mgr = new_test_manager("Mgr");
        let mut root = root_category(&mgr);
        let mut source = root.create_category("source").unwrap();
        let _sub = source.create_category("sub").unwrap();
        let dt = Box::new(MockDataType::new("Foo", source.get_category_path()));
        source.add_data_type(dt, &DEFAULT_HANDLER);

        let mut dest_parent = root.create_category("dest_parent").unwrap();
        let monitor = DummyMonitor;
        let copy = dest_parent.copy_category(source.as_ref(), &DEFAULT_HANDLER, &monitor);

        assert_eq!(copy.get_name(), "source");
        assert_eq!(copy.get_category_path().get_path(), "/dest_parent/source");
        assert!(copy.get_category("sub").is_some());
        assert_eq!(copy.get_data_types().len(), 1);
        assert_eq!(copy.get_data_types()[0].get_name(), "Foo");

        // The original is untouched.
        assert!(source.get_category("sub").is_some());
        assert_eq!(source.get_data_types().len(), 1);
    }

    #[test]
    fn usable_as_trait_object() {
        let mgr = new_test_manager("Mgr");
        let root = root_category(&mgr);
        let dyn_cat: &dyn Category = root.as_ref();
        assert!(dyn_cat.is_root());
        assert_eq!(dyn_cat.get_id(), ROOT_CATEGORY_ID);
    }

    // Silence "unused" warnings for the notification/error logs -- they exist so future tests
    // (or a debugger) can inspect manager-side call-backs, mirroring
    // `MockModuleManager::notifications`.
    #[test]
    fn manager_receives_creation_and_removal_notifications() {
        let mgr = new_test_manager("Mgr");
        let mut root = root_category(&mgr);
        let cat = root.create_category("a").unwrap();
        let id = cat.get_id();
        let monitor = DummyMonitor;
        assert!(root.remove_empty_category("a", &monitor));

        let notifications = mgr.borrow().notifications.clone();
        assert!(notifications.contains(&format!("created:{id}")));
        assert!(notifications.iter().any(|n| n.starts_with(&format!("removed:{id}:"))));
        assert!(mgr.borrow().errors.is_empty());
    }

    #[test]
    fn cancelled_monitor_stops_recursive_remove() {
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
                Err(CancelledException::default())
            }
            fn increment_progress(&self, _amount: i64) {}
            fn get_progress(&self) -> i64 {
                0
            }
            fn cancel(&self) {}
            fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
            fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
            fn set_cancel_enabled(&self, _enabled: bool) {}
            fn is_cancel_enabled(&self) -> bool {
                false
            }
            fn clear_cancelled(&self) {}
        }

        let mgr = new_test_manager("Mgr");
        let mut root = root_category(&mgr);
        let mut parent = root.create_category("parent").unwrap();
        let _child = parent.create_category("child").unwrap();

        let monitor = CancelledMonitor;
        assert!(!root.remove_category("parent", &monitor));
        // Nothing was actually removed since the monitor was already cancelled.
        assert!(root.get_category("parent").is_some());
    }
}
