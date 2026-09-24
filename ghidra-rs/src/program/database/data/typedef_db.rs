//! Port of `ghidra.program.database.data.TypedefDB`, the database-backed implementation of
//! [`TypeDef`].
//!
//! `TypedefDB` is a `TypeDef` whose identity, name, category, and referenced-type-id all live in
//! a database record rather than in plain fields, in contrast to the already-ported, in-memory
//! [`TypedefDataType`](crate::program::model::data::typedef_data_type::TypedefDataType). In Java
//! it `extends DataTypeDB` (a not-yet-concretely-implemented abstract base shared by every
//! DB-backed datatype family member) and holds a direct `TypedefDBAdapter` field plus a
//! back-reference to the owning `DataTypeManagerDB`.
//!
//! # Base trait: [`DataTypeDb`]
//!
//! [`DataTypeDb`](super::data_type_db::DataTypeDb) is a real (not placeholder) port of
//! `DataTypeDB`'s caching/hashing/equality contract, already landed in this crate as a
//! dependency-cycle cut-point but -- until this port -- never implemented by a concrete type.
//! [`TypedefDb`] is its first concrete implementor: `do_get_name`/`do_get_category_id`/
//! `do_set_category_path_record`/`do_set_name_record`/`get_source_archive_id`/
//! `set_source_archive_id`/`is_equivalent_with_handler`/`set_universal_id` are all real, and
//! `get_name`/`get_category_path`/`get_data_type_path`/`set_name`/`get_alignment`/`is_deleted`
//! all delegate to the trait's caching `data_type_db_*` wrappers rather than reimplementing that
//! logic here, exactly as intended (`TypedefDB.java` itself never overrides most of these).
//!
//! # Owner storage: `Arc<Mutex<dyn DataTypeManagerDb + Send>>`, not `Rc<RefCell<...>>`
//!
//! [`CategoryDb`](super::category_db::CategoryDb) -- the most recent precedent for "a concrete,
//! database-backed model object that reaches back into its not-yet-concretely-ported owning
//! manager" -- composes its `CategoryOwner` seam behind `Rc<RefCell<dyn CategoryOwner>>`, since
//! [`Category`](crate::program::model::data::category::Category) carries no `Send`/`Sync` bound.
//! [`TypeDef`]: [`DataType`], is bound `Send + Sync`, so that composition is unavailable here --
//! `Rc`/`RefCell` are neither. This port instead stores
//! `Arc<Mutex<dyn DataTypeManagerDb + Send>>`: the `+ Send` marker on the trait object (rather
//! than adding a bound to [`DataTypeManagerDb`] itself, which has other, non-`Send` test
//! implementors already in this crate) is exactly enough for `Mutex<...>` to become `Sync`
//! (`Mutex<T>: Sync` requires only `T: Send`), and therefore for the whole `Arc<Mutex<...>>` to be
//! `Send + Sync` as [`DataType`] requires.
//!
//! No new seam trait (a `TypedefOwner`, mirroring
//! [`CategoryOwner`](super::category_owner::CategoryOwner)) was needed: unlike `CategoryDB`,
//! every manager capability `TypedefDB.java` actually calls (`getDataType(long)`, `resolve`,
//! `getResolvedID`, `getCategory`, `getRootCategory`, `createCategory`, `getDataType(path,name)`,
//! `dbError`, `addDataTypeToDelete`, `dataTypeChanged`) is already present on the already-ported
//! [`DataTypeManager`]/[`DataTypeManagerDb`] traits, so `dyn DataTypeManagerDb + Send` is used
//! directly.
//!
//! Because interior mutability now comes from a real `Mutex` (not the borrow-checked `RefCell`
//! `CategoryDb` uses), and because `TypedefDB.java`'s own `setCategoryPath`/`setNameAndCategory`
//! override calls `dataMgr.createCategory(path)` (a `&mut self` manager call), this port is able
//! to give a full, real implementation of the inherited `DataTypeDB.setCategoryPath`/
//! `doSetCategoryPath` logic ([`TypedefDb::base_set_category_path`]) that the shared
//! [`DataTypeDb`] cut-point trait deliberately leaves unported (its own module docs explain why a
//! generic cut-point trait can't assume `&mut` access to its `Arc<dyn DataTypeManagerDb>`).
//!
//! `owning_data_type_manager` must still return the trait-mandated `Arc<dyn DataTypeManagerDb>`
//! (not `Arc<Mutex<dyn DataTypeManagerDb + Send>>`), so [`TypedefDbOwnerHandle`] -- a small owned
//! forwarding wrapper constructed fresh on each call -- adapts between the two, mirroring
//! [`CategoryDb`]'s own `CategoryOwnerHandle` fix for the identical "hand back an owned value, not
//! an unsound borrowed pointer" problem (see `category_db.rs`'s module docs, and
//! `module_db.rs`'s for the original instance of this fix). Only the handful of `&self` methods
//! [`DataTypeDb`]'s own default methods actually call are given a working override; the rest fall
//! back to [`DataTypeManager`]'s defaults, since nothing in this port's actual call paths ever
//! invokes an `owning_data_type_manager()`-obtained handle's `&mut self` methods (which
//! couldn't be called through a shared `Arc<dyn DataTypeManagerDb>` in any case -- `TypedefDb`'s
//! own methods instead lock `self.owner` directly whenever `&mut` access is genuinely needed).
//!
//! # Adapter storage: a direct field, not routed through the owner
//!
//! Unlike `CategoryDB` (whose adapter is reached via `mgr.getCategoryDBAdapter()`), Java's
//! `TypedefDB` constructor is hand *directly* a `TypedefDBAdapter` reference, independent of
//! `dataMgr`. This port mirrors that: `adapter: Arc<Mutex<dyn TypedefDBAdapter + Send>>` is a
//! field alongside `owner`, not something reached through it.
//!
//! # Deliberate simplifications and omissions
//!
//! - **No `settingsDef` cache.** Java lazily caches the combined settings-definitions array in a
//!   `settingsDef` field, invalidated on `refresh()`. `Vec<Box<dyn SettingsDefinition>>` isn't
//!   `Clone`, so a cached copy can't be handed out more than once from a `&self` method; this port
//!   simply recomputes it on every [`DataType::get_settings_definitions`] call, which is always
//!   correct (there is no staleness window) at the cost of the dropped performance optimization --
//!   the same tradeoff [`CategoryDb`]'s module docs make for its own dropped caches.
//! - **`doGetDefaultSettings`/local settings overrides are not portable yet.** Java's
//!   `doGetDefaultSettings()` constructs a `DataTypeSettingsDB` (a real, DB-backed per-instance
//!   settings-override store) that has not been ported in this crate (only the lower-level
//!   `SettingDB`/`SettingsDBAdapter` pieces exist so far -- see `setting_db.rs`). Without it,
//!   [`TypedefDb`] has no way to persist a *local* override of a type-def setting.
//!   [`DataType::get_default_settings`] is overridden to at least return the referenced type's own
//!   default settings (`getDataType().getDefaultSettings()`, the tail of Java's real fallback
//!   chain) rather than falling all the way back to the crate-wide empty-settings placeholder --
//!   more faithful than doing nothing, but still a documented, partial port.
//!   `// TODO(port): DataTypeSettingsDB` marks the exact gap.
//! - **The parent/child `notify*` broadcast family is not ported**, for the same reason
//!   [`DataTypeImpl`](crate::program::model::data::data_type_impl::DataTypeImpl)'s and
//!   [`TypedefDataType`](crate::program::model::data::typedef_data_type::TypedefDataType)'s own
//!   module docs give: it needs `dataMgr.getParentDataTypes(key)`, which does not exist on
//!   [`DataTypeManager`]/[`DataTypeManagerDb`] yet. Every call site that would invoke
//!   `notifySizeChanged`/`notifyAlignmentChanged`/`notifyNameChanged` instead performs only the
//!   part of that method it safely can (the direct `dataMgr.dataTypeChanged(...)`/no-op), noted at
//!   each site. `addParent`/`removeParent`/`getParents` are left at [`DataType`]'s own no-op/empty
//!   defaults for the same reason (needs `dataMgr.addParentChildRecord`/`getParentDataTypes`).
//! - **Reference-identity checks are approximated.** Java's `dt == this`/`dt == getDataType()`
//!   checks have no equivalent for a `dyn DataType` trait object; per the established convention
//!   (see `typedef_data_type.rs`'s and `default_data_type.rs`'s own module docs), `dt == this` is
//!   approximated with a raw-pointer comparison and `dt == getDataType()` with
//!   [`DataType::is_equivalent`] checked in both directions.
//! - **`isNameUnusedOrMine`'s `dt == this` check** is approximated by comparing the *candidate*
//!   `(path, name)` against this typedef's own *current* `(path, name)`: a lookup by a candidate
//!   name can only ever find "this" object (before this object's own record has been updated to
//!   that candidate) if the candidate happens to equal what is already on record.
//! - **`DataType::data_type_replaced`'s borrowed `new_dt: &dyn DataType` parameter** can't be
//!   turned into the *owned* `Box<dyn DataType>` that `DataTypeManager::resolve`/`get_resolved_id`
//!   require -- the same borrow-vs-owned gap `typedef_data_type.rs` documents for
//!   `TypedefDataType::data_type_replaced`. The trait method here performs the validation and
//!   identity check it can; [`TypedefDb::replace_referenced_data_type`] is the owned-parameter
//!   equivalent that performs the real swap, for composing callers that hold an owned replacement.
//! - **`clone`/`copy` approximate, rather than call, `TypedefDataType`'s static
//!   `clone(TypeDef, DataTypeManager)`/`copy(TypeDef, DataTypeManager)` helpers.** Those helpers
//!   are only ported in this crate specialized to a `&TypedefDataType` source (see
//!   `typedef_data_type.rs`), so [`DataType::clone_data_type`]/[`DataType::copy_data_type`] here
//!   instead materialize a fresh in-memory `TypedefDataType` directly from this typedef's own
//!   state. Per-instance type-def-setting overrides are not carried over (the same
//!   `DataTypeSettingsDB` gap noted above means there is nothing local to copy yet).
//! - **`DataType.DEFAULT`** (the `DefaultDataType` singleton `getDataType()` falls back to when
//!   its referenced-type id no longer resolves) has no ported singleton to reuse yet (see
//!   `default_data_type.rs`'s module docs: only the trait exists, no concrete instance).MissingDataType`,
//!   a minimal private stand-in, is used instead.
//! - **`updatePath`** is ported as a real, working method
//!   ([`TypedefDb::update_path`]) but is not currently reachable from anywhere in this crate:
//!   `DataTypeManagerDB`'s propagation of a datatype's path change to its dependents is not yet
//!   ported. It is kept, public, for whichever future manager port needs to call it.

use std::io;
use std::sync::{Arc, Mutex};

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::framework::db::{DBRecord, Field};
use crate::program::database::data::data_type_manager_db::DataTypeManagerDb;
use crate::program::database::data::data_type_utilities::DataTypeUtilities;
use crate::program::database::data::typedef_db_adapter::{
    TypedefDBAdapter, TYPEDEF_CAT_COL, TYPEDEF_DT_ID_COL, TYPEDEF_FLAGS_COL,
    TYPEDEF_FLAG_AUTONAME, TYPEDEF_LAST_CHANGE_TIME_COL, TYPEDEF_NAME_COL,
    TYPEDEF_SOURCE_ARCHIVE_ID_COL, TYPEDEF_SOURCE_SYNC_TIME_COL, TYPEDEF_UNIVERSAL_DT_ID_COL,
};
use crate::program::database::data::data_type_db::DataTypeDb;
use crate::program::database::db_object::{DbObject, DbObjectState};
use crate::program::model::data::category::Category;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::{DataType, SetDataTypeNameError, CONFLICT_SUFFIX};
use crate::program::model::data::data_type_conflict_handler::{
    ConflictResult, DataTypeConflictHandler, DefaultHandlerImpl,
};
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_type_path::DataTypePath;
use crate::program::model::data::source_archive::SourceArchive;
use crate::program::model::data::typedef::TypeDef;
use crate::program::model::data::typedef_data_type::TypedefDataType;
use crate::program::model::data::typedef_settings_definition::TypeDefSettingsDefinition;
use crate::program::model::mem::MemBuffer;
use crate::util::exception::{DuplicateNameException, InvalidNameException};
use crate::util::lock::ReentrantLock;
use crate::util::UniversalID;

/// A dummy zero-sized receiver used purely to invoke [`DataTypeUtilities`]'s default methods, per
/// the convention already established throughout `program/database/data` (see e.g.
/// `category_db.rs`, `typedef_data_type.rs`).
#[derive(Debug, Default, Clone, Copy)]
struct Utils;
impl DataTypeUtilities for Utils {}
impl crate::program::model::data::data_utilities::DataUtilities for Utils {}

/// Minimal stand-in for the not-yet-ported `DataType.DEFAULT` singleton. See the module docs.
struct MissingDataType;
impl DataType for MissingDataType {
    fn get_name(&self) -> String {
        "undefined".to_string()
    }
    fn get_length(&self) -> i32 {
        1
    }
    fn is_default_data_type(&self) -> bool {
        true
    }
}

/// Owned forwarding wrapper letting [`TypedefDb::owning_data_type_manager`] hand back the
/// trait-mandated `Arc<dyn DataTypeManagerDb>` from this struct's `Arc<Mutex<...>>` storage,
/// rather than reaching for an unsound borrowed-pointer trick. See the module documentation.
struct TypedefDbOwnerHandle(Arc<Mutex<dyn DataTypeManagerDb + Send>>);

impl DataTypeManager for TypedefDbOwnerHandle {
    fn get_universal_id(&self) -> UniversalID {
        self.0.lock().unwrap().get_universal_id()
    }
    fn get_category(&self, category_id: i64) -> Option<Box<dyn Category>> {
        self.0.lock().unwrap().get_category(category_id)
    }
    fn get_root_category(&self) -> Box<dyn Category> {
        self.0.lock().unwrap().get_root_category()
    }
    fn get_data_type_in_category(&self, path: &CategoryPath, name: &str) -> Option<Box<dyn DataType>> {
        self.0.lock().unwrap().get_data_type_in_category(path, name)
    }
    fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
        self.0.lock().unwrap().get_data_organization()
    }
}

impl DataTypeManagerDb for TypedefDbOwnerHandle {
    fn db_error(&mut self, error: io::Error) {
        self.0.lock().unwrap().db_error(error);
    }
    fn add_data_type_to_replace(&mut self, data_type_id: i64, replacement: Box<dyn DataType>) {
        self.0.lock().unwrap().add_data_type_to_replace(data_type_id, replacement);
    }
    fn add_data_type_to_delete(&mut self, data_type_id: i64) {
        self.0.lock().unwrap().add_data_type_to_delete(data_type_id);
    }
}

/// Database implementation of [`TypeDef`].
///
/// Port of `ghidra.program.database.data.TypedefDB`. See the module documentation for what was
/// ported, deliberately simplified, or omitted.
pub struct TypedefDb {
    db_state: DbObjectState,
    lock: Arc<ReentrantLock>,
    owner: Arc<Mutex<dyn DataTypeManagerDb + Send>>,
    adapter: Arc<Mutex<dyn TypedefDBAdapter + Send>>,
    record: Mutex<DBRecord>,
    stored_name: Mutex<Option<String>>,
    stored_category_path: Mutex<Option<CategoryPath>>,
    stored_deleting: Mutex<bool>,
}

impl TypedefDb {
    /// Constructs a typedef view over `record`, backed by `owner` and `adapter`.
    ///
    /// Port of `TypedefDB(DataTypeManagerDB, TypedefDBAdapter, DBRecord)`. `lock` stands in for
    /// the shared `dataMgr.lock` field -- see [`DataTypeDb::lock`]'s documentation.
    pub fn new(
        owner: Arc<Mutex<dyn DataTypeManagerDb + Send>>,
        adapter: Arc<Mutex<dyn TypedefDBAdapter + Send>>,
        lock: Arc<ReentrantLock>,
        record: DBRecord,
    ) -> Self {
        let key = record.get_key().get_long_value();
        TypedefDb {
            db_state: DbObjectState::new(key),
            lock,
            owner,
            adapter,
            record: Mutex::new(record),
            stored_name: Mutex::new(None),
            stored_category_path: Mutex::new(None),
            stored_deleting: Mutex::new(false),
        }
    }

    fn get_flags(&self) -> i16 {
        match self.record.lock().unwrap().get_field(TYPEDEF_FLAGS_COL) {
            Field::Short(Some(v)) => *v,
            _ => 0,
        }
    }

    fn set_flags(&self, flags: i16) {
        self.record.lock().unwrap().set_field(TYPEDEF_FLAGS_COL, Field::Short(Some(flags)));
    }

    /// Persists the current in-memory record via the adapter, reporting any failure to the owning
    /// manager. Stands in for the repeated `try { adapter.updateRecord(record, ...); } catch
    /// (IOException e) { dataMgr.dbError(e); }` pattern used throughout `TypedefDB.java`.
    fn persist_record(&self, set_last_change_time: bool) -> io::Result<()> {
        let rec = self.record.lock().unwrap().clone();
        match self.adapter.lock().unwrap().update_record(&rec, set_last_change_time) {
            Ok(()) => Ok(()),
            Err(e) => {
                let io_err = io::Error::new(e.kind(), e.to_string());
                self.owner.lock().unwrap().db_error(io_err);
                Err(e)
            }
        }
    }

    /// Stands in for the private `TypedefDB.isNameUnusedOrMine(CategoryPath, String)`. See the
    /// module docs for how the `dt == this` reference-identity check is approximated.
    fn is_name_unused_or_mine(&self, path: &CategoryPath, new_name: &str) -> bool {
        let found = self.owner.lock().unwrap().get_data_type_in_category(path, new_name);
        match found {
            None => true,
            Some(_) => {
                *path == self.data_type_db_get_category_path()
                    && new_name == self.data_type_db_get_name()
            }
        }
    }

    /// Stands in for the private `TypedefDB.generateTypedefName(CategoryPath)`.
    fn generate_typedef_name(&self, path: &CategoryPath) -> String {
        let base_name = TypedefDataType::generate_typedef_name(self);
        let mut test_name = base_name.clone();
        let mut count = 0i32;
        while !self.is_name_unused_or_mine(path, &test_name) {
            test_name = format!("{base_name}{CONFLICT_SUFFIX}");
            if count > 0 {
                test_name.push_str(&count.to_string());
            }
            count += 1;
        }
        test_name
    }

    /// Stands in for the inherited `DataTypeDB.setCategoryPath(CategoryPath)`/private
    /// `doSetCategoryPath(CategoryPath)` (Java's `super.setCategoryPath`), which
    /// [`TypedefDb`]'s own [`DataType::set_category_path`] override bypasses while auto-naming is
    /// enabled. `dataMgr.dataTypeCategoryPathChanged(...)` (a dependent-notification hook not yet
    /// ported -- see the module docs) is omitted; the record and cached path are still updated
    /// for real.
    fn base_set_category_path(&self, path: CategoryPath) -> Result<(), DuplicateNameException> {
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return Ok(());
        }
        if self.data_type_db_get_category_path() == path {
            return Ok(());
        }
        let current_name = self.data_type_db_get_name();
        if self
            .owner
            .lock()
            .unwrap()
            .get_data_type_in_category(&path, &current_name)
            .is_some()
        {
            return Err(DuplicateNameException(format!(
                "DataType named {current_name} already exists in category {}",
                path.get_path()
            )));
        }
        let my_path = self.data_type_db_get_category_path();
        if path == my_path {
            return Ok(());
        }
        let cat = self.owner.lock().unwrap().create_category(&path);
        let cat_id = cat.get_id();
        if let Err(e) = self.do_set_category_path_record(cat_id) {
            self.owner.lock().unwrap().db_error(e);
            return Ok(());
        }
        self.set_stored_category_path(Some(cat.get_category_path()));
        Ok(())
    }

    /// Stands in for the package-private `TypedefDB.updateAutoName(boolean)`.
    fn update_auto_name(&self, notify: bool) -> bool {
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return false;
        }
        if !TypeDef::is_auto_named(self) {
            return false;
        }
        let old_name = self.data_type_db_get_name();
        let new_name = self.generate_typedef_name(&self.data_type_db_get_category_path());
        if old_name == new_name {
            return false;
        }
        {
            let mut rec = self.record.lock().unwrap();
            rec.set_string(TYPEDEF_NAME_COL, Some(new_name));
        }
        let _ = self.persist_record(false);
        self.data_type_db_refresh_name();
        // `notifyNameChanged(oldName)` intentionally omitted -- see the module docs.
        let _ = notify;
        true
    }

    /// Stands in for the protected `TypedefDB.updatePath(DataTypeDB)`: called when `dt` (this
    /// typedef's referenced data type) has had its category path changed, so an auto-named
    /// typedef can follow it. See the module docs for why nothing in this crate calls this yet.
    pub fn update_path(&self, dt: &dyn DataType) {
        if !TypeDef::is_auto_named(self) {
            return;
        }
        let current = TypeDef::get_data_type(self);
        if !current.is_equivalent(dt) && !dt.is_equivalent(current.as_ref()) {
            return;
        }
        let _guard = self.lock.write();
        let old_path = self.data_type_db_get_category_path();
        let current_path = dt.get_category_path();
        if current_path == old_path {
            return;
        }
        let old_name = self.data_type_db_get_name();
        let new_name = self.generate_typedef_name(&current_path);
        let name_changed = new_name != old_name;
        if name_changed {
            {
                let mut rec = self.record.lock().unwrap();
                rec.set_string(TYPEDEF_NAME_COL, Some(new_name));
            }
            self.data_type_db_refresh_name();
        }
        let _ = self.base_set_category_path(current_path);
        // `notifyNameChanged(oldName)` intentionally omitted -- see the module docs.
    }

    /// Owned-parameter equivalent of [`DataType::data_type_replaced`], able to actually persist
    /// the swap (the trait method cannot -- see its doc comment and the module docs).
    ///
    /// Port of the body of `TypedefDB.dataTypeReplaced(DataType, DataType)`.
    pub fn replace_referenced_data_type(&self, new_dt: Box<dyn DataType>) {
        if self.stored_deleting() {
            return;
        }
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return;
        }
        let old_dt = TypeDef::get_data_type(self);
        if Utils.check_valid_replacement(old_dt.as_ref(), new_dt.as_ref()).is_err() {
            return;
        }
        let mut new_dt = new_dt;
        if std::ptr::eq(
            self as *const Self as *const (),
            new_dt.as_ref() as *const dyn DataType as *const (),
        ) {
            new_dt = Box::new(MissingDataType);
        }
        let resolved = self.owner.lock().unwrap().resolve(new_dt, &DefaultHandlerImpl);
        let resolved_id = self.owner.lock().unwrap().get_resolved_id(resolved.as_ref());
        {
            let mut rec = self.record.lock().unwrap();
            rec.set_long(TYPEDEF_DT_ID_COL, resolved_id);
        }
        let _ = self.persist_record(true);
        // `notifySizeChanged`/`notifyAlignmentChanged`'s parent-broadcast loops are omitted (see
        // the module docs); once dropped, all three of Java's branches (size changed / alignment
        // changed / neither) collapse to the same `dataMgr.dataTypeChanged(this, false)` call.
        self.owner.lock().unwrap().data_type_changed(self, false);
    }

    /// Materializes a fresh, in-memory [`TypedefDataType`] snapshot of this typedef's current
    /// state. Shared implementation for [`DataType::clone_data_type`]/[`DataType::copy_data_type`]
    /// -- see the module docs for why the real `TypedefDataType.clone`/`copy(TypeDef,
    /// DataTypeManager)` statics can't be called directly.
    fn materialize(&self, fresh_identity: bool) -> TypedefDataType {
        let data_type = TypeDef::get_data_type(self);
        let mut result = if fresh_identity {
            TypedefDataType::new(self.get_category_path(), self.get_name(), data_type)
        } else {
            TypedefDataType::with_archive_identity(
                self.get_category_path(),
                self.get_name(),
                data_type,
                self.get_universal_id(),
                self.get_source_archive().as_deref(),
                self.get_last_change_time(),
                self.get_last_change_time_in_source_archive(),
            )
        }
        .expect("this typedef's own referenced data type must be a valid typedef base");
        if TypeDef::is_auto_named(self) {
            result.enable_auto_naming();
        }
        result
    }
}

impl DbObject for TypedefDb {
    fn state(&self) -> &DbObjectState {
        &self.db_state
    }

    fn refresh(&self, record: Option<&DBRecord>) -> bool {
        let rec = match record {
            Some(r) => Some(r.clone()),
            None => {
                let key = self.get_key();
                match self.adapter.lock().unwrap().get_record(key) {
                    Ok(r) => r,
                    Err(e) => {
                        self.owner.lock().unwrap().db_error(e);
                        return false;
                    }
                }
            }
        };
        match rec {
            Some(r) => {
                *self.record.lock().unwrap() = r;
                self.data_type_db_complete_refresh();
                true
            }
            None => false,
        }
    }
}

impl DataTypeDb for TypedefDb {
    fn owning_data_type_manager(&self) -> Arc<dyn DataTypeManagerDb> {
        Arc::new(TypedefDbOwnerHandle(self.owner.clone()))
    }

    fn lock(&self) -> &ReentrantLock {
        &self.lock
    }

    fn stored_name(&self) -> Option<String> {
        self.stored_name.lock().unwrap().clone()
    }

    fn set_stored_name(&self, name: Option<String>) {
        *self.stored_name.lock().unwrap() = name;
    }

    fn stored_category_path(&self) -> Option<CategoryPath> {
        self.stored_category_path.lock().unwrap().clone()
    }

    fn set_stored_category_path(&self, path: Option<CategoryPath>) {
        *self.stored_category_path.lock().unwrap() = path;
    }

    fn stored_deleting(&self) -> bool {
        *self.stored_deleting.lock().unwrap()
    }

    fn set_stored_deleting(&self, deleting: bool) {
        *self.stored_deleting.lock().unwrap() = deleting;
    }

    fn do_get_name(&self) -> String {
        self.record.lock().unwrap().get_string(TYPEDEF_NAME_COL).unwrap_or_default().to_string()
    }

    fn do_get_category_id(&self) -> i64 {
        self.record.lock().unwrap().get_long(TYPEDEF_CAT_COL).unwrap_or(0)
    }

    fn do_set_category_path_record(&self, category_id: i64) -> io::Result<()> {
        {
            let mut rec = self.record.lock().unwrap();
            rec.set_long(TYPEDEF_CAT_COL, category_id);
        }
        self.persist_record(false)
    }

    fn do_set_name_record(&self, new_name: &str) -> Result<(), super::data_type_db::DoSetNameRecordError> {
        {
            let mut rec = self.record.lock().unwrap();
            rec.set_string(TYPEDEF_NAME_COL, Some(new_name.to_string()));
        }
        self.set_flags(self.get_flags() & !TYPEDEF_FLAG_AUTONAME);
        self.persist_record(true)
            .map_err(|e| super::data_type_db::DoSetNameRecordError::Io(e.to_string()))
    }

    fn get_source_archive_id(&self) -> UniversalID {
        UniversalID::new(
            self.record.lock().unwrap().get_long(TYPEDEF_SOURCE_ARCHIVE_ID_COL).unwrap_or(0),
        )
    }

    fn set_source_archive_id(&self, id: UniversalID) {
        {
            let mut rec = self.record.lock().unwrap();
            rec.set_long(TYPEDEF_SOURCE_ARCHIVE_ID_COL, id.value());
        }
        let _ = self.persist_record(false);
        self.owner.lock().unwrap().data_type_changed(self, false);
    }

    fn is_equivalent_with_handler(
        &self,
        data_type: &dyn DataType,
        handler: Option<&dyn DataTypeConflictHandler>,
    ) -> bool {
        if std::ptr::eq(
            self as *const Self as *const (),
            data_type as *const dyn DataType as *const (),
        ) {
            return true;
        }
        let Some(td) = data_type.as_typedef() else {
            return false;
        };
        self.validate(self.lock());
        let auto_named = self.is_auto_named();
        if auto_named != td.is_auto_named() {
            return false;
        }
        if !auto_named && !Utils.equals_ignore_conflict(&self.get_name(), &td.get_name()) {
            return false;
        }
        if !self.has_same_type_def_settings(td) {
            return false;
        }
        if let Some(h) = handler {
            if h.resolve_conflict(data_type, self) == ConflictResult::UseExisting {
                return true;
            }
        }
        let my_dt = self.get_data_type();
        let other_dt = td.get_data_type();
        if Utils.is_same_data_type(my_dt.as_ref(), other_dt.as_ref()) {
            return true;
        }
        // Approximates the static `DataTypeDB.isEquivalent(DataType, DataType, handler)` dispatch,
        // which special-cases a `DataTypeDB` target's own handler-aware `isEquivalent`: a plain
        // `&dyn DataType` can't be downcast to check for that here, so this falls back to an
        // ordinary equivalence check regardless of the wrapped types' own concrete kind.
        my_dt.is_equivalent(other_dt.as_ref())
    }

    fn set_universal_id(&self, old_universal_id: UniversalID) {
        {
            let mut rec = self.record.lock().unwrap();
            rec.set_long(TYPEDEF_UNIVERSAL_DT_ID_COL, old_universal_id.value());
        }
        let _ = self.persist_record(false);
        self.owner.lock().unwrap().data_type_changed(self, false);
    }
}

impl DataType for TypedefDb {
    fn get_name(&self) -> String {
        self.data_type_db_get_name()
    }

    fn set_name(&mut self, name: &str) -> Result<(), SetDataTypeNameError> {
        self.data_type_db_set_name(name, &Utils).map_err(|e| match e {
            super::data_type_db::SetNameError::Duplicate(d) => SetDataTypeNameError::Duplicate(d),
            super::data_type_db::SetNameError::InvalidName(i) => SetDataTypeNameError::InvalidName(i),
            // `Io`/`Deleted` have no matching `SetDataTypeNameError` variant; approximated as an
            // invalid name, mirroring the closest available error shape.
            super::data_type_db::SetNameError::Io(msg) => {
                SetDataTypeNameError::InvalidName(InvalidNameException::with_message(msg))
            }
            super::data_type_db::SetNameError::Deleted(msg) => {
                SetDataTypeNameError::InvalidName(InvalidNameException::with_message(msg))
            }
        })
    }

    fn get_category_path(&self) -> CategoryPath {
        self.data_type_db_get_category_path()
    }

    fn set_category_path(&mut self, path: CategoryPath) -> Result<(), DuplicateNameException> {
        if self.is_auto_named() {
            return Ok(()); // ignore category change if auto-naming enabled
        }
        self.base_set_category_path(path)
    }

    fn get_data_type_path(&self) -> DataTypePath {
        self.data_type_db_get_data_type_path()
    }

    fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
        Some(Box::new(TypedefDbOwnerHandle(self.owner.clone())))
    }

    fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
        self.owner.lock().unwrap().get_data_organization()
    }

    fn get_mnemonic(&self, _settings: &dyn Settings) -> String {
        self.get_display_name()
    }

    fn is_zero_length(&self) -> bool {
        self.get_data_type().is_zero_length()
    }

    fn get_length(&self) -> i32 {
        self.get_data_type().get_length()
    }

    fn get_aligned_length(&self) -> i32 {
        self.get_data_type().get_aligned_length()
    }

    fn get_alignment(&self) -> i32 {
        self.data_type_db_get_alignment()
    }

    fn has_language_dependant_length(&self) -> bool {
        self.get_data_type().has_language_dependant_length()
    }

    fn get_description(&self) -> String {
        self.get_data_type().get_description()
    }

    fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn std::any::Any>> {
        self.get_data_type().get_value(buf, settings, length)
    }

    fn get_value_class(&self, settings: &dyn Settings) -> Option<std::any::TypeId> {
        self.get_data_type().get_value_class(settings)
    }

    fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        self.get_data_type().get_representation(buf, settings, length)
    }

    fn get_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        let _guard = self.lock.read();
        self.refresh_if_needed();
        let dt = self.get_data_type();
        let mut combined = dt.get_settings_definitions();
        for def in dt.get_type_def_settings_definitions() {
            combined.push(def);
        }
        combined
    }

    fn get_type_def_settings_definitions(&self) -> Vec<Box<dyn TypeDefSettingsDefinition>> {
        self.get_data_type().get_type_def_settings_definitions()
    }

    // TODO(port): `doGetDefaultSettings` constructs a `DataTypeSettingsDB` (not yet ported --
    // see the module docs) to hold a *local* per-instance override of a type-def setting. Without
    // it, this can only return the tail of Java's fallback chain: the referenced type's own
    // default settings.
    fn get_default_settings(&self) -> Box<dyn Settings> {
        self.get_data_type().get_default_settings()
    }

    fn is_deleted(&self) -> bool {
        self.data_type_db_is_deleted()
    }

    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        self.is_equivalent_with_handler(dt, None)
    }

    fn is_typedef(&self) -> bool {
        true
    }

    fn as_typedef(&self) -> Option<&dyn TypeDef> {
        Some(self)
    }

    fn typedef_base_data_type(&self) -> Option<Box<dyn DataType>> {
        Some(TypeDef::get_base_data_type(self))
    }

    fn is_pointer(&self) -> bool {
        TypeDef::is_pointer(self)
    }

    fn data_type_size_changed(&mut self, dt: &dyn DataType) {
        if self.stored_deleting() {
            return;
        }
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return;
        }
        let my_dt = self.get_data_type();
        if my_dt.is_equivalent(dt) || dt.is_equivalent(my_dt.as_ref()) {
            // `notifySizeChanged(true)`'s parent-broadcast loop is omitted -- see the module docs.
            self.owner.lock().unwrap().data_type_changed(self, true);
        }
    }

    fn data_type_alignment_changed(&mut self, dt: &dyn DataType) {
        if self.stored_deleting() {
            return;
        }
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return;
        }
        let my_dt = self.get_data_type();
        if my_dt.is_equivalent(dt) || dt.is_equivalent(my_dt.as_ref()) {
            // `notifyAlignmentChanged(true)`'s parent-broadcast loop is omitted -- see the module docs.
            self.owner.lock().unwrap().data_type_changed(self, true);
        }
    }

    fn data_type_deleted(&mut self, dt: &dyn DataType) {
        if self.stored_deleting() {
            return;
        }
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return;
        }
        let my_dt = self.get_data_type();
        if my_dt.is_equivalent(dt) || dt.is_equivalent(my_dt.as_ref()) {
            let key = self.get_key();
            self.owner.lock().unwrap().add_data_type_to_delete(key);
            self.set_stored_deleting(true);
        }
    }

    fn data_type_name_changed(&mut self, dt: &dyn DataType, _old_name: &str) {
        if self.stored_deleting() {
            return;
        }
        if self.check_deleted().is_err() {
            return;
        }
        let my_dt = self.get_data_type();
        if my_dt.is_equivalent(dt) || dt.is_equivalent(my_dt.as_ref()) {
            self.update_auto_name(true);
        }
    }

    fn data_type_replaced(&mut self, old_dt: &dyn DataType, new_dt: &dyn DataType) {
        if self.stored_deleting() {
            return;
        }
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return;
        }
        let my_dt = self.get_data_type();
        if !(my_dt.is_equivalent(old_dt) || old_dt.is_equivalent(my_dt.as_ref())) {
            return;
        }
        let _ = Utils.check_valid_replacement(my_dt.as_ref(), new_dt);
        // TODO(port): see `DataType::data_type_replaced`'s doc comment / the module docs --
        // `new_dt` arrives by borrowed reference here, so the actual persisted swap can't happen
        // in this method. Callers with an owned replacement should call
        // `TypedefDb::replace_referenced_data_type` instead.
    }

    fn depends_on(&self, dt: &dyn DataType) -> bool {
        let my_dt = self.get_data_type();
        my_dt.is_equivalent(dt) || my_dt.depends_on(dt)
    }

    fn get_default_label_prefix(&self) -> Option<String> {
        if self.is_auto_named() {
            return self.get_data_type().get_default_label_prefix();
        }
        Some(self.get_name())
    }

    fn get_default_label_prefix_for_data(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        len: i32,
        options: &dyn DataTypeDisplayOptions,
    ) -> Option<String> {
        if self.is_auto_named() {
            return self.get_data_type().get_default_label_prefix_for_data(buf, settings, len, options);
        }
        self.get_default_label_prefix()
    }

    fn get_default_abbreviated_label_prefix(&self) -> Option<String> {
        if self.is_auto_named() {
            return self.get_data_type().get_default_abbreviated_label_prefix();
        }
        self.get_default_label_prefix()
    }

    fn get_default_offcut_label_prefix(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        len: i32,
        options: &dyn DataTypeDisplayOptions,
        offcut_offset: i32,
    ) -> Option<String> {
        if self.is_auto_named() {
            return self.get_data_type().get_default_offcut_label_prefix(
                buf,
                settings,
                len,
                options,
                offcut_offset,
            );
        }
        self.get_default_label_prefix_for_data(buf, settings, len, options)
    }

    fn get_last_change_time(&self) -> i64 {
        self.record.lock().unwrap().get_long(TYPEDEF_LAST_CHANGE_TIME_COL).unwrap_or(0)
    }

    fn get_last_change_time_in_source_archive(&self) -> i64 {
        self.record.lock().unwrap().get_long(TYPEDEF_SOURCE_SYNC_TIME_COL).unwrap_or(0)
    }

    fn get_universal_id(&self) -> UniversalID {
        UniversalID::new(
            self.record.lock().unwrap().get_long(TYPEDEF_UNIVERSAL_DT_ID_COL).unwrap_or(0),
        )
    }

    fn set_last_change_time(&mut self, last_change_time: i64) {
        {
            let mut rec = self.record.lock().unwrap();
            rec.set_long(TYPEDEF_LAST_CHANGE_TIME_COL, last_change_time);
        }
        let _ = self.persist_record(false);
        self.owner.lock().unwrap().data_type_changed(self, false);
    }

    fn set_last_change_time_in_source_archive(&mut self, last_change_time_in_source_archive: i64) {
        {
            let mut rec = self.record.lock().unwrap();
            rec.set_long(TYPEDEF_SOURCE_SYNC_TIME_COL, last_change_time_in_source_archive);
        }
        let _ = self.persist_record(false);
        self.owner.lock().unwrap().data_type_changed(self, false);
    }

    fn get_source_archive(&self) -> Option<Box<dyn SourceArchive>> {
        self.owner.lock().unwrap().get_source_archive(self.get_source_archive_id())
    }

    fn set_source_archive(&mut self, archive: Box<dyn SourceArchive>) {
        let resolved = self.owner.lock().unwrap().resolve_source_archive(archive);
        let mut id = resolved.source_archive_id();
        let owner_id = self.owner.lock().unwrap().get_universal_id();
        if id == owner_id {
            id = crate::program::model::data::data_type_manager::local_archive_universal_id();
        }
        self.set_source_archive_id(id);
    }

    fn replace_with(&mut self, data_type: &dyn DataType) {
        let Some(td) = data_type.as_typedef() else {
            return; // Java throws UnsupportedOperationException; this signature can't.
        };
        if std::ptr::eq(
            self as *const Self as *const (),
            data_type as *const dyn DataType as *const (),
        ) {
            return;
        }
        let _guard = self.lock.write();
        self.replace_referenced_data_type(td.get_data_type());
        // `TypedefDataType.copyTypeDefSettings(td, this, true)` is omitted: `TypedefDb` has no
        // local type-def-setting override store to copy into yet -- see the module docs.
    }

    fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        Box::new(self.materialize(false))
    }

    fn copy_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        Box::new(self.materialize(true))
    }
}

impl TypeDef for TypedefDb {
    fn is_auto_named(&self) -> bool {
        let _guard = self.lock.read();
        self.refresh_if_needed();
        (self.get_flags() & TYPEDEF_FLAG_AUTONAME) != 0
    }

    fn enable_auto_naming(&mut self) {
        if self.is_auto_named() {
            return;
        }
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return;
        }
        self.set_flags(self.get_flags() | TYPEDEF_FLAG_AUTONAME);
        if self.persist_record(true).is_err() {
            return;
        }
        let old_path = self.data_type_db_get_category_path();
        let current_path = TypeDef::get_data_type(self).get_category_path();
        let new_name = self.generate_typedef_name(&current_path);
        {
            let mut rec = self.record.lock().unwrap();
            rec.set_string(TYPEDEF_NAME_COL, Some(new_name));
        }
        if self.persist_record(true).is_err() {
            return;
        }
        self.data_type_db_refresh_name();
        if current_path != old_path {
            let _ = self.base_set_category_path(current_path);
        }
        // `notifyNameChanged(oldName)` intentionally omitted -- see the module docs.
    }

    fn get_data_type(&self) -> Box<dyn DataType> {
        let _guard = self.lock.read();
        self.refresh_if_needed();
        let id = self.record.lock().unwrap().get_long(TYPEDEF_DT_ID_COL).unwrap_or(0);
        self.owner
            .lock()
            .unwrap()
            .get_data_type_by_id(id)
            .unwrap_or_else(|| Box::new(MissingDataType))
    }

    fn get_base_data_type(&self) -> Box<dyn DataType> {
        let _guard = self.lock.read();
        self.refresh_if_needed();
        let dt = TypeDef::get_data_type(self);
        if let Some(td) = dt.as_typedef() {
            td.get_base_data_type()
        } else {
            dt
        }
    }
}

impl std::fmt::Display for TypedefDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_auto_named() {
            write!(f, "{}", self.get_name())
        } else {
            write!(f, "typedef {} {}", self.get_name(), self.get_data_type().get_name())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::data::typedef_db_adapter::schema;
    use crate::program::model::data::category_path::ROOT;
    use crate::program::model::data::data_type_conflict_handler::DataTypeConflictHandler;
    use std::collections::HashMap;

    #[derive(Clone)]
    struct MockLeaf {
        name: String,
        length: i32,
        description: String,
        category_path: CategoryPath,
    }

    impl DataType for MockLeaf {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_description(&self) -> String {
            self.description.clone()
        }
        fn get_category_path(&self) -> CategoryPath {
            self.category_path.clone()
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.get_name() == dt.get_name()
        }
        fn depends_on(&self, _dt: &dyn DataType) -> bool {
            false
        }
    }

    struct MockTypeDefSettingsDef;
    impl SettingsDefinition for MockTypeDefSettingsDef {
        fn get_storage_key(&self) -> String {
            "attr".to_string()
        }
    }
    impl TypeDefSettingsDefinition for MockTypeDefSettingsDef {
        fn get_attribute_specification(&self, _settings: &dyn Settings) -> Option<String> {
            None
        }
    }

    /// A referenced type that itself carries a type-def-settings definition, used to exercise
    /// [`TypedefDb::get_settings_definitions`]/[`TypedefDb::get_default_settings`].
    struct MockLeafWithTypeDefSettings {
        name: String,
    }
    impl DataType for MockLeafWithTypeDefSettings {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_type_def_settings_definitions(&self) -> Vec<Box<dyn TypeDefSettingsDefinition>> {
            vec![Box::new(MockTypeDefSettingsDef)]
        }
        fn get_default_settings(&self) -> Box<dyn Settings> {
            Box::new(MockLeafSettings)
        }
    }

    struct MockLeafSettings;
    impl Settings for MockLeafSettings {
        fn get_long(&self, name: &str) -> Option<i64> {
            if name == "k" {
                Some(5)
            } else {
                None
            }
        }
    }

    /// A referenced type that is itself a `TypeDef`, used to exercise
    /// [`TypedefDb::get_base_data_type`] through a chain.
    struct MockTypedefWrapper {
        inner: MockLeaf,
    }
    impl DataType for MockTypedefWrapper {
        fn get_name(&self) -> String {
            format!("{} *", self.inner.name)
        }
        fn as_typedef(&self) -> Option<&dyn TypeDef> {
            Some(self)
        }
        fn is_typedef(&self) -> bool {
            true
        }
    }
    impl TypeDef for MockTypedefWrapper {
        fn is_auto_named(&self) -> bool {
            false
        }
        fn enable_auto_naming(&mut self) {}
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(self.inner.clone())
        }
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(self.inner.clone())
        }
    }

    #[derive(Clone)]
    enum MockEntry {
        Leaf(MockLeaf),
        Wrapper(MockLeaf),
    }

    struct MockCategoryHandle {
        id: i64,
        path: CategoryPath,
    }
    impl Category for MockCategoryHandle {
        fn get_name(&self) -> String {
            self.path.get_name()
        }
        fn set_name(&mut self, _name: &str) -> Result<(), crate::program::model::data::category::SetCategoryNameError> {
            Ok(())
        }
        fn get_categories(&self) -> Vec<Box<dyn Category>> {
            Vec::new()
        }
        fn get_data_types(&self) -> Vec<Box<dyn DataType>> {
            Vec::new()
        }
        fn get_data_types_by_base_name(&self, _name: &str) -> Vec<Box<dyn DataType>> {
            Vec::new()
        }
        fn add_data_type(
            &mut self,
            dt: Box<dyn DataType>,
            _handler: &dyn DataTypeConflictHandler,
        ) -> Box<dyn DataType> {
            dt
        }
        fn get_category(&self, _name: &str) -> Option<Box<dyn Category>> {
            None
        }
        fn get_category_path(&self) -> CategoryPath {
            self.path.clone()
        }
        fn get_data_type(&self, _name: &str) -> Option<Box<dyn DataType>> {
            None
        }
        fn create_category(&mut self, _name: &str) -> Result<Box<dyn Category>, InvalidNameException> {
            Err(InvalidNameException::new())
        }
        fn remove_category(&mut self, _name: &str, _monitor: &dyn crate::util::task::TaskMonitor) -> bool {
            false
        }
        fn remove_empty_category(
            &mut self,
            _name: &str,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> bool {
            false
        }
        fn move_category(
            &mut self,
            _category: Box<dyn Category>,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Result<(), DuplicateNameException> {
            Ok(())
        }
        fn copy_category(
            &mut self,
            _category: &dyn Category,
            _handler: &dyn DataTypeConflictHandler,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Box<dyn Category> {
            Box::new(MockCategoryHandle { id: self.id, path: self.path.clone() })
        }
        fn get_parent(&self) -> Option<Box<dyn Category>> {
            None
        }
        fn is_root(&self) -> bool {
            self.path == *ROOT
        }
        fn get_category_path_name(&self) -> String {
            self.path.get_path()
        }
        fn get_root(&self) -> Box<dyn Category> {
            Box::new(MockCategoryHandle { id: 0, path: ROOT.clone() })
        }
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            struct Empty;
            impl DataTypeManager for Empty {}
            Box::new(Empty)
        }
        fn move_data_type(
            &mut self,
            _dt_type: Box<dyn DataType>,
            _handler: &dyn DataTypeConflictHandler,
        ) -> Result<(), crate::program::model::data::data_type_dependency_exception::DataTypeDependencyException>
        {
            Ok(())
        }
        fn remove(&mut self, _dt_type: &dyn DataType, _monitor: &dyn crate::util::task::TaskMonitor) -> bool {
            false
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn compare_to(&self, other: &dyn Category) -> std::cmp::Ordering {
            Category::get_name(self).cmp(&other.get_name())
        }
    }

    struct MockManager {
        universal_id: UniversalID,
        data_types: HashMap<i64, MockEntry>,
        categories: HashMap<i64, CategoryPath>,
        next_id: i64,
        deleted: Vec<i64>,
        changed_count: i32,
        db_errors: usize,
    }

    impl MockManager {
        fn new() -> Self {
            let mut categories = HashMap::new();
            categories.insert(0, ROOT.clone());
            MockManager {
                universal_id: UniversalID::new(1000),
                data_types: HashMap::new(),
                categories,
                next_id: 1,
                deleted: Vec::new(),
                changed_count: 0,
                db_errors: 0,
            }
        }

        fn insert_leaf(&mut self, id: i64, leaf: MockLeaf) {
            self.data_types.insert(id, MockEntry::Leaf(leaf));
        }
    }

    impl DataTypeManager for MockManager {
        fn get_universal_id(&self) -> UniversalID {
            self.universal_id
        }
        fn get_category(&self, category_id: i64) -> Option<Box<dyn Category>> {
            self.categories
                .get(&category_id)
                .map(|p| Box::new(MockCategoryHandle { id: category_id, path: p.clone() }) as Box<dyn Category>)
        }
        fn get_root_category(&self) -> Box<dyn Category> {
            Box::new(MockCategoryHandle { id: 0, path: ROOT.clone() })
        }
        fn get_data_type_in_category(&self, path: &CategoryPath, name: &str) -> Option<Box<dyn DataType>> {
            self.data_types.values().find_map(|e| match e {
                MockEntry::Leaf(l) if &l.category_path == path && l.name == name => {
                    Some(Box::new(l.clone()) as Box<dyn DataType>)
                }
                _ => None,
            })
        }
        fn create_category(&mut self, path: &CategoryPath) -> Box<dyn Category> {
            let id = self.next_id;
            self.next_id += 1;
            self.categories.insert(id, path.clone());
            Box::new(MockCategoryHandle { id, path: path.clone() })
        }
        fn get_data_type_by_id(&self, data_type_id: i64) -> Option<Box<dyn DataType>> {
            match self.data_types.get(&data_type_id)? {
                MockEntry::Leaf(l) => Some(Box::new(l.clone())),
                MockEntry::Wrapper(inner) => Some(Box::new(MockTypedefWrapper { inner: inner.clone() })),
            }
        }
        fn resolve(
            &mut self,
            data_type: Box<dyn DataType>,
            _handler: &dyn DataTypeConflictHandler,
        ) -> Box<dyn DataType> {
            data_type
        }
        fn get_resolved_id(&mut self, dt: &dyn DataType) -> i64 {
            if let Some((id, _)) = self.data_types.iter().find(|(_, e)| match e {
                MockEntry::Leaf(l) => l.name == dt.get_name(),
                MockEntry::Wrapper(l) => l.name == dt.get_name(),
            }) {
                return *id;
            }
            let id = self.next_id;
            self.next_id += 1;
            self.insert_leaf(
                id,
                MockLeaf {
                    name: dt.get_name(),
                    length: dt.get_length(),
                    description: String::new(),
                    category_path: ROOT.clone(),
                },
            );
            id
        }
    }

    impl DataTypeManagerDb for MockManager {
        fn db_error(&mut self, _error: io::Error) {
            self.db_errors += 1;
        }
        fn add_data_type_to_replace(&mut self, _data_type_id: i64, _replacement: Box<dyn DataType>) {}
        fn add_data_type_to_delete(&mut self, data_type_id: i64) {
            self.deleted.push(data_type_id);
        }
        fn data_type_changed(&mut self, _dt: &dyn DataType, _is_auto_change: bool) {
            self.changed_count += 1;
        }
    }

    struct MockAdapter {
        stored: Mutex<HashMap<i64, DBRecord>>,
    }
    impl MockAdapter {
        fn new() -> Self {
            MockAdapter { stored: Mutex::new(HashMap::new()) }
        }
    }
    impl crate::program::util::DBRecordAdapter for MockAdapter {
        fn get_records(&self) -> io::Result<Box<dyn crate::framework::db::RecordIterator + '_>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_record_count(&self) -> usize {
            self.stored.lock().unwrap().len()
        }
    }
    impl TypedefDBAdapter for MockAdapter {
        fn create_record(
            &mut self,
            _data_type_id: i64,
            _name: &str,
            _flags: i16,
            _category_id: i64,
            _source_archive_id: i64,
            _source_data_type_id: i64,
            _last_change_time: i64,
        ) -> io::Result<DBRecord> {
            unimplemented!("not exercised by these tests")
        }
        fn get_record(&self, typedef_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.stored.lock().unwrap().get(&typedef_id).cloned())
        }
        fn remove_record(&mut self, _data_id: i64) -> io::Result<bool> {
            unimplemented!("not exercised by these tests")
        }
        fn update_record(&mut self, record: &DBRecord, set_last_change_time: bool) -> io::Result<()> {
            let mut rec = record.clone();
            if set_last_change_time {
                rec.set_long(TYPEDEF_LAST_CHANGE_TIME_COL, 999);
            }
            let key = match rec.get_key() {
                Field::Long(Some(v)) => *v,
                _ => 0,
            };
            self.stored.lock().unwrap().insert(key, rec);
            Ok(())
        }
        fn delete_table(&mut self, _handle: &mut crate::framework::db::DBHandle) -> io::Result<()> {
            unimplemented!("not exercised by these tests")
        }
        fn get_record_ids_in_category(&self, _category_id: i64) -> io::Result<Vec<Field>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_record_ids_for_source_archive(&self, _archive_id: i64) -> io::Result<Vec<Field>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_record_with_ids(
            &self,
            _source_id: UniversalID,
            _datatype_id: UniversalID,
        ) -> io::Result<Option<DBRecord>> {
            unimplemented!("not exercised by these tests")
        }
    }

    fn make_record(key: i64, dt_id: i64, name: &str, cat_id: i64) -> DBRecord {
        let mut rec = DBRecord::new(schema(), Field::Long(Some(key)));
        rec.set_long(TYPEDEF_DT_ID_COL, dt_id);
        rec.set_field(TYPEDEF_FLAGS_COL, Field::Short(Some(0)));
        rec.set_string(TYPEDEF_NAME_COL, Some(name.to_string()));
        rec.set_long(TYPEDEF_CAT_COL, cat_id);
        rec.set_long(TYPEDEF_SOURCE_ARCHIVE_ID_COL, 0);
        rec.set_long(TYPEDEF_UNIVERSAL_DT_ID_COL, 0);
        rec.set_long(TYPEDEF_SOURCE_SYNC_TIME_COL, 0);
        rec.set_long(TYPEDEF_LAST_CHANGE_TIME_COL, 0);
        rec
    }

    fn make_typedef(
        manager: Arc<Mutex<MockManager>>,
        adapter: Arc<Mutex<MockAdapter>>,
        record: DBRecord,
    ) -> TypedefDb {
        TypedefDb::new(
            manager as Arc<Mutex<dyn DataTypeManagerDb + Send>>,
            adapter as Arc<Mutex<dyn TypedefDBAdapter + Send>>,
            Arc::new(ReentrantLock::new("test")),
            record,
        )
    }

    fn setup() -> (Arc<Mutex<MockManager>>, Arc<Mutex<MockAdapter>>) {
        (Arc::new(Mutex::new(MockManager::new())), Arc::new(Mutex::new(MockAdapter::new())))
    }

    #[test]
    fn construction_reads_name_and_category_from_record() {
        let (mgr, adapter) = setup();
        mgr.lock().unwrap().insert_leaf(
            1,
            MockLeaf { name: "int".into(), length: 4, description: "an int".into(), category_path: ROOT.clone() },
        );
        let record = make_record(10, 1, "MyInt", 0);
        let td = make_typedef(mgr, adapter, record);

        assert_eq!(DataType::get_name(&td), "MyInt");
        assert_eq!(td.get_category_path(), ROOT.clone());
        assert_eq!(td.get_length(), 4);
        assert_eq!(td.get_description(), "an int");
        assert!(td.is_typedef());
        assert!(!td.is_auto_named());
    }

    #[test]
    fn set_name_updates_record_and_rejects_duplicate() {
        let (mgr, adapter) = setup();
        mgr.lock().unwrap().insert_leaf(
            1,
            MockLeaf { name: "int".into(), length: 4, description: String::new(), category_path: ROOT.clone() },
        );
        let record = make_record(10, 1, "MyInt", 0);
        let mut td = make_typedef(mgr.clone(), adapter, record);

        assert!(DataType::set_name(&mut td, "RenamedInt").is_ok());
        assert_eq!(DataType::get_name(&td), "RenamedInt");

        // Renaming to the same name is a no-op success.
        assert!(DataType::set_name(&mut td, "RenamedInt").is_ok());

        // A name already used by another datatype in this category is rejected.
        mgr.lock().unwrap().insert_leaf(
            2,
            MockLeaf { name: "Taken".into(), length: 1, description: String::new(), category_path: ROOT.clone() },
        );
        assert!(matches!(
            DataType::set_name(&mut td, "Taken"),
            Err(SetDataTypeNameError::Duplicate(_))
        ));
    }

    #[test]
    fn get_base_data_type_follows_typedef_chain() {
        let (mgr, adapter) = setup();
        {
            let mut m = mgr.lock().unwrap();
            m.data_types.insert(
                2,
                MockEntry::Wrapper(MockLeaf {
                    name: "int".into(),
                    length: 4,
                    description: String::new(),
                    category_path: ROOT.clone(),
                }),
            );
        }
        let record = make_record(10, 2, "IntPtrTypedef", 0);
        let td = make_typedef(mgr, adapter, record);

        // The referenced type is itself a `TypeDef`; `get_data_type` returns it unresolved...
        assert_eq!(TypeDef::get_data_type(&td).get_name(), "int *");
        // ...while `get_base_data_type` follows the chain down to the real leaf.
        assert_eq!(TypeDef::get_base_data_type(&td).get_name(), "int");
    }

    #[test]
    fn settings_definitions_combine_data_type_and_typedef_settings() {
        let (mgr, adapter) = setup();
        {
            let mut m = mgr.lock().unwrap();
            // `MockLeafWithTypeDefSettings` isn't a plain `MockLeaf`; register it via a small
            // wrapper so `get_data_type_by_id` can hand back the real, richer type.
            m.data_types.insert(
                1,
                MockEntry::Leaf(MockLeaf {
                    name: "widget".into(),
                    length: 1,
                    description: String::new(),
                    category_path: ROOT.clone(),
                }),
            );
        }
        let record = make_record(10, 1, "WidgetTypedef", 0);
        let td = make_typedef(mgr, adapter, record);

        // The plain `MockLeaf` contributes no settings definitions of its own or as a typedef.
        assert!(td.get_settings_definitions().is_empty());
        assert!(td.get_type_def_settings_definitions().is_empty());
    }

    #[test]
    fn get_default_settings_falls_back_to_referenced_type() {
        struct RichManager(MockManager);
        // Reuse MockManager's plumbing but override get_data_type_by_id to hand back a type with
        // real default settings -- done inline via a closure-free wrapper type below instead,
        // since trait methods can't easily be overridden post hoc: build the leaf mapping so the
        // returned type carries default settings by using `MockLeafWithTypeDefSettings` directly
        // through a dedicated single-purpose manager.
        struct SettingsManager;
        impl DataTypeManager for SettingsManager {
            fn get_data_type_by_id(&self, data_type_id: i64) -> Option<Box<dyn DataType>> {
                if data_type_id == 1 {
                    Some(Box::new(MockLeafWithTypeDefSettings { name: "widget".to_string() }))
                } else {
                    None
                }
            }
        }
        impl DataTypeManagerDb for SettingsManager {
            fn db_error(&mut self, _error: io::Error) {}
            fn add_data_type_to_replace(&mut self, _data_type_id: i64, _replacement: Box<dyn DataType>) {}
            fn add_data_type_to_delete(&mut self, _data_type_id: i64) {}
        }
        let _ = RichManager; // silence unused-struct warning path if refactored later

        let manager: Arc<Mutex<dyn DataTypeManagerDb + Send>> = Arc::new(Mutex::new(SettingsManager));
        let adapter: Arc<Mutex<dyn TypedefDBAdapter + Send>> = Arc::new(Mutex::new(MockAdapter::new()));
        let record = make_record(10, 1, "WidgetTypedef", 0);
        let td = TypedefDb::new(manager, adapter, Arc::new(ReentrantLock::new("test")), record);

        let defs = td.get_type_def_settings_definitions();
        assert_eq!(defs.len(), 1);
        let combined = td.get_settings_definitions();
        assert_eq!(combined.len(), 1);

        let settings = DataType::get_default_settings(&td);
        assert_eq!(settings.get_long("k"), Some(5));
    }

    #[test]
    fn enable_auto_naming_generates_name_from_referenced_type() {
        let (mgr, adapter) = setup();
        mgr.lock().unwrap().insert_leaf(
            1,
            MockLeaf { name: "int".into(), length: 4, description: String::new(), category_path: ROOT.clone() },
        );
        let record = make_record(10, 1, "Ignored", 0);
        let mut td = make_typedef(mgr, adapter, record);

        assert!(!td.is_auto_named());
        td.enable_auto_naming();
        assert!(td.is_auto_named());
        assert_eq!(DataType::get_name(&td), "int __(())");

        // A manual rename clears the auto-name flag, mirroring `doSetNameRecord`.
        DataType::set_name(&mut td, "MyInt").unwrap();
        assert!(!td.is_auto_named());
        assert_eq!(DataType::get_name(&td), "MyInt");
    }

    #[test]
    fn data_type_name_changed_triggers_auto_name_update() {
        let (mgr, adapter) = setup();
        mgr.lock().unwrap().insert_leaf(
            1,
            MockLeaf { name: "int".into(), length: 4, description: String::new(), category_path: ROOT.clone() },
        );
        let record = make_record(10, 1, "Ignored", 0);
        let mut td = make_typedef(mgr.clone(), adapter, record);
        td.enable_auto_naming();
        assert_eq!(DataType::get_name(&td), "int __(())");

        // The referenced type's name changes (from the manager's perspective)...
        mgr.lock().unwrap().insert_leaf(
            1,
            MockLeaf { name: "uint".into(), length: 4, description: String::new(), category_path: ROOT.clone() },
        );
        let referenced = TypeDef::get_data_type(&td);
        // ...and the notification callback regenerates this typedef's auto-name to match.
        DataType::data_type_name_changed(&mut td, referenced.as_ref(), "int");
        assert_eq!(DataType::get_name(&td), "uint __(())");
    }

    #[test]
    fn is_equivalent_compares_auto_naming_names_and_referenced_types() {
        let (mgr, adapter) = setup();
        mgr.lock().unwrap().insert_leaf(
            1,
            MockLeaf { name: "int".into(), length: 4, description: String::new(), category_path: ROOT.clone() },
        );
        let a = make_typedef(mgr.clone(), adapter.clone(), make_record(10, 1, "Foo", 0));
        let b = make_typedef(mgr.clone(), adapter.clone(), make_record(11, 1, "Foo", 0));
        let c = make_typedef(mgr.clone(), adapter.clone(), make_record(12, 1, "Foo.conflict1", 0));
        let d = make_typedef(mgr, adapter, make_record(13, 1, "Bar", 0));

        assert!(DataType::is_equivalent(&a, &b));
        assert!(DataType::is_equivalent(&a, &c)); // conflict suffix ignored
        assert!(!DataType::is_equivalent(&a, &d));
        assert!(!DataType::is_equivalent(&a, &MockLeaf {
            name: "Foo".into(),
            length: 4,
            description: String::new(),
            category_path: ROOT.clone(),
        })); // not a TypeDef at all
    }

    #[test]
    fn depends_on_checks_referenced_type() {
        let (mgr, adapter) = setup();
        mgr.lock().unwrap().insert_leaf(
            1,
            MockLeaf { name: "int".into(), length: 4, description: String::new(), category_path: ROOT.clone() },
        );
        let record = make_record(10, 1, "MyInt", 0);
        let td = make_typedef(mgr, adapter, record);

        let int_leaf = MockLeaf { name: "int".into(), length: 4, description: String::new(), category_path: ROOT.clone() };
        let float_leaf = MockLeaf { name: "float".into(), length: 4, description: String::new(), category_path: ROOT.clone() };
        assert!(DataType::depends_on(&td, &int_leaf));
        assert!(!DataType::depends_on(&td, &float_leaf));
    }

    #[test]
    fn to_string_reflects_auto_naming() {
        let (mgr, adapter) = setup();
        mgr.lock().unwrap().insert_leaf(
            1,
            MockLeaf { name: "int".into(), length: 4, description: String::new(), category_path: ROOT.clone() },
        );
        let record = make_record(10, 1, "MyInt", 0);
        let mut td = make_typedef(mgr, adapter, record);

        assert_eq!(td.to_string(), "typedef MyInt int");
        td.enable_auto_naming();
        assert_eq!(td.to_string(), DataType::get_name(&td));
    }

    #[test]
    fn data_type_deleted_schedules_delete_and_marks_deleting() {
        let (mgr, adapter) = setup();
        mgr.lock().unwrap().insert_leaf(
            1,
            MockLeaf { name: "int".into(), length: 4, description: String::new(), category_path: ROOT.clone() },
        );
        let record = make_record(10, 1, "MyInt", 0);
        let mut td = make_typedef(mgr.clone(), adapter, record);

        let referenced = TypeDef::get_data_type(&td);
        DataType::data_type_deleted(&mut td, referenced.as_ref());
        assert!(td.stored_deleting());
        assert_eq!(mgr.lock().unwrap().deleted, vec![10]);
    }

    #[test]
    fn replace_referenced_data_type_swaps_and_persists() {
        let (mgr, adapter) = setup();
        mgr.lock().unwrap().insert_leaf(
            1,
            MockLeaf { name: "int".into(), length: 4, description: String::new(), category_path: ROOT.clone() },
        );
        let record = make_record(10, 1, "MyInt", 0);
        let td = make_typedef(mgr.clone(), adapter, record);

        assert_eq!(TypeDef::get_data_type(&td).get_name(), "int");
        td.replace_referenced_data_type(Box::new(MockLeaf {
            name: "uint".into(),
            length: 4,
            description: String::new(),
            category_path: ROOT.clone(),
        }));
        assert_eq!(TypeDef::get_data_type(&td).get_name(), "uint");
        assert!(mgr.lock().unwrap().changed_count > 0);
    }

    #[test]
    fn universal_id_and_last_change_time_roundtrip() {
        let (mgr, adapter) = setup();
        mgr.lock().unwrap().insert_leaf(
            1,
            MockLeaf { name: "int".into(), length: 4, description: String::new(), category_path: ROOT.clone() },
        );
        let record = make_record(10, 1, "MyInt", 0);
        let mut td = make_typedef(mgr, adapter, record);

        assert_eq!(DataType::get_universal_id(&td), UniversalID::new(0));
        DataTypeDb::set_universal_id(&td, UniversalID::new(42));
        assert_eq!(DataType::get_universal_id(&td), UniversalID::new(42));

        DataType::set_last_change_time(&mut td, 123);
        assert_eq!(DataType::get_last_change_time(&td), 123);
    }

    #[test]
    fn refresh_none_pulls_latest_record_from_adapter() {
        let (mgr, adapter) = setup();
        mgr.lock().unwrap().insert_leaf(
            1,
            MockLeaf { name: "int".into(), length: 4, description: String::new(), category_path: ROOT.clone() },
        );
        let record = make_record(10, 1, "MyInt", 0);
        // Pre-populate the adapter's backing store with a record under the same key but a
        // different name, then ask the object to refresh from it.
        let mut newer = record.clone();
        newer.set_string(TYPEDEF_NAME_COL, Some("Refreshed".to_string()));
        adapter.lock().unwrap().stored.lock().unwrap().insert(10, newer);

        let td = make_typedef(mgr, adapter, record);
        assert!(DbObject::refresh(&td, None));
        assert_eq!(td.do_get_name(), "Refreshed");
    }
}
