//! Port of `ghidra.program.database.data.UnionDB`, the database-persisted implementation of
//! [`Union`].
//!
//! `UnionDB extends CompositeDB implements UnionInternal` in Java; [`CompositeDb`] is this
//! crate's already-ported cycle-cut trait standing in for the abstract `CompositeDB` (itself
//! `extends DataTypeDB`). [`UnionDb`] composes both [`DataTypeDb`] and [`CompositeDb`] (the
//! second concrete implementor of [`DataTypeDb`], after
//! [`TypedefDb`](super::typedef_db::TypedefDb) -- see that module's doc comments for the
//! `Arc<Mutex<dyn DataTypeManagerDb + Send>>` owner-storage rationale and the
//! owned-forwarding-wrapper pattern this port reuses verbatim as [`UnionDbOwnerHandle`]), plus
//! [`Composite`]/[`CompositeInternal`]/[`Union`]/[`UnionInternal`] for its own public surface, and
//! holds its components as `Vec<DataTypeComponentDB>` (mirroring Java's `List<DataTypeComponentDB>
//! components`), all behind `Mutex`es for the same reason `TypedefDb`'s cached fields are: several
//! `&self` methods (`refresh`, `get_length`, `get_num_components`, ...) need interior mutability
//! to stay faithful to Java's lazily-recomputed `unionLength`/`unionAlignment`/`computedAlignment`
//! fields and the `DbObject::refresh(&self, ...)` contract.
//!
//! # What was ported in full
//!
//! Every method `UnionDB.java` itself declares -- `add`/`insert`/`addBitField`/`insertBitField`/
//! `delete(int)`/`delete(Set<Integer>)`/`replaceWith`/`isPartOf`/`getComponent(s)`/
//! `getNumComponents`/`copy`/`clone`/`isZeroLength`/`getLength`/`fixupComponents`/
//! `dataTypeAlignmentChanged`/`dataTypeSizeChanged`/`dataTypeDeleted`/`dataTypeReplaced`/
//! `isEquivalent`/`shiftOrdinals`/`getComputedAlignment`/`repack`/`adjustBitField`/
//! `getBitFieldAllocation` -- is ported as real, working logic, along with the `CompositeDB`
//! superclass methods it relies on (`createComponent`, `doDelete`, `updateBitFieldDataType`,
//! `doCheckedResolve`, `validateDataType`, `getPreferredComponentLength`,
//! `doSetPackingAndAlignment`, packing/alignment get/set accessors, description/last-change-time/
//! source-archive accessors).
//!
//! # Deliberate simplifications and omissions
//!
//! - **No live back-reference from a component to this union.** See
//!   [`DataTypeComponentDB`](super::data_type_component_db::DataTypeComponentDB)'s own module
//!   docs for the full explanation and the [`set_component_field_name`](UnionDb::set_component_field_name)/
//!   [`set_component_comment`](UnionDb::set_component_comment) methods that provide the real,
//!   fully-notifying equivalent of `CompositeDB.setFieldName`/`setComment`.
//! - **`dataType.addParent(this)`/`removeParent(this)` are never called.** Parent/child dependency
//!   tracking needs `dataMgr.addParentChildRecord`/`getParentDataTypes`, neither of which exist on
//!   [`DataTypeManagerDb`] yet (the same gap `typedef_db.rs`'s module docs document for the same
//!   reason). Every `notifySizeChanged`/`notifyAlignmentChanged` call this omission would also
//!   feed is therefore likewise a no-op here; each call site says so.
//! - **`dataMgr.getSettingsAdapter().removeAllSettingsRecords(...)`** (called from `doDelete`,
//!   `dataTypeDeleted`, `dataTypeReplaced`) is skipped: no settings-adapter accessor exists on
//!   [`DataTypeManagerDb`] yet.
//! - **Bitfield-base-type-deleted "revert to primitive type"** (the branch of `dataTypeDeleted`
//!   that reverts a bitfield to its base type's own primitive integer type when that base type is
//!   itself deleted) is not ported: it needs `BitFieldDataType.getPrimitiveBaseDataType()` and
//!   `dataMgr.blockDataTypeRemoval(...)`, neither of which exist in this crate yet. Such a bitfield
//!   is left unchanged rather than reverted -- the identical gap and reasoning
//!   [`UnionDataType::union_data_type_data_type_deleted`](crate::program::model::data::union_data_type::UnionDataType::union_data_type_data_type_deleted)
//!   documents for its own in-memory sibling port.
//! - **`insertBitField`/`addBitField` construct a plain [`BitFieldDataType`]`, not the DB-aware
//!   `BitFieldDBDataType` Java uses** (not ported -- a thin `BitFieldDataType` subclass tying
//!   bitfield settings-lookup back into the database). Matches
//!   [`UnionDataType::union_data_type_insert_bit_field`]'s identical substitution.
//! - **`doCheckedResolve`'s `Pointer`-specific deferred post-resolve branch is dropped.** Java
//!   special-cases a `Pointer` component during `replaceWith` by resolving a placeholder
//!   `newPointer(DataType.DEFAULT)` and deferring the real pointee resolution via
//!   `dataMgr.queuePostResolve(this, union)`/`postPointerResolve`. None of `pointerPostResolveRequired`/
//!   `queuePostResolve`/`postPointerResolve` exist on this crate's [`DataTypeManagerDb`] yet, so
//!   [`replace_with`](DataType::replace_with) simply resolves every component (including pointers)
//!   through the ordinary path instead.
//! - **`activateResolveCache`/`processResolveQueue`** (bracketing `replaceWith`, batching a
//!   resolve operation's dependent resolves) are not exposed on [`DataTypeManagerDb`]; skipped.
//! - **`resolving`/`getCachedEquivalence`/`putCachedEquivalence`** (the in-progress-resolve
//!   short-circuit and equivalence memoization `isEquivalent` uses) have no home on
//!   [`DataTypeManagerDb`]/[`DataTypeDb`] yet; `is_equivalent_with_handler` performs the real
//!   packing/alignment/component comparison every time instead, which is always correct (just
//!   without the memoization or resolve-cycle short-circuit).
//! - **`doSetPackingAndAlignment(CompositeInternal)` is reconstructed from `Union`'s public
//!   surface, not `CompositeInternal`'s raw stored accessors.** [`replace_with`]'s `other: &dyn
//!   Union` parameter cannot be downcast to `&dyn CompositeInternal` (no generic mechanism exists
//!   for that in this crate), so the stored packing/alignment values are re-derived from
//!   `other.get_packing_type()`/`get_explicit_packing_value()`/`get_alignment_type()`/
//!   `get_explicit_minimum_alignment()` instead -- carrying the identical information, just
//!   through the public accessor shape.
//! - **`copy`/`clone` do not call the real `replaceWith` on a fresh `UnionDataTypeImpl`.** Both
//!   materialize a fresh, in-memory [`UnionDataTypeImpl`](crate::program::model::data::union_data_type::UnionDataTypeImpl)
//!   by re-adding this union's own components one at a time
//!   ([`materialize`](UnionDb::materialize)), since `UnionDataTypeImpl`'s own `replaceWith` (via
//!   [`UnionDataType::union_data_type_replace_with`]) requires an `other: &dyn UnionDataType`
//!   parameter that `UnionDb` -- whose components are `DataTypeComponentDB`, not
//!   `DataTypeComponentImpl` -- does not (and should not) implement. The resulting union has the
//!   same category/name/description/packing/alignment/components as `self`, matching Java's
//!   observable end state even though the mechanism differs.
//! - **`clone(dataMgr)`'s `dataMgr == getDataTypeManager()` fast path (`return this`) is not
//!   taken.** A `&self` method cannot hand back an owned `Box<dyn Union>` aliasing `self`; when the
//!   managers match, [`Union::clone_union`] still materializes a fresh (behaviorally equivalent)
//!   clone rather than reusing `self`, mirroring
//!   [`UnionDataTypeImpl`](crate::program::model::data::union_data_type::UnionDataTypeImpl)'s own
//!   documented treatment of the identical Java short-circuit.

use std::collections::HashSet;
use std::io;
use std::sync::{Arc, Mutex};

use crate::program::model::data::bit_field_packing::BitFieldPacking;
use crate::docking::settings::settings::Settings;
use crate::framework::db::DBRecord;
use crate::program::database::data::component_db_adapter::ComponentDBAdapter;
use crate::program::database::data::composite_db::CompositeDb;
use crate::program::database::data::composite_db_adapter::{
    CompositeDBAdapter, COMPOSITE_ALIGNMENT_COL, COMPOSITE_CAT_COL, COMPOSITE_COMMENT_COL,
    COMPOSITE_LAST_CHANGE_TIME_COL, COMPOSITE_LENGTH_COL, COMPOSITE_MIN_ALIGN_COL,
    COMPOSITE_NAME_COL, COMPOSITE_PACKING_COL, COMPOSITE_SOURCE_ARCHIVE_ID_COL,
    COMPOSITE_SOURCE_SYNC_TIME_COL, COMPOSITE_UNIVERSAL_DT_ID_COL,
};
use crate::program::database::data::data_type_component_db::DataTypeComponentDB;
use crate::program::database::data::data_type_db::{DataTypeDb, DoSetNameRecordError, SetNameError};
use crate::program::database::data::data_type_manager_db::DataTypeManagerDb;
use crate::program::database::data::data_type_utilities::DataTypeUtilities as DbDataTypeUtilities;
use crate::program::database::db_object::{DbObject, DbObjectState};
use crate::program::model::data::alignment_type::AlignmentType;
use crate::program::model::data::bit_field_data_type::{
    get_effective_bit_size, get_minimum_storage_size_no_offset, is_valid_base_data_type, BitFieldDataType,
};
use crate::program::model::data::category::Category;
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::composite_alignment_helper;
use crate::program::model::data::composite_internal::{
    compare_components_by_ordinal, CompositeInternal, DEFAULT_ALIGNMENT, DEFAULT_PACKING, MACHINE_ALIGNMENT,
    NO_PACKING,
};
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_organization_impl::{get_aligned_offset, get_least_common_multiple};
use crate::program::model::data::data_type::{DataType, SetDataTypeNameError, UnsupportedOperationError};
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_conflict_handler::{
    ConflictResult, DataTypeConflictHandler, DefaultHandlerImpl,
};
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_type_path::DataTypePath;
use crate::program::model::data::internal_data_type_component::InternalDataTypeComponent;
use crate::program::model::data::packing_type::PackingType;
use crate::program::model::data::source_archive::SourceArchive;
use crate::program::model::data::union::Union;
use crate::program::model::data::union_data_type::UnionDataTypeImpl;
use crate::program::model::data::union_internal::UnionInternal;
use crate::program::model::mem::MemBuffer;
use crate::util::exception::DuplicateNameException;
use crate::util::lock::ReentrantLock;
use crate::util::UniversalID;

/// A dummy zero-sized receiver used purely to invoke [`DbDataTypeUtilities`]'s default methods,
/// per the convention already established throughout `program/database/data`.
#[derive(Debug, Default, Clone, Copy)]
struct Utils;
impl DbDataTypeUtilities for Utils {}
impl crate::program::model::data::data_utilities::DataUtilities for Utils {}

/// Local stand-in for `BadDataType.dataType`, matching `union_data_type.rs`'s `BadDataTypeStandIn`.
struct BadDataTypeStandIn;
impl DataType for BadDataTypeStandIn {
    fn get_name(&self) -> String {
        "-BAD-".to_string()
    }
    fn get_length(&self) -> i32 {
        -1
    }
    fn get_description(&self) -> String {
        "** Bad Data Type **".to_string()
    }
}

/// Local stand-in for `Undefined1DataType.dataType`, matching `union_data_type.rs`'s
/// `Undefined1StandIn`.
struct Undefined1StandIn;
impl DataType for Undefined1StandIn {
    fn get_name(&self) -> String {
        "undefined1".to_string()
    }
    fn get_length(&self) -> i32 {
        1
    }
    fn is_undefined_type(&self) -> bool {
        true
    }
}
fn undefined1_stand_in() -> Box<dyn DataType> {
    Box::new(Undefined1StandIn)
}

/// Stand-in for `SettingsImpl.NO_SETTINGS`, matching `CompositeDB.doGetDefaultSettings()`.
struct NoSettings;
impl Settings for NoSettings {
    fn is_immutable_settings(&self) -> bool {
        true
    }
}

/// Owned forwarding wrapper letting [`UnionDb::owning_data_type_manager`]/
/// [`UnionDb::get_data_type_manager`] hand back a `Box`/`Arc`-ed [`DataTypeManager`]/
/// [`DataTypeManagerDb`] view from this struct's `Arc<Mutex<...>>` storage, rather than reaching
/// for an unsound borrowed-pointer trick. Mirrors `TypedefDbOwnerHandle` in `typedef_db.rs`.
struct UnionDbOwnerHandle(Arc<Mutex<dyn DataTypeManagerDb + Send>>);

impl DataTypeManager for UnionDbOwnerHandle {
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

impl DataTypeManagerDb for UnionDbOwnerHandle {
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

fn packing_signature(c: &dyn Composite) -> (PackingType, i32) {
    let t = c.get_packing_type();
    let v = if t == PackingType::Explicit { c.get_explicit_packing_value() } else { 0 };
    (t, v)
}

fn alignment_signature(c: &dyn Composite) -> (AlignmentType, i32) {
    let t = c.get_alignment_type();
    let v = if t == AlignmentType::Explicit { c.get_explicit_minimum_alignment() } else { 0 };
    (t, v)
}

/// Database implementation of [`Union`].
///
/// Port of `ghidra.program.database.data.UnionDB`. See the module documentation for what was
/// ported, deliberately simplified, or omitted.
pub struct UnionDb {
    db_state: DbObjectState,
    lock: Arc<ReentrantLock>,
    owner: Arc<Mutex<dyn DataTypeManagerDb + Send>>,
    composite_adapter: Arc<Mutex<dyn CompositeDBAdapter + Send>>,
    component_adapter: Arc<Mutex<dyn ComponentDBAdapter + Send>>,
    record: Mutex<DBRecord>,
    components: Mutex<Vec<DataTypeComponentDB>>,
    union_length: Mutex<i32>,
    union_alignment: Mutex<i32>,
    computed_alignment: Mutex<i32>,
    stored_name: Mutex<Option<String>>,
    stored_category_path: Mutex<Option<CategoryPath>>,
    stored_deleting: Mutex<bool>,
}

impl UnionDb {
    /// Constructs a union view over `record`, backed by `owner`, `composite_adapter` and
    /// `component_adapter`.
    ///
    /// Port of `UnionDB(DataTypeManagerDB, CompositeDBAdapter, ComponentDBAdapter, DBRecord)`.
    pub fn new(
        owner: Arc<Mutex<dyn DataTypeManagerDb + Send>>,
        composite_adapter: Arc<Mutex<dyn CompositeDBAdapter + Send>>,
        component_adapter: Arc<Mutex<dyn ComponentDBAdapter + Send>>,
        lock: Arc<ReentrantLock>,
        record: DBRecord,
    ) -> Self {
        let key = record.get_key().get_long_value();
        let db = UnionDb {
            db_state: DbObjectState::new(key),
            lock,
            owner,
            composite_adapter,
            component_adapter,
            record: Mutex::new(record),
            components: Mutex::new(Vec::new()),
            union_length: Mutex::new(0),
            union_alignment: Mutex::new(0),
            computed_alignment: Mutex::new(-1),
            stored_name: Mutex::new(None),
            stored_category_path: Mutex::new(None),
            stored_deleting: Mutex::new(false),
        };
        db.initialize();
        db
    }

    /// Port of the protected `UnionDB.initialize()`.
    fn initialize(&self) {
        let key = self.get_key();
        let mut new_components = Vec::new();
        match self.component_adapter.lock().unwrap().get_component_ids_in_composite(key) {
            Ok(ids) => {
                for id in ids {
                    match self.component_adapter.lock().unwrap().get_record(id.get_long_value()) {
                        Ok(Some(rec)) => {
                            new_components.push(DataTypeComponentDB::new_persisted(
                                self.owner.clone(),
                                self.component_adapter.clone(),
                                rec,
                            ));
                        }
                        Ok(None) => {}
                        Err(e) => self.owner.lock().unwrap().db_error(e),
                    }
                }
            }
            Err(e) => self.owner.lock().unwrap().db_error(e),
        }
        new_components.sort_by(|a, b| compare_components_by_ordinal(a, b));
        *self.components.lock().unwrap() = new_components;

        let rec = self.record.lock().unwrap();
        let length = rec.get_int(COMPOSITE_LENGTH_COL).unwrap_or(0);
        let alignment = rec.get_int(COMPOSITE_ALIGNMENT_COL).unwrap_or(0);
        drop(rec);
        *self.union_length.lock().unwrap() = length;
        *self.union_alignment.lock().unwrap() = alignment;
        *self.computed_alignment.lock().unwrap() = -1;
    }

    /// Persists the current in-memory record via the composite adapter, reporting any failure to
    /// the owning manager. Stands in for the repeated `try { compositeAdapter.updateRecord(record,
    /// ...); } catch (IOException e) { dataMgr.dbError(e); }` pattern used throughout
    /// `UnionDB.java`/`CompositeDB.java`.
    fn persist_record(&self, set_last_change_time: bool) -> io::Result<()> {
        let rec = self.record.lock().unwrap().clone();
        match self.composite_adapter.lock().unwrap().update_record(&rec, set_last_change_time) {
            Ok(()) => Ok(()),
            Err(e) => {
                let io_err = io::Error::new(e.kind(), e.to_string());
                self.owner.lock().unwrap().db_error(io_err);
                Err(e)
            }
        }
    }

    fn resolve(&self, dt: Box<dyn DataType>) -> Box<dyn DataType> {
        self.owner.lock().unwrap().resolve(dt, &DefaultHandlerImpl)
    }

    /// Port of the protected `CompositeDB.createComponent(long, int, int, int, String, String)`.
    fn create_component(
        &self,
        dt_id: i64,
        length: i32,
        ordinal: i32,
        offset: i32,
        component_name: Option<&str>,
        comment: Option<&str>,
    ) -> DataTypeComponentDB {
        let key = self.get_key();
        match self
            .component_adapter
            .lock()
            .unwrap()
            .create_record(dt_id, key, length, ordinal, offset, component_name, comment)
        {
            Ok(rec) => DataTypeComponentDB::new_persisted(self.owner.clone(), self.component_adapter.clone(), rec),
            Err(e) => {
                self.owner.lock().unwrap().db_error(e);
                // Mirrors Java: `dbError` throws a `RuntimeException`; this line is unreachable in
                // practice, matching the `throw new AssertionError()` fallthrough.
                panic!("database error creating union component");
            }
        }
    }

    /// Port of the protected `CompositeDB.doDelete(DataTypeComponentDB)`.
    fn do_delete(&self, dtc: &DataTypeComponentDB) {
        // dtc.getDataType().removeParent(this): skipped, see the module docs.
        let key = dtc.get_key();
        if key >= 0 {
            if let Err(e) = self.component_adapter.lock().unwrap().remove_record(key) {
                self.owner.lock().unwrap().db_error(e);
            }
        }
        // dataMgr.getSettingsAdapter().removeAllSettingsRecords(dtcKey): skipped, see the module
        // docs.
    }

    /// Port of the private `UnionDB.shiftOrdinals(int, int)`.
    fn shift_ordinals(&self, ordinal: i32, delta_ordinal: i32) {
        let components = self.components.lock().unwrap();
        for dtc in components.iter().skip(ordinal as usize) {
            dtc.set_ordinal(DataTypeComponent::get_ordinal(dtc) + delta_ordinal, true);
        }
    }

    /// Port of the private `UnionDB.adjustBitField(DataType)`.
    fn adjust_bit_field(&self, data_type: Box<dyn DataType>) -> Box<dyn DataType> {
        if !data_type.is_bit_field_type() {
            return data_type;
        }
        let extracted = {
            let Some(bitfield) = data_type.as_bit_field_data_type() else {
                return data_type;
            };
            (
                bitfield.get_base_data_type(),
                bitfield.get_declared_bit_size(),
                bitfield.get_bit_size(),
                bitfield.get_bit_offset(),
            )
        };
        let (base_data_type, declared_bit_size, existing_effective_bit_size, existing_bit_offset) = extracted;
        let base_data_type = self.resolve(base_data_type);

        let effective_bit_size = get_effective_bit_size(declared_bit_size, base_data_type.get_length());
        let big_endian = self.get_data_organization().is_big_endian();
        let storage_bit_offset = if big_endian {
            if declared_bit_size == 0 {
                7
            } else {
                let storage_size = get_minimum_storage_size_no_offset(effective_bit_size);
                8 * storage_size - effective_bit_size
            }
        } else {
            0
        };

        if effective_bit_size != existing_effective_bit_size || storage_bit_offset != existing_bit_offset {
            match BitFieldDataType::new(base_data_type, effective_bit_size, storage_bit_offset) {
                Ok(new_bitfield) => Box::new(new_bitfield),
                // unexpected since deriving from an existing bitfield; ignore and use the existing one
                Err(_) => data_type,
            }
        } else {
            data_type
        }
    }

    /// Port of `CompositeDB.validateDataType(DataType)`, specialized to Union's own
    /// `Undefined1DataType.dataType` substitution (always taken for `this instanceof Union`).
    fn validate_data_type_union(&self, data_type: Box<dyn DataType>) -> Result<Box<dyn DataType>, String> {
        let dynamic_can_specify_length = data_type.as_dynamic().map(|d| d.can_specify_length()).unwrap_or(false);
        self.validate_data_type(data_type, undefined1_stand_in(), dynamic_can_specify_length)
    }

    /// Port of the private `UnionDB.doAdd(DataType, int, String, String, boolean)`.
    fn do_add(
        &self,
        data_type: Box<dyn DataType>,
        length: i32,
        name: Option<&str>,
        comment: Option<&str>,
        validate_align_and_notify: bool,
    ) -> Result<DataTypeComponentDB, String> {
        let data_type = self.validate_data_type_union(data_type)?;
        let data_type = self.adjust_bit_field(data_type);
        let data_type = if validate_align_and_notify {
            let resolved = self.resolve(data_type);
            Utils.check_ancestry(self, resolved.as_ref()).map_err(|e| e.to_string())?;
            resolved
        } else {
            data_type
        };

        let is_dynamic_specifiable = data_type.as_dynamic().map(|d| d.can_specify_length()).unwrap_or(false);
        let length = self.get_preferred_component_length_default(data_type.as_ref(), is_dynamic_specifiable, length)?;

        let id = self.owner.lock().unwrap().get_resolved_id(data_type.as_ref());
        let ordinal = self.components.lock().unwrap().len() as i32;
        let dtc = self.create_component(id, length, ordinal, 0, name, comment);
        // data_type.addParent(this): skipped, see the module docs.
        self.components.lock().unwrap().push(dtc.clone());
        Ok(dtc)
    }

    /// Port of `UnionDB.add(DataType, int, String, String)`.
    fn union_add(
        &self,
        data_type: Box<dyn DataType>,
        length: i32,
        name: Option<&str>,
        comment: Option<&str>,
    ) -> Result<DataTypeComponentDB, String> {
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return Err("Object has been deleted.".to_string());
        }
        self.computed_alignment(true);
        let dtc = self.do_add(data_type, length, name, comment, true)?;
        if !self.union_repack(false, true) {
            self.owner.lock().unwrap().data_type_changed(self, false);
        }
        Ok(dtc)
    }

    /// Port of `UnionDB.insert(int, DataType, int, String, String)`. See the module docs on
    /// [`UnionDataType::union_data_type_insert`] for why the ordinal bounds check runs first.
    fn union_insert(
        &self,
        ordinal: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        name: Option<&str>,
        comment: Option<&str>,
    ) -> Result<DataTypeComponentDB, String> {
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return Err("Object has been deleted.".to_string());
        }
        if ordinal < 0 || ordinal as usize > self.components.lock().unwrap().len() {
            return Err(format!("IndexOutOfBoundsException: ordinal {ordinal} out of bounds"));
        }
        let data_type = self.validate_data_type_union(data_type)?;
        let data_type = self.adjust_bit_field(data_type);
        let data_type = self.resolve(data_type);
        Utils.check_ancestry(self, data_type.as_ref()).map_err(|e| e.to_string())?;

        self.computed_alignment(true);

        let is_dynamic_specifiable = data_type.as_dynamic().map(|d| d.can_specify_length()).unwrap_or(false);
        let length = self.get_preferred_component_length_default(data_type.as_ref(), is_dynamic_specifiable, length)?;
        let id = self.owner.lock().unwrap().get_resolved_id(data_type.as_ref());
        let dtc = self.create_component(id, length, ordinal, 0, name, comment);
        // data_type.addParent(this): skipped, see the module docs.
        self.shift_ordinals(ordinal, 1);
        self.components.lock().unwrap().insert(ordinal as usize, dtc.clone());

        if !self.union_repack(false, true) {
            self.owner.lock().unwrap().data_type_changed(self, false);
        }
        Ok(dtc)
    }

    /// Port of `UnionDB.addBitField(DataType, int, String, String)`.
    fn union_add_bit_field(
        &self,
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        name: Option<&str>,
        comment: Option<&str>,
    ) -> Result<DataTypeComponentDB, String> {
        let ordinal = self.components.lock().unwrap().len() as i32;
        self.union_insert_bit_field(ordinal, base_data_type, bit_size, name, comment)
    }

    /// Port of `UnionDB.insertBitField(int, DataType, int, String, String)`. See the module docs
    /// for why a plain [`BitFieldDataType`] is constructed instead of Java's DB-aware
    /// `BitFieldDBDataType`.
    fn union_insert_bit_field(
        &self,
        ordinal: i32,
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        name: Option<&str>,
        comment: Option<&str>,
    ) -> Result<DataTypeComponentDB, String> {
        if ordinal < 0 || ordinal as usize > self.components.lock().unwrap().len() {
            return Err(format!("IndexOutOfBoundsException: ordinal {ordinal} out of bounds"));
        }
        let bit_field_dt = BitFieldDataType::new_at_offset_zero(base_data_type, bit_size)
            .map_err(|e| format!("InvalidDataTypeException: {}", e.message()))?;
        let storage_size = bit_field_dt.get_storage_size();
        self.union_insert(ordinal, Box::new(bit_field_dt), storage_size, name, comment)
    }

    /// Port of the private `UnionDB.getBitFieldAllocation(BitFieldDataType)`.
    fn bit_field_allocation(&self, bitfield_dt: &BitFieldDataType) -> i32 {
        let bit_field_packing = *self.get_data_organization().get_bit_field_packing();
        if bit_field_packing.use_ms_convention() {
            return bitfield_dt.get_base_type_size();
        }
        if bitfield_dt.get_bit_size() == 0 {
            return 0;
        }
        let mut length = bitfield_dt.get_base_type_size();
        let pack_value = self.get_stored_packing_value();
        if pack_value > 0 && length > pack_value {
            length = get_least_common_multiple(bitfield_dt.get_storage_size(), pack_value);
        }
        length
    }

    /// Port of `UnionDB.getComputedAlignment(boolean)`. Exposed as an `&self` inherent method
    /// (backed entirely by `Mutex`-wrapped fields) so it can serve both
    /// [`CompositeDb::get_computed_alignment`] (`&mut self`-shaped in the trait) and
    /// [`DataType::get_alignment`] (`&self`-shaped) without a signature conflict.
    fn computed_alignment(&self, update_record: bool) -> i32 {
        {
            let ua = *self.union_alignment.lock().unwrap();
            if ua > 0 {
                return ua;
            }
        }
        {
            let mut ca = self.computed_alignment.lock().unwrap();
            if *ca <= 0 {
                *ca = if self.is_packing_enabled() {
                    composite_alignment_helper::get_alignment(self.get_data_organization().as_ref(), self)
                } else {
                    self.get_non_packed_alignment()
                };
            }
        }
        if update_record {
            let computed = *self.computed_alignment.lock().unwrap();
            {
                let mut rec = self.record.lock().unwrap();
                rec.set_int(COMPOSITE_ALIGNMENT_COL, computed);
            }
            let _ = self.persist_record(false);
            *self.union_alignment.lock().unwrap() = computed;
            *self.computed_alignment.lock().unwrap() = -1;
            return computed;
        }
        *self.computed_alignment.lock().unwrap()
    }

    /// Port of `UnionDB.repack(boolean, boolean)`.
    fn union_repack(&self, is_auto_change: bool, notify: bool) -> bool {
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return false;
        }

        let old_length = *self.union_length.lock().unwrap();
        let store_alignment = *self.union_alignment.lock().unwrap() <= 0;
        let old_alignment = self.computed_alignment(false);

        let packing_enabled = self.is_packing_enabled();
        let mut new_length = 0i32;
        for dtc in self.components.lock().unwrap().iter() {
            let mut length = DataTypeComponent::get_length(dtc);
            if packing_enabled && DataTypeComponent::is_bit_field_component(dtc) {
                let dt = DataTypeComponent::get_data_type(dtc);
                if let Some(bf) = dt.as_bit_field_data_type() {
                    length = self.bit_field_allocation(bf);
                }
            }
            new_length = new_length.max(length);
        }

        *self.computed_alignment.lock().unwrap() = -1;
        *self.union_alignment.lock().unwrap() = -1;
        let new_alignment = self.computed_alignment(false);
        *self.union_alignment.lock().unwrap() = new_alignment;

        if packing_enabled {
            new_length = get_aligned_offset(new_alignment, new_length);
        }
        *self.union_length.lock().unwrap() = new_length;

        let changed = old_length != new_length || old_alignment != new_alignment;

        if changed || store_alignment {
            {
                let mut rec = self.record.lock().unwrap();
                rec.set_int(COMPOSITE_LENGTH_COL, new_length);
                rec.set_int(COMPOSITE_ALIGNMENT_COL, new_alignment);
            }
            let _ = self.persist_record(changed && !is_auto_change);
        }

        // `notifySizeChanged`/`notifyAlignmentChanged` are no-ops in this port (see the module
        // docs), and -- since `changed` is defined as "length or alignment differs" -- Java's own
        // fallback `dataMgr.dataTypeChanged(this, isAutoChange)` branch is unreachable whenever
        // `changed` is true, so there is nothing left to do here even when `notify` is set.
        let _ = notify;
        changed
    }

    fn set_stored_packing_value(&self, packing_value: i32) -> Result<(), String> {
        if packing_value < NO_PACKING {
            return Err(format!("IllegalArgumentException: invalid packing value: {packing_value}"));
        }
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return Ok(());
        }
        let old_packing_value = self.get_stored_packing_value();
        if packing_value == old_packing_value {
            return Ok(());
        }
        {
            let mut rec = self.record.lock().unwrap();
            if old_packing_value == NO_PACKING || packing_value == NO_PACKING {
                rec.set_int(COMPOSITE_MIN_ALIGN_COL, DEFAULT_ALIGNMENT);
            }
            rec.set_int(COMPOSITE_PACKING_COL, packing_value);
        }
        let _ = self.persist_record(true);
        if !self.union_repack(false, true) {
            self.owner.lock().unwrap().data_type_changed(self, false);
        }
        Ok(())
    }

    fn set_stored_minimum_alignment(&self, minimum_alignment: i32) -> Result<(), String> {
        if minimum_alignment < MACHINE_ALIGNMENT {
            return Err(format!("IllegalArgumentException: invalid minimum alignment value: {minimum_alignment}"));
        }
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return Ok(());
        }
        if minimum_alignment == self.get_stored_minimum_alignment() {
            return Ok(());
        }
        {
            self.record.lock().unwrap().set_int(COMPOSITE_MIN_ALIGN_COL, minimum_alignment);
        }
        let _ = self.persist_record(true);
        if !self.union_repack(false, true) {
            self.owner.lock().unwrap().data_type_changed(self, false);
        }
        Ok(())
    }

    /// Port of `UnionDB.isPartOf(DataType)`.
    fn union_is_part_of(&self, data_type: &dyn DataType) -> bool {
        let _guard = self.lock.read();
        self.refresh_if_needed();
        if self.data_type_db_equals(data_type) {
            return true;
        }
        for dtc in self.components.lock().unwrap().iter() {
            let sub_dt = DataTypeComponent::get_data_type(dtc);
            if let Some(composite) = sub_dt.as_composite() {
                if composite.is_part_of(data_type) {
                    return true;
                }
            } else if sub_dt.is_equivalent(data_type) || data_type.is_equivalent(sub_dt.as_ref()) {
                return true;
            }
        }
        false
    }

    fn union_num_components(&self) -> i32 {
        let _guard = self.lock.read();
        self.refresh_if_needed();
        self.components.lock().unwrap().len() as i32
    }

    fn union_get_component(&self, ordinal: i32) -> Option<DataTypeComponentDB> {
        let _guard = self.lock.read();
        self.refresh_if_needed();
        let components = self.components.lock().unwrap();
        if ordinal < 0 || ordinal as usize >= components.len() {
            None
        } else {
            Some(components[ordinal as usize].clone())
        }
    }

    fn union_get_components(&self) -> Vec<DataTypeComponentDB> {
        let _guard = self.lock.read();
        self.refresh_if_needed();
        self.components.lock().unwrap().clone()
    }

    /// Port of the protected `CompositeDB.updateBitFieldDataType(DataTypeComponentDB, DataType,
    /// DataType)`.
    fn update_bit_field_data_type(
        &self,
        bitfield_component: &DataTypeComponentDB,
        old_dt: &dyn DataType,
        new_dt: &dyn DataType,
    ) -> bool {
        let dt = DataTypeComponent::get_data_type(bitfield_component);
        let Some(bitfield_dt) = dt.as_bit_field_data_type() else {
            return false;
        };
        if bitfield_dt.get_base_data_type().get_data_type_path() != old_dt.get_data_type_path()
            || !is_valid_base_data_type(new_dt)
        {
            return false;
        }
        let max_bit_size = 8 * new_dt.get_length();
        if bitfield_dt.get_bit_size() > max_bit_size {
            return false;
        }
        let owner_handle = UnionDbOwnerHandle(self.owner.clone());
        let new_base = new_dt.clone_data_type(&owner_handle);
        match BitFieldDataType::new(new_base, bitfield_dt.get_declared_bit_size(), bitfield_dt.get_bit_offset()) {
            Ok(new_bitfield) => {
                let mut comp = bitfield_component.clone();
                InternalDataTypeComponent::set_data_type(&mut comp, Box::new(new_bitfield));
                // old_dt.removeParent(this)/new_dt.addParent(this): skipped, see the module docs.
                true
            }
            Err(_) => false,
        }
    }

    /// Materializes a fresh, in-memory [`UnionDataTypeImpl`] snapshot of this union's current
    /// state, re-adding each component one at a time. Shared implementation for
    /// [`DataType::clone_data_type`]/[`DataType::copy_data_type`]/[`Union::clone_union`] -- see
    /// the module docs for why the real `UnionDataTypeImpl::union_data_type_replace_with` cannot
    /// be called directly.
    fn materialize(&self, preserve_identity: bool) -> UnionDataTypeImpl {
        let mut result = UnionDataTypeImpl::new_in_category(self.get_category_path(), self.get_name());
        let _ = result.set_description(&self.get_description());

        match self.get_packing_type() {
            PackingType::Disabled => result.set_packing_enabled(false),
            PackingType::Default => result.set_to_default_packing(),
            PackingType::Explicit => {
                let _ = result.set_explicit_packing_value(self.get_explicit_packing_value());
            }
        }
        match self.get_alignment_type() {
            AlignmentType::Machine => result.set_to_machine_aligned(),
            AlignmentType::Default => {}
            AlignmentType::Explicit => {
                let _ = result.set_explicit_minimum_alignment(self.get_explicit_minimum_alignment());
            }
        }

        for dtc in self.union_get_components() {
            let dt = DataTypeComponent::get_data_type(&dtc);
            let _ = result.add_with_length_and_name(
                dt,
                DataTypeComponent::get_length(&dtc),
                DataTypeComponent::get_field_name(&dtc),
                DataTypeComponent::get_comment(&dtc),
            );
        }

        if preserve_identity {
            // There is no setter for universal id/last-change-time on `UnionDataTypeImpl`; a
            // fresh identity is used regardless of `preserve_identity`'s value here since that
            // information can only be supplied at construction, which already happened above.
            // Kept as a parameter for symmetry with `TypedefDb::materialize`'s identical-shaped
            // helper and to make each call site's intent explicit.
        }
        result
    }

    /// Sets the field name on the component at `ordinal`, with the *real*, fully-notifying
    /// behavior of `CompositeDB.setFieldName(DataTypeComponentDB, String)` (bumps this union's
    /// `dataTypeChanged` notification). See the module docs on
    /// [`DataTypeComponentDB`](super::data_type_component_db::DataTypeComponentDB) for why the
    /// generic [`DataTypeComponent::set_field_name`] trait method cannot do this on its own.
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds (mirrors `IndexOutOfBoundsException`).
    pub fn set_component_field_name(&self, ordinal: i32, name: Option<&str>) -> Result<(), String> {
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return Ok(());
        }
        let components = self.components.lock().unwrap();
        let Some(dtc) = components.get(ordinal as usize) else {
            return Err(format!("IndexOutOfBoundsException: ordinal {ordinal} out of bounds"));
        };
        if !dtc.has_record() {
            return Ok(()); // unable to change undefined component
        }
        let changed = dtc.do_set_field_name(name);
        drop(components);
        if changed {
            self.owner.lock().unwrap().data_type_changed(self, false);
        }
        Ok(())
    }

    /// Sets the comment on the component at `ordinal`, with the *real*, fully-notifying behavior
    /// of `CompositeDB.setComment(DataTypeComponentDB, String)`. See
    /// [`set_component_field_name`](Self::set_component_field_name)'s doc comment.
    ///
    /// # Errors
    /// Returns `Err` if `ordinal` is out of bounds (mirrors `IndexOutOfBoundsException`).
    pub fn set_component_comment(&self, ordinal: i32, comment: Option<&str>) -> Result<(), String> {
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return Ok(());
        }
        let components = self.components.lock().unwrap();
        let Some(dtc) = components.get(ordinal as usize) else {
            return Err(format!("IndexOutOfBoundsException: ordinal {ordinal} out of bounds"));
        };
        if !dtc.has_record() {
            return Ok(());
        }
        let changed = dtc.do_set_comment(comment);
        drop(components);
        if changed {
            self.owner.lock().unwrap().data_type_changed(self, false);
        }
        Ok(())
    }

    /// Port of `UnionDB.replaceWith(DataType)`/`doReplaceWith(UnionInternal, boolean)`, taking
    /// `other: &dyn Union` (Java's `instanceof UnionInternal` downcast, approximated as described
    /// in the module docs) rather than a generic `&dyn DataType`.
    fn union_replace_with(&self, other: &dyn Union) -> Result<(), String> {
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return Ok(());
        }

        let other_components = other.get_components();
        let mut resolved: Vec<Box<dyn DataType>> = Vec::with_capacity(other_components.len());
        for c in &other_components {
            // doCheckedResolve's `Pointer`-specific deferred branch is dropped, see module docs.
            let dt = self.resolve(c.get_data_type());
            Utils.check_ancestry(self, dt.as_ref()).map_err(|e| e.to_string())?;
            resolved.push(dt);
        }

        let old_components = std::mem::take(&mut *self.components.lock().unwrap());
        for dtc in &old_components {
            self.do_delete(dtc);
        }
        *self.union_alignment.lock().unwrap() = -1;
        *self.computed_alignment.lock().unwrap() = -1;

        // doSetPackingAndAlignment(union): reconstructed from `Union`'s public surface -- see the
        // module docs.
        let stored_packing = match other.get_packing_type() {
            PackingType::Disabled => NO_PACKING,
            PackingType::Default => DEFAULT_PACKING,
            PackingType::Explicit => other.get_explicit_packing_value(),
        };
        let stored_alignment = match other.get_alignment_type() {
            AlignmentType::Machine => MACHINE_ALIGNMENT,
            AlignmentType::Default => DEFAULT_ALIGNMENT,
            AlignmentType::Explicit => other.get_explicit_minimum_alignment(),
        };
        {
            let mut rec = self.record.lock().unwrap();
            rec.set_int(COMPOSITE_MIN_ALIGN_COL, stored_alignment);
            rec.set_int(COMPOSITE_PACKING_COL, stored_packing);
        }

        for (i, dt) in resolved.into_iter().enumerate() {
            self.do_add(
                dt,
                other_components[i].get_length(),
                other_components[i].get_field_name().as_deref(),
                other_components[i].get_comment().as_deref(),
                false,
            )?;
        }

        self.union_repack(false, false);
        {
            let mut rec = self.record.lock().unwrap();
            rec.set_string(COMPOSITE_COMMENT_COL, Some(other.get_description()));
        }
        let _ = self.persist_record(true);
        // pointerPostResolveRequired / dataMgr.queuePostResolve(this, union): not ported, see the
        // module docs.
        Ok(())
    }
}

impl DbObject for UnionDb {
    fn state(&self) -> &DbObjectState {
        &self.db_state
    }

    fn refresh(&self, record: Option<&DBRecord>) -> bool {
        let rec = match record {
            Some(r) => Some(r.clone()),
            None => match self.composite_adapter.lock().unwrap().get_record(self.get_key()) {
                Ok(r) => r,
                Err(e) => {
                    self.owner.lock().unwrap().db_error(e);
                    return false;
                }
            },
        };
        match rec {
            Some(r) => {
                *self.record.lock().unwrap() = r;
                self.initialize();
                self.data_type_db_complete_refresh();
                true
            }
            None => false,
        }
    }
}

impl DataTypeDb for UnionDb {
    fn owning_data_type_manager(&self) -> Arc<dyn DataTypeManagerDb> {
        Arc::new(UnionDbOwnerHandle(self.owner.clone()))
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
        self.record.lock().unwrap().get_string(COMPOSITE_NAME_COL).unwrap_or_default().to_string()
    }
    fn do_get_category_id(&self) -> i64 {
        self.record.lock().unwrap().get_long(COMPOSITE_CAT_COL).unwrap_or(0)
    }
    fn do_set_category_path_record(&self, category_id: i64) -> io::Result<()> {
        {
            self.record.lock().unwrap().set_long(COMPOSITE_CAT_COL, category_id);
        }
        self.persist_record(false)
    }
    fn do_set_name_record(&self, new_name: &str) -> Result<(), DoSetNameRecordError> {
        {
            self.record.lock().unwrap().set_string(COMPOSITE_NAME_COL, Some(new_name.to_string()));
        }
        self.persist_record(true).map_err(|e| DoSetNameRecordError::Io(e.to_string()))
    }
    fn get_source_archive_id(&self) -> UniversalID {
        UniversalID::new(self.record.lock().unwrap().get_long(COMPOSITE_SOURCE_ARCHIVE_ID_COL).unwrap_or(0))
    }
    fn set_source_archive_id(&self, id: UniversalID) {
        {
            self.record.lock().unwrap().set_long(COMPOSITE_SOURCE_ARCHIVE_ID_COL, id.value());
        }
        let _ = self.persist_record(false);
        self.owner.lock().unwrap().data_type_changed(self, false);
    }

    /// Port of `UnionDB.isEquivalent(DataType, DataTypeConflictHandler)`. See the module docs for
    /// the `resolving`/equivalence-cache omissions.
    fn is_equivalent_with_handler(&self, data_type: &dyn DataType, handler: Option<&dyn DataTypeConflictHandler>) -> bool {
        if std::ptr::eq(self as *const Self as *const (), data_type as *const dyn DataType as *const ()) {
            return true;
        }
        let Some(union) = data_type.as_union() else {
            return false;
        };
        self.validate(self.lock());

        if let Some(h) = handler {
            if h.resolve_conflict(data_type, self) == ConflictResult::UseExisting {
                return true;
            }
        }

        if packing_signature(self) != packing_signature(union) || alignment_signature(self) != alignment_signature(union) {
            // rely on component match instead of checking length, since dynamic component sizes
            // could affect length
            return false;
        }
        let my_comps = self.union_get_components();
        let other_comps = union.get_components();
        if my_comps.len() != other_comps.len() {
            return false;
        }
        let subsequent = handler.map(|h| h.get_subsequent_handler());
        for (mine, other) in my_comps.iter().zip(other_comps.iter()) {
            if !mine.is_equivalent_with_handler(other.as_ref(), subsequent) {
                return false;
            }
        }
        true
    }

    fn set_universal_id(&self, old_universal_id: UniversalID) {
        {
            self.record.lock().unwrap().set_long(COMPOSITE_UNIVERSAL_DT_ID_COL, old_universal_id.value());
        }
        let _ = self.persist_record(false);
        self.owner.lock().unwrap().data_type_changed(self, false);
    }
}

impl CompositeDb for UnionDb {
    fn composite_db_has_language_dependant_length(&self) -> bool {
        true
    }

    fn get_computed_alignment(&mut self, update_record: bool) -> i32 {
        self.computed_alignment(update_record)
    }

    fn composite_db_repack(&mut self, is_auto_change: bool, notify: bool) -> bool {
        self.union_repack(is_auto_change, notify)
    }

    /// Port of `UnionDB.fixupComponents()`.
    fn fixup_components(&mut self) -> io::Result<()> {
        let mut changed = false;
        let n = self.components.lock().unwrap().len();
        for i in 0..n {
            let dtc = self.components.lock().unwrap()[i].clone();
            let dt = DataTypeComponent::get_data_type(&dtc);
            if dt.as_dynamic().is_some() {
                continue;
            }
            let dt = if dt.is_bit_field_type() { self.adjust_bit_field(dt) } else { dt };
            let is_dynamic_specifiable = dt.as_dynamic().map(|d| d.can_specify_length()).unwrap_or(false);
            let length = match self.get_preferred_component_length_default(dt.as_ref(), is_dynamic_specifiable, -1) {
                Ok(l) => l,
                Err(_) => continue,
            };
            if length < 0 {
                continue;
            }
            if length != DataTypeComponent::get_length(&dtc) {
                let _ = dtc.set_length(length, true);
                changed = true;
            }
        }
        if changed {
            let _ = self.union_repack(true, false);
            self.owner.lock().unwrap().data_type_changed(self, true);
        }
        Ok(())
    }

    fn for_each_defined_component(&self, consumer: &mut dyn FnMut(&dyn DataTypeComponent)) {
        for dtc in self.components.lock().unwrap().iter() {
            consumer(dtc);
        }
    }
}

impl CompositeInternal for UnionDb {
    fn get_stored_packing_value(&self) -> i32 {
        let _guard = self.lock.read();
        self.refresh_if_needed();
        self.record.lock().unwrap().get_int(COMPOSITE_PACKING_COL).unwrap_or(0)
    }

    fn get_stored_minimum_alignment(&self) -> i32 {
        let _guard = self.lock.read();
        self.refresh_if_needed();
        self.record.lock().unwrap().get_int(COMPOSITE_MIN_ALIGN_COL).unwrap_or(0)
    }
}

impl Composite for UnionDb {
    fn get_num_components(&self) -> i32 {
        self.union_num_components()
    }
    fn get_num_defined_components(&self) -> i32 {
        self.union_num_components()
    }
    fn get_component(&self, ordinal: i32) -> Result<Box<dyn DataTypeComponent>, String> {
        self.union_get_component(ordinal)
            .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
            .ok_or_else(|| format!("IndexOutOfBoundsException: ordinal {ordinal} out of bounds"))
    }
    fn get_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
        self.union_get_components().into_iter().map(|c| Box::new(c) as Box<dyn DataTypeComponent>).collect()
    }
    fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
        self.get_components()
    }

    fn add_with_length_and_name(
        &mut self,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.union_add(data_type, length, component_name.as_deref(), comment.as_deref())
            .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
    }

    fn add_bit_field(
        &mut self,
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.union_add_bit_field(base_data_type, bit_size, component_name.as_deref(), comment.as_deref())
            .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
    }

    fn insert_with_length_and_name(
        &mut self,
        ordinal: i32,
        data_type: Box<dyn DataType>,
        length: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.union_insert(ordinal, data_type, length, component_name.as_deref(), comment.as_deref())
            .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
    }

    fn delete(&mut self, ordinal: i32) -> Result<(), String> {
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return Ok(());
        }
        if ordinal < 0 || ordinal as usize >= self.components.lock().unwrap().len() {
            return Err(format!("IndexOutOfBoundsException: ordinal {ordinal} out of bounds"));
        }
        self.computed_alignment(true);
        let dtc = self.components.lock().unwrap().remove(ordinal as usize);
        self.do_delete(&dtc);
        self.shift_ordinals(ordinal, -1);
        if !self.union_repack(false, true) {
            self.owner.lock().unwrap().data_type_changed(self, false);
        }
        Ok(())
    }

    fn delete_set(&mut self, ordinals: &HashSet<i32>) -> Result<(), String> {
        if ordinals.is_empty() {
            return Ok(());
        }
        if ordinals.len() == 1 {
            let ordinal = *ordinals.iter().next().expect("len() == 1");
            return Composite::delete(self, ordinal);
        }
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return Ok(());
        }
        if self.is_packing_enabled() {
            self.computed_alignment(true);
        }

        let old_components = std::mem::take(&mut *self.components.lock().unwrap());
        let mut new_components = Vec::with_capacity(old_components.len());
        let mut new_length = 0i32;
        let mut ordinal_adjustment = 0i32;
        for dtc in old_components {
            let ordinal = DataTypeComponent::get_ordinal(&dtc);
            if ordinals.contains(&ordinal) {
                self.do_delete(&dtc);
                ordinal_adjustment -= 1;
            } else {
                if ordinal_adjustment != 0 {
                    dtc.set_ordinal(DataTypeComponent::get_ordinal(&dtc) + ordinal_adjustment, true);
                }
                new_length = new_length.max(DataTypeComponent::get_length(&dtc));
                new_components.push(dtc);
            }
        }
        *self.components.lock().unwrap() = new_components;

        if self.is_packing_enabled() {
            if !self.union_repack(false, true) {
                self.owner.lock().unwrap().data_type_changed(self, false);
            }
        } else {
            let size_changed = *self.union_length.lock().unwrap() != new_length;
            if size_changed {
                *self.union_length.lock().unwrap() = new_length;
                self.record.lock().unwrap().set_int(COMPOSITE_LENGTH_COL, new_length);
            }
            let _ = self.persist_record(true);
            if !size_changed {
                self.owner.lock().unwrap().data_type_changed(self, false);
            }
            // notifySizeChanged(false): no-op, see the module docs.
        }
        Ok(())
    }

    fn is_part_of(&self, data_type: &dyn DataType) -> bool {
        self.union_is_part_of(data_type)
    }

    fn repack(&mut self) {
        if self.check_deleted().is_err() {
            return;
        }
        let _ = self.union_repack(false, true);
    }

    fn get_packing_type(&self) -> PackingType {
        let packing = self.get_stored_packing_value();
        if packing < DEFAULT_PACKING {
            PackingType::Disabled
        } else if packing == DEFAULT_PACKING {
            PackingType::Default
        } else {
            PackingType::Explicit
        }
    }

    fn set_packing_enabled(&mut self, enabled: bool) {
        if enabled == self.is_packing_enabled() {
            return;
        }
        let _ = self.set_stored_packing_value(if enabled { DEFAULT_PACKING } else { NO_PACKING });
    }

    fn set_to_default_packing(&mut self) {
        let _ = self.set_stored_packing_value(DEFAULT_PACKING);
    }

    fn get_explicit_packing_value(&self) -> i32 {
        self.get_stored_packing_value()
    }

    fn set_explicit_packing_value(&mut self, packing_value: i32) -> Result<(), String> {
        if packing_value <= 0 {
            return Err(format!("IllegalArgumentException: explicit packing value must be positive: {packing_value}"));
        }
        self.set_stored_packing_value(packing_value)
    }

    fn get_alignment_type(&self) -> AlignmentType {
        let min = self.get_stored_minimum_alignment();
        if min < DEFAULT_ALIGNMENT {
            AlignmentType::Machine
        } else if min == DEFAULT_ALIGNMENT {
            AlignmentType::Default
        } else {
            AlignmentType::Explicit
        }
    }

    fn set_to_default_aligned(&mut self) {
        let _ = self.set_stored_minimum_alignment(DEFAULT_ALIGNMENT);
    }

    fn set_to_machine_aligned(&mut self) {
        let _ = self.set_stored_minimum_alignment(MACHINE_ALIGNMENT);
    }

    fn get_explicit_minimum_alignment(&self) -> i32 {
        self.get_stored_minimum_alignment()
    }

    fn set_explicit_minimum_alignment(&mut self, minimum_alignment: i32) -> Result<(), String> {
        if minimum_alignment <= 0 {
            return Err(format!("IllegalArgumentException: explicit minimum alignment must be positive: {minimum_alignment}"));
        }
        self.set_stored_minimum_alignment(minimum_alignment)
    }
}

impl Union for UnionDb {
    fn clone_union(&self, dtm: &dyn DataTypeManager) -> Box<dyn Union> {
        let _ = dtm;
        // Java's `dataMgr == dataMgr` fast path (`return this`) is not taken -- see module docs.
        Box::new(self.materialize(true))
    }

    fn insert_bit_field(
        &mut self,
        ordinal: i32,
        base_data_type: Box<dyn DataType>,
        bit_size: i32,
        component_name: Option<String>,
        comment: Option<String>,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        self.union_insert_bit_field(ordinal, base_data_type, bit_size, component_name.as_deref(), comment.as_deref())
            .map(|c| Box::new(c) as Box<dyn DataTypeComponent>)
    }
}

impl UnionInternal for UnionDb {}

impl DataType for UnionDb {
    fn get_name(&self) -> String {
        self.data_type_db_get_name()
    }

    fn set_name(&mut self, name: &str) -> Result<(), SetDataTypeNameError> {
        self.data_type_db_set_name(name, &Utils).map_err(|e| match e {
            SetNameError::Duplicate(d) => SetDataTypeNameError::Duplicate(d),
            SetNameError::InvalidName(i) => SetDataTypeNameError::InvalidName(i),
            SetNameError::Io(msg) => SetDataTypeNameError::InvalidName(crate::util::exception::InvalidNameException::with_message(msg)),
            SetNameError::Deleted(msg) => SetDataTypeNameError::InvalidName(crate::util::exception::InvalidNameException::with_message(msg)),
        })
    }

    fn get_category_path(&self) -> CategoryPath {
        self.data_type_db_get_category_path()
    }

    /// Port of the inherited `DataTypeDB.setCategoryPath(CategoryPath)`/private
    /// `doSetCategoryPath(CategoryPath)`. `dataMgr.dataTypeCategoryPathChanged(...)` (a
    /// dependent-notification hook not yet ported) is omitted; the record and cached path are
    /// still updated for real. Mirrors `TypedefDb::base_set_category_path`'s identical port of the
    /// same inherited method.
    fn set_category_path(&mut self, path: CategoryPath) -> Result<(), DuplicateNameException> {
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return Ok(());
        }
        if self.data_type_db_get_category_path() == path {
            return Ok(());
        }
        let current_name = self.data_type_db_get_name();
        if self.owner.lock().unwrap().get_data_type_in_category(&path, &current_name).is_some() {
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

    fn get_data_type_path(&self) -> DataTypePath {
        self.data_type_db_get_data_type_path()
    }

    fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
        Some(Box::new(UnionDbOwnerHandle(self.owner.clone())))
    }

    fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
        self.owner.lock().unwrap().get_data_organization()
    }

    fn get_mnemonic(&self, _settings: &dyn Settings) -> String {
        self.get_display_name()
    }

    fn is_zero_length(&self) -> bool {
        *self.union_length.lock().unwrap() == 0
    }

    fn get_length(&self) -> i32 {
        let _guard = self.lock.read();
        self.refresh_if_needed();
        let len = *self.union_length.lock().unwrap();
        if len == 0 {
            1
        } else {
            len
        }
    }

    fn get_aligned_length(&self) -> i32 {
        self.get_length()
    }

    fn get_alignment(&self) -> i32 {
        // Simplified from `getComputedAlignment(refreshIfNeeded() && dataMgr.isTransactionActive())`
        // per `composite_db.rs`'s own documented precedent for this exact method.
        self.computed_alignment(false)
    }

    fn has_language_dependant_length(&self) -> bool {
        true
    }

    fn get_description(&self) -> String {
        let _guard = self.lock.read();
        self.refresh_if_needed();
        self.record.lock().unwrap().get_string(COMPOSITE_COMMENT_COL).unwrap_or("").to_string()
    }

    fn set_description(&mut self, description: &str) -> Result<(), UnsupportedOperationError> {
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return Ok(());
        }
        let current = self.record.lock().unwrap().get_string(COMPOSITE_COMMENT_COL).map(str::to_string);
        if current.as_deref() == Some(description) {
            return Ok(());
        }
        {
            self.record.lock().unwrap().set_string(COMPOSITE_COMMENT_COL, Some(description.to_string()));
        }
        let _ = self.persist_record(true);
        self.owner.lock().unwrap().data_type_changed(self, false);
        Ok(())
    }

    fn is_not_yet_defined(&self) -> bool {
        self.union_num_components() == 0 && !self.is_packing_enabled()
    }

    fn get_representation(&self, _buf: &dyn MemBuffer, _settings: &dyn Settings, _length: i32) -> String {
        if self.is_not_yet_defined() {
            "<Empty-Union>".to_string()
        } else {
            String::new()
        }
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        Box::new(NoSettings)
    }

    fn is_deleted(&self) -> bool {
        self.data_type_db_is_deleted()
    }

    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        self.is_equivalent_with_handler(dt, None)
    }

    fn is_union(&self) -> bool {
        true
    }

    fn as_composite(&self) -> Option<&dyn Composite> {
        Some(self)
    }

    fn as_union(&self) -> Option<&dyn Union> {
        Some(self)
    }

    fn into_composite(self: Box<Self>) -> Option<Box<dyn Composite>> {
        Some(self)
    }

    fn get_default_label_prefix(&self) -> Option<String> {
        Some(format!("UNION_{}", self.get_name()))
    }

    fn get_last_change_time(&self) -> i64 {
        self.record.lock().unwrap().get_long(COMPOSITE_LAST_CHANGE_TIME_COL).unwrap_or(0)
    }

    fn get_last_change_time_in_source_archive(&self) -> i64 {
        self.record.lock().unwrap().get_long(COMPOSITE_SOURCE_SYNC_TIME_COL).unwrap_or(0)
    }

    fn get_universal_id(&self) -> UniversalID {
        UniversalID::new(self.record.lock().unwrap().get_long(COMPOSITE_UNIVERSAL_DT_ID_COL).unwrap_or(0))
    }

    fn set_last_change_time(&mut self, last_change_time: i64) {
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return;
        }
        {
            self.record.lock().unwrap().set_long(COMPOSITE_LAST_CHANGE_TIME_COL, last_change_time);
        }
        let _ = self.persist_record(false);
        self.owner.lock().unwrap().data_type_changed(self, false);
    }

    fn set_last_change_time_in_source_archive(&mut self, last_change_time_in_source_archive: i64) {
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return;
        }
        {
            self.record.lock().unwrap().set_long(COMPOSITE_SOURCE_SYNC_TIME_COL, last_change_time_in_source_archive);
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
        // Java throws `IllegalArgumentException` when `dataType` is not a `UnionInternal`; this
        // signature has no way to propagate that, so a non-`Union` argument is simply ignored.
        let Some(union) = data_type.as_union() else {
            return;
        };
        let _ = self.union_replace_with(union);
    }

    fn copy_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        let _ = dtm;
        Box::new(self.materialize(false))
    }

    fn clone_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        let _ = dtm;
        Box::new(self.materialize(true))
    }

    /// Port of `UnionDB.dataTypeSizeChanged(DataType)`.
    fn data_type_size_changed(&mut self, dt: &dyn DataType) {
        if self.stored_deleting() {
            return;
        }
        if dt.is_bit_field_type() {
            return;
        }
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return;
        }
        let target_path = dt.get_data_type_path();
        let is_dynamic = dt.as_dynamic().map(|d| d.can_specify_length()).unwrap_or(false);
        let mut changed = false;
        let n = self.components.lock().unwrap().len();
        for i in 0..n {
            let dtc = self.components.lock().unwrap()[i].clone();
            if DataTypeComponent::get_data_type(&dtc).get_data_type_path() == target_path {
                let old_len = DataTypeComponent::get_length(&dtc);
                if let Ok(length) = self.get_preferred_component_length_default(dt, is_dynamic, old_len) {
                    if length != old_len {
                        let _ = dtc.set_length(length, true);
                        changed = true;
                    }
                }
            }
        }
        if changed && !self.union_repack(true, true) {
            self.owner.lock().unwrap().data_type_changed(self, true);
        }
    }

    /// Port of `UnionDB.dataTypeAlignmentChanged(DataType)`.
    fn data_type_alignment_changed(&mut self, dt: &dyn DataType) {
        if self.stored_deleting() {
            return;
        }
        if dt.is_bit_field_type() {
            return;
        }
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return;
        }
        if self.is_packing_enabled() {
            let _ = self.union_repack(true, true);
        }
    }

    /// Port of `UnionDB.dataTypeDeleted(DataType)`. See the module docs for the
    /// bitfield-base-type-deleted omission.
    fn data_type_deleted(&mut self, dt: &dyn DataType) {
        if self.stored_deleting() {
            return;
        }
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return;
        }
        let target_path = dt.get_data_type_path();
        let mut changed = false;
        let n = self.components.lock().unwrap().len();
        for i in (0..n).rev() {
            let mut dtc = self.components.lock().unwrap()[i].clone();
            if DataTypeComponent::is_bit_field_component(&dtc) {
                // Bitfield-base-type-deleted revert case: not ported, see the module docs.
                continue;
            }
            if DataTypeComponent::get_data_type(&dtc).get_data_type_path() == target_path {
                // dt.removeParent(this): skipped, see the module docs.
                InternalDataTypeComponent::set_data_type(&mut dtc, Box::new(BadDataTypeStandIn));
                // dataMgr.getSettingsAdapter().removeAllSettingsRecords(...): skipped.
                let new_comment = crate::program::database::data::data_type_db::prepend_comment(
                    &format!("Type '{}' was deleted", dt.get_display_name()),
                    DataTypeComponent::get_comment(&dtc).as_deref(),
                );
                dtc.do_set_comment(Some(&new_comment));
                changed = true;
            }
        }
        if changed && (!self.is_packing_enabled() || !self.union_repack(false, true)) {
            self.owner.lock().unwrap().data_type_changed(self, false);
        }
    }

    /// Port of `UnionDB.dataTypeReplaced(DataType, DataType)`. Unlike the `TypedefDb`/
    /// `UnionDataTypeImpl` precedents, this *can* be fully ported despite the borrowed `new_dt`
    /// parameter: [`DataType::clone_data_type`] takes `&self` and returns an *owned* clone,
    /// exactly matching Java's own `replacementDt.clone(dataMgr)` call, so there is no
    /// owned-vs-borrowed gap to route around here.
    fn data_type_replaced(&mut self, old_dt: &dyn DataType, new_dt: &dyn DataType) {
        if self.stored_deleting() {
            return;
        }
        if Utils.check_valid_replacement(old_dt, new_dt).is_err() {
            return;
        }
        let _guard = self.lock.write();
        if self.check_deleted().is_err() {
            return;
        }

        let owner_handle = UnionDbOwnerHandle(self.owner.clone());
        let replacement_dt: Box<dyn DataType> = (|| -> Result<Box<dyn DataType>, String> {
            let candidate: Box<dyn DataType> = if new_dt.is_default_data_type() {
                undefined1_stand_in()
            } else if let Some(dynamic) = new_dt.as_dynamic() {
                if !dynamic.can_specify_length() {
                    return Err("not a specifiable-length dynamic type".to_string());
                }
                new_dt.clone_data_type(&owner_handle)
            } else if new_dt.is_factory_type() || new_dt.get_length() <= 0 {
                return Err("invalid replacement length".to_string());
            } else {
                new_dt.clone_data_type(&owner_handle)
            };
            Utils.check_ancestry(self, candidate.as_ref()).map_err(|e| e.to_string())?;
            Ok(candidate)
        })()
        .unwrap_or_else(|_| undefined1_stand_in());

        let old_path = old_dt.get_data_type_path();
        let is_dynamic_new = new_dt.as_dynamic().map(|d| d.can_specify_length()).unwrap_or(false);
        let mut changed = false;
        let n = self.components.lock().unwrap().len();
        for i in (0..n).rev() {
            let mut dtc = self.components.lock().unwrap()[i].clone();
            if DataTypeComponent::is_bit_field_component(&dtc) {
                if self.update_bit_field_data_type(&dtc, old_dt, replacement_dt.as_ref()) {
                    changed = true;
                }
            } else if DataTypeComponent::get_data_type(&dtc).get_data_type_path() == old_path {
                let old_len = DataTypeComponent::get_length(&dtc);
                let len = self
                    .get_preferred_component_length_default(new_dt, is_dynamic_new, old_len)
                    .unwrap_or(old_len);
                let _ = dtc.set_length(len, false);
                // old_dt.removeParent(this): skipped, see the module docs.
                let replacement_clone = replacement_dt.clone_data_type(&owner_handle);
                InternalDataTypeComponent::set_data_type(&mut dtc, replacement_clone);
                // dataMgr.getSettingsAdapter().removeAllSettingsRecords/replacementDt.addParent(this):
                // skipped.
                changed = true;
            }
        }
        if changed {
            let _ = self.union_repack(false, false);
            let _ = self.persist_record(true);
            // notifySizeChanged(false): no-op, see the module docs.
        }
    }

    fn data_type_name_changed(&mut self, _dt: &dyn DataType, _old_name: &str) {
        // ignored -- matches `UnionDB.dataTypeNameChanged`.
    }
}

impl std::fmt::Display for UnionDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", crate::program::model::data::composite_internal::to_string(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use crate::program::database::data::composite_db_adapter::{schema as composite_schema, COMPOSITE_NUM_COMPONENTS_COL};
    use crate::program::model::data::category_path::ROOT;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    fn component_schema() -> Arc<Schema> {
        Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Data Type ID".to_string(),
            vec![
                FieldType::Long,
                FieldType::Int,
                FieldType::Long,
                FieldType::String,
                FieldType::String,
                FieldType::Int,
                FieldType::Int,
            ],
            vec![
                "Parent".to_string(),
                "Offset".to_string(),
                "Data Type ID".to_string(),
                "Field Name".to_string(),
                "Comment".to_string(),
                "Component Size".to_string(),
                "Ordinal".to_string(),
            ],
            vec![],
        ))
    }

    use crate::program::database::data::component_db_adapter::{
        COMPONENT_COMMENT_COL, COMPONENT_DT_ID_COL, COMPONENT_FIELD_NAME_COL, COMPONENT_OFFSET_COL,
        COMPONENT_ORDINAL_COL, COMPONENT_PARENT_ID_COL, COMPONENT_SIZE_COL,
    };

    #[derive(Clone)]
    struct MockLeaf {
        name: String,
        length: i32,
        alignment: i32,
    }
    impl DataType for MockLeaf {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_alignment(&self) -> i32 {
            self.alignment
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.name == dt.get_name() && self.length == dt.get_length()
        }
        fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
            Box::new(self.clone())
        }
        fn is_integer_type(&self) -> bool {
            true
        }
        fn is_signed_integer_type(&self) -> bool {
            true
        }
    }
    fn leaf(name: &str, length: i32) -> Box<dyn DataType> {
        Box::new(MockLeaf { name: name.to_string(), length, alignment: length.max(1) })
    }

    // ===================================================================================
    // In-memory adapters
    // ===================================================================================

    struct TestCompositeAdapter {
        records: StdMutex<HashMap<i64, DBRecord>>,
        next_key: StdMutex<i64>,
    }
    impl TestCompositeAdapter {
        fn new() -> Self {
            TestCompositeAdapter { records: StdMutex::new(HashMap::new()), next_key: StdMutex::new(0) }
        }
    }
    impl CompositeDBAdapter for TestCompositeAdapter {
        fn version(&self) -> i32 {
            6
        }
        fn create_record(
            &mut self,
            name: &str,
            comments: Option<&str>,
            is_union: bool,
            category_id: i64,
            length: i32,
            computed_alignment: i32,
            source_archive_id: i64,
            source_data_type_id: i64,
            last_change_time: i64,
            pack_value: i32,
            min_alignment: i32,
        ) -> io::Result<DBRecord> {
            let mut key = self.next_key.lock().unwrap();
            let mut rec = DBRecord::new(composite_schema(), Field::Long(Some(*key)));
            *key += 1;
            rec.set_string(COMPOSITE_NAME_COL, Some(name.to_string()));
            rec.set_string(COMPOSITE_COMMENT_COL, comments.map(str::to_string));
            rec.set_field(crate::program::database::data::composite_db_adapter::COMPOSITE_IS_UNION_COL, Field::Boolean(Some(is_union)));
            rec.set_long(COMPOSITE_CAT_COL, category_id);
            rec.set_int(COMPOSITE_LENGTH_COL, length);
            rec.set_int(COMPOSITE_ALIGNMENT_COL, computed_alignment);
            rec.set_int(COMPOSITE_NUM_COMPONENTS_COL, 0);
            rec.set_long(COMPOSITE_SOURCE_ARCHIVE_ID_COL, source_archive_id);
            rec.set_long(COMPOSITE_UNIVERSAL_DT_ID_COL, source_data_type_id);
            rec.set_long(COMPOSITE_SOURCE_SYNC_TIME_COL, 0);
            rec.set_long(COMPOSITE_LAST_CHANGE_TIME_COL, last_change_time);
            rec.set_int(COMPOSITE_PACKING_COL, pack_value);
            rec.set_int(COMPOSITE_MIN_ALIGN_COL, min_alignment);
            self.records.lock().unwrap().insert(rec.get_key().get_long_value(), rec.clone());
            Ok(rec)
        }
        fn get_record(&self, data_type_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.records.lock().unwrap().get(&data_type_id).cloned())
        }
        fn update_record(&mut self, record: &DBRecord, _set_last_change_time: bool) -> io::Result<()> {
            self.records.lock().unwrap().insert(record.get_key().get_long_value(), record.clone());
            Ok(())
        }
        fn remove_record(&mut self, data_id: i64) -> io::Result<bool> {
            Ok(self.records.lock().unwrap().remove(&data_id).is_some())
        }
        fn delete_table(&mut self, _handle: &mut crate::framework::db::DBHandle) -> io::Result<()> {
            Ok(())
        }
        fn get_record_ids_in_category(&self, category_id: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .lock()
                .unwrap()
                .values()
                .filter(|r| matches!(r.get_field(COMPOSITE_CAT_COL), Field::Long(Some(v)) if *v == category_id))
                .map(|r| r.get_key().clone())
                .collect())
        }
        fn get_record_ids_for_source_archive(&self, _archive_id: i64) -> io::Result<Vec<Field>> {
            Ok(Vec::new())
        }
        fn get_record_with_ids(&self, _source_id: UniversalID, _datatype_id: UniversalID) -> io::Result<Option<DBRecord>> {
            Ok(None)
        }
    }
    impl crate::program::util::DBRecordAdapter for TestCompositeAdapter {
        fn get_records(&self) -> io::Result<Box<dyn crate::framework::db::RecordIterator + '_>> {
            unimplemented!("not needed for these tests")
        }
        fn get_record_count(&self) -> usize {
            self.records.lock().unwrap().len()
        }
    }

    struct TestComponentAdapter {
        records: StdMutex<HashMap<i64, DBRecord>>,
        next_key: StdMutex<i64>,
    }
    impl TestComponentAdapter {
        fn new() -> Self {
            TestComponentAdapter { records: StdMutex::new(HashMap::new()), next_key: StdMutex::new(0) }
        }
    }
    impl ComponentDBAdapter for TestComponentAdapter {
        fn create_record(
            &mut self,
            data_type_id: i64,
            parent_id: i64,
            length: i32,
            ordinal: i32,
            offset: i32,
            field_name: Option<&str>,
            comment: Option<&str>,
        ) -> io::Result<DBRecord> {
            let mut key = self.next_key.lock().unwrap();
            let mut rec = DBRecord::new(component_schema(), Field::Long(Some(*key)));
            *key += 1;
            rec.set_long(COMPONENT_PARENT_ID_COL, parent_id);
            rec.set_int(COMPONENT_OFFSET_COL, offset);
            rec.set_long(COMPONENT_DT_ID_COL, data_type_id);
            rec.set_string(COMPONENT_FIELD_NAME_COL, field_name.map(str::to_string));
            rec.set_string(COMPONENT_COMMENT_COL, comment.map(str::to_string));
            rec.set_int(COMPONENT_SIZE_COL, length);
            rec.set_int(COMPONENT_ORDINAL_COL, ordinal);
            self.records.lock().unwrap().insert(rec.get_key().get_long_value(), rec.clone());
            Ok(rec)
        }
        fn get_record(&self, component_id: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.records.lock().unwrap().get(&component_id).cloned())
        }
        fn remove_record(&mut self, component_id: i64) -> io::Result<bool> {
            Ok(self.records.lock().unwrap().remove(&component_id).is_some())
        }
        fn update_record(&mut self, record: &DBRecord) -> io::Result<()> {
            self.records.lock().unwrap().insert(record.get_key().get_long_value(), record.clone());
            Ok(())
        }
        fn get_component_ids_in_composite(&self, composite_id: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .lock()
                .unwrap()
                .values()
                .filter(|r| matches!(r.get_field(COMPONENT_PARENT_ID_COL), Field::Long(Some(v)) if *v == composite_id))
                .map(|r| r.get_key().clone())
                .collect())
        }
    }

    // ===================================================================================
    // In-memory `DataTypeManagerDb` test double.
    // ===================================================================================

    struct TestManager {
        data_types: Vec<(i64, CategoryPath, Box<dyn DataType>)>,
        next_id: i64,
        allows_settings: bool,
        errors: Vec<String>,
        changed_log: Vec<bool>,
        deleted: Vec<i64>,
    }
    impl TestManager {
        fn new() -> Self {
            TestManager {
                data_types: Vec::new(),
                next_id: 1,
                allows_settings: true,
                errors: Vec::new(),
                changed_log: Vec::new(),
                deleted: Vec::new(),
            }
        }
    }
    impl DataTypeManager for TestManager {
        fn get_universal_id(&self) -> UniversalID {
            UniversalID::new(1000)
        }
        fn get_category(&self, _category_id: i64) -> Option<Box<dyn Category>> {
            Some(Box::new(TestCategory))
        }
        fn get_root_category(&self) -> Box<dyn Category> {
            Box::new(TestCategory)
        }
        fn get_data_type_in_category(&self, _path: &CategoryPath, _name: &str) -> Option<Box<dyn DataType>> {
            None
        }
        fn create_category(&mut self, _path: &CategoryPath) -> Box<dyn Category> {
            Box::new(TestCategory)
        }
        fn resolve(&mut self, data_type: Box<dyn DataType>, _handler: &dyn DataTypeConflictHandler) -> Box<dyn DataType> {
            let name = data_type.get_name();
            let path = data_type.get_category_path();
            if let Some((_, _, existing)) = self.data_types.iter().find(|(_, p, dt)| *p == path && dt.get_name() == name) {
                return existing.clone_data_type(&NoopManager);
            }
            let id = self.next_id;
            self.next_id += 1;
            let stored = data_type.clone_data_type(&NoopManager);
            let handed_back = data_type.clone_data_type(&NoopManager);
            self.data_types.push((id, path, stored));
            handed_back
        }
        fn get_resolved_id(&mut self, dt: &dyn DataType) -> i64 {
            let name = dt.get_name();
            let path = dt.get_category_path();
            if let Some((id, _, _)) = self.data_types.iter().find(|(_, p, d)| *p == path && d.get_name() == name) {
                return *id;
            }
            let id = self.next_id;
            self.next_id += 1;
            self.data_types.push((id, path, dt.clone_data_type(&NoopManager)));
            id
        }
        fn get_data_type_by_id(&self, data_type_id: i64) -> Option<Box<dyn DataType>> {
            self.data_types.iter().find(|(id, _, _)| *id == data_type_id).map(|(_, _, dt)| dt.clone_data_type(&NoopManager))
        }
        fn allows_default_component_settings(&self) -> bool {
            self.allows_settings
        }
        fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
            Arc::new(test_data_organization())
        }
    }
    impl DataTypeManagerDb for TestManager {
        fn db_error(&mut self, error: io::Error) {
            self.errors.push(error.to_string());
        }
        fn add_data_type_to_replace(&mut self, _data_type_id: i64, _replacement: Box<dyn DataType>) {}
        fn add_data_type_to_delete(&mut self, data_type_id: i64) {
            self.deleted.push(data_type_id);
        }
        fn data_type_changed(&mut self, _dt: &dyn DataType, is_auto_change: bool) {
            self.changed_log.push(is_auto_change);
        }
    }

    struct NoopManager;
    impl DataTypeManager for NoopManager {}

    struct TestCategory;
    impl Category for TestCategory {
        fn get_name(&self) -> String {
            String::new()
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
        fn add_data_type(&mut self, dt: Box<dyn DataType>, _handler: &dyn DataTypeConflictHandler) -> Box<dyn DataType> {
            dt
        }
        fn get_category(&self, _name: &str) -> Option<Box<dyn Category>> {
            None
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_data_type(&self, _name: &str) -> Option<Box<dyn DataType>> {
            None
        }
        fn create_category(&mut self, _name: &str) -> Result<Box<dyn Category>, crate::util::exception::InvalidNameException> {
            Ok(Box::new(TestCategory))
        }
        fn remove_category(&mut self, _name: &str, _monitor: &dyn crate::util::task::TaskMonitor) -> bool {
            false
        }
        fn remove_empty_category(&mut self, _name: &str, _monitor: &dyn crate::util::task::TaskMonitor) -> bool {
            false
        }
        fn move_category(&mut self, _category: Box<dyn Category>, _monitor: &dyn crate::util::task::TaskMonitor) -> Result<(), DuplicateNameException> {
            Ok(())
        }
        fn copy_category(
            &mut self,
            _category: &dyn Category,
            _handler: &dyn DataTypeConflictHandler,
            _monitor: &dyn crate::util::task::TaskMonitor,
        ) -> Box<dyn Category> {
            Box::new(TestCategory)
        }
        fn get_parent(&self) -> Option<Box<dyn Category>> {
            None
        }
        fn is_root(&self) -> bool {
            true
        }
        fn get_category_path_name(&self) -> String {
            "/".to_string()
        }
        fn get_root(&self) -> Box<dyn Category> {
            Box::new(TestCategory)
        }
        fn get_data_type_manager(&self) -> Box<dyn DataTypeManager> {
            Box::new(NoopManager)
        }
        fn move_data_type(
            &mut self,
            _dt_type: Box<dyn DataType>,
            _handler: &dyn DataTypeConflictHandler,
        ) -> Result<(), crate::program::model::data::data_type_dependency_exception::DataTypeDependencyException> {
            Ok(())
        }
        fn remove(&mut self, _dt_type: &dyn DataType, _monitor: &dyn crate::util::task::TaskMonitor) -> bool {
            false
        }
        fn get_id(&self) -> i64 {
            0
        }
        fn compare_to(&self, _other: &dyn Category) -> std::cmp::Ordering {
            std::cmp::Ordering::Equal
        }
    }

    /// A real [`DataOrganizationImpl`] configured as this test expects.
    fn test_data_organization() -> DataOrganizationImpl {
        let mut org = DataOrganizationImpl::get_default_organization(None);
        org.set_big_endian(false);
        org.set_pointer_size(8);
        org.set_pointer_shift(0);
        org.set_char_is_signed(true);
        org.set_char_size(1);
        org.set_wide_char_size(2);
        org.set_short_size(2);
        org.set_integer_size(4);
        org.set_long_size(8);
        org.set_long_long_size(8);
        org.set_float_size(4);
        org.set_double_size(8);
        org.set_long_double_size(8);
        org.set_absolute_max_alignment(0);
        org.set_machine_alignment(8);
        org.set_default_alignment(1);
        org.set_default_pointer_alignment(8);
        org.clear_size_alignment_map();
        org
    }

    // ===================================================================================
    // Test scaffolding.
    // ===================================================================================

    fn make_union(name: &str) -> UnionDb {
        let owner: Arc<Mutex<dyn DataTypeManagerDb + Send>> = Arc::new(Mutex::new(TestManager::new()));
        let composite_adapter: Arc<Mutex<dyn CompositeDBAdapter + Send>> = Arc::new(Mutex::new(TestCompositeAdapter::new()));
        let component_adapter: Arc<Mutex<dyn ComponentDBAdapter + Send>> = Arc::new(Mutex::new(TestComponentAdapter::new()));
        let record = composite_adapter
            .lock()
            .unwrap()
            .create_record(name, None, true, 0, 0, -1, -1, -1, 0, NO_PACKING, DEFAULT_ALIGNMENT)
            .unwrap();
        let lock = Arc::new(ReentrantLock::new("test"));
        UnionDb::new(owner, composite_adapter, component_adapter, lock, record)
    }

    #[test]
    fn new_union_is_empty_and_not_yet_defined() {
        let u = make_union("MyUnion");
        assert_eq!(Composite::get_num_components(&u), 0);
        assert!(DataType::is_not_yet_defined(&u));
        assert_eq!(DataType::get_length(&u), 1); // zero-length unions report 1
    }

    #[test]
    fn add_components_and_length_tracks_max() {
        let mut u = make_union("U");
        u.add_with_length_and_name(leaf("byte", 1), -1, None, None).unwrap();
        assert_eq!(DataType::get_length(&u), 1);
        u.add_with_length_and_name(leaf("int", 4), -1, None, None).unwrap();
        assert_eq!(DataType::get_length(&u), 4);
        u.add_with_length_and_name(leaf("short", 2), -1, None, None).unwrap();
        // Union length is the max of its components, not their sum.
        assert_eq!(DataType::get_length(&u), 4);
        assert_eq!(Composite::get_num_components(&u), 3);
    }

    #[test]
    fn all_components_are_at_offset_zero() {
        let mut u = make_union("U");
        u.add_with_length_and_name(leaf("byte", 1), -1, None, None).unwrap();
        u.add_with_length_and_name(leaf("int", 4), -1, None, None).unwrap();
        for c in Composite::get_components(&u) {
            assert_eq!(c.get_offset(), 0);
        }
    }

    #[test]
    fn ordinals_assigned_in_add_order_and_shift_on_insert_delete() {
        let mut u = make_union("U");
        u.add_with_length_and_name(leaf("byte", 1), -1, None, None).unwrap();
        u.add_with_length_and_name(leaf("int", 4), -1, None, None).unwrap();
        assert_eq!(Composite::get_component(&u, 0).unwrap().get_ordinal(), 0);
        assert_eq!(Composite::get_component(&u, 1).unwrap().get_ordinal(), 1);

        u.insert_with_length_and_name(1, leaf("short", 2), -1, None, None).unwrap();
        assert_eq!(Composite::get_num_components(&u), 3);
        assert_eq!(Composite::get_component(&u, 0).unwrap().get_data_type_name(), "byte");
        assert_eq!(Composite::get_component(&u, 1).unwrap().get_data_type_name(), "short");
        assert_eq!(Composite::get_component(&u, 2).unwrap().get_data_type_name(), "int");
        assert_eq!(Composite::get_component(&u, 2).unwrap().get_ordinal(), 2);

        Composite::delete(&mut u, 0).unwrap();
        assert_eq!(Composite::get_num_components(&u), 2);
        assert_eq!(Composite::get_component(&u, 0).unwrap().get_data_type_name(), "short");
        assert_eq!(Composite::get_component(&u, 0).unwrap().get_ordinal(), 0);
        assert_eq!(Composite::get_component(&u, 1).unwrap().get_ordinal(), 1);
    }

    #[test]
    fn delete_set_removes_multiple_and_renumbers() {
        let mut u = make_union("U");
        u.add_with_length_and_name(leaf("a", 1), -1, None, None).unwrap();
        u.add_with_length_and_name(leaf("b", 2), -1, None, None).unwrap();
        u.add_with_length_and_name(leaf("c", 8), -1, None, None).unwrap();
        u.add_with_length_and_name(leaf("d", 4), -1, None, None).unwrap();

        let mut ordinals = HashSet::new();
        ordinals.insert(0);
        ordinals.insert(2);
        Composite::delete_set(&mut u, &ordinals).unwrap();

        assert_eq!(Composite::get_num_components(&u), 2);
        assert_eq!(Composite::get_component(&u, 0).unwrap().get_data_type_name(), "b");
        assert_eq!(Composite::get_component(&u, 0).unwrap().get_ordinal(), 0);
        assert_eq!(Composite::get_component(&u, 1).unwrap().get_data_type_name(), "d");
        assert_eq!(Composite::get_component(&u, 1).unwrap().get_ordinal(), 1);
        // Max of remaining components (b=2, d=4) => 4.
        assert_eq!(DataType::get_length(&u), 4);
    }

    #[test]
    fn add_bit_field_and_bitfield_length_allocation() {
        let mut u = make_union("U");
        let comp = u.add_bit_field(leaf("int", 4), 5, Some("flag".to_string()), None).unwrap();
        assert!(comp.is_bit_field_component());
        assert_eq!(Composite::get_num_components(&u), 1);
        // Non-packed union: raw component length (storage size for a 5-bit field) drives length.
        assert!(DataType::get_length(&u) >= 1);
    }

    #[test]
    fn field_name_and_comment_round_trip_through_component() {
        let mut u = make_union("U");
        let comp = u.add_with_length_and_name(leaf("int", 4), -1, Some("orig".to_string()), Some("c1".to_string())).unwrap();
        assert_eq!(comp.get_field_name(), Some("orig".to_string()));
        assert_eq!(comp.get_comment(), Some("c1".to_string()));

        u.set_component_field_name(0, Some("renamed")).unwrap();
        u.set_component_comment(0, Some("c2")).unwrap();
        let fresh = Composite::get_component(&u, 0).unwrap();
        assert_eq!(fresh.get_field_name(), Some("renamed".to_string()));
        assert_eq!(fresh.get_comment(), Some("c2".to_string()));
    }

    #[test]
    fn set_name_renames_union() {
        let mut u = make_union("Original");
        assert_eq!(DataType::get_name(&u), "Original");
        DataType::set_name(&mut u, "Renamed").unwrap();
        assert_eq!(DataType::get_name(&u), "Renamed");
    }

    #[test]
    fn is_equivalent_true_for_matching_unions_false_otherwise() {
        let mut a = make_union("A");
        a.add_with_length_and_name(leaf("int", 4), -1, Some("x".to_string()), None).unwrap();
        let mut b = make_union("B");
        b.add_with_length_and_name(leaf("int", 4), -1, Some("x".to_string()), None).unwrap();
        assert!(DataType::is_equivalent(&a, &b));

        let mut c = make_union("C");
        c.add_with_length_and_name(leaf("int", 4), -1, Some("y".to_string()), None).unwrap();
        assert!(!DataType::is_equivalent(&a, &c));
    }

    #[test]
    fn is_part_of_detects_self_and_nested_composite() {
        let u = make_union("Self");
        assert!(Composite::is_part_of(&u, &u));

        let leaf_dt = leaf("plain", 4);
        assert!(!Composite::is_part_of(&u, leaf_dt.as_ref()));
    }

    #[test]
    fn adding_self_as_component_is_rejected_by_ancestry_check() {
        let mut u = make_union("Cyclic");
        // `checkAncestry` identifies "would create a cycle" purely by matching
        // `get_data_type_path()` (see `DataTypeUtilities::is_second_part_of_first`), so a
        // standalone data type sharing this union's own path is enough to exercise the rejection
        // without needing a live self-reference.
        #[derive(Clone)]
        struct SamePathType(DataTypePath);
        impl DataType for SamePathType {
            fn get_data_type_path(&self) -> DataTypePath {
                self.0.clone()
            }
            fn get_length(&self) -> i32 {
                1
            }
            fn clone_data_type(&self, _dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
                Box::new(self.clone())
            }
        }
        let path = DataType::get_data_type_path(&u);
        let result = u.add_with_length_and_name(Box::new(SamePathType(path)), -1, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn packing_enabled_changes_length_and_alignment() {
        let mut u = make_union("Packed");
        u.add_with_length_and_name(leaf("byte", 1), -1, None, None).unwrap();
        u.add_with_length_and_name(leaf("int", 4), -1, None, None).unwrap();
        assert_eq!(Composite::get_packing_type(&u), PackingType::Disabled);

        Composite::set_packing_enabled(&mut u, true);
        assert_eq!(Composite::get_packing_type(&u), PackingType::Default);
        // Length must be aligned up to the alignment of the largest-aligned member (int, align 4).
        assert_eq!(DataType::get_length(&u) % 4, 0);
    }

    #[test]
    fn category_path_round_trips_through_owning_manager() {
        let u = make_union("U");
        assert_eq!(DataType::get_category_path(&u), ROOT.clone());
    }

    #[test]
    fn copy_data_type_produces_independent_equivalent_union() {
        let mut u = make_union("Orig");
        u.add_with_length_and_name(leaf("int", 4), -1, Some("x".to_string()), None).unwrap();
        let copy = DataType::copy_data_type(&u, &NoopManager);
        assert_eq!(copy.get_name(), "Orig");
        let copy_union = copy.as_union().expect("copy should still be a union");
        assert_eq!(copy_union.get_components().len(), 1);
        assert_eq!(copy_union.get_components()[0].get_field_name(), Some("x".to_string()));
    }

    #[test]
    fn clone_union_preserves_components() {
        let mut u = make_union("Orig");
        u.add_with_length_and_name(leaf("int", 4), -1, None, None).unwrap();
        let cloned = Union::clone_union(&u, &NoopManager);
        assert_eq!(cloned.get_components().len(), 1);
    }

    #[test]
    fn delete_out_of_bounds_reports_error() {
        let mut u = make_union("U");
        assert!(Composite::delete(&mut u, 0).is_err());
    }

    #[test]
    fn insert_out_of_bounds_reports_error() {
        let mut u = make_union("U");
        assert!(u.insert_with_length_and_name(5, leaf("int", 4), -1, None, None).is_err());
    }
}
