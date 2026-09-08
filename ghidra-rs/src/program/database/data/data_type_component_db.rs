//! Port of `ghidra.program.database.data.DataTypeComponentDB`, the database-persisted
//! implementation of [`DataTypeComponent`] used by [`UnionDb`](super::union_db::UnionDb) (and, in
//! Java, `StructureDB`).
//!
//! Java's class holds a direct `parent: CompositeDB` field so that mutating operations
//! (`setFieldName`/`setComment`) can be delegated *outward* to the owning composite (which
//! validates the component is still current and bumps the composite's own `lastChangeTime`/fires
//! `dataMgr.dataTypeChanged(...)`), and so `getParent()`/bit-field/alignment helpers can consult
//! the owning composite's current packing state.
//!
//! # No live back-reference to the owning composite
//!
//! This port does **not** give [`DataTypeComponentDB`] a back-reference to its owning
//! [`UnionDb`](super::union_db::UnionDb): `UnionDb` owns its components in a
//! `Vec<DataTypeComponentDB>`, and there is no sound, `unsafe`-free way for an element of that
//! `Vec` to also hold a live handle back to the `Vec`'s owner (the same "owned, not borrowed"
//! constraint documented throughout this crate -- see `module_db.rs`'s `get_address_set` note).
//! Concretely, this means:
//!   - [`DataTypeComponent::set_comment`]/[`DataTypeComponent::set_field_name`] (the trait-level
//!     entry points, e.g. reachable from `composite.get_component(i).set_field_name(...)`) *do*
//!     really persist the edit to the backing database record (via [`do_set_comment`]/
//!     [`do_set_field_name`], which are exactly [`DataTypeComponentDB.doSetComment`]/
//!     `doSetFieldName` ported faithfully), but they do **not** bump the owning composite's
//!     `lastChangeTime` or fire a `dataTypeChanged` notification the way Java's
//!     `parent.setComment(this, comment)`/`parent.setFieldName(this, name)` delegation does. This
//!     is a real, if narrow, observability gap.
//!   - [`UnionDb::set_component_comment`](super::union_db::UnionDb::set_component_comment)/
//!     [`UnionDb::set_component_field_name`](super::union_db::UnionDb::set_component_field_name)
//!     are the faithful, fully-notifying equivalents of `CompositeDB.setComment`/`setFieldName`,
//!     operating with full `&mut self` access to the owning union (its `lastChangeTime` and
//!     `dataMgr.dataTypeChanged` notification). Callers that need Java's exact behavior should go
//!     through those instead of the generic trait methods.
//!   - [`get_parent`](DataTypeComponent::get_parent) cannot return the real owning union (there is
//!     nothing to return it *from*), so it returns [`ComponentParentStandIn`], a minimal
//!     [`DataType`] + [`Composite`] implementation reporting `is_union() == true` and
//!     `is_packing_enabled() == false`. This is exact for every currently-real caller: a
//!     [`DataTypeComponentDB`] is only ever constructed by `UnionDb`, whose components are always
//!     placed at offset 0 regardless of packing (so the one caller that reads
//!     `getParent().isPackingEnabled()` -- [`is_equivalent`](DataTypeComponentDB::is_equivalent),
//!     guarding an offset comparison -- always compares `0 == 0` either way), and
//!     `get_default_field_name`/`is_default_field_name`'s `parent.is_structure()` check (which
//!     controls whether a hex offset suffix is appended) is correctly always `false` for a
//!     union-owned component.
//!
//! # Settings overrides are not persisted
//!
//! Java's `getDefaultSettings()` lazily builds a `ComponentDBSettings` inner class that reads/
//! writes *per-component* setting overrides via `dataMgr.getSetting`/`updateSettingsRecord`/
//! `clearSetting`/`clearAllSettings`/`getSettingsNames`. None of those exist on
//! [`DataTypeManagerDb`] yet (the same class of gap as `TypedefDb`'s missing `DataTypeSettingsDB`
//! -- see `typedef_db.rs`'s module docs). [`get_default_settings`](DataTypeComponentDB::get_default_settings)
//! therefore falls back to the component's own data type's default settings (a real, correct
//! answer for every *read*, matching Java's own fallback chain when no override is stored) but
//! has no way to persist a local override; `// TODO(port):` marks the exact spot.
//!
//! # `isBitFieldComponent` uses a type-based check, not the DB table-id encoding
//!
//! Java's `isBitFieldComponent()` checks `DataTypeManagerDB.getTableID(id) == BITFIELD` against
//! the raw referenced-datatype id stored in the component record -- a DB-internal encoding scheme
//! that is not part of the not-yet-fully-ported [`DataTypeManagerDb`]/[`DataTypeManager`] surface.
//! Since every component here always resolves its full concrete data type object via
//! [`DataTypeManager::get_data_type_by_id`], this port instead checks
//! `self.get_data_type().as_bit_field_data_type().is_some()` -- a faithful, not merely
//! approximate, substitute given this crate's architecture (the real
//! [`BitFieldDataType`](crate::program::model::data::bit_field_data_type::BitFieldDataType) is
//! fully ported).
//!
//! # `isEquivalent(DataTypeComponent, DataTypeConflictHandler)` dispatch is not polymorphic
//!
//! Java's `static DataTypeComponentDB.isEquivalent(DataTypeComponent, DataTypeComponent,
//! DataTypeConflictHandler)` helper `instanceof`-checks the *existing* side to reach this class's
//! own handler-aware `isEquivalent` when possible. [`UnionDb`](super::union_db::UnionDb) always
//! knows statically that its own components are [`DataTypeComponentDB`], so it calls
//! [`is_equivalent_with_handler`](DataTypeComponentDB::is_equivalent_with_handler) directly rather
//! than through a polymorphic `&dyn DataTypeComponent` dispatch -- achieving the identical effect
//! without needing a downcast this crate has no generic mechanism for.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

use crate::docking::settings::settings::Settings;
use crate::framework::db::DBRecord;
use crate::program::database::data::component_db_adapter::{
    ComponentDBAdapter, COMPONENT_COMMENT_COL, COMPONENT_DT_ID_COL, COMPONENT_FIELD_NAME_COL,
    COMPONENT_OFFSET_COL, COMPONENT_ORDINAL_COL, COMPONENT_SIZE_COL,
};
use crate::program::database::data::data_type_manager_db::DataTypeManagerDb;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::database::data::data_type_utilities::DataTypeUtilities as ModelDataTypeUtilities;
use crate::program::model::data::data_type_conflict_handler::DataTypeConflictHandler;
use crate::program::model::data::internal_data_type_component::{cleanup_field_name, InternalDataTypeComponent};
use crate::program::seam_stubs::share_data_type;

/// A dummy zero-sized receiver used purely to invoke the model-layer [`ModelDataTypeUtilities`]'s
/// default methods, per the convention already established throughout `program/model/data` (see
/// e.g. `typedef_data_type.rs`, `data_type_component_impl.rs`).
#[derive(Debug, Default, Clone, Copy)]
struct Utils;
impl ModelDataTypeUtilities for Utils {}

/// Stand-in for `DataType.DEFAULT`, returned by [`DataTypeComponentDB::data_type`] when the
/// component's referenced-type id is `-1` (an "undefined" component) or, for a non-record
/// component, when no explicit data type was supplied at construction. Mirrors the identical
/// `MissingDataType` stand-in in `typedef_db.rs`.
#[derive(Debug, Clone, Copy)]
struct DefaultDataTypeStandIn;
impl DataType for DefaultDataTypeStandIn {
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

/// Stand-in for `BadDataType.dataType`, returned by [`DataTypeComponentDB::data_type`] when the
/// component's referenced-type id no longer resolves to anything in the owning manager. Mirrors
/// the identical `BadDataTypeStandIn` in `union_data_type.rs`.
#[derive(Debug, Clone, Copy)]
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

/// Stand-in for [`DataTypeComponent::get_parent`]'s narrow real surface, in place of a live
/// back-reference to the owning [`UnionDb`](super::union_db::UnionDb). See the module docs for
/// exactly why this is sound for every current caller.
#[derive(Debug, Clone, Copy)]
struct ComponentParentStandIn;
impl DataType for ComponentParentStandIn {
    fn is_union(&self) -> bool {
        true
    }
    fn as_composite(&self) -> Option<&dyn Composite> {
        Some(self)
    }
}
impl Composite for ComponentParentStandIn {
    fn is_packing_enabled(&self) -> bool {
        false
    }
}

/// Stand-in for `SettingsImpl.NO_SETTINGS`: an immutable, empty [`Settings`] object. Mirrors the
/// `NoSettings`/`EmptySettings` convention used throughout `program/model/data`.
#[derive(Debug, Clone, Copy)]
struct NoSettings;
impl Settings for NoSettings {
    fn is_immutable_settings(&self) -> bool {
        true
    }
}

/// Database implementation of a [`DataTypeComponent`]. If this component is for an undefined
/// data type, then no backing record exists.
///
/// Port of `ghidra.program.database.data.DataTypeComponentDB`. See the module documentation for
/// what was ported, deliberately simplified, or omitted.
///
/// Cheaply [`Clone`]: every field is an `Arc` (or a plain `Copy` value), so a clone shares the
/// exact same underlying record/atomics as the original -- this is what lets
/// [`Composite::get_component`]-style snapshots returned to callers stay observably identical to
/// the canonical instance held in [`UnionDb`](super::union_db::UnionDb)'s own component list,
/// matching Java's single-shared-object-reference semantics without needing a true back-reference.
#[derive(Clone)]
pub struct DataTypeComponentDB {
    data_mgr: Arc<Mutex<dyn DataTypeManagerDb + Send>>,
    adapter: Option<Arc<Mutex<dyn ComponentDBAdapter + Send>>>,
    /// `None` for an immutable component not backed by a database record.
    record: Option<Arc<Mutex<DBRecord>>>,
    /// Used only by the record-less "explicit datatype+length" constructor.
    cached_data_type: Option<Arc<dyn DataType>>,
    ordinal: Arc<AtomicI32>,
    offset: Arc<AtomicI32>,
    length: Arc<AtomicI32>,
}

impl DataTypeComponentDB {
    /// Constructs an immutable component not backed by a record, with a specified datatype and
    /// length. No comment or field name is provided.
    ///
    /// Port of `DataTypeComponentDB(DataTypeManagerDB, CompositeDB, int, int, DataType, int)`.
    pub fn new_immutable(
        data_mgr: Arc<Mutex<dyn DataTypeManagerDb + Send>>,
        ordinal: i32,
        offset: i32,
        data_type: Box<dyn DataType>,
        length: i32,
    ) -> Self {
        DataTypeComponentDB {
            data_mgr,
            adapter: None,
            record: None,
            cached_data_type: Some(Arc::from(data_type)),
            ordinal: Arc::new(AtomicI32::new(ordinal)),
            offset: Arc::new(AtomicI32::new(offset)),
            length: Arc::new(AtomicI32::new(length)),
        }
    }

    /// Constructs an immutable undefined 1-byte component not backed by a record. No comment or
    /// field name is provided.
    ///
    /// Port of `DataTypeComponentDB(DataTypeManagerDB, CompositeDB, int, int)`.
    pub fn new_undefined(data_mgr: Arc<Mutex<dyn DataTypeManagerDb + Send>>, ordinal: i32, offset: i32) -> Self {
        DataTypeComponentDB {
            data_mgr,
            adapter: None,
            record: None,
            cached_data_type: None,
            ordinal: Arc::new(AtomicI32::new(ordinal)),
            offset: Arc::new(AtomicI32::new(offset)),
            length: Arc::new(AtomicI32::new(1)),
        }
    }

    /// Constructs a component backed by a record.
    ///
    /// Port of `DataTypeComponentDB(DataTypeManagerDB, ComponentDBAdapter, CompositeDB,
    /// DBRecord)`.
    pub fn new_persisted(
        data_mgr: Arc<Mutex<dyn DataTypeManagerDb + Send>>,
        adapter: Arc<Mutex<dyn ComponentDBAdapter + Send>>,
        record: DBRecord,
    ) -> Self {
        let ordinal = record.get_int(COMPONENT_ORDINAL_COL).unwrap_or(0);
        let offset = record.get_int(COMPONENT_OFFSET_COL).unwrap_or(0);
        let length = record.get_int(COMPONENT_SIZE_COL).unwrap_or(0);
        let component = DataTypeComponentDB {
            data_mgr,
            adapter: Some(adapter),
            record: Some(Arc::new(Mutex::new(record))),
            cached_data_type: None,
            ordinal: Arc::new(AtomicI32::new(ordinal)),
            offset: Arc::new(AtomicI32::new(offset)),
            length: Arc::new(AtomicI32::new(length)),
        };
        if component.is_zero_bit_field_component() {
            // previously stored as 1, force to 0 (matches the in-memory `length` field only --
            // the persisted record column is left untouched, exactly as in Java).
            component.length.store(0, Ordering::SeqCst);
        }
        component
    }

    /// Get record key, or `-1` for an undefined component without a record.
    ///
    /// Port of the public `DataTypeComponentDB.getKey()`.
    pub fn get_key(&self) -> i64 {
        match &self.record {
            Some(record) => record.lock().unwrap().get_key().get_long_value(),
            None => -1,
        }
    }

    /// Returns `true` if this component is backed by a database record.
    pub fn has_record(&self) -> bool {
        self.record.is_some()
    }

    fn data_type(&self) -> Box<dyn DataType> {
        if let Some(dt) = &self.cached_data_type {
            return share_data_type(dt);
        }
        let Some(record) = &self.record else {
            return Box::new(DefaultDataTypeStandIn);
        };
        let id = record.lock().unwrap().get_long(COMPONENT_DT_ID_COL).unwrap_or(-1);
        if id == -1 {
            return Box::new(DefaultDataTypeStandIn);
        }
        match self.data_mgr.lock().unwrap().get_data_type_by_id(id) {
            Some(dt) => dt,
            None => Box::new(BadDataTypeStandIn),
        }
    }

    /// Port of the package-private `DataTypeComponentDB.containsOffset(int)`.
    pub fn contains_offset(&self, off: i32) -> bool {
        let offset = self.offset.load(Ordering::SeqCst);
        if off == offset {
            // separate check required to handle zero-length case
            return true;
        }
        let length = self.length.load(Ordering::SeqCst);
        off > offset && off < (offset + length)
    }

    fn has_settings(&self) -> bool {
        self.record.is_some()
            && self.data_mgr.lock().unwrap().allows_default_component_settings()
            && !self.data_type().get_settings_definitions().is_empty()
    }

    /// Port of the package-private `DataTypeComponentDB.doSetComment(String)`. Returns `true` if
    /// the comment actually changed.
    pub fn do_set_comment(&self, comment: Option<&str>) -> bool {
        let Some(record) = &self.record else {
            return false;
        };
        let cleaned = comment.filter(|c| !c.trim().is_empty()).map(str::to_string);
        let mut rec = record.lock().unwrap();
        let current = rec.get_string(COMPONENT_COMMENT_COL).map(str::to_string);
        if cleaned != current {
            rec.set_string(COMPONENT_COMMENT_COL, cleaned);
            drop(rec);
            self.update_record(true);
            true
        } else {
            false
        }
    }

    /// Port of the package-private `DataTypeComponentDB.doSetFieldName(String)`. Returns `true`
    /// if the field name actually changed.
    pub fn do_set_field_name(&self, name: Option<&str>) -> bool {
        let Some(record) = &self.record else {
            return false;
        };
        let mut rec = record.lock().unwrap();
        let old_name = rec.get_string(COMPONENT_FIELD_NAME_COL).map(str::to_string);
        let field_name = cleanup_field_name(name);
        if old_name != field_name {
            rec.set_string(COMPONENT_FIELD_NAME_COL, field_name);
            drop(rec);
            self.update_record(true);
            true
        } else {
            false
        }
    }

    /// Update component record and (were it wired -- see the module docs) optionally update the
    /// composite's last-modified time. `set_last_change_time` is accepted for fidelity with
    /// Java's parameter but, absent a back-reference to the owning composite, never has an
    /// observable effect here.
    ///
    /// Port of the package-private `DataTypeComponentDB.updateRecord(boolean)`.
    pub fn update_record(&self, set_last_change_time: bool) {
        let _ = set_last_change_time;
        if let (Some(adapter), Some(record)) = (&self.adapter, &self.record) {
            let rec = record.lock().unwrap().clone();
            if let Err(e) = adapter.lock().unwrap().update_record(&rec) {
                self.data_mgr.lock().unwrap().db_error(e);
            }
        }
    }

    /// Sets the byte offset of where this component begins in its parent, optionally persisting
    /// the change.
    ///
    /// Port of the package-private `DataTypeComponentDB.setOffset(int, boolean)`.
    pub fn set_offset(&self, new_offset: i32, update_record: bool) {
        self.offset.store(new_offset, Ordering::SeqCst);
        if let Some(record) = &self.record {
            record.lock().unwrap().set_int(COMPONENT_OFFSET_COL, new_offset);
        }
        if update_record {
            self.update_record(false);
        }
    }

    /// Sets the ordinal position of this component within its parent, optionally persisting the
    /// change.
    ///
    /// Port of the package-private `DataTypeComponentDB.setOrdinal(int, boolean)`.
    pub fn set_ordinal(&self, new_ordinal: i32, update_record: bool) {
        self.ordinal.store(new_ordinal, Ordering::SeqCst);
        if let Some(record) = &self.record {
            record.lock().unwrap().set_int(COMPONENT_ORDINAL_COL, new_ordinal);
        }
        if update_record {
            self.update_record(false);
        }
    }

    /// Sets the length of this component, optionally persisting the change.
    ///
    /// Port of the package-private `DataTypeComponentDB.setLength(int, boolean)`.
    ///
    /// # Errors
    /// Returns `Err` if `length` is negative (mirrors `IllegalArgumentException`).
    pub fn set_length(&self, new_length: i32, update_record: bool) -> Result<(), String> {
        if new_length < 0 {
            return Err(format!("IllegalArgumentException: Cannot set data type component length to {new_length}."));
        }
        self.length.store(new_length, Ordering::SeqCst);
        if let Some(record) = &self.record {
            record.lock().unwrap().set_int(COMPONENT_SIZE_COL, new_length);
        }
        if update_record {
            self.update_record(false);
        }
        Ok(())
    }

    /// Port of the public `DataTypeComponentDB.update(int, int, int)`.
    ///
    /// NOTE: matches Java verbatim on a subtle point -- the length-negative guard checks the
    /// *current* (pre-update) length, not `new_length`. Since this component's length is never
    /// negative once constructed, that guard can never actually trigger; this looks like a latent
    /// no-op in the original, ported as-is per this crate's faithful-porting policy rather than
    /// "fixed" to check `new_length` instead.
    pub fn do_update(&self, new_ordinal: i32, new_offset: i32, new_length: i32) {
        if self.length.load(Ordering::SeqCst) < 0 {
            return; // would have thrown IllegalArgumentException in Java
        }
        self.ordinal.store(new_ordinal, Ordering::SeqCst);
        self.offset.store(new_offset, Ordering::SeqCst);
        self.length.store(new_length, Ordering::SeqCst);
        if let Some(record) = &self.record {
            let mut rec = record.lock().unwrap();
            rec.set_int(COMPONENT_ORDINAL_COL, new_ordinal);
            rec.set_int(COMPONENT_OFFSET_COL, new_offset);
            rec.set_int(COMPONENT_SIZE_COL, new_length);
            drop(rec);
            self.update_record(false);
        }
    }

    /// Performs a special-case component update that does not result in size or alignment
    /// changes and does not modify the composite's last-change time.
    ///
    /// Port of the package-private `DataTypeComponentDB.update(String, DataType, String)`. Named
    /// distinctly from [`do_update`](Self::do_update) (Java overloads both as `update`; Rust
    /// cannot).
    pub fn update_special(&self, field_name: Option<&str>, new_dt: Box<dyn DataType>, comment: Option<&str>) {
        let Some(record) = &self.record else {
            return;
        };
        let cleaned_name = cleanup_field_name(field_name);
        let cleaned_comment = comment.filter(|c| !c.trim().is_empty()).map(str::to_string);
        let id = self.data_mgr.lock().unwrap().get_resolved_id(new_dt.as_ref());
        let mut rec = record.lock().unwrap();
        rec.set_string(COMPONENT_FIELD_NAME_COL, cleaned_name);
        rec.set_long(COMPONENT_DT_ID_COL, id);
        rec.set_string(COMPONENT_COMMENT_COL, cleaned_comment);
        drop(rec);
        self.update_record(false);
    }

    fn do_set_data_type(&self, new_dt: Box<dyn DataType>) {
        let Some(record) = &self.record else {
            return;
        };
        let id = self.data_mgr.lock().unwrap().get_resolved_id(new_dt.as_ref());
        record.lock().unwrap().set_long(COMPONENT_DT_ID_COL, id);
        self.update_record(false);
    }

    /// Port of `DataTypeComponentDB.isEquivalent(DataTypeComponent, DataTypeConflictHandler)`.
    /// See the module docs for why this is exposed as a directly-callable method rather than
    /// through the polymorphic `static isEquivalent(DataTypeComponent, DataTypeComponent,
    /// DataTypeConflictHandler)` dispatch Java uses.
    pub fn is_equivalent_with_handler(
        &self,
        dtc: &dyn DataTypeComponent,
        handler: Option<&dyn DataTypeConflictHandler>,
    ) -> bool {
        let my_dt = self.data_type();
        let other_dt = dtc.get_data_type();

        let my_parent = self.get_parent();
        let is_packed = my_parent.as_composite().map(Composite::is_packing_enabled).unwrap_or(false);

        if (!is_packed && self.get_offset() != dtc.get_offset())
            || self.get_field_name() != dtc.get_field_name()
            || self.get_comment() != dtc.get_comment()
        {
            return false;
        }

        // Component lengths need only be checked for dynamic types.
        if self.get_length() != dtc.get_length() && my_dt.as_dynamic().is_some() {
            return false;
        }

        if Utils.is_same_data_type(my_dt.as_ref(), other_dt.as_ref()) {
            return true;
        }

        // Approximates the static `DataTypeDB.isEquivalent(DataType, DataType, handler)` dispatch
        // (which special-cases a `DataTypeDB` target's own handler-aware `isEquivalent`): a plain
        // `&dyn DataType` can't be downcast to check for that here, so this falls back to an
        // ordinary equivalence check. Mirrors `typedef_db.rs`'s identical precedent.
        let _ = handler;
        my_dt.is_equivalent(other_dt.as_ref())
    }

    /// Port of `DataTypeComponentDB.equals(Object)`.
    pub fn components_equal(&self, other: &dyn DataTypeComponent) -> bool {
        let my_dt = self.data_type();
        let other_dt = other.get_data_type();

        if self.get_offset() != other.get_offset()
            || self.get_length() != other.get_length()
            || self.get_ordinal() != other.get_ordinal()
            || self.get_field_name() != other.get_field_name()
            || self.get_comment() != other.get_comment()
        {
            return false;
        }
        if my_dt.as_pointer().is_none() && my_dt.get_path_name() != other_dt.get_path_name() {
            return false;
        }
        if my_dt.is_structure() {
            return other_dt.is_structure();
        } else if my_dt.is_union() {
            return other_dt.is_union();
        } else if my_dt.is_array() {
            return other_dt.is_array();
        } else if my_dt.as_pointer().is_some() {
            return other_dt.as_pointer().is_some();
        } else if my_dt.is_typedef() {
            return other_dt.is_typedef();
        }
        // No reflection equivalent for `myDt.getClass() == otherDt.getClass()`; approximated by
        // name equality, the same proxy used throughout this crate (see e.g.
        // `data_type_component_impl.rs`'s identical `components_equal`).
        my_dt.get_name() == other_dt.get_name()
    }
}

impl DataTypeComponent for DataTypeComponentDB {
    fn get_data_type(&self) -> Box<dyn DataType> {
        self.data_type()
    }

    fn get_parent(&self) -> Box<dyn DataType> {
        Box::new(ComponentParentStandIn)
    }

    fn is_bit_field_component(&self) -> bool {
        self.data_type().as_bit_field_data_type().is_some()
    }

    fn is_zero_bit_field_component(&self) -> bool {
        let dt = self.data_type();
        match dt.as_bit_field_data_type() {
            Some(bf) => bf.get_bit_size() == 0,
            None => false,
        }
    }

    fn get_ordinal(&self) -> i32 {
        self.ordinal.load(Ordering::SeqCst)
    }

    fn get_offset(&self) -> i32 {
        self.offset.load(Ordering::SeqCst)
    }

    fn get_end_offset(&self) -> i32 {
        let length = self.length.load(Ordering::SeqCst);
        let offset = self.offset.load(Ordering::SeqCst);
        if length == 0 {
            // separate check required to handle zero-length case
            offset
        } else {
            offset + length - 1
        }
    }

    fn get_length(&self) -> i32 {
        self.length.load(Ordering::SeqCst)
    }

    fn get_data_type_name(&self) -> String {
        self.data_type().get_name()
    }

    fn bit_field_bit_offset(&self) -> i32 {
        self.data_type().as_bit_field_data_type().map(|bf| bf.get_bit_offset()).unwrap_or(0)
    }

    fn get_comment(&self) -> Option<String> {
        self.record.as_ref().and_then(|r| r.lock().unwrap().get_string(COMPONENT_COMMENT_COL).map(str::to_string))
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        if !self.has_settings() {
            return Box::new(NoSettings);
        }
        // TODO(port): Java's `ComponentDBSettings` reads/writes a *local* per-component setting
        // override via `dataMgr.getSetting`/`updateSettingsRecord`/`clearSetting`/
        // `clearAllSettings`/`getSettingsNames`, none of which exist on `DataTypeManagerDb` yet
        // (the same class of gap as `TypedefDb`'s missing `DataTypeSettingsDB` -- see
        // `typedef_db.rs`'s module docs). This returns the tail of Java's real fallback chain (the
        // component's own data type's default settings) rather than falling all the way back to
        // an empty placeholder.
        self.data_type().get_default_settings()
    }

    fn set_comment(&self, comment: Option<String>) -> Box<dyn DataTypeComponent> {
        if self.record.is_some() {
            self.do_set_comment(comment.as_deref());
        }
        Box::new(self.clone())
    }

    fn get_field_name(&self) -> Option<String> {
        if self.record.is_some() && !DataTypeComponent::is_zero_bit_field_component(self) {
            let name = self
                .record
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .get_string(COMPONENT_FIELD_NAME_COL)
                .map(str::to_string);
            // Blank check is required since blank names were improperly allowed in the past.
            name.filter(|n| !n.trim().is_empty())
        } else {
            None
        }
    }

    fn set_field_name(&self, field_name: Option<String>) -> Box<dyn DataTypeComponent> {
        if self.record.is_some() {
            self.do_set_field_name(field_name.as_deref());
        }
        Box::new(self.clone())
    }

    fn is_equivalent(&self, dtc: &dyn DataTypeComponent) -> bool {
        self.is_equivalent_with_handler(dtc, None)
    }

    fn is_undefined(&self) -> bool {
        self.record.is_none() && self.cached_data_type.is_none()
    }
}

impl InternalDataTypeComponent for DataTypeComponentDB {
    fn set_data_type(&mut self, data_type: Box<dyn DataType>) {
        self.do_set_data_type(data_type);
    }

    fn update(&mut self, ordinal: i32, offset: i32, length: i32) {
        self.do_update(ordinal, offset, length);
    }
}

impl std::fmt::Display for DataTypeComponentDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", crate::program::model::data::internal_data_type_component::to_string(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{Field, FieldType, Schema};
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use std::collections::HashMap;
    use std::io;
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

    #[derive(Clone)]
    struct MockLeaf {
        name: String,
        length: i32,
    }
    impl DataType for MockLeaf {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.name == dt.get_name() && self.length == dt.get_length()
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
            rec.set_field(COMPONENT_PARENT_ID_COL_TEST, Field::Long(Some(parent_id)));
            rec.set_field(COMPONENT_OFFSET_COL, Field::Int(Some(offset)));
            rec.set_field(COMPONENT_DT_ID_COL, Field::Long(Some(data_type_id)));
            rec.set_field(COMPONENT_FIELD_NAME_COL, Field::String(field_name.map(str::to_string)));
            rec.set_field(COMPONENT_COMMENT_COL, Field::String(comment.map(str::to_string)));
            rec.set_field(COMPONENT_SIZE_COL, Field::Int(Some(length)));
            rec.set_field(COMPONENT_ORDINAL_COL, Field::Int(Some(ordinal)));
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
                .filter(|r| matches!(r.get_field(COMPONENT_PARENT_ID_COL_TEST), Field::Long(Some(v)) if *v == composite_id))
                .map(|r| r.get_key().clone())
                .collect())
        }
    }
    const COMPONENT_PARENT_ID_COL_TEST: usize = crate::program::database::data::component_db_adapter::COMPONENT_PARENT_ID_COL;

    struct TestManager {
        data_types: StdMutex<Vec<(i64, MockLeaf)>>,
        next_id: StdMutex<i64>,
        allows_settings: bool,
        errors: StdMutex<Vec<String>>,
    }
    impl TestManager {
        fn new(allows_settings: bool) -> Self {
            TestManager {
                data_types: StdMutex::new(Vec::new()),
                next_id: StdMutex::new(1),
                allows_settings,
                errors: StdMutex::new(Vec::new()),
            }
        }
        fn register(&self, leaf: MockLeaf) -> i64 {
            let mut id = self.next_id.lock().unwrap();
            let this_id = *id;
            *id += 1;
            self.data_types.lock().unwrap().push((this_id, leaf));
            this_id
        }
    }
    impl DataTypeManager for TestManager {
        fn allows_default_component_settings(&self) -> bool {
            self.allows_settings
        }
        fn get_data_type_by_id(&self, data_type_id: i64) -> Option<Box<dyn DataType>> {
            self.data_types
                .lock()
                .unwrap()
                .iter()
                .find(|(id, _)| *id == data_type_id)
                .map(|(_, leaf)| Box::new(leaf.clone()) as Box<dyn DataType>)
        }
        fn get_resolved_id(&mut self, dt: &dyn DataType) -> i64 {
            let name = dt.get_name();
            let length = dt.get_length();
            if let Some((id, _)) = self.data_types.lock().unwrap().iter().find(|(_, l)| l.name == name && l.length == length) {
                return *id;
            }
            self.register(MockLeaf { name, length })
        }
    }
    impl DataTypeManagerDb for TestManager {
        fn db_error(&mut self, error: io::Error) {
            self.errors.lock().unwrap().push(error.to_string());
        }
        fn add_data_type_to_replace(&mut self, _data_type_id: i64, _replacement: Box<dyn DataType>) {}
        fn add_data_type_to_delete(&mut self, _data_type_id: i64) {}
    }

    fn make_manager(allows_settings: bool) -> Arc<Mutex<dyn DataTypeManagerDb + Send>> {
        Arc::new(Mutex::new(TestManager::new(allows_settings)))
    }

    fn make_component(
        mgr: &Arc<Mutex<dyn DataTypeManagerDb + Send>>,
        adapter: &Arc<Mutex<dyn ComponentDBAdapter + Send>>,
        dt_id: i64,
        ordinal: i32,
        offset: i32,
        length: i32,
        name: Option<&str>,
        comment: Option<&str>,
    ) -> DataTypeComponentDB {
        let rec = adapter.lock().unwrap().create_record(dt_id, 100, length, ordinal, offset, name, comment).unwrap();
        DataTypeComponentDB::new_persisted(mgr.clone(), adapter.clone(), rec)
    }

    #[test]
    fn basic_getters_reflect_record_state() {
        let mgr = make_manager(true);
        let byte_id = {
            let mut guard = mgr.lock().unwrap();
            guard.get_resolved_id(&MockLeaf { name: "byte".to_string(), length: 1 })
        };
        let adapter: Arc<Mutex<dyn ComponentDBAdapter + Send>> = Arc::new(Mutex::new(TestComponentAdapter::new()));
        let c = make_component(&mgr, &adapter, byte_id, 2, 8, 4, Some("field2"), Some("a comment"));

        assert_eq!(DataTypeComponent::get_ordinal(&c), 2);
        assert_eq!(DataTypeComponent::get_offset(&c), 8);
        assert_eq!(DataTypeComponent::get_length(&c), 4);
        assert_eq!(DataTypeComponent::get_end_offset(&c), 11);
        assert_eq!(DataTypeComponent::get_field_name(&c), Some("field2".to_string()));
        assert_eq!(DataTypeComponent::get_comment(&c), Some("a comment".to_string()));
        assert_eq!(DataTypeComponent::get_data_type(&c).get_name(), "byte");
        assert!(!DataTypeComponent::is_bit_field_component(&c));
        assert!(!DataTypeComponent::is_undefined(&c));
        assert_eq!(c.get_key(), 0);
    }

    #[test]
    fn zero_length_end_offset_equals_offset() {
        let mgr = make_manager(true);
        let byte_id = mgr.lock().unwrap().get_resolved_id(&MockLeaf { name: "byte".to_string(), length: 1 });
        let adapter: Arc<Mutex<dyn ComponentDBAdapter + Send>> = Arc::new(Mutex::new(TestComponentAdapter::new()));
        let c = make_component(&mgr, &adapter, byte_id, 0, 10, 0, None, None);
        assert_eq!(DataTypeComponent::get_length(&c), 0);
        assert_eq!(DataTypeComponent::get_end_offset(&c), 10);
    }

    #[test]
    fn contains_offset_matches_java_semantics() {
        let mgr = make_manager(true);
        let byte_id = mgr.lock().unwrap().get_resolved_id(&MockLeaf { name: "byte".to_string(), length: 1 });
        let adapter: Arc<Mutex<dyn ComponentDBAdapter + Send>> = Arc::new(Mutex::new(TestComponentAdapter::new()));
        let c = make_component(&mgr, &adapter, byte_id, 0, 10, 4, None, None);
        assert!(c.contains_offset(10));
        assert!(c.contains_offset(12));
        assert!(!c.contains_offset(14));
        assert!(!c.contains_offset(9));
    }

    #[test]
    fn comment_round_trips_and_blank_clears() {
        let mgr = make_manager(true);
        let byte_id = mgr.lock().unwrap().get_resolved_id(&MockLeaf { name: "byte".to_string(), length: 1 });
        let adapter: Arc<Mutex<dyn ComponentDBAdapter + Send>> = Arc::new(Mutex::new(TestComponentAdapter::new()));
        let c = make_component(&mgr, &adapter, byte_id, 0, 0, 1, None, None);

        let updated = DataTypeComponent::set_comment(&c, Some("hello".to_string()));
        assert_eq!(updated.get_comment(), Some("hello".to_string()));
        // The original shares the same underlying record, so it observes the change too.
        assert_eq!(DataTypeComponent::get_comment(&c), Some("hello".to_string()));

        let cleared = DataTypeComponent::set_comment(&c, Some("   ".to_string()));
        assert_eq!(cleared.get_comment(), None);
    }

    #[test]
    fn field_name_round_trips_and_sanitizes_whitespace() {
        let mgr = make_manager(true);
        let byte_id = mgr.lock().unwrap().get_resolved_id(&MockLeaf { name: "byte".to_string(), length: 1 });
        let adapter: Arc<Mutex<dyn ComponentDBAdapter + Send>> = Arc::new(Mutex::new(TestComponentAdapter::new()));
        let c = make_component(&mgr, &adapter, byte_id, 0, 0, 1, None, None);

        let updated = DataTypeComponent::set_field_name(&c, Some("my field".to_string()));
        assert_eq!(updated.get_field_name(), Some("my_field".to_string()));
        assert_eq!(DataTypeComponent::get_field_name(&c), Some("my_field".to_string()));
    }

    #[test]
    fn ordinal_offset_length_setters_persist_to_record() {
        let mgr = make_manager(true);
        let byte_id = mgr.lock().unwrap().get_resolved_id(&MockLeaf { name: "byte".to_string(), length: 1 });
        let adapter: Arc<Mutex<dyn ComponentDBAdapter + Send>> = Arc::new(Mutex::new(TestComponentAdapter::new()));
        let c = make_component(&mgr, &adapter, byte_id, 0, 0, 1, None, None);

        c.set_ordinal(5, true);
        c.set_offset(20, true);
        c.set_length(8, true).unwrap();

        assert_eq!(DataTypeComponent::get_ordinal(&c), 5);
        assert_eq!(DataTypeComponent::get_offset(&c), 20);
        assert_eq!(DataTypeComponent::get_length(&c), 8);

        // Persisted via the adapter too, not just the in-memory copy.
        let key = c.get_key();
        let persisted = adapter.lock().unwrap().get_record(key).unwrap().unwrap();
        assert_eq!(persisted.get_int(COMPONENT_ORDINAL_COL), Some(5));
        assert_eq!(persisted.get_int(COMPONENT_OFFSET_COL), Some(20));
        assert_eq!(persisted.get_int(COMPONENT_SIZE_COL), Some(8));
    }

    #[test]
    fn set_length_rejects_negative() {
        let mgr = make_manager(true);
        let byte_id = mgr.lock().unwrap().get_resolved_id(&MockLeaf { name: "byte".to_string(), length: 1 });
        let adapter: Arc<Mutex<dyn ComponentDBAdapter + Send>> = Arc::new(Mutex::new(TestComponentAdapter::new()));
        let c = make_component(&mgr, &adapter, byte_id, 0, 0, 1, None, None);
        assert!(c.set_length(-1, false).is_err());
    }

    #[test]
    fn clone_shares_underlying_record() {
        let mgr = make_manager(true);
        let byte_id = mgr.lock().unwrap().get_resolved_id(&MockLeaf { name: "byte".to_string(), length: 1 });
        let adapter: Arc<Mutex<dyn ComponentDBAdapter + Send>> = Arc::new(Mutex::new(TestComponentAdapter::new()));
        let c = make_component(&mgr, &adapter, byte_id, 0, 0, 1, None, None);
        let snapshot = c.clone();
        snapshot.set_ordinal(9, false);
        assert_eq!(DataTypeComponent::get_ordinal(&c), 9);
    }

    #[test]
    fn is_undefined_reflects_missing_record_and_data_type() {
        let mgr = make_manager(true);
        let c = DataTypeComponentDB::new_undefined(mgr, 0, 0);
        assert!(DataTypeComponent::is_undefined(&c));
        assert_eq!(DataTypeComponent::get_length(&c), 1);
        assert_eq!(DataTypeComponent::get_data_type(&c).get_name(), "undefined");
    }

    #[test]
    fn immutable_component_reports_supplied_data_type() {
        let mgr = make_manager(true);
        let dt: Box<dyn DataType> = Box::new(MockLeaf { name: "dword".to_string(), length: 4 });
        let c = DataTypeComponentDB::new_immutable(mgr, 3, 12, dt, 4);
        assert_eq!(DataTypeComponent::get_data_type(&c).get_name(), "dword");
        assert_eq!(DataTypeComponent::get_ordinal(&c), 3);
        assert_eq!(DataTypeComponent::get_offset(&c), 12);
        assert_eq!(DataTypeComponent::get_length(&c), 4);
        assert_eq!(c.get_key(), -1);
        // No record, so field-name/comment mutators are no-ops (mirrors Java: `record == null`).
        let unchanged = DataTypeComponent::set_field_name(&c, Some("x".to_string()));
        assert_eq!(unchanged.get_field_name(), None);
    }

    #[test]
    fn default_settings_falls_back_to_no_settings_when_manager_disallows() {
        let mgr = make_manager(false);
        let byte_id = mgr.lock().unwrap().get_resolved_id(&MockLeaf { name: "byte".to_string(), length: 1 });
        let adapter: Arc<Mutex<dyn ComponentDBAdapter + Send>> = Arc::new(Mutex::new(TestComponentAdapter::new()));
        let c = make_component(&mgr, &adapter, byte_id, 0, 0, 1, None, None);
        assert!(DataTypeComponent::get_default_settings(&c).is_immutable_settings());
    }

    #[test]
    fn is_equivalent_compares_offset_name_and_comment() {
        let mgr = make_manager(true);
        let byte_id = mgr.lock().unwrap().get_resolved_id(&MockLeaf { name: "byte".to_string(), length: 1 });
        let adapter: Arc<Mutex<dyn ComponentDBAdapter + Send>> = Arc::new(Mutex::new(TestComponentAdapter::new()));
        let a = make_component(&mgr, &adapter, byte_id, 0, 0, 1, Some("f"), Some("c"));
        let b = make_component(&mgr, &adapter, byte_id, 0, 0, 1, Some("f"), Some("c"));
        assert!(DataTypeComponent::is_equivalent(&a, &b));

        let different_name = make_component(&mgr, &adapter, byte_id, 0, 0, 1, Some("g"), Some("c"));
        assert!(!DataTypeComponent::is_equivalent(&a, &different_name));
    }

    #[test]
    fn components_equal_matches_structurally_identical_components() {
        let mgr = make_manager(true);
        let byte_id = mgr.lock().unwrap().get_resolved_id(&MockLeaf { name: "byte".to_string(), length: 1 });
        let adapter: Arc<Mutex<dyn ComponentDBAdapter + Send>> = Arc::new(Mutex::new(TestComponentAdapter::new()));
        let a = make_component(&mgr, &adapter, byte_id, 1, 4, 1, Some("f"), None);
        let b = make_component(&mgr, &adapter, byte_id, 1, 4, 1, Some("f"), None);
        assert!(a.components_equal(&b));

        let different_offset = make_component(&mgr, &adapter, byte_id, 1, 8, 1, Some("f"), None);
        assert!(!a.components_equal(&different_offset));
    }

    #[test]
    fn display_matches_internal_to_string() {
        let mgr = make_manager(true);
        let byte_id = mgr.lock().unwrap().get_resolved_id(&MockLeaf { name: "byte".to_string(), length: 1 });
        let adapter: Arc<Mutex<dyn ComponentDBAdapter + Send>> = Arc::new(Mutex::new(TestComponentAdapter::new()));
        let c = make_component(&mgr, &adapter, byte_id, 0, 0, 1, Some("f"), None);
        let text = format!("{c}");
        assert!(text.contains("byte"));
    }
}
