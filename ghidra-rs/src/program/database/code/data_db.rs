//! Port of `ghidra.program.database.code.DataDB`.
//!
//! The Java class is a package-private `class DataDB extends CodeUnitDB implements Data`. This
//! file carries three things:
//!
//! 1. [`base_data_type`], a port of the `protected static DataDB.getBaseDataType(DataType)`
//!    helper -- real, self-contained logic that is not an instance method, so it stays a free
//!    function.
//! 2. The [`DataDb`] trait, which is the cut-point for the `DataDB` <-> `DataComponent`
//!    inheritance cycle. `CodeUnitDB` declares `hasBeenDeleted(DBRecord)` abstract, `DataDB`
//!    supplies the "is this address still data" implementation, and `DataComponent` (which
//!    `extends DataDB`, and which `DataDB.ComponentFactory` constructs) overrides it *again* with
//!    component-specific logic. Exposing `has_been_deleted` as a required trait method lets both
//!    concrete types provide their own body and be referred to polymorphically as `dyn DataDb`,
//!    without either needing to name the other's concrete type -- which is exactly what
//!    [`DataComponent`](super::data_component::DataComponent) does for its `parent` field.
//! 3. [`DataDB`] itself: the concrete, database-backed [`Data`] implementation, composing
//!    [`CodeUnitDbBase`] the same way
//!    [`InstructionDB`](super::instruction_db::InstructionDB) does.
//!
//! # Composition instead of inheritance
//!
//! Java's `CodeUnitDB` is an abstract class; its shared state and behaviour live in
//! [`CodeUnitDbBase`], which [`DataDB`] holds in its `base` field and forwards to wherever Java
//! inherits. The three `CodeUnitDB` hooks (`hasBeenDeleted`, `getPreferredCacheLength`,
//! `toString`) come through the [`CodeUnitDb`] trait, and every `codeMgr.xxx(..)` call goes
//! through the [`CodeUnitOwner`] seam.
//!
//! `DataComponent extends DataDB` gets the same treatment one level down: it composes a `DataDB`
//! and forwards. Because Java's `DataDB` method bodies dispatch virtually onto `this`
//! (`getComponent` builds components parented on `DataDB.this`; `getValue`/`getRepresentation`
//! read bytes through `this` as a `MemBuffer`; every bounds check calls the possibly-overridden
//! `getLength()`), those bodies are exposed here as inherent methods taking the virtual result as
//! an **explicit parameter** -- the same convention [`CodeUnitDbBase`] already established, and
//! the reason `DataComponent` can reuse them while still overriding `getLength`/`getByte`/
//! `getBytes`.
//!
//! # Owned handles
//!
//! The ported [`Data`] trait returns *owned* `Box<dyn Data>` values from `getParent()`,
//! `getRoot()`, `getComponent(..)` and friends, where Java returns aliased references into a
//! `DbCache`. [`DataDb::to_boxed_data`] is the seam that makes that possible: each implementor
//! hands back an independent instance describing the same data item. Since a `DataDB` is fully
//! determined by `(owner, cacheKey, address, addr, dataType)` and a `DataComponent` by
//! `(owner, parent, ordinal)`, rebuilding one is cheap and loses nothing but the lazily
//! repopulated byte/comment caches.
//!
//! # Known gaps
//!
//! `DataDB`'s `Settings` half is routed through `program.getDataTypeManager()` in Java (a
//! `ProgramDataTypeManager`, which stores *instance* settings per address). The ported
//! [`Program`](crate::program::model::listing::program::Program) trait exposes no data-type
//! manager, so the instance-settings layer is unreachable; the getters fall back to the data
//! type's default settings and the setters are no-ops. Every such method carries a
//! `TODO(port):` naming the blocker.

use std::any::{Any, TypeId};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, RwLock};

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::framework::db::DBRecord;
use crate::program::database::code::code_unit_db::{CodeUnitDb, CodeUnitDbBase};
use crate::program::database::code::code_unit_owner::CodeUnitOwner;
use crate::program::database::code::data_component::DataComponent;
use crate::program::database::code::data_db_adapter;
use crate::program::database::db_object::{DbObject, DbObjectState};
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::model::data::mutability_settings_definition::{
    self, MutabilitySettingsDefinition,
};
use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::model::lang::processor_context_view::ProcessorContextView;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::model::lang::register_value::RegisterValue;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::data::Data;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::CommentType;
use crate::program::model::mem::{MemBuffer, Memory, MemoryAccessException};
use crate::program::model::scalar::scalar::Scalar;
use crate::program::model::symbol::{
    ExternalReference, Reference as SymReference, ReferenceIterator, RefType as SymRefType,
    SourceType, Symbol, SymbolUtilities,
};
use crate::program::model::util::PropertySet;
use crate::util::string_utilities::StringUtilities;
use crate::program::seam_stubs::{share_data_type, RefType, Reference};
use crate::util::exception::NoValueException;
use crate::util::saveable::Saveable;

/// The operand index every data reference is filed under. Stands in for
/// `CodeManager.DATA_OP_INDEX`.
pub const DATA_OP_INDEX: i32 = 0;

/// If `data_type` is a typedef, returns its base data type; otherwise returns `data_type`
/// unchanged. Stands in for the protected static `DataDB.getBaseDataType(DataType)`.
pub fn base_data_type(data_type: Box<dyn DataType>) -> Box<dyn DataType> {
    if data_type.is_typedef() {
        if let Some(base) = data_type.typedef_base_data_type() {
            return base;
        }
    }
    data_type
}

/// The [`Arc`]-holding sibling of [`base_data_type`], used by [`DataDB`] itself.
///
/// Java's `baseDataType` field aliases the `dataType` field outright when the type is not a
/// typedef (`DataType dt = dataType; if (dt instanceof TypeDef) ...; return dt;`); cloning the
/// `Arc` reproduces that aliasing, which a `Box`-taking helper cannot.
fn shared_base_data_type(data_type: &Arc<dyn DataType>) -> Arc<dyn DataType> {
    if data_type.is_typedef() {
        if let Some(base) = data_type.typedef_base_data_type() {
            return Arc::from(base);
        }
    }
    data_type.clone()
}

/// Database implementation of the [`Data`] interface.
///
/// Port of `ghidra.program.database.code.DataDB`'s own contract -- see the module docs for why
/// this trait exists alongside the concrete [`DataDB`] struct.
pub trait DataDb: Data + DbObject {
    /// Determines whether this data code unit has been deleted (or, following a refresh, updates
    /// this object's cached data type to match the current database state and returns `false`).
    /// `record` mirrors the Java method's `DBRecord` parameter, which may be absent when the
    /// caller expects the implementor to look its own record up as needed.
    ///
    /// Stands in for the protected `DataDB.hasBeenDeleted(DBRecord)`. Declared here as a required
    /// method (rather than given a shared default) because `DataComponent` overrides it again
    /// with independent logic -- see the module docs.
    fn has_been_deleted(&self, record: Option<&DBRecord>) -> bool;

    /// Hands back an independent, owned [`Data`] describing this same data item.
    ///
    /// Not a port of a Java method: Java's `getParent()`/`getRoot()`/`getComponent(int[])` return
    /// `this` or a cached sibling *by reference*, whereas the ported [`Data`] trait returns an
    /// owned `Box<dyn Data>`. Every implementor of this trait is reconstructible from data it
    /// already holds (a `DataDB` from its owner/address/data type, a `DataComponent` from its
    /// owner/parent/ordinal), so this rebuilds an equivalent instance. The only state not carried
    /// over is the lazily repopulated byte and comment caches.
    fn to_boxed_data(&self) -> Box<dyn Data>;
}

// ===========================================================================================
// `DataType.DEFAULT`.
// ===========================================================================================

/// Stands in for the `DefaultDataType.dataType` singleton that Java's `DataType.DEFAULT` names.
///
/// The ported [`DefaultDataType`](crate::program::model::data::default_data_type::DefaultDataType)
/// is a *trait* (it was selected as a cycle cut-point and so declares no singleton), and nothing
/// in the crate implements it outside test modules. `DataDB`'s constructor and its
/// `hasBeenDeleted` "still undefined?" branch both need a concrete instance, so this supplies the
/// smallest possible one, delegating every behavioural method to that trait's ported bodies
/// rather than reimplementing them.
#[derive(Clone, Default)]
struct DefaultDataTypeInstance;

impl DataType for DefaultDataTypeInstance {
    fn get_name(&self) -> String {
        "undefined".to_string()
    }

    fn get_length(&self) -> i32 {
        // Port of `DefaultDataType.getLength()`.
        1
    }

    fn get_mnemonic(&self, _settings: &dyn Settings) -> String {
        // Port of `DefaultDataType.getMnemonic(Settings)`.
        "??".to_string()
    }

    fn get_description(&self) -> String {
        // Port of `DefaultDataType.getDescription()`.
        "Undefined Byte".to_string()
    }

    fn get_representation(
        &self,
        buf: &dyn MemBuffer,
        _settings: &dyn Settings,
        _length: i32,
    ) -> String {
        // Port of `DefaultDataType.getRepresentation(MemBuffer, Settings, int)`.
        match buf.get_byte(0) {
            Ok(byte) => {
                let b = u32::from(byte);
                let mut rep = format!("{b:X}h");
                if rep.len() == 2 {
                    rep = format!("0{rep}");
                }
                if b > 31 && b < 128 {
                    rep.push_str("    ");
                    rep.push(b as u8 as char);
                }
                rep
            }
            Err(_) => "??".to_string(),
        }
    }

    fn get_value(
        &self,
        buf: &dyn MemBuffer,
        _settings: &dyn Settings,
        _length: i32,
    ) -> Option<Box<dyn Any>> {
        // Port of `DefaultDataType.getValue(MemBuffer, Settings, int)`, which yields a Scalar.
        buf.get_byte(0)
            .ok()
            .map(|byte| Box::new(Scalar::new(8, i64::from(byte))) as Box<dyn Any>)
    }

    fn get_value_class(&self, _settings: &dyn Settings) -> Option<TypeId> {
        // Port of `DefaultDataType.getValueClass(Settings)`, which is `Scalar.class`.
        Some(TypeId::of::<Scalar>())
    }

    fn is_default_data_type(&self) -> bool {
        true
    }
}

// ===========================================================================================
// The concrete `DataDB`.
// ===========================================================================================

/// Database implementation for the [`Data`] interface.
///
/// Port of `ghidra.program.database.code.DataDB`.
///
/// NOTE (from the Java source): `DataComponent`s only have a unique key within their parent
/// struct/array. This places a constraint on the use of the key field and `getKey()` method on
/// `CodeUnitDB`/`DataDB` -- the key should only be used for managing an object cache, and the
/// `addr` field should be used within this class instead.
pub struct DataDB {
    /// The shared `CodeUnitDB` state Java inherits. See the module docs.
    base: CodeUnitDbBase,
    /// Stands in for `DataDB.dataType`; reassigned by `hasBeenDeleted` on a refresh.
    data_type: RwLock<Arc<dyn DataType>>,
    /// Stands in for `DataDB.baseDataType`, kept in step with [`Self::data_type`].
    base_data_type: RwLock<Arc<dyn DataType>>,
    /// Stands in for `DataDB.level`. `0` for a top-level data item; a `DataComponent` raises its
    /// own copy to `parent.level + 1`.
    level: AtomicI32,
    /// Stands in for the `Boolean DataDB.hasMutabilitySetting` tri-state cache: `None` is Java's
    /// `null` ("not yet determined").
    has_mutability_setting: RwLock<Option<bool>>,
}

impl DataDB {
    /// Constructs a new `DataDB`.
    ///
    /// Stands in for the protected
    /// `DataDB(CodeManager, long cacheKey, Address, long addr, DataType)`.
    ///
    /// # Arguments
    /// * `owner` - the creating code manager, narrowed to the callbacks a code unit makes
    /// * `cache_key` - normally the encoded address, but for data components the ordinal
    /// * `address` - the address for the data
    /// * `addr` - the encoded address for the data
    /// * `data_type` - the data type for the data; `None` maps to Java's `null`, which the
    ///   constructor replaces with `DataType.DEFAULT`
    pub fn new(
        owner: Arc<dyn CodeUnitOwner>,
        cache_key: i64,
        address: Address,
        addr: i64,
        data_type: Option<Arc<dyn DataType>>,
    ) -> Self {
        let initial_length = data_type.as_ref().map_or(1, |dt| dt.get_length());
        let base = CodeUnitDbBase::new(owner, cache_key, address, addr, initial_length);
        let data_type: Arc<dyn DataType> =
            data_type.unwrap_or_else(|| Arc::new(DefaultDataTypeInstance));
        let base_data_type = shared_base_data_type(&data_type);
        // Java: `dataMgr = program.getDataTypeManager();` -- see the module docs for why the
        // ported `Program` trait cannot supply one.
        base.set_length(-1); // lazy compute
        DataDB {
            base,
            data_type: RwLock::new(data_type),
            base_data_type: RwLock::new(base_data_type),
            level: AtomicI32::new(0),
            has_mutability_setting: RwLock::new(None),
        }
    }

    /// The shared `CodeUnitDB` half, for [`DataComponent`]'s forwarding impls.
    pub(crate) fn base(&self) -> &CodeUnitDbBase {
        &self.base
    }

    /// Stands in for reading the `DataDB.dataType` field.
    pub(crate) fn data_type_ref(&self) -> Arc<dyn DataType> {
        self.data_type.read().unwrap().clone()
    }

    /// Stands in for reading the `DataDB.baseDataType` field.
    pub(crate) fn base_data_type_ref(&self) -> Arc<dyn DataType> {
        self.base_data_type.read().unwrap().clone()
    }

    /// Overwrites `dataType` (and the derived `baseDataType`), as `hasBeenDeleted` does.
    pub(crate) fn set_data_type(&self, data_type: Arc<dyn DataType>) {
        let base = shared_base_data_type(&data_type);
        *self.data_type.write().unwrap() = data_type;
        *self.base_data_type.write().unwrap() = base;
    }

    /// Stands in for reading the `DataDB.level` field.
    pub(crate) fn level(&self) -> i32 {
        self.level.load(Ordering::SeqCst)
    }

    /// Stands in for `DataComponent`'s constructor assignment `this.level = parent.level + 1`.
    pub(crate) fn set_level(&self, level: i32) {
        self.level.store(level, Ordering::SeqCst);
    }

    /// Rebuilds an equivalent, independent `DataDB`. See [`DataDb::to_boxed_data`].
    pub(crate) fn duplicate(&self) -> DataDB {
        let duplicate = DataDB::new(
            self.base.owner().clone(),
            self.base.state().get_key(),
            self.base.address(),
            self.base.addr(),
            Some(self.data_type_ref()),
        );
        duplicate.set_level(self.level());
        duplicate
    }

    /// This object as the polymorphic `DataDB.this` that `ComponentFactory` captures as the new
    /// component's parent.
    fn this(&self) -> Arc<dyn DataDb> {
        Arc::new(self.duplicate())
    }

    // -- length -----------------------------------------------------------------------------

    /// Port of `DataDB.getLength()`, including its lazy `length == -1` trigger.
    pub(crate) fn data_length(&self) -> i32 {
        if self.base.length() == -1 {
            self.compute_length();
        }
        self.base.length()
    }

    /// Port of the private `DataDB.computeLength()`.
    fn compute_length(&self) {
        let data_type = self.data_type_ref();
        let address = self.base.address();

        // NOTE: Data intentionally does not use aligned-length
        let mut length = data_type.get_length();

        // undefined will never change their size
        if data_type.is_undefined_type() {
            self.base.set_length(length);
            return;
        }

        if length < 1 {
            length = self.base.owner().get_length_at(&address);
        }
        if length <= 0 {
            length = 1;
        }

        // no need to do all that follow on checking when length == 1
        if length == 1 {
            self.base.set_length(length);
            return;
        }

        // FIXME Trying to get Data to display for External.
        if address.is_external_address() {
            self.base.set_length(length);
            return;
        }

        let memory = self.base.get_memory();
        let mut end_address = address.add_no_wrap(i64::from(length - 1)).ok();

        // Java: `!mem.contains(address, endAddress)`. The ported `Memory` trait carries only the
        // single-address `contains(Address)` (it has no `AddressSetView` supertrait here), so the
        // range test is expressed as "both endpoints lie in memory", which agrees with Java for
        // every gap-free block layout.
        let range_in_memory = match (&memory, &end_address) {
            (Some(memory), Some(end)) => memory.contains(&address) && memory.contains(end),
            _ => false,
        };

        if !range_in_memory {
            match memory.as_ref().and_then(|memory| memory.get_block(&address)) {
                Some(block) => {
                    let end = block.get_end();
                    length = (end.subtract(&address) + 1) as i32;
                    end_address = Some(end);
                }
                None => {
                    length = 1; // ?? what should this be?
                    end_address = Some(address.clone());
                }
            }
        }

        // if this is not a component where the size could change and the length restricted by the
        // following instruction/data item, assume the createData method stopped fixed code units
        // that won't fit from being added.
        //
        // This is potentially expensive! So only do if necessary -- see if the datatype length is
        // restricted by a following codeunit.
        if let (Some(next_addr), Some(end)) = (
            self.base.owner().get_defined_address_after(&address),
            end_address.as_ref(),
        ) {
            if next_addr <= *end {
                length = next_addr.subtract(&address) as i32;
            }
        }

        self.base.set_length(length);
    }

    // -- refresh ----------------------------------------------------------------------------

    /// The `DataDB`-specific half of `DataDB.refresh(DBRecord)`, i.e. everything it does before
    /// `return super.refresh(record)` plus `CodeUnitDB.refresh`'s own cache resetting.
    ///
    /// Split out so `DataComponent` -- which inherits `refresh` but overrides `hasBeenDeleted` --
    /// can run the same preamble ahead of *its* deletion check.
    ///
    /// Java also invalidates the `DbCache<DataComponent> componentCache` here; this port builds a
    /// fresh component on every `getComponent` call (the ported `Data::get_component` returns an
    /// owned `Box<dyn Data>`, so callers cannot share a cached instance anyway), so there is no
    /// cache to invalidate.
    pub(crate) fn refresh_shared(&self) {
        *self.has_mutability_setting.write().unwrap() = None;
        self.base.refresh_base();
    }

    /// Mirrors `DBRecord.hasSameSchema(DataDBAdapter.DATA_SCHEMA)`, matching the equivalent
    /// helper in [`InstructionDB`](super::instruction_db::InstructionDB).
    fn has_data_schema(record: &DBRecord) -> bool {
        let schema = data_db_adapter::schema();
        if record.get_key().get_type() != schema.get_key_type() {
            return false;
        }
        if record.get_field_count() != schema.get_field_count() {
            return false;
        }
        (0..schema.get_field_count())
            .all(|i| record.get_field(i).get_type() == schema.get_field_type(i))
    }

    // -- value / representation (Java dispatches these virtually onto `this`) -----------------
    //
    // Java's bodies open with `refreshIfNeeded()`, a *virtual* `DbObject` call: on a
    // `DataComponent` it must run `DataComponent.hasBeenDeleted`, not `DataDB`'s. Since these
    // shared helpers are also called *by* `DataComponent` (on its embedded `DataDB`), the refresh
    // is hoisted out of them and performed by each public trait method on the outermost object,
    // the same way `CodeUnitDbBase` turns virtual calls into explicit obligations of the caller.

    /// Port of `DataDB.getValue()`. `buf`/`settings` stand in for the two `this` arguments Java
    /// passes, and `length` for the (possibly overridden) `getLength()`.
    pub(crate) fn value(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Option<Box<dyn Any>> {
        let _guard = self.base.lock().read();
        self.data_type_ref().get_value(buf, settings, length)
    }

    /// Port of `DataDB.getValueClass()`.
    pub(crate) fn value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        self.base_data_type_ref().get_value_class(settings)
    }

    /// Port of `DataDB.getDefaultValueRepresentation()`.
    pub(crate) fn default_value_representation(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> String {
        let _guard = self.base.lock().read();
        self.data_type_ref().get_representation(buf, settings, length)
    }

    /// Port of `DataDB.getMnemonicString()`.
    pub(crate) fn mnemonic_string(&self, settings: &dyn Settings) -> String {
        let _guard = self.base.lock().read();
        self.data_type_ref().get_mnemonic(settings)
    }

    /// Port of `DataDB.getDefaultLabelPrefix(DataTypeDisplayOptions)`.
    pub(crate) fn default_label_prefix(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
        options: &dyn DataTypeDisplayOptions,
    ) -> Option<String> {
        let data_type = self.data_type_ref();
        if data_type.is_default_data_type() {
            return None;
        }
        data_type.get_default_label_prefix_for_data(buf, settings, length, options)
    }

    /// Port of `DataDB.toString()`, which `CodeUnitDB` declares abstract.
    pub(crate) fn data_string(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> String {
        let value_representation = self.default_value_representation(buf, settings, length);
        let mnemonic_string = self.mnemonic_string(settings);
        if value_representation.is_empty() {
            // Java tests `valueRepresentation == null`; the ported
            // `DataType::get_representation` returns a `String`, whose empty value is the closest
            // equivalent (it is what every representation-less type yields).
            return mnemonic_string;
        }
        format!("{mnemonic_string} {value_representation}")
    }

    /// Port of `DataDB.getAddress(int)`.
    pub(crate) fn address_for_operand(
        &self,
        op_index: i32,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Option<Address> {
        if op_index != 0 {
            return None;
        }
        self.value(buf, settings, length)?
            .downcast::<Address>()
            .ok()
            .map(|address| *address)
    }

    /// Port of `DataDB.getScalar(int)`.
    pub(crate) fn scalar_for_operand(
        &self,
        op_index: i32,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Option<Scalar> {
        if op_index != 0 {
            return None;
        }
        let value = self.value(buf, settings, length)?;
        let value = match value.downcast::<Scalar>() {
            Ok(scalar) => return Some(*scalar),
            Err(value) => value,
        };
        let address = *value.downcast::<Address>().ok()?;
        let offset = address.addressable_word_offset();
        Some(Scalar::new_with_signedness(
            (address.space().pointer_size() * 8) as u8,
            offset,
            false,
        ))
    }

    // -- components (Java dispatches these virtually onto `this`) -----------------------------

    /// Port of `DataDB.getNumComponents()`.
    ///
    /// # TODO(port)
    /// The `baseDataType instanceof DynamicDataType` branch is unreachable: the ported
    /// [`DataType`] trait exposes `as_dynamic()` (the `Dynamic` *interface*) but no downcast to
    /// [`DynamicDataType`](crate::program::model::data::dynamic_data_type::DynamicDataType),
    /// which is where `getNumComponents(MemBuffer)` lives. A dynamic type therefore reports `0`
    /// components here (the same value Java's `catch (Throwable)` arm produces).
    pub(crate) fn num_components(&self, _buf: &dyn MemBuffer, length: i32) -> i32 {
        let _guard = self.base.lock().read();
        if length < self.data_type_ref().get_length() {
            return -1;
        }
        let base_data_type = self.base_data_type_ref();
        if let Some(composite) = base_data_type.as_composite() {
            return composite.get_num_components();
        }
        if let Some(array) = base_data_type.as_array() {
            return array.get_num_elements();
        }
        0
    }

    /// Port of `DataDB.getComponent(int)` -- including its `ComponentFactory` construction path,
    /// which lives in [`DataComponent::for_ordinal`].
    ///
    /// `this` is Java's `DataDB.this`, captured by the inner `ComponentFactory` class as the new
    /// component's parent; `buf`/`length` are the virtual `getNumComponents()` inputs.
    pub(crate) fn component(
        &self,
        index: i32,
        this: &Arc<dyn DataDb>,
        buf: &dyn MemBuffer,
        length: i32,
    ) -> Option<DataComponent> {
        let _guard = self.base.lock().read();
        if index < 0 || index >= self.num_components(buf, length) {
            return None;
        }
        DataComponent::for_ordinal(self.base.owner().clone(), this.clone(), index)
    }

    /// Port of `DataDB.getComponent(int[])`.
    pub(crate) fn component_by_path(
        &self,
        component_path: &[i32],
        this: &Arc<dyn DataDb>,
        buf: &dyn MemBuffer,
        length: i32,
    ) -> Option<Box<dyn Data>> {
        let _guard = self.base.lock().read();
        let level = self.level();
        if component_path.len() <= level.max(0) as usize {
            return Some(this.to_boxed_data());
        }
        let component = self.component(component_path[level as usize], this, buf, length)?;
        component.get_component_by_path(component_path)
    }

    /// Port of `DataDB.getComponentContaining(int)`.
    ///
    /// # TODO(port)
    /// The `baseDataType instanceof DynamicDataType` branch is unreachable for the reason given
    /// on [`num_components`](Self::num_components); a dynamic type yields `None` here.
    pub(crate) fn component_containing(
        &self,
        offset: i32,
        this: &Arc<dyn DataDb>,
        buf: &dyn MemBuffer,
        length: i32,
    ) -> Option<DataComponent> {
        let _guard = self.base.lock().read();
        if offset < 0 || offset > length {
            return None;
        }
        let base_data_type = self.base_data_type_ref();
        if let Some(array) = base_data_type.as_array() {
            let element_length = array.get_element_length();
            if element_length <= 0 {
                return None;
            }
            return self.component(offset / element_length, this, buf, length);
        }
        if let Some(structure) = base_data_type.as_structure() {
            let dtc = structure.get_component_containing(offset)?;
            return self.component(dtc.get_ordinal(), this, buf, length);
        }
        // Java's `baseDataType instanceof Union` arm is empty ("TODO: Returning anything is
        // potentially bad"), and falls through to `return null` like every other type.
        None
    }

    /// Port of `DataDB.getComponentsContaining(int)`.
    ///
    /// # TODO(port)
    /// The `baseDataType instanceof DynamicDataType` branch is unreachable for the reason given
    /// on [`num_components`](Self::num_components); a dynamic type yields an empty list here.
    pub(crate) fn components_containing(
        &self,
        offset: i32,
        this: &Arc<dyn DataDb>,
        buf: &dyn MemBuffer,
        length: i32,
    ) -> Option<Vec<Box<dyn Data>>> {
        let _guard = self.base.lock().read();
        if offset < 0 || offset >= length {
            return None;
        }
        let base_data_type = self.base_data_type_ref();

        if let Some(array) = base_data_type.as_array() {
            let element_length = array.get_element_length();
            if element_length <= 0 {
                return Some(Vec::new());
            }
            let index = offset / element_length;
            return Some(
                self.component(index, this, buf, length)
                    .into_iter()
                    .map(|component| Box::new(component) as Box<dyn Data>)
                    .collect(),
            );
        }

        if let Some(structure) = base_data_type.as_structure() {
            let mut result: Vec<Box<dyn Data>> = Vec::new();
            for dtc in structure.get_components_containing(offset) {
                if let Some(component) = self.component(dtc.get_ordinal(), this, buf, length) {
                    result.push(Box::new(component));
                }
            }
            return Some(result);
        }

        if let Some(union) = base_data_type.as_union() {
            let mut result: Vec<Box<dyn Data>> = Vec::new();
            for dtc in union.get_components() {
                if offset < dtc.get_length() {
                    if let Some(component) = self.component(dtc.get_ordinal(), this, buf, length) {
                        result.push(Box::new(component));
                    }
                }
            }
            return Some(result);
        }

        Some(Vec::new())
    }

    /// Port of `DataDB.getPrimitiveAt(int)`.
    pub(crate) fn primitive_at(
        &self,
        offset: i32,
        this: &Arc<dyn DataDb>,
        buf: &dyn MemBuffer,
        length: i32,
    ) -> Option<Box<dyn Data>> {
        let _guard = self.base.lock().read();
        if offset < 0 || offset >= length {
            return None;
        }
        // Java also short-circuits on `dc == this`; a component is never its own parent here, so
        // only the `dc == null` arm can fire.
        let Some(component) = self.component_containing(offset, this, buf, length) else {
            return Some(this.to_boxed_data());
        };
        let parent_offset = component.get_parent_offset();
        component.get_primitive_at(offset - parent_offset)
    }

    // -- comments (Java routes these through the lowest component) ----------------------------

    /// Port of `DataDB.getComment(CommentType)`, which keeps a comment at the lowest point in the
    /// data path to avoid a caching issue.
    pub(crate) fn comment_at(
        &self,
        comment_type: CommentType,
        this: &Arc<dyn DataDb>,
        buf: &dyn MemBuffer,
        length: i32,
    ) -> Option<String> {
        match self.component_containing(0, this, buf, length) {
            Some(child) => child.get_comment(comment_type),
            None => self.base.get_comment(comment_type),
        }
    }

    /// Port of `DataDB.setComment(CommentType, String)`.
    pub(crate) fn set_comment_at(
        &self,
        comment_type: CommentType,
        comment: Option<String>,
        this: &Arc<dyn DataDb>,
        buf: &dyn MemBuffer,
        length: i32,
    ) {
        match self.component_containing(0, this, buf, length) {
            Some(mut child) => child.set_comment(comment_type, comment),
            None => self.base.set_comment(comment_type, comment),
        }
    }

    // -- settings ------------------------------------------------------------------------------

    /// Port of the private generic `DataDB.getSettingsDefinition(Class<T>)`, specialised to the
    /// one definition class Java looks up with it.
    ///
    /// Java selects by `Class.isAssignableFrom`; with no runtime class tokens available here, the
    /// definition is identified by its storage key, which is exactly what distinguishes it in the
    /// settings store.
    fn mutability_settings_definition(&self) -> Option<MutabilitySettingsDefinition> {
        let wanted = MutabilitySettingsDefinition::DEF.get_storage_key();
        self.data_type_ref()
            .get_settings_definitions()
            .into_iter()
            .any(|def| def.get_storage_key() == wanted)
            .then_some(MutabilitySettingsDefinition::DEF)
    }

    /// Port of the private `DataDB.hasMutability(int)`, including its `hasMutabilitySetting`
    /// memoization.
    pub(crate) fn has_mutability(&self, mutability_type: i32, settings: &dyn Settings) -> bool {
        let has_setting = *self.has_mutability_setting.read().unwrap();
        if has_setting == Some(false) {
            return mutability_type == mutability_settings_definition::NORMAL;
        }
        let _guard = self.base.lock().read();
        match self.mutability_settings_definition() {
            Some(def) => {
                *self.has_mutability_setting.write().unwrap() = Some(true);
                use crate::docking::settings::enum_settings_definition::EnumSettingsDefinition;
                def.get_choice(settings) == mutability_type
            }
            None => {
                *self.has_mutability_setting.write().unwrap() = Some(false);
                false
            }
        }
    }

    // -- misc ----------------------------------------------------------------------------------

    /// Port of `DataDB.getPathName()`.
    ///
    /// # TODO(port)
    /// Java falls back to `SymbolUtilities.getDynamicName(program, cuAddress)`, whose ported
    /// counterpart
    /// ([`SymbolUtilities::get_dynamic_name_for_program`](crate::program::model::symbol::SymbolUtilities::get_dynamic_name_for_program))
    /// needs a `&mut dyn Program` to consult the listing and reference level; a code unit only
    /// ever holds an `Arc<dyn Program>`. The reference-level-0 overload
    /// ([`SymbolUtilities::get_dynamic_name`]) is used instead, which matches Java for every
    /// address that is not the target of an offcut/data reference.
    pub(crate) fn path_name(&self) -> String {
        let address = self.base.address();
        if let Some(symbol) = self.base.get_primary_symbol() {
            return symbol.get_name().to_owned();
        }
        struct Naming;
        impl SymbolUtilities for Naming {}
        Naming.get_dynamic_name(0, Some(&address)).unwrap_or_default()
    }

    /// Port of `DataDB.getReferencesFrom()`, which -- unlike `CodeUnitDB`'s -- gathers references
    /// from *every* address this data item covers, not just its minimum address.
    pub(crate) fn references_from(&self, length: i32) -> Vec<Arc<dyn SymReference>> {
        let min_address = self.base.address();
        let max_address = self.base.get_max_address(length);
        let reference_manager = self.base.owner().get_reference_manager();
        let reference_manager = reference_manager.lock().unwrap();
        let mut list = Vec::new();
        // Java restricts the iterator with `new AddressSet(min, max)`; iterating forward from the
        // minimum address and stopping past the maximum is the same traversal.
        for from_address in reference_manager.get_reference_source_iterator(min_address, true) {
            if from_address > max_address {
                break;
            }
            list.extend(reference_manager.get_references_from(from_address));
        }
        list
    }
}

// ===========================================================================================
// MemBuffer -- inherited from `CodeUnitDB` in Java.
// ===========================================================================================

impl MemBuffer for DataDB {
    fn get_address(&self) -> Address {
        self.base.address()
    }

    fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        self.base.get_byte(offset, self.get_preferred_cache_length())
    }

    fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
        self.base
            .get_bytes_at(buf, offset, self.get_preferred_cache_length())
    }

    fn is_big_endian(&self) -> bool {
        self.base.is_big_endian()
    }

    fn get_memory(&self) -> Option<Arc<dyn Memory>> {
        self.base.get_memory()
    }
}

// ===========================================================================================
// PropertySet -- inherited from `CodeUnitDB` in Java.
// ===========================================================================================

impl PropertySet for DataDB {
    fn set_object_property(&mut self, name: &str, value: Box<dyn Saveable>) {
        // TODO(port): `CodeUnitDbBase` has no object-property setter -- the ported
        // `PropertyMapManager`/`ObjectPropertyMap` pair carries no `add_object`, so
        // `CodeUnitDB.setProperty(String, Saveable)` has no shared implementation to forward to.
        let _ = (name, value);
    }

    fn set_string_property(&mut self, name: &str, value: &str) {
        self.base.set_string_property(name, value);
    }

    fn set_int_property(&mut self, name: &str, value: i32) {
        self.base.set_int_property(name, value);
    }

    fn set_void_property(&mut self, name: &str) {
        self.base.set_void_property(name);
    }

    fn get_object_property(&self, name: &str) -> Option<Box<dyn Saveable>> {
        self.base.get_object_property(name)
    }

    fn get_string_property(&self, name: &str) -> Option<String> {
        self.base.get_string_property(name)
    }

    fn get_int_property(&self, name: &str) -> Result<i32, NoValueException> {
        self.base.get_int_property(name)
    }

    fn has_property(&self, name: &str) -> bool {
        self.base.has_property(name)
    }

    fn get_void_property(&self, name: &str) -> bool {
        self.base.get_void_property(name)
    }

    fn property_names(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.base.property_names().into_iter())
    }

    fn remove_property(&mut self, name: &str) {
        self.base.remove_property(name);
    }
}

// ===========================================================================================
// Settings -- `DataDB` implements these against its owning `ProgramDataTypeManager`.
// ===========================================================================================

impl Settings for DataDB {
    /// Port of `DataDB.getDefaultSettings()`.
    fn get_default_settings(&self) -> Option<Box<dyn Settings>> {
        Some(self.data_type_ref().get_default_settings())
    }

    /// Port of `DataDB.getLong(String)`.
    ///
    /// TODO(port): Java first consults `dataMgr.getLongSettingsValue(this, name)` for an
    /// *instance* setting. The ported `Program` trait exposes no data-type manager, so only the
    /// data type's default settings can be consulted.
    fn get_long(&self, name: &str) -> Option<i64> {
        self.get_default_settings()
            .and_then(|settings| settings.get_long(name))
    }

    /// Port of `DataDB.getString(String)`. Same `dataMgr` blocker as [`Self::get_long`].
    fn get_string(&self, name: &str) -> Option<String> {
        self.get_default_settings()
            .and_then(|settings| settings.get_string(name))
    }

    /// Port of `DataDB.getValue(String)`. Same `dataMgr` blocker as [`Self::get_long`].
    fn get_value(&self, name: &str) -> Option<Box<dyn Any>> {
        self.get_default_settings()
            .and_then(|settings| settings.get_value(name))
    }

    /// Port of `DataDB.getNames()`.
    ///
    /// TODO(port): `dataMgr.getInstanceSettingsNames(this)` is unreachable (see
    /// [`Self::get_long`]); no instance settings exist to name.
    fn get_names(&self) -> Vec<String> {
        Vec::new()
    }

    /// Port of `DataDB.isEmpty()`.
    ///
    /// TODO(port): `dataMgr.isEmptySetting(this)` is unreachable (see [`Self::get_long`]); with
    /// no instance-settings store there is nothing non-empty to report.
    fn is_empty(&self) -> bool {
        true
    }

    /// Port of `DataDB.isChangeAllowed(SettingsDefinition)`.
    ///
    /// TODO(port): `dataMgr.isChangeAllowed(this, settingsDefinition)` is unreachable (see
    /// [`Self::get_long`]).
    fn is_change_allowed(&self, _settings_definition: &dyn SettingsDefinition) -> bool {
        false
    }

    /// Port of `DataDB.setLong(String, long)`.
    ///
    /// TODO(port): `dataMgr.setLongSettingsValue(this, name, value)` is unreachable (see
    /// [`Self::get_long`]), so instance settings cannot be written.
    fn set_long(&mut self, name: &str, value: i64) {
        let _ = (name, value);
    }

    /// Port of `DataDB.setString(String, String)`. Same `dataMgr` blocker as [`Self::set_long`].
    fn set_string(&mut self, name: &str, value: &str) {
        let _ = (name, value);
    }

    /// Port of `DataDB.setValue(String, Object)`. Same `dataMgr` blocker as [`Self::set_long`].
    fn set_value(&mut self, name: &str, value: Box<dyn Any>) {
        let _ = (name, value);
    }

    /// Port of `DataDB.clearSetting(String)`. Same `dataMgr` blocker as [`Self::set_long`].
    fn clear_setting(&mut self, name: &str) {
        let _ = name;
    }

    /// Port of `DataDB.clearAllSettings()`. Same `dataMgr` blocker as [`Self::set_long`].
    fn clear_all_settings(&mut self) {}
}

// ===========================================================================================
// CodeUnit -- inherited from `CodeUnitDB` except where `DataDB` overrides.
// ===========================================================================================

impl CodeUnit for DataDB {
    fn get_address_string(&self, show_block_name: bool, pad: bool) -> String {
        self.base.get_address_string(show_block_name, pad)
    }

    fn get_label(&self) -> Option<String> {
        self.base.get_label()
    }

    fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
        self.base.get_symbols()
    }

    fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
        self.base.get_primary_symbol()
    }

    fn get_min_address(&self) -> Address {
        self.base.address()
    }

    fn get_max_address(&self) -> Address {
        self.base.get_max_address(self.get_length())
    }

    /// Port of `DataDB.getMnemonicString()`.
    fn get_mnemonic_string(&self) -> String {
        self.refresh_if_needed();
        self.mnemonic_string(self)
    }

    /// Port of `DataDB.getComment(CommentType)`.
    fn get_comment(&self, comment_type: CommentType) -> Option<String> {
        let length = self.get_length();
        self.comment_at(comment_type, &self.this(), self, length)
    }

    /// Inherited `CodeUnitDB.getCommentAsArray(CommentType)`, which splits the *virtual*
    /// `getComment(..)` -- i.e. `DataDB`'s override, not the raw comment record.
    fn get_comment_as_array(&self, comment_type: CommentType) -> Vec<String> {
        match CodeUnit::get_comment(self, comment_type) {
            Some(comment) => comment.to_lines_default(),
            None => Vec::new(),
        }
    }

    /// Port of `DataDB.setComment(CommentType, String)`.
    fn set_comment(&mut self, comment_type: CommentType, comment: Option<String>) {
        let length = self.get_length();
        self.set_comment_at(comment_type, comment, &self.this(), self, length);
    }

    fn set_comment_as_array(&mut self, comment_type: CommentType, comment: &[String]) {
        self.base.set_comment_as_array(comment_type, comment);
    }

    /// Port of `DataDB.getLength()`.
    fn get_length(&self) -> i32 {
        self.data_length()
    }

    fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
        self.base
            .get_bytes(self.get_length(), self.get_preferred_cache_length())
    }

    fn get_bytes_in_code_unit(
        &self,
        buffer: &mut [u8],
        buffer_offset: i32,
    ) -> Result<(), MemoryAccessException> {
        self.base.get_bytes_in_code_unit(
            buffer,
            buffer_offset,
            self.get_length(),
            self.get_preferred_cache_length(),
        )
    }

    fn contains(&self, test_addr: &Address) -> bool {
        self.base.contains(test_addr, self.get_length())
    }

    fn compare_to(&self, addr: &Address) -> i32 {
        self.base.compare_to(addr, self.get_length())
    }

    fn add_mnemonic_reference(
        &mut self,
        ref_addr: Address,
        ref_type: SymRefType,
        source_type: SourceType,
    ) {
        self.base
            .add_mnemonic_reference(&ref_addr, ref_type, source_type);
    }

    fn remove_mnemonic_reference(&mut self, ref_addr: &Address) {
        self.base.remove_mnemonic_reference(ref_addr);
    }

    fn get_mnemonic_references(&self) -> Vec<Arc<dyn SymReference>> {
        self.base.get_mnemonic_references()
    }

    fn get_operand_references(&self, index: i32) -> Vec<Arc<dyn SymReference>> {
        self.base.get_operand_references(index)
    }

    fn get_primary_reference(&self, index: i32) -> Option<Arc<dyn SymReference>> {
        self.base.get_primary_reference(index)
    }

    fn add_operand_reference(
        &mut self,
        index: i32,
        ref_addr: Address,
        ref_type: SymRefType,
        source_type: SourceType,
    ) {
        self.base
            .add_operand_reference(index, &ref_addr, ref_type, source_type);
    }

    fn remove_operand_reference(&mut self, index: i32, ref_addr: &Address) {
        self.base.remove_operand_reference(index, ref_addr);
    }

    /// Port of `DataDB.getReferencesFrom()`.
    fn get_references_from(&self) -> Vec<Arc<dyn SymReference>> {
        self.references_from(self.get_length())
    }

    fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
        self.base.get_reference_iterator_to()
    }

    fn get_program(&self) -> Arc<dyn Program> {
        self.base.get_program()
    }

    fn get_external_reference(&self, op_index: i32) -> Option<Arc<dyn ExternalReference>> {
        self.base.get_external_reference(op_index)
    }

    fn remove_external_reference(&mut self, op_index: i32) {
        self.base.remove_external_reference(op_index);
    }

    fn set_primary_memory_reference(&mut self, reference: Arc<dyn SymReference>) {
        self.base.set_primary_memory_reference(reference);
    }

    fn set_stack_reference(
        &mut self,
        op_index: i32,
        offset: i32,
        source_type: SourceType,
        ref_type: SymRefType,
    ) {
        let num_operands = self.get_num_operands();
        self.base
            .set_stack_reference(op_index, offset, source_type, ref_type, num_operands);
    }

    fn set_register_reference(
        &mut self,
        op_index: i32,
        reg: &Register,
        source_type: SourceType,
        ref_type: SymRefType,
    ) {
        let num_operands = self.get_num_operands();
        self.base.set_register_reference(
            op_index,
            Register::from_register(reg),
            source_type,
            ref_type,
            num_operands,
        );
    }

    /// Port of `DataDB.getNumOperands()`.
    fn get_num_operands(&self) -> i32 {
        1
    }

    /// Port of `DataDB.getAddress(int)`.
    fn get_address(&self, op_index: i32) -> Option<Address> {
        let length = self.get_length();
        self.address_for_operand(op_index, self, self, length)
    }

    /// Port of `DataDB.getScalar(int)`.
    fn get_scalar(&self, op_index: i32) -> Option<Scalar> {
        let length = self.get_length();
        self.scalar_for_operand(op_index, self, self, length)
    }

    fn as_data(&self) -> Option<&dyn Data> {
        Some(self)
    }
}


// ===========================================================================================
// ProcessorContext / ProcessorContextView -- inherited from `CodeUnitDB` in Java.
// ===========================================================================================

impl ProcessorContextView for DataDB {
    fn get_base_context_register(&self) -> Option<RegisterRef> {
        Some(self.base.get_base_context_register())
    }

    fn get_registers(&self) -> Vec<RegisterRef> {
        self.base.get_registers()
    }

    fn get_register(&self, name: &str) -> Option<RegisterRef> {
        self.base.get_register(name)
    }

    fn get_value(&self, register: &Register, signed: bool) -> Option<i128> {
        self.base.get_register_bigint_value(register, signed)
    }

    fn get_register_value(&self, register: &Register) -> Option<RegisterValue> {
        self.base.get_register_value(register)
    }

    fn has_value(&self, register: &Register) -> bool {
        self.base.has_value(register)
    }
}

impl ProcessorContext for DataDB {
    fn set_value(&mut self, register: &Register, value: i128) -> Result<(), ContextChangeException> {
        self.base.set_register_bigint_value(register, value)
    }

    fn set_register_value(
        &mut self,
        value: RegisterValue,
    ) -> Result<(), ContextChangeException> {
        self.base.set_register_value(value)
    }

    fn clear_register(&mut self, register: &Register) -> Result<(), ContextChangeException> {
        self.base.clear_register(register)
    }
}

// ===========================================================================================
// Data.
// ===========================================================================================

impl Data for DataDB {
    fn get_value(&self) -> Option<Box<dyn Any>> {
        self.refresh_if_needed();
        let length = self.get_length();
        self.value(self, self, length)
    }

    fn get_value_class(&self) -> Option<TypeId> {
        self.value_class(self)
    }

    fn has_string_value(&self) -> bool {
        self.get_value_class() == Some(TypeId::of::<String>())
    }

    fn is_constant(&self) -> bool {
        self.refresh_if_needed();
        self.has_mutability(mutability_settings_definition::CONSTANT, self)
    }

    fn is_writable(&self) -> bool {
        self.refresh_if_needed();
        self.has_mutability(mutability_settings_definition::WRITABLE, self)
    }

    fn is_volatile(&self) -> bool {
        self.refresh_if_needed();
        self.has_mutability(mutability_settings_definition::VOLATILE, self)
    }

    fn is_defined(&self) -> bool {
        !self.data_type_ref().is_default_data_type()
    }

    fn get_data_type(&self) -> Box<dyn DataType> {
        share_data_type(&self.data_type_ref())
    }

    fn get_base_data_type(&self) -> Box<dyn DataType> {
        share_data_type(&self.base_data_type_ref())
    }

    /// Port of `DataDB.getValueReferences()`, which is `getOperandReferences(DATA_OP_INDEX)`.
    ///
    /// TODO(port): the ported `Data` trait types its elements as the empty placeholder trait
    /// [`seam_stubs::Reference`](crate::program::seam_stubs::Reference), not the real
    /// [`symbol::Reference`](crate::program::model::symbol::Reference) the reference manager
    /// hands back, so only the *arity* of the result survives the conversion.
    fn get_value_references(&self) -> Vec<Box<dyn Reference>> {
        struct OpaqueReference;
        impl Reference for OpaqueReference {}
        self.base
            .get_operand_references(DATA_OP_INDEX)
            .into_iter()
            .map(|_| Box::new(OpaqueReference) as Box<dyn Reference>)
            .collect()
    }

    /// Port of `DataDB.addValueReference(Address, RefType)`.
    ///
    /// TODO(port): the ported `Data` trait declares `ref_type` as the empty placeholder trait
    /// [`seam_stubs::RefType`](crate::program::seam_stubs::RefType), which carries no way to
    /// recover the real [`symbol::RefType`](crate::program::model::symbol::RefType) variant that
    /// `ReferenceManager::add_memory_reference` requires, so the reference cannot be created.
    fn add_value_reference(&mut self, ref_addr: Address, ref_type: Box<dyn RefType>) {
        let _ = (ref_addr, ref_type);
    }

    /// Port of `DataDB.removeValueReference(Address)`.
    fn remove_value_reference(&mut self, ref_addr: Address) {
        self.base.remove_operand_reference(DATA_OP_INDEX, &ref_addr);
    }

    /// Port of `DataDB.getFieldName()`.
    fn get_field_name(&self) -> Option<String> {
        None
    }

    /// Port of `DataDB.getPathName()`.
    fn get_path_name(&self) -> String {
        self.path_name()
    }

    /// Port of `DataDB.getComponentPathName()`, which returns `null` for a top-level data item.
    fn get_component_path_name(&self) -> String {
        String::new()
    }

    fn is_pointer(&self) -> bool {
        self.base_data_type_ref().is_pointer()
    }

    fn is_union(&self) -> bool {
        self.base_data_type_ref().is_union()
    }

    fn is_structure(&self) -> bool {
        self.base_data_type_ref().is_structure()
    }

    fn is_array(&self) -> bool {
        self.base_data_type_ref().is_array()
    }

    fn is_dynamic(&self) -> bool {
        self.base_data_type_ref().is_dynamic_type()
    }

    /// Port of `DataDB.getParent()`, which is always `null` for a top-level data item.
    fn get_parent(&self) -> Option<Box<dyn Data>> {
        None
    }

    /// Port of `DataDB.getRoot()`, which is `this`.
    fn get_root(&self) -> Box<dyn Data> {
        self.to_boxed_data()
    }

    /// Port of `DataDB.getRootOffset()`.
    fn get_root_offset(&self) -> i32 {
        0
    }

    /// Port of `DataDB.getParentOffset()`.
    fn get_parent_offset(&self) -> i32 {
        0
    }

    fn get_component(&self, index: i32) -> Option<Box<dyn Data>> {
        let length = self.get_length();
        self.component(index, &self.this(), self, length)
            .map(|component| Box::new(component) as Box<dyn Data>)
    }

    fn get_component_by_path(&self, component_path: &[i32]) -> Option<Box<dyn Data>> {
        let length = self.get_length();
        self.component_by_path(component_path, &self.this(), self, length)
    }

    /// Port of `DataDB.getComponentPath()`, which is `EMPTY_PATH` for a top-level data item.
    fn get_component_path(&self) -> Vec<i32> {
        Vec::new()
    }

    fn get_num_components(&self) -> i32 {
        self.refresh_if_needed();
        let length = self.get_length();
        self.num_components(self, length)
    }

    fn get_component_at(&self, offset: i32) -> Option<Box<dyn Data>> {
        self.get_component_containing(offset)
    }

    fn get_component_containing(&self, offset: i32) -> Option<Box<dyn Data>> {
        self.refresh_if_needed();
        let length = self.get_length();
        self.component_containing(offset, &self.this(), self, length)
            .map(|component| Box::new(component) as Box<dyn Data>)
    }

    fn get_components_containing(&self, offset: i32) -> Option<Vec<Box<dyn Data>>> {
        self.refresh_if_needed();
        let length = self.get_length();
        self.components_containing(offset, &self.this(), self, length)
    }

    fn get_primitive_at(&self, offset: i32) -> Option<Box<dyn Data>> {
        self.refresh_if_needed();
        let length = self.get_length();
        self.primitive_at(offset, &self.this(), self, length)
    }

    /// Port of `DataDB.getComponentIndex()`.
    fn get_component_index(&self) -> i32 {
        -1
    }

    /// Port of `DataDB.getComponentLevel()`.
    fn get_component_level(&self) -> i32 {
        self.level()
    }

    fn get_default_value_representation(&self) -> String {
        self.refresh_if_needed();
        let length = self.get_length();
        self.default_value_representation(self, self, length)
    }

    fn get_default_label_prefix(&self, options: &dyn DataTypeDisplayOptions) -> Option<String> {
        let length = self.get_length();
        self.default_label_prefix(self, self, length, options)
    }
}

// ===========================================================================================
// DbObject / CodeUnitDb / DataDb.
// ===========================================================================================

impl DbObject for DataDB {
    fn state(&self) -> &DbObjectState {
        self.base.state()
    }

    /// Port of `DataDB.refresh(DBRecord)` (which chains into `CodeUnitDB.refresh`).
    fn refresh(&self, record: Option<&DBRecord>) -> bool {
        self.refresh_shared();
        !DataDb::has_been_deleted(self, record)
    }
}

impl CodeUnitDb for DataDB {
    fn has_been_deleted(&self, record: Option<&DBRecord>) -> bool {
        DataDb::has_been_deleted(self, record)
    }

    fn code_unit_string(&self) -> String {
        let length = self.get_length();
        self.data_string(self, self, length)
    }
}

impl DataDb for DataDB {
    /// Port of `DataDB.hasBeenDeleted(DBRecord)`.
    ///
    /// # TODO(port)
    /// The `address.isExternalAddress()` branch -- which recovers the data type from the
    /// address's external location via `program.getExternalManager()` -- is not ported: the
    /// ported [`Program`](crate::program::model::listing::program::Program) trait exposes neither
    /// an external manager nor a symbol table, and [`CodeUnitOwner`] has no callback for one. An
    /// external address therefore falls through to the `codeMgr.getDataType(addr)` lookup, which
    /// reports the code unit deleted if no data type is recorded there.
    fn has_been_deleted(&self, record: Option<&DBRecord>) -> bool {
        let address = self.base.address();
        let addr = self.base.addr();
        let owner = self.base.owner();

        if self.data_type_ref().is_default_data_type() {
            return record.is_some() || !owner.is_undefined(&address, addr);
        }

        let data_type = match record {
            Some(record) => {
                // ensure that record provided corresponds to a DataDB record since following an
                // undo/redo the record could correspond to a different type of code unit
                // (hopefully with a different record schema)
                if !Self::has_data_schema(record) {
                    return true;
                }
                let data_type = owner.get_data_type_for_record(record);
                if data_type.is_none() {
                    owner.db_error(std::io::Error::other(format!(
                        "Data found but datatype missing at {address}"
                    )));
                }
                data_type
            }
            None => owner.get_data_type_at(addr),
        };

        let Some(data_type) = data_type else {
            return true;
        };
        self.set_data_type(Arc::from(data_type));
        self.base.set_length(-1); // set to compute lazily later
        // Java also clears the cached `bytes` here. `CodeUnitDbBase` exposes no selective byte
        // cache invalidator, so the full `refresh_base()` reset is used; its only extra effect is
        // dropping the (re-readable) comment record cache and re-decoding the -- unchanged --
        // address.
        self.base.refresh_base();
        false
    }

    fn to_boxed_data(&self) -> Box<dyn Data> {
        Box::new(self.duplicate())
    }
}

impl std::fmt::Display for DataDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", CodeUnitDb::code_unit_string(self))
    }
}

/// Port of `CodeUnitDB.equals(Object)` as narrowed to `DataDB`: same address index, same owning
/// manager, same concrete type.
impl PartialEq for DataDB {
    fn eq(&self, other: &Self) -> bool {
        self.base.same_code_unit(&other.base)
    }
}

impl Eq for DataDB {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::code::test_support::{TestCodeUnitOwner, TestDataType};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type_display_options::DEFAULT;

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn owner_with(bytes: Vec<u8>) -> Arc<TestCodeUnitOwner> {
        Arc::new(TestCodeUnitOwner::new(space(), 0x1000, bytes))
    }

    #[test]
    fn base_data_type_unwraps_typedef() {
        let typedef: Box<dyn DataType> = Box::new(TestDataType::typedef_of(TestDataType::fixed(
            "int", 4,
        )));
        let base = base_data_type(typedef);
        assert!(!base.is_typedef());
        assert_eq!(base.get_name(), "int");
    }

    #[test]
    fn base_data_type_passes_through_non_typedef() {
        let plain: Box<dyn DataType> = Box::new(TestDataType::fixed("int", 4));
        let base = base_data_type(plain);
        assert!(!base.is_typedef());
        assert_eq!(base.get_name(), "int");
    }

    #[test]
    fn construction_uses_fixed_data_type_length() {
        let owner = owner_with(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        let data_type: Arc<dyn DataType> = Arc::new(TestDataType::fixed("dword", 4));
        let data = DataDB::new(
            owner.clone(),
            0x1000,
            owner.address(0x1000),
            0x1000,
            Some(data_type),
        );

        assert_eq!(data.get_length(), 4);
        assert_eq!(data.get_min_address(), owner.address(0x1000));
        assert_eq!(data.get_max_address(), owner.address(0x1003));
        assert_eq!(data.get_num_operands(), 1);
        assert!(data.is_defined());
        assert_eq!(data.get_component_index(), -1);
        assert_eq!(data.get_component_level(), 0);
        assert!(data.get_component_path().is_empty());
        assert!(data.get_parent().is_none());
        assert_eq!(data.get_parent_offset(), 0);
        assert_eq!(data.get_root_offset(), 0);
        assert_eq!(CodeUnit::get_bytes(&data).unwrap(), vec![0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn missing_data_type_becomes_default_undefined_byte() {
        let owner = owner_with(vec![0x41, 0x42]);
        let data = DataDB::new(owner.clone(), 0x1000, owner.address(0x1000), 0x1000, None);

        assert_eq!(data.get_length(), 1);
        assert!(!data.is_defined());
        assert_eq!(data.get_mnemonic_string(), "??");
        // `DefaultDataType.getRepresentation` renders the byte and, for printable ASCII, the char.
        assert_eq!(data.get_default_value_representation(), "41h    A");
        assert_eq!(data.get_default_label_prefix(&DEFAULT), None);
    }

    #[test]
    fn dynamic_length_type_asks_the_owner_for_its_length() {
        let owner = owner_with(vec![0; 16]);
        owner.set_length_at(0x1000, 6);
        let data_type: Arc<dyn DataType> = Arc::new(TestDataType::dynamic_length("string"));
        let data = DataDB::new(
            owner.clone(),
            0x1000,
            owner.address(0x1000),
            0x1000,
            Some(data_type),
        );

        assert_eq!(data.get_length(), 6);
        assert_eq!(data.get_max_address(), owner.address(0x1005));
    }

    #[test]
    fn refresh_recomputes_length_and_bounds_it_by_the_next_defined_address() {
        let owner = owner_with(vec![0; 16]);
        owner.set_length_at(0x1000, 8);
        let data_type: Arc<dyn DataType> = Arc::new(TestDataType::dynamic_length("string"));
        let data = DataDB::new(
            owner.clone(),
            0x1000,
            owner.address(0x1000),
            0x1000,
            Some(data_type.clone()),
        );
        assert_eq!(data.get_length(), 8);

        // A defined code unit now starts three bytes in, which must clamp the dynamic length.
        owner.set_defined_address_after(Some(owner.address(0x1003)));
        owner.set_data_type_at(0x1000, data_type);
        assert!(data.refresh(None));
        assert_eq!(data.get_length(), 3);
    }

    #[test]
    fn has_been_deleted_for_default_data_follows_is_undefined() {
        let owner = owner_with(vec![0x00; 4]);
        let data = DataDB::new(owner.clone(), 0x1000, owner.address(0x1000), 0x1000, None);

        owner.set_undefined(0x1000, true);
        assert!(!DataDb::has_been_deleted(&data, None));

        owner.set_undefined(0x1000, false);
        assert!(DataDb::has_been_deleted(&data, None));
    }

    #[test]
    fn has_been_deleted_when_the_data_type_is_gone() {
        let owner = owner_with(vec![0x00; 4]);
        let data_type: Arc<dyn DataType> = Arc::new(TestDataType::fixed("dword", 4));
        let data = DataDB::new(
            owner.clone(),
            0x1000,
            owner.address(0x1000),
            0x1000,
            Some(data_type),
        );

        // Nothing recorded at this address any more.
        assert!(DataDb::has_been_deleted(&data, None));
        assert!(!data.refresh(None));
    }

    #[test]
    fn has_been_deleted_adopts_the_data_type_recorded_at_the_address() {
        let owner = owner_with(vec![0x00; 8]);
        let original: Arc<dyn DataType> = Arc::new(TestDataType::fixed("word", 2));
        let data = DataDB::new(
            owner.clone(),
            0x1000,
            owner.address(0x1000),
            0x1000,
            Some(original),
        );
        assert_eq!(data.get_length(), 2);

        owner.set_data_type_at(0x1000, Arc::new(TestDataType::fixed("qword", 8)));
        assert!(!DataDb::has_been_deleted(&data, None));
        assert_eq!(data.get_data_type().get_name(), "qword");
        assert_eq!(data.get_length(), 8);
    }

    #[test]
    fn typedef_data_type_reports_its_base_type() {
        let owner = owner_with(vec![0x00; 8]);
        let typedef: Arc<dyn DataType> =
            Arc::new(TestDataType::typedef_of(TestDataType::array("int", 4, 2)));
        let data = DataDB::new(
            owner.clone(),
            0x1000,
            owner.address(0x1000),
            0x1000,
            Some(typedef),
        );

        assert!(data.get_data_type().is_typedef());
        assert!(!data.get_base_data_type().is_typedef());
        assert!(data.is_array());
        assert_eq!(data.get_num_components(), 2);
    }

    #[test]
    fn array_components_are_reachable_by_index_offset_and_path() {
        let owner = owner_with(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let array: Arc<dyn DataType> = Arc::new(TestDataType::array("byte", 1, 4));
        let data = DataDB::new(
            owner.clone(),
            0x1000,
            owner.address(0x1000),
            0x1000,
            Some(array),
        );

        assert_eq!(data.get_length(), 4);
        assert_eq!(data.get_num_components(), 4);

        let second = data.get_component(1).expect("component 1");
        assert_eq!(second.get_component_index(), 1);
        assert_eq!(second.get_parent_offset(), 1);
        assert_eq!(second.get_min_address(), owner.address(0x1001));
        assert_eq!(second.get_field_name().as_deref(), Some("[1]"));

        assert!(data.get_component(-1).is_none());
        assert!(data.get_component(4).is_none());

        let containing = data.get_component_containing(2).expect("component at 2");
        assert_eq!(containing.get_component_index(), 2);

        #[allow(deprecated)]
        let at = data.get_component_at(3).expect("component at 3");
        assert_eq!(at.get_component_index(), 3);

        let by_path = data.get_component_by_path(&[2]).expect("path [2]");
        assert_eq!(by_path.get_component_index(), 2);

        let primitive = data.get_primitive_at(3).expect("primitive at 3");
        assert_eq!(primitive.get_component_index(), 3);

        let all = data.get_components_containing(1).expect("components at 1");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].get_component_index(), 1);
    }

    #[test]
    fn structure_components_are_reachable_by_offset() {
        let owner = owner_with(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let structure: Arc<dyn DataType> = Arc::new(TestDataType::structure(
            "S",
            vec![("a", 1, 0), ("b", 2, 1), ("c", 1, 3)],
        ));
        let data = DataDB::new(
            owner.clone(),
            0x1000,
            owner.address(0x1000),
            0x1000,
            Some(structure),
        );

        assert!(data.is_structure());
        assert_eq!(data.get_num_components(), 3);

        let b = data.get_component_containing(2).expect("component at 2");
        assert_eq!(b.get_component_index(), 1);
        assert_eq!(b.get_field_name().as_deref(), Some("b"));
        assert_eq!(b.get_parent_offset(), 1);
        assert_eq!(b.get_length(), 2);
        assert_eq!(b.get_root_offset(), 1);

        let c = data.get_component_containing(3).expect("component at 3");
        assert_eq!(c.get_component_index(), 2);
        assert_eq!(c.get_component_path(), vec![2]);
        assert_eq!(c.get_component_path_name(), "c");
    }

    #[test]
    fn usable_as_trait_object() {
        let owner = owner_with(vec![0x00; 4]);
        let data = DataDB::new(owner.clone(), 0x1000, owner.address(0x1000), 0x1000, None);
        owner.set_undefined(0x1000, true);

        let dyn_data: &dyn DataDb = &data;
        assert!(!dyn_data.has_been_deleted(None));
        assert!(!Data::is_defined(dyn_data));
        let boxed = dyn_data.to_boxed_data();
        assert_eq!(boxed.get_min_address(), owner.address(0x1000));
    }

    #[test]
    fn equality_is_by_address_index_and_owner() {
        let owner = owner_with(vec![0x00; 8]);
        let make = |addr: i64| {
            DataDB::new(
                owner.clone(),
                addr,
                owner.address(addr),
                addr,
                Some(Arc::new(TestDataType::fixed("byte", 1)) as Arc<dyn DataType>),
            )
        };
        assert!(make(0x1000) == make(0x1000));
        assert!(make(0x1000) != make(0x1001));
    }
}
