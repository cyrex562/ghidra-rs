//! Port of `ghidra.program.model.data.TypedefDataType`.
//!
//! The Java class `extends GenericDataType implements TypeDef` and stores a single `dataType`
//! field (the referenced type being aliased) plus a lazily-cached settings/definitions pair and
//! an `isAutoNamed` flag. Both supertraits ([`GenericDataType`] and [`TypeDef`]) are already
//! ported in this crate as thin cut-point traits with no field storage of their own, so this is
//! the first concrete, field-owning struct built on top of that stack.
//!
//! ## Storage strategy for the wrapped `DataType`
//!
//! The Java field `dataType` is a plain object reference, handed back unchanged by
//! `getDataType()` and read repeatedly elsewhere (`getBaseDataType()`, `isEquivalent()`, ...).
//! [`TypeDef::get_data_type`] must return an *owned* `Box<dyn DataType>` from a `&self` method,
//! and `dyn DataType` has no `Clone` bound, so a literal field of type `Box<dyn DataType>` cannot
//! be handed back out more than once. This port instead stores `data_type: Arc<dyn DataType>`
//! and hands back fresh handles via
//! [`share_data_type`](crate::program::seam_stubs::share_data_type), the established crate-wide
//! answer to exactly this problem (see [`SharedDataType`](crate::program::seam_stubs) and its use
//! in `function_definition_data_type.rs`'s `BasicParameterDefinition`). Note that the returned
//! handle only forwards a handful of [`DataType`] methods (`get_name`, `get_length`,
//! `is_void_type`, `is_equivalent`, `clone_data_type`); callers needing full fidelity on the
//! wrapped type (e.g. `is_pointer`/`as_typedef`) should go through this struct's own inherent
//! [`TypedefDataType::referenced_data_type`] instead, which exposes the real stored value.
//!
//! ## Dropped defensive clone
//!
//! Every Java constructor defensively copies its `dt` argument via `dt.clone(dtm)` before storing
//! it, and calls `dt.addParent(this)`. This port stores the caller-supplied `Box<dyn DataType>`
//! directly instead of calling [`DataType::clone_data_type`] on it: that method's crate-wide
//! default returns a placeholder `EmptyDataType` for any type that hasn't grown a real override,
//! which would silently corrupt the common case (most already-ported leaf datatypes are
//! cut-point traits with no real `clone_data_type` override yet). Callers that need the Java
//! clone-on-construct behavior can call `.clone_data_type(dtm)` themselves before constructing.
//! `addParent`/`removeParent` wiring is dropped for the same reason [`DataTypeImpl`]'s own module
//! docs give for not porting the `notify*` family: [`DataType::add_parent`] takes only a borrowed
//! `&dyn DataType`, giving no way to build the `Weak` back-reference
//! [`DataTypeImpl::data_type_impl_add_parent`] needs.
//!
//! ## Settings storage
//!
//! Java's `getDefaultSettings()`/`isAllowedSetting` machinery is backed by a real, shared
//! `SettingsImpl` object that every caller mutates in place. Since
//! [`DataType::get_default_settings`] is `&self -> Box<dyn Settings>` (an owned, detached value),
//! a naive per-call snapshot (a plain `HashMap` field, cloned into each returned `Box`) would
//! leave every mutation through the returned object disconnected from `self` -- the same "fresh
//! value each call" limitation documented elsewhere in this crate (see `DataTypeUtilities`'s
//! module docs). This port instead stores the setting values behind `Arc<Mutex<...>>`
//! ([`TypedefDataType`]'s `settings` field) and hands out a [`TypedefSettingsSnapshot`] that
//! clones the `Arc` (cheap, shares the same lock) rather than the map itself, so writes through
//! the returned `Settings` object *do* persist back into `self` -- matching Java's shared-reference
//! semantics far more closely than a disconnected snapshot would. `Mutex` (rather than `RefCell`)
//! is required here since [`DataType`] itself is declared `Send + Sync`. This is what lets
//! `PointerTypedef` (composing over this struct) implement its `PointerTypeSettingsDefinition`/
//! `ComponentOffsetSettingsDefinition`/`AddressSpaceSettingsDefinition`-setting constructors by
//! calling `.set_long()`/`.set_string()` directly on `get_default_settings()`'s return value, the
//! same way the Java constructors do.
//!
//! Code that holds a concrete `&mut TypedefDataType` can still bypass the `Settings` indirection
//! entirely via [`TypedefDataType::set_type_def_setting_long`]/
//! [`TypedefDataType::set_type_def_setting_string`], which are equivalent but avoid the lock/trait
//! object overhead.
//!
//! ## Other dropped/simplified pieces
//!
//! - `sourceArchive` is tracked only as its [`UniversalID`] ([`TypedefDataType::source_archive_id`]);
//!   [`DataTypeImpl::stored_source_archive`] always returns `None` since `dyn SourceArchive` can't
//!   be reconstructed as an owned value from just an ID without a registry this crate doesn't
//!   have yet. This narrows [`DataTypeUtilities::is_same_data_type`] to always report `false` for
//!   two `TypedefDataType`s, even when they do share a source archive.
//! - [`DataType::data_type_replaced`]'s signature (`&mut self, old_dt: &dyn DataType, new_dt: &dyn
//!   DataType`) hands the replacement in by borrowed reference, so this port can validate the
//!   replacement (via [`DataTypeUtilities::check_valid_replacement`]) but cannot actually swap the
//!   stored field from it -- the same ownership-from-a-borrow problem documented throughout this
//!   port. [`TypedefDataType::replace_data_type`] is the real, owned-parameter equivalent for
//!   composing callers.
//! - Reference-identity checks (`obj == this`, `oldDt == dataType`, `myDt == dt` in
//!   `isEquivalent`/`dependsOn`) are approximated with [`DataType::is_equivalent`] (checked both
//!   directions), matching the established substitution documented in `DataTypeUtilities`'s
//!   module docs.
//! - The parent/child `notify*` broadcast family (`notifySizeChanged`, `notifyNameChanged`, ...)
//!   is not ported, for the same soundness reason given in [`DataTypeImpl`]'s module docs.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::database::data::data_type_utilities::DataTypeUtilities;
use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::data_type::{
    DataType, SetDataTypeNameError, TYPEDEF_ATTRIBUTE_PREFIX, TYPEDEF_ATTRIBUTE_SUFFIX,
};
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::model::data::data_type_impl::DataTypeImpl;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_utilities::DataUtilities;
use crate::program::model::data::generic_data_type::GenericDataType;
use crate::program::model::data::source_archive::SourceArchive;
use crate::program::model::data::typedef::TypeDef;
use crate::program::model::data::typedef_settings_definition::TypeDefSettingsDefinition;
use crate::program::model::mem::MemBuffer;
use crate::program::seam_stubs::share_data_type;
use crate::util::exception::{DuplicateNameException, InvalidNameException};
use crate::util::UniversalID;

/// Zero-sized marker used purely to call the defaulted trait methods of
/// [`DataTypeUtilities`]/[`DataUtilities`] (both are designed as `&dyn Trait`-object seams --
/// see their own module docs -- rather than free-function modules).
#[derive(Debug, Default, Clone, Copy)]
struct Utils;
impl DataTypeUtilities for Utils {}
impl DataUtilities for Utils {}

/// Basic implementation for the typedef dataType.
///
/// Port of `ghidra.program.model.data.TypedefDataType`. See the module-level documentation for
/// what was dropped, simplified, or exposed under a different (inherent, non-trait) name.
pub struct TypedefDataType {
    category_path: CategoryPath,
    name: String,
    data_type: Arc<dyn DataType>,
    is_auto_named: bool,
    deleted: bool,
    universal_id: UniversalID,
    source_archive_id: Option<UniversalID>,
    last_change_time: i64,
    last_change_time_in_source_archive: i64,
    parents: Vec<Weak<dyn DataType>>,
    settings: Arc<Mutex<TypedefSettingsStore>>,
}

/// Shared, lockable backing store for a [`TypedefDataType`]'s type-def settings. See the module
/// docs for why this is behind `Arc<Mutex<...>>` rather than plain fields.
#[derive(Default, Clone)]
struct TypedefSettingsStore {
    longs: HashMap<String, i64>,
    strings: HashMap<String, String>,
}

impl TypedefDataType {
    /// Construct a new typedef within the root category.
    ///
    /// Port of the 2-arg Java constructor `TypedefDataType(String, DataType)`.
    ///
    /// # Errors
    /// Returns `Err` if `data_type` may not be used as a typedef base (void, default-undefined,
    /// bitfield, factory, or dynamic), mirroring the `IllegalArgumentException` thrown by the
    /// Java constructor's private `validate` helper.
    pub fn new_in_root(name: impl Into<String>, data_type: Box<dyn DataType>) -> Result<Self, String> {
        Self::new(ROOT.clone(), name, data_type)
    }

    /// Construct a new typedef.
    ///
    /// Port of the 3-arg Java constructor `TypedefDataType(CategoryPath, String, DataType)` (the
    /// 4-arg overload additionally taking a `DataTypeManager` collapses into this one, since --
    /// per the module docs -- the `dtm` parameter's only effect in Java is on the dropped
    /// defensive clone).
    ///
    /// # Errors
    /// See [`TypedefDataType::new_in_root`].
    pub fn new(
        category_path: CategoryPath,
        name: impl Into<String>,
        data_type: Box<dyn DataType>,
    ) -> Result<Self, String> {
        Utils.check_valid_replacement_data_type(data_type.as_ref())?;
        Ok(Self::new_unchecked(
            category_path,
            name.into(),
            Arc::from(data_type),
            UniversalID::new(0),
            None,
            0,
            0,
        ))
    }

    /// Construct a new typedef with an explicit archive identity.
    ///
    /// Port of the 7-arg Java constructor taking `universalID`/`sourceArchive`/`lastChangeTime`/
    /// `lastChangeTimeInSourceArchive`. `source_archive` is tracked only by ID -- see the module
    /// docs.
    ///
    /// # Errors
    /// See [`TypedefDataType::new_in_root`].
    #[allow(clippy::too_many_arguments)]
    pub fn with_archive_identity(
        category_path: CategoryPath,
        name: impl Into<String>,
        data_type: Box<dyn DataType>,
        universal_id: UniversalID,
        source_archive: Option<&dyn SourceArchive>,
        last_change_time: i64,
        last_change_time_in_source_archive: i64,
    ) -> Result<Self, String> {
        Utils.check_valid_replacement_data_type(data_type.as_ref())?;
        Ok(Self::new_unchecked(
            category_path,
            name.into(),
            Arc::from(data_type),
            universal_id,
            source_archive.map(|a| a.source_archive_id()),
            last_change_time,
            last_change_time_in_source_archive,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn new_unchecked(
        category_path: CategoryPath,
        name: String,
        data_type: Arc<dyn DataType>,
        universal_id: UniversalID,
        source_archive_id: Option<UniversalID>,
        last_change_time: i64,
        last_change_time_in_source_archive: i64,
    ) -> Self {
        TypedefDataType {
            category_path,
            name,
            data_type,
            is_auto_named: false,
            deleted: false,
            universal_id,
            source_archive_id,
            last_change_time,
            last_change_time_in_source_archive,
            parents: Vec::new(),
            settings: Arc::new(Mutex::new(TypedefSettingsStore::default())),
        }
    }

    /// The real, fully-faithful wrapped data type (as opposed to [`TypeDef::get_data_type`]'s
    /// partially-forwarding [`share_data_type`] handle -- see the module docs).
    pub fn referenced_data_type(&self) -> &dyn DataType {
        self.data_type.as_ref()
    }

    /// The tracked source archive ID, if any. See the module docs for why the full
    /// `SourceArchive` is not reconstructable here.
    pub fn source_archive_id(&self) -> Option<UniversalID> {
        self.source_archive_id
    }

    /// Directly persist a type-def setting long value. Equivalent to (but cheaper than) calling
    /// `.set_long()` on the `Box<dyn Settings>` returned by `get_default_settings()` -- both
    /// routes share the same underlying store. See the module docs.
    pub fn set_type_def_setting_long(&mut self, name: impl Into<String>, value: i64) {
        let mut store = self.settings.lock().expect("typedef settings mutex poisoned");
        store.longs.insert(name.into(), value);
    }

    /// Directly persist a type-def setting string value. See
    /// [`set_type_def_setting_long`](Self::set_type_def_setting_long).
    pub fn set_type_def_setting_string(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let mut store = self.settings.lock().expect("typedef settings mutex poisoned");
        store.strings.insert(name.into(), value.into());
    }

    /// Directly clear a type-def setting. See
    /// [`set_type_def_setting_long`](Self::set_type_def_setting_long).
    pub fn clear_type_def_setting(&mut self, name: &str) {
        let mut store = self.settings.lock().expect("typedef settings mutex poisoned");
        store.longs.remove(name);
        store.strings.remove(name);
    }

    /// Owned-parameter equivalent of [`DataType::data_type_replaced`], able to actually swap the
    /// stored referenced type (the trait method cannot -- see the module docs).
    ///
    /// # Errors
    /// Returns `Err` if `new_dt` is not a valid replacement for the currently-referenced type,
    /// mirroring `DataTypeUtilities.checkValidReplacement`.
    pub fn replace_data_type(&mut self, new_dt: Box<dyn DataType>) -> Result<(), String> {
        Utils.check_valid_replacement(self.data_type.as_ref(), new_dt.as_ref())?;
        self.data_type = Arc::from(new_dt);
        Ok(())
    }

    /// Port of the static `TypedefDataType.generateTypedefName(TypeDef)`.
    pub fn generate_typedef_name(model_type: &dyn TypeDef) -> String {
        let settings = model_type.get_default_settings();
        let mut attributes = String::new();
        for def in model_type.get_type_def_settings_definitions() {
            if let Some(attribute) = def.get_attribute_specification(settings.as_ref()) {
                if !attributes.is_empty() {
                    attributes.push(',');
                }
                attributes.push_str(&attribute);
            }
        }
        format!(
            "{} {TYPEDEF_ATTRIBUTE_PREFIX}{attributes}{TYPEDEF_ATTRIBUTE_SUFFIX}",
            model_type.get_data_type().get_name()
        )
    }

    /// Port of the static `TypedefDataType.copyTypeDefSettings(TypeDef, TypeDef, boolean)`,
    /// specialized to two concrete [`TypedefDataType`]s (see the module docs for why the
    /// Settings-trait-object route can't round-trip a real copy).
    pub fn copy_type_def_settings_from(&mut self, src: &TypedefDataType, clear_before_copy: bool) {
        let src_store = src.settings.lock().expect("typedef settings mutex poisoned").clone();
        let mut dest_store = self.settings.lock().expect("typedef settings mutex poisoned");
        if clear_before_copy {
            dest_store.longs.clear();
            dest_store.strings.clear();
        }
        if src_store.longs.is_empty() && src_store.strings.is_empty() {
            return;
        }
        drop(dest_store);
        for def in self.get_type_def_settings_definitions() {
            let key = def.get_storage_key();
            let mut dest_store = self.settings.lock().expect("typedef settings mutex poisoned");
            if let Some(v) = src_store.longs.get(&key) {
                dest_store.longs.insert(key.clone(), *v);
            }
            if let Some(v) = src_store.strings.get(&key) {
                dest_store.strings.insert(key, v.clone());
            }
        }
    }

    /// Port of the static `TypedefDataType.clone(TypeDef, DataTypeManager)`, specialized to a
    /// concrete [`TypedefDataType`] source (`dtm` is accepted for signature parity but unused --
    /// see the module docs on the dropped defensive clone).
    pub fn clone_typedef(&self, _dtm: &dyn DataTypeManager) -> TypedefDataType {
        let mut cloned = TypedefDataType::new_unchecked(
            self.category_path.clone(),
            self.name.clone(),
            self.data_type.clone(),
            self.universal_id,
            self.source_archive_id,
            self.last_change_time,
            self.last_change_time_in_source_archive,
        );
        cloned.is_auto_named = self.is_auto_named;
        cloned.copy_type_def_settings_from(self, false);
        cloned
    }

    /// Port of the static `TypedefDataType.copy(TypeDef, DataTypeManager)`: a fresh identity
    /// (new universal ID left at the zero sentinel, no source archive), preserving only the
    /// name/category/referenced-type/auto-naming/settings.
    pub fn copy_typedef(&self, _dtm: &dyn DataTypeManager) -> TypedefDataType {
        let mut copied = TypedefDataType::new_unchecked(
            self.category_path.clone(),
            self.name.clone(),
            self.data_type.clone(),
            UniversalID::new(0),
            None,
            0,
            0,
        );
        copied.is_auto_named = self.is_auto_named;
        copied.copy_type_def_settings_from(self, false);
        copied
    }
}

impl DataType for TypedefDataType {
    fn get_name(&self) -> String {
        if self.is_auto_named() {
            return TypedefDataType::generate_typedef_name(self);
        }
        self.name.clone()
    }

    fn set_name(&mut self, name: &str) -> Result<(), SetDataTypeNameError> {
        if self.generic_check_name_change(name, &Utils)? {
            self.name = name.to_string();
        }
        self.is_auto_named = false;
        Ok(())
    }

    fn get_category_path(&self) -> CategoryPath {
        if self.is_auto_named() {
            return self.data_type.get_category_path();
        }
        self.category_path.clone()
    }

    fn set_category_path(&mut self, path: CategoryPath) -> Result<(), DuplicateNameException> {
        if self.is_auto_named() {
            return Ok(()); // ignore category change if auto-naming enabled
        }
        self.category_path = self.generic_normalize_category_path(Some(path));
        Ok(())
    }

    /// Preserved Java quirk: this always returns the raw stored name field, bypassing the
    /// auto-naming logic that [`DataType::get_name`] applies.
    fn get_mnemonic(&self, _settings: &dyn Settings) -> String {
        self.name.clone()
    }

    fn get_description(&self) -> String {
        self.data_type.get_description()
    }

    fn is_zero_length(&self) -> bool {
        self.data_type.is_zero_length()
    }

    fn get_length(&self) -> i32 {
        self.data_type.get_length()
    }

    fn get_aligned_length(&self) -> i32 {
        self.data_type.get_aligned_length()
    }

    fn has_language_dependant_length(&self) -> bool {
        self.data_type.has_language_dependant_length()
    }

    fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        self.data_type.get_representation(buf, settings, length)
    }

    fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
        self.data_type.get_value(buf, settings, length)
    }

    fn get_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        self.data_type.get_value_class(settings)
    }

    fn get_default_label_prefix(&self) -> Option<String> {
        if self.is_auto_named() {
            return self.data_type.get_default_label_prefix();
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
            return self.data_type.get_default_label_prefix_for_data(buf, settings, len, options);
        }
        self.get_default_label_prefix()
    }

    fn get_default_abbreviated_label_prefix(&self) -> Option<String> {
        if self.is_auto_named() {
            return self.data_type.get_default_abbreviated_label_prefix();
        }
        None
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
            return self.data_type.get_default_offcut_label_prefix(
                buf,
                settings,
                len,
                options,
                offcut_offset,
            );
        }
        self.get_default_label_prefix_for_data(buf, settings, len, options)
    }

    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        let Some(other_td) = dt.as_typedef() else {
            return false;
        };
        if self.is_auto_named != other_td.is_auto_named() {
            return false;
        }
        if !self.is_auto_named
            && !Utils.equals_ignore_conflict(&DataType::get_name(self), &other_td.get_name())
        {
            return false;
        }
        if !self.has_same_type_def_settings(other_td) {
            return false;
        }
        let other_data_type = other_td.get_data_type();
        if Utils.is_same_data_type(self.data_type.as_ref(), other_data_type.as_ref()) {
            return true;
        }
        self.data_type.is_equivalent(other_data_type.as_ref())
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

    fn is_deleted(&self) -> bool {
        self.deleted
    }

    fn data_type_deleted(&mut self, dt: &dyn DataType) {
        if self.data_type.is_equivalent(dt) {
            self.deleted = true;
        }
    }

    /// See the module docs: this validates the replacement but cannot actually swap the stored
    /// field (the trait signature hands `new_dt` in by borrowed reference). Composing callers
    /// with a concrete `&mut TypedefDataType` should call
    /// [`TypedefDataType::replace_data_type`] instead.
    fn data_type_replaced(&mut self, old_dt: &dyn DataType, new_dt: &dyn DataType) {
        if self.data_type.is_equivalent(old_dt) {
            let _ = Utils.check_valid_replacement(self.data_type.as_ref(), new_dt);
        }
    }

    fn depends_on(&self, dt: &dyn DataType) -> bool {
        self.data_type.is_equivalent(dt) || self.data_type.depends_on(dt)
    }

    fn get_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        let mut combined: Vec<Box<dyn SettingsDefinition>> = self.data_type.get_settings_definitions();
        for def in self.data_type.get_type_def_settings_definitions() {
            combined.push(def);
        }
        combined
    }

    fn get_type_def_settings_definitions(&self) -> Vec<Box<dyn TypeDefSettingsDefinition>> {
        self.data_type.get_type_def_settings_definitions()
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        Box::new(TypedefSettingsSnapshot {
            store: Arc::clone(&self.settings),
            immutable: self.get_type_def_settings_definitions().is_empty(),
            allowed_keys: self
                .get_type_def_settings_definitions()
                .iter()
                .map(|d| d.get_storage_key())
                .collect(),
            fallback: self.data_type.get_default_settings(),
        })
    }
}

impl DataTypeImpl for TypedefDataType {
    fn stored_default_settings(&self) -> Box<dyn Settings> {
        DataType::get_default_settings(self)
    }

    fn set_stored_default_settings(&mut self, settings: Box<dyn Settings>) {
        let mut store = self.settings.lock().expect("typedef settings mutex poisoned");
        for name in settings.get_names() {
            if let Some(v) = settings.get_long(&name) {
                store.longs.insert(name, v);
            } else if let Some(v) = settings.get_string(&name) {
                store.strings.insert(name, v);
            }
        }
    }

    fn stored_source_archive(&self) -> Option<Box<dyn SourceArchive>> {
        None
    }

    fn set_stored_source_archive(&mut self, archive: Option<Box<dyn SourceArchive>>) {
        self.source_archive_id = archive.map(|a| a.source_archive_id());
    }

    fn stored_universal_id(&self) -> UniversalID {
        self.universal_id
    }

    fn stored_last_change_time(&self) -> i64 {
        self.last_change_time
    }

    fn set_stored_last_change_time(&mut self, last_change_time: i64) {
        self.last_change_time = last_change_time;
    }

    fn stored_last_change_time_in_source_archive(&self) -> i64 {
        self.last_change_time_in_source_archive
    }

    fn set_stored_last_change_time_in_source_archive(&mut self, last_change_time: i64) {
        self.last_change_time_in_source_archive = last_change_time;
    }

    fn stored_parent_refs(&self) -> Vec<Weak<dyn DataType>> {
        self.parents.clone()
    }

    fn set_stored_parent_refs(&mut self, parents: Vec<Weak<dyn DataType>>) {
        self.parents = parents;
    }
}

impl GenericDataType for TypedefDataType {}

impl TypeDef for TypedefDataType {
    fn is_auto_named(&self) -> bool {
        self.is_auto_named
    }

    fn enable_auto_naming(&mut self) {
        self.is_auto_named = true;
    }

    fn get_data_type(&self) -> Box<dyn DataType> {
        share_data_type(&self.data_type)
    }

    fn get_base_data_type(&self) -> Box<dyn DataType> {
        if let Some(inner_td) = self.data_type.as_typedef() {
            inner_td.get_base_data_type()
        } else {
            share_data_type(&self.data_type)
        }
    }
}

impl std::fmt::Display for TypedefDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_auto_named() {
            write!(f, "{}", self.get_name())
        } else {
            write!(f, "typedef {} {}", self.get_name(), self.data_type.get_name())
        }
    }
}

/// [`Settings`] handle returned by [`TypedefDataType`]'s `get_default_settings`. Shares the same
/// underlying `Arc<Mutex<TypedefSettingsStore>>` as the owning [`TypedefDataType`] (rather than a
/// disconnected clone of its contents), so writes through this object persist back -- see the
/// module docs.
struct TypedefSettingsSnapshot {
    store: Arc<Mutex<TypedefSettingsStore>>,
    immutable: bool,
    allowed_keys: Vec<String>,
    fallback: Box<dyn Settings>,
}

impl Settings for TypedefSettingsSnapshot {
    fn is_immutable_settings(&self) -> bool {
        self.immutable
    }

    fn is_change_allowed(&self, settings_definition: &dyn SettingsDefinition) -> bool {
        if self.immutable {
            return false;
        }
        self.allowed_keys.iter().any(|k| k == &settings_definition.get_storage_key())
    }

    fn get_long(&self, name: &str) -> Option<i64> {
        let store = self.store.lock().expect("typedef settings mutex poisoned");
        store.longs.get(name).copied().or_else(|| self.fallback.get_long(name))
    }

    fn get_string(&self, name: &str) -> Option<String> {
        let store = self.store.lock().expect("typedef settings mutex poisoned");
        store.strings.get(name).cloned().or_else(|| self.fallback.get_string(name))
    }

    fn set_long(&mut self, name: &str, value: i64) {
        if !self.immutable && self.allowed_keys.iter().any(|k| k == name) {
            let mut store = self.store.lock().expect("typedef settings mutex poisoned");
            store.longs.insert(name.to_string(), value);
        }
    }

    fn set_string(&mut self, name: &str, value: &str) {
        if !self.immutable && self.allowed_keys.iter().any(|k| k == name) {
            let mut store = self.store.lock().expect("typedef settings mutex poisoned");
            store.strings.insert(name.to_string(), value.to_string());
        }
    }

    fn clear_setting(&mut self, name: &str) {
        let mut store = self.store.lock().expect("typedef settings mutex poisoned");
        store.longs.remove(name);
        store.strings.remove(name);
    }

    fn clear_all_settings(&mut self) {
        let mut store = self.store.lock().expect("typedef settings mutex poisoned");
        store.longs.clear();
        store.strings.clear();
    }

    fn get_names(&self) -> Vec<String> {
        let store = self.store.lock().expect("typedef settings mutex poisoned");
        let mut names: Vec<String> = store.longs.keys().cloned().collect();
        names.extend(store.strings.keys().cloned());
        names
    }

    fn is_empty(&self) -> bool {
        let store = self.store.lock().expect("typedef settings mutex poisoned");
        store.longs.is_empty() && store.strings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.get_name() == dt.get_name() && self.get_length() == dt.get_length()
        }
    }

    struct MockDtm;
    impl DataTypeManager for MockDtm {}

    fn leaf(name: &str, length: i32) -> Box<dyn DataType> {
        Box::new(MockLeaf { name: name.to_string(), length })
    }

    #[test]
    fn new_wraps_referenced_type() {
        let td = TypedefDataType::new_in_root("MyByte", leaf("byte", 1)).unwrap();
        assert_eq!(DataType::get_name(&td), "MyByte");
        assert_eq!(td.get_length(), 1);
        assert_eq!(td.referenced_data_type().get_name(), "byte");
    }

    #[test]
    fn rejects_void_like_replacement() {
        struct VoidLike;
        impl DataType for VoidLike {
            fn is_void_type(&self) -> bool {
                true
            }
        }
        let err = match TypedefDataType::new_in_root("Bad", Box::new(VoidLike)) {
            Err(e) => e,
            Ok(_) => panic!("expected void-like replacement to be rejected"),
        };
        assert!(err.contains("void"));
    }

    #[test]
    fn get_data_type_returns_independent_handle() {
        let td = TypedefDataType::new_in_root("MyByte", leaf("byte", 1)).unwrap();
        let handle = TypeDef::get_data_type(&td);
        assert_eq!(handle.get_name(), "byte");
        assert_eq!(handle.get_length(), 1);
    }

    #[test]
    fn get_base_data_type_follows_nested_typedef_chain() {
        let inner = TypedefDataType::new_in_root("Inner", leaf("int", 4)).unwrap();
        let outer = TypedefDataType::new_in_root("Outer", Box::new(inner)).unwrap();
        assert_eq!(TypeDef::get_base_data_type(&outer).get_name(), "int");
    }

    #[test]
    fn auto_naming_generates_name_from_referenced_type() {
        let mut td = TypedefDataType::new_in_root("Ignored", leaf("int", 4)).unwrap();
        assert!(!td.is_auto_named());
        td.enable_auto_naming();
        assert!(td.is_auto_named());
        assert_eq!(DataType::get_name(&td), "int __(())");
    }

    #[test]
    fn set_name_disables_auto_naming() {
        let mut td = TypedefDataType::new_in_root("Ignored", leaf("int", 4)).unwrap();
        td.enable_auto_naming();
        DataType::set_name(&mut td, "MyInt").unwrap();
        assert!(!td.is_auto_named());
        assert_eq!(DataType::get_name(&td), "MyInt");
    }

    #[test]
    fn mnemonic_bypasses_auto_naming() {
        struct NoSettings;
        impl Settings for NoSettings {}
        let mut td = TypedefDataType::new_in_root("Raw", leaf("int", 4)).unwrap();
        td.enable_auto_naming();
        // get_name() would now report the generated name, but get_mnemonic preserves the raw
        // stored field, matching the documented Java quirk.
        assert_eq!(td.get_mnemonic(&NoSettings), "Raw");
    }

    #[test]
    fn is_equivalent_compares_names_and_referenced_types() {
        let a = TypedefDataType::new_in_root("Foo", leaf("int", 4)).unwrap();
        let b = TypedefDataType::new_in_root("Foo", leaf("int", 4)).unwrap();
        let c = TypedefDataType::new_in_root("Foo.conflict1", leaf("int", 4)).unwrap();
        let d = TypedefDataType::new_in_root("Bar", leaf("int", 4)).unwrap();
        assert!(DataType::is_equivalent(&a, &b));
        assert!(DataType::is_equivalent(&a, &c)); // conflict suffix ignored
        assert!(!DataType::is_equivalent(&a, &d));
    }

    #[test]
    fn get_default_settings_reflects_direct_setting_writes() {
        let mut td = TypedefDataType::new_in_root("Foo", leaf("int", 4)).unwrap();
        td.set_type_def_setting_long("k", 7);
        let settings = DataType::get_default_settings(&td);
        assert_eq!(settings.get_long("k"), Some(7));
    }

    struct MockTypeDefSettingsDef;
    impl SettingsDefinition for MockTypeDefSettingsDef {
        fn get_storage_key(&self) -> String {
            "my_key".to_string()
        }
    }
    impl TypeDefSettingsDefinition for MockTypeDefSettingsDef {
        fn get_attribute_specification(&self, _settings: &dyn Settings) -> Option<String> {
            None
        }
    }

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
    }

    #[test]
    fn writes_through_default_settings_handle_persist_back() {
        let td = TypedefDataType::new_in_root(
            "Foo",
            Box::new(MockLeafWithTypeDefSettings { name: "widget".to_string() }),
        )
        .unwrap();

        // Two independent calls to get_default_settings() should share the same backing store
        // (mirroring Java's shared SettingsImpl reference), not each be a disconnected snapshot.
        let mut first = DataType::get_default_settings(&td);
        first.set_long("my_key", 99);
        let second = DataType::get_default_settings(&td);
        assert_eq!(second.get_long("my_key"), Some(99));
    }

    #[test]
    fn clone_typedef_preserves_identity_and_settings() {
        let mut original = TypedefDataType::new_in_root("Foo", leaf("int", 4)).unwrap();
        original.set_type_def_setting_long("k", 42);
        let dtm = MockDtm;
        let cloned = original.clone_typedef(&dtm);
        assert_eq!(DataType::get_name(&cloned), "Foo");
        assert_eq!(cloned.source_archive_id(), original.source_archive_id());
    }

    #[test]
    fn copy_typedef_gets_fresh_identity() {
        let original = TypedefDataType::with_archive_identity(
            ROOT.clone(),
            "Foo",
            leaf("int", 4),
            UniversalID::new(99),
            None,
            0,
            0,
        )
        .unwrap();
        let dtm = MockDtm;
        let copied = original.copy_typedef(&dtm);
        assert_ne!(copied.stored_universal_id(), original.stored_universal_id());
    }

    #[test]
    fn replace_data_type_swaps_referenced_type() {
        let mut td = TypedefDataType::new_in_root("Foo", leaf("int", 4)).unwrap();
        td.replace_data_type(leaf("uint", 4)).unwrap();
        assert_eq!(td.referenced_data_type().get_name(), "uint");
    }

    #[test]
    fn replace_data_type_rejects_invalid_replacement() {
        struct VoidLike;
        impl DataType for VoidLike {
            fn is_void_type(&self) -> bool {
                true
            }
        }
        let mut td = TypedefDataType::new_in_root("Foo", leaf("int", 4)).unwrap();
        assert!(td.replace_data_type(Box::new(VoidLike)).is_err());
        assert_eq!(td.referenced_data_type().get_name(), "int"); // unchanged
    }

    #[test]
    fn depends_on_checks_referenced_type() {
        let td = TypedefDataType::new_in_root("Foo", leaf("int", 4)).unwrap();
        assert!(DataType::depends_on(&td, leaf("int", 4).as_ref()));
        assert!(!DataType::depends_on(&td, leaf("float", 4).as_ref()));
    }

    #[test]
    fn is_typedef_and_downcast_report_true() {
        let td = TypedefDataType::new_in_root("Foo", leaf("int", 4)).unwrap();
        assert!(DataType::is_typedef(&td));
        assert!(DataType::as_typedef(&td).is_some());
        assert_eq!(DataType::typedef_base_data_type(&td).unwrap().get_name(), "int");
    }
}
