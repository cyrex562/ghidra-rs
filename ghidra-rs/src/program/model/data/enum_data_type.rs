//! Port of `ghidra.program.model.data.EnumDataType`.
//!
//! The Java class `extends GenericDataType implements Enum`. Both supertraits
//! ([`GenericDataType`] and [`Enum`]) are already ported in this crate, and
//! [`GenericDataType`]`: `[`DataTypeImpl`]`: `[`DataType`] is exactly the same trait stack
//! [`TypedefDataType`](super::typedef_data_type::TypedefDataType) is already built on, so this
//! struct follows that same, proven concrete-struct pattern (shared settings store behind
//! `Arc<Mutex<...>>`, no tracked `DataTypeManager` field, `Utils` marker for the `&dyn
//! Trait`-object seams).
//!
//! ## Name clash: `Enum::set_description` vs `DataType::set_description`
//!
//! [`Enum::set_description`] (`fn(&mut self, &str)`, required, no default) and
//! [`DataType::set_description`] (`fn(&mut self, &str) -> Result<(), UnsupportedOperationError>`,
//! defaulted) share a name but differ in return type -- an allowed-but-ambiguous-at-call-sites
//! situation in Rust (see this crate's other cut-point traits for the same restriction pattern,
//! though this is the first case where the *colliding* method itself is a `dyn`-safe requirement
//! rather than a same-named default). Both are implemented here, delegating to the private
//! inherent [`EnumDataType::set_enum_description`] to avoid duplicating the field write, and this
//! struct's own internal call sites (`copy`/`clone_enum`) call that inherent helper directly
//! rather than either trait method, sidestepping the ambiguity entirely.
//!
//! ## Dropped/simplified pieces
//!
//! - **`dataMgr`**: like [`TypedefDataType`](super::typedef_data_type::TypedefDataType) and every
//!   other [`DataTypeImpl`]-based concrete type in this crate, no `DataTypeManager` is tracked (
//!   [`DataTypeImpl`]'s own port drops it -- see its module docs), so `getDataTypeManager() == dtm`
//!   in Java's `clone(DataTypeManager)` is never true here; [`EnumDataType::clone_enum`]
//!   unconditionally rebuilds, matching [`TypedefDataType::clone_typedef`]'s identical
//!   unconditional-rebuild precedent (no reference-equality fast path).
//! - **`bitGroups` cache**: Java lazily computes and caches `List<BitGroup>` per-instance,
//!   invalidated on every `add`/`remove`. This port recomputes
//!   [`EnumValuePartitioner::partition`] on every call to the private compound-value formatter
//!   instead of caching it as a field, matching the "fresh value each call" simplification
//!   documented elsewhere in this crate (e.g. `DataTypeUtilities`'s module docs) -- functionally
//!   identical, just without the memoization.
//! - **`getValue`/`checkValue`/`doAdd`/`setLength`'s `IllegalArgumentException`s**: ported as
//!   panics, mirroring this crate's established convention for that specific Java exception (see
//!   e.g. `AbstractDataType::check_new_abstract_data_type_args`'s own doc comment). [`Enum::add`]/
//!   [`Enum::add_with_comment`]/[`EnumDataType::set_length`] have no `Result`-returning shape to
//!   report failure through (matching the Java interface's own unchecked-exception signature), so
//!   there is no alternative to panicking here without changing the trait.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, Weak};

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::database::data::data_type_utilities::DataTypeUtilities;
use crate::program::database::data::EnumSignedState;
use crate::program::model::data::bit_group::BitGroup;
use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::data_type::{DataType, SetDataTypeNameError};
use crate::program::model::data::data_type_impl::DataTypeImpl;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::data_utilities::DataUtilities;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::enum_value_partitioner::EnumValuePartitioner;
use crate::program::model::data::generic_data_type::GenericDataType;
use crate::program::model::data::mutability_settings_definition::MutabilitySettingsDefinition;
use crate::program::model::data::source_archive::SourceArchive;
use crate::program::model::mem::MemBuffer;
use crate::program::model::scalar::Scalar;
use crate::util::exception::{DuplicateNameException, InvalidNameException};
use crate::util::UniversalID;

/// Zero-sized marker used purely to call the defaulted trait methods of
/// [`DataTypeUtilities`]/[`DataUtilities`] (both `&dyn Trait`-object seams -- see their own module
/// docs). Mirrors [`TypedefDataType`](super::typedef_data_type::TypedefDataType)'s identical
/// `Utils` marker.
#[derive(Debug, Default, Clone, Copy)]
struct Utils;
impl DataTypeUtilities for Utils {}
impl DataUtilities for Utils {}

/// Shared, lockable backing store for an [`EnumDataType`]'s default settings (just the single
/// `MutabilitySettingsDefinition` "mutability" long value in practice, but stored generically).
/// See the module docs and [`TypedefDataType`](super::typedef_data_type::TypedefDataType)'s
/// identical `TypedefSettingsStore` precedent for why this is behind `Arc<Mutex<...>>` rather than
/// a plain field.
#[derive(Default, Clone)]
struct EnumSettingsStore {
    longs: HashMap<String, i64>,
}

/// [`Settings`] handle returned by [`EnumDataType`]'s `get_default_settings`. Shares the same
/// underlying `Arc<Mutex<EnumSettingsStore>>` as the owning [`EnumDataType`] rather than a
/// disconnected snapshot, so writes through this object persist back -- see
/// [`TypedefDataType`](super::typedef_data_type::TypedefDataType)'s identical
/// `TypedefSettingsSnapshot`.
struct EnumSettingsSnapshot {
    store: Arc<Mutex<EnumSettingsStore>>,
}

impl Settings for EnumSettingsSnapshot {
    fn get_long(&self, name: &str) -> Option<i64> {
        self.store.lock().expect("enum settings mutex poisoned").longs.get(name).copied()
    }

    fn get_value(&self, name: &str) -> Option<Box<dyn std::any::Any>> {
        self.get_long(name).map(|v| Box::new(v) as Box<dyn std::any::Any>)
    }

    fn set_long(&mut self, name: &str, value: i64) {
        self.store.lock().expect("enum settings mutex poisoned").longs.insert(name.to_string(), value);
    }

    fn clear_setting(&mut self, name: &str) {
        self.store.lock().expect("enum settings mutex poisoned").longs.remove(name);
    }

    fn clear_all_settings(&mut self) {
        self.store.lock().expect("enum settings mutex poisoned").longs.clear();
    }

    fn get_names(&self) -> Vec<String> {
        self.store.lock().expect("enum settings mutex poisoned").longs.keys().cloned().collect()
    }

    fn is_empty(&self) -> bool {
        self.store.lock().expect("enum settings mutex poisoned").longs.is_empty()
    }
}

/// Basic implementation of the Enum data type.
///
/// Port of `ghidra.program.model.data.EnumDataType`. See the module-level documentation for the
/// naming-collision convention and for what was dropped or simplified.
pub struct EnumDataType {
    category_path: CategoryPath,
    name: String,
    name_map: HashMap<String, i64>,
    comment_map: HashMap<String, String>,
    value_map: BTreeMap<i64, Vec<String>>,
    length: i32,
    description: Option<String>,
    signed_state: EnumSignedState,
    universal_id: UniversalID,
    source_archive_id: Option<UniversalID>,
    last_change_time: i64,
    last_change_time_in_source_archive: i64,
    parents: Vec<Weak<dyn DataType>>,
    settings: Arc<Mutex<EnumSettingsStore>>,
}

impl EnumDataType {
    /// Construct a new enum within the root category.
    ///
    /// Port of the 2-arg Java constructor `EnumDataType(String, int)`.
    ///
    /// # Panics
    /// Panics (standing in for `IllegalArgumentException`) if `length` is not in `1..=8`, or if
    /// `name` is not a valid data-type name (mirroring `GenericDataType`'s own constructor
    /// validation).
    pub fn new(name: impl Into<String>, length: i32) -> Self {
        Self::new_in_category(ROOT.clone(), name, length)
    }

    /// Construct a new enum.
    ///
    /// Port of the 3-arg Java constructor `EnumDataType(CategoryPath, String, int)` (the 4-arg
    /// overload additionally taking a `DataTypeManager` collapses into this one -- see the module
    /// docs on why `dataMgr` is not tracked).
    ///
    /// # Panics
    /// See [`EnumDataType::new`].
    pub fn new_in_category(category_path: CategoryPath, name: impl Into<String>, length: i32) -> Self {
        let name = name.into();
        check_length(length);
        if !Utils.is_valid_data_type_name(&name) {
            panic!("Invalid DataType name: {name}");
        }
        EnumDataType {
            category_path,
            name,
            name_map: HashMap::new(),
            comment_map: HashMap::new(),
            value_map: BTreeMap::new(),
            length,
            description: None,
            signed_state: EnumSignedState::None,
            universal_id: UniversalID::new(0),
            source_archive_id: None,
            last_change_time: 0,
            last_change_time_in_source_archive: 0,
            parents: Vec::new(),
            settings: Arc::new(Mutex::new(EnumSettingsStore::default())),
        }
    }

    /// Construct a new enum with an explicit archive identity.
    ///
    /// Port of the 8-arg Java constructor taking `universalID`/`sourceArchive`/`lastChangeTime`/
    /// `lastChangeTimeInSourceArchive`. `source_archive` is tracked only by ID, matching
    /// [`TypedefDataType::with_archive_identity`](super::typedef_data_type::TypedefDataType::with_archive_identity)'s
    /// identical simplification.
    ///
    /// # Panics
    /// See [`EnumDataType::new`].
    #[allow(clippy::too_many_arguments)]
    pub fn with_archive_identity(
        category_path: CategoryPath,
        name: impl Into<String>,
        length: i32,
        universal_id: UniversalID,
        source_archive: Option<&dyn SourceArchive>,
        last_change_time: i64,
        last_change_time_in_source_archive: i64,
    ) -> Self {
        let mut e = Self::new_in_category(category_path, name, length);
        e.universal_id = universal_id;
        e.source_archive_id = source_archive.map(|a| a.source_archive_id());
        e.last_change_time = last_change_time;
        e.last_change_time_in_source_archive = last_change_time_in_source_archive;
        e
    }

    /// Private helper backing both [`Enum::set_description`] and [`DataType::set_description`]
    /// overrides -- see the module docs on the name clash between them.
    fn set_enum_description(&mut self, description: Option<String>) {
        self.description = description;
    }

    /// Port of the private `EnumDataType.doAdd(String, long, String)`.
    ///
    /// # Errors
    /// Returns `Err` (standing in for `IllegalArgumentException`) if `value` is out of range for
    /// this enum's current length/signedness, or if `value_name` already exists.
    fn do_add(&mut self, value_name: &str, value: i64, comment: Option<&str>) -> Result<(), String> {
        self.check_value(value)?;
        if self.name_map.contains_key(value_name) {
            return Err(format!("{value_name} already exists in this enum"));
        }
        self.name_map.insert(value_name.to_string(), value);
        self.value_map.entry(value).or_default().push(value_name.to_string());
        if let Some(comment) = comment {
            if !comment.trim().is_empty() {
                self.comment_map.insert(value_name.to_string(), comment.to_string());
            }
        }
        Ok(())
    }

    /// Port of the private `EnumDataType.computeSignedness()`.
    fn compute_signedness(&self) -> EnumSignedState {
        let (Some((&min_value, _)), Some((&max_value, _))) =
            (self.value_map.iter().next(), self.value_map.iter().next_back())
        else {
            return EnumSignedState::None;
        };

        if max_value > max_possible_value(self.length, true) {
            if min_value < 0 {
                return EnumSignedState::Invalid;
            }
            return EnumSignedState::Unsigned;
        }

        if min_value < 0 {
            return EnumSignedState::Signed;
        }

        EnumSignedState::None
    }

    /// Port of the private `EnumDataType.checkValue(long)`.
    fn check_value(&self, value: i64) -> Result<(), String> {
        if self.length == 8 {
            return Ok(()); // all long values permitted
        }
        let min = self.get_min_possible_value();
        let max = self.get_max_possible_value();
        if value < min || value > max {
            return Err(format!(
                "Attempted to add a value outside the range for this enum: ({min}, {max}): {value}"
            ));
        }
        Ok(())
    }

    /// Port of `EnumDataType.setLength(int)`.
    ///
    /// # Panics
    /// Panics (standing in for `IllegalArgumentException`) if `new_length` is less than
    /// [`Enum::get_minimum_possible_length`] or greater than 8.
    pub fn set_length(&mut self, new_length: i32) {
        if new_length == self.length {
            return;
        }
        let min_length = self.get_minimum_possible_length();
        if new_length < min_length || new_length > 8 {
            panic!("Enum length must be between {min_length}and 8 inclusive");
        }
        self.length = new_length;
    }

    /// Sets this enum to its smallest (power of 2) size that it can still represent all its
    /// current values with.
    ///
    /// Port of `EnumDataType.pack()`.
    pub fn pack(&mut self) {
        self.set_length(self.get_minimum_possible_length());
    }

    /// Port of the private `EnumDataType.getRepresentation(long)`.
    fn get_representation_for_value(&self, value: i64) -> String {
        match self.get_name_for_value(value) {
            Some(name) => name,
            None => self.get_compound_value(value),
        }
    }

    /// Port of the private `EnumDataType.getCompoundValue(long)`.
    fn get_compound_value(&self, value: i64) -> String {
        if value == 0 {
            return "0".to_string();
        }
        let groups = self.get_bit_groups();
        let mut buf = String::new();
        for bit_group in &groups {
            let sub_value = bit_group.get_mask() & value;
            if sub_value != 0 {
                let part = match self.get_name_for_value(sub_value) {
                    Some(name) => name,
                    None => format!("{:X}h", sub_value as u64),
                };
                if !buf.is_empty() {
                    buf.push_str(" | ");
                }
                buf.push_str(&part);
            }
        }
        buf
    }

    /// Port of the private `EnumDataType.getBitGroups()`. Recomputed each call rather than cached
    /// -- see the module docs.
    fn get_bit_groups(&self) -> Vec<BitGroup> {
        EnumValuePartitioner::partition(&self.get_values(), self.length)
    }

    /// Port of the private `EnumDataType.isEachValueEquivalent(Enum)`.
    fn is_each_value_equivalent(&self, other: &dyn Enum) -> bool {
        let names = Enum::get_names(self);
        let other_names = other.get_names();
        if names.len() != other_names.len() {
            return false;
        }
        for (name, other_name) in names.iter().zip(other_names.iter()) {
            if name != other_name {
                return false;
            }
            let (Some(value), Some(other_value)) =
                (self.get_value_for_name(name), other.get_value_for_name(name))
            else {
                return false;
            };
            if value != other_value {
                return false;
            }
            if Enum::get_comment(self, name) != other.get_comment(name) {
                return false;
            }
        }
        true
    }
}

/// Port of the private `EnumDataType.getMaxPossibleValue(int, boolean)`.
fn max_possible_value(bytes: i32, allow_negative_values: bool) -> i64 {
    if bytes == 8 {
        return i64::MAX;
    }
    let mut bits = bytes * 8;
    if allow_negative_values {
        bits -= 1;
    }
    (1i64 << bits) - 1
}

/// Port of the private `EnumDataType.getMinPossibleValue(int, boolean)`.
fn min_possible_value(bytes: i32, allow_negative_values: bool) -> i64 {
    if !allow_negative_values {
        return 0;
    }
    let bits = bytes * 8;
    -1i64 << (bits - 1)
}

fn check_length(length: i32) {
    if !(1..=8).contains(&length) {
        panic!("unsupported enum length: {length}");
    }
}

impl DataType for EnumDataType {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn set_name(&mut self, name: &str) -> Result<(), SetDataTypeNameError> {
        if self.generic_check_name_change(name, &Utils)? {
            self.name = name.to_string();
        }
        Ok(())
    }

    fn get_category_path(&self) -> CategoryPath {
        self.category_path.clone()
    }

    fn set_category_path(&mut self, path: CategoryPath) -> Result<(), DuplicateNameException> {
        self.category_path = self.generic_normalize_category_path(Some(path));
        Ok(())
    }

    fn get_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        vec![Box::new(MutabilitySettingsDefinition::DEF)]
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        self.data_type_impl_get_default_settings()
    }

    /// Preserved Java quirk: this always returns the raw stored `name` field directly rather than
    /// calling `get_name()` (though for `EnumDataType`, which has no auto-naming, the two are
    /// always identical anyway).
    fn get_mnemonic(&self, _settings: &dyn Settings) -> String {
        self.name.clone()
    }

    fn get_length(&self) -> i32 {
        self.length
    }

    fn get_aligned_length(&self) -> i32 {
        self.get_length()
    }

    fn get_description(&self) -> String {
        self.description.clone().unwrap_or_default()
    }

    fn set_description(&mut self, description: &str) -> Result<(), crate::program::model::data::data_type::UnsupportedOperationError> {
        self.set_enum_description(Some(description.to_string()));
        Ok(())
    }

    fn get_default_label_prefix(&self) -> Option<String> {
        Some(self.name.clone())
    }

    fn as_enum(&self) -> Option<&dyn Enum> {
        Some(self)
    }

    /// Port of `EnumDataType.getValue(MemBuffer, Settings, int)`.
    fn get_value(&self, buf: &dyn MemBuffer, _settings: &dyn Settings, value_length: i32) -> Option<Box<dyn std::any::Any>> {
        let value = match value_length {
            1 => buf.get_byte(0).ok()? as i8 as i64,
            2 => buf.get_short(0).ok()? as i64,
            4 => buf.get_int(0).ok()? as i64,
            8 => buf.get_long(0).ok()?,
            _ => 0,
        };
        Some(Box::new(Scalar::new((value_length.max(0) as u32 * 8).min(64) as u8, value)))
    }

    fn get_value_class(&self, _settings: &dyn Settings) -> Option<std::any::TypeId> {
        Some(std::any::TypeId::of::<Scalar>())
    }

    /// Port of `EnumDataType.getRepresentation(MemBuffer, Settings, int)`.
    fn get_representation(&self, buf: &dyn MemBuffer, _settings: &dyn Settings, _value_length: i32) -> String {
        let value = match self.length {
            1 => match buf.get_byte(0) {
                Ok(b) => b as i64,
                Err(_) => return "??".to_string(),
            },
            2 => match buf.get_short(0) {
                Ok(v) => (v as u16) as i64,
                Err(_) => return "??".to_string(),
            },
            4 => match buf.get_int(0) {
                Ok(v) => (v as u32) as i64,
                Err(_) => return "??".to_string(),
            },
            8 => match buf.get_long(0) {
                Ok(v) => v,
                Err(_) => return "??".to_string(),
            },
            _ => 0,
        };
        self.get_representation_for_value(value)
    }

    /// Port of `EnumDataType.isEquivalent(DataType)`. `other.get_name()`/`.get_length()` resolve
    /// to the [`DataType`] supertrait methods directly on the `&dyn Enum` trait object (`Enum:
    /// DataType`, and Rust trait objects expose supertrait methods without an explicit upcast).
    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        let Some(other) = dt.as_enum() else {
            return false;
        };
        if !Utils.equals_ignore_conflict(&self.name, &other.get_name())
            || self.length != other.get_length()
            || self.get_count() != other.get_count()
        {
            return false;
        }
        self.is_each_value_equivalent(other)
    }

    /// Port of `EnumDataType.replaceWith(DataType)`.
    ///
    /// # Panics
    /// Panics (standing in for `IllegalArgumentException`) if `data_type` is not an [`Enum`].
    fn replace_with(&mut self, data_type: &dyn DataType) {
        let Some(other) = data_type.as_enum() else {
            panic!("IllegalArgumentException: replaceWith requires an Enum");
        };
        self.name_map = HashMap::new();
        self.value_map = BTreeMap::new();
        self.comment_map = HashMap::new();
        self.set_length(other.get_length());
        let names = other.get_names();
        self.signed_state = other.get_signed_state();
        for value_name in names {
            let value = other.get_value_for_name(&value_name).unwrap_or(0);
            let comment = other.get_comment(&value_name);
            let comment = if comment.is_empty() { None } else { Some(comment.as_str()) };
            if let Err(e) = self.do_add(&value_name, value, comment) {
                panic!("{e}");
            }
        }
    }

    fn copy_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        let _ = dtm;
        let mut enum_data_type = EnumDataType::new_in_category(self.get_category_path(), self.get_name(), self.get_length());
        enum_data_type.set_enum_description(Some(self.get_description()));
        DataType::replace_with(&mut enum_data_type, self);
        Box::new(enum_data_type)
    }

    fn clone_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        self.clone_enum(dtm) as Box<dyn DataType>
    }
}

impl DataTypeImpl for EnumDataType {
    fn stored_default_settings(&self) -> Box<dyn Settings> {
        Box::new(EnumSettingsSnapshot { store: Arc::clone(&self.settings) })
    }

    fn set_stored_default_settings(&mut self, settings: Box<dyn Settings>) {
        let mut store = self.settings.lock().expect("enum settings mutex poisoned");
        for name in settings.get_names() {
            if let Some(v) = settings.get_long(&name) {
                store.longs.insert(name, v);
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

impl GenericDataType for EnumDataType {}

impl Enum for EnumDataType {
    fn get_value_for_name(&self, name: &str) -> Option<i64> {
        self.name_map.get(name).copied()
    }

    fn get_name_for_value(&self, value: i64) -> Option<String> {
        self.value_map.get(&value).and_then(|names| names.first().cloned())
    }

    fn get_names_for_value(&self, value: i64) -> Option<Vec<String>> {
        self.value_map.get(&value).filter(|names| !names.is_empty()).cloned()
    }

    fn get_comment(&self, name: &str) -> String {
        self.comment_map.get(name).cloned().unwrap_or_default()
    }

    fn get_values(&self) -> Vec<i64> {
        self.value_map.keys().copied().collect()
    }

    fn get_names(&self) -> Vec<String> {
        // Names are first sorted by value (BTreeMap iteration order), then sub-sorted by name.
        let mut names = Vec::new();
        for list in self.value_map.values() {
            let mut list = list.clone();
            list.sort();
            names.extend(list);
        }
        names
    }

    fn get_count(&self) -> i32 {
        self.name_map.len() as i32
    }

    /// Port of `EnumDataType.add(String, long)`.
    ///
    /// # Panics
    /// Panics (standing in for `IllegalArgumentException`) if `value` is out of range or `name`
    /// already exists.
    fn add(&mut self, name: &str, value: i64) {
        Enum::add_with_comment(self, name, value, "");
    }

    /// Port of `EnumDataType.add(String, long, String)`. See [`Enum::add`]'s doc comment for the
    /// panic conditions.
    fn add_with_comment(&mut self, name: &str, value: i64, comment: &str) {
        if let Err(e) = self.do_add(name, value, Some(comment)) {
            panic!("{e}");
        }
        self.signed_state = self.compute_signedness();
    }

    fn remove(&mut self, name: &str) {
        let Some(value) = self.name_map.remove(name) else {
            return;
        };
        if let Some(list) = self.value_map.get_mut(&value) {
            if let Some(pos) = list.iter().position(|n| n == name) {
                list.remove(pos);
            }
            if list.is_empty() {
                self.value_map.remove(&value);
            }
        }
        self.comment_map.remove(name);
        self.signed_state = self.compute_signedness();
    }

    fn set_description(&mut self, description: &str) {
        self.set_enum_description(Some(description.to_string()));
    }

    fn get_enum_representation(&self, big_int: i128, _settings: &dyn Settings, _bit_length: i32) -> String {
        self.get_representation_for_value(big_int as i64)
    }

    fn contains_name(&self, name: &str) -> bool {
        self.name_map.contains_key(name)
    }

    fn contains_value(&self, value: i64) -> bool {
        self.value_map.contains_key(&value)
    }

    fn is_signed(&self) -> bool {
        self.signed_state == EnumSignedState::Signed
    }

    fn get_signed_state(&self) -> EnumSignedState {
        self.signed_state
    }

    fn get_min_possible_value(&self) -> i64 {
        min_possible_value(self.length, self.signed_state != EnumSignedState::Unsigned)
    }

    fn get_max_possible_value(&self) -> i64 {
        max_possible_value(self.length, self.signed_state == EnumSignedState::Signed)
    }

    fn get_minimum_possible_length(&self) -> i32 {
        let (Some((&min_value, _)), Some((&max_value, _))) =
            (self.value_map.iter().next(), self.value_map.iter().next_back())
        else {
            return 1;
        };
        let has_negative_values = min_value < 0;

        let mut size = 1;
        while size < 8 {
            let min_possible = min_possible_value(size, has_negative_values);
            let max_possible = max_possible_value(size, has_negative_values);
            if min_value >= min_possible && max_value <= max_possible {
                return size;
            }
            size *= 2;
        }
        8
    }

    fn clone_enum(&self, dtm: &dyn DataTypeManager) -> Box<dyn Enum> {
        let _ = dtm;
        let mut cloned = EnumDataType::with_archive_identity(
            self.category_path.clone(),
            self.name.clone(),
            self.length,
            self.universal_id,
            None,
            self.last_change_time,
            self.last_change_time_in_source_archive,
        );
        cloned.source_archive_id = self.source_archive_id;
        cloned.set_enum_description(self.description.clone());
        DataType::replace_with(&mut cloned, self);
        Box::new(cloned)
    }
}

impl std::fmt::Display for EnumDataType {
    /// Port of `EnumDataType.toString()`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.get_path_name())?;
        write!(f, "\tDescription: {}", self.get_description())?;
        write!(f, "\nValues: \n")?;
        for name in Enum::get_names(self) {
            let value = self.get_value_for_name(&name).unwrap_or(0);
            write!(f, "\t{name}: {value}")?;
            let comment = Enum::get_comment(self, &name);
            if !comment.is_empty() {
                write!(f, " {comment}")?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::mem::MemoryAccessException;

    #[test]
    fn new_rejects_out_of_range_length() {
        let result = std::panic::catch_unwind(|| EnumDataType::new("Bad", 0));
        assert!(result.is_err());
        let result = std::panic::catch_unwind(|| EnumDataType::new("Bad", 9));
        assert!(result.is_err());
    }

    #[test]
    fn add_and_lookup_round_trip() {
        let mut e = EnumDataType::new("Color", 1);
        e.add("RED", 0);
        e.add("GREEN", 1);
        e.add("BLUE", 2);
        assert_eq!(e.get_value_for_name("RED"), Some(0));
        assert_eq!(e.get_name_for_value(1), Some("GREEN".to_string()));
        assert_eq!(e.get_count(), 3);
        assert_eq!(Enum::get_values(&e), vec![0, 1, 2]);
    }

    #[test]
    fn add_with_comment_stores_comment() {
        let mut e = EnumDataType::new("Color", 1);
        e.add_with_comment("RED", 0, "the color red");
        assert_eq!(Enum::get_comment(&e, "RED"), "the color red");
        assert_eq!(Enum::get_comment(&e, "MISSING"), "");
    }

    #[test]
    fn add_blank_comment_is_not_stored() {
        let mut e = EnumDataType::new("Color", 1);
        e.add_with_comment("RED", 0, "   ");
        assert_eq!(Enum::get_comment(&e, "RED"), "");
    }

    #[test]
    #[should_panic(expected = "already exists")]
    fn add_duplicate_name_panics() {
        let mut e = EnumDataType::new("Color", 1);
        e.add("RED", 0);
        e.add("RED", 1);
    }

    #[test]
    #[should_panic(expected = "outside the range")]
    fn add_out_of_range_value_panics() {
        let mut e = EnumDataType::new("Small", 1);
        e.add("TOO_BIG", 1000);
    }

    #[test]
    fn remove_deletes_name_value_and_comment() {
        let mut e = EnumDataType::new("Color", 1);
        e.add_with_comment("RED", 0, "red");
        e.add("GREEN", 0); // shares value 0 with RED
        e.remove("RED");
        assert_eq!(e.get_value_for_name("RED"), None);
        assert_eq!(Enum::get_comment(&e, "RED"), "");
        assert_eq!(e.get_name_for_value(0), Some("GREEN".to_string())); // GREEN survives
        e.remove("GREEN");
        assert_eq!(e.get_name_for_value(0), None); // list now empty, value removed too
    }

    #[test]
    fn remove_missing_name_is_a_no_op() {
        let mut e = EnumDataType::new("Color", 1);
        e.add("RED", 0);
        e.remove("NOT_THERE");
        assert_eq!(e.get_count(), 1);
    }

    #[test]
    fn get_names_sorted_by_value_then_name() {
        let mut e = EnumDataType::new("Color", 1);
        e.add("ZEBRA", 1);
        e.add("APPLE", 1);
        e.add("BANANA", 0);
        assert_eq!(Enum::get_names(&e), vec!["BANANA", "APPLE", "ZEBRA"]);
    }

    #[test]
    fn get_names_for_value_returns_all_aliases() {
        let mut e = EnumDataType::new("Color", 1);
        e.add("A", 1);
        e.add("B", 1);
        let mut names = e.get_names_for_value(1).unwrap();
        names.sort();
        assert_eq!(names, vec!["A".to_string(), "B".to_string()]);
        assert_eq!(e.get_names_for_value(99), None);
    }

    #[test]
    fn signedness_tracks_added_values() {
        let mut e = EnumDataType::new("Sign", 1);
        assert_eq!(e.get_signed_state(), EnumSignedState::None);
        e.add("NEG", -1);
        assert_eq!(e.get_signed_state(), EnumSignedState::Signed);
        assert!(e.is_signed());

        let mut u = EnumDataType::new("Unsign", 1);
        u.add("BIG", 200); // exceeds signed byte max (127)
        assert_eq!(u.get_signed_state(), EnumSignedState::Unsigned);
        assert!(!u.is_signed());
    }

    #[test]
    fn set_length_rejects_below_minimum_or_above_eight() {
        let mut e = EnumDataType::new("Color", 4);
        e.add("BIG", 70000); // needs at least 4 bytes
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| e.set_length(1)));
        assert!(result.is_err());
    }

    #[test]
    fn pack_shrinks_to_minimum_possible_length() {
        let mut e = EnumDataType::new("Color", 8);
        e.add("SMALL", 5);
        e.pack();
        assert_eq!(e.get_length(), 1);
    }

    #[test]
    fn get_representation_falls_back_to_compound_value() {
        let mut e = EnumDataType::new("Flags", 1);
        e.add("A", 1);
        e.add("B", 2);
        // 3 has no direct name, but decomposes into bit groups A (1) | B (2).
        let repr = e.get_representation_for_value(3);
        assert!(repr.contains('A') && repr.contains('B'));
    }

    #[test]
    fn get_representation_for_value_zero_is_literal_zero() {
        let e = EnumDataType::new("Flags", 1);
        assert_eq!(e.get_representation_for_value(0), "0");
    }

    #[test]
    fn get_representation_prefers_exact_name_match() {
        let mut e = EnumDataType::new("Color", 1);
        e.add("RED", 5);
        assert_eq!(e.get_representation_for_value(5), "RED");
    }

    struct FixedBuf {
        bytes: [u8; 8],
    }
    impl MemBuffer for FixedBuf {
        fn get_address(&self) -> crate::program::model::address::Address {
            crate::program::model::address::SpecialAddress::no_address()
        }
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.bytes.get(offset as usize).copied().ok_or_else(|| MemoryAccessException::new("oob"))
        }
        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            let o = offset as usize;
            if o >= self.bytes.len() {
                return 0;
            }
            let n = buf.len().min(self.bytes.len() - o);
            buf[..n].copy_from_slice(&self.bytes[o..o + n]);
            n
        }
        fn is_big_endian(&self) -> bool {
            false
        }
    }

    struct NoSettings;
    impl Settings for NoSettings {}

    #[test]
    fn get_value_reads_by_length() {
        let mut e = EnumDataType::new("Color", 1);
        e.add("RED", 5);
        let buf = FixedBuf { bytes: [5, 0, 0, 0, 0, 0, 0, 0] };
        let value = DataType::get_value(&e, &buf, &NoSettings, 1).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_unsigned_value(), 5);
    }

    #[test]
    fn get_representation_reads_declared_length_not_value_length_arg() {
        let mut e = EnumDataType::new("Color", 2);
        e.add("BIG", 0x0102);
        // Little-endian 2-byte read: bytes [0x02, 0x01] -> 0x0102.
        let buf = FixedBuf { bytes: [0x02, 0x01, 0, 0, 0, 0, 0, 0] };
        assert_eq!(DataType::get_representation(&e, &buf, &NoSettings, 1), "BIG");
    }

    #[test]
    fn is_equivalent_compares_name_length_and_all_values() {
        let mut a = EnumDataType::new("Color", 1);
        a.add("RED", 0);
        a.add("GREEN", 1);
        let mut b = EnumDataType::new("Color", 1);
        b.add("RED", 0);
        b.add("GREEN", 1);
        assert!(DataType::is_equivalent(&a, &b));

        let mut c = EnumDataType::new("Color", 1);
        c.add("RED", 0);
        c.add("GREEN", 2); // different value
        assert!(!DataType::is_equivalent(&a, &c));
    }

    #[test]
    fn is_equivalent_false_against_non_enum() {
        let e = EnumDataType::new("Color", 1);
        struct NotAnEnum;
        impl DataType for NotAnEnum {
            fn get_name(&self) -> String {
                "Color".to_string()
            }
        }
        assert!(!DataType::is_equivalent(&e, &NotAnEnum));
    }

    #[test]
    fn replace_with_rebuilds_from_another_enum() {
        let mut a = EnumDataType::new("A", 1);
        a.add("X", 1);
        let mut b = EnumDataType::new("B", 1);
        b.add_with_comment("Y", 2, "why");
        DataType::replace_with(&mut a, &b);
        assert_eq!(a.get_value_for_name("X"), None);
        assert_eq!(a.get_value_for_name("Y"), Some(2));
        assert_eq!(Enum::get_comment(&a, "Y"), "why");
    }

    #[test]
    #[should_panic(expected = "IllegalArgumentException")]
    fn replace_with_non_enum_panics() {
        let mut a = EnumDataType::new("A", 1);
        struct NotAnEnum;
        impl DataType for NotAnEnum {}
        DataType::replace_with(&mut a, &NotAnEnum);
    }

    #[test]
    fn copy_data_type_preserves_contents_with_fresh_identity() {
        let mut a = EnumDataType::new("A", 1);
        a.add("X", 1);
        a.set_enum_description(Some("desc".to_string()));
        let copied = a.copy_data_type(&NoMgr);
        let copied_enum = copied.as_enum().unwrap();
        assert_eq!(copied_enum.get_value_for_name("X"), Some(1));
        assert_eq!(copied.get_description(), "desc");
    }

    struct NoMgr;
    impl DataTypeManager for NoMgr {}

    #[test]
    fn clone_enum_preserves_identity_and_contents() {
        let mut a = EnumDataType::with_archive_identity(ROOT.clone(), "A", 1, UniversalID::new(42), None, 5, 6);
        a.add("X", 1);
        let cloned = a.clone_enum(&NoMgr);
        assert_eq!(cloned.get_value_for_name("X"), Some(1));
        assert_eq!(DataType::get_name(cloned.as_ref()), "A");
    }

    #[test]
    fn display_matches_expected_format() {
        let mut e = EnumDataType::new("Color", 1);
        e.add("RED", 0);
        let shown = format!("{e}");
        assert!(shown.contains("Values:"));
        assert!(shown.contains("RED: 0"));
    }

    #[test]
    fn settings_definitions_includes_mutability_only() {
        let e = EnumDataType::new("Color", 1);
        let defs = DataType::get_settings_definitions(&e);
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].get_storage_key(), "mutability");
    }

    #[test]
    fn default_settings_write_persists_across_calls() {
        let e = EnumDataType::new("Color", 1);
        let mut first = DataType::get_default_settings(&e);
        first.set_long("mutability", 2);
        let second = DataType::get_default_settings(&e);
        assert_eq!(second.get_long("mutability"), Some(2));
    }

    #[test]
    fn free_function_helpers_match_static_java_methods() {
        assert_eq!(max_possible_value(8, true), i64::MAX);
        assert_eq!(max_possible_value(1, true), 127);
        assert_eq!(max_possible_value(1, false), 255);
        assert_eq!(min_possible_value(1, true), -128);
        assert_eq!(min_possible_value(1, false), 0);
    }
}
