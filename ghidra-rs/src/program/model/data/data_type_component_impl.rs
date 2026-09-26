//! Port of `ghidra.program.model.data.DataTypeComponentImpl`: basic (mutable) implementation of a
//! `DataTypeComponent`.
//!
//! # Fidelity notes
//!
//! `data_type`/`parent` are stored as `Arc` (rather than `Box`), mirroring the
//! [`share_data_type`](crate::program::seam_stubs::share_data_type) convention used by
//! [`ReadOnlyDataTypeComponent`](super::read_only_data_type_component::ReadOnlyDataTypeComponent):
//! [`DataTypeComponent::get_data_type`]/[`DataTypeComponent::get_parent`] must hand back an owned
//! `Box<dyn DataType>` from a `&self` borrow.
//!
//! Java's `parent` field is documented as "may be null in certain use cases", modeled here as
//! `Option<Arc<dyn CompositeDataTypeImpl>>`; when it is `None`,
//! [`get_parent`](DataTypeComponent::get_parent) returns a private [`NoParentDataType`] stand-in
//! (a `DataType` with every method left at its default) rather than a null, since the shared
//! [`DataTypeComponent`] trait's `get_parent` signature is not `Option`-shaped.
//!
//! `comment`/`field_name` are held behind [`std::sync::Mutex`] (not [`std::cell::RefCell`],
//! despite the interior-mutability need described below being otherwise identical to a
//! `RefCell`'s: [`DataType`] carries a `Send + Sync` supertrait bound, so any concrete type
//! composing a `Vec<DataTypeComponentImpl>` as a field -- e.g. a real
//! `StructureDataType`/`UnionDataType` implementor -- must itself be `Sync`, which a `RefCell`
//! field would make impossible; a single-threaded-only `Mutex::lock().unwrap()` has the same
//! effective semantics here as `RefCell::borrow_mut()` since nothing in this crate shares a
//! `DataTypeComponentImpl` across real threads): the
//! [`DataTypeComponent`] trait declares `set_comment`/`set_field_name`/`get_default_settings` as
//! `&self` methods (matching that trait's general "immutable value type" convention), but Java's
//! `DataTypeComponentImpl` genuinely mutates `this` in place and returns it from `setComment`/
//! `setFieldName` -- a real difference from
//! [`ReadOnlyDataTypeComponent`](super::read_only_data_type_component::ReadOnlyDataTypeComponent),
//! whose identical-looking setters are no-ops. Mutating a `Mutex`-backed field through `&self`
//! reproduces that in-place mutation faithfully (any other holder of the same `&self` reference
//! observes the change too, exactly like Java's shared object reference), while the trait's
//! required `Box<dyn DataTypeComponent>` return value is a freshly built snapshot sharing the same
//! `Arc`s -- observationally identical to Java's `return this;` for every getter a caller could
//! call on it. `offset`/`ordinal`/`length`/`data_type` are mutated via genuine `&mut self` methods
//! instead (matching [`InternalDataTypeComponent::set_data_type`]/
//! [`InternalDataTypeComponent::update`], and this struct's own `set_offset`/`set_length`/
//! `set_ordinal` for the package-private Java setters of the same names), so they need no
//! interior mutability at all.
//!
//! `getDefaultSettings()`'s lazily-**cached** `new SettingsImpl(immutableSettings)` is instead
//! recomputed on every call here (`invalidate_settings` is correspondingly a no-op): a cache would
//! need an `Arc<dyn Settings>`-shaped field, but `Settings` (unlike `DataType`/
//! `CompositeDataTypeImpl`) carries no `Send + Sync` supertrait bound, so `Arc<dyn Settings>` is
//! not `Sync` and storing one directly in this struct would (per the same reasoning as the
//! `RefCell`-vs-`Mutex` note above) make `DataTypeComponentImpl` `!Sync` outright, unusable inside
//! any real composite. Recomputing is behaviorally identical for every getter a caller could
//! invoke on the result (both produce a fresh, equivalent [`ComponentDefaultSettings`]/
//! [`NoDefaultSettings`] each time this method is queried through that lens), just without the
//! memoization. The lazily-built `new SettingsImpl(immutableSettings)` itself is still reproduced
//! directly as [`ComponentDefaultSettings`], the same approach
//! [`ReadOnlyDataTypeComponent`](super::read_only_data_type_component::ReadOnlyDataTypeComponent)
//! takes for its own (unconditionally immutable) equivalent, since the general-purpose
//! `ghidra.docking.settings.SettingsImpl` is still `TODO` in `PORT_MANIFEST.tsv`. Unlike that
//! sibling, immutability here depends on whether the parent's `DataTypeManager` allows default
//! component settings, and Java returns `null` outright when `parent` is `null` -- reproduced
//! here as [`NoDefaultSettings`], the same kind of `Option`-signature-can't-express-this stand-in
//! as [`NoParentDataType`] above.
//!
//! `hashCode()` is explicitly documented in Java as identity-based and "not expected" to be used
//! (`return super.hashCode();`), so it is not ported: there is nothing meaningful to reproduce
//! and nothing in this crate calls it. `equals(Object)`'s real structural comparison *is* ported,
//! as the inherent [`DataTypeComponentImpl::components_equal`] method (mirroring
//! `ReadOnlyDataTypeComponent::components_equal`'s identical treatment, since `equals` has no
//! counterpart on the [`DataTypeComponent`] trait). Its final `myDt.getClass() ==
//! otherDt.getClass()` fallback (once none of the `Structure`/`Union`/`Array`/`Pointer`/`TypeDef`
//! `instanceof` checks matched) has no reflection equivalent for `dyn DataType`; it is approximated
//! by [`DataType::get_name`] equality, the same established proxy
//! [`is_same_kind_built_in_data_type`](crate::program::database::data::data_type_utilities)
//! (see that function's own module) already uses for an identical "same concrete class" question.
//!
//! `isEquivalent`'s `DataTypeUtilities.isSameOrEquivalentDataType` call uses the already-ported
//! `ghidra.program.database.data.DataTypeUtilities`, reached via the same private zero-sized
//! `Utils` marker convention as
//! [`ReadOnlyDataTypeComponent`](super::read_only_data_type_component::ReadOnlyDataTypeComponent).

use std::any::Any;
use std::sync::{Arc, Mutex};

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::database::data::data_type_utilities::DataTypeUtilities;
use crate::program::model::data::composite::Composite;
use crate::program::model::data::composite_data_type_impl::CompositeDataTypeImpl;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::{
    uses_zero_length_component, DataTypeComponent, DEFAULT_FIELD_NAME_PREFIX,
};
use crate::program::model::data::internal_data_type_component::{
    cleanup_field_name, InternalDataTypeComponent,
};
use crate::program::seam_stubs::share_data_type;

/// Zero-sized marker used purely to call the defaulted trait methods of [`DataTypeUtilities`]
/// (a `&dyn Trait`-object seam -- see its own module docs). Mirrors the identical marker in
/// `read_only_data_type_component.rs`/`pointer_typedef.rs`/`typedef_data_type.rs`.
#[derive(Debug, Default, Clone, Copy)]
struct Utils;
impl DataTypeUtilities for Utils {}

/// Stand-in for a `null` `parent`, since [`DataTypeComponent::get_parent`]'s signature always
/// returns an owned `Box<dyn DataType>` rather than an `Option`. Every method is left at its
/// [`DataType`] default.
struct NoParentDataType;
impl DataType for NoParentDataType {}

/// Stand-in for a `null` return from `getDefaultSettings()` (when `parent` is `None`), for the
/// same "the trait signature can't express `Option` here" reason as [`NoParentDataType`].
struct NoDefaultSettings;
impl Settings for NoDefaultSettings {}

/// Delegates every [`Settings`] method to a shared, `Arc`-held inner settings object, letting
/// multiple independent `Box<dyn Settings>` handles reference the same underlying value (`dyn
/// Settings` has no `Clone` bound). Mirrors
/// [`SharedDataType`](crate::program::seam_stubs)'s identical rationale for `DataType`.
struct SharedSettings(Arc<dyn Settings>);

impl Settings for SharedSettings {
    fn is_immutable_settings(&self) -> bool {
        self.0.is_immutable_settings()
    }
    fn is_change_allowed(&self, settings_definition: &dyn SettingsDefinition) -> bool {
        self.0.is_change_allowed(settings_definition)
    }
    fn get_long(&self, name: &str) -> Option<i64> {
        self.0.get_long(name)
    }
    fn get_string(&self, name: &str) -> Option<String> {
        self.0.get_string(name)
    }
    fn get_value(&self, name: &str) -> Option<Box<dyn Any>> {
        self.0.get_value(name)
    }
    fn get_names(&self) -> Vec<String> {
        self.0.get_names()
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    fn get_default_settings(&self) -> Option<Box<dyn Settings>> {
        self.0.get_default_settings()
    }
}

/// Stand-in for the specific `new SettingsImpl(immutableSettings)` instance
/// `DataTypeComponentImpl.getDefaultSettings()` lazily builds and caches. See the module docs for
/// why the general-purpose `SettingsImpl` is not used, and for how immutability is decided.
struct ComponentDefaultSettings {
    fallback: Arc<dyn Settings>,
    immutable: bool,
}

impl Settings for ComponentDefaultSettings {
    fn is_immutable_settings(&self) -> bool {
        self.immutable
    }
    fn is_change_allowed(&self, _settings_definition: &dyn SettingsDefinition) -> bool {
        !self.immutable
    }
    fn get_long(&self, name: &str) -> Option<i64> {
        self.fallback.get_long(name)
    }
    fn get_string(&self, name: &str) -> Option<String> {
        self.fallback.get_string(name)
    }
    fn get_value(&self, name: &str) -> Option<Box<dyn Any>> {
        self.fallback.get_value(name)
    }
    fn get_names(&self) -> Vec<String> {
        self.fallback.get_names()
    }
    fn is_empty(&self) -> bool {
        self.fallback.is_empty()
    }
    fn get_default_settings(&self) -> Option<Box<dyn Settings>> {
        // Mirrors `SettingsImpl.getDefaultSettings()` returning the `defaultSettings` field,
        // which in this construction is exactly the wrapped fallback.
        Some(Box::new(SharedSettings(self.fallback.clone())))
    }
}

/// Basic implementation of a `DataTypeComponent`.
///
/// Port of `ghidra.program.model.data.DataTypeComponentImpl`.
pub struct DataTypeComponentImpl {
    data_type: Arc<dyn DataType>,
    parent: Option<Arc<dyn CompositeDataTypeImpl>>,
    offset: i32,
    ordinal: i32,
    field_name: Mutex<Option<String>>,
    comment: Mutex<Option<String>>,
    length: i32,
}

impl DataTypeComponentImpl {
    /// Create a new `DataTypeComponent`.
    ///
    /// # Arguments
    /// * `data_type` - the dataType for this component
    /// * `parent` - the dataType that this component belongs to
    /// * `length` - the length of the dataType in this component
    /// * `ordinal` - the index within its parent
    /// * `offset` - the byte offset within the parent
    /// * `field_name` - the name associated with this component, or `None`
    /// * `comment` - the comment associated with this component, or `None`
    pub fn new(
        data_type: Box<dyn DataType>,
        parent: Option<Arc<dyn CompositeDataTypeImpl>>,
        length: i32,
        ordinal: i32,
        offset: i32,
        field_name: Option<String>,
        comment: Option<String>,
    ) -> Self {
        let data_type: Arc<dyn DataType> = Arc::from(data_type);
        let mut length = length;
        if is_zero_bit_field(data_type.as_ref()) {
            // previously stored as 1, force to 0
            length = 0;
        }
        DataTypeComponentImpl {
            data_type,
            parent,
            offset,
            ordinal,
            field_name: Mutex::new(cleanup_field_name(field_name.as_deref())),
            comment: Mutex::new(clean_comment(comment)),
            length,
        }
    }

    /// Create a new `DataTypeComponent` without a name.
    pub fn new_unnamed(
        data_type: Box<dyn DataType>,
        parent: Option<Arc<dyn CompositeDataTypeImpl>>,
        length: i32,
        ordinal: i32,
        offset: i32,
    ) -> Self {
        Self::new(data_type, parent, length, ordinal, offset, None, None)
    }

    fn parent_as_data_type(&self) -> Option<Arc<dyn DataType>> {
        self.parent.as_ref().map(|p| p.clone() as Arc<dyn DataType>)
    }

    /// Port of the package-private `containsOffset(int)`.
    pub fn contains_offset(&self, off: i32) -> bool {
        if off == self.offset {
            // separate check required to handle zero-length case
            return true;
        }
        off > self.offset && off < (self.offset + self.length)
    }

    /// Port of the package-private `setOffset(int)`: set the byte offset of where this component
    /// begins in its immediate parent data type.
    pub fn set_offset(&mut self, offset: i32) {
        self.offset = offset;
    }

    /// Port of the package-private `setLength(int)`.
    pub fn set_length(&mut self, length: i32) {
        self.length = length;
    }

    /// Port of the package-private `setOrdinal(int)`: set the component ordinal of this
    /// component within its parent data type.
    pub fn set_ordinal(&mut self, ordinal: i32) {
        self.ordinal = ordinal;
    }

    /// Port of the package-private `invalidateSettings()`. A no-op here: unlike Java's lazily
    /// cached `defaultSettings` field, [`get_default_settings`](DataTypeComponent::get_default_settings)
    /// below recomputes on every call rather than caching (see the module docs for why -- caching
    /// would need an `Arc<dyn Settings>`-shaped field, and `Settings` carries no `Send + Sync`
    /// bound, which would make this struct `!Sync` and thus unusable as a field of any real
    /// `DataType` implementor). Kept as a method (rather than removed) since it is part of the
    /// ported Java surface and callers may still invoke it expecting Java's contract ("subsequent
    /// `getDefaultSettings()` reflects current state"), which recomputing-every-time already
    /// satisfies trivially.
    pub fn invalidate_settings(&self) {}

    /// Port of the package-private `update(String, DataType, String)`: perform a special-case
    /// component update that does not result in size or alignment changes. Named distinctly from
    /// [`InternalDataTypeComponent::update`] (Java overloads both as `update`; Rust cannot).
    pub fn update_special(&mut self, name: Option<String>, new_data_type: Box<dyn DataType>, new_comment: Option<String>) {
        self.data_type = Arc::from(new_data_type);
        *self.field_name.lock().unwrap() = cleanup_field_name(name.as_deref());
        *self.comment.lock().unwrap() = clean_comment(new_comment);
    }

    /// Port of `DataTypeComponentImpl.equals(Object)`. See the module docs for why this isn't
    /// exposed as a trait method, and for the reflection-based final fallback's approximation.
    pub fn components_equal(&self, other: &dyn DataTypeComponent) -> bool {
        let my_dt = self.get_data_type();
        let other_dt = other.get_data_type();

        if self.offset != other.get_offset()
            || self.get_length() != other.get_length()
            || self.ordinal != other.get_ordinal()
            || self.get_field_name() != other.get_field_name()
            || self.get_comment() != other.get_comment()
        {
            return false;
        }

        if my_dt.as_pointer().is_none() {
            let my_rel_path = my_dt.get_path_name();
            let other_rel_path = other_dt.get_path_name();
            if my_rel_path != other_rel_path {
                return false;
            }
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
        // name equality, the same proxy `is_same_kind_built_in_data_type` uses. See module docs.
        my_dt.get_name() == other_dt.get_name()
    }

    /// Duplicate this component (sharing the same underlying `Arc`s, matching Java's
    /// object-reference `return this;`/copy-construction idioms). `pub(crate)` since it is a
    /// crate-internal cloning primitive rather than part of the ported public API; used by
    /// [`StructureDataType`](super::structure_data_type::StructureDataType) to hand back an owned
    /// component from `getComponent`-style queries without exposing a full `Clone` impl.
    pub(crate) fn snapshot(&self) -> DataTypeComponentImpl {
        DataTypeComponentImpl {
            data_type: self.data_type.clone(),
            parent: self.parent.clone(),
            offset: self.offset,
            ordinal: self.ordinal,
            field_name: Mutex::new(self.field_name.lock().unwrap().clone()),
            comment: Mutex::new(self.comment.lock().unwrap().clone()),
            length: self.length,
        }
    }
}

/// Port of `DataTypeComponentImpl.checkDefaultFieldName(String)`.
///
/// Only recognizes the bare `fieldN` form and the *legacy* `field_0xHEX` form (no ordinal digits
/// before `_0x`) as reserved; a "new style" `fieldN_0xHEX` name (ordinal digits *and* a hex
/// offset, which is what [`DataTypeComponent::get_default_field_name`] itself actually generates
/// for a `Structure` parent) is *not* recognized, because Java's own `subname.startsWith("_0x")`
/// check only matches when `_0x` immediately follows the `field` prefix. This looks like a gap in
/// the original Java method, ported faithfully rather than "fixed".
///
/// # Errors
/// Returns `Err` if `field_name` collides with an auto-generated default field name (mirrors
/// `DuplicateNameException`).
pub fn check_default_field_name(field_name: &str) -> Result<(), String> {
    if let Some(rest) = field_name.strip_prefix(DEFAULT_FIELD_NAME_PREFIX) {
        let (subname, radix) = if rest.len() > 3 && rest.starts_with("_0x") {
            (&rest[3..], 16)
        } else {
            (rest, 10)
        };
        if !subname.is_empty() && i32::from_str_radix(subname, radix).is_ok() {
            return Err(format!("DuplicateNameException: Reserved field name: {field_name}"));
        }
    }
    Ok(())
}

/// Port of the static `DataTypeComponentImpl.getPreferredComponentLength(DataType, int)`.
///
/// Get the preferred length for a new component. The length returned will be no larger than the
/// specified `length`.
///
/// `length` is the constrained length, or a non-positive value to force use of `data_type`'s own
/// size. Dynamic types such as string must have a positive length specified.
///
/// # Errors
/// Returns `Err` if no length can be determined for a [`Dynamic`](crate::program::model::data::dynamic::Dynamic)
/// data type (mirrors `IllegalArgumentException`).
pub fn get_preferred_component_length(data_type: &dyn DataType, length: i32) -> Result<i32, String> {
    if uses_zero_length_component(data_type) {
        return Ok(0);
    }
    if let Some(dynamic) = data_type.as_dynamic() {
        if dynamic.can_specify_length() {
            return Ok(length);
        }
    }
    let dt_length = data_type.get_length();
    let mut length = length;
    if length <= 0 {
        length = dt_length;
    } else if dt_length >= 0 && dt_length < length {
        length = dt_length;
    }
    if length <= 0 {
        return Err(format!(
            "IllegalArgumentException: Positive length must be specified for {} component",
            data_type.get_display_name()
        ));
    }
    Ok(length)
}

fn is_zero_bit_field(data_type: &dyn DataType) -> bool {
    data_type.as_bit_field().map(|bf| bf.get_bit_size() == 0).unwrap_or(false)
}

fn clean_comment(comment: Option<String>) -> Option<String> {
    comment.filter(|c| !c.trim().is_empty())
}

impl DataTypeComponent for DataTypeComponentImpl {
    fn is_bit_field_component(&self) -> bool {
        self.data_type.as_bit_field().is_some()
    }

    fn is_zero_bit_field_component(&self) -> bool {
        is_zero_bit_field(self.data_type.as_ref())
    }

    fn get_data_type_name(&self) -> String {
        self.data_type.get_name()
    }

    fn bit_field_bit_offset(&self) -> i32 {
        self.data_type.as_bit_field().map(|bf| bf.get_bit_offset()).unwrap_or(0)
    }

    fn get_offset(&self) -> i32 {
        self.offset
    }

    fn get_end_offset(&self) -> i32 {
        if self.length == 0 {
            // separate check required to handle zero-length case
            return self.offset;
        }
        self.offset + self.length - 1
    }

    fn get_comment(&self) -> Option<String> {
        self.comment.lock().unwrap().clone()
    }

    fn set_comment(&self, comment: Option<String>) -> Box<dyn DataTypeComponent> {
        *self.comment.lock().unwrap() = clean_comment(comment);
        Box::new(self.snapshot())
    }

    fn get_field_name(&self) -> Option<String> {
        if self.is_zero_bit_field_component() {
            return None;
        }
        self.field_name.lock().unwrap().clone()
    }

    fn set_field_name(&self, field_name: Option<String>) -> Box<dyn DataTypeComponent> {
        *self.field_name.lock().unwrap() = cleanup_field_name(field_name.as_deref());
        Box::new(self.snapshot())
    }

    fn get_data_type(&self) -> Box<dyn DataType> {
        share_data_type(&self.data_type)
    }

    fn get_parent(&self) -> Box<dyn DataType> {
        match self.parent_as_data_type() {
            Some(parent) => share_data_type(&parent),
            None => Box::new(NoParentDataType),
        }
    }

    fn get_length(&self) -> i32 {
        self.length
    }

    fn get_ordinal(&self) -> i32 {
        self.ordinal
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        // Recomputed on every call rather than cached (see `invalidate_settings`'s doc comment
        // for why); observationally equivalent to Java's lazily-cached field for every getter a
        // caller could invoke on the result, just without the memoization.
        let Some(parent) = &self.parent else {
            return Box::new(NoDefaultSettings);
        };
        let data_mgr = parent.get_data_type_manager();
        let immutable = data_mgr
            .as_ref()
            .map(|mgr| !mgr.allows_default_component_settings())
            .unwrap_or(true);
        let fallback: Arc<dyn Settings> = Arc::from(self.data_type.get_default_settings());
        Box::new(ComponentDefaultSettings { fallback, immutable })
    }

    fn is_equivalent(&self, dtc: &dyn DataTypeComponent) -> bool {
        let my_dt = self.get_data_type();
        let other_dt = dtc.get_data_type();
        let my_parent = self.get_parent();
        let aligned = my_parent
            .as_composite()
            .map(Composite::is_packing_enabled)
            .unwrap_or(false);

        if (!aligned && (self.offset != dtc.get_offset()))
            || self.get_field_name() != dtc.get_field_name()
            || self.get_comment() != dtc.get_comment()
        {
            return false;
        }

        // Component lengths need only be checked for dynamic types.
        if self.get_length() != dtc.get_length() && my_dt.as_dynamic().is_some() {
            return false;
        }

        Utils.is_same_or_equivalent_data_type(my_dt.as_ref(), other_dt.as_ref())
    }

    fn is_undefined(&self) -> bool {
        self.data_type.is_default_data_type()
    }
}

impl InternalDataTypeComponent for DataTypeComponentImpl {
    fn set_data_type(&mut self, data_type: Box<dyn DataType>) {
        // intended for internal use only - note existing settings should be preserved
        self.data_type = Arc::from(data_type);
    }

    fn update(&mut self, ordinal: i32, offset: i32, length: i32) {
        self.ordinal = ordinal;
        self.offset = offset;
        self.length = length;
    }
}

impl std::fmt::Display for DataTypeComponentImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", crate::program::model::data::internal_data_type_component::to_string(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::composite_internal::CompositeInternal;
    use crate::program::model::data::data_type_manager::DataTypeManager;

    struct MockSettings;
    impl Settings for MockSettings {}

    #[derive(Clone)]
    struct MockLeaf {
        name: String,
        default_flag: bool,
    }

    impl DataType for MockLeaf {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.name == dt.get_name()
        }
        fn is_default_data_type(&self) -> bool {
            self.default_flag
        }
        fn get_default_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }
    }

    fn leaf(name: &str) -> Box<dyn DataType> {
        Box::new(MockLeaf { name: name.to_string(), default_flag: false })
    }

    struct MockDataTypeManager {
        allows_default_component_settings: bool,
    }
    impl DataTypeManager for MockDataTypeManager {
        fn allows_default_component_settings(&self) -> bool {
            self.allows_default_component_settings
        }
    }

    struct MockParent {
        dtm: Option<Arc<MockDataTypeManager>>,
    }
    impl DataType for MockParent {
        fn get_name(&self) -> String {
            "parent".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_data_type_manager(&self) -> Option<Box<dyn DataTypeManager>> {
            self.dtm.clone().map(|dtm| Box::new(SharedDtm(dtm)) as Box<dyn DataTypeManager>)
        }
    }

    // Thin owned-handle wrapper so `MockParent::get_data_type_manager` can hand back a
    // `Box<dyn DataTypeManager>` sharing the same underlying `Arc<MockDataTypeManager>`.
    struct SharedDtm(Arc<MockDataTypeManager>);
    impl DataTypeManager for SharedDtm {
        fn allows_default_component_settings(&self) -> bool {
            self.0.allows_default_component_settings()
        }
    }

    impl Composite for MockParent {
        fn is_packing_enabled(&self) -> bool {
            false
        }
    }
    impl CompositeInternal for MockParent {}
    impl CompositeDataTypeImpl for MockParent {
        fn stored_description(&self) -> String {
            String::new()
        }
        fn set_stored_description(&mut self, _description: String) {}
        fn stored_minimum_alignment_value(&self) -> i32 {
            0
        }
        fn set_stored_minimum_alignment_value(&mut self, _minimum_alignment: i32) {}
        fn stored_packing_value(&self) -> i32 {
            0
        }
        fn set_stored_packing_value_raw(&mut self, _packing: i32) {}
        fn set_stored_name(&mut self, _name: String) {}
        fn composite_impl_has_language_dependant_length(&self) -> bool {
            false
        }
        fn repack_with_notify(&mut self, _notify: bool) -> bool {
            false
        }
        fn composite_impl_alignment(&self) -> i32 {
            1
        }
        fn for_each_defined_component(&self, _consumer: &mut dyn FnMut(&dyn DataTypeComponent)) {}
        fn composite_impl_add_with_length_and_name(
            &mut self,
            _data_type: Box<dyn DataType>,
            _length: i32,
            _field_name: Option<String>,
            _comment: Option<String>,
        ) -> Result<Box<dyn DataTypeComponent>, String> {
            Err("not exercised by these tests".to_string())
        }
        fn composite_impl_insert_with_length_and_name(
            &mut self,
            _ordinal: i32,
            _data_type: Box<dyn DataType>,
            _length: i32,
            _field_name: Option<String>,
            _comment: Option<String>,
        ) -> Result<Box<dyn DataTypeComponent>, String> {
            Err("not exercised by these tests".to_string())
        }
        fn composite_impl_validate_data_type(
            &self,
            data_type: Box<dyn DataType>,
        ) -> Result<Box<dyn DataType>, String> {
            Ok(data_type)
        }
        fn composite_impl_update_bit_field_data_type(
            &mut self,
            _bitfield_component: Box<dyn DataTypeComponent>,
            _old_dt: &dyn DataType,
            _new_dt: Option<&dyn DataType>,
        ) -> Result<bool, String> {
            Err("not exercised by these tests".to_string())
        }
    }

    fn parent_allowing(allows: bool) -> Arc<dyn CompositeDataTypeImpl> {
        Arc::new(MockParent { dtm: Some(Arc::new(MockDataTypeManager { allows_default_component_settings: allows })) })
    }

    fn parent_no_manager() -> Arc<dyn CompositeDataTypeImpl> {
        Arc::new(MockParent { dtm: None })
    }

    fn component(length: i32, ordinal: i32, offset: i32) -> DataTypeComponentImpl {
        DataTypeComponentImpl::new_unnamed(leaf("byte"), Some(parent_allowing(false)), length, ordinal, offset)
    }

    #[test]
    fn basic_getters() {
        let c = component(4, 2, 8);
        assert_eq!(c.get_offset(), 8);
        assert_eq!(c.get_ordinal(), 2);
        assert_eq!(c.get_length(), 4);
        assert_eq!(c.get_end_offset(), 11);
    }

    #[test]
    fn zero_length_end_offset_equals_offset() {
        let c = component(0, 0, 10);
        assert_eq!(c.get_length(), 0);
        assert_eq!(c.get_end_offset(), 10);
    }

    #[test]
    fn contains_offset() {
        let c = component(4, 0, 10);
        assert!(c.contains_offset(10));
        assert!(c.contains_offset(12));
        assert!(!c.contains_offset(14));
        assert!(!c.contains_offset(9));
    }

    #[test]
    fn field_name_has_no_lazy_default_unlike_read_only_sibling() {
        let c = component(4, 3, 0x10);
        assert_eq!(c.get_field_name(), None);
    }

    #[test]
    fn set_field_name_mutates_in_place_and_returns_updated_snapshot() {
        let c = component(4, 1, 0);
        let updated = c.set_field_name(Some("custom name".to_string()));
        // The original component itself was mutated (RefCell), not just the returned copy.
        assert_eq!(c.get_field_name(), Some("custom_name".to_string()));
        assert_eq!(updated.get_field_name(), Some("custom_name".to_string()));
    }

    #[test]
    fn set_comment_blank_is_cleared_to_none() {
        let c = component(4, 0, 0);
        c.set_comment(Some("  ".to_string()));
        assert_eq!(c.get_comment(), None);

        c.set_comment(Some("hello".to_string()));
        assert_eq!(c.get_comment(), Some("hello".to_string()));
    }

    #[test]
    fn get_data_type_and_parent() {
        let c = component(1, 0, 0);
        assert_eq!(c.get_data_type().get_name(), "byte");
        assert_eq!(c.get_parent().get_name(), "parent");
    }

    #[test]
    fn get_parent_without_parent_uses_stand_in() {
        let c = DataTypeComponentImpl::new_unnamed(leaf("byte"), None, 1, 0, 0);
        // No panic, and a real (if empty) DataType is returned.
        assert_eq!(c.get_parent().get_name(), "");
    }

    #[test]
    fn default_settings_immutability_follows_data_type_manager() {
        let restrictive = DataTypeComponentImpl::new_unnamed(leaf("byte"), Some(parent_allowing(false)), 1, 0, 0);
        assert!(restrictive.get_default_settings().is_immutable_settings());

        let permissive = DataTypeComponentImpl::new_unnamed(leaf("byte"), Some(parent_allowing(true)), 1, 0, 0);
        assert!(!permissive.get_default_settings().is_immutable_settings());
    }

    #[test]
    fn default_settings_immutable_when_parent_has_no_data_type_manager() {
        let c = DataTypeComponentImpl::new_unnamed(leaf("byte"), Some(parent_no_manager()), 1, 0, 0);
        assert!(c.get_default_settings().is_immutable_settings());
    }

    #[test]
    fn invalidate_settings_forces_recomputation() {
        let c = component(1, 0, 0);
        let _ = c.get_default_settings();
        c.invalidate_settings();
        // Must not panic, and should still produce a usable settings object.
        assert!(c.get_default_settings().is_immutable_settings());
    }

    #[test]
    fn update_special_replaces_data_type_name_and_comment() {
        let mut c = component(4, 0, 0);
        c.update_special(Some("renamed".to_string()), leaf("word"), Some("note".to_string()));
        assert_eq!(c.get_data_type().get_name(), "word");
        assert_eq!(c.get_field_name(), Some("renamed".to_string()));
        assert_eq!(c.get_comment(), Some("note".to_string()));
    }

    #[test]
    fn internal_update_sets_ordinal_offset_and_length() {
        let mut c = component(4, 0, 0);
        InternalDataTypeComponent::update(&mut c, 5, 20, 8);
        assert_eq!(c.get_ordinal(), 5);
        assert_eq!(c.get_offset(), 20);
        assert_eq!(c.get_length(), 8);
    }

    #[test]
    fn set_data_type_replaces_the_data_type() {
        let mut c = component(1, 0, 0);
        c.set_data_type(leaf("dword"));
        assert_eq!(c.get_data_type().get_name(), "dword");
    }

    #[test]
    fn setters_for_offset_length_ordinal() {
        let mut c = component(1, 0, 0);
        c.set_offset(4);
        c.set_length(8);
        c.set_ordinal(2);
        assert_eq!(c.get_offset(), 4);
        assert_eq!(c.get_length(), 8);
        assert_eq!(c.get_ordinal(), 2);
    }

    #[test]
    fn is_undefined_reflects_default_data_type() {
        let default_dt = Box::new(MockLeaf { name: "undefined".to_string(), default_flag: true });
        let c = DataTypeComponentImpl::new_unnamed(default_dt, Some(parent_allowing(false)), 1, 0, 0);
        assert!(c.is_undefined());
    }

    #[test]
    fn is_equivalent_true_for_matching_components() {
        let a = component(4, 2, 8);
        let b = component(4, 2, 8);
        assert!(a.is_equivalent(&b));
    }

    #[test]
    fn is_equivalent_false_when_offset_differs() {
        let a = component(4, 2, 8);
        let b = component(4, 2, 12);
        assert!(!a.is_equivalent(&b));
    }

    #[test]
    fn is_equivalent_ignores_length_for_non_dynamic_types() {
        let a = component(4, 0, 0);
        let b = component(8, 0, 0);
        // MockLeaf is not Dynamic, so a length mismatch alone should not break equivalence.
        assert!(a.is_equivalent(&b));
    }

    #[test]
    fn components_equal_matches_structurally_identical_components() {
        let a = component(4, 2, 8);
        let b = component(4, 2, 8);
        assert!(a.components_equal(&b));
    }

    #[test]
    fn components_equal_false_when_offset_differs() {
        let a = component(4, 2, 8);
        let b = component(4, 2, 12);
        assert!(!a.components_equal(&b));
    }

    #[test]
    fn check_default_field_name_rejects_decimal_default_style() {
        assert!(check_default_field_name("field3").is_err());
    }

    #[test]
    fn check_default_field_name_rejects_legacy_hex_offset_style() {
        // The legacy "field_0xHEX" form (no ordinal digits) is reserved...
        assert!(check_default_field_name("field_0x10").is_err());
        // ...but the "new style" `fieldN_0xHEX` form (with ordinal digits before "_0x") is not:
        // `subname.startsWith("_0x")` only matches when "_0x" immediately follows the prefix, so
        // Java's own `checkDefaultFieldName` never actually recognizes this newer format either.
        assert!(check_default_field_name("field1_0x10").is_ok());
    }

    #[test]
    fn check_default_field_name_accepts_non_reserved_names() {
        assert!(check_default_field_name("myField").is_ok());
        assert!(check_default_field_name("field").is_ok()); // empty subname is fine
        assert!(check_default_field_name("fieldxyz").is_ok()); // non-numeric subname
    }

    #[test]
    fn get_preferred_component_length_uses_data_type_length_when_unconstrained() {
        let dt = MockLeaf { name: "byte".to_string(), default_flag: false };
        struct FixedLen(MockLeaf, i32);
        impl DataType for FixedLen {
            fn get_name(&self) -> String {
                self.0.get_name()
            }
            fn get_length(&self) -> i32 {
                self.1
            }
        }
        let dt = FixedLen(dt, 4);
        assert_eq!(get_preferred_component_length(&dt, 0).unwrap(), 4);
    }

    #[test]
    fn get_preferred_component_length_errors_when_no_positive_length_available() {
        struct NoLength;
        impl DataType for NoLength {
            fn get_length(&self) -> i32 {
                -1
            }
        }
        assert!(get_preferred_component_length(&NoLength, 0).is_err());
    }

    #[test]
    fn display_matches_internal_to_string() {
        let c = component(4, 1, 8);
        let displayed = format!("{c}");
        assert!(displayed.contains("byte"));
    }
}
