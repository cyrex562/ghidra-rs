//! Port of `ghidra.program.model.data.ArrayDataType`: basic implementation of the [`Array`]
//! interface.
//!
//! NOTE: The use of `FactoryDataType` and [`Dynamic`](crate::program::model::data::dynamic::Dynamic),
//! where `Dynamic::can_specify_length()` is `false`, are not supported for array use.
//!
//! # Fidelity notes
//!
//! Java's `ArrayDataType extends DataTypeImpl`. This port implements [`DataType`] + [`Array`]
//! directly instead of also implementing
//! [`DataTypeImpl`](crate::program::model::data::data_type_impl::DataTypeImpl): every
//! `DataTypeImpl`-mediated method Java's `ArrayDataType` would otherwise inherit
//! (`getUniversalID` aside -- see below -- plus `addParent`/`removeParent`/`getParents`/
//! `hashCode`/`equals`/`getDefaultSettings`/`getSourceArchive`/`setSourceArchive`/
//! `setLastChangeTime*`/`replaceWith`/`setDescription`/`checkValidName`) is never actually called
//! by `ArrayDataType.java` itself, and `DataType`'s own defaults for all of them are already
//! reasonable (empty parent list, placeholder settings, etc.), so pulling in that whole cut-point
//! trait would only add unused machinery. `getAlignment()` is *not* overridden by Java's
//! `ArrayDataType` either (it relies on `DataTypeImpl`'s real, `DataOrganization`-based
//! computation) -- this port keeps [`DataType::get_alignment`]'s default (`1`) instead, a real,
//! narrow fidelity gap tied to the next point.
//!
//! No `DataTypeManager` is retained as a field: `ArrayDataType`'s three Java constructors all
//! accept one, but this port only ever uses it transiently (accepted for constructor-signature
//! parity, never stored) since [`DataType::clone_data_type`]'s default in this crate is a
//! non-functional `EmptyDataType` placeholder for every leaf `DataType` that hasn't specifically
//! overridden it (i.e., essentially every already-ported leaf `DataType` in this crate today) --
//! faithfully replicating `dataType = dataType.clone(getDataTypeManager())`'s re-association step
//! against that placeholder would silently corrupt the element type. Using the caller's own
//! element type instance directly instead preserves the same practical outcome for the common
//! "clone returns something equivalent" case without that corruption risk. Because of this,
//! [`ArrayDataType::clone_data_type`]/[`copy_data_type`](DataType::copy_data_type) always
//! reconstruct a fresh, equivalent `ArrayDataType` around the *same* element type reference
//! (sharing the `Arc`) rather than attempting `dtm`-based re-resolution or an identity fast path
//! (`if (dtm == getDataTypeManager()) return this;` can't return `self` from `&self` regardless).
//!
//! `getUniversalID()` *is* given real, generated-once-at-construction storage (mirroring the
//! `next_universal_id()` convention already established in
//! [`PointerTypedef`](super::pointer_typedef)), even though it technically comes from
//! `DataTypeImpl` in Java, since it is cheap, meaningfully used elsewhere (e.g.
//! `DataTypeUtilities::is_same_data_type`), and needs no other `DataTypeImpl` machinery to
//! support.
//!
//! `name` is computed once at construction (`DataTypeUtilities.getName(this, true)`) and never
//! recomputed afterward -- matching Java exactly: `setName` is an explicit no-op ("unsupported -
//! ignore"), and `dataTypeReplaced` never reassigns the `name` field either, despite computing and
//! comparing an `oldName` local for its `notifyNameChanged` check. That comparison is therefore
//! *always* false in the real Java class too (a likely latent no-op/bug in the upstream source),
//! which this port does not attempt to "fix".
//!
//! `dataTypeSizeChanged`/`dataTypeAlignmentChanged`/`dataTypeDeleted` are ported for real (their
//! observable state changes -- `elementLength`, the `deleted` flag -- only ever need to read
//! `self.data_type`, not the borrowed `dt` parameter's data), *except* for their
//! `notifySizeChanged`/`notifyAlignmentChanged`/`notifyDeleted` broadcasts to this array's own
//! parents, which are skipped for the same reason
//! [`DataTypeImpl`](crate::program::model::data::data_type_impl::DataTypeImpl)'s module docs give
//! for not porting that notification chain at all (soundly reaching a parent through only a
//! [`Weak`](std::sync::Weak) back-reference is provably impossible without a project-wide
//! interior-mutability convention this crate does not yet have). `dataTypeNameChanged` is left as
//! [`DataType`]'s default no-op, since -- per the point above -- there is nothing else it could
//! observably do here. `dataTypeReplaced` is also left as the default no-op: unlike the other
//! four, its entire *purpose* is to replace `self.data_type` with the `new_dt: &dyn DataType`
//! parameter, but that parameter is only ever a *borrow*, and this crate has no generic way to
//! turn a borrowed `dyn DataType` into an owned, storable `Arc<dyn DataType>` (no `Clone`-like
//! capability exists on the trait) -- implementing a version that updates some fields (like
//! `element_length`) without actually retargeting `data_type` would leave the two inconsistent,
//! which is worse than doing nothing.

use std::any::{Any, TypeId};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::database::data::data_type_utilities::DataTypeUtilities;
use crate::program::model::data::array::{Array, ARRAY_LABEL_PREFIX};
use crate::program::model::data::category_path::CategoryPath;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::typedef_settings_definition::TypeDefSettingsDefinition;
use crate::program::model::mem::MemBuffer;
use crate::program::seam_stubs::share_data_type;
use crate::util::UniversalID;

/// Zero-sized marker used purely to call the defaulted trait methods of [`DataTypeUtilities`]
/// (a `&dyn Trait`-object seam -- see its own module docs). Mirrors the identical marker in
/// `read_only_data_type_component.rs`/`data_type_component_impl.rs`/`pointer_typedef.rs`/
/// `typedef_data_type.rs`.
#[derive(Debug, Default, Clone, Copy)]
struct Utils;
impl DataTypeUtilities for Utils {}

/// Process-local substitute for `ghidra.util.UniversalIdGenerator.nextID()`, which has no port in
/// this crate. Not a port of any specific Java class; only guarantees uniqueness within a single
/// process run, unlike the real generator's cross-session persistence guarantees. Mirrors the
/// identical helper in `pointer_typedef.rs`.
fn next_universal_id() -> UniversalID {
    static COUNTER: AtomicI64 = AtomicI64::new(1);
    UniversalID::new(COUNTER.fetch_add(1, Ordering::Relaxed))
}

/// Port of the private static `ArrayDataType.validate(DataType)`.
///
/// Validate an array base datatype to ensure that it is allowed. `base_dt` should always be the
/// typedef's base type already stripped away, if applicable.
///
/// # Errors
/// Returns `Err` if `base_dt` is not a valid base datatype for an array (mirrors
/// `IllegalArgumentException`).
fn validate_array_base(base_dt: &dyn DataType) -> Result<(), String> {
    if base_dt.as_bit_field().is_some() {
        return Err(format!(
            "IllegalArgumentException: Array data-type may not be a bitfield: {}",
            base_dt.get_name()
        ));
    }
    if base_dt.as_factory().is_some() {
        return Err(format!(
            "IllegalArgumentException: Array data-type may not be a Factory data-type: {}",
            base_dt.get_name()
        ));
    }
    if let Some(dynamic) = base_dt.as_dynamic() {
        if !dynamic.can_specify_length() {
            return Err(format!(
                "IllegalArgumentException: Array data-type may not be a non-sizable Dynamic data-type: {}",
                base_dt.get_name()
            ));
        }
    } else if base_dt.get_length() < 1 {
        // No reflection equivalent for `baseDt.getClass().getSimpleName()`; approximated by name.
        return Err(format!(
            "IllegalArgumentException: Data type may not report a length less than 1: {}",
            base_dt.get_name()
        ));
    }
    Ok(())
}

/// Basic implementation of the [`Array`] interface.
///
/// Port of `ghidra.program.model.data.ArrayDataType`. See the module docs for what was ported,
/// simplified, and (deliberately, and for documented reasons) left as a gap.
pub struct ArrayDataType {
    data_type: Arc<dyn DataType>,
    num_elements: i32,
    element_length: i32,
    deleted: bool,
    name: String,
    universal_id: UniversalID,
}

impl ArrayDataType {
    /// Constructs a new Array dataType for fixed-length datatypes.
    ///
    /// # Arguments
    /// * `data_type` - the dataType of the elements in the array (`FactoryDataType` and
    ///   [`Dynamic`](crate::program::model::data::dynamic::Dynamic) data types are not permitted)
    /// * `num_elements` - the number of elements in the array (`0` is permitted)
    ///
    /// # Errors
    /// Returns `Err` if an invalid datatype is specified or a valid `element_length` is required
    /// (mirrors `IllegalArgumentException`).
    pub fn new(data_type: Box<dyn DataType>, num_elements: i32) -> Result<Self, String> {
        Self::with_element_length(data_type, num_elements, -1)
    }

    /// Constructs a new Array dataType.
    ///
    /// # Arguments
    /// * `data_type` - the dataType of the elements in the array
    /// * `num_elements` - the number of elements in the array (`0` is permitted)
    /// * `element_length` - the length of an individual element in the array. Only used for a
    ///   [`Dynamic`](crate::program::model::data::dynamic::Dynamic) dataType where
    ///   `can_specify_length()` returns `true`. A negative value can be specified for
    ///   fixed-length datatypes.
    ///
    /// # Errors
    /// Returns `Err` if an invalid datatype is specified or a valid `element_length` is required
    /// (mirrors `IllegalArgumentException`).
    pub fn with_element_length(
        data_type: Box<dyn DataType>,
        num_elements: i32,
        element_length: i32,
    ) -> Result<Self, String> {
        Self::with_manager(data_type, num_elements, element_length, None)
    }

    /// Constructs a new Array dataType.
    ///
    /// # Arguments
    /// * `data_type` - the dataType of the elements in the array
    /// * `num_elements` - the number of elements in the array (`0` is permitted)
    /// * `element_length` - the length of an individual element in the array, as above
    /// * `data_mgr` - datatype manager, accepted for signature parity with the Java constructor
    ///   but not retained -- see the module docs for why
    ///
    /// # Errors
    /// Returns `Err` if an invalid datatype is specified or a valid `element_length` is required
    /// (mirrors `IllegalArgumentException`).
    pub fn with_manager(
        data_type: Box<dyn DataType>,
        num_elements: i32,
        element_length: i32,
        data_mgr: Option<Box<dyn DataTypeManager>>,
    ) -> Result<Self, String> {
        let _ = data_mgr;

        if data_type.as_factory().is_some() {
            return Err("IllegalArgumentException: Factory data type not permitted".to_string());
        }
        if num_elements < 0 {
            return Err(format!(
                "IllegalArgumentException: Number of array elements may not be negative [{num_elements}]"
            ));
        }

        let base_dt_owned = data_type.typedef_base_data_type();
        let base_dt: &dyn DataType = base_dt_owned.as_deref().unwrap_or(data_type.as_ref());
        validate_array_base(base_dt)?;

        let resolved_element_length = if let Some(dynamic) = base_dt.as_dynamic() {
            if element_length < 0 {
                return Err(format!(
                    "IllegalArgumentException: Must specify Array element-length for dynamic {}",
                    base_dt.get_name()
                ));
            }
            let _ = dynamic;
            element_length
        } else {
            data_type.get_aligned_length()
        };

        let data_type: Arc<dyn DataType> = Arc::from(data_type);
        let mut array = ArrayDataType {
            data_type,
            num_elements,
            element_length: resolved_element_length,
            deleted: false,
            name: String::new(),
            universal_id: next_universal_id(),
        };
        array.name = Utils.get_array_name(&array, true);
        Ok(array)
    }

    /// Notification that the given datatype's size has changed. Real (`element_length`
    /// recomputation), except the broadcast to this array's own parents -- see the module docs.
    pub fn data_type_size_changed(&mut self, dt: &dyn DataType) {
        if self.matches_element(dt) && dt.get_length() > 0 {
            self.element_length = self.data_type.get_aligned_length();
        }
    }

    /// Notification that the given datatype's alignment has changed. See
    /// [`data_type_size_changed`](Self::data_type_size_changed) and the module docs for the
    /// skipped broadcast.
    pub fn data_type_alignment_changed(&mut self, dt: &dyn DataType) {
        let _ = dt;
        // Nothing else to recompute here; the broadcast itself is skipped (see module docs).
    }

    /// Informs this datatype that the given datatype has been deleted.
    pub fn data_type_deleted(&mut self, dt: &dyn DataType) {
        if self.matches_element(dt) {
            self.deleted = true;
        }
    }

    /// Approximates Java's `dt == dataType` reference-equality check against this array's element
    /// type. Raw pointer identity (as used elsewhere in this crate, e.g.
    /// `DataTypeImpl::data_type_impl_remove_parent`) is deliberately *not* used here: this
    /// struct's own [`Array::get_data_type`]/`DataType::depends_on` callers routinely obtain their
    /// `dt` via [`share_data_type`], which always allocates a fresh wrapper object around the
    /// shared `Arc` -- so a genuinely-the-same element would still compare unequal by address. Two
    /// -directional [`DataType::is_equivalent`] is the same substitution
    /// [`crate::program::database::data::data_type_utilities`]'s own module docs already establish
    /// for this exact "no general reference-identity facility exists for `dyn DataType`" problem.
    fn matches_element(&self, dt: &dyn DataType) -> bool {
        self.data_type.is_equivalent(dt) || dt.is_equivalent(self.data_type.as_ref())
    }
}

impl DataType for ArrayDataType {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_category_path(&self) -> CategoryPath {
        self.data_type.get_category_path()
    }

    fn get_description(&self) -> String {
        format!("Array of {}", self.data_type.get_display_name())
    }

    fn has_language_dependant_length(&self) -> bool {
        self.data_type.has_language_dependant_length()
    }

    fn get_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        // NOTE: it may be necessary to allow array-specific settings at some point to
        // facilitate appropriate char array string generation.
        self.data_type.get_settings_definitions()
    }

    fn get_type_def_settings_definitions(&self) -> Vec<Box<dyn TypeDefSettingsDefinition>> {
        self.data_type.get_type_def_settings_definitions()
    }

    fn is_equivalent(&self, obj: &dyn DataType) -> bool {
        // A direct reflexive reference (`arr.is_equivalent(&arr)`) compares equal by address;
        // unlike `matches_element`'s callers, nothing here routes `obj` through `share_data_type`
        // first, so raw pointer identity is safe (and cheaper) for this particular fast path.
        if std::ptr::eq(self as *const ArrayDataType as *const (), obj as *const dyn DataType as *const ()) {
            return true;
        }
        let Some(array) = obj.as_array() else {
            return false;
        };
        if self.num_elements != array.get_num_elements() {
            return false;
        }
        if !self.data_type.is_equivalent(array.get_data_type().as_ref()) {
            return false;
        }
        if self.data_type.as_dynamic().is_some() && self.element_length != array.get_element_length() {
            return false;
        }
        true
    }

    fn get_mnemonic(&self, settings: &dyn Settings) -> String {
        Utils.get_array_mnemonic(self, false, settings)
    }

    fn is_zero_length(&self) -> bool {
        self.num_elements == 0
    }

    fn get_length(&self) -> i32 {
        if self.num_elements == 0 {
            1 // 0-length datatype instance not supported
        } else {
            self.num_elements * self.element_length
        }
    }

    fn get_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        self.get_array_value_class(settings)
    }

    fn get_default_label_prefix(&self) -> Option<String> {
        if self.data_type.is_default_data_type() {
            return Some(ARRAY_LABEL_PREFIX.to_string());
        }
        Some(format!(
            "{}_{}",
            self.data_type.get_default_label_prefix().unwrap_or_default(),
            ARRAY_LABEL_PREFIX
        ))
    }

    fn get_default_label_prefix_for_data(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        len: i32,
        options: &dyn DataTypeDisplayOptions,
    ) -> Option<String> {
        self.get_array_default_label_prefix(buf, settings, len, options)
    }

    fn get_default_offcut_label_prefix(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        len: i32,
        options: &dyn DataTypeDisplayOptions,
        offcut_length: i32,
    ) -> Option<String> {
        self.get_array_default_offcut_label_prefix(buf, settings, len, options, offcut_length)
    }

    fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
        self.get_array_value(buf, settings, length)
    }

    fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        self.get_array_representation(buf, settings, length)
    }

    fn depends_on(&self, dt: &dyn DataType) -> bool {
        self.matches_element(dt) || self.data_type.depends_on(dt)
    }

    fn is_deleted(&self) -> bool {
        self.deleted
    }

    fn is_array(&self) -> bool {
        true
    }

    fn as_array(&self) -> Option<&dyn Array> {
        Some(self)
    }

    fn into_array(self: Box<Self>) -> Option<Box<dyn Array>> {
        Some(self)
    }

    fn get_universal_id(&self) -> UniversalID {
        self.universal_id
    }

    fn clone_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        let _ = dtm;
        let cloned = ArrayDataType::with_manager(
            share_data_type(&self.data_type),
            self.num_elements,
            self.element_length,
            None,
        )
        .expect("re-cloning an already-valid ArrayDataType should not fail validation");
        Box::new(cloned)
    }

    fn copy_data_type(&self, dtm: &dyn DataTypeManager) -> Box<dyn DataType> {
        self.clone_data_type(dtm)
    }

    fn data_type_size_changed(&mut self, dt: &dyn DataType) {
        ArrayDataType::data_type_size_changed(self, dt);
    }

    fn data_type_alignment_changed(&mut self, dt: &dyn DataType) {
        ArrayDataType::data_type_alignment_changed(self, dt);
    }

    fn data_type_deleted(&mut self, dt: &dyn DataType) {
        ArrayDataType::data_type_deleted(self, dt);
    }
}

impl Array for ArrayDataType {
    fn get_num_elements(&self) -> i32 {
        self.num_elements
    }

    fn get_element_length(&self) -> i32 {
        self.element_length
    }

    fn get_data_type(&self) -> Box<dyn DataType> {
        share_data_type(&self.data_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::category_path::ROOT;
    use crate::program::model::data::dynamic::Dynamic;
    use crate::program::model::data::data_type_display_options::DEFAULT as DEFAULT_DISPLAY_OPTIONS;
    use crate::program::model::mem::MemoryAccessException;

    struct MockSettings;
    impl Settings for MockSettings {}

    #[derive(Clone)]
    struct MockLeaf {
        name: String,
        length: i32,
        default_flag: bool,
    }

    impl DataType for MockLeaf {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_display_name(&self) -> String {
            self.name.clone()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_default_data_type(&self) -> bool {
            self.default_flag
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.name == dt.get_name() && self.length == dt.get_length()
        }
        fn get_default_label_prefix(&self) -> Option<String> {
            Some(self.name.clone())
        }
    }

    fn leaf(name: &str, length: i32) -> Box<dyn DataType> {
        Box::new(MockLeaf { name: name.to_string(), length, default_flag: false })
    }

    struct MockDynamicLeaf {
        name: String,
        can_specify: bool,
    }
    impl DataType for MockDynamicLeaf {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn as_dynamic(&self) -> Option<&dyn Dynamic> {
            Some(self)
        }
    }
    impl crate::program::model::data::built_in_data_type::BuiltInDataType for MockDynamicLeaf {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&crate::program::model::data::data_organization_impl::DataOrganizationImpl>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }
    impl Dynamic for MockDynamicLeaf {
        fn get_dynamic_length(&self, _buf: &dyn MemBuffer, _max_length: i32) -> i32 {
            -1
        }
        fn can_specify_length(&self) -> bool {
            self.can_specify
        }
        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            leaf("byte", 1)
        }
    }

    struct FixedMemBuffer(Vec<u8>);
    impl MemBuffer for FixedMemBuffer {
        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            let start = offset as usize;
            let mut n = 0;
            for (i, slot) in buf.iter_mut().enumerate() {
                match self.0.get(start + i) {
                    Some(&b) => {
                        *slot = b;
                        n += 1;
                    }
                    None => break,
                }
            }
            n
        }
        fn is_big_endian(&self) -> bool {
            true
        }
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.0
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
    }

    #[test]
    fn new_computes_length_from_num_elements_and_element_length() {
        let arr = ArrayDataType::new(leaf("byte", 1), 4).unwrap();
        assert_eq!(arr.get_num_elements(), 4);
        assert_eq!(arr.get_element_length(), 1);
        assert_eq!(arr.get_length(), 4);
    }

    #[test]
    fn zero_elements_reports_length_one() {
        let arr = ArrayDataType::new(leaf("byte", 1), 0).unwrap();
        assert!(arr.is_zero_length());
        assert_eq!(arr.get_length(), 1);
    }

    #[test]
    fn negative_num_elements_is_rejected() {
        assert!(ArrayDataType::new(leaf("byte", 1), -1).is_err());
    }

    #[test]
    fn factory_data_type_is_rejected() {
        use crate::program::model::data::built_in_data_type::BuiltInDataType;
        use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
        use crate::program::model::data::factory_data_type::FactoryDataType;

        struct Marker;
        impl DataType for Marker {}
        impl BuiltInDataType for Marker {
            fn get_c_type_declaration(&self, _data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
                None
            }
            fn set_default_settings(&mut self, _settings: &dyn Settings) {}
        }
        impl FactoryDataType for Marker {
            fn get_data_type(&self, _buf: &dyn MemBuffer) -> Box<dyn DataType> {
                Box::new(Marker)
            }
        }

        struct MockFactory(Marker);
        impl DataType for MockFactory {
            fn as_factory(&self) -> Option<&dyn FactoryDataType> {
                Some(&self.0)
            }
        }

        let result = ArrayDataType::new(Box::new(MockFactory(Marker)), 1);
        assert!(result.is_err());
    }

    #[test]
    fn zero_length_element_is_rejected() {
        assert!(ArrayDataType::new(leaf("empty", 0), 1).is_err());
    }

    #[test]
    fn non_sizable_dynamic_element_is_rejected() {
        let dyn_leaf = Box::new(MockDynamicLeaf { name: "dyn".to_string(), can_specify: false });
        assert!(ArrayDataType::new(dyn_leaf, 1).is_err());
    }

    #[test]
    fn sizable_dynamic_element_requires_positive_element_length() {
        let dyn_leaf = Box::new(MockDynamicLeaf { name: "dyn".to_string(), can_specify: true });
        assert!(ArrayDataType::with_element_length(dyn_leaf, 1, -1).is_err());

        let dyn_leaf2 = Box::new(MockDynamicLeaf { name: "dyn".to_string(), can_specify: true });
        let arr = ArrayDataType::with_element_length(dyn_leaf2, 3, 5).unwrap();
        assert_eq!(arr.get_element_length(), 5);
        assert_eq!(arr.get_length(), 15);
    }

    #[test]
    fn description_mentions_element_display_name() {
        let arr = ArrayDataType::new(leaf("byte", 1), 4).unwrap();
        assert_eq!(arr.get_description(), "Array of byte");
    }

    #[test]
    fn name_includes_dimensions() {
        let arr = ArrayDataType::new(leaf("byte", 1), 4).unwrap();
        assert_eq!(arr.get_name(), "byte[4]");
    }

    #[test]
    fn nested_array_name_includes_all_dimensions() {
        let inner = ArrayDataType::new(leaf("byte", 1), 3).unwrap();
        let outer = ArrayDataType::new(Box::new(inner), 2).unwrap();
        assert_eq!(outer.get_name(), "byte[2][3]");
    }

    #[test]
    fn is_equivalent_true_for_matching_arrays() {
        let a = ArrayDataType::new(leaf("byte", 1), 4).unwrap();
        let b = ArrayDataType::new(leaf("byte", 1), 4).unwrap();
        assert!(a.is_equivalent(&b));
    }

    #[test]
    fn is_equivalent_false_for_different_num_elements() {
        let a = ArrayDataType::new(leaf("byte", 1), 4).unwrap();
        let b = ArrayDataType::new(leaf("byte", 1), 5).unwrap();
        assert!(!a.is_equivalent(&b));
    }

    #[test]
    fn is_equivalent_false_for_non_array() {
        let a = ArrayDataType::new(leaf("byte", 1), 4).unwrap();
        assert!(!a.is_equivalent(leaf("byte", 1).as_ref()));
    }

    #[test]
    fn is_equivalent_reflexive_via_reference_identity() {
        let a = ArrayDataType::new(leaf("byte", 1), 4).unwrap();
        assert!(a.is_equivalent(&a));
    }

    #[test]
    fn get_value_class_delegates_to_array_trait() {
        let arr = ArrayDataType::new(leaf("byte", 1), 4).unwrap();
        assert_eq!(DataType::get_value_class(&arr, &MockSettings), arr.get_array_value_class(&MockSettings));
    }

    #[test]
    fn default_label_prefix_appends_array_suffix() {
        let arr = ArrayDataType::new(leaf("byte", 1), 4).unwrap();
        assert_eq!(arr.get_default_label_prefix(), Some("byte_ARRAY".to_string()));
    }

    #[test]
    fn default_label_prefix_is_bare_when_element_is_default_type() {
        let default_dt = Box::new(MockLeaf { name: "undefined".to_string(), length: 1, default_flag: true });
        let arr = ArrayDataType::new(default_dt, 4).unwrap();
        assert_eq!(arr.get_default_label_prefix(), Some("ARRAY".to_string()));
    }

    #[test]
    fn get_universal_id_is_unique_per_instance() {
        let a = ArrayDataType::new(leaf("byte", 1), 1).unwrap();
        let b = ArrayDataType::new(leaf("byte", 1), 1).unwrap();
        assert_ne!(a.get_universal_id(), b.get_universal_id());
    }

    #[test]
    fn is_deleted_initially_false_and_set_by_data_type_deleted() {
        let mut arr = ArrayDataType::new(leaf("byte", 1), 1).unwrap();
        assert!(!arr.is_deleted());
        let element = arr.get_data_type();
        arr.data_type_deleted(element.as_ref());
        assert!(arr.is_deleted());
    }

    #[test]
    fn data_type_deleted_ignores_unrelated_data_type() {
        let mut arr = ArrayDataType::new(leaf("byte", 1), 1).unwrap();
        let other = leaf("word", 2);
        arr.data_type_deleted(other.as_ref());
        assert!(!arr.is_deleted());
    }

    #[test]
    fn data_type_size_changed_recomputes_element_length() {
        let mut arr = ArrayDataType::new(leaf("byte", 1), 4).unwrap();
        assert_eq!(arr.get_element_length(), 1);
        let element = arr.get_data_type();
        arr.data_type_size_changed(element.as_ref());
        // MockLeaf's aligned length falls back to plain length (1), so this is a no-visible-change
        // recomputation, but it must not panic and must still reflect the element's own length.
        assert_eq!(arr.get_element_length(), element.get_aligned_length());
    }

    #[test]
    fn depends_on_true_for_element_type() {
        let arr = ArrayDataType::new(leaf("byte", 1), 4).unwrap();
        let element = arr.get_data_type();
        assert!(arr.depends_on(element.as_ref()));
        assert!(!arr.depends_on(leaf("word", 2).as_ref()));
    }

    #[test]
    fn clone_data_type_produces_an_equivalent_instance() {
        struct MockDataTypeManager;
        impl DataTypeManager for MockDataTypeManager {}

        let arr = ArrayDataType::new(leaf("byte", 1), 4).unwrap();
        let cloned = arr.clone_data_type(&MockDataTypeManager);
        assert!(arr.is_equivalent(cloned.as_ref()));
        assert_ne!(cloned.get_universal_id(), arr.get_universal_id());
    }

    #[test]
    fn representation_and_value_delegate_to_array_trait() {
        let arr = ArrayDataType::new(leaf("byte", 1), 0).unwrap();
        let buf = FixedMemBuffer(vec![]);
        assert_eq!(DataType::get_representation(&arr, &buf, &MockSettings, 0), "");
        assert!(DataType::get_value(&arr, &buf, &MockSettings, 0).is_none());
    }

    #[test]
    fn default_label_prefix_for_data_and_offcut_do_not_panic() {
        let arr = ArrayDataType::new(leaf("byte", 1), 2).unwrap();
        let buf = FixedMemBuffer(vec![0x41, 0x42]);
        let _ = arr.get_default_label_prefix_for_data(&buf, &MockSettings, 2, &DEFAULT_DISPLAY_OPTIONS);
        let _ = arr.get_default_offcut_label_prefix(&buf, &MockSettings, 2, &DEFAULT_DISPLAY_OPTIONS, 1);
    }
}
