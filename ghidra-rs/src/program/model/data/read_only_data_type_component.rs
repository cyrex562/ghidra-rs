//! Port of `ghidra.program.model.data.ReadOnlyDataTypeComponent`: `DataTypeComponent`s from
//! dataTypes that cannot be modified.
//!
//! # Fidelity notes
//!
//! `data_type`/`parent` are stored as `Arc` rather than `Box`, mirroring the established
//! [`share_data_type`](crate::program::seam_stubs::share_data_type) convention (see e.g.
//! [`TypedefDataType`](super::typedef_data_type::TypedefDataType)) for the same reason:
//! [`DataTypeComponent::get_data_type`]/[`DataTypeComponent::get_parent`] must hand back an owned
//! `Box<dyn DataType>` from a `&self` borrow, which requires a cheap, shareable handle rather than
//! sole ownership. [`DynamicDataType`] (the Java constructor's `parent` parameter type) is a
//! supertrait of [`DataType`], so `Arc<dyn DynamicDataType>` upcasts to `Arc<dyn DataType>` for
//! this purpose.
//!
//! `getFieldName()`'s lazy `fieldName = getDefaultFieldName()` cache is reproduced with a
//! [`std::cell::RefCell`], since [`DataTypeComponent::get_field_name`] also takes `&self`.
//!
//! `getDefaultSettings()` lazily builds a `new SettingsImpl(true)` (immutable) whose
//! `defaultSettings` is `dataType.getDefaultSettings()`; `ghidra.docking.settings.SettingsImpl`
//! itself is still `TODO` in `PORT_MANIFEST.tsv` (and is a large, general-purpose class well
//! outside this one component's scope), so this port builds the same *observable* immutable,
//! fallback-delegating settings object directly as [`ReadOnlyComponentSettings`], computed once
//! at construction (rather than lazily, since with no mutable own state the two are
//! indistinguishable to any caller) and cheaply reshared via `Arc` on every
//! [`get_default_settings`](DataTypeComponent::get_default_settings) call, the same `Arc`-sharing
//! trick used for `data_type`/`parent` above.
//!
//! `equals(Object)` (Java's structural `Object.equals` override, used by collections) has no
//! direct counterpart on the [`DataTypeComponent`] trait (which only has
//! [`is_equivalent`](DataTypeComponent::is_equivalent)) and is not exposed here; the field-by-field
//! comparison it performs is folded into an inherent [`ReadOnlyDataTypeComponent::components_equal`]
//! helper instead, kept private since nothing outside this module calls it.
//!
//! `isEquivalent`'s `DataTypeUtilities.isSameOrEquivalentDataType` call uses
//! `ghidra.program.database.data.DataTypeUtilities` (already ported, real, as a `&dyn
//! Trait`-object seam -- see its own module docs), reached the same way
//! [`PointerTypedef`](super::pointer_typedef::PointerTypedef) and
//! [`TypedefDataType`](super::typedef_data_type::TypedefDataType) already do: a private
//! zero-sized `Utils` marker implementing it.

use std::cell::RefCell;
use std::sync::Arc;

use crate::docking::settings::settings::Settings;
use crate::program::database::data::data_type_utilities::DataTypeUtilities;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::dynamic_data_type::DynamicDataType;
use crate::program::seam_stubs::share_data_type;

/// Zero-sized marker used purely to call the defaulted trait methods of [`DataTypeUtilities`]
/// (a `&dyn Trait`-object seam -- see its own module docs). Mirrors the identical marker in
/// `pointer_typedef.rs`/`typedef_data_type.rs`.
#[derive(Debug, Default, Clone, Copy)]
struct Utils;
impl DataTypeUtilities for Utils {}

/// Stand-in for the specific `new SettingsImpl(true)` instance
/// `ReadOnlyDataTypeComponent.getDefaultSettings()` constructs, since the general-purpose
/// `ghidra.docking.settings.SettingsImpl` is not yet ported. See the module docs. Since this
/// settings object is immutable and never itself receives a value, every read accessor simply
/// forwards to the wrapped fallback settings (`dataType.getDefaultSettings()`).
struct ReadOnlyComponentSettings(Arc<dyn Settings>);

impl Settings for ReadOnlyComponentSettings {
    fn is_immutable_settings(&self) -> bool {
        true
    }

    fn is_change_allowed(&self, _settings_definition: &dyn crate::docking::settings::settings_definition::SettingsDefinition) -> bool {
        false
    }

    fn get_long(&self, name: &str) -> Option<i64> {
        self.0.get_long(name)
    }

    fn get_string(&self, name: &str) -> Option<String> {
        self.0.get_string(name)
    }

    fn get_value(&self, name: &str) -> Option<Box<dyn std::any::Any>> {
        self.0.get_value(name)
    }

    fn get_names(&self) -> Vec<String> {
        self.0.get_names()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn get_default_settings(&self) -> Option<Box<dyn Settings>> {
        Some(Box::new(ReadOnlyComponentSettings(self.0.clone())))
    }
}

/// `DataTypeComponent`s from dataTypes that cannot be modified.
///
/// Port of `ghidra.program.model.data.ReadOnlyDataTypeComponent`.
pub struct ReadOnlyDataTypeComponent {
    data_type: Arc<dyn DataType>,
    parent: Arc<dyn DynamicDataType>,
    offset: i32,
    ordinal: i32,
    comment: Option<String>,
    length: i32,
    field_name: RefCell<Option<String>>,
    default_settings: Arc<dyn Settings>,
}

impl ReadOnlyDataTypeComponent {
    /// Create a new `DataTypeComponent`.
    ///
    /// # Arguments
    /// * `data_type` - the dataType for this component
    /// * `parent` - the dataType that this component belongs to
    /// * `length` - the length of the dataType in this component
    /// * `ordinal` - the index of this component in the parent
    /// * `offset` - the byte offset within the parent
    /// * `field_name` - the name associated with this component
    /// * `comment` - the comment associated with this component
    pub fn new(
        data_type: Arc<dyn DataType>,
        parent: Arc<dyn DynamicDataType>,
        length: i32,
        ordinal: i32,
        offset: i32,
        field_name: Option<String>,
        comment: Option<String>,
    ) -> Self {
        let default_settings: Arc<dyn Settings> = Arc::from(data_type.get_default_settings());
        ReadOnlyDataTypeComponent {
            data_type,
            parent,
            offset,
            ordinal,
            comment,
            length,
            field_name: RefCell::new(field_name),
            default_settings,
        }
    }

    /// Create a new `DataTypeComponent` with no field name or comment.
    pub fn new_unnamed(
        data_type: Arc<dyn DataType>,
        parent: Arc<dyn DynamicDataType>,
        length: i32,
        ordinal: i32,
        offset: i32,
    ) -> Self {
        Self::new(data_type, parent, length, ordinal, offset, None, None)
    }

    fn parent_as_data_type(&self) -> Arc<dyn DataType> {
        self.parent.clone()
    }

    /// Port of the private `isSameString(String, String)` helper.
    fn is_same_string(s1: Option<&str>, s2: Option<&str>) -> bool {
        s1 == s2
    }

    /// Port of `ReadOnlyDataTypeComponent.equals(Object)`. See the module docs for why this isn't
    /// exposed as a trait method.
    pub fn components_equal(&self, other: &dyn DataTypeComponent) -> bool {
        let other_data_type = other.get_data_type();
        if self.offset != other.get_offset()
            || self.length != other.get_length()
            || self.ordinal != other.get_ordinal()
            || !self.data_type.is_equivalent(other_data_type.as_ref())
        {
            return false;
        }
        Self::is_same_string(self.get_field_name().as_deref(), other.get_field_name().as_deref())
            && Self::is_same_string(self.comment.as_deref(), other.get_comment().as_deref())
    }
}

impl DataTypeComponent for ReadOnlyDataTypeComponent {
    fn is_bit_field_component(&self) -> bool {
        self.data_type.as_bit_field().is_some()
    }

    fn is_zero_bit_field_component(&self) -> bool {
        self.data_type
            .as_bit_field()
            .map(|bf| bf.get_bit_size() == 0)
            .unwrap_or(false)
    }

    fn get_offset(&self) -> i32 {
        self.offset
    }

    fn get_end_offset(&self) -> i32 {
        // Uses the raw `length` field directly, exactly like Java's `offset + length - 1` --
        // *not* the adjusted `get_length()` (which reports a minimum of 1). This means a
        // zero-length component's `get_end_offset()` is `offset - 1`, one less than `offset`.
        self.offset + self.length - 1
    }

    fn get_comment(&self) -> Option<String> {
        self.comment.clone()
    }

    fn set_comment(&self, _comment: Option<String>) -> Box<dyn DataTypeComponent> {
        // Ignored -- read-only. Java returns `this`; since this component has no interior
        // mutable field besides the lazily-cached field name (already captured below), a fresh
        // component sharing the same `Arc`s is observationally identical to returning `self`.
        Box::new(ReadOnlyDataTypeComponent {
            data_type: self.data_type.clone(),
            parent: self.parent.clone(),
            offset: self.offset,
            ordinal: self.ordinal,
            comment: self.comment.clone(),
            length: self.length,
            field_name: RefCell::new(self.field_name.borrow().clone()),
            default_settings: self.default_settings.clone(),
        })
    }

    fn get_field_name(&self) -> Option<String> {
        {
            let existing = self.field_name.borrow();
            if existing.is_some() {
                return existing.clone();
            }
        }
        let default_name = self.get_default_field_name();
        *self.field_name.borrow_mut() = default_name.clone();
        default_name
    }

    fn set_field_name(&self, _field_name: Option<String>) -> Box<dyn DataTypeComponent> {
        // Ignored -- read-only; see `set_comment` for why this returns an equivalent fresh
        // component rather than `self`.
        Box::new(ReadOnlyDataTypeComponent {
            data_type: self.data_type.clone(),
            parent: self.parent.clone(),
            offset: self.offset,
            ordinal: self.ordinal,
            comment: self.comment.clone(),
            length: self.length,
            field_name: RefCell::new(self.field_name.borrow().clone()),
            default_settings: self.default_settings.clone(),
        })
    }

    fn get_data_type(&self) -> Box<dyn DataType> {
        share_data_type(&self.data_type)
    }

    fn get_parent(&self) -> Box<dyn DataType> {
        share_data_type(&self.parent_as_data_type())
    }

    fn get_length(&self) -> i32 {
        if self.length == 0 {
            1
        } else {
            self.length
        }
    }

    fn get_ordinal(&self) -> i32 {
        self.ordinal
    }

    fn get_default_settings(&self) -> Box<dyn Settings> {
        Box::new(ReadOnlyComponentSettings(self.default_settings.clone()))
    }

    fn is_equivalent(&self, dtc: &dyn DataTypeComponent) -> bool {
        let my_dt = self.get_data_type();
        let other_dt = dtc.get_data_type();
        let other_length = dtc.get_length();
        let my_parent = self.get_parent();
        let aligned = my_parent
            .as_composite()
            .map(|c| c.is_packing_enabled())
            .unwrap_or(false);

        if (!aligned && (self.offset != dtc.get_offset()))
            || (!aligned && (self.length != other_length))
            || self.ordinal != dtc.get_ordinal()
            || !Self::is_same_string(self.get_field_name().as_deref(), dtc.get_field_name().as_deref())
            || !Self::is_same_string(self.get_comment().as_deref(), dtc.get_comment().as_deref())
        {
            return false;
        }
        // if they contain datatypes that have same ids, then we are essentially equivalent.
        Utils.is_same_or_equivalent_data_type(my_dt.as_ref(), other_dt.as_ref())
    }

    fn is_undefined(&self) -> bool {
        self.data_type.is_default_data_type()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::dynamic::Dynamic;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::mem::MemBuffer;

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

    fn leaf(name: &str) -> Arc<dyn DataType> {
        Arc::new(MockLeaf { name: name.to_string(), default_flag: false })
    }

    struct MockDynamicParent;
    impl DataType for MockDynamicParent {
        fn get_name(&self) -> String {
            "parent".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
    }
    impl BuiltInDataType for MockDynamicParent {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }
    impl Dynamic for MockDynamicParent {
        fn get_dynamic_length(&self, _buf: &dyn MemBuffer, _max_length: i32) -> i32 {
            0
        }
        fn can_specify_length(&self) -> bool {
            false
        }
        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            Box::new(MockLeaf { name: "byte".to_string(), default_flag: false })
        }
    }
    impl DynamicDataType for MockDynamicParent {
        fn get_all_components(
            &self,
            _buf: &dyn MemBuffer,
        ) -> Option<Vec<Option<Box<dyn DataTypeComponent>>>> {
            None
        }
    }

    fn parent() -> Arc<dyn DynamicDataType> {
        Arc::new(MockDynamicParent)
    }

    fn component(length: i32, ordinal: i32, offset: i32) -> ReadOnlyDataTypeComponent {
        ReadOnlyDataTypeComponent::new_unnamed(leaf("byte"), parent(), length, ordinal, offset)
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
    fn zero_length_reports_length_one_but_end_offset_uses_raw_length() {
        let c = component(0, 0, 10);
        assert_eq!(c.get_length(), 1);
        // Uses the raw (zero) length, not the adjusted get_length(), matching Java exactly.
        assert_eq!(c.get_end_offset(), 9);
    }

    #[test]
    fn get_data_type_and_parent_share_the_underlying_instances() {
        let c = component(1, 0, 0);
        assert_eq!(c.get_data_type().get_name(), "byte");
        assert_eq!(c.get_parent().get_name(), "parent");
    }

    #[test]
    fn field_name_defaults_and_is_cached() {
        let c = component(4, 3, 0x10);
        assert_eq!(c.get_field_name(), Some("field3".to_string()));
        // Calling again must return the same (now-cached) value.
        assert_eq!(c.get_field_name(), Some("field3".to_string()));
    }

    #[test]
    fn explicit_field_name_is_not_overridden_by_the_default() {
        let c = ReadOnlyDataTypeComponent::new(
            leaf("byte"),
            parent(),
            4,
            0,
            0,
            Some("custom".to_string()),
            None,
        );
        assert_eq!(c.get_field_name(), Some("custom".to_string()));
    }

    #[test]
    fn comment_getter() {
        let c = ReadOnlyDataTypeComponent::new(
            leaf("byte"),
            parent(),
            4,
            0,
            0,
            None,
            Some("a note".to_string()),
        );
        assert_eq!(c.get_comment(), Some("a note".to_string()));
    }

    #[test]
    fn set_comment_and_set_field_name_are_ignored() {
        let c = component(4, 1, 0);
        let updated = c.set_comment(Some("ignored".to_string()));
        assert_eq!(updated.get_comment(), None);

        let renamed = c.set_field_name(Some("ignored".to_string()));
        assert_eq!(renamed.get_field_name(), Some("field1".to_string()));
    }

    #[test]
    fn is_undefined_reflects_default_data_type() {
        let default_dt: Arc<dyn DataType> = Arc::new(MockLeaf { name: "undefined".to_string(), default_flag: true });
        let c = ReadOnlyDataTypeComponent::new_unnamed(default_dt, parent(), 1, 0, 0);
        assert!(c.is_undefined());

        let not_default = component(1, 0, 0);
        assert!(!not_default.is_undefined());
    }

    #[test]
    fn is_bit_field_component_false_for_plain_data_type() {
        let c = component(1, 0, 0);
        assert!(!c.is_bit_field_component());
        assert!(!c.is_zero_bit_field_component());
    }

    #[test]
    fn default_settings_falls_back_to_the_data_types_own_settings() {
        let c = component(1, 0, 0);
        let settings = c.get_default_settings();
        assert!(settings.is_immutable_settings());
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
    fn is_equivalent_false_when_ordinal_differs() {
        let a = component(4, 2, 8);
        let b = component(4, 3, 8);
        assert!(!a.is_equivalent(&b));
    }

    #[test]
    fn is_equivalent_false_when_field_names_differ() {
        let a = ReadOnlyDataTypeComponent::new(leaf("byte"), parent(), 4, 0, 0, Some("a".to_string()), None);
        let b = ReadOnlyDataTypeComponent::new(leaf("byte"), parent(), 4, 0, 0, Some("b".to_string()), None);
        assert!(!a.is_equivalent(&b));
    }

    #[test]
    fn components_equal_matches_structurally_identical_components() {
        let a = component(4, 2, 8);
        let b = component(4, 2, 8);
        assert!(a.components_equal(&b));
    }

    #[test]
    fn components_equal_false_when_length_differs() {
        let a = component(4, 2, 8);
        let b = component(8, 2, 8);
        assert!(!a.components_equal(&b));
    }
}
