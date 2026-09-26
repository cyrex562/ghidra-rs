//! Port of `ghidra.program.database.data.PointerTypedefInspector`.
//!
//! The Java class is a private-constructor static-utility holder with no fields and no instance
//! state (this repo's own shape classifier tags it a "statics-holder"), so it is ported here as
//! plain free functions rather than the trait-of-defaults "cycle cut-point" pattern used for
//! classes like [`DataTypeUtilities`](crate::program::database::data::data_type_utilities::DataTypeUtilities)
//! -- matching the established convention for this shape elsewhere in this crate (e.g.
//! [`composite_alignment_helper`](crate::program::model::data::composite_alignment_helper)).
//!
//! Every `TypeDef::isPointer()` call in the Java source is ported as
//! `TypeDef::is_pointer(pointer_type_def)` (fully-qualified syntax) rather than
//! `pointer_type_def.is_pointer()`: `TypeDef: DataType` and both supertrait and subtrait declare
//! a method named `is_pointer` with its own default body, so calling it through a `&dyn TypeDef`
//! receiver is otherwise ambiguous.
//!
//! ## Known gap: `get_pointer_address_space`
//!
//! Java's `getPointerAddressSpace` has a branch for `addressSpace instanceof
//! SegmentedAddressSpace` that skips the `PointerType` check entirely for segmented spaces. This
//! crate's `AddressSpace` and `SegmentedAddressSpace` are unrelated concrete structs (composition
//! -- `SegmentedAddressSpace` wraps an `Arc<AddressSpace>` -- rather than the Java subclassing
//! relationship), so there is no way to detect at runtime that an `Arc<AddressSpace>` returned
//! from `AddressFactory::get_address_space_by_name` is "really" a segmented space. This exact
//! limitation is already established precedent elsewhere in this crate (see
//! `PointerDataType::get_address_value`'s and `HighFunctionDBUtil`'s own module docs for the same
//! trade-off): the branch is intentionally not ported, and this port always falls through to the
//! `PointerType` check.

use crate::program::model::address::factory::AddressFactory;
use crate::program::model::data::address_space_settings_definition::AddressSpaceSettingsDefinition;
use crate::program::model::data::component_offset_settings_definition::ComponentOffsetSettingsDefinition;
use crate::program::model::data::offset_mask_settings_definition::OffsetMaskSettingsDefinition;
use crate::program::model::data::offset_shift_settings_definition::OffsetShiftSettingsDefinition;
use crate::program::model::data::pointer_type::{DefaultPointerType, PointerType};
use crate::program::model::data::pointer_type_settings_definition::PointerTypeSettingsDefinition;
use crate::program::model::data::typedef::TypeDef;
use std::sync::Arc;

use crate::docking::settings::number_settings_definition::NumberSettingsDefinition;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::docking::settings::string_settings_definition::StringSettingsDefinition;
use crate::program::model::address::AddressSpace;

/// Determine the component-offset for the specified `pointer_type_def` based upon its default
/// settings.
///
/// Returns the pointer component offset, or `0` if unspecified or not applicable.
pub fn get_pointer_component_offset(pointer_type_def: &dyn TypeDef) -> i64 {
    if TypeDef::is_pointer(pointer_type_def) {
        ComponentOffsetSettingsDefinition::DEF
            .get_value(pointer_type_def.get_default_settings().as_ref())
    } else {
        0
    }
}

/// Determine the referenced address space for specified `pointer_type_def` based upon its
/// default settings.
///
/// Returns the referenced address space, or `None` if not specified or address space lookup
/// fails. See the module docs for a known gap regarding segmented address spaces.
pub fn get_pointer_address_space(
    pointer_type_def: &dyn TypeDef,
    addr_factory: &dyn AddressFactory,
) -> Option<Arc<AddressSpace>> {
    if !TypeDef::is_pointer(pointer_type_def) {
        return None;
    }
    let settings = pointer_type_def.get_default_settings();
    let space_name = AddressSpaceSettingsDefinition::DEF.get_value(settings.as_ref())?;
    let address_space = addr_factory.get_address_space_by_name(&space_name)?;

    // NOTE: Java's `addressSpace instanceof SegmentedAddressSpace` short-circuit (which skips
    // the PointerType check below for segmented spaces) is not portable here -- see module docs.

    // Address space setting ignored if Pointer Type has been specified.
    let choice = PointerTypeSettingsDefinition::DEF.get_type(Some(settings.as_ref()));
    if choice.value() == DefaultPointerType.value() {
        Some(address_space)
    } else {
        None
    }
}

/// Determine if the specified `pointer_type_def` has a pointer bit-shift specified.
pub fn has_pointer_bit_shift(pointer_type_def: &dyn TypeDef) -> bool {
    TypeDef::is_pointer(pointer_type_def)
        && OffsetShiftSettingsDefinition::DEF.has_value(pointer_type_def.get_default_settings().as_ref())
}

/// Determine the pointer bit-shift for the specified `pointer_type_def` based upon its default
/// settings. A right-shift is specified by a positive value while a left-shift is specified by a
/// negative value. If specified, bit-shift will be applied after applying any specified bit-mask.
///
/// Returns the pointer bit-shift, or `0` if unspecified or not applicable.
pub fn get_pointer_bit_shift(pointer_type_def: &dyn TypeDef) -> i64 {
    if TypeDef::is_pointer(pointer_type_def) {
        OffsetShiftSettingsDefinition::DEF.get_value(pointer_type_def.get_default_settings().as_ref())
    } else {
        0
    }
}

/// Determine if the specified `pointer_type_def` has a pointer bit-mask specified.
pub fn has_pointer_bit_mask(pointer_type_def: &dyn TypeDef) -> bool {
    TypeDef::is_pointer(pointer_type_def)
        && OffsetMaskSettingsDefinition::DEF.has_value(pointer_type_def.get_default_settings().as_ref())
}

/// Determine the pointer bit-mask for the specified `pointer_type_def` based upon its default
/// settings. If specified, bit-mask will be AND-ed with stored offset prior to any specified
/// bit-shift.
///
/// Returns the pointer bit-mask, or `0` if unspecified or not applicable.
pub fn get_pointer_bit_mask(pointer_type_def: &dyn TypeDef) -> i64 {
    if TypeDef::is_pointer(pointer_type_def) {
        OffsetMaskSettingsDefinition::DEF.get_value(pointer_type_def.get_default_settings().as_ref())
    } else {
        0
    }
}

/// Get the pointer type (see [`PointerType`]).
///
/// Returns `None` if `pointer_type_def` is not a pointer.
pub fn get_pointer_type(pointer_type_def: &dyn TypeDef) -> Option<Box<dyn PointerType>> {
    if TypeDef::is_pointer(pointer_type_def) {
        Some(PointerTypeSettingsDefinition::DEF.get_type(Some(pointer_type_def.get_default_settings().as_ref())))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::address::{Address, AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::pointer_type::{FileOffsetPointerType, RelativePointerType};
    use std::collections::HashMap;

    // `DataType: Send + Sync`, so this fixture uses plain (non-interior-mutable) fields --
    // `Settings`'s mutating methods already take `&mut self`, so no `RefCell` is needed.
    #[derive(Default, Clone)]
    struct MockSettings {
        longs: HashMap<String, i64>,
        strings: HashMap<String, String>,
    }

    impl Settings for MockSettings {
        fn get_long(&self, name: &str) -> Option<i64> {
            self.longs.get(name).copied()
        }

        fn set_long(&mut self, name: &str, value: i64) {
            self.longs.insert(name.to_string(), value);
        }

        fn get_string(&self, name: &str) -> Option<String> {
            self.strings.get(name).cloned()
        }

        fn set_string(&mut self, name: &str, value: &str) {
            self.strings.insert(name.to_string(), value.to_string());
        }

        fn clear_setting(&mut self, name: &str) {
            self.longs.remove(name);
            self.strings.remove(name);
        }

        fn is_empty(&self) -> bool {
            self.longs.is_empty() && self.strings.is_empty()
        }
    }

    /// A minimal `TypeDef` fixture: `is_pointer` and `default_settings` are the only members
    /// this module's functions ever touch.
    struct FakeTypeDef {
        pointer: bool,
        settings: MockSettings,
    }

    impl DataType for FakeTypeDef {
        fn get_default_settings(&self) -> Box<dyn Settings> {
            Box::new(self.settings.clone())
        }
    }

    impl TypeDef for FakeTypeDef {
        fn is_auto_named(&self) -> bool {
            false
        }
        fn enable_auto_naming(&mut self) {}
        fn get_data_type(&self) -> Box<dyn DataType> {
            unimplemented!("not exercised by PointerTypedefInspector")
        }
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            unimplemented!("not exercised by PointerTypedefInspector")
        }
        fn is_pointer(&self) -> bool {
            self.pointer
        }
    }

    fn non_pointer() -> FakeTypeDef {
        FakeTypeDef {
            pointer: false,
            settings: MockSettings::default(),
        }
    }

    fn pointer_with(settings: MockSettings) -> FakeTypeDef {
        FakeTypeDef {
            pointer: true,
            settings,
        }
    }

    #[test]
    fn non_pointer_typedef_reports_all_defaults() {
        let td = non_pointer();
        assert_eq!(get_pointer_component_offset(&td), 0);
        assert!(!has_pointer_bit_shift(&td));
        assert_eq!(get_pointer_bit_shift(&td), 0);
        assert!(!has_pointer_bit_mask(&td));
        assert_eq!(get_pointer_bit_mask(&td), 0);
        assert!(get_pointer_type(&td).is_none());
    }

    #[test]
    fn pointer_component_offset_reads_setting() {
        let mut settings = MockSettings::default();
        ComponentOffsetSettingsDefinition::DEF.set_value(&mut settings, 0x18);
        let td = pointer_with(settings);
        assert_eq!(get_pointer_component_offset(&td), 0x18);
    }

    #[test]
    fn pointer_bit_shift_and_mask_read_settings() {
        let mut settings = MockSettings::default();
        OffsetShiftSettingsDefinition::DEF.set_value(&mut settings, -4);
        OffsetMaskSettingsDefinition::DEF.set_value(&mut settings, 0xff);
        let td = pointer_with(settings);

        assert!(has_pointer_bit_shift(&td));
        assert_eq!(get_pointer_bit_shift(&td), -4);
        assert!(has_pointer_bit_mask(&td));
        assert_eq!(get_pointer_bit_mask(&td), 0xff);
    }

    #[test]
    fn pointer_bit_shift_and_mask_absent_when_unset() {
        let td = pointer_with(MockSettings::default());
        assert!(!has_pointer_bit_shift(&td));
        assert!(!has_pointer_bit_mask(&td));
    }

    #[test]
    fn pointer_type_defaults_to_default_when_unset() {
        let td = pointer_with(MockSettings::default());
        let pt = get_pointer_type(&td).expect("pointer typedef should report a PointerType");
        assert_eq!(pt.value(), DefaultPointerType.value());
    }

    #[test]
    fn pointer_type_reads_non_default_setting() {
        let mut settings = MockSettings::default();
        PointerTypeSettingsDefinition::DEF.set_type(&mut settings, &RelativePointerType);
        let td = pointer_with(settings);
        let pt = get_pointer_type(&td).unwrap();
        assert_eq!(pt.value(), RelativePointerType.value());
    }

    /// A minimal `AddressFactory` fixture whose only real behavior is resolving `"ram"` to a
    /// single fixed 32-bit RAM space by name; every other method is unused by
    /// `get_pointer_address_space` and just returns an empty/`None` placeholder.
    struct FakeAddrFactory {
        ram: Arc<AddressSpace>,
    }

    impl FakeAddrFactory {
        fn new() -> Self {
            FakeAddrFactory {
                ram: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0),
            }
        }
    }

    impl AddressFactory for FakeAddrFactory {
        fn get_address(&self, _addr_string: &str) -> Option<Address> {
            None
        }
        fn get_all_addresses_case(&self, _addr_string: &str, _case_sensitive: bool) -> Vec<Address> {
            Vec::new()
        }
        fn get_default_address_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
            Vec::new()
        }
        fn get_address_space_by_name(&self, name: &str) -> Option<Arc<AddressSpace>> {
            (name == "ram").then(|| self.ram.clone())
        }
        fn get_address_space_by_id(&self, _id: i32) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_all_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
            Vec::new()
        }
        fn get_num_address_spaces(&self) -> usize {
            0
        }
        fn is_valid_address(&self, _address: &Address) -> bool {
            false
        }
        fn get_index(&self, _address: &Address) -> i64 {
            0
        }
        fn get_physical_space(&self, space: &Arc<AddressSpace>) -> Arc<AddressSpace> {
            space.clone()
        }
        fn get_physical_spaces(&self) -> Vec<Arc<AddressSpace>> {
            Vec::new()
        }
        fn address(&self, _space_id: i32, _offset: i64) -> Option<Address> {
            None
        }
        fn get_stack_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_constant_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_unique_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_register_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_constant_address(&self, _offset: i64) -> Option<Address> {
            None
        }
        fn get_address_set_range(&self, _min: &Address, _max: &Address) -> AddressSet {
            AddressSet::new()
        }
        fn get_address_set(&self) -> AddressSet {
            AddressSet::new()
        }
        fn old_get_address_from_long(&self, _value: i64) -> Option<Address> {
            None
        }
        fn has_multiple_memory_spaces(&self) -> bool {
            false
        }
    }

    #[test]
    fn pointer_address_space_resolves_default_pointer_type() {
        let mut settings = MockSettings::default();
        AddressSpaceSettingsDefinition::DEF.set_value(&mut settings, "ram");
        let td = pointer_with(settings);
        let factory = FakeAddrFactory::new();

        let space = get_pointer_address_space(&td, &factory).expect("space should resolve");
        assert_eq!(space.name(), "ram");
    }

    #[test]
    fn pointer_address_space_ignored_when_pointer_type_is_non_default() {
        let mut settings = MockSettings::default();
        AddressSpaceSettingsDefinition::DEF.set_value(&mut settings, "ram");
        PointerTypeSettingsDefinition::DEF.set_type(&mut settings, &FileOffsetPointerType);
        let td = pointer_with(settings);
        let factory = FakeAddrFactory::new();

        assert!(get_pointer_address_space(&td, &factory).is_none());
    }

    #[test]
    fn pointer_address_space_none_when_space_name_unresolvable() {
        let mut settings = MockSettings::default();
        AddressSpaceSettingsDefinition::DEF.set_value(&mut settings, "no-such-space");
        let td = pointer_with(settings);
        let factory = FakeAddrFactory::new();

        assert!(get_pointer_address_space(&td, &factory).is_none());
    }

    #[test]
    fn pointer_address_space_none_for_non_pointer() {
        let td = non_pointer();
        let factory = FakeAddrFactory::new();
        assert!(get_pointer_address_space(&td, &factory).is_none());
    }
}
