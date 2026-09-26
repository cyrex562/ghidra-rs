//! Port of `ghidra.app.util.bin.format.elf.AndroidElfRelocationData`.
//!
//! Java's version is a package-private concrete class `extends SignedLeb128DataType`. Per this
//! crate's trait-stack for that dependency-cycle cut-point (see
//! [`SignedLeb128DataType`]/[`AbstractLeb128DataType`]/[`BuiltIn`]/[`Dynamic`]/[`DataTypeImpl`]'s
//! own module docs), a concrete implementor must implement the whole chain:
//! [`DataType`] + [`DataTypeImpl`] + [`BuiltInDataType`] + [`BuiltIn`] + [`Dynamic`] +
//! [`AbstractLeb128DataType`] + [`SignedLeb128DataType`]. This is the first concrete, in-repo
//! production implementor of that chain; the `DataTypeImpl` bookkeeping fields
//! (`universal_id`/`source_archive_id`/`last_change_time*`/`parents`) follow the same shape
//! [`TypedefDataType`](crate::program::model::data::typedef_data_type::TypedefDataType)
//! established for its own `DataTypeImpl` storage.
//!
//! The `DataTypeManager` constructor parameter has no stored field, matching `TypedefDataType`'s
//! precedent of not retaining `dtm` (its only real effect in the base `AbstractLeb128DataType`
//! constructor chain is on category-path/data-organization resolution, which this port does not
//! yet need).

use std::any::TypeId;

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::address::Address;
use crate::program::model::data::abstract_leb128_data_type::AbstractLeb128DataType;
use crate::program::model::data::built_in::BuiltIn;
use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_impl::DataTypeImpl;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::dynamic::Dynamic;
use crate::program::model::data::signed_leb128_data_type::SignedLeb128DataType;
use crate::program::model::data::source_archive::SourceArchive;
use crate::util::UniversalID;
use std::sync::Weak;

/// Provides a dynamic LEB128 data component for the packed Android ELF relocation table.
///
/// Port of `ghidra.app.util.bin.format.elf.AndroidElfRelocationData`. Secondary purpose: retains
/// the relocation offset associated with a component instance (relies on a 1:1 relationship
/// between an instance and the single component that references it, exactly as in Java).
pub struct AndroidElfRelocationData {
    relocation_offset: i64,
    universal_id: UniversalID,
    source_archive_id: Option<UniversalID>,
    last_change_time: i64,
    last_change_time_in_source_archive: i64,
    parents: Vec<Weak<dyn DataType>>,
}

impl AndroidElfRelocationData {
    /// Creates a packed relocation offset data type based upon a signed LEB128 value.
    ///
    /// Port of `AndroidElfRelocationData(DataTypeManager, long)`. `_dtm` is accepted (matching
    /// the Java constructor's parameter list) but not retained; see the module docs.
    pub fn new(_dtm: Option<&dyn DataTypeManager>, relocation_offset: i64) -> Self {
        AndroidElfRelocationData {
            relocation_offset,
            universal_id: UniversalID::new(0),
            source_archive_id: None,
            last_change_time: 0,
            last_change_time_in_source_archive: 0,
            parents: Vec::new(),
        }
    }

    /// Gets the relocation offset associated with this data item.
    ///
    /// Port of the package-private `getRelocationOffset()`.
    pub fn relocation_offset(&self) -> i64 {
        self.relocation_offset
    }
}

impl DataType for AndroidElfRelocationData {
    fn get_name(&self) -> String {
        "sleb128".to_string()
    }

    fn get_category_path(&self) -> CategoryPath {
        ROOT.clone()
    }

    fn get_length(&self) -> i32 {
        self.leb128_length()
    }

    /// Port of `AndroidElfRelocationData.getDescription()`, overriding
    /// `SignedLeb128DataType.getDescription()`.
    fn get_description(&self) -> String {
        "Android Packed Relocation Data for ELF".to_string()
    }

    /// Port of `AndroidElfRelocationData.getValueClass(Settings)`, overriding
    /// `DataType.getValueClass(Settings)`. Returns [`Address`]'s [`TypeId`], standing in for
    /// `Address.class`.
    fn get_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        let _ = settings;
        Some(TypeId::of::<Address>())
    }
}

impl DataTypeImpl for AndroidElfRelocationData {
    fn stored_default_settings(&self) -> Box<dyn Settings> {
        DataType::get_default_settings(self)
    }

    fn set_stored_default_settings(&mut self, _settings: Box<dyn Settings>) {}

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

impl BuiltInDataType for AndroidElfRelocationData {
    fn get_c_type_declaration(&self, _data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
        None
    }

    fn set_default_settings(&mut self, _settings: &dyn Settings) {}
}

impl BuiltIn for AndroidElfRelocationData {
    fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
        dt.get_name() == self.get_name()
    }

    /// Port of `AndroidElfRelocationData.getBuiltInSettingsDefinitions()`, overriding
    /// `BuiltIn.getBuiltInSettingsDefinitions()`. Java returns `null`; the empty `Vec` default
    /// already matches that (an empty settings-definitions list), so no override is needed here
    /// beyond documenting the correspondence.
    fn get_built_in_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        Vec::new()
    }
}

impl Dynamic for AndroidElfRelocationData {
    fn get_dynamic_length(&self, buf: &dyn crate::program::model::mem::MemBuffer, max_length: i32) -> i32 {
        self.leb128_dynamic_length(buf, max_length)
    }

    fn can_specify_length(&self) -> bool {
        self.leb128_can_specify_length()
    }

    fn get_replacement_base_type(&self) -> Box<dyn DataType> {
        self.leb128_replacement_base_type()
    }
}

impl AbstractLeb128DataType for AndroidElfRelocationData {
    fn leb128_is_signed(&self) -> bool {
        true
    }
}

impl SignedLeb128DataType for AndroidElfRelocationData {
    /// Port of `AndroidElfRelocationData.clone(DataTypeManager)`, overriding
    /// `SignedLeb128DataType.clone(DataTypeManager)`.
    ///
    /// # Panics
    /// Always panics, mirroring Java's `throw new UnsupportedOperationException("may not be
    /// cloned")`: specific instances are used by `AndroidElfRelocationTableDataType` and must not
    /// be duplicated.
    fn signed_leb128_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn SignedLeb128DataType> {
        panic!("may not be cloned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::SpecialAddress;
    use crate::program::model::data::leb128::Leb128;
    use crate::program::model::mem::{MemBuffer, MemoryAccessException};
    use crate::program::model::scalar::scalar::Scalar;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct BytesMemBuffer(Vec<u8>);
    impl MemBuffer for BytesMemBuffer {
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.0.get(offset as usize).copied().ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }
    }

    #[test]
    fn new_stores_relocation_offset() {
        let dt = AndroidElfRelocationData::new(None, 0x1234);
        assert_eq!(dt.relocation_offset(), 0x1234);
    }

    #[test]
    fn name_and_length_match_java() {
        let dt = AndroidElfRelocationData::new(None, 0);
        assert_eq!(dt.get_name(), "sleb128");
        assert_eq!(dt.get_length(), -1);
        assert!(dt.leb128_is_signed());
    }

    #[test]
    fn description_overrides_signed_leb128_default() {
        let dt = AndroidElfRelocationData::new(None, 0);
        assert_eq!(dt.get_description(), "Android Packed Relocation Data for ELF");
        // Confirms the override, not `SignedLeb128DataType`'s own default description.
        assert_ne!(dt.get_description(), dt.signed_leb128_description());
    }

    #[test]
    fn value_class_is_address_not_scalar() {
        let dt = AndroidElfRelocationData::new(None, 0);
        assert_eq!(dt.get_value_class(&MockSettings), Some(TypeId::of::<Address>()));
        assert_ne!(dt.get_value_class(&MockSettings), Some(TypeId::of::<Scalar>()));
    }

    #[test]
    fn decodes_signed_leb128_value_through_the_trait_chain() {
        let dt = AndroidElfRelocationData::new(None, 0);
        let bytes = Leb128::encode(-42, true);
        let buf = BytesMemBuffer(bytes);
        let value = dt.leb128_value(&buf, &MockSettings, -1).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_signed_value(), -42);
    }

    #[test]
    #[should_panic(expected = "may not be cloned")]
    fn clone_is_unsupported() {
        let dt = AndroidElfRelocationData::new(None, 0);
        let _ = dt.signed_leb128_clone(None);
    }

    #[test]
    fn built_in_settings_definitions_are_empty() {
        let dt = AndroidElfRelocationData::new(None, 0);
        assert!(dt.get_built_in_settings_definitions().is_empty());
    }
}
