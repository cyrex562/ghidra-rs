//! Port of `ghidra.program.model.data.UnsignedLeb128DataType`, promoted to a trait because it
//! was selected as a dependency-cycle cut-point.
//!
//! The Java class `extends AbstractLeb128DataType`, forwarding `"uleb128"`/`false` (unsigned) to
//! its superclass constructor. Mirrors
//! [`SignedLeb128DataType`](super::signed_leb128_data_type::SignedLeb128DataType) -- see that
//! module's docs for the naming/shape conventions reused here. A concrete implementor's
//! `leb128_is_signed()` is expected to return `false`, matching that constructor forward.

use crate::program::model::data::abstract_leb128_data_type::AbstractLeb128DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// An Unsigned Little Endian Base 128 integer data type.
///
/// Port of `ghidra.program.model.data.UnsignedLeb128DataType`. See the module docs for what was
/// ported, added, and omitted.
pub trait UnsignedLeb128DataType: AbstractLeb128DataType {
    /// Port of `UnsignedLeb128DataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn unsigned_leb128_description(&self) -> String {
        "Unsigned LEB128-Encoded Number".to_string()
    }

    /// Port of `UnsignedLeb128DataType.clone(DataTypeManager)`. Left as a required method (no
    /// default); see [`Undefined1DataType::undefined1_clone`](super::undefined1_data_type::Undefined1DataType::undefined1_clone)
    /// for why.
    fn unsigned_leb128_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn UnsignedLeb128DataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::built_in::BuiltIn;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_impl::DataTypeImpl;
    use crate::program::model::data::dynamic::Dynamic;
    use crate::program::model::data::source_archive::SourceArchive;
    use crate::program::model::mem::{MemBuffer, MemoryAccessException};
    use crate::util::UniversalID;
    use std::sync::Weak;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct BytesMemBuffer(Vec<u8>);
    impl MemBuffer for BytesMemBuffer {
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.0
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
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

    #[derive(Clone)]
    struct MockUnsignedLeb128;

    impl DataType for MockUnsignedLeb128 {
        fn get_name(&self) -> String {
            "uleb128".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.leb128_length()
        }
        fn get_description(&self) -> String {
            self.unsigned_leb128_description()
        }
    }

    impl DataTypeImpl for MockUnsignedLeb128 {
        fn stored_default_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }
        fn set_stored_default_settings(&mut self, _settings: Box<dyn Settings>) {}
        fn stored_source_archive(&self) -> Option<Box<dyn SourceArchive>> {
            None
        }
        fn set_stored_source_archive(&mut self, _archive: Option<Box<dyn SourceArchive>>) {}
        fn stored_universal_id(&self) -> UniversalID {
            UniversalID::new(0)
        }
        fn stored_last_change_time(&self) -> i64 {
            0
        }
        fn set_stored_last_change_time(&mut self, _last_change_time: i64) {}
        fn stored_last_change_time_in_source_archive(&self) -> i64 {
            0
        }
        fn set_stored_last_change_time_in_source_archive(&mut self, _last_change_time: i64) {}
        fn stored_parent_refs(&self) -> Vec<Weak<dyn DataType>> {
            Vec::new()
        }
        fn set_stored_parent_refs(&mut self, _parents: Vec<Weak<dyn DataType>>) {}
    }

    impl BuiltInDataType for MockUnsignedLeb128 {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&DataOrganizationImpl>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl BuiltIn for MockUnsignedLeb128 {
        fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
            dt.get_name() == self.get_name()
        }
    }

    impl Dynamic for MockUnsignedLeb128 {
        fn get_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
            self.leb128_dynamic_length(buf, max_length)
        }
        fn can_specify_length(&self) -> bool {
            self.leb128_can_specify_length()
        }
        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            self.leb128_replacement_base_type()
        }
    }

    impl AbstractLeb128DataType for MockUnsignedLeb128 {
        fn leb128_is_signed(&self) -> bool {
            false
        }
    }

    impl UnsignedLeb128DataType for MockUnsignedLeb128 {
        fn unsigned_leb128_clone(
            &self,
            _dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn UnsignedLeb128DataType> {
            Box::new(self.clone())
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockUnsignedLeb128;
        let dyn_dt: &dyn UnsignedLeb128DataType = &dt;
        assert_eq!(dyn_dt.unsigned_leb128_description(), "Unsigned LEB128-Encoded Number");
        assert!(!dyn_dt.leb128_is_signed());
        assert_eq!(DataType::get_description(dyn_dt), "Unsigned LEB128-Encoded Number");
    }

    #[test]
    fn value_is_decoded_as_unsigned() {
        use crate::program::model::data::leb128::Leb128;
        use crate::program::model::scalar::scalar::Scalar;

        // LEB128-encode a large unsigned value, then decode it back through the trait's own
        // `leb128_value` (which delegates to `Leb128::read(..., self.leb128_is_signed())`).
        let dt = MockUnsignedLeb128;
        let bytes = Leb128::encode(624485, false);
        let buf = BytesMemBuffer(bytes);
        let value = dt.leb128_value(&buf, &MockSettings, -1).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_unsigned_value(), 624485);
    }

    #[test]
    fn clone_preserves_unsignedness_and_description() {
        let dt = MockUnsignedLeb128;
        let cloned = dt.unsigned_leb128_clone(None);
        assert!(!cloned.leb128_is_signed());
        assert_eq!(cloned.unsigned_leb128_description(), dt.unsigned_leb128_description());
    }
}
