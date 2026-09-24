//! Port of `ghidra.program.model.data.SignedLeb128DataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends AbstractLeb128DataType`, forwarding `"sleb128"`/`true` (signed) to
//! its superclass constructor. This trait extends
//! [`AbstractLeb128DataType`](super::abstract_leb128_data_type::AbstractLeb128DataType) directly;
//! a concrete implementor's `leb128_is_signed()` is expected to return `true`, matching that
//! constructor forward.
//!
//! `getDescription()` (overriding the default `DataType.getDescription()`) is exposed under a
//! distinct `signed_leb128_description` name for the same reason established throughout this
//! crate (a subtrait cannot redeclare a supertrait's same-named default without ambiguity). The
//! public constructors and static `dataType` singleton field have no trait equivalent; see
//! [`Undefined1DataType`](super::undefined1_data_type::Undefined1DataType)'s module docs for why.
//!
//! `clone(DataTypeManager)` is left as a required method (no default), mirroring every other
//! `BuiltIn`-derived cut-point trait in this crate.

use crate::program::model::data::abstract_leb128_data_type::AbstractLeb128DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// A Signed Little Endian Base 128 integer data type.
///
/// Port of `ghidra.program.model.data.SignedLeb128DataType`. See the module docs for what was
/// ported, added, and omitted.
pub trait SignedLeb128DataType: AbstractLeb128DataType {
    /// Port of `SignedLeb128DataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn signed_leb128_description(&self) -> String {
        "Signed LEB128-Encoded Number".to_string()
    }

    /// Port of `SignedLeb128DataType.clone(DataTypeManager)`. Left as a required method (no
    /// default); see [`Undefined1DataType::undefined1_clone`](super::undefined1_data_type::Undefined1DataType::undefined1_clone)
    /// for why.
    fn signed_leb128_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn SignedLeb128DataType>;
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
    struct MockSignedLeb128;

    impl DataType for MockSignedLeb128 {
        fn get_name(&self) -> String {
            "sleb128".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            self.leb128_length()
        }
        fn get_description(&self) -> String {
            self.signed_leb128_description()
        }
    }

    impl DataTypeImpl for MockSignedLeb128 {
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

    impl BuiltInDataType for MockSignedLeb128 {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&DataOrganizationImpl>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl BuiltIn for MockSignedLeb128 {
        fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
            dt.get_name() == self.get_name()
        }
    }

    impl Dynamic for MockSignedLeb128 {
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

    impl AbstractLeb128DataType for MockSignedLeb128 {
        fn leb128_is_signed(&self) -> bool {
            true
        }
    }

    impl SignedLeb128DataType for MockSignedLeb128 {
        fn signed_leb128_clone(
            &self,
            _dtm: Option<Box<dyn DataTypeManager>>,
        ) -> Box<dyn SignedLeb128DataType> {
            Box::new(self.clone())
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockSignedLeb128;
        let dyn_dt: &dyn SignedLeb128DataType = &dt;
        assert_eq!(dyn_dt.signed_leb128_description(), "Signed LEB128-Encoded Number");
        assert!(dyn_dt.leb128_is_signed());
        assert_eq!(DataType::get_description(dyn_dt), "Signed LEB128-Encoded Number");
    }

    #[test]
    fn value_is_decoded_as_signed() {
        use crate::program::model::data::leb128::Leb128;
        use crate::program::model::scalar::scalar::Scalar;

        // LEB128-encode -42 as a signed value, then decode it back through the trait's own
        // `leb128_value` (which delegates to `Leb128::read(..., self.leb128_is_signed())`).
        let dt = MockSignedLeb128;
        let bytes = Leb128::encode(-42, true);
        let buf = BytesMemBuffer(bytes);
        let value = dt.leb128_value(&buf, &MockSettings, -1).unwrap();
        let scalar = value.downcast_ref::<Scalar>().unwrap();
        assert_eq!(scalar.get_signed_value(), -42);
    }

    #[test]
    fn clone_preserves_signedness_and_description() {
        let dt = MockSignedLeb128;
        let cloned = dt.signed_leb128_clone(None);
        assert!(cloned.leb128_is_signed());
        assert_eq!(cloned.signed_leb128_description(), dt.signed_leb128_description());
    }
}
