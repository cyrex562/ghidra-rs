//! Port of `ghidra.program.model.data.UInt16TDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends AbstractUnsignedIntegerDataType`, already ported as a trait
//! ([`AbstractUnsignedIntegerDataType`]), so this trait extends it directly -- structurally
//! similar to the fixed-size
//! [`UnsignedInteger5DataType`](super::unsigned_integer5_data_type::UnsignedInteger5DataType)
//! family (`getDescription`/`getLength`/`getOppositeSignednessDataType`/`clone` exposed under
//! distinct `uint16_t_*` names for the same "subtrait cannot redeclare a supertrait method"
//! restriction documented there), except `UInt16TDataType` additionally overrides
//! `getCDeclaration()` (always `None`, matching the Java override which unconditionally returns
//! `null`) and `getCTypeDeclaration(DataOrganization)` (reproducing the `BuiltIn.getCTypeDeclaration(BuiltIn,
//! boolean, DataOrganization, boolean)` overload's formula directly, mirroring
//! [`UnsignedPointerSizedIntegerDataType::unsigned_pointer_sized_integer_c_type_declaration`](super::unsigned_pointer_sized_integer_data_type::UnsignedPointerSizedIntegerDataType::unsigned_pointer_sized_integer_c_type_declaration),
//! but with a fixed 1-byte width rather than the pointer-size width used there).
//!
//! `getOppositeSignednessDataType()` clones `Int16TDataType.dataType`, an already-ported trait
//! ([`Int16TDataType`](crate::program::model::data::int16_t_data_type::Int16TDataType)) with no
//! seam-stub placeholder needed, so this trait's `uint16_t_opposite_signedness_data_type` returns
//! `Box<dyn Int16TDataType>` directly.
//!
//! Static state not translated: the `dataType` singleton (needs a concrete struct).

use crate::program::model::data::abstract_unsigned_integer_data_type::AbstractUnsignedIntegerDataType;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::int16_t_data_type::Int16TDataType;

/// 16-bit unsigned integer (C99 Standard type `uint16_t`).
///
/// Port of `ghidra.program.model.data.UInt16TDataType`. See the module-level documentation for the
/// naming conventions used to resolve clashes with
/// [`DataType`]/[`AbstractIntegerDataType`](crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType).
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait UInt16TDataType: AbstractUnsignedIntegerDataType {
    /// Port of `UInt16TDataType.getLength()`, which overrides the default `DataType.getLength()`.
    /// Always `2`, matching the fixed C99 `uint16_t` width.
    fn uint16_t_length(&self) -> i32 {
        2
    }

    /// Port of `UInt16TDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn uint16_t_description(&self) -> String {
        "Unsigned 16-bit Integer".to_string()
    }

    /// Port of `UInt16TDataType.getCDeclaration()`, which overrides the default
    /// `AbstractIntegerDataType.getCDeclaration()`. Always `None`, matching the Java override
    /// which unconditionally returns `null`.
    fn uint16_t_c_declaration(&self) -> Option<String> {
        None
    }

    /// Returns the data-type with the opposite signedness from this data-type (an 16-bit signed
    /// integer type).
    ///
    /// Port of `UInt16TDataType.getOppositeSignednessDataType()`, which overrides the required
    /// `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required method (no
    /// default) since the real implementation clones the `Int16TDataType.dataType` singleton --
    /// see the module docs for why this can point at the already-ported [`Int16TDataType`]
    /// directly rather than a seam-stub placeholder.
    fn uint16_t_opposite_signedness_data_type(&self) -> Box<dyn Int16TDataType>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `UInt16TDataType.clone(DataTypeManager)`, which overrides
    /// `AbstractUnsignedIntegerDataType`'s inherited `BuiltIn.clone(DataTypeManager)`. Left as a
    /// required method (no default); see
    /// [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) for why.
    fn uint16_t_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn UInt16TDataType>;

    /// Port of `UInt16TDataType.getCTypeDeclaration(DataOrganization)`, which overrides the
    /// abstract `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. Reproduces
    /// `BuiltIn.getCTypeDeclaration(this, false, dataOrganization, false)`: a `typedef` line
    /// naming this type's fixed display name (`uint16_t`) after the organization's *unsigned*
    /// 16-bit C-type approximation.
    fn uint16_t_get_c_type_declaration(&self, data_organization: &dyn DataOrganization) -> Option<String> {
        Some(format!(
            "typedef {}    uint16_t;",
            data_organization.get_integer_c_type_approximation(2, false)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType;
    use crate::program::model::data::array_stringable::ArrayStringable;
    use crate::program::model::data::bit_field_packing::BitFieldPacking;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::data::string_data_instance::StringDataInstance;
    use crate::program::model::mem::MemBuffer;

    struct MockBitFieldPacking;
    impl BitFieldPacking for MockBitFieldPacking {
        fn use_ms_convention(&self) -> bool {
            false
        }
        fn is_type_alignment_enabled(&self) -> bool {
            true
        }
        fn get_zero_length_boundary(&self) -> i32 {
            0
        }
    }

    struct MockDataOrganization;
    impl DataOrganization for MockDataOrganization {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_pointer_size(&self) -> i32 {
            8
        }
        fn get_pointer_shift(&self) -> i32 {
            0
        }
        fn is_signed_char(&self) -> bool {
            true
        }
        fn get_char_size(&self) -> i32 {
            1
        }
        fn get_wide_char_size(&self) -> i32 {
            2
        }
        fn get_short_size(&self) -> i32 {
            2
        }
        fn get_integer_size(&self) -> i32 {
            4
        }
        fn get_long_size(&self) -> i32 {
            8
        }
        fn get_long_long_size(&self) -> i32 {
            8
        }
        fn get_float_size(&self) -> i32 {
            4
        }
        fn get_double_size(&self) -> i32 {
            8
        }
        fn get_long_double_size(&self) -> i32 {
            8
        }
        fn get_absolute_max_alignment(&self) -> i32 {
            0
        }
        fn get_machine_alignment(&self) -> i32 {
            8
        }
        fn get_default_alignment(&self) -> i32 {
            1
        }
        fn get_default_pointer_alignment(&self) -> i32 {
            8
        }
        fn get_size_alignment(&self, _size: i32) -> i32 {
            1
        }
        fn get_bit_field_packing(&self) -> Box<dyn BitFieldPacking> {
            Box::new(MockBitFieldPacking)
        }
        fn get_size_alignment_count(&self) -> i32 {
            0
        }
        fn get_sizes(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_integer_c_type_approximation(&self, size: i32, signed: bool) -> String {
            format!("{}int{}", if signed { "" } else { "unsigned " }, size * 8)
        }
        fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
            1
        }
    }

    struct MockInt16TDataType;
    impl DataType for MockInt16TDataType {
        fn get_name(&self) -> String {
            "int16_t".to_string()
        }
    }
    impl BuiltInDataType for MockInt16TDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }
    impl Int16TDataType for MockInt16TDataType {
        fn get_opposite_signedness_data_type(&self) -> Box<dyn crate::program::seam_stubs::UInt16TDataType> {
            unreachable!("not exercised in this smoke test")
        }
        fn int16_t_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Int16TDataType> {
            Box::new(MockInt16TDataType)
        }
    }

    struct MockUInt16TDataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockUInt16TDataType {
        fn get_name(&self) -> String {
            "uint16_t".to_string()
        }
        fn get_length(&self) -> i32 {
            self.uint16_t_length()
        }
    }

    impl BuiltInDataType for MockUInt16TDataType {
        fn get_c_type_declaration(&self, data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            data_organization.and_then(|org| self.uint16_t_get_c_type_declaration(org))
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl ArrayStringable for MockUInt16TDataType {
        fn has_string_value(&self, _settings: &dyn crate::docking::settings::settings::Settings) -> bool {
            false
        }
        fn string_data_instance(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn crate::docking::settings::settings::Settings,
            _length: i32,
        ) -> Box<dyn StringDataInstance> {
            Box::new(crate::program::model::data::string_data_instance::null_instance())
        }
        fn get_array_default_label_prefix(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn crate::docking::settings::settings::Settings,
            _len: i32,
            _options: &dyn DataTypeDisplayOptions,
        ) -> Option<String> {
            None
        }
        fn get_array_default_offcut_label_prefix(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn crate::docking::settings::settings::Settings,
            _len: i32,
            _options: &dyn DataTypeDisplayOptions,
            _offcut_length: i32,
        ) -> Option<String> {
            None
        }
    }

    impl AbstractIntegerDataType for MockUInt16TDataType {
        fn is_signed(&self) -> bool {
            self.unsigned_is_signed()
        }
        fn get_opposite_signedness_data_type(&self) -> Box<dyn AbstractIntegerDataType> {
            unreachable!("not exercised in this smoke test")
        }
    }

    impl AbstractUnsignedIntegerDataType for MockUInt16TDataType {}

    impl UInt16TDataType for MockUInt16TDataType {
        fn uint16_t_opposite_signedness_data_type(&self) -> Box<dyn Int16TDataType> {
            Box::new(MockInt16TDataType)
        }

        fn uint16_t_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn UInt16TDataType> {
            match dtm {
                None => Box::new(MockUInt16TDataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockUInt16TDataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockUInt16TDataType { dtm_tag: None };
        let dyn_dt: &dyn UInt16TDataType = &dt;
        assert_eq!(dyn_dt.uint16_t_length(), 2);
        assert_eq!(DataType::get_length(dyn_dt), 2);
        assert_eq!(dyn_dt.uint16_t_description(), "Unsigned 16-bit Integer");
        assert_eq!(dyn_dt.uint16_t_c_declaration(), None);
        assert!(!dt.is_signed());
    }

    #[test]
    fn c_type_declaration_uses_unsigned_8bit_approximation() {
        let dt = MockUInt16TDataType { dtm_tag: None };
        let org = MockDataOrganization;
        assert_eq!(
            dt.uint16_t_get_c_type_declaration(&org),
            Some("typedef unsigned int16    uint16_t;".to_string())
        );
    }

    #[test]
    fn opposite_signedness_returns_int16_t_data_type() {
        let dt = MockUInt16TDataType { dtm_tag: None };
        let opposite = dt.uint16_t_opposite_signedness_data_type();
        assert_eq!(opposite.get_name(), "int16_t");
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockUInt16TDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.uint16_t_clone(None);
        assert_eq!(cloned.uint16_t_length(), 2);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockUInt16TDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.uint16_t_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.uint16_t_length(), 2);
    }
}
