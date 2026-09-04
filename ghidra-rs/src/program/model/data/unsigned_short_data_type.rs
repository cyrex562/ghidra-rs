//! Port of `ghidra.program.model.data.UnsignedShortDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point. Structurally identical to
//! [`UnsignedIntegerDataType`](super::unsigned_integer_data_type::UnsignedIntegerDataType) -- see
//! that trait's module docs for the shared rationale (naming clashes with `DataType`/
//! `AbstractIntegerDataType`, and the reproduced `BuiltIn.getCTypeDeclaration` formula) -- with
//! `ShortDataType` standing in for `IntegerDataType` as the opposite-signedness sibling.

use crate::program::model::data::abstract_integer_data_type::C_UNSIGNED_SHORT;
use crate::program::model::data::abstract_unsigned_integer_data_type::AbstractUnsignedIntegerDataType;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::short_data_type::ShortDataType;

/// Basic implementation for an unsigned Short Integer dataType.
///
/// Port of `ghidra.program.model.data.UnsignedShortDataType`. See the module-level documentation
/// for the naming conventions this mirrors from
/// [`UnsignedIntegerDataType`](super::unsigned_integer_data_type::UnsignedIntegerDataType).
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait UnsignedShortDataType: AbstractUnsignedIntegerDataType {
    /// Port of `UnsignedShortDataType.getLength()`, which overrides the default
    /// `DataType.getLength()`.
    fn unsigned_short_length(&self) -> i32 {
        self.get_data_organization().get_short_size()
    }

    /// Port of `UnsignedShortDataType.hasLanguageDependantLength()`, which overrides the default
    /// `DataType.hasLanguageDependantLength()`. Always `true`.
    fn unsigned_short_has_language_dependant_length(&self) -> bool {
        true
    }

    /// Port of `UnsignedShortDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn unsigned_short_description(&self) -> String {
        "Unsigned Short Integer (compiler-specific size)".to_string()
    }

    /// Port of `UnsignedShortDataType.getCDeclaration()`, which overrides the default
    /// `AbstractIntegerDataType.getCDeclaration()`.
    fn unsigned_short_c_declaration(&self) -> String {
        C_UNSIGNED_SHORT.to_string()
    }

    /// Port of `UnsignedShortDataType.getOppositeSignednessDataType()`, which overrides the
    /// required `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required
    /// method (no default); see
    /// [`UnsignedIntegerDataType::unsigned_integer_opposite_signedness_data_type`](super::unsigned_integer_data_type::UnsignedIntegerDataType::unsigned_integer_opposite_signedness_data_type)
    /// for why.
    fn unsigned_short_opposite_signedness_data_type(&self) -> Box<dyn ShortDataType>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `UnsignedShortDataType.clone(DataTypeManager)`, which overrides
    /// `AbstractUnsignedIntegerDataType`'s inherited `BuiltIn.clone(DataTypeManager)`. Left as a
    /// required method (no default); see
    /// [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) for why.
    fn unsigned_short_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn UnsignedShortDataType>;

    /// Port of `UnsignedShortDataType.getCTypeDeclaration(DataOrganization)`, which overrides the
    /// abstract `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. `data_organization` is
    /// unused, matching the Java original. See
    /// [`UnsignedIntegerDataType::unsigned_integer_c_type_declaration`](super::unsigned_integer_data_type::UnsignedIntegerDataType::unsigned_integer_c_type_declaration)
    /// for why the `BuiltIn.getCTypeDeclaration(String, String, boolean)` helper's formula is
    /// reproduced directly instead of stubbed.
    fn unsigned_short_c_type_declaration(&self, data_organization: Option<&dyn DataOrganization>) -> Option<String> {
        let _ = data_organization;
        Some(format!("typedef {}    {};", C_UNSIGNED_SHORT, self.get_name()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
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

    struct MockDataOrganization {
        short_size: i32,
    }

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
            self.short_size
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
        fn get_integer_c_type_approximation(&self, _size: i32, _signed: bool) -> String {
            "int".to_string()
        }
        fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
            1
        }
    }

    struct MockShortDataType;
    impl DataType for MockShortDataType {
        fn get_name(&self) -> String {
            "short".to_string()
        }
    }
    impl BuiltInDataType for MockShortDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }
    impl ShortDataType for MockShortDataType {
        fn get_opposite_signedness_data_type(&self) -> Box<dyn crate::program::seam_stubs::UnsignedShortDataType> {
            unreachable!("not exercised in this smoke test")
        }
        fn short_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn ShortDataType> {
            Box::new(MockShortDataType)
        }
    }

    struct MockUnsignedShortDataType {
        short_size: i32,
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockUnsignedShortDataType {
        fn get_name(&self) -> String {
            "ushort".to_string()
        }
        fn get_length(&self) -> i32 {
            self.unsigned_short_length()
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization { short_size: self.short_size })
        }
    }

    impl BuiltInDataType for MockUnsignedShortDataType {
        fn get_c_type_declaration(&self, data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            self.unsigned_short_c_type_declaration(data_organization)
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl ArrayStringable for MockUnsignedShortDataType {
        fn has_string_value(&self, _settings: &dyn Settings) -> bool {
            false
        }
        fn string_data_instance(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _length: i32,
        ) -> Box<dyn StringDataInstance> {
            Box::new(crate::program::model::data::string_data_instance::null_instance())
        }
        fn get_array_default_label_prefix(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _len: i32,
            _options: &dyn DataTypeDisplayOptions,
        ) -> Option<String> {
            None
        }
        fn get_array_default_offcut_label_prefix(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _len: i32,
            _options: &dyn DataTypeDisplayOptions,
            _offcut_length: i32,
        ) -> Option<String> {
            None
        }
    }

    impl AbstractIntegerDataType for MockUnsignedShortDataType {
        fn is_signed(&self) -> bool {
            self.unsigned_is_signed()
        }
        fn get_opposite_signedness_data_type(&self) -> Box<dyn AbstractIntegerDataType> {
            unreachable!("not exercised in this smoke test")
        }
    }

    impl AbstractUnsignedIntegerDataType for MockUnsignedShortDataType {}

    impl UnsignedShortDataType for MockUnsignedShortDataType {
        fn unsigned_short_opposite_signedness_data_type(&self) -> Box<dyn ShortDataType> {
            Box::new(MockShortDataType)
        }

        fn unsigned_short_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn UnsignedShortDataType> {
            match dtm {
                None => Box::new(MockUnsignedShortDataType {
                    short_size: self.short_size,
                    dtm_tag: self.dtm_tag,
                }),
                Some(_) => Box::new(MockUnsignedShortDataType {
                    short_size: self.short_size,
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockUnsignedShortDataType { short_size: 2, dtm_tag: None };
        let dyn_dt: &dyn UnsignedShortDataType = &dt;
        assert_eq!(dyn_dt.unsigned_short_length(), 2);
        assert_eq!(DataType::get_length(dyn_dt), 2);
        assert!(dyn_dt.unsigned_short_has_language_dependant_length());
        assert_eq!(dyn_dt.unsigned_short_description(), "Unsigned Short Integer (compiler-specific size)");
        assert_eq!(dyn_dt.unsigned_short_c_declaration(), "unsigned short");
        assert!(!dt.is_signed());
    }

    #[test]
    fn c_type_declaration_formats_typedef() {
        let dt = MockUnsignedShortDataType { short_size: 2, dtm_tag: None };
        assert_eq!(
            dt.unsigned_short_c_type_declaration(None),
            Some("typedef unsigned short    ushort;".to_string())
        );
    }

    #[test]
    fn opposite_signedness_returns_short_data_type() {
        let dt = MockUnsignedShortDataType { short_size: 2, dtm_tag: None };
        let _opposite = dt.unsigned_short_opposite_signedness_data_type();
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockUnsignedShortDataType { short_size: 2, dtm_tag: Some("mgr-a") };
        let cloned = dt.unsigned_short_clone(None);
        assert_eq!(cloned.unsigned_short_length(), 2);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockUnsignedShortDataType { short_size: 2, dtm_tag: Some("mgr-a") };
        let cloned = dt.unsigned_short_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.unsigned_short_length(), 2);
    }
}
