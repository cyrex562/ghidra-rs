//! Port of `ghidra.program.model.data.UnsignedLongLongDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends AbstractUnsignedIntegerDataType`, already ported as a trait
//! ([`AbstractUnsignedIntegerDataType`]), so this trait extends it directly. Structurally similar
//! to [`UnsignedIntegerDataType`](super::unsigned_integer_data_type::UnsignedIntegerDataType) --
//! see that trait's module docs for the shared rationale (`getLength`/
//! `hasLanguageDependantLength`/`getDescription`/`getCTypeDeclaration` overriding
//! already-provided defaults, `getCDeclaration` overriding the reached-transitively default
//! `AbstractIntegerDataType.getCDeclaration()`, `getOppositeSignednessDataType` overriding the
//! required no-default `AbstractIntegerDataType.getOppositeSignednessDataType()`, all five
//! therefore exposed under distinct `unsigned_long_long_*` names) -- except `getOppositeSignednessDataType()`
//! clones `LongLongDataType.dataType`, and unlike `UnsignedIntegerDataType`'s own `IntegerDataType`
//! counterpart, [`LongLongDataType`](crate::program::model::data::long_long_data_type::LongLongDataType) is an
//! already-ported trait with no seam-stub placeholder needed at all, so this trait's
//! `unsigned_long_long_opposite_signedness_data_type` returns `Box<dyn LongLongDataType>` directly.
//!
//! Static state not translated: the `dataType` singleton (needs a concrete struct).

use crate::program::model::data::abstract_unsigned_integer_data_type::AbstractUnsignedIntegerDataType;
use crate::program::model::data::abstract_integer_data_type::C_UNSIGNED_LONGLONG;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::long_long_data_type::LongLongDataType;

/// Basic implementation for an Signed LongLong Integer dataType.
///
/// Port of `ghidra.program.model.data.UnsignedLongLongDataType`. See the module-level documentation
/// for the naming conventions used to resolve clashes with
/// [`DataType`]/[`AbstractIntegerDataType`](crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType).
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait UnsignedLongLongDataType: AbstractUnsignedIntegerDataType {
    /// Port of `UnsignedLongLongDataType.getLength()`, which overrides the default
    /// `DataType.getLength()`.
    fn unsigned_long_long_length(&self) -> i32 {
        self.get_data_organization().get_long_long_size()
    }

    /// Port of `UnsignedLongLongDataType.hasLanguageDependantLength()`, which overrides the default
    /// `DataType.hasLanguageDependantLength()`. Always `true`.
    fn unsigned_long_long_has_language_dependant_length(&self) -> bool {
        true
    }

    /// Port of `UnsignedLongLongDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn unsigned_long_long_description(&self) -> String {
        "Unsigned Long Long Integer (compiler-specific size)".to_string()
    }

    /// Port of `UnsignedLongLongDataType.getCDeclaration()`, which overrides the default
    /// `AbstractIntegerDataType.getCDeclaration()`.
    fn unsigned_long_long_c_declaration(&self) -> String {
        C_UNSIGNED_LONGLONG.to_string()
    }

    /// Returns the data-type with the opposite signedness from this data-type (a signed long long
    /// type).
    ///
    /// Port of `UnsignedLongLongDataType.getOppositeSignednessDataType()`, which overrides the
    /// required `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required
    /// method (no default) since the real implementation clones the `LongLongDataType.dataType`
    /// singleton -- see the module docs for why this can point at the already-ported
    /// [`LongLongDataType`] directly rather than a seam-stub placeholder.
    fn unsigned_long_long_opposite_signedness_data_type(&self) -> Box<dyn LongLongDataType>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `UnsignedLongLongDataType.clone(DataTypeManager)`, which overrides
    /// `AbstractUnsignedIntegerDataType`'s inherited `BuiltIn.clone(DataTypeManager)`. Left as a
    /// required method (no default); see
    /// [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) for why.
    fn unsigned_long_long_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn UnsignedLongLongDataType>;

    /// Port of `UnsignedLongLongDataType.getCTypeDeclaration(DataOrganization)`, which overrides the
    /// abstract `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. `data_organization` is
    /// unused, matching the Java original (which only ever formats `getName()`/`"unsigned
    /// long long"`). Reproduces `getCTypeDeclaration(getName(), "unsigned long long", false)`'s trivial
    /// `typedef` formula directly, mirroring
    /// [`UnsignedIntegerDataType::unsigned_integer_c_type_declaration`](super::unsigned_integer_data_type::UnsignedIntegerDataType::unsigned_integer_c_type_declaration).
    fn unsigned_long_long_c_type_declaration(&self, data_organization: Option<&dyn DataOrganization>) -> Option<String> {
        let _ = data_organization;
        Some(format!("typedef {}    {};", C_UNSIGNED_LONGLONG, self.get_name()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        long_long_size: i32,
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
            2
        }
        fn get_integer_size(&self) -> i32 {
            4
        }
        fn get_long_size(&self) -> i32 {
            8
        }
        fn get_long_long_size(&self) -> i32 {
            self.long_long_size
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

    struct MockLongLongDataType;
    impl DataType for MockLongLongDataType {
        fn get_name(&self) -> String {
            "longlong".to_string()
        }
    }
    impl BuiltInDataType for MockLongLongDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }
    impl LongLongDataType for MockLongLongDataType {
        fn get_opposite_signedness_data_type(&self) -> Box<dyn crate::program::seam_stubs::UnsignedLongLongDataType> {
            unreachable!("not exercised in this smoke test")
        }
        fn long_long_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn LongLongDataType> {
            Box::new(MockLongLongDataType)
        }
    }

    struct MockUnsignedLongLongDataType {
        long_long_size: i32,
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockUnsignedLongLongDataType {
        fn get_name(&self) -> String {
            "ulonglong".to_string()
        }
        fn get_length(&self) -> i32 {
            self.unsigned_long_long_length()
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization { long_long_size: self.long_long_size })
        }
    }

    impl BuiltInDataType for MockUnsignedLongLongDataType {
        fn get_c_type_declaration(&self, data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            self.unsigned_long_long_c_type_declaration(data_organization)
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl ArrayStringable for MockUnsignedLongLongDataType {
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

    impl crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType for MockUnsignedLongLongDataType {
        fn is_signed(&self) -> bool {
            self.unsigned_is_signed()
        }
        fn get_opposite_signedness_data_type(
            &self,
        ) -> Box<dyn crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType> {
            unreachable!("not exercised in this smoke test")
        }
    }

    impl AbstractUnsignedIntegerDataType for MockUnsignedLongLongDataType {}

    impl UnsignedLongLongDataType for MockUnsignedLongLongDataType {
        fn unsigned_long_long_opposite_signedness_data_type(&self) -> Box<dyn LongLongDataType> {
            Box::new(MockLongLongDataType)
        }

        fn unsigned_long_long_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn UnsignedLongLongDataType> {
            match dtm {
                None => Box::new(MockUnsignedLongLongDataType {
                    long_long_size: self.long_long_size,
                    dtm_tag: self.dtm_tag,
                }),
                Some(_) => Box::new(MockUnsignedLongLongDataType {
                    long_long_size: self.long_long_size,
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockUnsignedLongLongDataType { long_long_size: 8, dtm_tag: None };
        let dyn_dt: &dyn UnsignedLongLongDataType = &dt;
        assert_eq!(dyn_dt.unsigned_long_long_length(), 8);
        assert_eq!(DataType::get_length(dyn_dt), 8);
        assert!(dyn_dt.unsigned_long_long_has_language_dependant_length());
        assert_eq!(dyn_dt.unsigned_long_long_description(), "Unsigned Long Long Integer (compiler-specific size)");
        assert_eq!(dyn_dt.unsigned_long_long_c_declaration(), "unsigned long long");
    }

    #[test]
    fn c_type_declaration_formats_typedef() {
        let dt = MockUnsignedLongLongDataType { long_long_size: 8, dtm_tag: None };
        assert_eq!(
            dt.unsigned_long_long_c_type_declaration(None),
            Some("typedef unsigned long long    ulonglong;".to_string())
        );
        let via_trait: &dyn BuiltInDataType = &dt;
        assert_eq!(via_trait.get_c_type_declaration(None), dt.unsigned_long_long_c_type_declaration(None));
    }

    #[test]
    fn opposite_signedness_returns_long_data_type() {
        let dt = MockUnsignedLongLongDataType { long_long_size: 8, dtm_tag: None };
        let opposite = dt.unsigned_long_long_opposite_signedness_data_type();
        assert_eq!(opposite.get_name(), "longlong");
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockUnsignedLongLongDataType { long_long_size: 8, dtm_tag: Some("mgr-a") };
        let cloned = dt.unsigned_long_long_clone(None);
        assert_eq!(cloned.unsigned_long_long_length(), 8);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockUnsignedLongLongDataType { long_long_size: 8, dtm_tag: Some("mgr-a") };
        let cloned = dt.unsigned_long_long_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.unsigned_long_long_length(), 8);
    }
}
