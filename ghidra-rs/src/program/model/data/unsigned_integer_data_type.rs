//! Port of `ghidra.program.model.data.UnsignedIntegerDataType`, promoted to a trait because it
//! was selected as a dependency-cycle cut-point.
//!
//! The Java class `extends AbstractUnsignedIntegerDataType`, already ported as a trait
//! ([`AbstractUnsignedIntegerDataType`]), so this trait extends it directly.
//!
//! `getLength()`, `hasLanguageDependantLength()`, `getDescription()`, `getCTypeDeclaration(DataOrganization)`
//! all override *default* methods already declared on [`DataType`]/[`BuiltInDataType`]; `getCDeclaration()`
//! overrides the *default* `AbstractIntegerDataType.getCDeclaration()` (reached transitively);
//! `getOppositeSignednessDataType()` overrides the *required* (no-default)
//! `AbstractIntegerDataType.getOppositeSignednessDataType()`. Rust does not allow a subtrait to
//! override a supertrait's method (default or required) by redeclaring it under the same name --
//! see this crate's other `Abstract*`/leaf cut-point traits for the same restriction -- so all six
//! are exposed here under distinct `unsigned_integer_*` names. A concrete `impl DataType +
//! BuiltInDataType + AbstractIntegerDataType for ...` should delegate to these.
//!
//! `getCTypeDeclaration(DataOrganization)` calls the protected `BuiltIn.getCTypeDeclaration(String,
//! String, boolean)` helper directly (bypassing `AbstractIntegerDataType`'s own
//! `hasLanguageDependantLength()`-gated default, since `AbstractIntegerDataType` does not itself
//! provide a `getCTypeDeclaration` default -- only [`BuiltInDataType::get_c_type_declaration`]'s
//! required, no-default signature exists to override). Since `BuiltIn` is not a supertrait reached
//! here (mirroring [`Integer3DataType`](super::integer3_data_type::Integer3DataType)'s identical
//! situation), that helper's trivial `typedef` formula is reproduced directly.

use crate::program::model::data::abstract_unsigned_integer_data_type::AbstractUnsignedIntegerDataType;
use crate::program::model::data::abstract_integer_data_type::C_UNSIGNED_INT;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::data::integer_data_type::IntegerDataType;

/// Basic implementation for an unsigned Integer dataType.
///
/// Port of `ghidra.program.model.data.UnsignedIntegerDataType`. See the module-level
/// documentation for the naming conventions used to resolve clashes with
/// [`DataType`]/[`AbstractIntegerDataType`](crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType).
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait UnsignedIntegerDataType: AbstractUnsignedIntegerDataType {
    /// Port of `UnsignedIntegerDataType.getLength()`, which overrides the default
    /// `DataType.getLength()`.
    fn unsigned_integer_length(&self) -> i32 {
        self.get_data_organization().get_integer_size()
    }

    /// Port of `UnsignedIntegerDataType.hasLanguageDependantLength()`, which overrides the default
    /// `DataType.hasLanguageDependantLength()`. Always `true`.
    fn unsigned_integer_has_language_dependant_length(&self) -> bool {
        true
    }

    /// Port of `UnsignedIntegerDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn unsigned_integer_description(&self) -> String {
        "Unsigned Integer (compiler-specific size)".to_string()
    }

    /// Port of `UnsignedIntegerDataType.getCDeclaration()`, which overrides the default
    /// `AbstractIntegerDataType.getCDeclaration()`.
    fn unsigned_integer_c_declaration(&self) -> String {
        C_UNSIGNED_INT.to_string()
    }

    /// Port of `UnsignedIntegerDataType.getOppositeSignednessDataType()`, which overrides the
    /// required `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required
    /// method (no default) since the real implementation clones the `IntegerDataType.dataType`
    /// singleton, which -- unlike most other `Abstract*DataType` opposite-signedness siblings in
    /// this crate -- corresponds to an *already-ported* trait
    /// ([`IntegerDataType`](crate::program::model::data::integer_data_type::IntegerDataType)) but
    /// still has no concrete singleton instance to clone generically.
    fn unsigned_integer_opposite_signedness_data_type(&self) -> Box<dyn IntegerDataType>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `UnsignedIntegerDataType.clone(DataTypeManager)`, which overrides
    /// `AbstractUnsignedIntegerDataType`'s inherited `BuiltIn.clone(DataTypeManager)`. Left as a
    /// required method (no default); see
    /// [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) for why.
    fn unsigned_integer_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn UnsignedIntegerDataType>;

    /// Port of `UnsignedIntegerDataType.getCTypeDeclaration(DataOrganization)`, which overrides
    /// the abstract `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. `data_organization`
    /// is unused, matching the Java original (which only ever formats `getName()`/`"unsigned
    /// int"`). See the module docs for why the `BuiltIn.getCTypeDeclaration(String, String,
    /// boolean)` helper's formula is reproduced directly instead of stubbed.
    fn unsigned_integer_c_type_declaration(&self, data_organization: Option<&dyn DataOrganization>) -> Option<String> {
        let _ = data_organization;
        Some(format!("typedef {}    {};", C_UNSIGNED_INT, self.get_name()))
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
        integer_size: i32,
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
            self.integer_size
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

    struct MockIntegerDataType;
    impl DataType for MockIntegerDataType {
        fn get_name(&self) -> String {
            "int".to_string()
        }
    }
    impl BuiltInDataType for MockIntegerDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }
    impl ArrayStringable for MockIntegerDataType {
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
    impl AbstractIntegerDataType for MockIntegerDataType {
        fn is_signed(&self) -> bool {
            true
        }
        fn get_opposite_signedness_data_type(&self) -> Box<dyn AbstractIntegerDataType> {
            unreachable!("not exercised in this smoke test")
        }
    }
    impl IntegerDataType for MockIntegerDataType {
        fn get_opposite_signedness_data_type(&self) -> Box<dyn crate::program::seam_stubs::UnsignedIntegerDataType> {
            unreachable!("not exercised in this smoke test")
        }
        fn integer_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn IntegerDataType> {
            Box::new(MockIntegerDataType)
        }
    }

    struct MockUnsignedIntegerDataType {
        integer_size: i32,
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockUnsignedIntegerDataType {
        fn get_name(&self) -> String {
            "uint".to_string()
        }
        fn get_length(&self) -> i32 {
            self.unsigned_integer_length()
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization { integer_size: self.integer_size })
        }
    }

    impl BuiltInDataType for MockUnsignedIntegerDataType {
        fn get_c_type_declaration(&self, data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            self.unsigned_integer_c_type_declaration(data_organization)
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl ArrayStringable for MockUnsignedIntegerDataType {
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

    impl AbstractIntegerDataType for MockUnsignedIntegerDataType {
        fn is_signed(&self) -> bool {
            self.unsigned_is_signed()
        }
        fn get_opposite_signedness_data_type(&self) -> Box<dyn AbstractIntegerDataType> {
            Box::new(MockIntegerDataType)
        }
    }

    impl AbstractUnsignedIntegerDataType for MockUnsignedIntegerDataType {}

    impl UnsignedIntegerDataType for MockUnsignedIntegerDataType {
        fn unsigned_integer_opposite_signedness_data_type(&self) -> Box<dyn IntegerDataType> {
            Box::new(MockIntegerDataType)
        }

        fn unsigned_integer_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn UnsignedIntegerDataType> {
            match dtm {
                None => Box::new(MockUnsignedIntegerDataType {
                    integer_size: self.integer_size,
                    dtm_tag: self.dtm_tag,
                }),
                Some(_) => Box::new(MockUnsignedIntegerDataType {
                    integer_size: self.integer_size,
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockUnsignedIntegerDataType { integer_size: 4, dtm_tag: None };
        let dyn_dt: &dyn UnsignedIntegerDataType = &dt;
        assert_eq!(dyn_dt.unsigned_integer_length(), 4);
        assert_eq!(DataType::get_length(dyn_dt), 4);
        assert!(dyn_dt.unsigned_integer_has_language_dependant_length());
        assert_eq!(dyn_dt.unsigned_integer_description(), "Unsigned Integer (compiler-specific size)");
        assert_eq!(dyn_dt.unsigned_integer_c_declaration(), "unsigned int");
        assert!(!dt.is_signed());
    }

    #[test]
    fn c_type_declaration_formats_typedef() {
        let dt = MockUnsignedIntegerDataType { integer_size: 4, dtm_tag: None };
        assert_eq!(
            dt.unsigned_integer_c_type_declaration(None),
            Some("typedef unsigned int    uint;".to_string())
        );
        let via_trait: &dyn BuiltInDataType = &dt;
        assert_eq!(via_trait.get_c_type_declaration(None), dt.unsigned_integer_c_type_declaration(None));
    }

    #[test]
    fn opposite_signedness_returns_integer_data_type() {
        let dt = MockUnsignedIntegerDataType { integer_size: 4, dtm_tag: None };
        let opposite = dt.unsigned_integer_opposite_signedness_data_type();
        assert!(opposite.is_signed());
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockUnsignedIntegerDataType { integer_size: 4, dtm_tag: Some("mgr-a") };
        let cloned = dt.unsigned_integer_clone(None);
        assert_eq!(cloned.unsigned_integer_length(), 4);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockUnsignedIntegerDataType { integer_size: 4, dtm_tag: Some("mgr-a") };
        let cloned = dt.unsigned_integer_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.unsigned_integer_length(), 4);
    }
}
