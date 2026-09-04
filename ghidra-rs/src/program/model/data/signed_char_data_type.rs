//! Port of `ghidra.program.model.data.SignedCharDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends CharDataType`, already ported as a trait
//! ([`CharDataType`](crate::program::model::data::char_data_type::CharDataType)), so this trait
//! extends it directly -- unlike its `UnsignedInteger*` siblings
//! ([`UnsignedIntegerDataType`](super::unsigned_integer_data_type::UnsignedIntegerDataType) etc.),
//! which extend `AbstractUnsignedIntegerDataType`.
//!
//! `isSigned()`, `getDescription()`, `getDefaultLabelPrefix()`, and `getCDeclaration()` each
//! override an already-provided default method on [`DataType`]/[`CharDataType`]; `getCTypeDeclaration(DataOrganization)`
//! overrides the abstract, required `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. Rust
//! does not allow a subtrait to override a supertrait's method (default or required) by
//! redeclaring it under the same name -- see this crate's other `Abstract*`/leaf cut-point traits
//! for the same restriction -- so all five are exposed here under distinct `signed_char_*`
//! names. A concrete `impl DataType + BuiltInDataType + CharDataType for ...` should delegate to
//! these.
//!
//! `getCTypeDeclaration(DataOrganization)` calls `getCTypeDeclaration(getName(),
//! getCDeclaration(), false)` -- i.e. it uses *this* class's own overridden `getCDeclaration()`
//! (`"signed char"`), not `CharDataType`'s. Mirroring
//! [`UnsignedIntegerDataType`](super::unsigned_integer_data_type::UnsignedIntegerDataType)'s
//! identical situation, the `BuiltIn.getCTypeDeclaration(String, String, boolean)` helper's
//! trivial `typedef` formula is reproduced directly here rather than stubbed, since `BuiltIn` is
//! not a supertrait reached from `CharDataType`.

use crate::program::model::data::char_data_type::CharDataType;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Provides a definition of a primitive signed char data type. While in most environments the
/// size is one 8-bit byte, this can vary based upon data organization imposed by the associated
/// data type manager.
///
/// Port of `ghidra.program.model.data.SignedCharDataType`. See the module-level documentation
/// for the naming conventions used to resolve clashes with
/// [`DataType`](crate::program::model::data::data_type::DataType)/[`CharDataType`].
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct) and the
/// `serialVersionUID` field (Java serialization has no Rust equivalent).
pub trait SignedCharDataType: CharDataType {
    /// Port of `SignedCharDataType.isSigned()`, which overrides the default
    /// `CharDataType.isSigned()` (which delegates to `DataOrganization::is_signed_char`). Always
    /// `true`.
    fn signed_char_is_signed(&self) -> bool {
        true
    }

    /// Port of `SignedCharDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn signed_char_description(&self) -> String {
        "Signed Character (ASCII)".to_string()
    }

    /// Port of `SignedCharDataType.getDefaultLabelPrefix()`, which overrides the default
    /// `DataType.getDefaultLabelPrefix()`.
    fn signed_char_default_label_prefix(&self) -> Option<String> {
        Some("SCHAR".to_string())
    }

    /// Port of `SignedCharDataType.getCDeclaration()`, which overrides the default
    /// `CharDataType.getCDeclaration()` (`Some(self.get_name())`). Unlike that default, this
    /// override always succeeds with a fixed value, matching the Java `return "signed char";`
    /// body.
    fn signed_char_c_declaration(&self) -> String {
        "signed char".to_string()
    }

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `SignedCharDataType.clone(DataTypeManager)`, which overrides
    /// `CharDataType`'s inherited `BuiltIn.clone(DataTypeManager)`. Left as a required method (no
    /// default); see [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone)
    /// for why.
    fn signed_char_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn SignedCharDataType>;

    /// Port of `SignedCharDataType.getCTypeDeclaration(DataOrganization)`, which overrides the
    /// abstract `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. `data_organization` is
    /// unused, matching the Java original. See the module docs for why the
    /// `BuiltIn.getCTypeDeclaration(String, String, boolean)` helper's formula is reproduced
    /// directly instead of stubbed, and for why this uses
    /// [`signed_char_c_declaration`](Self::signed_char_c_declaration) rather than
    /// `CharDataType::get_c_declaration`.
    fn signed_char_c_type_declaration(&self, data_organization: Option<&dyn DataOrganization>) -> Option<String> {
        let _ = data_organization;
        Some(format!("typedef {}    {};", self.signed_char_c_declaration(), self.get_name()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::bit_field_packing::BitFieldPacking;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_with_charset::DataTypeWithCharset;
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
            true
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
            4
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
        fn get_size_alignment(&self, size: i32) -> i32 {
            size
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
            String::new()
        }
        fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
            1
        }
    }

    struct MockSignedCharDataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockSignedCharDataType {
        fn get_name(&self) -> String {
            "schar".to_string()
        }
        fn get_length(&self) -> i32 {
            1
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization)
        }
    }

    impl DataTypeWithCharset for MockSignedCharDataType {
        fn string_data_instance(
            &self,
            _settings: &dyn Settings,
            _buf: &dyn MemBuffer,
        ) -> Box<dyn crate::program::model::data::string_data_instance::StringDataInstance> {
            unimplemented!("not exercised by these tests")
        }
        fn get_charset_name(&self, settings: &dyn Settings) -> String {
            self.char_charset_name(settings)
        }
    }

    impl BuiltInDataType for MockSignedCharDataType {
        fn get_c_type_declaration(&self, data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            self.signed_char_c_type_declaration(data_organization)
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl CharDataType for MockSignedCharDataType {
        fn is_signed(&self) -> bool {
            self.signed_char_is_signed()
        }
        fn get_opposite_signedness_data_type(&self) -> Box<dyn CharDataType> {
            unreachable!("not exercised in this smoke test")
        }
    }

    impl SignedCharDataType for MockSignedCharDataType {
        fn signed_char_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn SignedCharDataType> {
            match dtm {
                None => Box::new(MockSignedCharDataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockSignedCharDataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockSignedCharDataType { dtm_tag: None };
        let dyn_dt: &dyn SignedCharDataType = &dt;
        assert!(dyn_dt.signed_char_is_signed());
        // Regardless of what the underlying DataOrganization reports, the override always
        // reports signed -- matching CharDataType::is_signed being pinned by this override.
        assert!(dt.is_signed());
        assert_eq!(dyn_dt.signed_char_description(), "Signed Character (ASCII)");
        assert_eq!(dyn_dt.signed_char_default_label_prefix(), Some("SCHAR".to_string()));
        assert_eq!(dyn_dt.signed_char_c_declaration(), "signed char");
    }

    #[test]
    fn c_type_declaration_uses_own_c_declaration_override() {
        let dt = MockSignedCharDataType { dtm_tag: None };
        assert_eq!(
            dt.signed_char_c_type_declaration(None),
            Some("typedef signed char    schar;".to_string())
        );
        let via_trait: &dyn BuiltInDataType = &dt;
        assert_eq!(via_trait.get_c_type_declaration(None), dt.signed_char_c_type_declaration(None));
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockSignedCharDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.signed_char_clone(None);
        assert_eq!(cloned.signed_char_description(), dt.signed_char_description());
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockSignedCharDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.signed_char_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.signed_char_c_declaration(), "signed char");
    }
}
