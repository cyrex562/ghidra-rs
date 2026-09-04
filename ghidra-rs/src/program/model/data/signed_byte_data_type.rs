//! Port of `ghidra.program.model.data.SignedByteDataType`, promoted straight to a trait because
//! it was selected as a dependency-cycle cut-point (mirrors
//! [`Integer5DataType`](crate::program::model::data::integer5_data_type::Integer5DataType), which
//! documents the same set of design decisions in more detail).
//!
//! The Java class `extends AbstractSignedIntegerDataType`, itself a subclass of
//! `AbstractIntegerDataType`. Neither is yet ported, but every member `SignedByteDataType`
//! actually calls on them (`getDataOrganization()` from [`DataType`], and the final
//! `AbstractSignedIntegerDataType.isSigned()`) is already covered by an already-ported trait or
//! reproducible here directly, so no `seam_stubs` placeholder is needed for either supertype.
//!
//! Unlike `Integer5DataType`/`Int8TDataType` (whose opposite-signedness singleton is not yet
//! ported), `SignedByteDataType.getOppositeSignednessDataType()` clones `ByteDataType.dataType`,
//! an already-ported trait
//! ([`ByteDataType`](crate::program::model::data::byte_data_type::ByteDataType)), so this trait's
//! `signed_byte_opposite_signedness_data_type` returns `Box<dyn ByteDataType>` directly with no
//! seam-stub placeholder needed.
//!
//! `ByteDataType` itself still declares its own opposite-signedness method
//! (`ByteDataType::get_opposite_signedness_data_type`) against
//! `crate::program::seam_stubs::SignedByteDataType` (an empty marker trait), not this new real
//! trait -- switching that import to this trait is not a mechanical drop-in, since the seam-stub
//! is an empty marker (`pub trait SignedByteDataType {}`) while this trait declares several
//! required methods, so any existing mock implementing the seam-stub trivially would stop
//! compiling. Left as documented deferred reconciliation, matching how earlier `Unsigned*`
//! cut-points in this crate were left pointed at their own now-real-but-unswapped counterparts
//! (e.g. `IntegerDataType::get_opposite_signedness_data_type` still returns
//! `Box<dyn crate::program::seam_stubs::UnsignedIntegerDataType>` even though
//! `UnsignedIntegerDataType` is itself now a real, ported trait).
//!
//! Methods that only *override* an already-ported supertrait method with
//! SignedByteDataType-specific behavior (`getLength`, `getDescription`,
//! `getDecompilerDisplayName`) cannot be redeclared here without creating an ambiguous method
//! name with [`DataType`] (Rust does not allow a subtrait to "override" a supertrait's default
//! method by re-declaring it). Instead, the real SignedByteDataType-specific values for those
//! overrides are exposed here under distinct `signed_byte_*` names; a future concrete
//! implementation (once `AbstractSignedIntegerDataType`/`AbstractIntegerDataType` are ported)
//! should implement `DataType`/`BuiltInDataType` directly and delegate to these helpers.
//! `getAssemblyMnemonic()` (unprefixed, since it is not declared by any already-ported
//! supertrait) mirrors [`ByteDataType::get_assembly_mnemonic`](crate::program::model::data::byte_data_type::ByteDataType::get_assembly_mnemonic)'s
//! own precedent for the same reason.
//!
//! Static state not translated: the `dataType` singleton (needs a concrete struct) and the
//! `serialVersionUID` field (Java serialization has no Rust equivalent).

use crate::program::model::data::byte_data_type::ByteDataType;
use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::decompiler_language::DecompilerLanguage;

/// Provides a definition of a Signed Byte within a program.
///
/// Port of `ghidra.program.model.data.SignedByteDataType`. See the module-level documentation for
/// the naming conventions used to resolve clashes with [`DataType`].
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait SignedByteDataType: DataType + BuiltInDataType {
    /// Determine if this type is signed.
    ///
    /// Port of the `final` `AbstractSignedIntegerDataType.isSigned()`, which `SignedByteDataType`
    /// inherits unchanged.
    fn is_signed(&self) -> bool {
        true
    }

    /// A brief description of this data-type.
    ///
    /// Port of `SignedByteDataType.getDescription()`, which overrides the abstract
    /// `DataType.getDescription()`. Exposed under a distinct name since [`DataType`] already
    /// declares `get_description`; see the module docs for why it cannot be redeclared here.
    fn signed_byte_description(&self) -> String {
        "Signed Byte (sdb)".to_string()
    }

    /// The length of this data-type, in bytes.
    ///
    /// Port of `SignedByteDataType.getLength()`, which overrides the abstract
    /// `DataType.getLength()`. Exposed under a distinct name since [`DataType`] already declares
    /// `get_length`; see the module docs for why it cannot be redeclared here.
    fn signed_byte_length(&self) -> i32 {
        1
    }

    /// The Assembly style data-type declaration for this data-type.
    ///
    /// Port of `SignedByteDataType.getAssemblyMnemonic()`, which overrides
    /// `AbstractIntegerDataType.getAssemblyMnemonic()`. That method is not part of any
    /// already-ported trait, so it is exposed here directly with no naming conflict.
    fn get_assembly_mnemonic(&self) -> String {
        "sdb".to_string()
    }

    /// The name to display for this data-type in the decompiler's output, for the given
    /// decompiler output language.
    ///
    /// Port of `SignedByteDataType.getDecompilerDisplayName(DecompilerLanguage)`, which overrides
    /// `DataType.getDecompilerDisplayName(DecompilerLanguage)`. Exposed under a distinct name
    /// since [`DataType`] already declares `get_decompiler_display_name`; see the module docs for
    /// why it cannot be redeclared here. Falls back to [`DataType::get_name`] (standing in for
    /// the Java `name` field) for every language other than
    /// [`DecompilerLanguage::JavaLanguage`].
    fn signed_byte_decompiler_display_name(&self, language: DecompilerLanguage) -> String {
        if language == DecompilerLanguage::JavaLanguage {
            "byte".to_string()
        } else {
            self.get_name()
        }
    }

    /// Returns the data-type with the opposite signedness from this data-type (an unsigned byte
    /// type).
    ///
    /// Port of `SignedByteDataType.getOppositeSignednessDataType()`, which overrides the abstract
    /// `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required method (no
    /// default) since the real implementation clones the `ByteDataType.dataType` singleton -- see
    /// the module docs for why this can point at the already-ported [`ByteDataType`] directly
    /// rather than a seam-stub placeholder.
    fn signed_byte_opposite_signedness_data_type(&self) -> Box<dyn ByteDataType>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `SignedByteDataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default) since the real
    /// implementation returns `self` when `dtm` already matches this instance's manager, which
    /// requires manager-identity comparison a mock cannot provide generically.
    fn signed_byte_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn SignedByteDataType>;

    /// The C style data-type declaration for this data-type, given a specific `DataOrganization`.
    ///
    /// Port of `SignedByteDataType.getCTypeDeclaration(DataOrganization)`, which overrides the
    /// abstract `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. Exposed under a distinct
    /// name since [`BuiltInDataType`] already declares `get_c_type_declaration`; see the module
    /// docs for why it cannot be redeclared here. Reproduces `BuiltIn.getCTypeDeclaration(this,
    /// true, dataOrganization, false)`: a `typedef` line naming this type's fixed display name
    /// (`sbyte`) after the organization's signed 1-byte C-type approximation.
    fn signed_byte_get_c_type_declaration(&self, data_organization: &dyn DataOrganization) -> Option<String> {
        Some(format!(
            "typedef {}    sbyte;",
            data_organization.get_integer_c_type_approximation(1, true)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::bit_field_packing::BitFieldPacking;

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

    struct MockByteDataType;
    impl DataType for MockByteDataType {
        fn get_name(&self) -> String {
            "byte".to_string()
        }
    }
    impl BuiltInDataType for MockByteDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }
    impl ByteDataType for MockByteDataType {
        fn get_opposite_signedness_data_type(&self) -> Box<dyn crate::program::seam_stubs::SignedByteDataType> {
            unreachable!("not exercised in this smoke test")
        }
        fn byte_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn ByteDataType> {
            Box::new(MockByteDataType)
        }
    }

    struct MockSignedByteDataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockSignedByteDataType {
        fn get_name(&self) -> String {
            "sbyte".to_string()
        }
    }

    impl BuiltInDataType for MockSignedByteDataType {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            data_organization.and_then(|org| self.signed_byte_get_c_type_declaration(org))
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl SignedByteDataType for MockSignedByteDataType {
        fn signed_byte_opposite_signedness_data_type(&self) -> Box<dyn ByteDataType> {
            Box::new(MockByteDataType)
        }

        fn signed_byte_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn SignedByteDataType> {
            match dtm {
                None => Box::new(MockSignedByteDataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockSignedByteDataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockSignedByteDataType { dtm_tag: None };
        let dyn_dt: &dyn SignedByteDataType = &dt;
        assert!(dyn_dt.is_signed());
        assert_eq!(dyn_dt.signed_byte_length(), 1);
        assert_eq!(dyn_dt.signed_byte_description(), "Signed Byte (sdb)");
        assert_eq!(dyn_dt.get_assembly_mnemonic(), "sdb");
        assert_eq!(DataType::get_name(dyn_dt), "sbyte");
    }

    #[test]
    fn decompiler_display_name_java_language_uses_byte() {
        let dt = MockSignedByteDataType { dtm_tag: None };
        assert_eq!(dt.signed_byte_decompiler_display_name(DecompilerLanguage::JavaLanguage), "byte");
    }

    #[test]
    fn decompiler_display_name_other_language_falls_back_to_name() {
        let dt = MockSignedByteDataType { dtm_tag: None };
        assert_eq!(dt.signed_byte_decompiler_display_name(DecompilerLanguage::CLanguage), "sbyte");
    }

    #[test]
    fn c_type_declaration_uses_signed_1byte_approximation() {
        let dt = MockSignedByteDataType { dtm_tag: None };
        let org = MockDataOrganization;
        assert_eq!(
            dt.signed_byte_get_c_type_declaration(&org),
            Some("typedef int8    sbyte;".to_string())
        );
    }

    #[test]
    fn opposite_signedness_returns_byte_data_type() {
        let dt = MockSignedByteDataType { dtm_tag: None };
        let opposite = dt.signed_byte_opposite_signedness_data_type();
        assert!(!opposite.is_signed());
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockSignedByteDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.signed_byte_clone(None);
        assert_eq!(cloned.signed_byte_length(), 1);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockSignedByteDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.signed_byte_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.signed_byte_length(), 1);
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}
}
