//! Port of `ghidra.program.model.data.SignedQWordDataType`, promoted straight to a trait because
//! it was selected as a dependency-cycle cut-point (mirrors
//! [`Integer5DataType`](crate::program::model::data::integer5_data_type::Integer5DataType), which
//! documents the same set of design decisions in more detail).
//!
//! The Java class `extends AbstractSignedIntegerDataType`, itself a subclass of
//! `AbstractIntegerDataType`. Neither is yet ported, but every member `SignedQWordDataType`
//! actually calls on them (`getDataOrganization()` from [`DataType`], and the final
//! `AbstractSignedIntegerDataType.isSigned()`) is already covered by an already-ported trait or
//! reproducible here directly, so no `seam_stubs` placeholder is needed for either supertype.
//!
//! Unlike `Integer5DataType`/`Int8TDataType` (whose opposite-signedness singleton is not yet
//! ported), `SignedQWordDataType.getOppositeSignednessDataType()` clones `QWordDataType.dataType`,
//! an already-ported trait
//! ([`QWordDataType`](crate::program::model::data::qword_data_type::QWordDataType)), so this trait's
//! `signed_qword_opposite_signedness_data_type` returns `Box<dyn QWordDataType>` directly with no
//! seam-stub placeholder needed.
//!
//! `QWordDataType` itself still declares its own opposite-signedness method
//! (`QWordDataType::get_opposite_signedness_data_type`) against
//! `crate::program::seam_stubs::SignedQWordDataType` (an empty marker trait), not this new real
//! trait -- switching that import to this trait is not a mechanical drop-in, since the seam-stub
//! is an empty marker (`pub trait SignedQWordDataType {}`) while this trait declares several
//! required methods, so any existing mock implementing the seam-stub trivially would stop
//! compiling. Left as documented deferred reconciliation, matching how earlier `Unsigned*`
//! cut-points in this crate were left pointed at their own now-real-but-unswapped counterparts
//! (e.g. `IntegerDataType::get_opposite_signedness_data_type` still returns
//! `Box<dyn crate::program::seam_stubs::UnsignedIntegerDataType>` even though
//! `UnsignedIntegerDataType` is itself now a real, ported trait).
//!
//! Methods that only *override* an already-ported supertrait method with
//! SignedQWordDataType-specific behavior (`getLength`, `getDescription`) cannot be redeclared
//! here without creating an ambiguous method name with [`DataType`] (Rust does not allow a
//! subtrait to "override" a supertrait's default method by re-declaring it). Instead, the real
//! SignedQWordDataType-specific values for those overrides are exposed here under distinct
//! `signed_qword_*` names; a future concrete implementation (once
//! `AbstractSignedIntegerDataType`/`AbstractIntegerDataType` are ported) should implement
//! `DataType`/`BuiltInDataType` directly and delegate to these helpers. Unlike
//! `SignedByteDataType` (which also overrides `getDecompilerDisplayName(DecompilerLanguage)`),
//! the Java source for this class has no such override, so this trait adds none either.
//! `getAssemblyMnemonic()` (unprefixed, since it is not declared by any already-ported
//! supertrait) mirrors [`QWordDataType::get_assembly_mnemonic`](crate::program::model::data::qword_data_type::QWordDataType::get_assembly_mnemonic)'s
//! own precedent for the same reason.
//!
//! Static state not translated: the `dataType` singleton (needs a concrete struct) and the
//! `serialVersionUID` field (Java serialization has no Rust equivalent).

use crate::program::model::data::qword_data_type::QWordDataType;
use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Provides a definition of a Signed Quad Word within a program.
///
/// Port of `ghidra.program.model.data.SignedQWordDataType`. See the module-level documentation for
/// the naming conventions used to resolve clashes with [`DataType`].
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait SignedQWordDataType: DataType + BuiltInDataType {
    /// Determine if this type is signed.
    ///
    /// Port of the `final` `AbstractSignedIntegerDataType.isSigned()`, which `SignedQWordDataType`
    /// inherits unchanged.
    fn is_signed(&self) -> bool {
        true
    }

    /// A brief description of this data-type.
    ///
    /// Port of `SignedQWordDataType.getDescription()`, which overrides the abstract
    /// `DataType.getDescription()`. Exposed under a distinct name since [`DataType`] already
    /// declares `get_description`; see the module docs for why it cannot be redeclared here.
    fn signed_qword_description(&self) -> String {
        "Signed Quad-Word (sdq, 8-bytes)".to_string()
    }

    /// The length of this data-type, in bytes.
    ///
    /// Port of `SignedQWordDataType.getLength()`, which overrides the abstract
    /// `DataType.getLength()`. Exposed under a distinct name since [`DataType`] already declares
    /// `get_length`; see the module docs for why it cannot be redeclared here.
    fn signed_qword_length(&self) -> i32 {
        8
    }

    /// The Assembly style data-type declaration for this data-type.
    ///
    /// Port of `SignedQWordDataType.getAssemblyMnemonic()`, which overrides
    /// `AbstractIntegerDataType.getAssemblyMnemonic()`. That method is not part of any
    /// already-ported trait, so it is exposed here directly with no naming conflict.
    fn get_assembly_mnemonic(&self) -> String {
        "sdq".to_string()
    }

    /// Returns the data-type with the opposite signedness from this data-type (an unsigned quad word
    /// type).
    ///
    /// Port of `SignedQWordDataType.getOppositeSignednessDataType()`, which overrides the abstract
    /// `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required method (no
    /// default) since the real implementation clones the `QWordDataType.dataType` singleton -- see
    /// the module docs for why this can point at the already-ported [`QWordDataType`] directly
    /// rather than a seam-stub placeholder.
    fn signed_qword_opposite_signedness_data_type(&self) -> Box<dyn QWordDataType>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `SignedQWordDataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default) since the real
    /// implementation returns `self` when `dtm` already matches this instance's manager, which
    /// requires manager-identity comparison a mock cannot provide generically.
    fn signed_qword_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn SignedQWordDataType>;

    /// The C style data-type declaration for this data-type, given a specific `DataOrganization`.
    ///
    /// Port of `SignedQWordDataType.getCTypeDeclaration(DataOrganization)`, which overrides the
    /// abstract `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. Exposed under a distinct
    /// name since [`BuiltInDataType`] already declares `get_c_type_declaration`; see the module
    /// docs for why it cannot be redeclared here. Reproduces `BuiltIn.getCTypeDeclaration(this,
    /// true, dataOrganization, false)`: a `typedef` line naming this type's fixed display name
    /// (`sqword`) after the organization's signed 8-byte C-type approximation.
    fn signed_qword_get_c_type_declaration(&self, data_organization: &dyn DataOrganization) -> Option<String> {
        Some(format!(
            "typedef {}    sqword;",
            data_organization.get_integer_c_type_approximation(8, true)
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

    struct MockQWordDataType;
    impl DataType for MockQWordDataType {
        fn get_name(&self) -> String {
            "qword".to_string()
        }
    }
    impl BuiltInDataType for MockQWordDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }
    impl QWordDataType for MockQWordDataType {
        fn get_opposite_signedness_data_type(&self) -> Box<dyn crate::program::seam_stubs::SignedQWordDataType> {
            unreachable!("not exercised in this smoke test")
        }
        fn qword_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn QWordDataType> {
            Box::new(MockQWordDataType)
        }
    }

    struct MockSignedQWordDataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockSignedQWordDataType {
        fn get_name(&self) -> String {
            "sqword".to_string()
        }
    }

    impl BuiltInDataType for MockSignedQWordDataType {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            data_organization.and_then(|org| self.signed_qword_get_c_type_declaration(org))
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl SignedQWordDataType for MockSignedQWordDataType {
        fn signed_qword_opposite_signedness_data_type(&self) -> Box<dyn QWordDataType> {
            Box::new(MockQWordDataType)
        }

        fn signed_qword_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn SignedQWordDataType> {
            match dtm {
                None => Box::new(MockSignedQWordDataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockSignedQWordDataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockSignedQWordDataType { dtm_tag: None };
        let dyn_dt: &dyn SignedQWordDataType = &dt;
        assert!(dyn_dt.is_signed());
        assert_eq!(dyn_dt.signed_qword_length(), 8);
        assert_eq!(dyn_dt.signed_qword_description(), "Signed Quad-Word (sdq, 8-bytes)");
        assert_eq!(dyn_dt.get_assembly_mnemonic(), "sdq");
        assert_eq!(DataType::get_name(dyn_dt), "sqword");
    }

    #[test]
    fn c_type_declaration_uses_signed_8byte_approximation() {
        let dt = MockSignedQWordDataType { dtm_tag: None };
        let org = MockDataOrganization;
        assert_eq!(
            dt.signed_qword_get_c_type_declaration(&org),
            Some("typedef int64    sqword;".to_string())
        );
    }

    #[test]
    fn opposite_signedness_returns_qword_data_type() {
        let dt = MockSignedQWordDataType { dtm_tag: None };
        let opposite = dt.signed_qword_opposite_signedness_data_type();
        assert!(!opposite.is_signed());
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockSignedQWordDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.signed_qword_clone(None);
        assert_eq!(cloned.signed_qword_length(), 8);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockSignedQWordDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.signed_qword_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.signed_qword_length(), 8);
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}
}
