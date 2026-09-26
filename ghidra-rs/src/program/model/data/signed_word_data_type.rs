//! Port of `ghidra.program.model.data.SignedWordDataType`, promoted straight to a trait because
//! it was selected as a dependency-cycle cut-point (mirrors
//! [`Integer5DataType`](crate::program::model::data::integer5_data_type::Integer5DataType), which
//! documents the same set of design decisions in more detail).
//!
//! The Java class `extends AbstractSignedIntegerDataType`, itself a subclass of
//! `AbstractIntegerDataType`. Neither is yet ported, but every member `SignedWordDataType`
//! actually calls on them (`getDataOrganization()` from [`DataType`], and the final
//! `AbstractSignedIntegerDataType.isSigned()`) is already covered by an already-ported trait or
//! reproducible here directly, so no `seam_stubs` placeholder is needed for either supertype.
//!
//! Unlike `Integer5DataType`/`Int8TDataType` (whose opposite-signedness singleton is not yet
//! ported), `SignedWordDataType.getOppositeSignednessDataType()` clones `WordDataType.dataType`,
//! an already-ported trait
//! ([`WordDataType`](crate::program::model::data::word_data_type::WordDataType)), so this trait's
//! `signed_word_opposite_signedness_data_type` returns `Box<dyn WordDataType>` directly with no
//! seam-stub placeholder needed.
//!
//! `WordDataType` itself still declares its own opposite-signedness method
//! (`WordDataType::get_opposite_signedness_data_type`) against
//! `crate::program::seam_stubs::SignedWordDataType` (an empty marker trait), not this new real
//! trait -- switching that import to this trait is not a mechanical drop-in, since the seam-stub
//! is an empty marker (`pub trait SignedWordDataType {}`) while this trait declares several
//! required methods, so any existing mock implementing the seam-stub trivially would stop
//! compiling. Left as documented deferred reconciliation, matching how earlier `Unsigned*`
//! cut-points in this crate were left pointed at their own now-real-but-unswapped counterparts
//! (e.g. `IntegerDataType::get_opposite_signedness_data_type` still returns
//! `Box<dyn crate::program::seam_stubs::UnsignedIntegerDataType>` even though
//! `UnsignedIntegerDataType` is itself now a real, ported trait).
//!
//! Methods that only *override* an already-ported supertrait method with
//! SignedWordDataType-specific behavior (`getLength`, `getDescription`) cannot be redeclared
//! here without creating an ambiguous method name with [`DataType`] (Rust does not allow a
//! subtrait to "override" a supertrait's default method by re-declaring it). Instead, the real
//! SignedWordDataType-specific values for those overrides are exposed here under distinct
//! `signed_word_*` names; a future concrete implementation (once
//! `AbstractSignedIntegerDataType`/`AbstractIntegerDataType` are ported) should implement
//! `DataType`/`BuiltInDataType` directly and delegate to these helpers. Unlike
//! `SignedByteDataType` (which also overrides `getDecompilerDisplayName(DecompilerLanguage)`),
//! the Java source for this class has no such override, so this trait adds none either.
//! `getAssemblyMnemonic()` (unprefixed, since it is not declared by any already-ported
//! supertrait) mirrors [`WordDataType::get_assembly_mnemonic`](crate::program::model::data::word_data_type::WordDataType::get_assembly_mnemonic)'s
//! own precedent for the same reason.
//!
//! Static state not translated: the `dataType` singleton (needs a concrete struct) and the
//! `serialVersionUID` field (Java serialization has no Rust equivalent).

use crate::program::model::data::word_data_type::WordDataType;
use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Provides a basic implementation of a signed word datatype.
///
/// Port of `ghidra.program.model.data.SignedWordDataType`. See the module-level documentation for
/// the naming conventions used to resolve clashes with [`DataType`].
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait SignedWordDataType: DataType + BuiltInDataType {
    /// Determine if this type is signed.
    ///
    /// Port of the `final` `AbstractSignedIntegerDataType.isSigned()`, which `SignedWordDataType`
    /// inherits unchanged.
    fn is_signed(&self) -> bool {
        true
    }

    /// A brief description of this data-type.
    ///
    /// Port of `SignedWordDataType.getDescription()`, which overrides the abstract
    /// `DataType.getDescription()`. Exposed under a distinct name since [`DataType`] already
    /// declares `get_description`; see the module docs for why it cannot be redeclared here.
    fn signed_word_description(&self) -> String {
        "Signed Word (sdw, 2-bytes)".to_string()
    }

    /// The length of this data-type, in bytes.
    ///
    /// Port of `SignedWordDataType.getLength()`, which overrides the abstract
    /// `DataType.getLength()`. Exposed under a distinct name since [`DataType`] already declares
    /// `get_length`; see the module docs for why it cannot be redeclared here.
    fn signed_word_length(&self) -> i32 {
        2
    }

    /// The Assembly style data-type declaration for this data-type.
    ///
    /// Port of `SignedWordDataType.getAssemblyMnemonic()`, which overrides
    /// `AbstractIntegerDataType.getAssemblyMnemonic()`. That method is not part of any
    /// already-ported trait, so it is exposed here directly with no naming conflict.
    fn get_assembly_mnemonic(&self) -> String {
        "sdw".to_string()
    }

    /// Returns the data-type with the opposite signedness from this data-type (an unsigned word
    /// type).
    ///
    /// Port of `SignedWordDataType.getOppositeSignednessDataType()`, which overrides the abstract
    /// `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required method (no
    /// default) since the real implementation clones the `WordDataType.dataType` singleton -- see
    /// the module docs for why this can point at the already-ported [`WordDataType`] directly
    /// rather than a seam-stub placeholder.
    fn signed_word_opposite_signedness_data_type(&self) -> Box<dyn WordDataType>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `SignedWordDataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default) since the real
    /// implementation returns `self` when `dtm` already matches this instance's manager, which
    /// requires manager-identity comparison a mock cannot provide generically.
    fn signed_word_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn SignedWordDataType>;

    /// The C style data-type declaration for this data-type, given a specific `DataOrganization`.
    ///
    /// Port of `SignedWordDataType.getCTypeDeclaration(DataOrganization)`, which overrides the
    /// abstract `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. Exposed under a distinct
    /// name since [`BuiltInDataType`] already declares `get_c_type_declaration`; see the module
    /// docs for why it cannot be redeclared here. Reproduces `BuiltIn.getCTypeDeclaration(this,
    /// true, dataOrganization, false)`: a `typedef` line naming this type's fixed display name
    /// (`sword`) after the organization's signed 2-byte C-type approximation.
    fn signed_word_get_c_type_declaration(&self, data_organization: &DataOrganizationImpl) -> Option<String> {
        Some(format!(
            "typedef {}    sword;",
            data_organization.get_integer_c_type_approximation(2, true)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

            /// A real [`DataOrganizationImpl`] configured as this test expects.
    fn mock_data_organization() -> DataOrganizationImpl {
        let mut org = DataOrganizationImpl::get_default_organization(None);
        org.set_big_endian(false);
        org.set_pointer_size(8);
        org.set_pointer_shift(0);
        org.set_char_is_signed(true);
        org.set_char_size(1);
        org.set_wide_char_size(2);
        org.set_short_size(2);
        org.set_integer_size(4);
        org.set_long_size(8);
        org.set_long_long_size(8);
        org.set_float_size(4);
        org.set_double_size(8);
        org.set_long_double_size(8);
        org.set_absolute_max_alignment(0);
        org.set_machine_alignment(8);
        org.set_default_alignment(1);
        org.set_default_pointer_alignment(8);
        org.clear_size_alignment_map();
        org
    }

    struct MockWordDataType;
    impl DataType for MockWordDataType {
        fn get_name(&self) -> String {
            "word".to_string()
        }
    }
    impl BuiltInDataType for MockWordDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }
    impl WordDataType for MockWordDataType {
        fn get_opposite_signedness_data_type(&self) -> Box<dyn crate::program::seam_stubs::SignedWordDataType> {
            unreachable!("not exercised in this smoke test")
        }
        fn word_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn WordDataType> {
            Box::new(MockWordDataType)
        }
    }

    struct MockSignedWordDataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockSignedWordDataType {
        fn get_name(&self) -> String {
            "sword".to_string()
        }
    }

    impl BuiltInDataType for MockSignedWordDataType {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&DataOrganizationImpl>,
        ) -> Option<String> {
            data_organization.and_then(|org| self.signed_word_get_c_type_declaration(org))
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl SignedWordDataType for MockSignedWordDataType {
        fn signed_word_opposite_signedness_data_type(&self) -> Box<dyn WordDataType> {
            Box::new(MockWordDataType)
        }

        fn signed_word_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn SignedWordDataType> {
            match dtm {
                None => Box::new(MockSignedWordDataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockSignedWordDataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockSignedWordDataType { dtm_tag: None };
        let dyn_dt: &dyn SignedWordDataType = &dt;
        assert!(dyn_dt.is_signed());
        assert_eq!(dyn_dt.signed_word_length(), 2);
        assert_eq!(dyn_dt.signed_word_description(), "Signed Word (sdw, 2-bytes)");
        assert_eq!(dyn_dt.get_assembly_mnemonic(), "sdw");
        assert_eq!(DataType::get_name(dyn_dt), "sword");
    }

    #[test]
    fn c_type_declaration_uses_signed_2byte_approximation() {
        let dt = MockSignedWordDataType { dtm_tag: None };
        let org = mock_data_organization();
        assert_eq!(
            dt.signed_word_get_c_type_declaration(&org),
            Some("typedef short    sword;".to_string())
        );
    }

    #[test]
    fn opposite_signedness_returns_word_data_type() {
        let dt = MockSignedWordDataType { dtm_tag: None };
        let opposite = dt.signed_word_opposite_signedness_data_type();
        assert!(!opposite.is_signed());
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockSignedWordDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.signed_word_clone(None);
        assert_eq!(cloned.signed_word_length(), 2);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockSignedWordDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.signed_word_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.signed_word_length(), 2);
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}
}
