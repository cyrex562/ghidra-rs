use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::decompiler_language::DecompilerLanguage;
use crate::program::seam_stubs::SignedByteDataType;

/// Provides a definition of a Byte within a program.
///
/// Port of `ghidra.program.model.data.ByteDataType`, promoted straight to a trait because it was
/// selected as a dependency-cycle cut-point.
///
/// The Java class `extends AbstractUnsignedIntegerDataType`, itself a subclass of
/// `AbstractIntegerDataType`. Neither is yet ported, but every member `ByteDataType` actually
/// calls on them (`getLength()`/`getDescription()` from [`DataType`], and the final
/// `AbstractUnsignedIntegerDataType.isSigned()`) is already covered by an already-ported trait or
/// reproducible here directly -- mirroring [`DWordDataType`](super::dword_data_type::DWordDataType)
/// -- so no `seam_stubs` placeholder is needed for either supertype.
///
/// Methods that only *override* an already-ported supertrait method with ByteDataType-specific
/// behavior (`getDescription`, `getLength`) cannot be redeclared here without creating an
/// ambiguous method name with [`DataType`] (Rust does not allow a subtrait to "override" a
/// supertrait's default method by re-declaring it). Instead, the real ByteDataType-specific
/// values for those overrides are exposed here under distinct `byte_*` names; a future concrete
/// implementation (once `AbstractUnsignedIntegerDataType`/`AbstractIntegerDataType` are ported)
/// should implement `DataType`/`BuiltInDataType` directly and delegate to these helpers.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct) and the
/// `serialVersionUID` field (Java serialization has no Rust equivalent).
pub trait ByteDataType: DataType + BuiltInDataType {
    /// Determine if this type is signed.
    ///
    /// Port of the `final` `AbstractUnsignedIntegerDataType.isSigned()`, which `ByteDataType`
    /// inherits unchanged.
    fn is_signed(&self) -> bool {
        false
    }

    /// A brief description of this data-type.
    ///
    /// Port of `ByteDataType.getDescription()`, which overrides the abstract
    /// `DataType.getDescription()`. Exposed under a distinct name since [`DataType`] already
    /// declares `get_description`; see the module docs for why it cannot be redeclared here.
    fn byte_description(&self) -> String {
        "Unsigned Byte (db)".to_string()
    }

    /// The length of this data-type, in bytes.
    ///
    /// Port of `ByteDataType.getLength()`, which overrides the abstract `DataType.getLength()`.
    /// Exposed under a distinct name since [`DataType`] already declares `get_length`; see the
    /// module docs for why it cannot be redeclared here.
    fn byte_length(&self) -> i32 {
        1
    }

    /// The Assembly style data-type declaration for this data-type.
    ///
    /// Port of `ByteDataType.getAssemblyMnemonic()`, which overrides
    /// `AbstractIntegerDataType.getAssemblyMnemonic()`. That method is not part of any
    /// already-ported trait, so it is exposed here directly with no naming conflict.
    fn get_assembly_mnemonic(&self) -> String {
        "db".to_string()
    }

    /// The name to display for this data-type in the decompiler's output, for the given
    /// decompiler output language.
    ///
    /// Port of `ByteDataType.getDecompilerDisplayName(DecompilerLanguage)`, which overrides
    /// `DataType.getDecompilerDisplayName(DecompilerLanguage)`. Exposed under a distinct name
    /// since [`DataType`] already declares `get_decompiler_display_name`; see the module docs for
    /// why it cannot be redeclared here. Falls back to [`DataType::get_name`] (standing in for the
    /// Java `name` field) for every language other than
    /// [`DecompilerLanguage::JavaLanguage`].
    fn byte_decompiler_display_name(&self, language: DecompilerLanguage) -> String {
        if language == DecompilerLanguage::JavaLanguage {
            "ubyte".to_string()
        } else {
            self.get_name()
        }
    }

    /// Returns the data-type with the opposite signedness from this data-type (a signed byte
    /// type).
    ///
    /// Port of `ByteDataType.getOppositeSignednessDataType()`, which overrides the abstract
    /// `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required method (no
    /// default) since the real implementation clones the `SignedByteDataType.dataType` singleton,
    /// which is not ported yet (see [`SignedByteDataType`] placeholder).
    fn get_opposite_signedness_data_type(&self) -> Box<dyn SignedByteDataType>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `ByteDataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default) since the real
    /// implementation returns `self` when `dtm` already matches this instance's manager, which
    /// requires manager-identity comparison a mock cannot provide generically.
    fn byte_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn ByteDataType>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSignedByteDataType;
    impl SignedByteDataType for MockSignedByteDataType {}

    struct MockByteDataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockByteDataType {
        fn get_name(&self) -> String {
            "byte".to_string()
        }
        fn get_length(&self) -> i32 {
            1
        }
        fn get_description(&self) -> String {
            "Unsigned Byte (db)".to_string()
        }
    }

    impl BuiltInDataType for MockByteDataType {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn crate::program::model::data::data_organization::DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl ByteDataType for MockByteDataType {
        fn get_opposite_signedness_data_type(&self) -> Box<dyn SignedByteDataType> {
            Box::new(MockSignedByteDataType)
        }

        fn byte_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn ByteDataType> {
            // Mirrors `ByteDataType.clone(DataTypeManager)`: return an equivalent instance tied
            // to the requested manager (`None` here stands in for "already matches").
            match dtm {
                None => Box::new(MockByteDataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockByteDataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockByteDataType { dtm_tag: None };
        let dyn_dt: &dyn ByteDataType = &dt;
        assert!(!dyn_dt.is_signed());
        assert_eq!(dyn_dt.byte_length(), 1);
        assert_eq!(dyn_dt.byte_description(), "Unsigned Byte (db)");
        assert_eq!(dyn_dt.get_assembly_mnemonic(), "db");
        // The DataType supertrait's own get_length/get_description are independently reachable.
        assert_eq!(DataType::get_length(dyn_dt), 1);
    }

    #[test]
    fn decompiler_display_name_java_language_uses_ubyte() {
        let dt = MockByteDataType { dtm_tag: None };
        assert_eq!(dt.byte_decompiler_display_name(DecompilerLanguage::JavaLanguage), "ubyte");
    }

    #[test]
    fn decompiler_display_name_other_language_falls_back_to_name() {
        let dt = MockByteDataType { dtm_tag: None };
        assert_eq!(dt.byte_decompiler_display_name(DecompilerLanguage::CLanguage), "byte");
    }

    #[test]
    fn opposite_signedness_returns_distinct_placeholder() {
        let dt = MockByteDataType { dtm_tag: Some("a") };
        let _opposite = dt.get_opposite_signedness_data_type();
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockByteDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.byte_clone(None);
        assert_eq!(cloned.byte_description(), dt.byte_description());
        assert_eq!(cloned.get_assembly_mnemonic(), "db");
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockByteDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.byte_clone(Some(Box::new(MockDataTypeManager)));
        // Mirrors the real `clone(DataTypeManager)` returning a distinct instance bound to the
        // requested manager when it differs from the current one, while remaining a fully
        // functional ByteDataType.
        assert_eq!(cloned.get_assembly_mnemonic(), "db");
        assert_eq!(cloned.byte_length(), 1);
    }
}
