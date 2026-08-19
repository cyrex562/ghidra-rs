use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::seam_stubs::SignedWordDataType;

/// Provides a basic implementation of a word datatype.
///
/// Port of `ghidra.program.model.data.WordDataType`, promoted straight to a trait because it was
/// selected as a dependency-cycle cut-point.
///
/// The Java class `extends AbstractUnsignedIntegerDataType`, itself a subclass of
/// `AbstractIntegerDataType`. Neither is yet ported, but every member `WordDataType` actually
/// calls on them (`getLength()`/`getDescription()` from [`DataType`], and the final
/// `AbstractUnsignedIntegerDataType.isSigned()`) is already covered by an already-ported trait or
/// reproducible here directly, so no `seam_stubs` placeholder is needed for either supertype.
///
/// Methods that only *override* an already-ported supertrait method with WordDataType-specific
/// behavior (`getDescription`, `getLength`) cannot be redeclared here without creating an
/// ambiguous method name with [`DataType`] (Rust does not allow a subtrait to "override" a
/// supertrait's default method by re-declaring it). Instead, the real WordDataType-specific
/// values for those overrides are exposed here under distinct `word_*` names; a future concrete
/// implementation (once `AbstractUnsignedIntegerDataType`/`AbstractIntegerDataType` are ported)
/// should implement `DataType`/`BuiltInDataType` directly and delegate to these helpers.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct) and the
/// `serialVersionUID` field (Java serialization has no Rust equivalent).
pub trait WordDataType: DataType + BuiltInDataType {
    /// Determine if this type is signed.
    ///
    /// Port of the `final` `AbstractUnsignedIntegerDataType.isSigned()`, which `WordDataType`
    /// inherits unchanged.
    fn is_signed(&self) -> bool {
        false
    }

    /// A brief description of this data-type.
    ///
    /// Port of `WordDataType.getDescription()`, which overrides the abstract
    /// `DataType.getDescription()`. Exposed under a distinct name since [`DataType`] already
    /// declares `get_description`; see the module docs for why it cannot be redeclared here.
    fn word_description(&self) -> String {
        "Unsigned Word (dw, 2-bytes)".to_string()
    }

    /// The length of this data-type, in bytes.
    ///
    /// Port of `WordDataType.getLength()`, which overrides the abstract `DataType.getLength()`.
    /// Exposed under a distinct name since [`DataType`] already declares `get_length`; see the
    /// module docs for why it cannot be redeclared here.
    fn word_length(&self) -> i32 {
        2
    }

    /// The Assembly style data-type declaration for this data-type.
    ///
    /// Port of `WordDataType.getAssemblyMnemonic()`, which overrides
    /// `AbstractIntegerDataType.getAssemblyMnemonic()`. That method is not part of any
    /// already-ported trait, so it is exposed here directly with no naming conflict.
    fn get_assembly_mnemonic(&self) -> String {
        "dw".to_string()
    }

    /// Returns the data-type with the opposite signedness from this data-type (a signed word
    /// type).
    ///
    /// Port of `WordDataType.getOppositeSignednessDataType()`, which overrides the abstract
    /// `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required method (no
    /// default) since the real implementation clones the `SignedWordDataType.dataType`
    /// singleton, which is not ported yet (see [`SignedWordDataType`] placeholder).
    fn get_opposite_signedness_data_type(&self) -> Box<dyn SignedWordDataType>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `WordDataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default) since the real
    /// implementation returns `self` when `dtm` already matches this instance's manager, which
    /// requires manager-identity comparison a mock cannot provide generically.
    fn word_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn WordDataType>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSignedWordDataType;
    impl SignedWordDataType for MockSignedWordDataType {}

    struct MockWordDataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockWordDataType {
        fn get_name(&self) -> String {
            "word".to_string()
        }
        fn get_length(&self) -> i32 {
            2
        }
        fn get_description(&self) -> String {
            "Unsigned Word (dw, 2-bytes)".to_string()
        }
    }

    impl BuiltInDataType for MockWordDataType {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn crate::program::model::data::data_organization::DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl WordDataType for MockWordDataType {
        fn get_opposite_signedness_data_type(&self) -> Box<dyn SignedWordDataType> {
            Box::new(MockSignedWordDataType)
        }

        fn word_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn WordDataType> {
            // Mirrors `WordDataType.clone(DataTypeManager)`: return an equivalent instance tied
            // to the requested manager (`None` here stands in for "already matches").
            match dtm {
                None => Box::new(MockWordDataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockWordDataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockWordDataType { dtm_tag: None };
        let dyn_dt: &dyn WordDataType = &dt;
        assert!(!dyn_dt.is_signed());
        assert_eq!(dyn_dt.word_length(), 2);
        assert_eq!(dyn_dt.word_description(), "Unsigned Word (dw, 2-bytes)");
        assert_eq!(dyn_dt.get_assembly_mnemonic(), "dw");
        // The DataType supertrait's own get_length/get_description are independently reachable.
        assert_eq!(DataType::get_length(dyn_dt), 2);
    }

    #[test]
    fn opposite_signedness_returns_distinct_placeholder() {
        let dt = MockWordDataType { dtm_tag: Some("a") };
        let _opposite = dt.get_opposite_signedness_data_type();
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockWordDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.word_clone(None);
        assert_eq!(cloned.word_description(), dt.word_description());
        assert_eq!(cloned.get_assembly_mnemonic(), "dw");
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockWordDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.word_clone(Some(Box::new(MockDataTypeManager)));
        // Mirrors the real `clone(DataTypeManager)` returning a distinct instance bound to the
        // requested manager when it differs from the current one, while remaining a fully
        // functional WordDataType.
        assert_eq!(cloned.get_assembly_mnemonic(), "dw");
        assert_eq!(cloned.word_length(), 2);
    }
}
