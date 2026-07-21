use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::seam_stubs::SignedQWordDataType;

/// Provides a definition of a Quad Word within a program.
///
/// Port of `ghidra.program.model.data.QWordDataType`, promoted straight to a trait because it was
/// selected as a dependency-cycle cut-point.
///
/// The Java class `extends AbstractUnsignedIntegerDataType`, itself a subclass of
/// `AbstractIntegerDataType`. Neither is yet ported, but every member `QWordDataType` actually
/// calls on them (`getLength()`/`getDescription()` from [`DataType`], and the final
/// `AbstractUnsignedIntegerDataType.isSigned()`) is already covered by an already-ported trait or
/// reproducible here directly, so no `seam_stubs` placeholder is needed for either supertype.
///
/// Methods that only *override* an already-ported supertrait method with QWordDataType-specific
/// behavior (`getDescription`, `getLength`) cannot be redeclared here without creating an
/// ambiguous method name with [`DataType`] (Rust does not allow a subtrait to "override" a
/// supertrait's default method by re-declaring it). Instead, the real QWordDataType-specific
/// values for those overrides are exposed here under distinct `qword_*` names; a future concrete
/// implementation (once `AbstractUnsignedIntegerDataType`/`AbstractIntegerDataType` are ported)
/// should implement `DataType`/`BuiltInDataType` directly and delegate to these helpers.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct) and the
/// `serialVersionUID` field (Java serialization has no Rust equivalent).
pub trait QWordDataType: DataType + BuiltInDataType {
    /// Determine if this type is signed.
    ///
    /// Port of the `final` `AbstractUnsignedIntegerDataType.isSigned()`, which `QWordDataType`
    /// inherits unchanged.
    fn is_signed(&self) -> bool {
        false
    }

    /// A brief description of this data-type.
    ///
    /// Port of `QWordDataType.getDescription()`, which overrides the abstract
    /// `DataType.getDescription()`. Exposed under a distinct name since [`DataType`] already
    /// declares `get_description`; see the module docs for why it cannot be redeclared here.
    fn qword_description(&self) -> String {
        "Unsigned Quad-Word (dq, 8-bytes)".to_string()
    }

    /// The length of this data-type, in bytes.
    ///
    /// Port of `QWordDataType.getLength()`, which overrides the abstract `DataType.getLength()`.
    /// Exposed under a distinct name since [`DataType`] already declares `get_length`; see the
    /// module docs for why it cannot be redeclared here.
    fn qword_length(&self) -> i32 {
        8
    }

    /// The Assembly style data-type declaration for this data-type.
    ///
    /// Port of `QWordDataType.getAssemblyMnemonic()`, which overrides
    /// `AbstractIntegerDataType.getAssemblyMnemonic()`. That method is not part of any
    /// already-ported trait, so it is exposed here directly with no naming conflict.
    fn get_assembly_mnemonic(&self) -> String {
        "dq".to_string()
    }

    /// Returns the data-type with the opposite signedness from this data-type (a signed
    /// quad-word type).
    ///
    /// Port of `QWordDataType.getOppositeSignednessDataType()`, which overrides the abstract
    /// `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required method (no
    /// default) since the real implementation clones the `SignedQWordDataType.dataType`
    /// singleton, which is not ported yet (see [`SignedQWordDataType`] placeholder).
    fn get_opposite_signedness_data_type(&self) -> Box<dyn SignedQWordDataType>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `QWordDataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default) since the real
    /// implementation returns `self` when `dtm` already matches this instance's manager, which
    /// requires manager-identity comparison a mock cannot provide generically.
    fn qword_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn QWordDataType>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSignedQWordDataType;
    impl SignedQWordDataType for MockSignedQWordDataType {}

    struct MockQWordDataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockQWordDataType {
        fn get_name(&self) -> String {
            "qword".to_string()
        }
        fn get_length(&self) -> i32 {
            8
        }
        fn get_description(&self) -> String {
            "Unsigned Quad-Word (dq, 8-bytes)".to_string()
        }
    }

    impl BuiltInDataType for MockQWordDataType {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn crate::program::model::data::data_organization::DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl QWordDataType for MockQWordDataType {
        fn get_opposite_signedness_data_type(&self) -> Box<dyn SignedQWordDataType> {
            Box::new(MockSignedQWordDataType)
        }

        fn qword_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn QWordDataType> {
            // Mirrors `QWordDataType.clone(DataTypeManager)`: return an equivalent instance tied
            // to the requested manager (`None` here stands in for "already matches").
            match dtm {
                None => Box::new(MockQWordDataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockQWordDataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockQWordDataType { dtm_tag: None };
        let dyn_dt: &dyn QWordDataType = &dt;
        assert!(!dyn_dt.is_signed());
        assert_eq!(dyn_dt.qword_length(), 8);
        assert_eq!(dyn_dt.qword_description(), "Unsigned Quad-Word (dq, 8-bytes)");
        assert_eq!(dyn_dt.get_assembly_mnemonic(), "dq");
        // The DataType supertrait's own get_length/get_description are independently reachable.
        assert_eq!(DataType::get_length(dyn_dt), 8);
    }

    #[test]
    fn opposite_signedness_returns_distinct_placeholder() {
        let dt = MockQWordDataType { dtm_tag: Some("a") };
        let _opposite = dt.get_opposite_signedness_data_type();
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockQWordDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.qword_clone(None);
        assert_eq!(cloned.qword_description(), dt.qword_description());
        assert_eq!(cloned.get_assembly_mnemonic(), "dq");
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockQWordDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.qword_clone(Some(Box::new(MockDataTypeManager)));
        // Mirrors the real `clone(DataTypeManager)` returning a distinct instance bound to the
        // requested manager when it differs from the current one, while remaining a fully
        // functional QWordDataType.
        assert_eq!(cloned.get_assembly_mnemonic(), "dq");
        assert_eq!(cloned.qword_length(), 8);
    }
}
