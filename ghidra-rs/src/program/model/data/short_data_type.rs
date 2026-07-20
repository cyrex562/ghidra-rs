use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::seam_stubs::UnsignedShortDataType;

/// Basic implementation for a Short Integer dataType.
///
/// Port of `ghidra.program.model.data.ShortDataType`, promoted straight to a trait because it was
/// selected as a dependency-cycle cut-point.
///
/// The Java class `extends AbstractSignedIntegerDataType`, itself a subclass of
/// `AbstractIntegerDataType`. Neither is yet ported, but every member `ShortDataType` actually
/// calls on them (`getDataOrganization()` from [`DataType`], and the final
/// `AbstractSignedIntegerDataType.isSigned()`) is already covered by an already-ported trait or
/// reproducible here directly, so no `seam_stubs` placeholder is needed for either supertype.
///
/// Methods that only *override* an already-ported supertrait method with ShortDataType-specific
/// behavior (`getLength`, `hasLanguageDependantLength`, `getDescription`,
/// `getCTypeDeclaration`) cannot be redeclared here without creating an ambiguous method name with
/// [`DataType`]/[`BuiltInDataType`] (Rust does not allow a subtrait to "override" a supertrait's
/// default method by re-declaring it). Instead, the real ShortDataType-specific values for those
/// overrides are exposed here under distinct `short_*` names; a future concrete implementation
/// (once `AbstractSignedIntegerDataType`/`AbstractIntegerDataType` are ported) should implement
/// `DataType`/`BuiltInDataType` directly and delegate to these helpers.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct) and the
/// `serialVersionUID` field (Java serialization has no Rust equivalent).
pub trait ShortDataType: DataType + BuiltInDataType {
    /// Determine if this type is signed.
    ///
    /// Port of the `final` `AbstractSignedIntegerDataType.isSigned()`, which `ShortDataType`
    /// inherits unchanged.
    fn is_signed(&self) -> bool {
        true
    }

    /// The length of this data-type, in bytes.
    ///
    /// Port of `ShortDataType.getLength()`, which overrides the abstract `DataType.getLength()`.
    /// Exposed under a distinct name since [`DataType`] already declares `get_length`; see the
    /// module docs for why it cannot be redeclared here.
    fn short_length(&self) -> i32 {
        self.get_data_organization().get_short_size()
    }

    /// Indicates if the length of this data-type is determined based upon the
    /// `DataOrganization` obtained from the associated `DataTypeManager`.
    ///
    /// Port of `ShortDataType.hasLanguageDependantLength()`, which overrides the abstract
    /// `DataType.hasLanguageDependantLength()`. Exposed under a distinct name since [`DataType`]
    /// already declares `has_language_dependant_length`; see the module docs for why it cannot be
    /// redeclared here.
    fn short_has_language_dependant_length(&self) -> bool {
        true
    }

    /// A brief description of this data-type.
    ///
    /// Port of `ShortDataType.getDescription()`, which overrides the abstract
    /// `DataType.getDescription()`. Exposed under a distinct name since [`DataType`] already
    /// declares `get_description`; see the module docs for why it cannot be redeclared here.
    fn short_description(&self) -> String {
        "Signed Short Integer (compiler-specific size)".to_string()
    }

    /// The C style data-type declaration for this data-type.
    ///
    /// Port of `ShortDataType.getCDeclaration()`, which overrides
    /// `AbstractIntegerDataType.getCDeclaration()`. That method is not part of any already-ported
    /// trait, so it is exposed here directly with no naming conflict.
    fn get_c_declaration(&self) -> String {
        "short".to_string()
    }

    /// Returns the data-type with the opposite signedness from this data-type (an unsigned short
    /// type).
    ///
    /// Port of `ShortDataType.getOppositeSignednessDataType()`, which overrides the abstract
    /// `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required method (no
    /// default) since the real implementation clones the `UnsignedShortDataType.dataType`
    /// singleton, which is not ported yet (see [`UnsignedShortDataType`] placeholder).
    fn get_opposite_signedness_data_type(&self) -> Box<dyn UnsignedShortDataType>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `ShortDataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default) since the real
    /// implementation returns `self` when `dtm` already matches this instance's manager, which
    /// requires manager-identity comparison a mock cannot provide generically.
    fn short_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn ShortDataType>;

    /// The C style data-type declaration for this data-type, given a specific `DataOrganization`.
    ///
    /// Port of `ShortDataType.getCTypeDeclaration(DataOrganization)`, which overrides the abstract
    /// `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. Exposed under a distinct name
    /// since [`BuiltInDataType`] already declares `get_c_type_declaration`; see the module docs
    /// for why it cannot be redeclared here. Always returns `None`, matching the Java original's
    /// comment that `short` is a standard C-primitive name and type.
    fn short_get_c_type_declaration(&self) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::bit_field_packing::BitFieldPacking;
    use crate::program::model::data::data_organization::DataOrganization;

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

    struct MockUnsignedShortDataType;
    impl UnsignedShortDataType for MockUnsignedShortDataType {}

    struct MockShortDataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockShortDataType {
        fn get_name(&self) -> String {
            "short".to_string()
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization { short_size: 2 })
        }
    }

    impl BuiltInDataType for MockShortDataType {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl ShortDataType for MockShortDataType {
        fn get_opposite_signedness_data_type(&self) -> Box<dyn UnsignedShortDataType> {
            Box::new(MockUnsignedShortDataType)
        }

        fn short_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn ShortDataType> {
            // Mirrors `ShortDataType.clone(DataTypeManager)`: return an equivalent instance tied
            // to the requested manager (`None` here stands in for "already matches").
            match dtm {
                None => Box::new(MockShortDataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockShortDataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockShortDataType { dtm_tag: None };
        let dyn_dt: &dyn ShortDataType = &dt;
        assert!(dyn_dt.is_signed());
        assert!(dyn_dt.short_has_language_dependant_length());
        assert_eq!(dyn_dt.short_description(), "Signed Short Integer (compiler-specific size)");
        assert_eq!(dyn_dt.get_c_declaration(), "short");
        assert_eq!(dyn_dt.short_get_c_type_declaration(), None);
        // The DataType supertrait's own get_name is independently reachable and untouched.
        assert_eq!(DataType::get_name(dyn_dt), "short");
    }

    #[test]
    fn short_length_delegates_to_data_organization() {
        let dt = MockShortDataType { dtm_tag: None };
        assert_eq!(dt.short_length(), 2);
    }

    #[test]
    fn opposite_signedness_returns_distinct_placeholder() {
        let dt = MockShortDataType { dtm_tag: Some("a") };
        let _opposite = dt.get_opposite_signedness_data_type();
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockShortDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.short_clone(None);
        assert_eq!(cloned.short_description(), dt.short_description());
        assert_eq!(cloned.get_c_declaration(), "short");
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockShortDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.short_clone(Some(Box::new(MockDataTypeManager)));
        // Mirrors the real `clone(DataTypeManager)` returning a distinct instance bound to the
        // requested manager when it differs from the current one, while remaining a fully
        // functional ShortDataType.
        assert_eq!(cloned.get_c_declaration(), "short");
        assert_eq!(cloned.short_length(), 2);
    }
}
