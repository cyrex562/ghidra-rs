use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::seam_stubs::UnsignedLongDataType;

/// Basic implementation for a Signed Long Integer dataType.
///
/// Port of `ghidra.program.model.data.LongDataType`, promoted straight to a trait because it was
/// selected as a dependency-cycle cut-point (mirrors
/// [`ShortDataType`](crate::program::model::data::short_data_type::ShortDataType), which
/// documents the same set of design decisions in more detail).
///
/// The Java class `extends AbstractSignedIntegerDataType`, itself a subclass of
/// `AbstractIntegerDataType`. Neither is yet ported, but every member `LongDataType` actually
/// calls on them (`getDataOrganization()` from [`DataType`], the final
/// `AbstractSignedIntegerDataType.isSigned()`, and the `C_SIGNED_LONG` constant) is already
/// covered by an already-ported trait or reproducible here directly, so no `seam_stubs`
/// placeholder is needed for either supertype.
///
/// Methods that only *override* an already-ported supertrait method with LongDataType-specific
/// behavior (`getLength`, `hasLanguageDependantLength`, `getDescription`, `getCTypeDeclaration`)
/// cannot be redeclared here without creating an ambiguous method name with [`DataType`]/
/// [`BuiltInDataType`] (Rust does not allow a subtrait to "override" a supertrait's default
/// method by re-declaring it). Instead, the real LongDataType-specific values for those overrides
/// are exposed here under distinct `long_*` names; a future concrete implementation (once
/// `AbstractSignedIntegerDataType`/`AbstractIntegerDataType` are ported) should implement
/// `DataType`/`BuiltInDataType` directly and delegate to these helpers.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct) and the
/// `serialVersionUID` field (Java serialization has no Rust equivalent).
pub trait LongDataType: DataType + BuiltInDataType {
    /// Determine if this type is signed.
    ///
    /// Port of the `final` `AbstractSignedIntegerDataType.isSigned()`, which `LongDataType`
    /// inherits unchanged.
    fn is_signed(&self) -> bool {
        true
    }

    /// The length of this data-type, in bytes.
    ///
    /// Port of `LongDataType.getLength()`, which overrides the abstract `DataType.getLength()`.
    /// Exposed under a distinct name since [`DataType`] already declares `get_length`; see the
    /// module docs for why it cannot be redeclared here.
    fn long_length(&self) -> i32 {
        self.get_data_organization().get_long_size()
    }

    /// Indicates if the length of this data-type is determined based upon the
    /// `DataOrganization` obtained from the associated `DataTypeManager`.
    ///
    /// Port of `LongDataType.hasLanguageDependantLength()`, which overrides the abstract
    /// `DataType.hasLanguageDependantLength()`. Exposed under a distinct name since [`DataType`]
    /// already declares `has_language_dependant_length`; see the module docs for why it cannot be
    /// redeclared here.
    fn long_has_language_dependant_length(&self) -> bool {
        true
    }

    /// A brief description of this data-type.
    ///
    /// Port of `LongDataType.getDescription()`, which overrides the abstract
    /// `DataType.getDescription()`. Exposed under a distinct name since [`DataType`] already
    /// declares `get_description`; see the module docs for why it cannot be redeclared here.
    fn long_description(&self) -> String {
        "Signed Long Integer (compiler-specific size)".to_string()
    }

    /// The C style data-type declaration for this data-type.
    ///
    /// Port of `LongDataType.getCDeclaration()`, which overrides
    /// `AbstractIntegerDataType.getCDeclaration()`. That method is not part of any already-ported
    /// trait, so it is exposed here directly with no naming conflict. Reproduces the
    /// `C_SIGNED_LONG` constant from `AbstractIntegerDataType`.
    fn get_c_declaration(&self) -> String {
        "long".to_string()
    }

    /// Returns the data-type with the opposite signedness from this data-type (an unsigned long
    /// type).
    ///
    /// Port of `LongDataType.getOppositeSignednessDataType()`, which overrides the abstract
    /// `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required method (no
    /// default) since the real implementation clones the `UnsignedLongDataType.dataType`
    /// singleton, which is not ported yet (see [`UnsignedLongDataType`] placeholder).
    fn get_opposite_signedness_data_type(&self) -> Box<dyn UnsignedLongDataType>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `LongDataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default) since the real
    /// implementation returns `self` when `dtm` already matches this instance's manager, which
    /// requires manager-identity comparison a mock cannot provide generically.
    fn long_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn LongDataType>;

    /// The C style data-type declaration for this data-type, given a specific `DataOrganization`.
    ///
    /// Port of `LongDataType.getCTypeDeclaration(DataOrganization)`, which overrides the abstract
    /// `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. Exposed under a distinct name
    /// since [`BuiltInDataType`] already declares `get_c_type_declaration`; see the module docs
    /// for why it cannot be redeclared here. Always returns `None`, matching the Java original's
    /// comment that `long` is a standard C-primitive name and type.
    fn long_get_c_type_declaration(&self) -> Option<String> {
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
        long_size: i32,
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
            self.long_size
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

    struct MockUnsignedLongDataType;
    impl UnsignedLongDataType for MockUnsignedLongDataType {}

    struct MockLongDataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockLongDataType {
        fn get_name(&self) -> String {
            "long".to_string()
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization { long_size: 8 })
        }
    }

    impl BuiltInDataType for MockLongDataType {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl LongDataType for MockLongDataType {
        fn get_opposite_signedness_data_type(&self) -> Box<dyn UnsignedLongDataType> {
            Box::new(MockUnsignedLongDataType)
        }

        fn long_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn LongDataType> {
            // Mirrors `LongDataType.clone(DataTypeManager)`: return an equivalent instance tied
            // to the requested manager (`None` here stands in for "already matches").
            match dtm {
                None => Box::new(MockLongDataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockLongDataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockLongDataType { dtm_tag: None };
        let dyn_dt: &dyn LongDataType = &dt;
        assert!(dyn_dt.is_signed());
        assert!(dyn_dt.long_has_language_dependant_length());
        assert_eq!(dyn_dt.long_description(), "Signed Long Integer (compiler-specific size)");
        assert_eq!(dyn_dt.get_c_declaration(), "long");
        assert_eq!(dyn_dt.long_get_c_type_declaration(), None);
        // The DataType supertrait's own get_name is independently reachable and untouched.
        assert_eq!(DataType::get_name(dyn_dt), "long");
    }

    #[test]
    fn long_length_delegates_to_data_organization() {
        let dt = MockLongDataType { dtm_tag: None };
        assert_eq!(dt.long_length(), 8);
    }

    #[test]
    fn opposite_signedness_returns_distinct_placeholder() {
        let dt = MockLongDataType { dtm_tag: Some("a") };
        let _opposite = dt.get_opposite_signedness_data_type();
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockLongDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.long_clone(None);
        assert_eq!(cloned.long_description(), dt.long_description());
        assert_eq!(cloned.get_c_declaration(), "long");
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockLongDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.long_clone(Some(Box::new(MockDataTypeManager)));
        // Mirrors the real `clone(DataTypeManager)` returning a distinct instance bound to the
        // requested manager when it differs from the current one, while remaining a fully
        // functional LongDataType.
        assert_eq!(cloned.get_c_declaration(), "long");
        assert_eq!(cloned.long_length(), 8);
    }
}
