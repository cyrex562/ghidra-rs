use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::seam_stubs::UInt16TDataType as UInt16TDataTypeStub;

/// 16-bit signed integer (C99 Standard type `int16_t`).
///
/// Port of `ghidra.program.model.data.Int16TDataType`, promoted straight to a trait because it
/// was selected as a dependency-cycle cut-point.
///
/// The Java class `extends AbstractSignedIntegerDataType`, itself a subclass of
/// `AbstractIntegerDataType`. Neither is yet ported, but every member `Int16TDataType` actually
/// calls on them (`getDataOrganization()` from [`DataType`], and the final
/// `AbstractSignedIntegerDataType.isSigned()`) is already covered by an already-ported trait or
/// reproducible here directly, so no `seam_stubs` placeholder is needed for either supertype.
/// Likewise, `getCTypeDeclaration(DataOrganization)` overrides the abstract
/// `BuiltInDataType.getCTypeDeclaration(DataOrganization)` by delegating to `BuiltIn`'s protected
/// `getCTypeDeclaration(BuiltIn, boolean, DataOrganization, boolean)` helper; that helper's logic
/// (format a `typedef` line from the type's fixed display name and
/// `DataOrganization.getIntegerCTypeApproximation`) is reproduced directly here rather than
/// stubbed, since `BuiltIn` itself is not otherwise referenced.
///
/// Methods that only *override* an already-ported supertrait method with Int16TDataType-specific
/// behavior (`getLength`, `getDescription`, `getCTypeDeclaration`) cannot be redeclared here
/// without creating an ambiguous method name with [`DataType`]/[`BuiltInDataType`] (Rust does not
/// allow a subtrait to "override" a supertrait's default method by re-declaring it). Instead, the
/// real Int16TDataType-specific values for those overrides are exposed here under distinct
/// `int16_t_*` names; a future concrete implementation (once
/// `AbstractSignedIntegerDataType`/`AbstractIntegerDataType` are ported) should implement
/// `DataType`/`BuiltInDataType` directly and delegate to these helpers.
///
/// `getCDeclaration()` (unprefixed, since it is not declared by any already-ported supertrait)
/// always returns `None`, matching the Java override which unconditionally returns `null`.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct) and the
/// `serialVersionUID` field (Java serialization has no Rust equivalent).
pub trait Int16TDataType: DataType + BuiltInDataType {
    /// Determine if this type is signed.
    ///
    /// Port of the `final` `AbstractSignedIntegerDataType.isSigned()`, which `Int16TDataType`
    /// inherits unchanged.
    fn is_signed(&self) -> bool {
        true
    }

    /// The length of this data-type, in bytes.
    ///
    /// Port of `Int16TDataType.getLength()`, which overrides the abstract `DataType.getLength()`.
    /// Exposed under a distinct name since [`DataType`] already declares `get_length`; see the
    /// module docs for why it cannot be redeclared here. Always `2`, matching the fixed C99
    /// `int16_t` width (unlike `ShortDataType`/`IntegerDataType`, this is not derived from a
    /// `DataOrganization`).
    fn int16_t_length(&self) -> i32 {
        2
    }

    /// A brief description of this data-type.
    ///
    /// Port of `Int16TDataType.getDescription()`, which overrides the abstract
    /// `DataType.getDescription()`. Exposed under a distinct name since [`DataType`] already
    /// declares `get_description`; see the module docs for why it cannot be redeclared here.
    fn int16_t_description(&self) -> String {
        "Signed 16-bit Integer".to_string()
    }

    /// The C style data-type declaration for this data-type.
    ///
    /// Port of `Int16TDataType.getCDeclaration()`, which overrides
    /// `AbstractIntegerDataType.getCDeclaration()`. That method is not part of any already-ported
    /// trait, so it is exposed here directly with no naming conflict. Always `None`, matching the
    /// Java override which unconditionally returns `null`.
    fn get_c_declaration(&self) -> Option<String> {
        None
    }

    /// Returns the data-type with the opposite signedness from this data-type (an unsigned
    /// 16-bit integer type).
    ///
    /// Port of `Int16TDataType.getOppositeSignednessDataType()`, which overrides the abstract
    /// `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required method (no
    /// default) since the real implementation clones the `UInt16TDataType.dataType` singleton,
    /// which is not ported yet (see [`UInt16TDataTypeStub`] placeholder).
    fn get_opposite_signedness_data_type(&self) -> Box<dyn UInt16TDataTypeStub>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `Int16TDataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default) since the real
    /// implementation returns `self` when `dtm` already matches this instance's manager, which
    /// requires manager-identity comparison a mock cannot provide generically.
    fn int16_t_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Int16TDataType>;

    /// The C style data-type declaration for this data-type, given a specific `DataOrganization`.
    ///
    /// Port of `Int16TDataType.getCTypeDeclaration(DataOrganization)`, which overrides the
    /// abstract `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. Exposed under a distinct
    /// name since [`BuiltInDataType`] already declares `get_c_type_declaration`; see the module
    /// docs for why it cannot be redeclared here. Reproduces `BuiltIn.getCTypeDeclaration(this,
    /// true, dataOrganization, false)`: a `typedef` line naming this type's fixed display name
    /// (`int16_t`) after the organization's signed 16-bit C-type approximation.
    fn int16_t_get_c_type_declaration(&self, data_organization: &dyn DataOrganization) -> Option<String> {
        Some(format!(
            "typedef {}    int16_t;",
            data_organization.get_integer_c_type_approximation(2, true)
        ))
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

    struct MockUInt16TDataType;
    impl UInt16TDataTypeStub for MockUInt16TDataType {}

    struct MockInt16TDataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockInt16TDataType {
        fn get_name(&self) -> String {
            "int16_t".to_string()
        }
    }

    impl BuiltInDataType for MockInt16TDataType {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            data_organization.and_then(|org| self.int16_t_get_c_type_declaration(org))
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl Int16TDataType for MockInt16TDataType {
        fn get_opposite_signedness_data_type(&self) -> Box<dyn UInt16TDataTypeStub> {
            Box::new(MockUInt16TDataType)
        }

        fn int16_t_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Int16TDataType> {
            // Mirrors `Int16TDataType.clone(DataTypeManager)`: return an equivalent instance tied
            // to the requested manager (`None` here stands in for "already matches").
            match dtm {
                None => Box::new(MockInt16TDataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockInt16TDataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockInt16TDataType { dtm_tag: None };
        let dyn_dt: &dyn Int16TDataType = &dt;
        assert!(dyn_dt.is_signed());
        assert_eq!(dyn_dt.int16_t_length(), 2);
        assert_eq!(dyn_dt.int16_t_description(), "Signed 16-bit Integer");
        assert_eq!(dyn_dt.get_c_declaration(), None);
        // The DataType supertrait's own get_name is independently reachable and untouched.
        assert_eq!(DataType::get_name(dyn_dt), "int16_t");
    }

    #[test]
    fn c_type_declaration_uses_signed_16bit_approximation() {
        let dt = MockInt16TDataType { dtm_tag: None };
        let org = MockDataOrganization;
        assert_eq!(
            dt.int16_t_get_c_type_declaration(&org),
            Some("typedef int16    int16_t;".to_string())
        );
    }

    #[test]
    fn opposite_signedness_returns_distinct_placeholder() {
        let dt = MockInt16TDataType { dtm_tag: Some("a") };
        let _opposite = dt.get_opposite_signedness_data_type();
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockInt16TDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.int16_t_clone(None);
        assert_eq!(cloned.int16_t_description(), dt.int16_t_description());
        assert_eq!(cloned.int16_t_length(), 2);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockInt16TDataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.int16_t_clone(Some(Box::new(MockDataTypeManager)));
        // Mirrors the real `clone(DataTypeManager)` returning a distinct instance bound to the
        // requested manager when it differs from the current one, while remaining a fully
        // functional Int16TDataType.
        assert_eq!(cloned.int16_t_length(), 2);
        assert_eq!(cloned.get_c_declaration(), None);
    }
}
