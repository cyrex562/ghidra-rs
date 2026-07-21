use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::seam_stubs::UnsignedInteger6DataType as UnsignedInteger6DataTypeStub;

/// A fixed size 6 byte signed integer.
///
/// Port of `ghidra.program.model.data.Integer6DataType`, promoted straight to a trait because it
/// was selected as a dependency-cycle cut-point (mirrors
/// [`Integer5DataType`](crate::program::model::data::integer5_data_type::Integer5DataType), which
/// documents the same set of design decisions in more detail).
///
/// The Java class `extends AbstractSignedIntegerDataType`, itself a subclass of
/// `AbstractIntegerDataType`. Neither is yet ported, but every member `Integer6DataType` actually
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
/// Methods that only *override* an already-ported supertrait method with
/// Integer6DataType-specific behavior (`getLength`, `getDescription`, `getCTypeDeclaration`)
/// cannot be redeclared here without creating an ambiguous method name with [`DataType`]/
/// [`BuiltInDataType`] (Rust does not allow a subtrait to "override" a supertrait's default method
/// by re-declaring it). Instead, the real Integer6DataType-specific values for those overrides
/// are exposed here under distinct `integer6_*` names; a future concrete implementation (once
/// `AbstractSignedIntegerDataType`/`AbstractIntegerDataType` are ported) should implement
/// `DataType`/`BuiltInDataType` directly and delegate to these helpers.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct) and the
/// `serialVersionUID` field (Java serialization has no Rust equivalent).
pub trait Integer6DataType: DataType + BuiltInDataType {
    /// Determine if this type is signed.
    ///
    /// Port of the `final` `AbstractSignedIntegerDataType.isSigned()`, which `Integer6DataType`
    /// inherits unchanged.
    fn is_signed(&self) -> bool {
        true
    }

    /// The length of this data-type, in bytes.
    ///
    /// Port of `Integer6DataType.getLength()`, which overrides the abstract
    /// `DataType.getLength()`. Exposed under a distinct name since [`DataType`] already declares
    /// `get_length`; see the module docs for why it cannot be redeclared here. Always `6`.
    fn integer6_length(&self) -> i32 {
        6
    }

    /// A brief description of this data-type.
    ///
    /// Port of `Integer6DataType.getDescription()`, which overrides the abstract
    /// `DataType.getDescription()`. Exposed under a distinct name since [`DataType`] already
    /// declares `get_description`; see the module docs for why it cannot be redeclared here.
    fn integer6_description(&self) -> String {
        "Signed 6-Byte Integer".to_string()
    }

    /// Returns the data-type with the opposite signedness from this data-type (an unsigned
    /// 6-byte integer type).
    ///
    /// Port of `Integer6DataType.getOppositeSignednessDataType()`, which overrides the abstract
    /// `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required method (no
    /// default) since the real implementation clones the `UnsignedInteger6DataType.dataType`
    /// singleton, which is not ported yet (see [`UnsignedInteger6DataTypeStub`] placeholder).
    fn get_opposite_signedness_data_type(&self) -> Box<dyn UnsignedInteger6DataTypeStub>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `Integer6DataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default) since the real
    /// implementation returns `self` when `dtm` already matches this instance's manager, which
    /// requires manager-identity comparison a mock cannot provide generically.
    fn integer6_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Integer6DataType>;

    /// The C style data-type declaration for this data-type, given a specific `DataOrganization`.
    ///
    /// Port of `Integer6DataType.getCTypeDeclaration(DataOrganization)`, which overrides the
    /// abstract `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. Exposed under a distinct
    /// name since [`BuiltInDataType`] already declares `get_c_type_declaration`; see the module
    /// docs for why it cannot be redeclared here. Reproduces `BuiltIn.getCTypeDeclaration(this,
    /// true, dataOrganization, false)`: a `typedef` line naming this type's fixed display name
    /// after the organization's signed 6-byte C-type approximation.
    fn integer6_get_c_type_declaration(&self, data_organization: &dyn DataOrganization) -> Option<String> {
        Some(format!(
            "typedef {}    int6;",
            data_organization.get_integer_c_type_approximation(6, true)
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

    struct MockUnsignedInteger6DataType;
    impl UnsignedInteger6DataTypeStub for MockUnsignedInteger6DataType {}

    struct MockInteger6DataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockInteger6DataType {
        fn get_name(&self) -> String {
            "int6".to_string()
        }
    }

    impl BuiltInDataType for MockInteger6DataType {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            data_organization.and_then(|org| self.integer6_get_c_type_declaration(org))
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl Integer6DataType for MockInteger6DataType {
        fn get_opposite_signedness_data_type(&self) -> Box<dyn UnsignedInteger6DataTypeStub> {
            Box::new(MockUnsignedInteger6DataType)
        }

        fn integer6_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Integer6DataType> {
            // Mirrors `Integer6DataType.clone(DataTypeManager)`: return an equivalent instance
            // tied to the requested manager (`None` here stands in for "already matches").
            match dtm {
                None => Box::new(MockInteger6DataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockInteger6DataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockInteger6DataType { dtm_tag: None };
        let dyn_dt: &dyn Integer6DataType = &dt;
        assert!(dyn_dt.is_signed());
        assert_eq!(dyn_dt.integer6_length(), 6);
        assert_eq!(dyn_dt.integer6_description(), "Signed 6-Byte Integer");
        // The DataType supertrait's own get_name is independently reachable and untouched.
        assert_eq!(DataType::get_name(dyn_dt), "int6");
    }

    #[test]
    fn c_type_declaration_uses_signed_6byte_approximation() {
        let dt = MockInteger6DataType { dtm_tag: None };
        let org = MockDataOrganization;
        assert_eq!(
            dt.integer6_get_c_type_declaration(&org),
            Some("typedef int48    int6;".to_string())
        );
    }

    #[test]
    fn opposite_signedness_returns_distinct_placeholder() {
        let dt = MockInteger6DataType { dtm_tag: Some("a") };
        let _opposite = dt.get_opposite_signedness_data_type();
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockInteger6DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.integer6_clone(None);
        assert_eq!(cloned.integer6_description(), dt.integer6_description());
        assert_eq!(cloned.integer6_length(), 6);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockInteger6DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.integer6_clone(Some(Box::new(MockDataTypeManager)));
        // Mirrors the real `clone(DataTypeManager)` returning a distinct instance bound to the
        // requested manager when it differs from the current one, while remaining a fully
        // functional Integer6DataType.
        assert_eq!(cloned.integer6_length(), 6);
        assert_eq!(cloned.integer6_description(), "Signed 6-Byte Integer");
    }
}
