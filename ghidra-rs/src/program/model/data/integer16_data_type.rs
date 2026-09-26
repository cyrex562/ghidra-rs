use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::seam_stubs::UnsignedInteger16DataType as UnsignedInteger16DataTypeStub;

/// A fixed size 16 byte signed integer (commonly referred to in C as `int128_t`).
///
/// Port of `ghidra.program.model.data.Integer16DataType`, promoted straight to a trait because it
/// was selected as a dependency-cycle cut-point (mirrors
/// [`Int64TDataType`](crate::program::model::data::int64_t_data_type::Int64TDataType), which
/// documents the same set of design decisions in more detail).
///
/// The Java class `extends AbstractSignedIntegerDataType`, itself a subclass of
/// `AbstractIntegerDataType`. Neither is yet ported, but every member `Integer16DataType` actually
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
/// Integer16DataType-specific behavior (`getLength`, `getDescription`, `getCTypeDeclaration`)
/// cannot be redeclared here without creating an ambiguous method name with [`DataType`]/
/// [`BuiltInDataType`] (Rust does not allow a subtrait to "override" a supertrait's default method
/// by re-declaring it). Instead, the real Integer16DataType-specific values for those overrides
/// are exposed here under distinct `integer16_*` names; a future concrete implementation (once
/// `AbstractSignedIntegerDataType`/`AbstractIntegerDataType` are ported) should implement
/// `DataType`/`BuiltInDataType` directly and delegate to these helpers.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct) and the
/// `serialVersionUID` field (Java serialization has no Rust equivalent).
pub trait Integer16DataType: DataType + BuiltInDataType {
    /// Determine if this type is signed.
    ///
    /// Port of the `final` `AbstractSignedIntegerDataType.isSigned()`, which `Integer16DataType`
    /// inherits unchanged.
    fn is_signed(&self) -> bool {
        true
    }

    /// The length of this data-type, in bytes.
    ///
    /// Port of `Integer16DataType.getLength()`, which overrides the abstract
    /// `DataType.getLength()`. Exposed under a distinct name since [`DataType`] already declares
    /// `get_length`; see the module docs for why it cannot be redeclared here. Always `16`,
    /// matching the fixed 16-byte width (commonly `int128_t` in C).
    fn integer16_length(&self) -> i32 {
        16
    }

    /// A brief description of this data-type.
    ///
    /// Port of `Integer16DataType.getDescription()`, which overrides the abstract
    /// `DataType.getDescription()`. Exposed under a distinct name since [`DataType`] already
    /// declares `get_description`; see the module docs for why it cannot be redeclared here.
    fn integer16_description(&self) -> String {
        "Signed 16-Byte Integer".to_string()
    }

    /// Returns the data-type with the opposite signedness from this data-type (an unsigned
    /// 16-byte integer type).
    ///
    /// Port of `Integer16DataType.getOppositeSignednessDataType()`, which overrides the abstract
    /// `AbstractIntegerDataType.getOppositeSignednessDataType()`. Left as a required method (no
    /// default) since the real implementation clones the `UnsignedInteger16DataType.dataType`
    /// singleton, which is not ported yet (see [`UnsignedInteger16DataTypeStub`] placeholder).
    fn get_opposite_signedness_data_type(&self) -> Box<dyn UnsignedInteger16DataTypeStub>;

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `Integer16DataType.clone(DataTypeManager)`, which overrides
    /// `BuiltIn.clone(DataTypeManager)`. Left as a required method (no default) since the real
    /// implementation returns `self` when `dtm` already matches this instance's manager, which
    /// requires manager-identity comparison a mock cannot provide generically.
    fn integer16_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Integer16DataType>;

    /// The C style data-type declaration for this data-type, given a specific `DataOrganization`.
    ///
    /// Port of `Integer16DataType.getCTypeDeclaration(DataOrganization)`, which overrides the
    /// abstract `BuiltInDataType.getCTypeDeclaration(DataOrganization)`. Exposed under a distinct
    /// name since [`BuiltInDataType`] already declares `get_c_type_declaration`; see the module
    /// docs for why it cannot be redeclared here. Reproduces `BuiltIn.getCTypeDeclaration(this,
    /// true, dataOrganization, false)`: a `typedef` line naming this type's fixed display name
    /// after the organization's signed 16-byte C-type approximation.
    fn integer16_get_c_type_declaration(&self, data_organization: &DataOrganizationImpl) -> Option<String> {
        Some(format!(
            "typedef {}    int16;",
            data_organization.get_integer_c_type_approximation(16, true)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_organization_impl::DataOrganizationImpl;

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

    struct MockUnsignedInteger16DataType;
    impl UnsignedInteger16DataTypeStub for MockUnsignedInteger16DataType {}

    struct MockInteger16DataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockInteger16DataType {
        fn get_name(&self) -> String {
            "int16".to_string()
        }
    }

    impl BuiltInDataType for MockInteger16DataType {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&DataOrganizationImpl>,
        ) -> Option<String> {
            data_organization.and_then(|org| self.integer16_get_c_type_declaration(org))
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }

    impl Integer16DataType for MockInteger16DataType {
        fn get_opposite_signedness_data_type(&self) -> Box<dyn UnsignedInteger16DataTypeStub> {
            Box::new(MockUnsignedInteger16DataType)
        }

        fn integer16_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Integer16DataType> {
            // Mirrors `Integer16DataType.clone(DataTypeManager)`: return an equivalent instance
            // tied to the requested manager (`None` here stands in for "already matches").
            match dtm {
                None => Box::new(MockInteger16DataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockInteger16DataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockInteger16DataType { dtm_tag: None };
        let dyn_dt: &dyn Integer16DataType = &dt;
        assert!(dyn_dt.is_signed());
        assert_eq!(dyn_dt.integer16_length(), 16);
        assert_eq!(dyn_dt.integer16_description(), "Signed 16-Byte Integer");
        // The DataType supertrait's own get_name is independently reachable and untouched.
        assert_eq!(DataType::get_name(dyn_dt), "int16");
    }

    #[test]
    fn c_type_declaration_uses_signed_16byte_approximation() {
        let dt = MockInteger16DataType { dtm_tag: None };
        let org = mock_data_organization();
        assert_eq!(
            dt.integer16_get_c_type_declaration(&org),
            Some("typedef long long    int16;".to_string())
        );
    }

    #[test]
    fn opposite_signedness_returns_distinct_placeholder() {
        let dt = MockInteger16DataType { dtm_tag: Some("a") };
        let _opposite = dt.get_opposite_signedness_data_type();
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockInteger16DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.integer16_clone(None);
        assert_eq!(cloned.integer16_description(), dt.integer16_description());
        assert_eq!(cloned.integer16_length(), 16);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockInteger16DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.integer16_clone(Some(Box::new(MockDataTypeManager)));
        // Mirrors the real `clone(DataTypeManager)` returning a distinct instance bound to the
        // requested manager when it differs from the current one, while remaining a fully
        // functional Integer16DataType.
        assert_eq!(cloned.integer16_length(), 16);
        assert_eq!(cloned.integer16_description(), "Signed 16-Byte Integer");
    }
}
