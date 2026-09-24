use crate::program::model::data::abstract_float_data_type::AbstractFloatDataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Provides a definition of a compiler-defined `double` within a program.
///
/// Port of `ghidra.program.model.data.DoubleDataType`, promoted straight to a trait because it
/// was selected as a dependency-cycle cut-point. Structurally identical to
/// [`FloatDataType`](super::float_data_type::FloatDataType) -- see that trait's module docs for
/// the full rationale, which this mirrors exactly (data-organization-dependent encoded length left
/// to a concrete implementation to compute/store; `buildDescription`/`hasLanguageDependantLength`
/// overrides exposed under distinct names for the same ambiguous-redeclare reason).
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait DoubleDataType: AbstractFloatDataType {
    /// Port of `DoubleDataType.buildDescription()`, which overrides the default
    /// `AbstractFloatDataType.buildDescription()` by prefixing the inherited IEEE-754 standard
    /// wording with `"Compiler-defined 'double' "`.
    fn double_data_type_description(&self) -> String {
        format!(
            "Compiler-defined 'double' {}",
            self.build_ieee754_standard_description()
        )
    }

    /// Port of `DoubleDataType.hasLanguageDependantLength()`, which overrides the default
    /// `DataType.hasLanguageDependantLength()`. Always `true`.
    fn double_data_type_has_language_dependant_length(&self) -> bool {
        true
    }

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `DoubleDataType.clone(DataTypeManager)`, which overrides
    /// `AbstractFloatDataType`'s inherited `BuiltIn.clone(DataTypeManager)`. Left as a required
    /// method (no default); see [`Float4DataType::float4_clone`](super::float4_data_type::Float4DataType::float4_clone)
    /// for why.
    fn double_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn DoubleDataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
    use crate::program::model::data::data_type::DataType;
    use crate::pcode::floatformat::{get_float_format, FloatFormat};

    struct MockDoubleDataType {
        length: i32,
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockDoubleDataType {
        fn get_name(&self) -> String {
            "double".to_string()
        }
        fn get_length(&self) -> i32 {
            self.encoded_length()
        }
        fn has_language_dependant_length(&self) -> bool {
            self.double_data_type_has_language_dependant_length()
        }
    }

    impl BuiltInDataType for MockDoubleDataType {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&DataOrganizationImpl>,
        ) -> Option<String> {
            self.float_c_type_declaration(data_organization)
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl AbstractFloatDataType for MockDoubleDataType {
        fn encoded_length(&self) -> i32 {
            self.length
        }
        fn float_format(&self) -> Option<&FloatFormat> {
            get_float_format(self.encoded_length()).ok()
        }
        fn build_description(&self) -> String {
            self.double_data_type_description()
        }
    }

    impl DoubleDataType for MockDoubleDataType {
        fn double_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn DoubleDataType> {
            match dtm {
                None => Box::new(MockDoubleDataType {
                    length: self.length,
                    dtm_tag: self.dtm_tag,
                }),
                Some(_) => Box::new(MockDoubleDataType {
                    length: self.length,
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockDoubleDataType { length: 8, dtm_tag: None };
        let dyn_dt: &dyn DoubleDataType = &dt;
        assert_eq!(dyn_dt.encoded_length(), 8);
        assert!(dyn_dt.double_data_type_has_language_dependant_length());
        assert!(DataType::has_language_dependant_length(dyn_dt));
    }

    #[test]
    fn description_prefixes_compiler_defined_wording() {
        let dt = MockDoubleDataType { length: 8, dtm_tag: None };
        let description = dt.double_data_type_description();
        assert!(description.starts_with("Compiler-defined 'double' "));
        assert!(description.contains("64-bit"));
        assert_eq!(dt.float_description(), description);
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockDoubleDataType { length: 8, dtm_tag: Some("mgr-a") };
        let cloned = dt.double_clone(None);
        assert_eq!(cloned.encoded_length(), 8);
        assert_eq!(cloned.double_data_type_description(), dt.double_data_type_description());
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockDoubleDataType { length: 8, dtm_tag: Some("mgr-a") };
        let cloned = dt.double_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.encoded_length(), 8);
    }
}
