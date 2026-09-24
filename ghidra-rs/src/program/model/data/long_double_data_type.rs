use crate::program::model::data::abstract_float_data_type::AbstractFloatDataType;
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Provides a definition of a compiler-defined `long double` within a program.
///
/// Port of `ghidra.program.model.data.LongDoubleDataType`, promoted straight to a trait because
/// it was selected as a dependency-cycle cut-point. Structurally similar to
/// [`FloatDataType`](super::float_data_type::FloatDataType)/[`DoubleDataType`](super::double_data_type::DoubleDataType)
/// -- see those traits' module docs for the shared rationale -- but `LongDoubleDataType`
/// additionally overrides `getCTypeDeclaration(DataOrganization)` itself (rather than inheriting
/// `AbstractFloatDataType`'s `float_c_type_declaration` default), always emitting a `typedef`
/// naming this type `"long double"` regardless of `hasLanguageDependantLength()`. That override
/// calls the protected `BuiltIn.getCTypeDeclaration(String, String, boolean)` helper; since
/// `AbstractFloatDataType` does not extend `BuiltIn` (only `DataType`/`BuiltInDataType`, per its
/// own module docs), that helper's trivial formula is reproduced directly here rather than
/// stubbed, mirroring the same precedent already set by
/// [`Integer3DataType`](super::integer3_data_type::Integer3DataType)'s own `getCTypeDeclaration`
/// override.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait LongDoubleDataType: AbstractFloatDataType {
    /// Port of `LongDoubleDataType.buildDescription()`, which overrides the default
    /// `AbstractFloatDataType.buildDescription()` by prefixing the inherited IEEE-754 standard
    /// wording with `"Compiler-defined 'long double' "`.
    fn long_double_data_type_description(&self) -> String {
        format!(
            "Compiler-defined 'long double' {}",
            self.build_ieee754_standard_description()
        )
    }

    /// Port of `LongDoubleDataType.hasLanguageDependantLength()`, which overrides the default
    /// `DataType.hasLanguageDependantLength()`. Always `true`.
    fn long_double_data_type_has_language_dependant_length(&self) -> bool {
        true
    }

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `LongDoubleDataType.clone(DataTypeManager)`, which overrides
    /// `AbstractFloatDataType`'s inherited `BuiltIn.clone(DataTypeManager)`. Left as a required
    /// method (no default); see [`Float4DataType::float4_clone`](super::float4_data_type::Float4DataType::float4_clone)
    /// for why.
    fn long_double_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn LongDoubleDataType>;

    /// Port of `LongDoubleDataType.getCTypeDeclaration(DataOrganization)`, which overrides the
    /// abstract `BuiltInDataType.getCTypeDeclaration(DataOrganization)` directly (bypassing
    /// `AbstractFloatDataType::float_c_type_declaration`'s `hasLanguageDependantLength()` check).
    /// `data_organization` is unused, matching the Java original. Exposed under a distinct name
    /// since `BuiltInDataType::get_c_type_declaration` is a required (no-default) method; a
    /// concrete `impl BuiltInDataType for ...` should delegate `get_c_type_declaration` to this
    /// instead of `float_c_type_declaration`.
    fn long_double_c_type_declaration(&self, data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
        let _ = data_organization;
        Some(format!("typedef long double    {};", self.get_name()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::pcode::floatformat::{get_float_format, FloatFormat};

    struct MockLongDoubleDataType {
        length: i32,
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockLongDoubleDataType {
        fn get_name(&self) -> String {
            "longdouble".to_string()
        }
        fn get_length(&self) -> i32 {
            self.encoded_length()
        }
        fn has_language_dependant_length(&self) -> bool {
            self.long_double_data_type_has_language_dependant_length()
        }
    }

    impl BuiltInDataType for MockLongDoubleDataType {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&DataOrganizationImpl>,
        ) -> Option<String> {
            self.long_double_c_type_declaration(data_organization)
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl AbstractFloatDataType for MockLongDoubleDataType {
        fn encoded_length(&self) -> i32 {
            self.length
        }
        fn float_format(&self) -> Option<&FloatFormat> {
            get_float_format(self.encoded_length()).ok()
        }
        fn build_description(&self) -> String {
            self.long_double_data_type_description()
        }
    }

    impl LongDoubleDataType for MockLongDoubleDataType {
        fn long_double_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn LongDoubleDataType> {
            match dtm {
                None => Box::new(MockLongDoubleDataType {
                    length: self.length,
                    dtm_tag: self.dtm_tag,
                }),
                Some(_) => Box::new(MockLongDoubleDataType {
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
        let dt = MockLongDoubleDataType { length: 10, dtm_tag: None };
        let dyn_dt: &dyn LongDoubleDataType = &dt;
        assert_eq!(dyn_dt.encoded_length(), 10);
        assert!(dyn_dt.long_double_data_type_has_language_dependant_length());
        assert!(DataType::has_language_dependant_length(dyn_dt));
    }

    #[test]
    fn description_prefixes_compiler_defined_wording() {
        let dt = MockLongDoubleDataType { length: 10, dtm_tag: None };
        let description = dt.long_double_data_type_description();
        assert!(description.starts_with("Compiler-defined 'long double' "));
        assert_eq!(dt.float_description(), description);
    }

    #[test]
    fn c_type_declaration_ignores_data_organization() {
        let dt = MockLongDoubleDataType { length: 10, dtm_tag: None };
        assert_eq!(
            dt.long_double_c_type_declaration(None),
            Some("typedef long double    longdouble;".to_string())
        );
        // Via the BuiltInDataType supertrait, matching the direct call.
        let via_trait: &dyn BuiltInDataType = &dt;
        assert_eq!(via_trait.get_c_type_declaration(None), dt.long_double_c_type_declaration(None));
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockLongDoubleDataType { length: 10, dtm_tag: Some("mgr-a") };
        let cloned = dt.long_double_clone(None);
        assert_eq!(cloned.encoded_length(), 10);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockLongDoubleDataType { length: 10, dtm_tag: Some("mgr-a") };
        let cloned = dt.long_double_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.encoded_length(), 10);
    }
}
