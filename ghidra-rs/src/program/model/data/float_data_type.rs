use crate::program::model::data::abstract_float_data_type::AbstractFloatDataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Provides a definition of a compiler-defined `float` within a program.
///
/// Port of `ghidra.program.model.data.FloatDataType`, promoted straight to a trait because it was
/// selected as a dependency-cycle cut-point.
///
/// The Java class `extends AbstractFloatDataType`, already ported as a trait
/// ([`AbstractFloatDataType`]). Unlike the fixed-length siblings
/// ([`Float4DataType`](super::float4_data_type::Float4DataType) etc.), `FloatDataType`'s encoded
/// length is data-organization-dependent (`getDataOrganization(dtm).getFloatSize()`, computed
/// once in the constructor); as with every other `Abstract*DataType` cut-point trait, that
/// constructor logic is left to a concrete implementation to perform and store itself (see
/// [`AbstractFloatDataType`]'s own module docs), so this trait adds nothing for
/// `AbstractFloatDataType::encoded_length` beyond what is already documented there.
///
/// `buildDescription()` overrides the *default* (not required) `AbstractFloatDataType.build_description`,
/// and `hasLanguageDependantLength()` overrides the *default* `DataType.has_language_dependant_length`.
/// Rust does not allow a subtrait to override a supertrait's default method by redeclaring it (see
/// [`AbstractFloatDataType`]'s own module docs on the same restriction), so both are exposed here
/// under distinct `float_data_type_*` names; a concrete implementation should have its own
/// `AbstractFloatDataType::build_description`/`DataType::has_language_dependant_length` overrides
/// delegate to these.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait FloatDataType: AbstractFloatDataType {
    /// Port of `FloatDataType.buildDescription()`, which overrides the default
    /// `AbstractFloatDataType.buildDescription()` by prefixing the inherited IEEE-754 standard
    /// wording (`super.buildDescription()`, ported as
    /// [`AbstractFloatDataType::build_ieee754_standard_description`]) with `"Compiler-defined
    /// 'float' "`.
    fn float_data_type_description(&self) -> String {
        format!(
            "Compiler-defined 'float' {}",
            self.build_ieee754_standard_description()
        )
    }

    /// Port of `FloatDataType.hasLanguageDependantLength()`, which overrides the default
    /// `DataType.hasLanguageDependantLength()`. Always `true`, since this type's length is
    /// resolved from the associated `DataTypeManager`'s `DataOrganization` at construction time.
    fn float_data_type_has_language_dependant_length(&self) -> bool {
        true
    }

    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `FloatDataType.clone(DataTypeManager)`, which overrides
    /// `AbstractFloatDataType`'s inherited `BuiltIn.clone(DataTypeManager)`. Left as a required
    /// method (no default); see [`Float4DataType::float4_clone`](super::float4_data_type::Float4DataType::float4_clone)
    /// for why.
    fn float_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn FloatDataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type::DataType;
    use crate::program::seam_stubs::FloatFormat;

    struct MockFloatFormat;
    impl FloatFormat for MockFloatFormat {
        fn decode_big_float(
            &self,
            value: i64,
        ) -> Result<
            Box<dyn crate::pcode::floatformat::big_float::BigFloat>,
            crate::pcode::floatformat::unsupported_float_format_exception::UnsupportedFloatFormatException,
        > {
            let _ = value;
            unimplemented!("not exercised by these tests")
        }
        fn decode_big_float_from_big_integer(
            &self,
            value: i128,
        ) -> Result<
            Box<dyn crate::pcode::floatformat::big_float::BigFloat>,
            crate::pcode::floatformat::unsupported_float_format_exception::UnsupportedFloatFormatException,
        > {
            let _ = value;
            unimplemented!("not exercised by these tests")
        }
        fn get_encoding(&self, value: f64) -> i64 {
            value as i64
        }
        fn get_encoding_big_float(&self, value: &dyn crate::pcode::floatformat::big_float::BigFloat) -> i128 {
            let _ = value;
            0
        }
        fn get_big_float(&self, repr: &str) -> Box<dyn crate::pcode::floatformat::big_float::BigFloat> {
            let _ = repr;
            unimplemented!("not exercised by these tests")
        }
        fn round(&self, value: &mut dyn crate::pcode::floatformat::big_float::BigFloat) {
            let _ = value;
        }
        fn to_decimal_string(&self, value: &dyn crate::pcode::floatformat::big_float::BigFloat, use_english: bool) -> String {
            let _ = (value, use_english);
            String::new()
        }
    }

    struct MockFloatDataType {
        length: i32,
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockFloatDataType {
        fn get_name(&self) -> String {
            "float".to_string()
        }
        fn get_length(&self) -> i32 {
            self.encoded_length()
        }
        fn has_language_dependant_length(&self) -> bool {
            self.float_data_type_has_language_dependant_length()
        }
    }

    impl BuiltInDataType for MockFloatDataType {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            self.float_c_type_declaration(data_organization)
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl AbstractFloatDataType for MockFloatDataType {
        fn encoded_length(&self) -> i32 {
            self.length
        }
        fn float_format(&self) -> Option<&dyn FloatFormat> {
            Some(&MockFloatFormat)
        }
        fn build_description(&self) -> String {
            self.float_data_type_description()
        }
    }

    impl FloatDataType for MockFloatDataType {
        fn float_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn FloatDataType> {
            match dtm {
                None => Box::new(MockFloatDataType {
                    length: self.length,
                    dtm_tag: self.dtm_tag,
                }),
                Some(_) => Box::new(MockFloatDataType {
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
        let dt = MockFloatDataType { length: 4, dtm_tag: None };
        let dyn_dt: &dyn FloatDataType = &dt;
        assert_eq!(dyn_dt.encoded_length(), 4);
        assert!(dyn_dt.float_data_type_has_language_dependant_length());
        assert!(DataType::has_language_dependant_length(dyn_dt));
    }

    #[test]
    fn description_prefixes_compiler_defined_wording() {
        let dt = MockFloatDataType { length: 8, dtm_tag: None };
        let description = dt.float_data_type_description();
        assert!(description.starts_with("Compiler-defined 'float' "));
        assert!(description.contains("64-bit"));
        // The AbstractFloatDataType-level accessor picks up the same override transitively.
        assert_eq!(dt.float_description(), description);
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockFloatDataType { length: 4, dtm_tag: Some("mgr-a") };
        let cloned = dt.float_clone(None);
        assert_eq!(cloned.encoded_length(), 4);
        assert_eq!(cloned.float_data_type_description(), dt.float_data_type_description());
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockFloatDataType { length: 4, dtm_tag: Some("mgr-a") };
        let cloned = dt.float_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.encoded_length(), 4);
    }
}
