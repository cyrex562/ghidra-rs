use crate::program::model::data::abstract_float_data_type::AbstractFloatDataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Fixed encoded length (in bytes) for a [`Float4DataType`], standing in for the literal `4`
/// passed to the `AbstractFloatDataType(String, int, DataTypeManager)` superclass constructor.
pub const FLOAT4_ENCODED_LENGTH: i32 = 4;

/// Provides a definition of a 4-byte Float within a program.
///
/// Port of `ghidra.program.model.data.Float4DataType`, promoted straight to a trait because it
/// was selected as a dependency-cycle cut-point.
///
/// The Java class `extends AbstractFloatDataType`, already ported as a trait
/// ([`AbstractFloatDataType`]). Every method `Float4DataType` overrides beyond its constructor is
/// just `clone(DataTypeManager)`; every other behavior (description, mnemonic, value decoding,
/// `getCTypeDeclaration`, ...) is inherited from `AbstractFloatDataType` unchanged, so this trait
/// adds nothing beyond that one override.
///
/// The constructor (`super("float4", 4, dtm)`) has no trait equivalent (traits cannot declare
/// constructors or store fields); [`AbstractFloatDataType::encoded_length`] is a *required* method
/// with no default (not something this subtrait can redeclare -- see
/// [`AbstractFloatDataType`]'s own module docs on the same restriction for its supertraits), so a
/// concrete implementation's `encoded_length()` override should simply return
/// [`FLOAT4_ENCODED_LENGTH`] directly; no distinct-named helper is needed for a value that has
/// nowhere else to collide.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait Float4DataType: AbstractFloatDataType {
    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `Float4DataType.clone(DataTypeManager)`, which overrides
    /// `AbstractFloatDataType`'s inherited `BuiltIn.clone(DataTypeManager)`. Left as a required
    /// method (no default) since the real implementation returns `self` when `dtm` already
    /// matches this instance's manager, which requires manager-identity comparison a mock cannot
    /// provide generically -- mirroring [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone).
    fn float4_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Float4DataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::mem::MemBuffer;
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

    struct MockFloat4DataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockFloat4DataType {
        fn get_name(&self) -> String {
            "float4".to_string()
        }
        fn get_length(&self) -> i32 {
            self.encoded_length()
        }
    }

    impl BuiltInDataType for MockFloat4DataType {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            self.float_c_type_declaration(data_organization)
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl AbstractFloatDataType for MockFloat4DataType {
        fn encoded_length(&self) -> i32 {
            FLOAT4_ENCODED_LENGTH
        }
        fn float_format(&self) -> Option<&dyn FloatFormat> {
            Some(&MockFloatFormat)
        }
    }

    impl Float4DataType for MockFloat4DataType {
        fn float4_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Float4DataType> {
            match dtm {
                None => Box::new(MockFloat4DataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockFloat4DataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockFloat4DataType { dtm_tag: None };
        let dyn_dt: &dyn Float4DataType = &dt;
        assert_eq!(dyn_dt.encoded_length(), 4);
        assert_eq!(DataType::get_length(dyn_dt), 4);
        assert_eq!(dyn_dt.get_name(), "float4");
    }

    #[test]
    fn description_uses_ieee754_standard_wording() {
        let dt = MockFloat4DataType { dtm_tag: None };
        assert!(dt.float_description().contains("32-bit"));
        assert!(dt.float_description().contains("4-byte"));
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockFloat4DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.float4_clone(None);
        assert_eq!(cloned.encoded_length(), 4);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockFloat4DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.float4_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.encoded_length(), 4);
    }
}
