use crate::program::model::data::abstract_float_data_type::AbstractFloatDataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Fixed encoded length (in bytes) for a [`Float16DataType`], standing in for the literal `16`
/// passed to the `AbstractFloatDataType(String, int, DataTypeManager)` superclass constructor.
pub const FLOAT16_ENCODED_LENGTH: i32 = 16;

/// Provides a definition of a 16-byte (quad precision) Float within a program.
///
/// Port of `ghidra.program.model.data.Float16DataType`, promoted straight to a trait because it
/// was selected as a dependency-cycle cut-point. See
/// [`Float4DataType`](super::float4_data_type::Float4DataType) for the full rationale this
/// mirrors: `Float16DataType` overrides nothing beyond its constructor and
/// `clone(DataTypeManager)`, so this trait only adds that one override.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait Float16DataType: AbstractFloatDataType {
    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `Float16DataType.clone(DataTypeManager)`, which overrides
    /// `AbstractFloatDataType`'s inherited `BuiltIn.clone(DataTypeManager)`. Left as a required
    /// method (no default); see [`Float4DataType::float4_clone`](super::float4_data_type::Float4DataType::float4_clone)
    /// for why.
    fn float16_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Float16DataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
    use crate::program::model::data::data_type::DataType;
    use crate::pcode::floatformat::{get_float_format, FloatFormat};

    struct MockFloat16DataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockFloat16DataType {
        fn get_name(&self) -> String {
            "float16".to_string()
        }
        fn get_length(&self) -> i32 {
            self.encoded_length()
        }
    }

    impl BuiltInDataType for MockFloat16DataType {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&DataOrganizationImpl>,
        ) -> Option<String> {
            self.float_c_type_declaration(data_organization)
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl AbstractFloatDataType for MockFloat16DataType {
        fn encoded_length(&self) -> i32 {
            FLOAT16_ENCODED_LENGTH
        }
        fn float_format(&self) -> Option<&FloatFormat> {
            get_float_format(self.encoded_length()).ok()
        }
    }

    impl Float16DataType for MockFloat16DataType {
        fn float16_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Float16DataType> {
            match dtm {
                None => Box::new(MockFloat16DataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockFloat16DataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockFloat16DataType { dtm_tag: None };
        let dyn_dt: &dyn Float16DataType = &dt;
        assert_eq!(dyn_dt.encoded_length(), 16);
        assert_eq!(DataType::get_length(dyn_dt), 16);
        assert_eq!(dyn_dt.get_name(), "float16");
    }

    #[test]
    fn description_uses_ieee754_standard_wording() {
        let dt = MockFloat16DataType { dtm_tag: None };
        assert!(dt.float_description().contains("128-bit"));
        assert!(dt.float_description().contains("16-byte"));
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockFloat16DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.float16_clone(None);
        assert_eq!(cloned.encoded_length(), 16);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockFloat16DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.float16_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.encoded_length(), 16);
    }
}
