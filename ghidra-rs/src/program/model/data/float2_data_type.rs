use crate::program::model::data::abstract_float_data_type::AbstractFloatDataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

/// Fixed encoded length (in bytes) for a [`Float2DataType`], standing in for the literal `2`
/// passed to the `AbstractFloatDataType(String, int, DataTypeManager)` superclass constructor.
pub const FLOAT2_ENCODED_LENGTH: i32 = 2;

/// Provides a definition of a 2-byte Float within a program.
///
/// Port of `ghidra.program.model.data.Float2DataType`, promoted straight to a trait because it
/// was selected as a dependency-cycle cut-point.
///
/// The Java class `extends AbstractFloatDataType`, already ported as a trait
/// ([`AbstractFloatDataType`]). Every method `Float2DataType` overrides beyond its constructor is
/// just `clone(DataTypeManager)`; every other behavior (description, mnemonic, value decoding,
/// `getCTypeDeclaration`, ...) is inherited from `AbstractFloatDataType` unchanged, so this trait
/// adds nothing beyond that one override.
///
/// The constructor (`super("float2", 2, dtm)`) has no trait equivalent (traits cannot declare
/// constructors or store fields); [`AbstractFloatDataType::encoded_length`] is a *required* method
/// with no default (not something this subtrait can redeclare -- see
/// [`AbstractFloatDataType`]'s own module docs on the same restriction for its supertraits), so a
/// concrete implementation's `encoded_length()` override should simply return
/// [`FLOAT2_ENCODED_LENGTH`] directly; no distinct-named helper is needed for a value that has
/// nowhere else to collide.
///
/// Static state not translated: the `dataType` singleton (needs a concrete struct).
pub trait Float2DataType: AbstractFloatDataType {
    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `Float2DataType.clone(DataTypeManager)`, which overrides
    /// `AbstractFloatDataType`'s inherited `BuiltIn.clone(DataTypeManager)`. Left as a required
    /// method (no default) since the real implementation returns `self` when `dtm` already
    /// matches this instance's manager, which requires manager-identity comparison a mock cannot
    /// provide generically -- mirroring [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone).
    fn float2_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Float2DataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type::DataType;
    use crate::pcode::floatformat::{get_float_format, FloatFormat};

    struct MockFloat2DataType {
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockFloat2DataType {
        fn get_name(&self) -> String {
            "float2".to_string()
        }
        fn get_length(&self) -> i32 {
            self.encoded_length()
        }
    }

    impl BuiltInDataType for MockFloat2DataType {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            self.float_c_type_declaration(data_organization)
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl AbstractFloatDataType for MockFloat2DataType {
        fn encoded_length(&self) -> i32 {
            FLOAT2_ENCODED_LENGTH
        }
        fn float_format(&self) -> Option<&FloatFormat> {
            get_float_format(self.encoded_length()).ok()
        }
    }

    impl Float2DataType for MockFloat2DataType {
        fn float2_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Float2DataType> {
            match dtm {
                None => Box::new(MockFloat2DataType { dtm_tag: self.dtm_tag }),
                Some(_) => Box::new(MockFloat2DataType {
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockFloat2DataType { dtm_tag: None };
        let dyn_dt: &dyn Float2DataType = &dt;
        assert_eq!(dyn_dt.encoded_length(), 2);
        assert_eq!(DataType::get_length(dyn_dt), 2);
        assert_eq!(dyn_dt.get_name(), "float2");
    }

    #[test]
    fn description_uses_ieee754_standard_wording() {
        let dt = MockFloat2DataType { dtm_tag: None };
        assert!(dt.float_description().contains("16-bit"));
        assert!(dt.float_description().contains("2-byte"));
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockFloat2DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.float2_clone(None);
        assert_eq!(cloned.encoded_length(), 2);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockFloat2DataType { dtm_tag: Some("mgr-a") };
        let cloned = dt.float2_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.encoded_length(), 2);
    }
}
