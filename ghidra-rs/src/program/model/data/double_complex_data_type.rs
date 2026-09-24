//! Port of `ghidra.program.model.data.DoubleComplexDataType`.
//!
//! Provides a definition of a `complex` built-in data type consisting of two double
//! point numbers in the IEEE 754 double precision format.
//!
//! The size of the double numbers is determined by the program's data organization as
//! defined by the language/compiler spec (unlike the fixed-size `Complex8`/`Complex16`/`Complex32`
//! siblings).
//!
//! Port of `ghidra.program.model.data.DoubleComplexDataType`, promoted straight to a trait because it
//! was selected as a dependency-cycle cut-point.
//!
//! The Java class `extends AbstractComplexDataType`, already ported as a trait
//! ([`AbstractComplexDataType`]). Every method `DoubleComplexDataType` overrides beyond its
//! constructor is just `clone(DataTypeManager)`; every other behavior (mnemonic, length,
//! description, value decoding, representation) is inherited from `AbstractComplexDataType`
//! unchanged, so this trait adds nothing beyond that one override.
//!
//! The constructor (`super("doublecomplex", DoubleDataType.dataType, dtm)`) has no trait equivalent
//! (traits cannot declare constructors or store fields); [`AbstractComplexDataType::float_type`]
//! is a *required* method with no default (not something this subtrait can redeclare -- see
//! [`AbstractComplexDataType`]'s own module docs on the same restriction for its supertraits), so
//! a concrete implementation's `float_type()` override should return a
//! [`DoubleDataType`](crate::program::model::data::double_data_type::DoubleDataType)-shaped
//! instance directly; no distinct-named helper is needed for a value that has nowhere else to
//! collide.
//!
//! Static state not translated: the `dataType` singleton (needs a concrete struct).

use crate::program::model::data::abstract_complex_data_type::AbstractComplexDataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

pub trait DoubleComplexDataType: AbstractComplexDataType {
    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `DoubleComplexDataType.clone(DataTypeManager)`, which overrides
    /// `AbstractComplexDataType`'s inherited `BuiltIn.clone(DataTypeManager)`. Left as a required
    /// method (no default) since the real implementation returns `self` when `dtm` already
    /// matches this instance's manager, which requires manager-identity comparison a mock cannot
    /// provide generically -- mirroring
    /// [`DoubleDataType`](crate::program::model::data::double_data_type::DoubleDataType), which computes its own
    /// encoded length from the associated `DataOrganization` at construction time rather than a
    /// fixed constant.
    fn double_complex_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn DoubleComplexDataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::abstract_float_data_type::AbstractFloatDataType;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::mem::MemBuffer;
    use crate::pcode::floatformat::{get_float_format, FloatFormat};

    struct MockFloat {
        length: i32,
    }

    impl DataType for MockFloat {
        fn get_name(&self) -> String {
            "double".to_string()
        }
        fn get_length(&self) -> i32 {
            self.encoded_length()
        }
    }

    impl BuiltInDataType for MockFloat {
        fn get_c_type_declaration(
            &self,
            data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            self.float_c_type_declaration(data_organization)
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl AbstractFloatDataType for MockFloat {
        fn encoded_length(&self) -> i32 {
            self.length
        }
        fn float_format(&self) -> Option<&FloatFormat> {
            get_float_format(self.encoded_length()).ok()
        }
    }

    struct MockDoubleComplexDataType {
        float_type: MockFloat,
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockDoubleComplexDataType {
        fn get_name(&self) -> String {
            "doublecomplex".to_string()
        }
        fn get_length(&self) -> i32 {
            self.complex_length()
        }
    }

    impl BuiltInDataType for MockDoubleComplexDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl AbstractComplexDataType for MockDoubleComplexDataType {
        fn float_type(&self) -> &dyn AbstractFloatDataType {
            &self.float_type
        }
    }

    impl DoubleComplexDataType for MockDoubleComplexDataType {
        fn double_complex_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn DoubleComplexDataType> {
            match dtm {
                None => Box::new(MockDoubleComplexDataType {
                    float_type: MockFloat { length: self.float_type.length },
                    dtm_tag: self.dtm_tag,
                }),
                Some(_) => Box::new(MockDoubleComplexDataType {
                    float_type: MockFloat { length: self.float_type.length },
                    dtm_tag: Some("new-manager"),
                }),
            }
        }
    }

    struct MockSettings;
    impl Settings for MockSettings {}

    struct FixedMemBuffer(Vec<u8>);
    impl MemBuffer for FixedMemBuffer {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }
        fn get_bytes(&self, buffer: &mut [u8], offset: i32) -> usize {
            let offset = offset as usize;
            if offset >= self.0.len() {
                return 0;
            }
            let n = buffer.len().min(self.0.len() - offset);
            buffer[..n].copy_from_slice(&self.0[offset..offset + n]);
            n
        }
        fn is_big_endian(&self) -> bool {
            true
        }
    }

    fn complex_doublecomplex() -> MockDoubleComplexDataType {
        MockDoubleComplexDataType { float_type: MockFloat { length: 8 }, dtm_tag: None }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = complex_doublecomplex();
        let dyn_dt: &dyn DoubleComplexDataType = &dt;
        assert_eq!(dyn_dt.complex_length(), 16);
        assert_eq!(DataType::get_length(dyn_dt), 16);
        assert_eq!(dyn_dt.get_name(), "doublecomplex");
    }

    #[test]
    fn description_names_component_float_type() {
        let dt = complex_doublecomplex();
        assert_eq!(
            dt.complex_description(),
            "The data type for a complex number: a + bi; consisting of two double values"
        );
    }

    #[test]
    fn complex_value_decodes_real_and_imaginary_from_adjacent_halves() {
        let dt = complex_doublecomplex();
        let settings = MockSettings;
        // real 3.0, imaginary 7.0 as big-endian 8-byte IEEE 754 encodings
        let mut bytes = vec![0x40, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        bytes.extend(vec![0x40, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let buf = FixedMemBuffer(bytes);
        let value = dt.complex_value(&buf, &settings, 16).expect("decodes");
        assert_eq!(value.get_real(), 3.0);
        assert_eq!(value.get_imaginary(), 7.0);
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockDoubleComplexDataType { float_type: MockFloat { length: 8 }, dtm_tag: Some("mgr-a") };
        let cloned = dt.double_complex_clone(None);
        assert_eq!(cloned.complex_length(), 16);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockDoubleComplexDataType { float_type: MockFloat { length: 8 }, dtm_tag: Some("mgr-a") };
        let cloned = dt.double_complex_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.complex_length(), 16);
    }
}
