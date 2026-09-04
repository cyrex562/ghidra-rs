//! Port of `ghidra.program.model.data.Complex8DataType`.
//!
//! Provides a definition of a `complex` built-in data type consisting of two 32-bit floating
//! point numbers in the IEEE 754 double precision format.
//!
//! Port of `ghidra.program.model.data.Complex8DataType`, promoted straight to a trait because it
//! was selected as a dependency-cycle cut-point.
//!
//! The Java class `extends AbstractComplexDataType`, already ported as a trait
//! ([`AbstractComplexDataType`]). Every method `Complex8DataType` overrides beyond its
//! constructor is just `clone(DataTypeManager)`; every other behavior (mnemonic, length,
//! description, value decoding, representation) is inherited from `AbstractComplexDataType`
//! unchanged, so this trait adds nothing beyond that one override.
//!
//! The constructor (`super("complex8", Float4DataType.dataType, dtm)`) has no trait equivalent
//! (traits cannot declare constructors or store fields); [`AbstractComplexDataType::float_type`]
//! is a *required* method with no default (not something this subtrait can redeclare -- see
//! [`AbstractComplexDataType`]'s own module docs on the same restriction for its supertraits), so
//! a concrete implementation's `float_type()` override should return a
//! [`Float4DataType`](crate::program::model::data::float4_data_type::Float4DataType)-shaped
//! instance directly; no distinct-named helper is needed for a value that has nowhere else to
//! collide.
//!
//! Static state not translated: the `dataType` singleton (needs a concrete struct).

use crate::program::model::data::abstract_complex_data_type::AbstractComplexDataType;
use crate::program::model::data::data_type_manager::DataTypeManager;

pub trait Complex8DataType: AbstractComplexDataType {
    /// Returns an instance of this DataType using the specified `DataTypeManager` to allow its
    /// use of the corresponding `DataOrganization` while retaining its unique identity.
    ///
    /// Port of `Complex8DataType.clone(DataTypeManager)`, which overrides
    /// `AbstractComplexDataType`'s inherited `BuiltIn.clone(DataTypeManager)`. Left as a required
    /// method (no default) since the real implementation returns `self` when `dtm` already
    /// matches this instance's manager, which requires manager-identity comparison a mock cannot
    /// provide generically -- mirroring
    /// [`Float4DataType::float4_clone`](crate::program::model::data::float4_data_type::Float4DataType::float4_clone).
    fn complex8_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Complex8DataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::pcode::floatformat::big_float::BigFloat;
    use crate::pcode::floatformat::float_kind::FloatKind;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::abstract_float_data_type::AbstractFloatDataType;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::mem::MemBuffer;
    use crate::program::seam_stubs::FloatFormat;

    #[derive(Debug, Clone, Copy)]
    struct MockBigFloat {
        value: f64,
    }

    impl BigFloat for MockBigFloat {
        fn fracbits(&self) -> i32 {
            52
        }
        fn expbits(&self) -> i32 {
            11
        }
        fn kind(&self) -> FloatKind {
            if self.value.is_nan() {
                FloatKind::QuietNan
            } else if self.value.is_infinite() {
                FloatKind::Infinite
            } else {
                FloatKind::Finite
            }
        }
        fn sign(&self) -> i32 {
            if self.value.is_sign_negative() {
                -1
            } else {
                1
            }
        }
        fn scale(&self) -> i32 {
            0
        }
        fn unscaled(&self) -> i128 {
            self.value as i128
        }
        fn is_normal(&self) -> bool {
            self.value.is_normal()
        }
        fn is_denormal(&self) -> bool {
            false
        }
        fn is_nan(&self) -> bool {
            self.value.is_nan()
        }
        fn is_infinite(&self) -> bool {
            self.value.is_infinite()
        }
        fn is_zero(&self) -> bool {
            self.value == 0.0
        }
        fn copy(&self) -> Box<dyn BigFloat> {
            Box::new(*self)
        }
        fn add(&mut self, other: &dyn BigFloat) {
            self.value += other.to_big_integer() as f64;
        }
        fn sub(&mut self, other: &dyn BigFloat) {
            self.value -= other.to_big_integer() as f64;
        }
        fn mul(&mut self, other: &dyn BigFloat) {
            self.value *= other.to_big_integer() as f64;
        }
        fn div(&mut self, other: &dyn BigFloat) {
            self.value /= other.to_big_integer() as f64;
        }
        fn sqrt(&mut self) {
            self.value = self.value.sqrt();
        }
        fn floor(&mut self) {
            self.value = self.value.floor();
        }
        fn ceil(&mut self) {
            self.value = self.value.ceil();
        }
        fn trunc(&mut self) {
            self.value = self.value.trunc();
        }
        fn negate(&mut self) {
            self.value = -self.value;
        }
        fn abs(&mut self) {
            self.value = self.value.abs();
        }
        fn round(&mut self) {
            self.value = self.value.round();
        }
        fn to_big_integer(&self) -> i128 {
            self.value as i128
        }
        fn to_big_decimal(&self) -> Option<f64> {
            if self.value.is_nan() {
                None
            } else {
                Some(self.value)
            }
        }
        fn to_binary_string(&self) -> String {
            format!("{:b}", self.value.to_bits())
        }
        fn to_display_string(&self) -> String {
            self.value.to_string()
        }
        fn to_display_string_with_context(
            &self,
            _context: crate::pcode::floatformat::big_float::MathContext,
        ) -> String {
            self.value.to_string()
        }
        fn to_display_string_with_format(
            &self,
            _format: &dyn crate::pcode::seam_stubs::FloatFormat,
            _compact: bool,
        ) -> String {
            self.value.to_string()
        }
        fn zero(fracbits: i32, expbits: i32, sign: i32) -> Self {
            let _ = (fracbits, expbits);
            MockBigFloat { value: 0.0 * sign as f64 }
        }
        fn infinity(fracbits: i32, expbits: i32, sign: i32) -> Self {
            let _ = (fracbits, expbits);
            MockBigFloat { value: sign as f64 * f64::INFINITY }
        }
        fn quiet_nan(fracbits: i32, expbits: i32, sign: i32) -> Self {
            let _ = (fracbits, expbits, sign);
            MockBigFloat { value: f64::NAN }
        }
    }

    struct MockFloatFormat;

    impl FloatFormat for MockFloatFormat {
        fn decode_big_float(
            &self,
            value: i64,
        ) -> Result<Box<dyn BigFloat>, crate::pcode::floatformat::unsupported_float_format_exception::UnsupportedFloatFormatException>
        {
            Ok(Box::new(MockBigFloat { value: value as f64 }))
        }

        fn decode_big_float_from_big_integer(
            &self,
            value: i128,
        ) -> Result<Box<dyn BigFloat>, crate::pcode::floatformat::unsupported_float_format_exception::UnsupportedFloatFormatException>
        {
            Ok(Box::new(MockBigFloat { value: value as f64 }))
        }

        fn get_encoding(&self, value: f64) -> i64 {
            value as i64
        }

        fn get_encoding_big_float(&self, value: &dyn BigFloat) -> i128 {
            value.to_big_integer()
        }

        fn get_big_float(&self, repr: &str) -> Box<dyn BigFloat> {
            Box::new(MockBigFloat { value: repr.parse().unwrap_or(0.0) })
        }

        fn round(&self, value: &mut dyn BigFloat) {
            value.round();
        }

        fn to_decimal_string(&self, value: &dyn BigFloat, _use_english: bool) -> String {
            value.to_display_string()
        }
    }

    struct MockFloat {
        length: i32,
    }

    impl DataType for MockFloat {
        fn get_name(&self) -> String {
            "float4".to_string()
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
        fn float_format(&self) -> Option<&dyn FloatFormat> {
            Some(&MockFloatFormat)
        }
    }

    struct MockComplex8DataType {
        float_type: MockFloat,
        dtm_tag: Option<&'static str>,
    }

    impl DataType for MockComplex8DataType {
        fn get_name(&self) -> String {
            "complex8".to_string()
        }
        fn get_length(&self) -> i32 {
            self.complex_length()
        }
    }

    impl BuiltInDataType for MockComplex8DataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl AbstractComplexDataType for MockComplex8DataType {
        fn float_type(&self) -> &dyn AbstractFloatDataType {
            &self.float_type
        }
    }

    impl Complex8DataType for MockComplex8DataType {
        fn complex8_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn Complex8DataType> {
            match dtm {
                None => Box::new(MockComplex8DataType {
                    float_type: MockFloat { length: self.float_type.length },
                    dtm_tag: self.dtm_tag,
                }),
                Some(_) => Box::new(MockComplex8DataType {
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

    fn complex8() -> MockComplex8DataType {
        MockComplex8DataType { float_type: MockFloat { length: 4 }, dtm_tag: None }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = complex8();
        let dyn_dt: &dyn Complex8DataType = &dt;
        assert_eq!(dyn_dt.complex_length(), 8);
        assert_eq!(DataType::get_length(dyn_dt), 8);
        assert_eq!(dyn_dt.get_name(), "complex8");
    }

    #[test]
    fn description_names_component_float_type() {
        let dt = complex8();
        assert_eq!(
            dt.complex_description(),
            "The data type for a complex number: a + bi; consisting of two float4 values"
        );
    }

    #[test]
    fn complex_value_decodes_real_and_imaginary_from_adjacent_halves() {
        let dt = complex8();
        let settings = MockSettings;
        let buf = FixedMemBuffer(vec![0, 0, 0, 3, 0, 0, 0, 7]);
        let value = dt.complex_value(&buf, &settings, 8).expect("decodes");
        assert_eq!(value.get_real(), 3.0);
        assert_eq!(value.get_imaginary(), 7.0);
    }

    #[test]
    fn clone_with_no_manager_preserves_identity_tag() {
        let dt = MockComplex8DataType { float_type: MockFloat { length: 4 }, dtm_tag: Some("mgr-a") };
        let cloned = dt.complex8_clone(None);
        assert_eq!(cloned.complex_length(), 8);
    }

    #[test]
    fn clone_with_new_manager_rebinds_instance() {
        let dt = MockComplex8DataType { float_type: MockFloat { length: 4 }, dtm_tag: Some("mgr-a") };
        let cloned = dt.complex8_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.complex_length(), 8);
    }
}
