//! Port of `ghidra.program.model.data.AbstractFloatDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends BuiltIn`. `BuiltIn` itself is not yet ported, so this trait extends
//! [`DataType`] + [`BuiltInDataType`] directly -- the two already-ported interfaces `BuiltIn`
//! implements that `AbstractFloatDataType` actually relies on.
//!
//! Several Java methods here share a name with an already-provided default method on [`DataType`]
//! (`getMnemonic`, `getDescription`, `getValue`, `isEncodable`, `encodeValue`,
//! `getRepresentation`, `encodeRepresentation`, `getValueClass`, `getDefaultLabelPrefix`) or
//! [`BuiltInDataType`] (`getCTypeDeclaration`). Rust does not allow a subtrait to override a
//! supertrait's method by redeclaring the same name -- it would just create an ambiguous method
//! for any type implementing both -- so, mirroring the convention established by
//! [`CharDataType`](crate::program::model::data::char_data_type::CharDataType), those overrides
//! are exposed here under distinct `float_*` names. A future concrete implementation (once
//! `BuiltIn`, `FloatFormatFactory`, and the `Float2DataType`/.../`Float16DataType`/
//! `FloatDataType`/`DoubleDataType`/`LongDoubleDataType`/`Undefined`/`DefaultDataType` singletons
//! are ported) should implement `DataType`/`BuiltInDataType` directly and delegate to these
//! helpers.
//!
//! Constructor logic (establishing `floatFormat` via `FloatFormatFactory.getFloatFormat(length)`,
//! catching `UnsupportedFloatFormatException` and leaving `floatFormat` as `null`/`None` on
//! failure) has no Rust equivalent since traits cannot declare constructors or store fields;
//! implementors are expected to perform that lookup themselves and expose the result via
//! [`AbstractFloatDataType::float_format`]. `getDescription`'s lazy caching (a mutable
//! `description` field) is likewise dropped in favor of recomputing
//! [`build_description`](AbstractFloatDataType::build_description) on each call, since trait
//! methods here only take `&self`.
//!
//! The two static factory methods `getFloatDataType(int, DataTypeManager)` and
//! `getFloatDataTypes(DataTypeManager)` are omitted entirely: both build a registry keyed off
//! concrete sibling types (`Float2DataType` .. `Float16DataType`, `FloatDataType`,
//! `DoubleDataType`, `LongDoubleDataType`, `Undefined`, `DefaultDataType`) that are not yet
//! ported and are unrelated to breaking this cycle, so no placeholder is created for them; port
//! them alongside those concrete types instead.
//!
//! `FloatFormat`/`BigFloat` are the real [`crate::pcode::floatformat`] ports; implementors
//! typically obtain their format from
//! [`get_float_format`](crate::pcode::floatformat::get_float_format)`(encoded_length)`.
//! Values wider than 8 bytes use arbitrary-precision [`num_bigint::BigInt`] encodings, so 16- and
//! 32-byte floats are not truncated.

use std::any::TypeId;

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::pcode::floatformat::{BigFloat, FloatFormat};
use crate::pcode::utils::utils;
use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_encode_exception::DataTypeEncodeException;
use crate::program::model::mem::MemBuffer;

/// Value accepted by [`AbstractFloatDataType::encode_float_value`], standing in for the
/// `Object value` parameter of `AbstractFloatDataType.encodeValue`, documented in the Java source
/// as "expected as Number or BigFloat object".
pub enum FloatEncodeValue {
    /// A plain numeric value, used for the standard 4- and 8-byte IEEE 754 encodings.
    Number(f64),
    /// An arbitrary-precision float value, required for non-standard lengths.
    Big(BigFloat),
}

fn describe_value(value: &FloatEncodeValue) -> String {
    match value {
        FloatEncodeValue::Number(v) => v.to_string(),
        FloatEncodeValue::Big(v) => v.to_string(),
    }
}

/// Provides a definition of a Float within a program.
///
/// Port of `ghidra.program.model.data.AbstractFloatDataType`. See the module-level documentation
/// for the conventions used to resolve name clashes with [`DataType`]/[`BuiltInDataType`] and for
/// what was intentionally left unported.
pub trait AbstractFloatDataType: DataType + BuiltInDataType {
    /// The floating encoding length as a number of 8-bit bytes.
    ///
    /// Port of the private final `encodedLength` field.
    fn encoded_length(&self) -> i32;

    /// The float format established for [`encoded_length`](Self::encoded_length), or `None` if
    /// that length has no supported format -- mirroring the Java constructor swallowing
    /// `UnsupportedFloatFormatException` and leaving `floatFormat` as `null`.
    ///
    /// Port of the private final `floatFormat` field.
    fn float_format(&self) -> Option<&FloatFormat>;

    /// Port of the protected final `AbstractFloatDataType.buildIEEE754StandardDescription()`.
    fn build_ieee754_standard_description(&self) -> String {
        let encoded_length = self.encoded_length();
        format!(
            "IEEE 754 floating-point type ({}-bit / {}-byte format, aligned-length is {}-bytes)",
            encoded_length * 8,
            encoded_length,
            self.get_aligned_length(),
        )
    }

    /// Port of the protected `AbstractFloatDataType.buildDescription()`, overridable by more
    /// specific float types.
    fn build_description(&self) -> String {
        self.build_ieee754_standard_description()
    }

    /// Port of the final `AbstractFloatDataType.getMnemonic(Settings)`, exposed under a distinct
    /// name since [`DataType::get_mnemonic`] already provides a default. A concrete
    /// `impl DataType for ...` should delegate `get_mnemonic` to this.
    fn float_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        self.get_name()
    }

    /// Port of the final `AbstractFloatDataType.getDescription()`, exposed under a distinct name
    /// since [`DataType::get_description`] already provides a default. Recomputed on each call
    /// rather than cached (see the module-level documentation). A concrete `impl DataType for
    /// ...` should delegate `get_description` to this.
    fn float_description(&self) -> String {
        self.build_description()
    }

    /// Port of `AbstractFloatDataType.getValueClass(Settings)`, exposed under a distinct name
    /// since [`DataType::get_value_class`] already provides a default. Always identifies
    /// [`BigFloat`] (Java `BigFloat.class`). A concrete `impl DataType for ...` should delegate
    /// `get_value_class` to this.
    fn float_value_type_id(&self, settings: &dyn Settings) -> TypeId {
        let _ = settings;
        TypeId::of::<BigFloat>()
    }

    /// Port of the final `AbstractFloatDataType.getValue(MemBuffer, Settings, int)`, exposed
    /// under a distinct name since [`DataType::get_value`] already provides a default. The
    /// `length` parameter is ignored, matching the Java method (which always uses
    /// [`encoded_length`](Self::encoded_length)). A concrete `impl DataType for ...` should
    /// delegate `get_value` to this.
    fn float_value(
        &self,
        buf: &dyn MemBuffer,
        _settings: &dyn Settings,
        _length: i32,
    ) -> Option<BigFloat> {
        let len = self.encoded_length() as usize;
        let format = self.float_format()?;
        let mut bytes = vec![0u8; len];
        if buf.get_bytes_into(&mut bytes, 0) as usize != len {
            return None;
        }
        if len <= 8 {
            let value = utils::bytes_to_long(&bytes, len, buf.is_big_endian());
            Some(format.decode_big_float(value))
        } else {
            let value = utils::bytes_to_big_int(&bytes, len, buf.is_big_endian(), false);
            Some(format.decode_big_float_big(&value))
        }
    }

    /// Port of `AbstractFloatDataType.isEncodable()`, exposed under a distinct name since
    /// [`DataType::is_encodable`] already provides a default. A concrete `impl DataType for ...`
    /// should delegate `is_encodable` to this.
    fn is_float_encodable(&self) -> bool {
        self.float_format().is_some()
    }

    /// Port of the final `AbstractFloatDataType.encodeValue(Object, MemBuffer, Settings, int)`,
    /// exposed under a distinct name since [`DataType::encode_value`] already provides a default
    /// with a different `value` type (`&dyn Any` vs. [`FloatEncodeValue`]). A concrete
    /// `impl DataType for ...` should delegate `encode_value` to this.
    fn encode_float_value(
        &self,
        value: &FloatEncodeValue,
        buf: &dyn MemBuffer,
        _settings: &dyn Settings,
        _length: i32,
    ) -> Result<Vec<u8>, DataTypeEncodeException> {
        let len = self.encoded_length() as usize;
        let Some(format) = self.float_format() else {
            return Err(DataTypeEncodeException::new(
                format!("Unsupported float format ({} bytes)", len),
                describe_value(value),
                self.get_name(),
            ));
        };
        match (len, value) {
            (4, FloatEncodeValue::Number(v)) | (8, FloatEncodeValue::Number(v)) => {
                let encoding = format.get_encoding(*v);
                Ok(utils::long_to_bytes(encoding, len, buf.is_big_endian()))
            }
            (_, FloatEncodeValue::Big(v)) => {
                let encoding = format.get_encoding_big(v);
                Ok(utils::big_int_to_bytes(&encoding, len, buf.is_big_endian()))
            }
            (_, FloatEncodeValue::Number(_)) => Err(DataTypeEncodeException::new(
                "non-standard float length requires BigFloat type",
                describe_value(value),
                self.get_name(),
            )),
        }
    }

    /// Port of `AbstractFloatDataType.getRepresentation(MemBuffer, Settings, int)`, exposed under
    /// a distinct name since [`DataType::get_representation`] already provides a default. A
    /// concrete `impl DataType for ...` should delegate `get_representation` to this.
    fn float_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        match self.float_value(buf, settings, length) {
            None => "??".to_string(),
            Some(value) => match self.float_format() {
                Some(format) => format.to_decimal_string_compact(&value, true),
                None => value.to_string(),
            },
        }
    }

    /// Port of `AbstractFloatDataType.encodeRepresentation(String, MemBuffer, Settings, int)`,
    /// exposed under a distinct name since [`DataType::encode_representation`] already provides a
    /// default. A concrete `impl DataType for ...` should delegate `encode_representation` to
    /// this.
    fn encode_float_representation(
        &self,
        repr: &str,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Result<Vec<u8>, DataTypeEncodeException> {
        let len = self.encoded_length();
        let Some(format) = self.float_format() else {
            return Err(DataTypeEncodeException::new(
                format!("Unsupported float format ({} bytes)", len),
                repr,
                self.get_name(),
            ));
        };
        if length == 8 || length == 4 {
            let value: f64 = repr.parse().map_err(|e: std::num::ParseFloatError| {
                DataTypeEncodeException::with_cause_only(repr, self.get_name(), Box::new(e))
            })?;
            return self.encode_float_value(&FloatEncodeValue::Number(value), buf, settings, length);
        }
        let bf = format.get_big_float_str(repr).map_err(|e| {
            DataTypeEncodeException::with_cause_only(repr, self.get_name(), Box::new(e))
        })?;
        // Java calls floatFormat.round(bf) here and discards the returned BigDecimal.
        let _ = format.round(&bf);
        self.encode_float_value(&FloatEncodeValue::Big(bf), buf, settings, length)
    }

    /// Port of the protected `AbstractFloatDataType.getBuiltInSettingsDefinitions()`. Always
    /// empty, matching the Java `SETTINGS_DEFS = {}` (with its `// TODO: Add
    /// FloatDisplayPrecisionSettingsDefinition` left unaddressed upstream).
    fn get_built_in_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        Vec::new()
    }

    /// Port of `AbstractFloatDataType.getDefaultLabelPrefix()`, exposed under a distinct name
    /// since [`DataType::get_default_label_prefix`] already provides a default. A concrete
    /// `impl DataType for ...` should delegate `get_default_label_prefix` to this.
    fn float_default_label_prefix(&self) -> String {
        self.get_name().to_uppercase()
    }

    /// Port of `AbstractFloatDataType.getCTypeDeclaration(DataOrganization)`, exposed under a
    /// distinct name since [`BuiltInDataType::get_c_type_declaration`] already declares this
    /// method (with no default). A concrete `impl BuiltInDataType for ...` should delegate
    /// `get_c_type_declaration` to this.
    fn float_c_type_declaration(&self, data_organization: Option<&dyn DataOrganization>) -> Option<String> {
        let _ = data_organization;
        if self.has_language_dependant_length() {
            None
        } else {
            Some(self.get_name())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::floatformat::get_float_format;
    use crate::program::model::address::{Address, SpecialAddress};

    struct TestFloat {
        length: i32,
        format: Option<&'static FloatFormat>,
    }

    impl TestFloat {
        /// Mirrors the Java constructor: the format for `length`, or none if unsupported.
        fn new(length: i32) -> Self {
            Self { length, format: get_float_format(length).ok() }
        }
    }

    impl DataType for TestFloat {
        fn get_name(&self) -> String {
            format!("float{}", self.length)
        }
        fn get_length(&self) -> i32 {
            self.encoded_length()
        }
    }

    impl BuiltInDataType for TestFloat {
        fn get_c_type_declaration(&self, data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            self.float_c_type_declaration(data_organization)
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl AbstractFloatDataType for TestFloat {
        fn encoded_length(&self) -> i32 {
            self.length
        }
        fn float_format(&self) -> Option<&FloatFormat> {
            self.format
        }
    }

    struct TestSettings;
    impl Settings for TestSettings {}

    struct FixedMemBuffer(Vec<u8>, bool);
    impl MemBuffer for FixedMemBuffer {
        fn get_byte(&self, offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            Ok(self.0[offset as usize])
        }
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }
        fn get_bytes(&self, buffer: &mut [u8], _offset: i32) -> usize {
            let n = buffer.len().min(self.0.len());
            buffer[..n].copy_from_slice(&self.0[..n]);
            n
        }
        fn is_big_endian(&self) -> bool {
            self.1
        }
    }

    fn be(bytes: Vec<u8>) -> FixedMemBuffer {
        FixedMemBuffer(bytes, true)
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = TestFloat::new(4);
        let dyn_dt: &dyn AbstractFloatDataType = &dt;
        assert_eq!(dyn_dt.encoded_length(), 4);
        assert!(dyn_dt.build_ieee754_standard_description().contains("32-bit"));
        assert!(dyn_dt.build_ieee754_standard_description().contains("4-byte"));
        assert_eq!(dyn_dt.float_default_label_prefix(), "FLOAT4");
        assert_eq!(dyn_dt.float_c_type_declaration(None), Some("float4".to_string()));
        assert!(dyn_dt.get_built_in_settings_definitions().is_empty());
    }

    #[test]
    fn build_description_defaults_to_ieee754_standard_description() {
        let dt = TestFloat::new(8);
        assert_eq!(dt.build_description(), dt.build_ieee754_standard_description());
        assert_eq!(dt.float_description(), dt.build_description());
    }

    #[test]
    fn float_mnemonic_and_value_type_id() {
        let dt = TestFloat::new(4);
        assert_eq!(dt.float_mnemonic(&TestSettings), "float4");
        assert_eq!(dt.float_value_type_id(&TestSettings), TypeId::of::<BigFloat>());
    }

    #[test]
    fn float_value_decodes_short_length_via_bytes_to_long() {
        let dt = TestFloat::new(4);
        // 42.0f = 0x42280000
        let value = dt.float_value(&be(vec![0x42, 0x28, 0, 0]), &TestSettings, -1).expect("decodes");
        assert_eq!(value, get_float_format(4).unwrap().get_big_float_f32(42.0));
        // little-endian buffer
        let le = FixedMemBuffer(vec![0, 0, 0x28, 0x42], false);
        assert_eq!(dt.float_value(&le, &TestSettings, -1), Some(value));
    }

    #[test]
    fn float_value_decodes_long_length_via_big_integer() {
        let dt = TestFloat::new(10);
        // x87 80-bit 7.0 = 0x4001 e000000000000000
        let bytes = vec![0x40, 0x01, 0xe0, 0, 0, 0, 0, 0, 0, 0];
        let value = dt.float_value(&be(bytes), &TestSettings, -1).expect("decodes");
        assert_eq!(value, get_float_format(10).unwrap().get_big_float_f64(7.0));
    }

    #[test]
    fn float_value_and_is_encodable_are_none_false_without_format() {
        let dt = TestFloat::new(3);
        assert!(dt.float_format().is_none());
        assert!(dt.float_value(&be(vec![0, 0, 1]), &TestSettings, -1).is_none());
        assert!(!dt.is_float_encodable());
        assert!(TestFloat::new(4).is_float_encodable());
    }

    #[test]
    fn encode_float_value_number_path_for_standard_length() {
        let dt = TestFloat::new(4);
        let bytes = dt
            .encode_float_value(&FloatEncodeValue::Number(3.0), &be(Vec::new()), &TestSettings, 4)
            .expect("encodes");
        assert_eq!(bytes, vec![0x40, 0x40, 0, 0]);
        let dt8 = TestFloat::new(8);
        let bytes = dt8
            .encode_float_value(&FloatEncodeValue::Number(-0.5), &FixedMemBuffer(Vec::new(), false), &TestSettings, 8)
            .expect("encodes");
        assert_eq!(bytes, (-0.5f64).to_bits().to_le_bytes().to_vec());
    }

    #[test]
    fn encode_float_value_big_path_for_nonstandard_length() {
        let dt = TestFloat::new(10);
        let five = get_float_format(10).unwrap().get_big_float_f64(5.0);
        let bytes = dt
            .encode_float_value(&FloatEncodeValue::Big(five), &be(Vec::new()), &TestSettings, 10)
            .expect("encodes");
        // 5.0 = 0x4001 a000000000000000
        assert_eq!(bytes, vec![0x40, 0x01, 0xa0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn encode_float_value_big_path_for_32_byte_float() {
        let dt = TestFloat::new(32);
        let ff = get_float_format(32).unwrap();
        let neg_one = ff.get_big_float_f64(-1.0);
        let bytes = dt
            .encode_float_value(&FloatEncodeValue::Big(neg_one.clone()), &be(Vec::new()), &TestSettings, 32)
            .expect("encodes");
        assert_eq!(bytes.len(), 32);
        // sign bit + exponent 262143 (0x3ffff) in the top 20 bits
        assert_eq!(&bytes[..3], &[0xbf, 0xff, 0xf0]);
        assert!(bytes[3..].iter().all(|&b| b == 0));
        assert_eq!(dt.float_value(&be(bytes), &TestSettings, -1), Some(neg_one));
    }

    #[test]
    fn encode_float_value_rejects_number_for_nonstandard_length() {
        let dt = TestFloat::new(10);
        let err = dt
            .encode_float_value(&FloatEncodeValue::Number(1.0), &be(Vec::new()), &TestSettings, 10)
            .unwrap_err();
        assert!(err.message().contains("non-standard float length"));
    }

    #[test]
    fn encode_float_value_errors_when_format_unsupported() {
        let dt = TestFloat::new(3);
        let err = dt
            .encode_float_value(&FloatEncodeValue::Number(1.0), &be(Vec::new()), &TestSettings, 3)
            .unwrap_err();
        assert!(err.message().contains("Unsupported float format"));
    }

    #[test]
    fn float_representation_renders_decoded_value_or_placeholder() {
        let dt = TestFloat::new(4);
        assert_eq!(dt.float_representation(&be(vec![0x41, 0x10, 0, 0]), &TestSettings, -1), "9.0");
        // 0.1f is shown compactly
        assert_eq!(dt.float_representation(&be(vec![0x3d, 0xcc, 0xcc, 0xcd]), &TestSettings, -1), "0.1");
        assert_eq!(dt.float_representation(&be(vec![0x7f, 0x80, 0, 0]), &TestSettings, -1), "+Infinity");
        assert_eq!(dt.float_representation(&be(vec![0, 0]), &TestSettings, -1), "??");
    }

    #[test]
    fn encode_float_representation_parses_decimal_for_standard_length() {
        let dt = TestFloat::new(4);
        let bytes = dt.encode_float_representation("3", &be(Vec::new()), &TestSettings, 4).expect("encodes");
        assert_eq!(bytes, vec![0x40, 0x40, 0, 0]);
    }

    #[test]
    fn encode_float_representation_uses_big_float_for_nonstandard_length() {
        let dt = TestFloat::new(10);
        let bytes = dt.encode_float_representation("7", &be(Vec::new()), &TestSettings, 10).expect("encodes");
        assert_eq!(bytes, vec![0x40, 0x01, 0xe0, 0, 0, 0, 0, 0, 0, 0]);
        let bytes = dt.encode_float_representation("-Infinity", &be(Vec::new()), &TestSettings, 10).expect("encodes");
        assert_eq!(bytes, vec![0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn encode_float_representation_rejects_invalid_decimal() {
        let dt = TestFloat::new(4);
        assert!(dt.encode_float_representation("not-a-number", &be(Vec::new()), &TestSettings, 4).is_err());
        let dt10 = TestFloat::new(10);
        assert!(dt10.encode_float_representation("1.2.3", &be(Vec::new()), &TestSettings, 10).is_err());
    }
}
