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
//! The Java `FloatFormat` (`ghidra.pcode.floatformat.FloatFormat`) is referenced here with a
//! larger surface (`decodeBigFloat`, `getEncoding`, `getBigFloat(String)`, `round`,
//! `toDecimalString`) than the minimal placeholder already defined at
//! [`crate::pcode::seam_stubs::FloatFormat`] for `BigFloat`'s own needs, so a second,
//! independently minimal placeholder for the same Java class is defined at
//! [`crate::program::seam_stubs::FloatFormat`] instead of widening or duplicating the pcode one;
//! see `STUBS.tsv`. `MemBuffer.getBytes(byte[], int)`/`isBigEndian()` were likewise missing from
//! the existing [`crate::program::seam_stubs::MemBuffer`] placeholder and are added there.

use std::any::TypeId;

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::pcode::floatformat::big_float::BigFloat;
use crate::pcode::utils::utils;
use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_organization::DataOrganization;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_encode_exception::DataTypeEncodeException;
use crate::program::seam_stubs::{FloatFormat, MemBuffer};

/// Marker type standing in for `BigFloat.class`, returned (wrapped in a `TypeId`) by
/// [`AbstractFloatDataType::float_value_type_id`] since `BigFloat` is a trait -- not a concrete
/// class -- in this port, and so has no single `TypeId` of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BigFloatValue;

/// Value accepted by [`AbstractFloatDataType::encode_float_value`], standing in for the
/// `Object value` parameter of `AbstractFloatDataType.encodeValue`, documented in the Java source
/// as "expected as Number or BigFloat object".
pub enum FloatEncodeValue {
    /// A plain numeric value, used for the standard 4- and 8-byte IEEE 754 encodings.
    Number(f64),
    /// An arbitrary-precision float value, required for non-standard lengths.
    Big(Box<dyn BigFloat>),
}

fn describe_value(value: &FloatEncodeValue) -> String {
    match value {
        FloatEncodeValue::Number(v) => v.to_string(),
        FloatEncodeValue::Big(v) => v.to_display_string(),
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
    fn float_format(&self) -> Option<&dyn FloatFormat>;

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
    /// [`BigFloatValue`], standing in for `BigFloat.class`. A concrete `impl DataType for ...`
    /// should delegate `get_value_class` to this.
    fn float_value_type_id(&self, settings: &dyn Settings) -> TypeId {
        let _ = settings;
        TypeId::of::<BigFloatValue>()
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
    ) -> Option<Box<dyn BigFloat>> {
        let len = self.encoded_length() as usize;
        let format = self.float_format()?;
        let mut bytes = vec![0u8; len];
        if buf.get_bytes_into(&mut bytes, 0) as usize != len {
            return None;
        }
        if len <= 8 {
            let value = utils::bytes_to_long(&bytes, len, buf.is_big_endian());
            format.decode_big_float(value).ok()
        } else {
            let value = utils::bytes_to_big_integer(&bytes, len, buf.is_big_endian(), false);
            format.decode_big_float_from_big_integer(value).ok()
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
                let encoding = format.get_encoding_big_float(v.as_ref());
                Ok(utils::big_integer_to_bytes(encoding, len, buf.is_big_endian()))
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
                Some(format) => format.to_decimal_string(value.as_ref(), true),
                None => value.to_display_string(),
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
        let mut bf = format.get_big_float(repr);
        format.round(bf.as_mut());
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
    use crate::pcode::floatformat::float_kind::FloatKind;
    use crate::program::model::address::{Address, SpecialAddress};

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
            MockBigFloat {
                value: 0.0 * sign as f64,
            }
        }
        fn infinity(fracbits: i32, expbits: i32, sign: i32) -> Self {
            let _ = (fracbits, expbits);
            MockBigFloat {
                value: sign as f64 * f64::INFINITY,
            }
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
            Box::new(MockBigFloat {
                value: repr.parse().unwrap_or(0.0),
            })
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
        format: Option<MockFloatFormat>,
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
        fn get_c_type_declaration(&self, data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            self.float_c_type_declaration(data_organization)
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl AbstractFloatDataType for MockFloat {
        fn encoded_length(&self) -> i32 {
            self.length
        }
        fn float_format(&self) -> Option<&dyn FloatFormat> {
            self.format.as_ref().map(|f| f as &dyn FloatFormat)
        }
    }

    struct MockSettings;
    impl Settings for MockSettings {}

    struct FixedMemBuffer(Vec<u8>);
    impl MemBuffer for FixedMemBuffer {
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }
        fn get_bytes_into(&self, buffer: &mut [u8], _offset: i32) -> i32 {
            let n = buffer.len().min(self.0.len());
            buffer[..n].copy_from_slice(&self.0[..n]);
            n as i32
        }
        fn is_big_endian(&self) -> bool {
            true
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockFloat {
            length: 4,
            format: Some(MockFloatFormat),
        };
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
        let dt = MockFloat {
            length: 8,
            format: Some(MockFloatFormat),
        };
        assert_eq!(dt.build_description(), dt.build_ieee754_standard_description());
        assert_eq!(dt.float_description(), dt.build_description());
    }

    #[test]
    fn float_mnemonic_and_value_type_id() {
        let dt = MockFloat {
            length: 4,
            format: Some(MockFloatFormat),
        };
        let settings = MockSettings;
        assert_eq!(dt.float_mnemonic(&settings), "float4");
        assert_eq!(dt.float_value_type_id(&settings), TypeId::of::<BigFloatValue>());
    }

    #[test]
    fn float_value_decodes_short_length_via_bytes_to_long() {
        let dt = MockFloat {
            length: 4,
            format: Some(MockFloatFormat),
        };
        let settings = MockSettings;
        let buf = FixedMemBuffer(vec![0, 0, 0, 42]);
        let value = dt.float_value(&buf, &settings, -1).expect("decodes");
        assert_eq!(value.to_display_string(), "42");
    }

    #[test]
    fn float_value_decodes_long_length_via_bytes_to_big_integer() {
        let dt = MockFloat {
            length: 10,
            format: Some(MockFloatFormat),
        };
        let settings = MockSettings;
        let mut bytes = vec![0u8; 10];
        bytes[9] = 7;
        let buf = FixedMemBuffer(bytes);
        let value = dt.float_value(&buf, &settings, -1).expect("decodes");
        assert_eq!(value.to_display_string(), "7");
    }

    #[test]
    fn float_value_and_is_encodable_are_none_false_without_format() {
        let dt = MockFloat {
            length: 4,
            format: None,
        };
        let settings = MockSettings;
        let buf = FixedMemBuffer(vec![0, 0, 0, 1]);
        assert!(dt.float_value(&buf, &settings, -1).is_none());
        assert!(!dt.is_float_encodable());
    }

    #[test]
    fn is_float_encodable_true_when_format_present() {
        let dt = MockFloat {
            length: 4,
            format: Some(MockFloatFormat),
        };
        assert!(dt.is_float_encodable());
    }

    #[test]
    fn encode_float_value_number_path_for_standard_length() {
        let dt = MockFloat {
            length: 4,
            format: Some(MockFloatFormat),
        };
        let settings = MockSettings;
        let buf = FixedMemBuffer(Vec::new());
        let bytes = dt
            .encode_float_value(&FloatEncodeValue::Number(3.0), &buf, &settings, 4)
            .expect("encodes");
        assert_eq!(bytes, utils::long_to_bytes(3, 4, true));
    }

    #[test]
    fn encode_float_value_big_path_for_nonstandard_length() {
        let dt = MockFloat {
            length: 10,
            format: Some(MockFloatFormat),
        };
        let settings = MockSettings;
        let buf = FixedMemBuffer(Vec::new());
        let bytes = dt
            .encode_float_value(
                &FloatEncodeValue::Big(Box::new(MockBigFloat { value: 5.0 })),
                &buf,
                &settings,
                10,
            )
            .expect("encodes");
        assert_eq!(bytes.len(), 10);
        assert_eq!(
            utils::bytes_to_big_integer(&bytes, 10, true, false),
            5
        );
    }

    #[test]
    fn encode_float_value_rejects_number_for_nonstandard_length() {
        let dt = MockFloat {
            length: 10,
            format: Some(MockFloatFormat),
        };
        let settings = MockSettings;
        let buf = FixedMemBuffer(Vec::new());
        let err = dt
            .encode_float_value(&FloatEncodeValue::Number(1.0), &buf, &settings, 10)
            .unwrap_err();
        assert!(err.message().contains("non-standard float length"));
    }

    #[test]
    fn encode_float_value_errors_when_format_unsupported() {
        let dt = MockFloat {
            length: 4,
            format: None,
        };
        let settings = MockSettings;
        let buf = FixedMemBuffer(Vec::new());
        let err = dt
            .encode_float_value(&FloatEncodeValue::Number(1.0), &buf, &settings, 4)
            .unwrap_err();
        assert!(err.message().contains("Unsupported float format"));
    }

    #[test]
    fn float_representation_renders_decoded_value_or_placeholder() {
        let dt = MockFloat {
            length: 4,
            format: Some(MockFloatFormat),
        };
        let settings = MockSettings;
        let ok_buf = FixedMemBuffer(vec![0, 0, 0, 9]);
        assert_eq!(dt.float_representation(&ok_buf, &settings, -1), "9");

        let short_buf = FixedMemBuffer(vec![0, 0]);
        assert_eq!(dt.float_representation(&short_buf, &settings, -1), "??");
    }

    #[test]
    fn encode_float_representation_parses_decimal_for_standard_length() {
        let dt = MockFloat {
            length: 4,
            format: Some(MockFloatFormat),
        };
        let settings = MockSettings;
        let buf = FixedMemBuffer(Vec::new());
        let bytes = dt
            .encode_float_representation("3", &buf, &settings, 4)
            .expect("encodes");
        assert_eq!(bytes, utils::long_to_bytes(3, 4, true));
    }

    #[test]
    fn encode_float_representation_uses_big_float_for_nonstandard_length() {
        let dt = MockFloat {
            length: 10,
            format: Some(MockFloatFormat),
        };
        let settings = MockSettings;
        let buf = FixedMemBuffer(Vec::new());
        let bytes = dt
            .encode_float_representation("7", &buf, &settings, 10)
            .expect("encodes");
        assert_eq!(bytes.len(), 10);
        assert_eq!(utils::bytes_to_big_integer(&bytes, 10, true, false), 7);
    }

    #[test]
    fn encode_float_representation_rejects_invalid_decimal() {
        let dt = MockFloat {
            length: 4,
            format: Some(MockFloatFormat),
        };
        let settings = MockSettings;
        let buf = FixedMemBuffer(Vec::new());
        assert!(dt
            .encode_float_representation("not-a-number", &buf, &settings, 4)
            .is_err());
    }
}
