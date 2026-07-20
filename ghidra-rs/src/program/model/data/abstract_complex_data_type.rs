//! Port of `ghidra.program.model.data.AbstractComplexDataType`, promoted to a trait because it
//! was selected as a dependency-cycle cut-point.
//!
//! The Java class `extends BuiltIn`. `BuiltIn` itself is not yet ported, so -- mirroring
//! [`AbstractFloatDataType`] -- this trait extends [`DataType`] + [`BuiltInDataType`] directly,
//! the two already-ported interfaces `BuiltIn` implements that `AbstractComplexDataType` actually
//! relies on.
//!
//! Several Java methods here share a name with an already-provided default method on [`DataType`]
//! (`getMnemonic`, `getLength`, `getDescription`, `getValue`, `getRepresentation`). Rust does not
//! allow a subtrait to override a supertrait's method by redeclaring the same name, so -- again
//! mirroring [`AbstractFloatDataType`]'s convention -- those overrides are exposed here under
//! distinct `complex_*` names. A concrete `impl DataType for ...` should delegate to these. Java's
//! `getAlignedLength()` override is not given a distinct method here: it simply returns
//! `getLength()`, which is exactly [`DataType::get_aligned_length`]'s existing default (`self
//! .get_length()`), so a concrete implementation that delegates `get_length` to
//! [`complex_length`](AbstractComplexDataType::complex_length) gets a correct `get_aligned_length`
//! for free.
//!
//! The private final `floatType` field (the `AbstractFloatDataType` shared by both real and
//! imaginary components) has no home on a trait, so it is exposed via the required
//! [`AbstractComplexDataType::float_type`] accessor instead; implementors are expected to store it
//! themselves.
//!
//! The two static factory methods `getDefaultComplexDataType(int)` and `getComplexDataType(int,
//! DataTypeManager)` are omitted entirely, matching the precedent set by
//! [`AbstractFloatDataType::float_format`]'s module documentation: both build a registry keyed off
//! concrete sibling types (`Complex8DataType`, `Complex16DataType`, `Complex32DataType`,
//! `FloatComplexDataType`, `DoubleComplexDataType`, `LongDoubleComplexDataType`, `Undefined`,
//! `DefaultDataType`) that are not yet ported and are unrelated to breaking this cycle, so no
//! placeholder is created for them; port them alongside those concrete types instead.
//!
//! The private static `toDouble(Object)` helper is ported as the free function
//! [`big_float_to_double`], but its logic necessarily diverges from the Java original. In Java it
//! dispatches on `instanceof Double`/`Float`/`Short`/`BigDecimal` -- deliberately *not*
//! `BigFloat`, even though the only value `floatType.getValue(...)` can actually produce is a
//! `BigFloat` (the source comment above it says as much: "Looking at
//! AbstractFloatDataType#getValue, this makes no sense to me"). Passing that `BigFloat` to the
//! real Java `toDouble` would fall through every `instanceof` check and throw
//! `IllegalArgumentException` -- or, if `getValue` returned `null` (unsupported float format),
//! `NullPointerException` from the `obj.getClass()` call inside the exception message. In this
//! port [`AbstractFloatDataType::float_value`] returns `Option<Box<dyn BigFloat>>`, so
//! `big_float_to_double` instead converts the `BigFloat` directly via
//! [`BigFloat::to_big_decimal`], and [`AbstractComplexDataType::complex_value`] returns `None`
//! (rendered as `"??"` by [`complex_representation`](AbstractComplexDataType::complex_representation),
//! matching `getRepresentation`'s existing null-check) when either component is unavailable,
//! rather than reproducing either Java failure mode.
//!
//! `new WrappedMemBuffer(buf, length / 2)` (used to read the imaginary component's bytes starting
//! after the real component) is not reused from the real
//! [`crate::program::model::mem::WrappedMemBuffer`] port: that struct wraps
//! `crate::program::model::lang::sleigh::walker::MemBuffer`, a different (already-ported)
//! `MemBuffer` trait than the [`crate::program::seam_stubs::MemBuffer`] placeholder
//! `AbstractFloatDataType::float_value` (and so this trait) is built against. Instead, a small
//! private `OffsetMemBuffer` adapter local to this module reproduces just the offsetting behavior
//! this call site needs.

use crate::docking::settings::settings::Settings;
use crate::generic::complex::Complex;
use crate::pcode::floatformat::big_float::BigFloat;
use crate::program::model::address::Address;
use crate::program::model::data::abstract_float_data_type::AbstractFloatDataType;
use crate::program::model::data::built_in_data_type::BuiltInDataType;
use crate::program::model::data::data_type::DataType;
use crate::program::seam_stubs::MemBuffer;

/// Port of the private static `AbstractComplexDataType.toDouble(Object)`, adapted to convert a
/// decoded [`BigFloat`] directly rather than dispatching on `Double`/`Float`/`Short`/`BigDecimal`
/// runtime types that `AbstractFloatDataType::float_value` never actually produces. See the
/// module-level documentation for why this diverges from the Java original. Mirrors
/// [`BigFloat::to_big_decimal`]'s own `None`-for-NaN convention by mapping that case to
/// [`f64::NAN`] instead of `None`, since every other component of a decoded value (finite or
/// infinite) is representable as an `f64`.
fn big_float_to_double(value: &dyn BigFloat) -> f64 {
    value.to_big_decimal().unwrap_or(f64::NAN)
}

/// Adapter standing in for `new WrappedMemBuffer(buf, offset)` for this module's narrow need:
/// presenting `inner` as if it started `offset` bytes further along. See the module-level
/// documentation for why the real `WrappedMemBuffer` port cannot be reused here.
struct OffsetMemBuffer<'a> {
    inner: &'a dyn MemBuffer,
    offset: i32,
}

impl MemBuffer for OffsetMemBuffer<'_> {
    fn get_address(&self) -> Address {
        self.inner.get_address()
    }

    fn get_bytes_into(&self, buffer: &mut [u8], offset: i32) -> i32 {
        self.inner.get_bytes_into(buffer, self.offset + offset)
    }

    fn is_big_endian(&self) -> bool {
        self.inner.is_big_endian()
    }
}

/// Base class for a variety of Complex data types of different sizes and types.
///
/// Port of `ghidra.program.model.data.AbstractComplexDataType`. See the module-level
/// documentation for the conventions used to resolve name clashes with [`DataType`] and for what
/// was intentionally left unported.
pub trait AbstractComplexDataType: DataType + BuiltInDataType {
    /// The shared float type used for both the real and imaginary components.
    ///
    /// Port of the private final `floatType` field.
    fn float_type(&self) -> &dyn AbstractFloatDataType;

    /// Port of the final `AbstractComplexDataType.getMnemonic(Settings)`, exposed under a
    /// distinct name since [`DataType::get_mnemonic`] already provides a default. A concrete
    /// `impl DataType for ...` should delegate `get_mnemonic` to this.
    fn complex_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        self.get_name()
    }

    /// Port of the final `AbstractComplexDataType.getLength()`, exposed under a distinct name
    /// since [`DataType::get_length`] already provides a default. A concrete `impl DataType for
    /// ...` should delegate `get_length` to this (which also makes the inherited
    /// [`DataType::get_aligned_length`] default correct, matching
    /// `AbstractComplexDataType.getAlignedLength()`; see the module-level documentation).
    fn complex_length(&self) -> i32 {
        self.float_type().encoded_length() * 2
    }

    /// Port of the final `AbstractComplexDataType.getDescription()`, exposed under a distinct
    /// name since [`DataType::get_description`] already provides a default. A concrete `impl
    /// DataType for ...` should delegate `get_description` to this.
    fn complex_description(&self) -> String {
        format!(
            "The data type for a complex number: a + bi; consisting of two {} values",
            self.float_type().get_name()
        )
    }

    /// Port of the final `AbstractComplexDataType.getValue(MemBuffer, Settings, int)`, exposed
    /// under a distinct name since [`DataType::get_value`] already provides a default with a
    /// different return type (`Option<Box<dyn Any>>` vs [`Complex`]). Returns `None` if either
    /// component cannot be decoded (see the module-level documentation for how this diverges from
    /// the Java original in that case). A concrete `impl DataType for ...` should delegate
    /// `get_value` to this.
    fn complex_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Complex> {
        let half = length / 2;
        let a = self.float_type().float_value(buf, settings, half)?;
        let wrapped = OffsetMemBuffer { inner: buf, offset: half };
        let b = self.float_type().float_value(&wrapped, settings, half)?;
        Some(Complex::new(big_float_to_double(a.as_ref()), big_float_to_double(b.as_ref())))
    }

    /// Port of `AbstractComplexDataType.getRepresentation(MemBuffer, Settings, int)`, exposed
    /// under a distinct name since [`DataType::get_representation`] already provides a default. A
    /// concrete `impl DataType for ...` should delegate `get_representation` to this.
    fn complex_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        match self.complex_value(buf, settings, length) {
            None => "??".to_string(),
            Some(value) => value.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::floatformat::float_kind::FloatKind;
    use crate::program::model::address::SpecialAddress;
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
        fn to_display_string_with_format(&self, _format: &dyn FloatFormat, _compact: bool) -> String {
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
            data_organization: Option<&dyn crate::program::model::data::data_organization::DataOrganization>,
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

    struct MockComplex {
        float_type: MockFloat,
    }

    impl DataType for MockComplex {
        fn get_name(&self) -> String {
            "complex8".to_string()
        }
        fn get_length(&self) -> i32 {
            self.complex_length()
        }
    }

    impl BuiltInDataType for MockComplex {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn crate::program::model::data::data_organization::DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl AbstractComplexDataType for MockComplex {
        fn float_type(&self) -> &dyn AbstractFloatDataType {
            &self.float_type
        }
    }

    struct MockSettings;
    impl Settings for MockSettings {}

    struct FixedMemBuffer(Vec<u8>);
    impl MemBuffer for FixedMemBuffer {
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }
        fn get_bytes_into(&self, buffer: &mut [u8], offset: i32) -> i32 {
            let offset = offset as usize;
            if offset >= self.0.len() {
                return 0;
            }
            let n = buffer.len().min(self.0.len() - offset);
            buffer[..n].copy_from_slice(&self.0[offset..offset + n]);
            n as i32
        }
        fn is_big_endian(&self) -> bool {
            true
        }
    }

    fn complex4() -> MockComplex {
        MockComplex { float_type: MockFloat { length: 4 } }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = complex4();
        let dyn_dt: &dyn AbstractComplexDataType = &dt;
        assert_eq!(dyn_dt.complex_length(), 8);
        assert_eq!(
            dyn_dt.complex_description(),
            "The data type for a complex number: a + bi; consisting of two float4 values"
        );
        assert_eq!(dyn_dt.get_aligned_length(), dyn_dt.get_length());
    }

    #[test]
    fn complex_mnemonic_uses_name() {
        let dt = complex4();
        let settings = MockSettings;
        assert_eq!(dt.complex_mnemonic(&settings), "complex8");
    }

    #[test]
    fn complex_value_decodes_real_and_imaginary_from_adjacent_halves() {
        let dt = complex4();
        let settings = MockSettings;
        // 8 bytes: first 4 decode (big-endian) to 3, next 4 decode to 7.
        let buf = FixedMemBuffer(vec![0, 0, 0, 3, 0, 0, 0, 7]);
        let value = dt.complex_value(&buf, &settings, 8).expect("decodes");
        assert_eq!(value.get_real(), 3.0);
        assert_eq!(value.get_imaginary(), 7.0);
    }

    #[test]
    fn complex_value_none_when_bytes_unavailable() {
        let dt = complex4();
        let settings = MockSettings;
        let buf = FixedMemBuffer(vec![0, 0]);
        assert!(dt.complex_value(&buf, &settings, 8).is_none());
    }

    #[test]
    fn complex_representation_renders_decoded_value_or_placeholder() {
        let dt = complex4();
        let settings = MockSettings;
        let ok_buf = FixedMemBuffer(vec![0, 0, 0, 1, 0, 0, 0, 2]);
        assert_eq!(dt.complex_representation(&ok_buf, &settings, 8), "1 + 2i");

        let short_buf = FixedMemBuffer(vec![0, 0]);
        assert_eq!(dt.complex_representation(&short_buf, &settings, 8), "??");
    }

    #[test]
    fn big_float_to_double_maps_nan_to_nan() {
        let nan = MockBigFloat { value: f64::NAN };
        assert!(big_float_to_double(&nan).is_nan());
        let finite = MockBigFloat { value: 42.5 };
        assert_eq!(big_float_to_double(&finite), 42.5);
    }
}
