//! Port of `ghidra.pcode.floatformat.FloatFormat`.
//!
//! IEEE 754 binary encodings (2, 4, 8, 10 (x87 extended), 16 and 32 bytes) in support of
//! floating-point data types and p-code float emulation. Encodings of at most 8 bytes can be
//! handled as `long`s through the host's `f64`; every size can be handled as a `BigInteger`
//! ([`BigInt`]) through [`BigFloat`].
//!
//! # Rust shape
//!
//! Java declares a concrete `class FloatFormat` that nothing extends, so this is a `struct`
//! (replacing two independent placeholder traits formerly in `pcode::seam_stubs` and
//! `program::seam_stubs`). Instances come from [`float_format_factory::get_float_format`]
//! (`&'static FloatFormat`).
//!
//! Java overloads are split by suffix: the `long`/`double` members keep the plain name
//! (`op_add`, `get_encoding`, `decode_big_float`) and the `BigInteger`/`BigFloat` members take
//! `_big` (`op_add_big`, `get_encoding_big`, `decode_big_float_big`); the `getBigFloat` overloads
//! are suffixed by argument type. Java's `long` shifts are reproduced with `wrapping_shl`/
//! `wrapping_shr`, which mask the shift count exactly as the JVM does. The unchecked
//! `UnsupportedOperationException` that the `long` members throw for sizes over 8 bytes is a
//! panic, as is the `UnsupportedOperationException` from `decodeBigFloat(long)`.
//!
//! [`float_format_factory::get_float_format`]: super::float_format_factory::get_float_format

use num_bigint::BigInt;
use num_traits::{One, Signed, ToPrimitive, Zero};

use super::big_decimal::{BigDecimal, MathContext, ParseBigDecimalError, RoundingMode};
use super::big_float::{self, bit_length, lowest_set_bit, shl, shr, test_bit, BigFloat};
use super::float_format_factory;
use super::{FloatKind, UnsupportedFloatFormatException};
use crate::pcode::utils::{calc_mask, zzz_sign_extend};

/// IEEE 754 encoding format for one storage size. See the module docs.
///
/// Port of `ghidra.pcode.floatformat.FloatFormat`.
#[derive(Debug, Clone)]
pub struct FloatFormat {
    size: i32,
    signbit_pos: i32,
    frac_pos: i32,
    frac_size: i32,
    effective_frac_size: i32,
    exp_pos: i32,
    exp_size: i32,
    bias: i32,
    maxexponent: i32,
    jbitimplied: bool,
    max_value: BigFloat,
    min_value: BigFloat,
    display_context: MathContext,
}

/// Port of the nested `FloatFormat.SmallFloatData`: a `long`-mantissa stand-in for [`BigFloat`].
struct SmallFloatData {
    fracbits: i32,
    #[allow(dead_code)]
    expbits: i32,
    kind: FloatKind,
    sign: i32,
    unscaled: i64,
    scale: i32,
}

impl SmallFloatData {
    fn is_zero(&self) -> bool {
        self.kind == FloatKind::Finite && self.unscaled == 0
    }
}

/// `java.util.Long.numberOfLeadingZeros`-based `leadBit(long)`.
fn lead_bit_long(l: i64) -> i32 {
    63 - (l as u64).leading_zeros() as i32
}

/// `leadBit(BigInteger)`.
fn lead_bit_big(i: &BigInt) -> i32 {
    bit_length(i) - 1
}

/// Port of `roundToLeadBit(BigInteger, int)`: shift right rounding half-even, or shift left, so
/// that the lead bit lands at `new_lead_bit`. A final round-up can carry one bit further.
fn round_to_lead_bit_big(i: &BigInt, new_lead_bit: i32) -> BigInt {
    let amt = lead_bit_big(i) - new_lead_bit;
    if amt == 0 {
        return i.clone();
    }
    if amt < 0 {
        return shl(i, -amt);
    }

    // round to nearest even
    let midbit = amt - 1;
    let midset = test_bit(i, midbit);
    let eps = lowest_set_bit(i) < midbit;
    let mut r = shr(i, amt);
    let odd = test_bit(&r, 0);
    if midset && (eps || odd) {
        r += 1;
    }
    r
}

/// Port of `roundToLeadBit(long, int)`.
fn round_to_lead_bit_long(i: i64, new_lead_bit: i32) -> i64 {
    let amt = lead_bit_long(i) - new_lead_bit;
    if amt == 0 {
        return i;
    }
    if amt < 0 {
        return i.wrapping_shl((-amt) as u32);
    }

    // round to nearest even
    let midbitmask = 1i64.wrapping_shl((amt - 1) as u32);
    let midset = (i & midbitmask) != 0;
    let eps = (midbitmask.wrapping_sub(1) & i) != 0;
    let mut r = (i as u64).wrapping_shr(amt as u32) as i64;
    let odd = (r & 1) != 0;
    if midset && (eps || odd) {
        r = r.wrapping_add(1);
    }
    r
}

/// Port of `Utils.convertToSignedValue(BigInteger, int)`.
fn convert_to_signed_value(val: BigInt, byte_size: i32) -> BigInt {
    let signbit = byte_size * 8 - 1;
    if val.is_negative() || !test_bit(&val, signbit) {
        return val; // positive value or already signed
    }
    val - shl(&BigInt::one(), signbit + 1)
}

/// Port of `Utils.convertToUnsignedValue(BigInteger, int)`.
fn convert_to_unsigned_value(val: BigInt, byte_size: i32) -> BigInt {
    if !val.is_negative() {
        return val;
    }
    let mask = shl(&BigInt::one(), byte_size * 8) - BigInt::one();
    val & mask
}

/// `BigInteger.doubleValue()`: nearest `f64`, ties to even (overflow to infinity).
fn big_int_to_f64(v: &BigInt) -> f64 {
    v.to_string().parse::<f64>().expect("integer string")
}

/// `BigInteger.floatValue()`: nearest `f32`, ties to even (overflow to infinity).
fn big_int_to_f32(v: &BigInt) -> f32 {
    v.to_string().parse::<f32>().expect("integer string")
}

fn one_if(b: bool) -> BigInt {
    if b {
        BigInt::one()
    }
    else {
        BigInt::zero()
    }
}

impl FloatFormat {
    /// Set format for the given size (in bytes) according to IEEE 754.
    ///
    /// Port of the package-private constructor `FloatFormat(int)`; outside this module use
    /// [`get_float_format`](super::float_format_factory::get_float_format).
    pub(crate) fn new(sz: i32) -> Result<Self, UnsupportedFloatFormatException> {
        let (signbit_pos, exp_pos, exp_size, frac_pos, frac_size, bias, jbitimplied, precision) = match sz {
            2 => (15, 10, 5, 0, 10, 15, true, 4),
            4 => (31, 23, 8, 0, 23, 127, true, 8),
            8 => (63, 52, 11, 0, 52, 1023, true, 16),
            16 => (127, 112, 15, 0, 112, 16383, true, 34),
            32 => (255, 236, 19, 0, 236, 262143, true, 71),
            // 80-bit double extended precision format. See
            // https://en.wikipedia.org/wiki/Extended_precision
            10 => (79, 64, 15, 0, 64, 16383, false, 18),
            _ => return Err(UnsupportedFloatFormatException::with_format_size(sz)),
        };

        if !jbitimplied && sz <= 8 {
            panic!("Small format implementation assumes jbitimplied=true");
        }

        let effective_frac_size = frac_size + if jbitimplied { 1 } else { 0 };
        let maxexponent = (1 << exp_size) - 1;

        // jbitimplied assumed true
        let max_value = BigFloat::new(
            effective_frac_size,
            exp_size,
            FloatKind::Finite,
            1,
            shl(&BigInt::one(), effective_frac_size) - BigInt::one(),
            (1 << (exp_size - 1)) - 1,
        );
        let min_value = BigFloat::new(
            effective_frac_size,
            exp_size,
            FloatKind::Finite,
            1,
            BigInt::one(),
            2 - (1 << (exp_size - 1)),
        );

        Ok(Self {
            size: sz,
            signbit_pos,
            frac_pos,
            frac_size,
            effective_frac_size,
            exp_pos,
            exp_size,
            bias,
            maxexponent,
            jbitimplied,
            max_value,
            min_value,
            display_context: MathContext::new(precision, RoundingMode::HalfEven),
        })
    }

    fn java_float_format() -> &'static FloatFormat {
        float_format_factory::get_float_format(4).expect("4-byte format is supported")
    }

    fn java_double_format() -> &'static FloatFormat {
        float_format_factory::get_float_format(8).expect("8-byte format is supported")
    }

    /// Port of `FloatFormat.getSize()`: the encoding size in bytes.
    pub fn get_size(&self) -> i32 {
        self.size
    }

    /// Port of the package-private `getDisplayContext()`: the decimal precision used to display
    /// values of this format.
    pub fn get_display_context(&self) -> &MathContext {
        &self.display_context
    }

    /// Port of `FloatFormat.getMaxBigFloat()` (the public `maxValue` field): the largest finite
    /// value.
    pub fn get_max_big_float(&self) -> &BigFloat {
        &self.max_value
    }

    /// Port of `FloatFormat.getMinBigFloat()` (the public `minValue` field): the smallest positive
    /// subnormal value.
    pub fn get_min_big_float(&self) -> &BigFloat {
        &self.min_value
    }

    fn extract_kind(&self, encoding: i64) -> FloatKind {
        let exp = self.extract_exponent_code(encoding);
        if exp == self.maxexponent {
            let frac = self.extract_fractional_code(encoding);
            if frac == 0 {
                return FloatKind::Infinite;
            }
            if (frac as u64).wrapping_shr((self.frac_size - 1) as u32) == 1 {
                return FloatKind::QuietNan;
            }
            return FloatKind::SignalingNan;
        }
        FloatKind::Finite
    }

    fn extract_kind_big(&self, l: &BigInt) -> FloatKind {
        let exp = self.extract_exponent_code_big(l);
        if exp == self.maxexponent {
            let frac = self.extract_fractional_code_big(l);
            if frac.is_zero() {
                return FloatKind::Infinite;
            }
            if shr(&frac, self.frac_size - 1).is_one() {
                return FloatKind::QuietNan;
            }
            return FloatKind::SignalingNan;
        }
        FloatKind::Finite
    }

    fn extract_fractional_code(&self, x: i64) -> i64 {
        let mask = 1i64.wrapping_shl(self.frac_size as u32).wrapping_sub(1);
        let x = (x as u64).wrapping_shr(self.frac_pos as u32) as i64; // Eliminate bits below
        x & mask
    }

    fn extract_fractional_code_big(&self, x: &BigInt) -> BigInt {
        let mask = shl(&BigInt::one(), self.frac_size) - BigInt::one();
        shr(x, self.frac_pos) & mask
    }

    fn extract_sign(&self, x: i64) -> bool {
        ((x as u64).wrapping_shr(self.signbit_pos as u32) & 1) != 0
    }

    fn extract_sign_big(&self, x: &BigInt) -> bool {
        test_bit(x, self.signbit_pos)
    }

    fn extract_exponent_code(&self, x: i64) -> i32 {
        let x = (x as u64).wrapping_shr(self.exp_pos as u32) as i64;
        let mask = 1i64.wrapping_shl(self.exp_size as u32).wrapping_sub(1);
        (x & mask) as i32
    }

    fn extract_exponent_code_big(&self, x: &BigInt) -> i32 {
        // Java: x.shiftRight(exp_pos).intValue() & maxexponent
        (shr(x, self.exp_pos) & BigInt::from(self.maxexponent)).to_i32().expect("masked exponent")
    }

    fn set_sign(&self, x: i64, sign: bool) -> i64 {
        if !sign {
            return x; // Assume bit is already zero
        }
        x | 1i64.wrapping_shl(self.signbit_pos as u32)
    }

    fn set_sign_big(&self, mut x: BigInt, sign: bool) -> BigInt {
        if sign {
            x.set_bit(self.signbit_pos as u64, true);
        }
        x
    }

    /// Port of `FloatFormat.getZeroEncoding(boolean)`.
    pub fn get_zero_encoding(&self, sgn: bool) -> i64 {
        self.set_sign(0, sgn)
    }

    /// Port of `FloatFormat.getInfinityEncoding(boolean)`.
    pub fn get_infinity_encoding(&self, sgn: bool) -> i64 {
        let res = (self.maxexponent as i64).wrapping_shl(self.exp_pos as u32);
        self.set_sign(res, sgn)
    }

    /// Port of `FloatFormat.getBigZeroEncoding(boolean)`.
    pub fn get_big_zero_encoding(&self, sgn: bool) -> BigInt {
        self.set_sign_big(BigInt::zero(), sgn)
    }

    /// Port of `FloatFormat.getBigZero(boolean)`.
    pub fn get_big_zero(&self, sgn: bool) -> BigFloat {
        BigFloat::new(
            self.effective_frac_size,
            self.exp_size,
            FloatKind::Finite,
            if sgn { -1 } else { 1 },
            BigInt::zero(),
            2 - (1 << (self.exp_size - 1)),
        )
    }

    /// Port of `FloatFormat.getBigInfinityEncoding(boolean)`.
    pub fn get_big_infinity_encoding(&self, sgn: bool) -> BigInt {
        let res = shl(&BigInt::from(self.maxexponent), self.exp_pos);
        self.set_sign_big(res, sgn)
    }

    /// Port of `FloatFormat.getBigInfinity(boolean)`.
    pub fn get_big_infinity(&self, sgn: bool) -> BigFloat {
        BigFloat::infinity(self.effective_frac_size, self.exp_size, if sgn { -1 } else { 1 })
    }

    /// Port of `FloatFormat.getNaNEncoding(boolean)`: the quiet NaN with only the top fraction bit
    /// set.
    pub fn get_nan_encoding(&self, sgn: bool) -> i64 {
        let mut res = 1i64.wrapping_shl((self.frac_pos + self.frac_size - 1) as u32);
        res |= (self.maxexponent as i64).wrapping_shl(self.exp_pos as u32);
        self.set_sign(res, sgn)
    }

    /// Port of `FloatFormat.getBigNaNEncoding(boolean)`.
    pub fn get_big_nan_encoding(&self, sgn: bool) -> BigInt {
        let res = shl(&BigInt::one(), self.frac_pos + self.frac_size - 1)
            | shl(&BigInt::from(self.maxexponent), self.exp_pos);
        self.set_sign_big(res, sgn)
    }

    /// Port of `FloatFormat.getBigNaN(boolean)`.
    pub fn get_big_nan(&self, sgn: bool) -> BigFloat {
        BigFloat::quiet_nan(self.effective_frac_size, self.exp_size, if sgn { -1 } else { 1 })
    }

    fn rescale_to_this(&self, bf: BigFloat) -> BigFloat {
        BigFloat::new(
            self.effective_frac_size,
            self.exp_size,
            bf.kind,
            bf.sign,
            shl(&bf.unscaled, self.effective_frac_size - bf.fracbits),
            bf.scale,
        )
    }

    /// Port of `FloatFormat.getBigFloat(float)`: the exact `f32` value, re-expressed at this
    /// format's precision (Java truncates the mantissa and keeps the scale, so the value must fit).
    pub fn get_big_float_f32(&self, f: f32) -> BigFloat {
        self.rescale_to_this(FloatFormat::to_big_float_f32(f))
    }

    /// Port of `FloatFormat.getBigFloat(double)`; see [`get_big_float_f32`](Self::get_big_float_f32).
    pub fn get_big_float_f64(&self, d: f64) -> BigFloat {
        self.rescale_to_this(FloatFormat::to_big_float_f64(d))
    }

    /// Port of `FloatFormat.decodeBigFloat(long)`: decode an encoding of at most 8 bytes.
    ///
    /// # Panics
    /// If this format is wider than 8 bytes (Java: `UnsupportedOperationException`); use
    /// [`decode_big_float_big`](Self::decode_big_float_big).
    pub fn decode_big_float(&self, encoding: i64) -> BigFloat {
        if self.size > 8 {
            panic!("method not supported for float size of {}", self.size);
        }
        let sgn = self.extract_sign(encoding);
        let exp = self.extract_exponent_code(encoding);
        let frac = self.extract_fractional_code(encoding);
        let kind = self.extract_kind(encoding);

        let scale;
        let mut unscaled = BigInt::from(frac);
        if kind == FloatKind::Finite {
            if exp == 0 {
                // subnormal
                scale = -self.bias + 1;
            }
            else {
                scale = exp - self.bias;
                if self.jbitimplied {
                    unscaled.set_bit(self.frac_size as u64, true);
                }
            }
        }
        else {
            scale = 0;
        }
        BigFloat::new(self.effective_frac_size, self.exp_size, kind, if sgn { -1 } else { 1 }, unscaled, scale)
    }

    /// Port of the package-private `getSmallFloatData(long)`.
    fn get_small_float_data(&self, encoding: i64) -> SmallFloatData {
        if self.size > 8 {
            panic!("method not supported for float size of {}", self.size);
        }
        let sgn = self.extract_sign(encoding);
        let exp = self.extract_exponent_code(encoding);
        let frac = self.extract_fractional_code(encoding);
        let kind = self.extract_kind(encoding);

        let scale;
        let mut unscaled = frac;
        if kind == FloatKind::Finite {
            if exp == 0 {
                // subnormal
                scale = -self.bias + 1;
            }
            else {
                scale = exp - self.bias;
                if self.jbitimplied {
                    unscaled |= 1i64.wrapping_shl(self.frac_size as u32);
                }
            }
        }
        else {
            scale = 0;
        }
        SmallFloatData {
            fracbits: self.effective_frac_size,
            expbits: self.exp_size,
            kind,
            sign: if sgn { -1 } else { 1 },
            unscaled,
            scale,
        }
    }

    /// Port of `FloatFormat.decodeHostFloat(long)`: convert an encoding of at most 8 bytes to the
    /// host `f64`.
    ///
    /// # Panics
    /// If this format is wider than 8 bytes (Java: `UnsupportedOperationException`).
    pub fn decode_host_float(&self, encoding: i64) -> f64 {
        if self.size == 8 {
            // assume IEEE-754 8-byte format which matches Java double encoding
            return f64::from_bits(encoding as u64);
        }

        if self.size > 8 {
            panic!("method not supported for float size of {}", self.size);
        }

        let sgn = self.extract_sign(encoding);
        let mut exp = self.extract_exponent_code(encoding);
        let mut frac = self.extract_fractional_code(encoding);

        let mut subnormal = false;
        if exp == 0 {
            if frac == 0 {
                // Floating point zero
                return if sgn { -0.0 } else { 0.0 };
            }
            subnormal = true;
        }
        else if exp == self.maxexponent {
            if frac == 0 {
                // Floating point infinity
                return if sgn { f64::NEG_INFINITY } else { f64::INFINITY };
            }
            return f64::NAN;
        }

        exp -= self.bias;

        // most-significant fractional/mantissa bit (Java computes this with an int shift)
        let msbit = 1i32.wrapping_shl((self.frac_size - 1) as u32) as i64;

        if !subnormal && !self.jbitimplied {
            frac &= !msbit; // remove explicit jbit
            frac = frac.wrapping_shl(1);
            exp -= 1;
        }

        if subnormal {
            // attempt to normalize
            exp = -self.bias;

            while exp > -1023 && (frac & msbit) == 0 && frac != 0 {
                frac = frac.wrapping_shl(1);
                exp -= 1;
            }

            // establish implied jbit
            if exp > -1023 && (frac & msbit) != 0 && frac != 0 {
                frac = frac.wrapping_shl(1);
            }
            else {
                exp -= 1;
            }

            // mask-off implied jbit (Java: int expression, sign-extended to long)
            frac &= (!(1i32.wrapping_shl(self.frac_size as u32)).wrapping_neg()) as i64;
        }

        exp += 1023;
        frac = frac.wrapping_shl((52 - self.frac_size) as u32);

        let encoded_double =
            (if sgn { 1i64 << 63 } else { 0 }) | ((exp as i64).wrapping_shl(52)) | frac;
        f64::from_bits(encoded_double as u64)
    }

    /// Port of `FloatFormat.decodeBigFloat(BigInteger)`: decode an encoding of any size.
    pub fn decode_big_float_big(&self, encoding: &BigInt) -> BigFloat {
        let sgn = self.extract_sign_big(encoding);
        let sign = if sgn { -1 } else { 1 };
        let mut frac = self.extract_fractional_code_big(encoding);
        let exp = self.extract_exponent_code_big(encoding);
        if exp == 0 {
            // subnormals
            // NOTE: 80-bit (size=10) encoding is implementation dependant
            if frac.is_zero() {
                return BigFloat::zero(self.effective_frac_size, self.exp_size, sign);
            }
            return BigFloat::new(self.effective_frac_size, self.exp_size, FloatKind::Finite, sign, frac, 1 - self.bias);
        }
        else if exp == self.maxexponent {
            // NOTE: 80-bit (size=10) encoding is implementation dependant
            if frac.is_zero() {
                // Floating point infinity
                return BigFloat::infinity(self.effective_frac_size, self.exp_size, sign);
            }
            return BigFloat::quiet_nan(self.effective_frac_size, self.exp_size, sign);
        }

        if self.jbitimplied {
            frac.set_bit(self.frac_size as u64, true);
        }
        BigFloat::new(self.effective_frac_size, self.exp_size, FloatKind::Finite, sign, frac, exp - self.bias)
    }

    /// Port of `FloatFormat.getEncoding(double)`: encode a host `f64` into this format (at most 8
    /// bytes), rounding half-even.
    pub fn get_encoding(&self, host: f64) -> i64 {
        let value = FloatFormat::get_small_float_data_f64(host);
        match value.kind {
            FloatKind::QuietNan | FloatKind::SignalingNan => return self.get_nan_encoding(value.sign < 0),
            FloatKind::Infinite => return self.get_infinity_encoding(value.sign < 0),
            FloatKind::Finite => {}
        }
        if value.is_zero() {
            return self.get_zero_encoding(value.sign < 0);
        }
        let mut exp;
        let mut fraction;

        let lb_unscaled = lead_bit_long(value.unscaled);
        if value.scale - value.fracbits + lb_unscaled >= -self.bias {
            // normal case
            exp = value.scale - value.fracbits + 1 + lb_unscaled + self.bias;
            fraction = round_to_lead_bit_long(value.unscaled, self.frac_size);
            // if carry..
            if lead_bit_long(fraction) > self.frac_size {
                fraction = ((fraction as u64) >> 1) as i64;
                exp += 1;
            }
            if self.jbitimplied {
                fraction &= 1i64.wrapping_shl(self.frac_size as u32).wrapping_sub(1);
            }
        }
        else if !self.jbitimplied {
            // subnormals are not supported
            return self.get_zero_encoding(value.sign < 0);
        }
        else {
            // subnormal
            exp = 0;
            let n = value.scale - value.fracbits + lb_unscaled + self.bias + self.frac_size;
            if n < 0 {
                return self.get_zero_encoding(value.sign < 0);
            }
            fraction = round_to_lead_bit_long(value.unscaled, n);
        }
        if exp >= self.maxexponent {
            return self.get_infinity_encoding(value.sign < 0);
        }

        let mut result = (exp as i64).wrapping_shl(self.exp_pos as u32) | fraction;
        if value.sign < 0 {
            result |= 1i64.wrapping_shl(self.signbit_pos as u32);
        }
        result
    }

    /// Port of `FloatFormat.getEncoding(BigFloat)`: encode `value` into this format, rounding
    /// half-even. Every NaN encodes as the positive quiet NaN.
    pub fn get_encoding_big(&self, value: &BigFloat) -> BigInt {
        match value.kind {
            FloatKind::QuietNan | FloatKind::SignalingNan => return self.get_big_nan_encoding(false),
            FloatKind::Infinite => return self.get_big_infinity_encoding(value.sign < 0),
            FloatKind::Finite => {}
        }
        if value.is_zero() {
            return self.get_big_zero_encoding(value.sign < 0);
        }
        let mut exp;
        let mut fraction;

        let lb_unscaled = lead_bit_big(&value.unscaled);
        if value.scale - value.fracbits + lb_unscaled >= -self.bias {
            // normal case
            exp = value.scale - value.fracbits + 1 + lb_unscaled + self.bias;
            let lead_bit = self.frac_size - if self.jbitimplied { 0 } else { 1 };
            fraction = round_to_lead_bit_big(&value.unscaled, lead_bit);
            // if carry..
            if lead_bit_big(&fraction) > self.frac_size {
                fraction = shr(&fraction, 1);
                exp += 1;
            }
            if self.jbitimplied {
                fraction.set_bit(self.frac_size as u64, false);
            }
        }
        else if !self.jbitimplied {
            // subnormals are not supported
            return self.get_big_zero_encoding(value.sign < 0);
        }
        else {
            // subnormal
            exp = 0;
            let n = value.scale - value.fracbits + lb_unscaled + self.bias + self.frac_size;
            if n < 0 {
                return self.get_big_zero_encoding(value.sign < 0);
            }
            fraction = round_to_lead_bit_big(&value.unscaled, n);
        }
        if exp >= self.maxexponent {
            return self.get_big_infinity_encoding(value.sign < 0);
        }

        let mut result = shl(&BigInt::from(exp), self.exp_pos) | fraction;
        if value.sign < 0 {
            result.set_bit(self.signbit_pos as u64, true);
        }
        result
    }

    /// Port of `FloatFormat.round(BigFloat)`: the exact decimal value rounded to this format's
    /// display context, or `None` for NaN.
    pub fn round(&self, big_float: &BigFloat) -> Option<BigDecimal> {
        big_float.to_big_decimal().map(|bd| bd.round(&self.display_context))
    }

    /// Port of `FloatFormat.toDecimalString(BigFloat)`.
    pub fn to_decimal_string(&self, big_float: &BigFloat) -> String {
        big_float.to_string_with_format(self, false)
    }

    /// Port of `FloatFormat.toDecimalString(BigFloat, boolean)`: if `compact`, the fewest digits
    /// that still encode to the same bits in this format.
    pub fn to_decimal_string_compact(&self, big_float: &BigFloat, compact: bool) -> String {
        big_float.to_string_with_format(self, compact)
    }

    /// Port of the private `toBinaryString(long)` (diagnostic; at most 8 bytes).
    fn to_binary_string_long(&self, encoding: i64) -> String {
        let sgn = self.extract_sign(encoding);
        let exp = self.extract_exponent_code(encoding);
        let frac = self.extract_fractional_code(encoding);
        match self.extract_kind(encoding) {
            FloatKind::Infinite => return if sgn { "-inf" } else { "+inf" }.to_string(),
            FloatKind::QuietNan => return "qNaN".to_string(),
            FloatKind::SignalingNan => return "sNaN".to_string(),
            FloatKind::Finite => {}
        }
        let binary = format!("{:b}", frac as u64);
        self.format_binary(sgn, exp, frac == 0, binary)
    }

    /// Port of the private `toBinaryString(BigInteger)` (diagnostic).
    fn to_binary_string_big(&self, encoding: &BigInt) -> String {
        let sgn = self.extract_sign_big(encoding);
        let exp = self.extract_exponent_code_big(encoding);
        let frac = self.extract_fractional_code_big(encoding);
        match self.extract_kind_big(encoding) {
            FloatKind::Infinite => return if sgn { "-inf" } else { "+inf" }.to_string(),
            FloatKind::QuietNan => return "qNaN".to_string(),
            FloatKind::SignalingNan => return "sNaN".to_string(),
            FloatKind::Finite => {}
        }
        let binary = frac.to_str_radix(2);
        self.format_binary(sgn, exp, frac.is_zero(), binary)
    }

    fn format_binary(&self, sgn: bool, exp: i32, frac_is_zero: bool, binary: String) -> String {
        let pad = (self.frac_size as usize).saturating_sub(binary.len());
        let mut binary = format!("{}{}", "0".repeat(pad), binary);
        let trimmed = binary.trim_end_matches('0').len();
        binary.truncate(trimmed);
        if binary.is_empty() {
            binary = "0".to_string();
        }
        let s = if sgn { "-" } else { "" };
        if exp == 0 {
            // subnormal
            if frac_is_zero {
                return format!("{}0b0.0", s);
            }
            return format!("{}0b0.{} * 2^{}", s, binary, -self.bias + 1);
        }
        format!("{}0b1.{} * 2^{}", s, binary, exp - self.bias)
    }

    /// Port of the static `FloatFormat.toBigFloat(float)`: the exact value of `f` (4-byte IEEE 754).
    pub fn to_big_float_f32(f: f32) -> BigFloat {
        Self::java_float_format().decode_big_float(f.to_bits() as i64)
    }

    /// Port of the static `FloatFormat.toBigFloat(double)`: the exact value of `d` (8-byte IEEE
    /// 754).
    pub fn to_big_float_f64(d: f64) -> BigFloat {
        Self::java_double_format().decode_big_float(d.to_bits() as i64)
    }

    fn get_small_float_data_f64(d: f64) -> SmallFloatData {
        Self::java_double_format().get_small_float_data(d.to_bits() as i64)
    }

    /// Port of the package-private static `toBinaryString(float)` (diagnostic).
    pub fn to_binary_string_f32(f: f32) -> String {
        Self::java_float_format().to_binary_string_long(f.to_bits() as i64)
    }

    /// Port of the package-private static `toBinaryString(double)` (diagnostic).
    pub fn to_binary_string_f64(d: f64) -> String {
        Self::java_double_format().to_binary_string_long(d.to_bits() as i64)
    }

    /// Port of the package-private `toBinaryString(BigFloat)`: the binary form of `value` after
    /// rounding it to this format (diagnostic).
    pub fn to_binary_string(&self, value: &BigFloat) -> String {
        self.to_binary_string_big(&self.get_encoding_big(value))
    }

    // Each operation exists for both encodings, long and BigInteger. The long members emulate the
    // target through the host's double and must not be used when size > 8.

    /// Port of `opEqual(long, long)`: `a == b` via host doubles.
    pub fn op_equal(&self, a: i64, b: i64) -> i64 {
        (self.decode_host_float(a) == self.decode_host_float(b)) as i64
    }

    /// Port of `opEqual(BigInteger, BigInteger)`. Like Java, compares with `BigFloat.equals`, so
    /// `+0` and `-0` are *not* equal on this path; NaN is never equal.
    pub fn op_equal_big(&self, a: &BigInt, b: &BigInt) -> BigInt {
        let fa = self.decode_big_float_big(a);
        let fb = self.decode_big_float_big(b);
        if fa.is_nan() || fb.is_nan() {
            return BigInt::zero();
        }
        one_if(fa == fb)
    }

    /// Port of `opNotEqual(long, long)`.
    pub fn op_not_equal(&self, a: i64, b: i64) -> i64 {
        (self.decode_host_float(a) != self.decode_host_float(b)) as i64
    }

    /// Port of `opNotEqual(BigInteger, BigInteger)`; see [`op_equal_big`](Self::op_equal_big).
    pub fn op_not_equal_big(&self, a: &BigInt, b: &BigInt) -> BigInt {
        let fa = self.decode_big_float_big(a);
        let fb = self.decode_big_float_big(b);
        if fa.is_nan() || fb.is_nan() {
            return BigInt::one();
        }
        one_if(fa != fb)
    }

    /// Port of `opLess(long, long)`.
    pub fn op_less(&self, a: i64, b: i64) -> i64 {
        (self.decode_host_float(a) < self.decode_host_float(b)) as i64
    }

    /// Port of `opLess(BigInteger, BigInteger)`, by [`BigFloat::compare_to`] (NaN sorts greatest).
    pub fn op_less_big(&self, a: &BigInt, b: &BigInt) -> BigInt {
        let fa = self.decode_big_float_big(a);
        let fb = self.decode_big_float_big(b);
        one_if(fa.compare_to(&fb) < 0)
    }

    /// Port of `opLessEqual(long, long)`.
    pub fn op_less_equal(&self, a: i64, b: i64) -> i64 {
        (self.decode_host_float(a) <= self.decode_host_float(b)) as i64
    }

    /// Port of `opLessEqual(BigInteger, BigInteger)`.
    pub fn op_less_equal_big(&self, a: &BigInt, b: &BigInt) -> BigInt {
        let fa = self.decode_big_float_big(a);
        let fb = self.decode_big_float_big(b);
        one_if(fa.compare_to(&fb) <= 0)
    }

    /// Port of `opNan(long)`: 1 if `a` is not a number.
    pub fn op_nan(&self, a: i64) -> i64 {
        self.decode_host_float(a).is_nan() as i64
    }

    /// Port of `opNan(BigInteger)`.
    pub fn op_nan_big(&self, a: &BigInt) -> BigInt {
        one_if(self.decode_big_float_big(a).is_nan())
    }

    /// Port of `opAdd(long, long)`.
    pub fn op_add(&self, a: i64, b: i64) -> i64 {
        self.get_encoding(self.decode_host_float(a) + self.decode_host_float(b))
    }

    /// Port of `opAdd(BigInteger, BigInteger)`.
    pub fn op_add_big(&self, a: &BigInt, b: &BigInt) -> BigInt {
        let mut fa = self.decode_big_float_big(a);
        fa.add(&self.decode_big_float_big(b));
        self.get_encoding_big(&fa)
    }

    /// Port of `opSub(long, long)`.
    pub fn op_sub(&self, a: i64, b: i64) -> i64 {
        self.get_encoding(self.decode_host_float(a) - self.decode_host_float(b))
    }

    /// Port of `opSub(BigInteger, BigInteger)`.
    pub fn op_sub_big(&self, a: &BigInt, b: &BigInt) -> BigInt {
        let mut fa = self.decode_big_float_big(a);
        fa.sub(&self.decode_big_float_big(b));
        self.get_encoding_big(&fa)
    }

    /// Port of `opDiv(long, long)`.
    pub fn op_div(&self, a: i64, b: i64) -> i64 {
        self.get_encoding(self.decode_host_float(a) / self.decode_host_float(b))
    }

    /// Port of `opDiv(BigInteger, BigInteger)`.
    pub fn op_div_big(&self, a: &BigInt, b: &BigInt) -> BigInt {
        let mut fa = self.decode_big_float_big(a);
        fa.div(&self.decode_big_float_big(b));
        self.get_encoding_big(&fa)
    }

    /// Port of `opMult(long, long)`.
    pub fn op_mult(&self, a: i64, b: i64) -> i64 {
        self.get_encoding(self.decode_host_float(a) * self.decode_host_float(b))
    }

    /// Port of `opMult(BigInteger, BigInteger)`.
    pub fn op_mult_big(&self, a: &BigInt, b: &BigInt) -> BigInt {
        let mut fa = self.decode_big_float_big(a);
        fa.mul(&self.decode_big_float_big(b));
        self.get_encoding_big(&fa)
    }

    /// Port of `opNeg(long)`.
    pub fn op_neg(&self, a: i64) -> i64 {
        self.get_encoding(-self.decode_host_float(a))
    }

    /// Port of `opNeg(BigInteger)`.
    pub fn op_neg_big(&self, a: &BigInt) -> BigInt {
        let mut fa = self.decode_big_float_big(a);
        fa.negate();
        self.get_encoding_big(&fa)
    }

    /// Port of `opAbs(long)`.
    pub fn op_abs(&self, a: i64) -> i64 {
        self.get_encoding(self.decode_host_float(a).abs())
    }

    /// Port of `opAbs(BigInteger)`.
    pub fn op_abs_big(&self, a: &BigInt) -> BigInt {
        let mut fa = self.decode_big_float_big(a);
        fa.abs();
        self.get_encoding_big(&fa)
    }

    /// Port of `opSqrt(long)`.
    pub fn op_sqrt(&self, a: i64) -> i64 {
        self.get_encoding(self.decode_host_float(a).sqrt())
    }

    /// Port of `opSqrt(BigInteger)`.
    pub fn op_sqrt_big(&self, a: &BigInt) -> BigInt {
        let mut fa = self.decode_big_float_big(a);
        fa.sqrt();
        self.get_encoding_big(&fa)
    }

    /// Port of `opInt2Float(long, int)`: convert the signed `sizein`-byte integer `a`.
    pub fn op_int2float(&self, a: i64, sizein: i32) -> i64 {
        let ival = zzz_sign_extend(a, 8 * sizein - 1);
        self.get_encoding(ival as f64) // Convert integer to float
    }

    /// Port of `opInt2Float(BigInteger, int, boolean)`: convert the `sizein`-byte integer `a`,
    /// interpreted as signed or unsigned.
    pub fn op_int2float_big(&self, a: &BigInt, sizein: i32, signed: bool) -> BigInt {
        let a = if signed {
            convert_to_signed_value(a.clone(), sizein)
        }
        else {
            convert_to_unsigned_value(a.clone(), sizein)
        };
        self.get_encoding_big(&self.get_big_float_big_int(&a))
    }

    /// Port of `opFloat2Float(long, FloatFormat)`: convert between precisions via the host double.
    pub fn op_float2float(&self, a: i64, outformat: &FloatFormat) -> i64 {
        outformat.get_encoding(self.decode_host_float(a))
    }

    /// Port of `opFloat2Float(BigInteger, FloatFormat)`.
    pub fn op_float2float_big(&self, a: &BigInt, outformat: &FloatFormat) -> BigInt {
        outformat.get_encoding_big(&self.decode_big_float_big(a))
    }

    /// Port of `opTrunc(long, int)`: convert to a `sizeout`-byte integer, truncating toward zero
    /// (saturating, NaN to 0, as a Java `(long)` cast does).
    pub fn op_trunc(&self, a: i64, sizeout: i32) -> i64 {
        let val = self.decode_host_float(a);
        let res = val as i64; // Convert to integer
        res & calc_mask(sizeout) // Truncate to proper size
    }

    /// Port of `opTrunc(BigInteger, int)`. NaN converts to 0 and infinities saturate to the
    /// largest/smallest signed integer of *this format's* size, as in Java.
    pub fn op_trunc_big(&self, a: &BigInt, _sizeout: i32) -> BigInt {
        let fa = self.decode_big_float_big(a);
        if fa.is_nan() {
            return BigInt::zero(); // consistent with Java Double->Long behavior
        }
        if fa.is_infinite() {
            if fa.sign > 0 {
                // max positive int
                return shr(&(shl(&BigInt::one(), 8 * self.size) - BigInt::one()), 1);
            }
            // max negative int
            return -shl(&BigInt::one(), 8 * self.size - 1);
        }
        fa.to_big_integer()
    }

    /// Port of `opCeil(long)`.
    pub fn op_ceil(&self, a: i64) -> i64 {
        self.get_encoding(self.decode_host_float(a).ceil())
    }

    /// Port of `opCeil(BigInteger)`.
    pub fn op_ceil_big(&self, a: &BigInt) -> BigInt {
        let mut fa = self.decode_big_float_big(a);
        fa.ceil();
        self.get_encoding_big(&fa)
    }

    /// Port of `opFloor(long)`.
    pub fn op_floor(&self, a: i64) -> i64 {
        self.get_encoding(self.decode_host_float(a).floor())
    }

    /// Port of `opFloor(BigInteger)`.
    pub fn op_floor_big(&self, a: &BigInt) -> BigInt {
        let mut fa = self.decode_big_float_big(a);
        fa.floor();
        self.get_encoding_big(&fa)
    }

    /// Port of `opRound(long)`: `floor(a + 0.5)`.
    pub fn op_round(&self, a: i64) -> i64 {
        self.get_encoding((self.decode_host_float(a) + 0.5).floor())
    }

    /// Port of `opRound(BigInteger)`.
    pub fn op_round_big(&self, a: &BigInt) -> BigInt {
        let mut fa = self.decode_big_float_big(a);
        fa.round();
        self.get_encoding_big(&fa)
    }

    /// Port of `FloatFormat.getBigFloat(BigInteger)`: the integer `value` in this format. The 4-
    /// and 8-byte formats round through the host `f32`/`f64`; the others truncate excess mantissa
    /// bits and overflow to infinity.
    pub fn get_big_float_big_int(&self, value: &BigInt) -> BigFloat {
        if self.size == 8 {
            return self.get_big_float_f64(big_int_to_f64(value));
        }
        if self.size == 4 {
            return self.get_big_float_f32(big_int_to_f32(value));
        }

        let mut unscaled = value.clone();
        let mut sign = 1;
        if unscaled.is_negative() {
            sign = -1;
            unscaled = -unscaled;
        }

        let mut scale = self.effective_frac_size - 1;
        let ulen = bit_length(&unscaled);
        if ulen > self.effective_frac_size {
            let shift = self.effective_frac_size - ulen; // may produce +/- shift
            unscaled = shl(&unscaled, shift);
            scale = self.effective_frac_size - shift - 1;
            if scale > self.bias {
                return BigFloat::infinity(self.effective_frac_size, self.exp_size, sign);
            }
        }

        BigFloat::new(self.effective_frac_size, self.exp_size, FloatKind::Finite, sign, unscaled, scale)
    }

    /// Port of `FloatFormat.getBigFloat(String)`: parse a decimal string as `new BigDecimal(String)`
    /// does, additionally accepting (case-insensitively) `NaN`, `Infinity`, `+Infinity` and
    /// `-Infinity`.
    ///
    /// # Errors
    /// Where Java throws `NumberFormatException`.
    pub fn get_big_float_str(&self, string: &str) -> Result<BigFloat, ParseBigDecimalError> {
        if string.eq_ignore_ascii_case(big_float::NAN) {
            return Ok(BigFloat::quiet_nan(self.effective_frac_size, self.exp_size, 1));
        }
        if string.eq_ignore_ascii_case(big_float::INFINITY)
            || string.eq_ignore_ascii_case(big_float::POSITIVE_INFINITY)
        {
            return Ok(BigFloat::infinity(self.effective_frac_size, self.exp_size, 1));
        }
        if string.eq_ignore_ascii_case(big_float::NEGATIVE_INFINITY) {
            return Ok(BigFloat::infinity(self.effective_frac_size, self.exp_size, -1));
        }
        let bd: BigDecimal = string.parse()?;
        Ok(self.get_big_float_big_decimal(&bd))
    }

    /// Port of `FloatFormat.getBigFloat(BigDecimal)`.
    pub fn get_big_float_big_decimal(&self, value: &BigDecimal) -> BigFloat {
        if self.size == 8 {
            return self.get_big_float_f64(value.double_value());
        }
        if self.size == 4 {
            return self.get_big_float_f32(value.float_value());
        }

        // Java BigDecimal.equals: ZERO with scale 0 only
        if *value == BigDecimal::zero() {
            return BigFloat::positive_zero(self.effective_frac_size, self.exp_size);
        }

        let mut bf;
        let mut scale10 = value.scale();
        if scale10 < 0 {
            scale10 = -scale10;
            let scalar = num_traits::pow(BigInt::from(10), scale10 as usize);
            if scale10 as f64 / 0.3 > self.effective_frac_size as f64 {
                // log10(2) = ~0.3; will be whole integer
                let int_val = scalar * value.unscaled_value();
                bf = self.get_big_float_big_int(&int_val);
            }
            else {
                // may have fractional value
                let scalar_bf = self.get_big_float_big_int(&scalar);
                bf = self.get_big_float_big_int(value.unscaled_value());
                bf.mul(&scalar_bf);
            }
        }
        else if scale10 as f64 / 0.3 >= self.bias as f64 {
            // divide down in two passes to avoid divide by infinity for edge case
            let s1 = scale10 / 2;
            let bs1 = num_traits::pow(BigInt::from(10), s1 as usize);
            let bs2 = num_traits::pow(BigInt::from(10), (scale10 - s1) as usize);
            let bf2 = self.get_big_float_big_int(&bs2);
            if bf2.is_infinite() {
                // bf2 >= bf1
                return BigFloat::zero(self.effective_frac_size, self.exp_size, value.signum());
            }
            let bf1 = self.get_big_float_big_int(&bs1);
            bf = self.get_big_float_big_int(value.unscaled_value());
            bf.div(&bf1);
            bf.div(&bf2);
        }
        else {
            let scalar = num_traits::pow(BigInt::from(10), scale10 as usize);
            let scalar_bf = self.get_big_float_big_int(&scalar);
            bf = self.get_big_float_big_int(value.unscaled_value());
            bf.div(&scalar_bf);
        }
        bf
    }
}

#[cfg(test)]
mod tests {
    //! Ports of `FloatFormatTest`.

    use super::*;
    use crate::pcode::floatformat::float_format_factory::get_float_format;

    fn ff(size: i32) -> FloatFormat {
        FloatFormat::new(size).unwrap()
    }

    fn big(v: i64) -> BigInt {
        BigInt::from(v)
    }

    fn bd(s: &str) -> BigDecimal {
        s.parse().unwrap()
    }

    /// `BigDecimal.valueOf(double)`, i.e. `new BigDecimal(Double.toString(d))`. Rust's `{:e}` gives
    /// the same shortest digits Java's `Double.toString` does; Java always shows one fraction digit.
    fn bd_value_of(d: f64) -> BigDecimal {
        let s = format!("{:e}", d);
        let (mantissa, exp) = s.split_once('e').unwrap();
        let mantissa = if mantissa.contains('.') { mantissa.to_string() } else { format!("{}.0", mantissa) };
        bd(&format!("{}e{}", mantissa, exp))
    }

    fn encoding_f32(f: f32) -> i64 {
        f.to_bits() as i32 as i64
    }

    #[test]
    fn unsupported_sizes() {
        for size in [0, 1, 3, 5, 6, 7, 9, 12, 64] {
            assert!(FloatFormat::new(size).is_err(), "size {}", size);
        }
        for size in [2, 4, 8, 10, 16, 32] {
            assert_eq!(ff(size).get_size(), size);
        }
    }

    #[test]
    fn get_encoding_minval() {
        let ff = ff(4);
        let min_float = f32::from_bits(1);
        let d0 = min_float as f64;

        let min_float_big4 = FloatFormat::to_big_float_f32(min_float);
        assert!(!min_float_big4.is_nan() && !min_float_big4.is_normal());
        // doubles have plenty of room at the bottom, so the minimum float is normal
        let min_float_big8 = FloatFormat::to_big_float_f64(d0);
        assert!(min_float_big8.is_normal());

        let true_encoding = min_float.to_bits() as i64;
        assert_eq!(true_encoding, ff.get_encoding(d0));
        assert_eq!(ff.get_min_big_float(), &min_float_big4);
        assert_ne!(ff.get_min_big_float(), &min_float_big8);
        assert_eq!(big(true_encoding), ff.get_encoding_big(&min_float_big4));
        assert_eq!(big(true_encoding), ff.get_encoding_big(&min_float_big8));
    }

    #[test]
    fn get_encoding_maxval() {
        let ff = ff(4);
        let max_float = f32::MAX;
        let d0 = max_float as f64;
        let max_float_big4 = FloatFormat::to_big_float_f32(max_float);
        assert!(max_float_big4.is_normal());
        let max_float_big8 = FloatFormat::to_big_float_f64(d0);
        assert!(max_float_big8.is_normal());

        let true_encoding = max_float.to_bits() as i64;
        assert_eq!(true_encoding, ff.get_encoding(d0));
        assert_eq!(ff.get_max_big_float(), &max_float_big4);
        assert_ne!(ff.get_max_big_float(), &max_float_big8);
        assert_eq!(big(true_encoding), ff.get_encoding_big(&max_float_big4));
        assert_eq!(big(true_encoding), ff.get_encoding_big(&max_float_big8));
    }

    #[test]
    fn get_encoding_round_to_nearest_even() {
        let ff = ff(4);
        let bits = [
            0x4010000000000000u64, // zeros in low 29 bits, round down
            0x4010000010000000,    // midpoint, even integer part, round down
            0x4010000010000001,    // just above the midpoint, round up
            0x4010000020000000,    // zeros in low 29 bits
            0x4010000030000000,    // midpoint, odd integer part, round up
            0x4010000030000001,    // just above the midpoint, round up
        ];
        let e: Vec<i64> = bits.iter().map(|&b| ff.get_encoding(f64::from_bits(b))).collect();
        for (i, &b) in bits.iter().enumerate() {
            assert_eq!((f64::from_bits(b) as f32).to_bits() as i64, e[i], "case {}", i);
        }
        assert_eq!(e[0], e[1]);
        assert_ne!(e[1], e[2]);
        assert_ne!(e[3], e[4]);
        assert_eq!(e[4], e[5]);
    }

    fn make_double_float(neg: bool, exp: i64, float_frac: i64) -> i64 {
        let mut l = if neg { 1i64 << 63 } else { 0 };
        l |= (1023 + exp) << 52;
        l |= float_frac << (52 - 23);
        l
    }

    fn assert_double_midpoint_round(neg: bool, exp: i64, float_frac: i64) {
        let insignif = 1i64 << (52 - 23 - 1);
        let lmid = make_double_float(neg, exp, float_frac) + insignif;
        let dmid = f64::from_bits(lmid as u64);
        let actual = ff(4).get_encoding(dmid) as i32;
        let expected = (dmid as f32).to_bits() as i32;
        assert_eq!(expected, actual, "expected {:08x} != actual {:08x}", expected, actual);
    }

    fn assert_big_midpoint_round(neg: bool, exp: i64, float_frac: i64) {
        let insignif = 1i64 << (52 - 23 - 1);
        let lmid = make_double_float(neg, exp, float_frac) + insignif;
        let dmid = f64::from_bits(lmid as u64);
        let bdmid = FloatFormat::to_big_float_f64(dmid);
        let actual = ff(4).get_encoding_big(&bdmid).to_i64().unwrap() as i32;
        let expected = (dmid as f32).to_bits() as i32;
        assert_eq!(expected, actual, "expected {:08x} != actual {:08x}", expected, actual);
    }

    #[test]
    fn double_round_at_midpoint() {
        for (neg, exp) in [(false, 1), (false, 120), (false, -120), (true, 1)] {
            for frac in [1, 2, (1 << 23) - 1, (1 << 23) - 2] {
                assert_double_midpoint_round(neg, exp, frac);
            }
        }
        // overflow
        assert_double_midpoint_round(false, 127, (1 << 23) - 1);
    }

    #[test]
    fn big_round_at_midpoint() {
        for (neg, exp) in [(false, 1), (false, 120), (false, -120), (true, 1)] {
            for frac in [1, 2, (1 << 23) - 1, (1 << 23) - 2] {
                assert_big_midpoint_round(neg, exp, frac);
            }
        }
    }

    #[test]
    fn get_host_float_big_integer() {
        // 32-bit encoding
        let ff4 = ff(4);
        for f in [4.5f32, 3.75, -4.5] {
            let b = ff4.get_big_float_f32(f);
            let encoding = ff4.get_encoding_big(&b);
            assert_eq!(big(f.to_bits() as i64), encoding);
            assert_eq!(b, ff4.decode_big_float_big(&encoding));
        }
        for f in [f32::from_bits(1), f32::MAX, -f32::from_bits(1), -f32::MAX] {
            let encoding = ff4.get_encoding_big(&ff4.get_big_float_f32(f));
            assert_eq!(f.to_bits() as i64, encoding.to_i64().unwrap());
            assert_eq!(f, ff4.decode_host_float(f.to_bits() as i64) as f32);
        }
        let e = ff4.get_encoding_big(&ff4.get_big_float_f32(f32::INFINITY));
        assert_eq!(big(f32::INFINITY.to_bits() as i64), e);
        assert_eq!(ff4.get_big_infinity(false), ff4.decode_big_float_big(&e));
        let e = ff4.get_encoding_big(&ff4.get_big_float_f32(f32::NEG_INFINITY));
        assert_eq!(big(f32::NEG_INFINITY.to_bits() as i64), e);
        assert_eq!(ff4.get_big_infinity(true), ff4.decode_big_float_big(&e));
        let e = ff4.get_encoding_big(&ff4.get_big_float_f32(f32::NAN));
        assert_eq!(big(0x7fc00000), e);
        assert_eq!(ff4.get_big_nan(false), ff4.decode_big_float_big(&e));

        // 64-bit encoding
        let ff8 = ff(8);
        for d in [4.5f64, 3.75, -4.5] {
            let b = ff8.get_big_float_f64(d);
            let encoding = ff8.get_encoding_big(&b);
            assert_eq!(d.to_bits() as i64, encoding.to_u64().unwrap() as i64);
            assert_eq!(b, ff8.decode_big_float_big(&encoding));
        }
        let e = ff8.get_big_infinity_encoding(false);
        assert_eq!(big(f64::INFINITY.to_bits() as i64), e);
        assert_eq!(ff8.get_big_infinity(false), ff8.decode_big_float_big(&e));
        let e = ff8.get_big_infinity_encoding(true);
        assert_eq!(BigInt::from(f64::NEG_INFINITY.to_bits()), e);
        assert_eq!(ff8.get_big_infinity(true), ff8.decode_big_float_big(&e));
        let e = ff8.get_big_nan_encoding(false);
        assert_eq!(BigInt::from(f64::NAN.to_bits()), e);
        assert_eq!(ff8.get_big_nan(false), ff8.decode_big_float_big(&e));

        // 80-bit and 128-bit encodings: round trips
        let ff10 = ff(10);
        let ff16 = ff(16);
        for f in [&ff10, &ff16] {
            for d in [1.0, 4.5, 3.75, -4.5] {
                let b = f.get_big_float_f64(d);
                assert_eq!(b, f.decode_big_float_big(&f.get_encoding_big(&b)), "size {} value {}", f.get_size(), d);
            }
            for b in [f.get_big_infinity(false), f.get_big_infinity(true), f.get_big_nan(false)] {
                assert_eq!(b, f.decode_big_float_big(&f.get_encoding_big(&b)));
            }
        }
    }

    #[test]
    fn x87_extended_encodings_have_explicit_integer_bit() {
        let ff10 = ff(10);
        // 1.0 = sign 0, exponent 0x3fff, mantissa 0x8000000000000000 (explicit j-bit)
        let one = BigInt::from(0x3fffu32) << 64u32 | BigInt::from(0x8000000000000000u64);
        assert_eq!(ff10.get_encoding_big(&ff10.get_big_float_f64(1.0)), one);
        // -2.5 = sign 1, exponent 0x4000, mantissa 0xa000000000000000
        let m25 = (BigInt::from(0xc000u32) << 64u32) | BigInt::from(0xa000000000000000u64);
        assert_eq!(ff10.get_encoding_big(&ff10.get_big_float_f64(-2.5)), m25);
        assert_eq!(ff10.decode_big_float_big(&m25), ff10.get_big_float_f64(-2.5));
        // infinity: exponent all ones, fraction 0 (the j-bit is part of the 64-bit fraction field)
        assert_eq!(ff10.get_big_infinity_encoding(false), BigInt::from(0x7fffu32) << 64u32);
        // quiet NaN: top fraction bit
        assert_eq!(ff10.get_big_nan_encoding(false), (BigInt::from(0x7fffu32) << 64u32) | (BigInt::one() << 63u32));
        // 1/3 rounded to a 64-bit significand, then back: exact round trip of the rounded value
        let mut third = ff10.get_big_float_f64(1.0);
        third.div(&ff10.get_big_float_f64(3.0));
        let enc = ff10.get_encoding_big(&third);
        assert_eq!(enc, (BigInt::from(0x3ffdu32) << 64u32) | BigInt::from(0xaaaaaaaaaaaaaaabu64));
        assert_eq!(ff10.decode_big_float_big(&enc), third);
        assert_eq!(ff10.to_decimal_string(&third), "0.333333333333333333");
    }

    #[test]
    fn quad_and_half_encodings() {
        let ff16 = ff(16);
        // binary128 1.0 = 0x3fff << 112
        assert_eq!(ff16.get_encoding_big(&ff16.get_big_float_f64(1.0)), BigInt::from(0x3fffu32) << 112u32);
        let ff2 = ff(2);
        // binary16: 1.0 = 0x3c00, -2.0 = 0xc000, 65504 = 0x7bff, smallest subnormal 0x0001
        assert_eq!(ff2.get_encoding(1.0), 0x3c00);
        assert_eq!(ff2.get_encoding(-2.0), 0xc000);
        assert_eq!(ff2.get_encoding(65504.0), 0x7bff);
        assert_eq!(ff2.get_encoding(65520.0), 0x7c00); // rounds to +inf
        assert_eq!(ff2.decode_host_float(0x0001), 2f64.powi(-24));
        assert_eq!(ff2.decode_host_float(0x3555), 0.333251953125);
        assert_eq!(ff2.get_encoding_big(&ff2.decode_big_float_big(&big(0x3555))), big(0x3555));
        let ff32 = ff(32);
        let two = ff32.get_big_float_big_int(&big(2));
        let e = ff32.get_encoding_big(&two);
        assert_eq!(e, BigInt::from(262144u32) << 236u32);
        assert_eq!(ff32.to_decimal_string(&ff32.decode_big_float_big(&e)), "2.0");
    }

    #[test]
    fn get_host_float() {
        let ff4 = ff(4);
        for f in [4.5f32, 3.75, -4.5, 8.908155E-39, f32::INFINITY, f32::NEG_INFINITY] {
            let encoding = ff4.get_encoding(f as f64);
            assert_eq!(encoding_f32(f) & 0xffffffff, encoding);
            assert_eq!(f, ff4.decode_host_float(encoding) as f32);
        }
        assert_eq!(f32::from_bits(1), ff4.decode_host_float(1) as f32);
        assert_eq!(-f32::from_bits(1), ff4.decode_host_float(0x80000001) as f32);
        assert_eq!(0x7fc00000, ff4.get_encoding(f64::NAN));
        assert!(ff4.decode_host_float(0x7fc00000).is_nan());

        let ff8 = ff(8);
        for d in [4.5f64, 3.75, -4.5, f64::INFINITY, f64::NEG_INFINITY] {
            let encoding = ff8.get_encoding(d);
            assert_eq!(d.to_bits() as i64, encoding);
            assert_eq!(d, ff8.decode_host_float(encoding));
        }
        assert_eq!(f64::NAN.to_bits() as i64, ff8.get_encoding(f64::NAN));
    }

    #[test]
    fn big_float_float_format_random() {
        use crate::pcode::floatformat::big_float::tests_support::JavaRandom;
        let mut rand = JavaRandom::new(1);
        let float_format = get_float_format(4).unwrap();
        for _ in 0..1000 {
            let f = rand.next_float();
            let encoding0 = big(f.to_bits() as i32 as i64);
            let bf1 = float_format.decode_big_float_big(&encoding0);
            let bf2 = FloatFormat::to_big_float_f32(f);
            assert_eq!(bf1.to_string(), bf2.to_string());
            assert_eq!(encoding0, float_format.get_encoding_big(&bf1));
        }
    }

    #[test]
    fn big_float_double_format_random() {
        use crate::pcode::floatformat::big_float::tests_support::JavaRandom;
        let mut rand = JavaRandom::new(1);
        let float_format = get_float_format(8).unwrap();
        for _ in 0..1000 {
            let f = rand.next_float() as f64;
            let encoding0 = big(f.to_bits() as i64);
            let bf1 = float_format.decode_big_float_big(&encoding0);
            let bf2 = FloatFormat::to_big_float_f64(f);
            assert_eq!(bf1.to_string(), bf2.to_string());
            assert_eq!(encoding0, float_format.get_encoding_big(&bf1));
        }
    }

    #[test]
    fn op_equal_and_not_equal() {
        let ff = ff(8);
        let e = |d: f64| ff.get_encoding(d);
        assert_eq!(1, ff.op_equal(e(1.234), e(1.234)));
        assert_eq!(1, ff.op_equal(e(-1.234), e(-1.234)));
        assert_eq!(0, ff.op_equal(e(-1.234), e(1.234)));
        assert_eq!(1, ff.op_equal(e(f64::INFINITY), e(f64::INFINITY)));
        assert_eq!(0, ff.op_equal(e(f64::INFINITY), e(f64::NEG_INFINITY)));
        assert_eq!(1, ff.op_equal(e(f64::NEG_INFINITY), e(f64::NEG_INFINITY)));
        assert_eq!(0, ff.op_equal(e(f64::INFINITY), e(f64::NAN)));
        assert_eq!(1, ff.op_equal(e(0.0), e(-0.0)));
        assert_eq!(0, ff.op_not_equal(e(1.234), e(1.234)));
        assert_eq!(1, ff.op_not_equal(e(-1.234), e(1.234)));
        assert_eq!(1, ff.op_not_equal(e(f64::INFINITY), e(f64::NAN)));

        let a = ff.get_encoding_big(&ff.get_big_float_f64(1.234));
        let b = ff.get_encoding_big(&ff.get_big_float_f64(-1.234));
        let inf = ff.get_big_infinity_encoding(false);
        let ninf = ff.get_big_infinity_encoding(true);
        let nan = ff.get_big_nan_encoding(false);
        assert_eq!(big(1), ff.op_equal_big(&a, &a));
        assert_eq!(big(1), ff.op_equal_big(&b, &b));
        assert_eq!(big(0), ff.op_equal_big(&b, &a));
        assert_eq!(big(1), ff.op_equal_big(&inf, &inf));
        assert_eq!(big(0), ff.op_equal_big(&inf, &ninf));
        assert_eq!(big(1), ff.op_equal_big(&ninf, &ninf));
        assert_eq!(big(0), ff.op_equal_big(&inf, &nan));
        assert_eq!(big(0), ff.op_equal_big(&nan, &nan));
        // Java quirk kept: BigFloat.equals distinguishes -0 from +0
        assert_eq!(big(0), ff.op_equal_big(&ff.get_big_zero_encoding(false), &ff.get_big_zero_encoding(true)));
        assert_eq!(big(0), ff.op_not_equal_big(&a, &a));
        assert_eq!(big(1), ff.op_not_equal_big(&b, &a));
        assert_eq!(big(1), ff.op_not_equal_big(&inf, &ninf));
        assert_eq!(big(0), ff.op_not_equal_big(&ninf, &ninf));
        assert_eq!(big(1), ff.op_not_equal_big(&inf, &nan));
    }

    #[test]
    fn op_less_and_less_equal() {
        let ff = ff(8);
        let e = |d: f64| ff.get_encoding(d);
        let cases = [
            (1.234, 1.234, 0, 1),
            (-1.234, -1.234, 0, 1),
            (1.234, -1.234, 0, 0),
            (0.0, -1.234, 0, 0),
            (0.0, 1.234, 1, 1),
            (-1.234, 1.234, 1, 1),
            (f64::INFINITY, 1.234, 0, 0),
            (f64::NEG_INFINITY, 1.234, 1, 1),
            (1.234, f64::INFINITY, 1, 1),
            (1.234, f64::NEG_INFINITY, 0, 0),
            (f64::INFINITY, f64::INFINITY, 0, 1),
            (f64::NEG_INFINITY, f64::INFINITY, 1, 1),
        ];
        for (a, b, less, less_eq) in cases {
            assert_eq!(less, ff.op_less(e(a), e(b)), "{} < {}", a, b);
            assert_eq!(less_eq, ff.op_less_equal(e(a), e(b)), "{} <= {}", a, b);
            let ba = ff.get_encoding_big(&ff.get_big_float_f64(a));
            let bb = ff.get_encoding_big(&ff.get_big_float_f64(b));
            assert_eq!(big(less), ff.op_less_big(&ba, &bb), "big {} < {}", a, b);
            assert_eq!(big(less_eq), ff.op_less_equal_big(&ba, &bb), "big {} <= {}", a, b);
        }
        // NaN compares false on the host path; on the BigFloat path NaN sorts greatest
        assert_eq!(0, ff.op_less(e(1.0), e(f64::NAN)));
        assert_eq!(big(1), ff.op_less_big(&big(e(1.0)), &ff.get_big_nan_encoding(false)));
    }

    #[test]
    fn op_nan() {
        let ff = ff(8);
        assert_eq!(1, ff.op_nan(ff.get_encoding(f64::NAN)));
        assert_eq!(0, ff.op_nan(ff.get_encoding(0.0)));
        assert_eq!(0, ff.op_nan(ff.get_encoding(1.234)));
        assert_eq!(big(1), ff.op_nan_big(&ff.get_big_nan_encoding(false)));
        assert_eq!(big(0), ff.op_nan_big(&ff.get_big_zero_encoding(false)));
        assert_eq!(big(0), ff.op_nan_big(&ff.get_encoding_big(&ff.get_big_float_f64(1.234))));
    }

    fn assert_host(ff: &FloatFormat, expect: f64, enc: i64) {
        let got = ff.decode_host_float(enc);
        if expect.is_nan() {
            assert!(got.is_nan(), "expected NaN, got {}", got);
        }
        else {
            assert_eq!(expect, got);
        }
    }

    #[test]
    fn op_add_sub_long() {
        let ff = ff(8);
        let e = |d: f64| ff.get_encoding(d);
        assert_host(&ff, 2.357, ff.op_add(e(1.234), e(1.123)));
        assert_host(&ff, 0.0, ff.op_add(e(-1.123), e(1.123)));
        assert_host(&ff, f64::INFINITY, ff.op_add(e(f64::INFINITY), e(1.123)));
        assert_host(&ff, f64::NEG_INFINITY, ff.op_add(e(f64::NEG_INFINITY), e(1.123)));
        assert_host(&ff, f64::NEG_INFINITY, ff.op_add(e(f64::NEG_INFINITY), e(f64::NEG_INFINITY)));
        assert_host(&ff, f64::NAN, ff.op_add(e(f64::NEG_INFINITY), e(f64::INFINITY)));
        assert_host(&ff, f64::NAN, ff.op_add(e(f64::NAN), e(1.123)));

        assert_host(&ff, 0.25, ff.op_sub(e(1.5), e(1.25)));
        assert_host(&ff, -2.5, ff.op_sub(e(-1.25), e(1.25)));
        assert_host(&ff, f64::INFINITY, ff.op_sub(e(f64::INFINITY), e(1.25)));
        assert_host(&ff, f64::NEG_INFINITY, ff.op_sub(e(f64::NEG_INFINITY), e(1.25)));
        assert_host(&ff, f64::NAN, ff.op_sub(e(f64::NEG_INFINITY), e(f64::NEG_INFINITY)));
        assert_host(&ff, f64::NEG_INFINITY, ff.op_sub(e(f64::NEG_INFINITY), e(f64::INFINITY)));
        assert_host(&ff, f64::NAN, ff.op_sub(e(f64::NAN), e(1.25)));
    }

    #[test]
    fn op_add_sub_big() {
        let ff = ff(8);
        let e = |d: f64| ff.get_encoding_big(&ff.get_big_float_f64(d));
        let dec = |x: BigInt| ff.decode_big_float_big(&x);
        let inf = ff.get_big_infinity_encoding(false);
        let ninf = ff.get_big_infinity_encoding(true);
        let nan = ff.get_big_nan_encoding(false);
        assert_eq!(ff.get_big_float_f64(2.357), dec(ff.op_add_big(&e(1.234), &e(1.123))));
        assert_eq!(ff.get_big_zero(false), dec(ff.op_add_big(&e(-1.123), &e(1.123))));
        assert_eq!(ff.get_big_infinity(false), dec(ff.op_add_big(&inf, &e(1.123))));
        assert_eq!(ff.get_big_infinity(true), dec(ff.op_add_big(&ninf, &e(1.123))));
        assert_eq!(ff.get_big_infinity(true), dec(ff.op_add_big(&ninf, &ninf)));
        assert_eq!(ff.get_big_nan(false), dec(ff.op_add_big(&ninf, &inf)));
        assert_eq!(ff.get_big_nan(false), dec(ff.op_add_big(&nan, &e(1.123))));

        assert_eq!(ff.get_big_float_f64(0.25), dec(ff.op_sub_big(&e(1.5), &e(1.25))));
        assert_eq!(ff.get_big_float_f64(-2.5), dec(ff.op_sub_big(&e(-1.25), &e(1.25))));
        assert_eq!(ff.get_big_infinity(false), dec(ff.op_sub_big(&inf, &e(1.25))));
        assert_eq!(ff.get_big_infinity(true), dec(ff.op_sub_big(&ninf, &e(1.25))));
        assert_eq!(ff.get_big_nan(false), dec(ff.op_sub_big(&ninf, &ninf)));
        assert_eq!(ff.get_big_infinity(true), dec(ff.op_sub_big(&ninf, &inf)));
        assert_eq!(ff.get_big_nan(false), dec(ff.op_sub_big(&nan, &e(1.25))));
    }

    #[test]
    fn op_div_mult() {
        let ff = ff(8);
        let e = |d: f64| ff.get_encoding(d);
        assert_host(&ff, 2.5, ff.op_div(e(3.75), e(1.5)));
        assert_host(&ff, f64::INFINITY, ff.op_div(e(3.75), e(0.0)));
        assert_host(&ff, f64::NEG_INFINITY, ff.op_div(e(-3.75), e(0.0)));
        assert_host(&ff, f64::NAN, ff.op_div(e(-3.75), e(f64::NAN)));
        assert_host(&ff, 3.75, ff.op_mult(e(2.5), e(1.5)));
        assert_host(&ff, f64::INFINITY, ff.op_mult(e(2.5), e(f64::INFINITY)));
        assert_host(&ff, f64::NEG_INFINITY, ff.op_mult(e(f64::NEG_INFINITY), e(f64::INFINITY)));
        assert_host(&ff, f64::NAN, ff.op_mult(e(f64::NEG_INFINITY), e(f64::NAN)));

        let be = |d: f64| ff.get_encoding_big(&ff.get_big_float_f64(d));
        let dec = |x: BigInt| ff.decode_big_float_big(&x);
        let zero = ff.get_big_zero_encoding(false);
        let inf = ff.get_big_infinity_encoding(false);
        let ninf = ff.get_big_infinity_encoding(true);
        let nan = ff.get_big_nan_encoding(false);
        assert_eq!(ff.get_big_float_f64(2.5), dec(ff.op_div_big(&be(3.75), &be(1.5))));
        assert_eq!(ff.get_big_infinity(false), dec(ff.op_div_big(&be(3.75), &zero)));
        assert_eq!(ff.get_big_infinity(true), dec(ff.op_div_big(&be(-3.75), &zero)));
        assert_eq!(ff.get_big_nan(false), dec(ff.op_div_big(&be(-3.75), &nan)));
        assert_eq!(ff.get_big_float_f64(3.75), dec(ff.op_mult_big(&be(2.5), &be(1.5))));
        assert_eq!(ff.get_big_infinity(false), dec(ff.op_mult_big(&be(2.5), &inf)));
        assert_eq!(ff.get_big_infinity(true), dec(ff.op_mult_big(&ninf, &inf)));
        assert_eq!(ff.get_big_nan(false), dec(ff.op_mult_big(&ninf, &nan)));
    }

    #[test]
    fn op_neg_abs() {
        let ff = ff(8);
        let e = |d: f64| ff.get_encoding(d);
        for (v, neg, abs) in [
            (2.5, -2.5, 2.5),
            (-2.5, 2.5, 2.5),
            (f64::INFINITY, f64::NEG_INFINITY, f64::INFINITY),
            (f64::NEG_INFINITY, f64::INFINITY, f64::INFINITY),
            (f64::NAN, f64::NAN, f64::NAN),
        ] {
            assert_host(&ff, neg, ff.op_neg(e(v)));
            assert_host(&ff, abs, ff.op_abs(e(v)));
            let be = if v.is_nan() { ff.get_big_nan_encoding(false) } else { ff.get_encoding_big(&ff.get_big_float_f64(v)) };
            let bneg = ff.decode_big_float_big(&ff.op_neg_big(&be));
            let babs = ff.decode_big_float_big(&ff.op_abs_big(&be));
            assert_eq!(ff.get_big_float_f64(neg), bneg);
            assert_eq!(ff.get_big_float_f64(abs), babs);
        }
    }

    #[test]
    fn op_sqrt() {
        let ff = ff(8);
        let r = ff.op_sqrt(ff.get_encoding(2.0));
        assert_eq!(1.4142135623730951, ff.decode_host_float(r));
        let enc = ff.op_sqrt_big(&ff.get_encoding_big(&ff.get_big_float_f64(2.0)));
        let result = ff.decode_big_float_big(&enc);
        assert_eq!("1.414213562373095", ff.round(&result).unwrap().to_string());
        assert_eq!(enc, BigInt::from(2f64.sqrt().to_bits()));
    }

    #[test]
    fn op_int2float() {
        let ff = ff(4);
        for (v, expect) in [(2i64, 2.0f64), (-2, -2.0), (0, 0.0)] {
            let result = ff.op_int2float(v, 4);
            assert_eq!(0, result & 0xffffffff00000000u64 as i64); // only 4 bytes are used
            assert_eq!(expect, ff.decode_host_float(result));
        }
        // sign extension from a 1-byte input: 0xfe is -2
        assert_eq!(ff.get_encoding(-2.0), ff.op_int2float(0xfe, 1));

        let limit = BigInt::one() << 32u32;
        let r = ff.op_int2float_big(&big(2), 4, true);
        assert!(r < limit);
        assert_eq!(ff.get_big_float_f64(2.0), ff.decode_big_float_big(&r));
        let r = ff.op_int2float_big(&big(-2), 4, true);
        assert!(r < limit);
        assert_eq!(ff.get_big_float_f64(-2.0), ff.decode_big_float_big(&r));
        let r = ff.op_int2float_big(&big(0), 4, true);
        assert_eq!(ff.get_big_zero(false), ff.decode_big_float_big(&r));
        // unsigned interpretation of 0xfffffffe (4 bytes) vs signed
        assert_eq!(ff.decode_big_float_big(&ff.op_int2float_big(&big(0xfffffffe), 4, true)), ff.get_big_float_f64(-2.0));
        assert_eq!(
            ff.decode_big_float_big(&ff.op_int2float_big(&big(0xfffffffe), 4, false)),
            ff.get_big_float_f32(4294967294.0)
        );
    }

    #[test]
    fn big_float_to_double_and_float_encoding() {
        use crate::pcode::floatformat::big_float::tests_support::{test_double_list, test_float_list};
        let ff8 = ff(8);
        for (i, d) in test_double_list().into_iter().enumerate() {
            let e = d.to_bits() as i64;
            let be = ff8.get_encoding_big(&FloatFormat::to_big_float_f64(d));
            if d.is_nan() {
                assert!(ff8.decode_big_float_big(&be).is_nan(), "case #{}", i);
            }
            else {
                assert_eq!(e, be.to_u64().unwrap() as i64, "case #{}", i);
            }
        }
        let ff4 = ff(4);
        for (i, f) in test_float_list().into_iter().enumerate() {
            let bf = FloatFormat::to_big_float_f32(f);
            if f.is_nan() {
                assert!(bf.is_nan(), "case #{}", i);
            }
            else {
                assert_eq!(f.to_bits() as i64, ff4.get_encoding_big(&bf).to_i64().unwrap(), "case #{}", i);
            }
        }
    }

    #[test]
    fn op_float2float() {
        let ff8 = ff(8);
        let ff4 = ff(4);
        for v in [1.75f32, -1.75, f32::INFINITY, f32::NEG_INFINITY, f32::NAN] {
            let result = ff4.op_float2float(ff4.get_encoding(v as f64), &ff8);
            assert_host(&ff8, v as f64, result);
        }
        let dec8 = |x: BigInt| ff8.decode_big_float_big(&x);
        let a = ff4.get_encoding_big(&ff4.get_big_float_f64(1.75));
        assert_eq!(ff8.get_big_float_f64(1.75), dec8(ff4.op_float2float_big(&a, &ff8)));
        let a = ff4.get_encoding_big(&ff4.get_big_float_f64(-1.75));
        assert_eq!(ff8.get_big_float_f64(-1.75), dec8(ff4.op_float2float_big(&a, &ff8)));
        let a = ff4.get_encoding_big(&ff4.get_big_infinity(false));
        assert_eq!(ff8.get_big_infinity(false), dec8(ff4.op_float2float_big(&a, &ff8)));
        let a = ff4.get_encoding_big(&ff4.get_big_infinity(true));
        assert_eq!(ff8.get_big_infinity(true), dec8(ff4.op_float2float_big(&a, &ff8)));
        let a = ff4.get_encoding_big(&ff4.get_big_nan(false));
        assert_eq!(ff8.get_big_nan(false), dec8(ff4.op_float2float_big(&a, &ff8)));
        // narrowing rounds half-even: 1 + 2^-24 is a tie between 1.0 and 1 + 2^-23
        let d = 1.0 + 2f64.powi(-24);
        assert_eq!(0x3f800000, ff8.op_float2float(ff8.get_encoding(d), &ff4));
        let bd = ff8.get_encoding_big(&ff8.get_big_float_f64(d));
        assert_eq!(big(0x3f800000), ff8.op_float2float_big(&bd, &ff4));
    }

    #[test]
    fn op_trunc() {
        let ff = ff(8);
        let e = |d: f64| ff.get_encoding(d);
        assert_eq!(2, ff.op_trunc(e(2.5), 8));
        assert_eq!(-2, ff.op_trunc(e(-2.5), 8));
        assert_eq!(i64::MAX, ff.op_trunc(e(f64::INFINITY), 8));
        assert_eq!(i64::MIN, ff.op_trunc(e(f64::NEG_INFINITY), 8));
        assert_eq!(0, ff.op_trunc(e(f64::NAN), 8));
        assert_eq!(0xfe, ff.op_trunc(e(-2.5), 1));

        let be = |d: f64| ff.get_encoding_big(&ff.get_big_float_f64(d));
        assert_eq!(big(2), ff.op_trunc_big(&be(2.5), 8));
        assert_eq!(big(-2), ff.op_trunc_big(&be(-2.5), 8));
        assert_eq!(big(i64::MAX), ff.op_trunc_big(&ff.get_big_infinity_encoding(false), 8));
        assert_eq!(big(i64::MIN), ff.op_trunc_big(&ff.get_big_infinity_encoding(true), 8));
        assert_eq!(big(0), ff.op_trunc_big(&ff.get_big_nan_encoding(false), 8));
    }

    #[test]
    fn op_ceil_floor_round() {
        let ff = ff(8);
        let e = |d: f64| ff.get_encoding(d);
        let special = [f64::INFINITY, f64::NEG_INFINITY, f64::NAN];
        for (v, c) in [(2.5, 3.0), (-2.5, -2.0)] {
            assert_host(&ff, c, ff.op_ceil(e(v)));
        }
        for (v, f) in [(2.5, 2.0), (-2.0, -2.0), (-2.5, -3.0)] {
            assert_host(&ff, f, ff.op_floor(e(v)));
        }
        let rounds = [(2.5, 3.0), (2.25, 2.0), (2.75, 3.0), (-2.5, -2.0), (-2.25, -2.0), (-2.75, -3.0)];
        for (v, r) in rounds {
            assert_host(&ff, r, ff.op_round(e(v)));
        }
        for s in special {
            assert_host(&ff, s, ff.op_ceil(e(s)));
            assert_host(&ff, s, ff.op_floor(e(s)));
            assert_host(&ff, s, ff.op_round(e(s)));
        }

        let be = |d: f64| ff.get_encoding_big(&ff.get_big_float_f64(d));
        let dec = |x: BigInt| ff.decode_big_float_big(&x);
        assert_eq!(ff.get_big_float_f64(3.0), dec(ff.op_ceil_big(&be(2.5))));
        assert_eq!(ff.get_big_float_f64(-2.0), dec(ff.op_ceil_big(&be(-2.5))));
        assert_eq!(ff.get_big_float_f64(2.0), dec(ff.op_floor_big(&be(2.5))));
        assert_eq!(ff.get_big_float_f64(-2.0), dec(ff.op_floor_big(&be(-2.0))));
        assert_eq!(ff.get_big_float_f64(-3.0), dec(ff.op_floor_big(&be(-2.5))));
        for (v, r) in rounds {
            assert_eq!(ff.get_big_float_f64(r), dec(ff.op_round_big(&be(v))), "round {}", v);
        }
        for (enc, expect) in [
            (ff.get_big_infinity_encoding(false), ff.get_big_infinity(false)),
            (ff.get_big_infinity_encoding(true), ff.get_big_infinity(true)),
            (ff.get_big_nan_encoding(false), ff.get_big_nan(false)),
        ] {
            assert_eq!(expect, dec(ff.op_ceil_big(&enc)));
            assert_eq!(expect, dec(ff.op_floor_big(&enc)));
            assert_eq!(expect, dec(ff.op_round_big(&enc)));
        }
    }

    fn do_test_value_of_big_integer(bd_val: BigDecimal) {
        let ff = get_float_format(8).unwrap();
        let bd_val = bd_val.round(ff.get_display_context());
        let bi_val = bd_val.to_big_integer();
        let f = ff.get_big_float_big_int(&bi_val);
        let rounded = ff.round(&f).unwrap();
        assert_eq!(bi_val, rounded.to_big_integer());
        assert_eq!(bd_val, rounded);
    }

    #[test]
    fn value_of_big_integer() {
        let ff = get_float_format(8).unwrap();
        assert_ne!(ff.get_big_zero(true), ff.get_big_zero(false));
        assert_eq!("-0.0", ff.to_decimal_string(&ff.get_big_zero(true)));
        assert_eq!("0.0", ff.to_decimal_string(&ff.get_big_zero(false)));
        assert_eq!("1.0", ff.to_decimal_string(&ff.get_big_float_big_int(&big(1))));
        assert_eq!("2.0", ff.to_decimal_string(&ff.get_big_float_big_int(&big(2))));
        assert_eq!("-1.0", ff.to_decimal_string(&ff.get_big_float_big_int(&big(-1))));
        assert_eq!("-2.0", ff.to_decimal_string(&ff.get_big_float_big_int(&big(-2))));

        do_test_value_of_big_integer(bd_value_of(2.1234567890123456789e123));
        do_test_value_of_big_integer(bd_value_of(2.1234567890123456789e123).negate());

        let bf = ff.decode_big_float(f64::MAX.to_bits() as i64);
        let bf = ff.get_big_float_big_int(&bf.to_big_integer());
        assert_eq!("1.797693134862316E+308", ff.to_decimal_string(&bf));

        // step just beyond Double.MAX_VALUE - still decodes the same
        let max_bd = bd_value_of(f64::MAX);
        let v = BigDecimal::new(max_bd.unscaled_value() + 1, max_bd.scale()).to_big_integer();
        let f = ff.get_big_float_big_int(&v);
        assert_eq!("1.797693134862316E+308", ff.to_decimal_string_compact(&f, true));

        // step far beyond Double.MAX_VALUE
        let v = BigDecimal::new(BigInt::one(), -309).to_big_integer();
        let f = ff.get_big_float_big_int(&v);
        assert_eq!("+Infinity", ff.to_decimal_string_compact(&f, true));
    }

    fn do_test_value_of_big_decimal(v: BigDecimal) {
        let ff = get_float_format(8).unwrap();
        let mut expect = v.round(ff.get_display_context()).to_string();
        if !expect.contains('.') {
            expect.push_str(".0");
        }
        let bf = ff.get_big_float_big_decimal(&v);
        assert_eq!(expect, ff.to_decimal_string_compact(&bf, true));
        assert_eq!(FloatFormat::to_binary_string_f64(v.double_value()), ff.to_binary_string(&bf));
    }

    #[test]
    fn value_of_big_decimal() {
        do_test_value_of_big_decimal(BigDecimal::from(0i64));
        do_test_value_of_big_decimal(BigDecimal::from(1i64));
        do_test_value_of_big_decimal(BigDecimal::from(2i64));
        do_test_value_of_big_decimal(BigDecimal::from(-1i64));
        do_test_value_of_big_decimal(BigDecimal::from(-2i64));
        for d in [
            2.123456789,
            2.1234567890123456789,
            2.1234567890123456789E+123,
            -2.123456789,
            -2.1234567890123456789,
            -2.1234567890123456789E+123,
            f64::MAX,
            2.1234567890123456789E-123,
            -2.1234567890123456789E-123,
        ] {
            do_test_value_of_big_decimal(bd_value_of(d));
        }
        // BigDecimal.valueOf(Double.MIN_VALUE): Java's Double.toString gives "4.9E-324"
        do_test_value_of_big_decimal(bd("4.9E-324"));

        let ff = get_float_format(8).unwrap();

        // step just beyond Double.MAX_VALUE - still decodes the same
        let max_bd = bd_value_of(f64::MAX);
        let v = BigDecimal::new(max_bd.unscaled_value() + 1, max_bd.scale());
        let f = ff.get_big_float_big_decimal(&v);
        assert_eq!(max_bd.round(ff.get_display_context()).to_string(), ff.to_decimal_string_compact(&f, true));

        // step far beyond Double.MAX_VALUE
        let v = BigDecimal::new(max_bd.unscaled_value().clone(), max_bd.scale() * 2);
        let f = ff.get_big_float_big_decimal(&v);
        assert_eq!("+Infinity", ff.to_decimal_string(&f));

        // step just beyond Double.MIN_VALUE - still decodes the same
        let min_bd = bd("4.9E-324");
        let v = BigDecimal::new(min_bd.unscaled_value() + 1, min_bd.scale());
        let f = ff.get_big_float_big_decimal(&v);
        assert_eq!(min_bd.round(ff.get_display_context()).to_string(), ff.to_decimal_string_compact(&f, true));

        // step far beyond Double.MIN_VALUE
        let v = BigDecimal::new(min_bd.unscaled_value().clone(), min_bd.scale() * 2);
        let f = ff.get_big_float_big_decimal(&v);
        assert_eq!("0.0", ff.to_decimal_string(&f));
    }

    fn do_test_value_of_decimal_string(s: &str, expect: Option<&str>) {
        let ff = get_float_format(8).unwrap();
        let expect = match expect {
            Some(e) => e.to_string(),
            None => {
                let d: f64 = s.parse().unwrap();
                ff.to_decimal_string(&ff.decode_big_float(d.to_bits() as i64))
            }
        };
        let f = ff.get_big_float_str(s).unwrap();
        assert_eq!(expect, ff.to_decimal_string(&f), "input {}", s);
    }

    #[test]
    fn value_of_decimal_string() {
        for s in [
            "0",
            "1",
            "2",
            "3.141592653589793238462643",
            "2.123456789",
            "2.1234567890123456789",
            "2.1234567890123456789E+123",
            "-1",
            "-2",
            "-2.123456789",
            "-2.1234567890123456789",
            "-2.1234567890123456789E+123",
            "1.7976931348623157E+308",
            "2.1234567890123456789E-123",
            "-2.1234567890123456789E-123",
            "4.9E-324",
            "4.98e-324",
            "5.1e-350",
        ] {
            do_test_value_of_decimal_string(s, None);
        }
        do_test_value_of_decimal_string("1.7976931348623159E+308", Some("+Infinity"));
        do_test_value_of_decimal_string("2.2e350", Some("+Infinity"));

        let ff = get_float_format(8).unwrap();
        assert!(ff.get_big_float_str("nan").unwrap().is_nan());
        assert_eq!(ff.get_big_float_str("INFINITY").unwrap(), ff.get_big_infinity(false));
        assert_eq!(ff.get_big_float_str("+Infinity").unwrap(), ff.get_big_infinity(false));
        assert_eq!(ff.get_big_float_str("-infinity").unwrap(), ff.get_big_infinity(true));
        assert!(ff.get_big_float_str("1.2.3").is_err());
    }

    #[test]
    fn value_of_decimal_string_wide_formats() {
        // 10- and 16-byte formats take the BigInteger/BigFloat decimal path
        let ff10 = ff(10);
        assert_eq!("0.1", ff10.to_decimal_string_compact(&ff10.get_big_float_str("0.1").unwrap(), true));
        assert_eq!("1.5", ff10.to_decimal_string(&ff10.get_big_float_str("1.5").unwrap()));
        assert_eq!("-1.25E+30", ff10.to_decimal_string(&ff10.get_big_float_str("-1.25e30").unwrap()));
        let ff16 = ff(16);
        let tenth = ff16.get_big_float_str("0.1").unwrap();
        // trailing zeros of the 34-digit display form are stripped even when not compacting
        assert_eq!("0.1", ff16.to_decimal_string(&tenth));
        assert_eq!(ff16.round(&tenth).unwrap().to_string(), "0.1000000000000000000000000000000000");
        assert_eq!("0.1", ff16.to_decimal_string_compact(&tenth, true));
        assert_eq!(ff16.get_big_float_big_decimal(&BigDecimal::zero()), ff16.get_big_zero(false));
    }

    #[test]
    fn double_decode_with_to_string() {
        let ff = get_float_format(8).unwrap();
        assert_eq!("9.346009625593543E-307", ff.to_decimal_string(&ff.decode_big_float(0x0065006700610050)));
        assert_eq!("2.123456789012346", ff.to_decimal_string(&ff.decode_big_float(0x4000FCD6E9BA37B3)));
        assert_eq!("0.3", ff.to_decimal_string(&ff.decode_big_float(0x3FD3333333333333)));
    }

    #[test]
    fn float_decode_with_to_string() {
        let ff = get_float_format(4).unwrap();
        assert_eq!("-1.4682312", ff.to_decimal_string_compact(&ff.decode_big_float(0xbfbbef00), true));
    }

    #[test]
    #[should_panic(expected = "method not supported for float size of 10")]
    fn long_decode_rejects_wide_formats() {
        ff(10).decode_big_float(0);
    }
}
