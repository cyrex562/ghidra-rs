//! Port of `ghidra.pcode.floatformat.BigFloat`.
//!
//! An IEEE 754 floating point value of arbitrary precision. Values represented:
//!
//! * `QUIET_NAN`, `SIGNALING_NAN`
//! * `-INF`, `+INF`
//! * `value = sign * unscaled * 2 ^ (scale - fracbits)`
//!
//! `sign` is `-1` or `+1`, `unscaled` has at most `fracbits + 1` bits, and `scale` is at most
//! `expbits` bits. Operations compute the exact result and then round to nearest even.
//!
//! # Rust shape
//!
//! Java declares a concrete `class BigFloat implements Comparable<BigFloat>` that nothing extends,
//! so this is a plain `struct` (it was previously a mock-only trait; see `PORT_MANIFEST.tsv`).
//! `BigInteger` is [`num_bigint::BigInt`]; `BigDecimal`/`MathContext` are the minimal JDK ports in
//! [`super::big_decimal`].
//!
//! * The package-private fields `FloatFormat` reads are `pub(super)`; read-only accessors are
//!   public for everyone else.
//! * The mutating instance methods (`add`, `sqrt`, ...) keep their Java names and take
//!   `&mut self`. Java's same-named static copy-and-apply twins (`BigFloat.add(a, b)`, ...) are the
//!   associated functions with an `_of` suffix ([`BigFloat::add_of`], ...).
//! * `copy()` is [`Clone`]; `equals`/`hashCode` are [`PartialEq`]/[`Hash`] with Java's rules (all
//!   NaNs of one precision are equal; `-0.0 != +0.0`); `compareTo` is [`BigFloat::compare_to`];
//!   `toString()` is [`Display`](std::fmt::Display).
//! * Java's `AssertionError`/`IllegalArgumentException` for violated internal invariants are
//!   panics; Java `assert` statements are `debug_assert!`.

use std::fmt;
use std::hash::{Hash, Hasher};

use num_bigint::BigInt;
use num_traits::{One, Signed, Zero};

use super::big_decimal::{BigDecimal, MathContext, RoundingMode};
use super::float_format::FloatFormat;
use super::FloatKind;

/// Mirrors the Java `BigFloat.INFINITY` constant.
pub const INFINITY: &str = "Infinity";
/// Mirrors the Java `BigFloat.POSITIVE_INFINITY` constant.
pub const POSITIVE_INFINITY: &str = "+Infinity";
/// Mirrors the Java `BigFloat.NEGATIVE_INFINITY` constant.
pub const NEGATIVE_INFINITY: &str = "-Infinity";
/// Mirrors the Java `BigFloat.NAN` constant.
pub const NAN: &str = "NaN";

const INFINITE_SCALE: i32 = -(64 * 1024);

/// Port of `BigFloat.BIG_POSITIVE_INFINITY` (`1E+65536`), the stand-in [`BigFloat::to_big_decimal`]
/// returns for `+inf`.
pub fn big_positive_infinity() -> BigDecimal {
    BigDecimal::new(BigInt::one(), INFINITE_SCALE)
}

/// Port of `BigFloat.BIG_NEGATIVE_INFINITY` (`-1E+65536`).
pub fn big_negative_infinity() -> BigDecimal {
    big_positive_infinity().negate()
}

// ---- java.math.BigInteger idioms over num-bigint ------------------------------------------------

/// `BigInteger.shiftLeft(n)`: a negative `n` shifts right (rounding toward negative infinity).
pub(super) fn shl(x: &BigInt, n: i32) -> BigInt {
    if n >= 0 {
        x << (n as u32)
    }
    else {
        x >> n.unsigned_abs()
    }
}

/// `BigInteger.shiftRight(n)`: a negative `n` shifts left.
pub(super) fn shr(x: &BigInt, n: i32) -> BigInt {
    if n >= 0 {
        x >> (n as u32)
    }
    else {
        x << n.unsigned_abs()
    }
}

/// `BigInteger.bitLength()` (two's-complement length, excluding the sign bit).
pub(super) fn bit_length(x: &BigInt) -> i32 {
    if x.is_negative() {
        (-x - BigInt::one()).bits() as i32
    }
    else {
        x.bits() as i32
    }
}

/// `BigInteger.getLowestSetBit()`: `-1` for zero.
pub(super) fn lowest_set_bit(x: &BigInt) -> i32 {
    x.trailing_zeros().map(|t| t as i32).unwrap_or(-1)
}

/// `BigInteger.testBit(n)` (two's-complement semantics).
///
/// # Panics
/// If `n` is negative, where Java throws `ArithmeticException`.
pub(super) fn test_bit(x: &BigInt, n: i32) -> bool {
    assert!(n >= 0, "Negative bit address");
    x.bit(n as u64)
}

// ---- BigFloat ----------------------------------------------------------------------------------

/// An IEEE 754 floating point value; see the module docs.
///
/// Port of `ghidra.pcode.floatformat.BigFloat`.
#[derive(Debug, Clone)]
pub struct BigFloat {
    /// Number of significant mantissa bits, including the implied leading bit where relevant.
    pub(super) fracbits: i32,
    /// Number of bits used for the exponent.
    pub(super) expbits: i32,
    pub(super) max_scale: i32,
    pub(super) min_scale: i32,
    pub(super) kind: FloatKind,
    /// `-1` or `+1`.
    pub(super) sign: i32,
    /// Normal numbers have `bit_length(unscaled) == fracbits`; subnormal numbers have
    /// `scale == min_scale` and fewer bits.
    pub(super) unscaled: BigInt,
    pub(super) scale: i32,
}

impl BigFloat {
    /// Construct a `BigFloat`. If `kind` is [`FloatKind::Finite`], the value is
    /// `sign * unscaled * 2^(scale - fracbits)`.
    ///
    /// Port of the package-private constructor. Normal values must be supplied in normal form.
    ///
    /// # Panics
    /// Where Java throws `IllegalArgumentException`: `unscaled` longer than `fracbits` bits, or
    /// `scale` outside the range `expbits` allows.
    pub(crate) fn new(
        fracbits: i32,
        expbits: i32,
        kind: FloatKind,
        sign: i32,
        unscaled: BigInt,
        scale: i32,
    ) -> Self {
        let max_scale = (1i32 << (expbits - 1)) - 1;
        let min_scale = 1 - max_scale;
        let ulen = bit_length(&unscaled);
        if ulen > fracbits {
            panic!("unscaled value exceeds {} bits in length (length={})", fracbits, ulen);
        }
        if scale < min_scale || scale > max_scale {
            panic!("scale out of bounds {} to {} (scale={})", min_scale, max_scale, scale);
        }
        Self { fracbits, expbits, max_scale, min_scale, kind, sign, unscaled, scale }
    }

    /// Port of `BigFloat.zero(int, int, int)`: `+0` or `-0` with the given precision.
    pub fn zero(fracbits: i32, expbits: i32, sign: i32) -> Self {
        Self::new(fracbits, expbits, FloatKind::Finite, sign, BigInt::zero(), 2 - (1 << (expbits - 1)))
    }

    /// Port of `BigFloat.zero(int, int)`: `+0` with the given precision.
    pub fn positive_zero(fracbits: i32, expbits: i32) -> Self {
        Self::zero(fracbits, expbits, 1)
    }

    /// Port of `BigFloat.infinity(int, int, int)`: `+inf` or `-inf`.
    pub fn infinity(fracbits: i32, expbits: i32, sign: i32) -> Self {
        Self::new(
            fracbits,
            expbits,
            FloatKind::Infinite,
            sign,
            BigInt::one() << ((fracbits - 1) as u32),
            (1 << (expbits - 1)) - 1,
        )
    }

    /// Port of `BigFloat.quietNaN(int, int, int)`.
    pub fn quiet_nan(fracbits: i32, expbits: i32, sign: i32) -> Self {
        Self::new(fracbits, expbits, FloatKind::QuietNan, sign, BigInt::zero(), (1 << (expbits - 1)) - 1)
    }

    /// Number of significant mantissa bits, including the implied leading bit where relevant.
    pub fn fracbits(&self) -> i32 {
        self.fracbits
    }

    /// Number of bits used to represent the exponent.
    pub fn expbits(&self) -> i32 {
        self.expbits
    }

    /// Which of `FINITE`/`INFINITE`/`QUIET_NAN`/`SIGNALING_NAN` this value holds.
    pub fn kind(&self) -> FloatKind {
        self.kind
    }

    /// The sign, `+1` or `-1`.
    pub fn sign(&self) -> i32 {
        self.sign
    }

    /// The scale (meaningful for finite values).
    pub fn scale(&self) -> i32 {
        self.scale
    }

    /// The unscaled mantissa (meaningful for finite values).
    pub fn unscaled(&self) -> &BigInt {
        &self.unscaled
    }

    fn upscale(&mut self, nbits: i32) {
        self.unscaled = shl(&self.unscaled, nbits);
        self.scale -= nbits;
    }

    /// Guarantee at least `new_length` significant bits. Port of `scaleUpTo`.
    fn scale_up_to(&mut self, new_length: i32) {
        if self.kind != FloatKind::Finite {
            panic!("scaling of non-finite float!");
        }
        let d = new_length - bit_length(&self.unscaled);
        if d > 0 {
            self.upscale(d);
        }
    }

    /// Port of `BigFloat.isNormal()`: finite and using every fractional bit.
    pub fn is_normal(&self) -> bool {
        self.kind == FloatKind::Finite && bit_length(&self.unscaled) == self.fracbits
    }

    /// Port of `BigFloat.isDenormal()`: finite, non-zero, and not using every fractional bit.
    pub fn is_denormal(&self) -> bool {
        self.kind == FloatKind::Finite
            && !self.unscaled.is_zero()
            && bit_length(&self.unscaled) < self.fracbits
    }

    /// Round after a computation whose true value is `sign * (unscaled + eps) * 2^(scale-fracbits)`
    /// with at least one extra bit of precision in `unscaled`. Port of `internalRound`.
    fn internal_round(&mut self, mut eps: bool) {
        if self.kind != FloatKind::Finite {
            panic!("Rounding non-finite float");
        }
        if self.unscaled.is_zero() {
            if eps {
                panic!("Rounding zero + epsilon, need bit length");
            }
            self.make_zero();
            return;
        }

        let extrabits =
            (bit_length(&self.unscaled) - self.fracbits).max(self.min_scale - self.scale);
        if extrabits <= 0 {
            panic!("Rounding with no extra bits of precision");
        }

        let midbit = extrabits - 1;
        let midbitset = test_bit(&self.unscaled, midbit);
        eps |= lowest_set_bit(&self.unscaled) < midbit;
        self.unscaled = shr(&self.unscaled, extrabits);
        self.scale += extrabits;
        let odd = test_bit(&self.unscaled, 0);

        if midbitset && (eps || odd) {
            self.unscaled += 1;
            // handle overflowing carry
            if bit_length(&self.unscaled) > self.fracbits {
                debug_assert_eq!(bit_length(&self.unscaled), lowest_set_bit(&self.unscaled) + 1);
                self.unscaled = shr(&self.unscaled, 1);
                self.scale += 1;
            }
        }

        if self.scale > self.max_scale {
            self.kind = FloatKind::Infinite;
        }
    }

    /// Port of `getLeadBitPos`.
    #[allow(dead_code)]
    fn get_lead_bit_pos(&self) -> i32 {
        if self.kind != FloatKind::Finite || self.unscaled.is_zero() {
            panic!("lead bit of non-finite or zero");
        }
        bit_length(&self.unscaled) - self.fracbits + self.scale + 1
    }

    /// Port of `BigFloat.toBigDecimal()`: exact for finite values, one of
    /// [`big_positive_infinity`]/[`big_negative_infinity`] for infinities, `None` (Java `null`)
    /// for NaN.
    pub fn to_big_decimal(&self) -> Option<BigDecimal> {
        match self.kind {
            FloatKind::Finite => {
                if self.is_zero() {
                    return Some(BigDecimal::zero());
                }
                let unused_bits = lowest_set_bit(&self.unscaled).max(0);
                let mut val = self.unscaled.clone();
                let mut iscale = self.scale - self.fracbits + 1;
                let mut x = if iscale >= -unused_bits {
                    BigDecimal::from_big_int(shl(&val, iscale))
                }
                else {
                    if unused_bits > 0 {
                        val = shr(&self.unscaled, unused_bits);
                        iscale += unused_bits;
                    }
                    let five_pow = num_traits::pow(BigInt::from(5), (-iscale) as usize);
                    BigDecimal::new(val * five_pow, -iscale)
                };
                if self.sign < 0 {
                    x = x.negate();
                }
                Some(x)
            }
            FloatKind::Infinite => Some(if self.sign < 0 {
                big_negative_infinity()
            }
            else {
                big_positive_infinity()
            }),
            FloatKind::QuietNan | FloatKind::SignalingNan => None,
        }
    }

    /// Port of `BigFloat.toBinaryString()`, e.g. `"-0b1.1 * 2^3"`.
    pub fn to_binary_string(&self) -> String {
        match self.kind {
            FloatKind::QuietNan => "qNaN".to_string(),
            FloatKind::SignalingNan => "sNaN".to_string(),
            FloatKind::Infinite => {
                if self.sign < 0 {
                    "-inf".to_string()
                }
                else {
                    "+inf".to_string()
                }
            }
            FloatKind::Finite => {
                let s = if self.sign < 0 { "-" } else { "" };
                let mut ascale = self.scale;
                let mut binary;
                if self.is_normal() {
                    binary = format!("1.{}", &self.unscaled.to_str_radix(2)[1..]);
                    ascale += bit_length(&self.unscaled) - self.fracbits;
                }
                else {
                    // subnormal
                    debug_assert!(bit_length(&self.unscaled) < self.fracbits);
                    if self.unscaled.is_zero() {
                        return format!("{}0b0.0", s);
                    }
                    let zeros = (self.fracbits - bit_length(&self.unscaled) - 1).max(0) as usize;
                    binary = format!("0.{}{}", "0".repeat(zeros), self.unscaled.to_str_radix(2));
                }
                let trimmed = binary.trim_end_matches('0').len();
                binary.truncate(trimmed);
                if binary.ends_with('.') {
                    binary.push('0');
                }
                format!("{}0b{} * 2^{}", s, binary, ascale)
            }
        }
    }

    fn make_quiet_nan(&mut self) {
        self.kind = FloatKind::QuietNan;
    }

    /// Port of `BigFloat.isNaN()`.
    pub fn is_nan(&self) -> bool {
        matches!(self.kind, FloatKind::QuietNan | FloatKind::SignalingNan)
    }

    fn make_zero(&mut self) {
        self.kind = FloatKind::Finite;
        self.unscaled = BigInt::zero();
        self.scale = self.min_scale;
    }

    /// Port of `BigFloat.isInfinite()`.
    pub fn is_infinite(&self) -> bool {
        self.kind == FloatKind::Infinite
    }

    /// Port of `BigFloat.isZero()`.
    pub fn is_zero(&self) -> bool {
        self.kind == FloatKind::Finite && self.unscaled.is_zero()
    }

    /// Port of `copyFrom` (assumes the same `fracbits` and `expbits`).
    fn copy_from(&mut self, other: &BigFloat) {
        self.kind = other.kind;
        self.sign = other.sign;
        self.unscaled = other.unscaled.clone();
        self.scale = other.scale;
    }

    /// Port of the static `BigFloat.div(BigFloat, BigFloat)`: `a / b`.
    pub fn div_of(a: &BigFloat, b: &BigFloat) -> BigFloat {
        let mut c = a.clone();
        c.div(b);
        c
    }

    /// Port of `BigFloat.div(BigFloat)`: `this /= other`.
    pub fn div(&mut self, other: &BigFloat) {
        if self.is_nan() || other.is_nan() {
            self.make_quiet_nan();
            return;
        }

        if self.is_infinite() {
            if other.is_infinite() {
                self.make_quiet_nan();
            }
            else {
                self.sign *= other.sign;
            }
            return;
        }

        // this is finite
        match other.kind {
            FloatKind::QuietNan | FloatKind::SignalingNan => {
                self.make_quiet_nan();
                return;
            }
            FloatKind::Infinite => {
                self.make_zero();
                self.sign *= other.sign;
                return;
            }
            FloatKind::Finite => {}
        }

        if other.is_zero() {
            if self.is_zero() {
                self.make_quiet_nan();
            }
            else {
                self.kind = FloatKind::Infinite;
                self.sign *= other.sign;
            }
            return;
        }

        // this is finite, other is finite non zero; give the quotient fracbits+2 bits:
        //   nbits(x) - nbits(y) <= nbits(x/y) <= nbits(x) - nbits(y) + 1
        let lshift = self.fracbits + 1 + bit_length(&other.unscaled) - bit_length(&self.unscaled);
        self.upscale(lshift);

        let q = &self.unscaled / &other.unscaled;
        let r = &self.unscaled % &other.unscaled;

        self.sign *= other.sign;
        self.scale -= other.scale - self.fracbits + 1;
        self.unscaled = q;
        self.internal_round(!r.is_zero());
    }

    /// Port of the static `BigFloat.mul(BigFloat, BigFloat)`: `a * b`.
    pub fn mul_of(a: &BigFloat, b: &BigFloat) -> BigFloat {
        let mut c = a.clone();
        c.mul(b);
        c
    }

    /// Port of `BigFloat.mul(BigFloat)`: `this *= other`.
    pub fn mul(&mut self, other: &BigFloat) {
        if self.is_nan() || other.is_nan() {
            self.make_quiet_nan();
            return;
        }
        if (self.is_zero() && other.is_infinite()) || (self.is_infinite() && other.is_zero()) {
            self.make_quiet_nan();
            return;
        }

        if self.is_infinite() || other.is_infinite() {
            self.kind = FloatKind::Infinite;
            self.sign *= other.sign;
            return;
        }

        // this and other are finite
        self.sign *= other.sign;
        self.unscaled = &self.unscaled * &other.unscaled;
        self.scale += other.scale - self.fracbits + 1;

        self.scale_up_to(self.fracbits + 1);
        self.internal_round(false);
    }

    /// Port of the static `BigFloat.add(BigFloat, BigFloat)`: `a + b`.
    pub fn add_of(a: &BigFloat, b: &BigFloat) -> BigFloat {
        let mut c = a.clone();
        c.add(b);
        c
    }

    /// Port of `BigFloat.add(BigFloat)`: `this += other`.
    pub fn add(&mut self, other: &BigFloat) {
        if self.is_nan() || other.is_nan() {
            self.make_quiet_nan();
            return;
        }
        if self.is_infinite() && other.is_infinite() {
            if self.sign != other.sign {
                self.make_quiet_nan();
            }
            return;
        }
        if self.is_infinite() {
            return;
        }
        if other.is_infinite() {
            self.copy_from(other);
            return;
        }

        if other.is_zero() {
            if self.is_zero() {
                self.sign = if self.sign < 0 && other.sign < 0 { -1 } else { 1 };
            }
            return;
        }
        if self.is_zero() {
            self.copy_from(other);
            return;
        }

        if self.sign == other.sign {
            self.add0(other);
        }
        else {
            self.sub0(other);
        }
    }

    /// Port of the static `BigFloat.sub(BigFloat, BigFloat)`: `a - b`.
    pub fn sub_of(a: &BigFloat, b: &BigFloat) -> BigFloat {
        let mut c = b.clone();
        c.sign *= -1;
        c.add(a);
        if c.is_zero() {
            c.sign = if a.sign < 0 && b.sign > 0 { -1 } else { 1 };
        }
        c
    }

    /// Port of `BigFloat.sub(BigFloat)`: `this -= other`.
    pub fn sub(&mut self, other: &BigFloat) {
        let thissign = self.sign;
        let mut nother = other.clone();
        nother.sign *= -1;
        self.add(&nother);
        if self.is_zero() {
            self.sign = if thissign < 0 && nother.sign < 0 { -1 } else { 1 };
        }
    }

    /// Port of `add0`: both finite with the same sign, neither zero.
    fn add0(&mut self, other: &BigFloat) {
        let mut d = self.scale - other.scale;

        if d > self.fracbits {
            return;
        }
        else if d < -self.fracbits {
            self.copy_from(other);
            return;
        }

        let (a_unscaled, a_scale, b_unscaled) = if d >= 0 {
            (self.unscaled.clone(), self.scale, other.unscaled.clone())
        }
        else {
            d = -d;
            (other.unscaled.clone(), other.scale, self.unscaled.clone())
        };

        let residue = lowest_set_bit(&b_unscaled) < d - 1;
        self.scale = a_scale - 1;
        self.unscaled = shl(&a_unscaled, 1) + shr(&b_unscaled, d - 1);

        self.scale_up_to(self.fracbits + 1);
        self.internal_round(residue);
    }

    /// Port of `sub0`: both finite with opposite signs, neither zero.
    fn sub0(&mut self, other: &BigFloat) {
        let mut d = self.scale - other.scale;

        if d > self.fracbits + 1 {
            return;
        }
        else if d < -(self.fracbits + 1) {
            self.copy_from(other);
            return;
        }

        let (a_unscaled, a_scale, a_sign, b_unscaled) = if d >= 0 {
            (self.unscaled.clone(), self.scale, self.sign, other.unscaled.clone())
        }
        else {
            d = -d;
            (other.unscaled.clone(), other.scale, other.sign, self.unscaled.clone())
        };

        // d <= 0 is ok.. no residue and right shift will become left shift
        let residue = lowest_set_bit(&b_unscaled) < d - 2;
        self.sign = a_sign;
        self.scale = a_scale - 2;
        let mut x = shr(&b_unscaled, d - 2);
        if residue {
            x += 1;
        }

        self.unscaled = shl(&a_unscaled, 2) - x;
        if self.unscaled.is_zero() {
            self.sign = 1; // cancellation results in positive 0.
        }
        else if self.unscaled.is_negative() {
            self.sign *= -1;
            self.unscaled = -&self.unscaled;
        }
        self.scale_up_to(self.fracbits + 1);
        self.internal_round(residue);
    }

    /// Port of the static `BigFloat.sqrt(BigFloat)`.
    pub fn sqrt_of(a: &BigFloat) -> BigFloat {
        let mut c = a.clone();
        c.sqrt();
        c
    }

    /// Port of `BigFloat.sqrt()`: `this = sqrt(this)`, by the abacus algorithm (Martin Guy, UKC,
    /// June 1985).
    pub fn sqrt(&mut self) {
        if self.is_zero() {
            return;
        }

        if self.is_nan() || self.sign == -1 {
            self.make_quiet_nan();
            return;
        }

        if self.is_infinite() {
            return;
        }

        // force at least fracbits+2 bits of precision in the result
        let sigbits = 2 * self.fracbits + 2;
        self.scale_up_to(sigbits);

        // scale+fracbits needs to be even for the sqrt computation
        if ((self.scale + self.fracbits - 1) & 1) != 0 {
            self.upscale(1);
        }

        let mut residue = self.unscaled.clone();
        let mut result = BigInt::zero();

        // "bit" starts at the highest 4 power <= n.
        let mut pow = bit_length(&residue) - 1; // highest 2 power <= n
        pow -= pow & 1; // highest 4 power
        let mut bit = BigInt::one() << (pow as u32);

        while !bit.is_zero() {
            let resp1 = &result + &bit;
            if residue >= resp1 {
                residue -= &resp1;
                result += &bit << 1u32;
            }
            result >>= 1u32;
            bit >>= 2u32;
        }

        self.unscaled = result;
        self.scale = (self.scale + self.fracbits - 1) / 2;

        self.internal_round(!residue.is_zero());
    }

    /// floor, ignoring sign. Port of `floor0`.
    fn floor0(&mut self) {
        if self.scale < 0 {
            self.make_zero();
            return;
        }
        let nbits_under_one = self.fracbits - self.scale - 1;
        self.unscaled = shl(&shr(&self.unscaled, nbits_under_one), nbits_under_one);
    }

    /// Port of `makeOne` (sign is not set).
    fn make_one(&mut self) {
        self.kind = FloatKind::Finite;
        self.scale = 0;
        self.unscaled = BigInt::one() << ((self.fracbits - 1) as u32);
    }

    /// ceil, ignoring sign. Port of `ceil0`.
    fn ceil0(&mut self) {
        if self.is_zero() {
            return;
        }
        else if self.scale < 0 {
            self.make_one();
            return;
        }

        let nbits_under_one = self.fracbits - self.scale - 1;
        let increment = lowest_set_bit(&self.unscaled) < nbits_under_one;
        self.unscaled = shl(&shr(&self.unscaled, nbits_under_one), nbits_under_one);
        if increment {
            self.unscaled += shl(&BigInt::one(), nbits_under_one);
        }

        // if we carry to a new bit, change the scale
        if bit_length(&self.unscaled) > self.fracbits {
            self.upscale(-1);
        }
    }

    /// Port of the static `BigFloat.floor(BigFloat)`.
    pub fn floor_of(a: &BigFloat) -> BigFloat {
        let mut b = a.clone();
        b.floor();
        b
    }

    /// Port of `BigFloat.floor()`.
    pub fn floor(&mut self) {
        match self.kind {
            FloatKind::Infinite => return,
            FloatKind::SignalingNan => {
                self.make_quiet_nan();
                return;
            }
            FloatKind::QuietNan => return,
            FloatKind::Finite => {}
        }

        if self.sign >= 0 {
            self.floor0();
        }
        else {
            self.ceil0();
        }
    }

    /// Port of the static `BigFloat.ceil(BigFloat)`.
    pub fn ceil_of(a: &BigFloat) -> BigFloat {
        let mut b = a.clone();
        b.ceil();
        b
    }

    /// Port of `BigFloat.ceil()`.
    pub fn ceil(&mut self) {
        match self.kind {
            FloatKind::Infinite => return,
            FloatKind::SignalingNan => {
                self.make_quiet_nan();
                return;
            }
            FloatKind::QuietNan => return,
            FloatKind::Finite => {}
        }

        if self.sign >= 0 {
            self.ceil0();
        }
        else {
            self.floor0();
        }
    }

    /// Port of the static `BigFloat.trunc(BigFloat)` (round toward zero).
    pub fn trunc_of(a: &BigFloat) -> BigFloat {
        let mut b = a.clone();
        b.trunc();
        b
    }

    /// Port of `BigFloat.trunc()` (round toward zero). Like Java, this does not check the kind.
    pub fn trunc(&mut self) {
        self.floor0();
    }

    /// Port of `BigFloat.negate()`: `this *= -1`.
    pub fn negate(&mut self) {
        self.sign *= -1;
    }

    /// Port of the static `BigFloat.negate(BigFloat)`.
    pub fn negate_of(a: &BigFloat) -> BigFloat {
        let mut b = a.clone();
        b.negate();
        b
    }

    /// Port of the static `BigFloat.abs(BigFloat)`.
    pub fn abs_of(a: &BigFloat) -> BigFloat {
        let mut b = a.clone();
        b.abs();
        b
    }

    /// Port of `BigFloat.abs()`.
    pub fn abs(&mut self) {
        self.sign = 1;
    }

    /// Port of `BigFloat.toBigInteger()`: the value truncated toward zero.
    pub fn to_big_integer(&self) -> BigInt {
        let res = shr(&self.unscaled, self.fracbits - self.scale - 1);
        if self.sign < 0 {
            -res
        }
        else {
            res
        }
    }

    /// Port of the static `BigFloat.round(BigFloat)`.
    pub fn round_of(a: &BigFloat) -> BigFloat {
        let mut b = a.clone();
        b.round();
        b
    }

    /// Port of `BigFloat.round()`: add one half, then floor.
    pub fn round(&mut self) {
        let half = BigFloat::new(
            self.fracbits,
            self.expbits,
            FloatKind::Finite,
            1,
            BigInt::one() << ((self.fracbits - 1) as u32),
            -1,
        );
        self.add(&half);
        self.floor();
    }

    /// Port of `BigFloat.compareTo(BigFloat)`: NaN is greatest (and equal to NaN), `-0 < +0`.
    pub fn compare_to(&self, other: &BigFloat) -> i32 {
        // this == NaN
        if self.is_nan() {
            return if other.is_nan() { 0 } else { 1 };
        }
        // this != NaN
        if other.is_nan() {
            return -1;
        }
        if self.is_infinite() {
            // this == -inf
            if self.sign < 0 {
                return if other.is_infinite() && other.sign < 0 { 0 } else { -1 };
            }
            // this == +inf
            return if other.is_infinite() && other.sign > 0 { 0 } else { 1 };
        }
        // this is finite
        if other.is_infinite() {
            return -other.sign;
        }

        // other is finite
        if self.sign != other.sign {
            return self.sign;
        }

        // both finite, same sign
        let c = self.scale.cmp(&other.scale) as i32;
        if c != 0 {
            return c * self.sign;
        }

        self.sign * (self.unscaled.cmp(&other.unscaled) as i32)
    }

    fn format_special_case(&self) -> Option<String> {
        if self.is_nan() {
            return Some(NAN.to_string());
        }
        if self.is_infinite() {
            return Some(if self.sign < 0 { NEGATIVE_INFINITY } else { POSITIVE_INFINITY }.to_string());
        }
        if self.is_zero() {
            return Some(if self.sign < 0 { "-0.0" } else { "0.0" }.to_string());
        }
        None
    }

    /// Port of `BigFloat.toString(MathContext)`.
    pub fn to_string_with_context(&self, display_context: &MathContext) -> String {
        if let Some(special) = self.format_special_case() {
            return special;
        }
        let bd = self.to_big_decimal().expect("finite value");
        bd.round(display_context).to_string()
    }

    /// Port of `BigFloat.toString(FloatFormat, boolean)`: round to the format's display context;
    /// if `compact`, drop trailing digits while the value still encodes identically in `ff`.
    pub fn to_string_with_format(&self, ff: &FloatFormat, compact: bool) -> String {
        if let Some(special) = self.format_special_case() {
            return special;
        }
        let mut bd = self.to_big_decimal().expect("finite value");
        bd = bd.round(ff.get_display_context());

        let mut s = bd.to_string();
        let precision = bd.precision();
        let bd_scale = bd.scale();

        // Generate compact representation if requested
        if compact && precision > 2 {
            let encoding = ff.get_encoding_big(self);
            let mut new_str = Some(s.clone());
            while let Some(current) = new_str {
                new_str = remove_fractional_digit(&current, 1, false);
                if let Some(candidate) = &new_str {
                    let cbd: BigDecimal = candidate.parse().expect("compacted decimal string");
                    let cbd = cbd.set_scale(bd_scale); // avoid scale change which may alter encoding
                    let bf = ff.get_big_float_big_decimal(&cbd);
                    if encoding == ff.get_encoding_big(&bf) {
                        s = candidate.clone();
                    }
                    else {
                        new_str = None; // stop compaction
                    }
                }
            }
        }
        // Strip trailing zeros
        s = strip_trailing_zeros(&s, 1);
        // Ensure decimal point is present
        if !s.contains('.') {
            s.push_str(".0");
        }
        s
    }
}

fn strip_trailing_zeros(dec_str: &str, _min_digits: i32) -> String {
    let mut s = dec_str.to_string();
    while let Some(next) = remove_fractional_digit(&s, 1, true) {
        s = next;
    }
    s
}

fn remove_fractional_digit(dec_str: &str, min_digits: usize, strip_zero_digit_only: bool) -> Option<String> {
    let decimal_point_ix = dec_str.find('.')?;
    let mut dec = dec_str;
    let mut exp = "";
    if let Some(exp_ix) = dec_str.to_uppercase().find('E') {
        if exp_ix > 0 {
            exp = &dec_str[exp_ix..];
            dec = &dec_str[..exp_ix];
        }
    }
    if dec.len() - decimal_point_ix - 1 <= min_digits {
        return None;
    }
    let last_digit_index = dec.len() - 1;
    if strip_zero_digit_only && dec.as_bytes()[last_digit_index] != b'0' {
        return None;
    }
    // discard last mantissa digit
    Some(format!("{}{}", &dec[..last_digit_index], exp))
}

/// Port of `getDefaultDisplayContext`: `log10(2) * fracBits` digits, half-even.
fn default_display_context(frac_bits: i32) -> MathContext {
    let precision = (0.30103 * frac_bits as f64) as u32;
    MathContext::new(precision, RoundingMode::HalfEven)
}

impl fmt::Display for BigFloat {
    /// Port of `BigFloat.toString()`: rounds to `log10(2) * fracbits` significant digits.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.format_special_case() {
            Some(special) => f.write_str(&special),
            None => f.write_str(&self.to_string_with_context(&default_display_context(self.fracbits))),
        }
    }
}

impl PartialEq for BigFloat {
    /// Port of `BigFloat.equals(Object)`.
    fn eq(&self, other: &Self) -> bool {
        if self.expbits != other.expbits || self.fracbits != other.fracbits || self.kind != other.kind {
            return false;
        }
        match self.kind {
            FloatKind::Finite => {
                self.sign == other.sign && self.scale == other.scale && self.unscaled == other.unscaled
            }
            FloatKind::Infinite => self.sign == other.sign,
            FloatKind::QuietNan | FloatKind::SignalingNan => true,
        }
    }
}

impl Eq for BigFloat {}

impl Hash for BigFloat {
    /// Port of `BigFloat.hashCode()`: hashes exactly the fields [`PartialEq`] compares.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.expbits.hash(state);
        self.fracbits.hash(state);
        self.kind.hash(state);
        match self.kind {
            FloatKind::Finite => {
                self.sign.hash(state);
                self.scale.hash(state);
                self.unscaled.hash(state);
            }
            FloatKind::Infinite => self.sign.hash(state),
            FloatKind::QuietNan | FloatKind::SignalingNan => {}
        }
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    //! Test vectors shared by the `BigFloat` and `FloatFormat` tests (`BigFloatTest`'s static
    //! lists), including a bit-exact `java.util.Random` so the random values match Java's.

    /// `java.util.Random`'s LCG, so the random test vectors match Java's.
    pub(crate) struct JavaRandom {
        seed: u64,
    }

    impl JavaRandom {
        pub(crate) fn new(seed: i64) -> Self {
            Self { seed: (seed as u64 ^ 0x5DEECE66D) & ((1u64 << 48) - 1) }
        }
        fn next(&mut self, bits: u32) -> i32 {
            self.seed = (self.seed.wrapping_mul(0x5DEECE66D).wrapping_add(0xB)) & ((1u64 << 48) - 1);
            (self.seed >> (48 - bits)) as i64 as i32
        }
        pub(crate) fn next_int(&mut self) -> i32 {
            self.next(32)
        }
        pub(crate) fn next_long(&mut self) -> i64 {
            ((self.next(32) as i64) << 32).wrapping_add(self.next(32) as i64)
        }
        pub(crate) fn next_float(&mut self) -> f32 {
            self.next(24) as f32 / (1 << 24) as f32
        }
    }

    const NUM_RANDOM_TEST_VALUES_UNARY: usize = 1000;
    const NUM_RANDOM_TEST_VALUES_BINARY: usize = 100;

    fn float_specials() -> Vec<f32> {
        let min = f32::from_bits(1);
        let min_normal = f32::MIN_POSITIVE;
        vec![
            -0.0, 0.0, -1.0, 1.0, -min, min, -f32::MAX, f32::MAX,
            -min_normal - min, -min_normal, -min_normal + min,
            min_normal - min, min_normal, min_normal + min,
            f32::NAN, f32::NEG_INFINITY, f32::INFINITY,
        ]
    }

    fn double_specials() -> Vec<f64> {
        let min = f64::from_bits(1);
        let min_normal = f64::MIN_POSITIVE;
        vec![
            -0.0, 0.0, -1.0, 1.0, -min, min, -f64::MAX, f64::MAX,
            -min_normal - min, -min_normal, -min_normal + min,
            min_normal - min, min_normal, min_normal + min,
            f64::NAN, f64::NEG_INFINITY, f64::INFINITY,
        ]
    }

    /// `BigFloatTest.testFloatList`.
    pub(crate) fn test_float_list() -> Vec<f32> {
        let mut rand = JavaRandom::new(1);
        let mut v = float_specials();
        for _ in 0..NUM_RANDOM_TEST_VALUES_UNARY {
            v.push(f32::from_bits(rand.next_int() as u32));
        }
        v
    }

    pub(crate) fn test_float_short_list() -> Vec<f32> {
        let mut v = test_float_list();
        v.truncate(float_specials().len() + NUM_RANDOM_TEST_VALUES_BINARY);
        v
    }

    /// `BigFloatTest.testDoubleList`.
    pub(crate) fn test_double_list() -> Vec<f64> {
        let mut rand = JavaRandom::new(1);
        let mut v = double_specials();
        for _ in 0..NUM_RANDOM_TEST_VALUES_UNARY {
            v.push(f64::from_bits(rand.next_long() as u64));
        }
        v
    }

    pub(crate) fn test_double_short_list() -> Vec<f64> {
        let mut v = test_double_list();
        v.truncate(double_specials().len() + NUM_RANDOM_TEST_VALUES_BINARY);
        v
    }

}

#[cfg(test)]
mod tests {
    //! Ports of `BigFloatTest`, with Java's native `float`/`double` arithmetic replaced by Rust's
    //! (both IEEE 754 round-half-even) and `java.util.Random(1)` reproduced bit-for-bit.

    use super::tests_support::*;
    use super::*;
    use crate::pcode::floatformat::float_format::FloatFormat;

    /// `Float.compare`: `-0.0 < 0.0`, every NaN equal and greater than everything.
    fn java_float_compare(a: f32, b: f32) -> i32 {
        match (a.is_nan(), b.is_nan()) {
            (true, true) => 0,
            (true, false) => 1,
            (false, true) => -1,
            _ => {
                if a < b {
                    -1
                }
                else if a > b {
                    1
                }
                else {
                    let (x, y) = (a.to_bits() as i32, b.to_bits() as i32);
                    x.cmp(&y) as i32
                }
            }
        }
    }

    fn java_double_compare(a: f64, b: f64) -> i32 {
        match (a.is_nan(), b.is_nan()) {
            (true, true) => 0,
            (true, false) => 1,
            (false, true) => -1,
            _ => {
                if a < b {
                    -1
                }
                else if a > b {
                    1
                }
                else {
                    let (x, y) = (a.to_bits() as i64, b.to_bits() as i64);
                    x.cmp(&y) as i32
                }
            }
        }
    }

    fn unary_float_op_test(op: impl Fn(f32) -> f32, bproc: impl Fn(&mut BigFloat)) {
        for (i, fa) in test_float_list().into_iter().enumerate() {
            let mut bfa = FloatFormat::to_big_float_f32(fa);
            let fb = op(fa);
            bproc(&mut bfa);
            assert_eq!(fb.is_nan(), bfa.is_nan(), "case #{}", i);
            if !fb.is_nan() {
                assert_eq!(FloatFormat::to_binary_string_f32(fb), bfa.to_binary_string(), "case #{}", i);
            }
        }
    }

    fn unary_double_op_test(op: impl Fn(f64) -> f64, bproc: impl Fn(&mut BigFloat)) {
        for (i, fa) in test_double_list().into_iter().enumerate() {
            let mut bfa = FloatFormat::to_big_float_f64(fa);
            let fb = op(fa);
            bproc(&mut bfa);
            assert_eq!(fb.is_nan(), bfa.is_nan(), "case #{}", i);
            if !fb.is_nan() {
                assert_eq!(FloatFormat::to_binary_string_f64(fb), bfa.to_binary_string(), "case #{}", i);
            }
        }
    }

    fn binary_float_op_test(op: impl Fn(f32, f32) -> f32, bproc: impl Fn(&mut BigFloat, &BigFloat)) {
        let list = test_float_short_list();
        for (i, &fa) in list.iter().enumerate() {
            for (j, &fb) in list.iter().enumerate() {
                let mut bfa = FloatFormat::to_big_float_f32(fa);
                let bfb = FloatFormat::to_big_float_f32(fb);
                let fc = op(fa, fb);
                bproc(&mut bfa, &bfb);
                assert_eq!(fc.is_nan(), bfa.is_nan(), "case #{},{}", i, j);
                if !fc.is_nan() {
                    assert_eq!(FloatFormat::to_binary_string_f32(fc), bfa.to_binary_string(), "case #{},{}", i, j);
                }
            }
        }
    }

    fn binary_double_op_test(op: impl Fn(f64, f64) -> f64, bproc: impl Fn(&mut BigFloat, &BigFloat)) {
        let list = test_double_short_list();
        for (i, &fa) in list.iter().enumerate() {
            for (j, &fb) in list.iter().enumerate() {
                let mut bfa = FloatFormat::to_big_float_f64(fa);
                let bfb = FloatFormat::to_big_float_f64(fb);
                let fc = op(fa, fb);
                bproc(&mut bfa, &bfb);
                assert_eq!(fc.is_nan(), bfa.is_nan(), "case #{},{}", i, j);
                if !fc.is_nan() {
                    assert_eq!(FloatFormat::to_binary_string_f64(fc), bfa.to_binary_string(), "case #{},{}", i, j);
                }
            }
        }
    }

    #[test]
    fn java_random_matches_java() {
        // new Random(1).nextInt() == -1155869325, nextLong() on a fresh Random(1) == -4964420948893066024
        assert_eq!(JavaRandom::new(1).next_int(), -1155869325);
        assert_eq!(JavaRandom::new(1).next_long(), -4964420948893066024);
    }

    #[test]
    fn ieee_float_representation() {
        assert_eq!("0b0.0", FloatFormat::to_binary_string_f32(0.0));
        assert_eq!("0b1.0 * 2^0", FloatFormat::to_binary_string_f32(1.0));
        assert_eq!("0b1.0 * 2^1", FloatFormat::to_binary_string_f32(2.0));
        assert_eq!("0b1.0 * 2^-1", FloatFormat::to_binary_string_f32(0.5));
        assert_eq!("-0b1.0 * 2^1", FloatFormat::to_binary_string_f32(-2.0));
    }

    #[test]
    fn ieee_float_as_big_float() {
        for f in [0.0f32, 1.0, 2.0, 0.5, -2.0] {
            assert_eq!(FloatFormat::to_big_float_f32(f).to_binary_string(), FloatFormat::to_binary_string_f32(f));
        }
    }

    #[test]
    fn ieee_float_as_big_float_random() {
        let mut rand = JavaRandom::new(1);
        for _ in 0..100 {
            let f = f32::from_bits(rand.next_int() as u32);
            assert_eq!(FloatFormat::to_big_float_f32(f).to_binary_string(), FloatFormat::to_binary_string_f32(f));
        }
    }

    #[test]
    fn ieee_double_representation() {
        assert_eq!("0b0.0", FloatFormat::to_binary_string_f64(0.0));
        assert_eq!("0b1.0 * 2^0", FloatFormat::to_binary_string_f64(1.0));
        assert_eq!("0b1.0 * 2^1", FloatFormat::to_binary_string_f64(2.0));
        assert_eq!("0b1.0 * 2^-1", FloatFormat::to_binary_string_f64(0.5));
        assert_eq!("-0b1.0 * 2^1", FloatFormat::to_binary_string_f64(-2.0));
        assert_eq!("0b1.1 * 2^0", FloatFormat::to_binary_string_f64(1.5));
        assert_eq!("0b0.0000000000000000000000000000000000000000000000000001 * 2^-1022",
            FloatFormat::to_binary_string_f64(f64::from_bits(1)));
    }

    #[test]
    fn ieee_double_as_big_float_random() {
        for d in [0.0f64, 1.0, 2.0, 0.5, -2.0] {
            assert_eq!(FloatFormat::to_big_float_f64(d).to_binary_string(), FloatFormat::to_binary_string_f64(d));
        }
        let mut rand = JavaRandom::new(1);
        for _ in 0..100 {
            let d = f64::from_bits(rand.next_long() as u64);
            assert_eq!(FloatFormat::to_big_float_f64(d).to_binary_string(), FloatFormat::to_binary_string_f64(d));
        }
    }

    #[test]
    fn float_add() {
        binary_float_op_test(|a, b| a + b, |a, b| a.add(b));
    }

    #[test]
    fn float_subtract() {
        binary_float_op_test(|a, b| a - b, |a, b| a.sub(b));
    }

    #[test]
    fn float_multiply() {
        binary_float_op_test(|a, b| a * b, |a, b| a.mul(b));
    }

    #[test]
    fn float_divide() {
        binary_float_op_test(|a, b| a / b, |a, b| a.div(b));
    }

    #[test]
    fn float_compare() {
        let list = test_float_short_list();
        for (i, &a) in list.iter().enumerate() {
            let fa = FloatFormat::to_big_float_f32(a);
            for (j, &b) in list.iter().enumerate() {
                let fb = FloatFormat::to_big_float_f32(b);
                assert_eq!(java_float_compare(a, b), fa.compare_to(&fb), "case #{},{}", i, j);
            }
        }
    }

    #[test]
    fn float_sqrt() {
        unary_float_op_test(|a| (a as f64).sqrt() as f32, |a| a.sqrt());
    }

    #[test]
    fn float_floor() {
        unary_float_op_test(|a| (a as f64).floor() as f32, |a| a.floor());
    }

    #[test]
    fn float_ceil() {
        unary_float_op_test(|a| (a as f64).ceil() as f32, |a| a.ceil());
    }

    #[test]
    fn double_add() {
        binary_double_op_test(|a, b| a + b, |a, b| a.add(b));
    }

    #[test]
    fn double_subtract() {
        binary_double_op_test(|a, b| a - b, |a, b| a.sub(b));
    }

    #[test]
    fn double_multiply() {
        binary_double_op_test(|a, b| a * b, |a, b| a.mul(b));
    }

    #[test]
    fn double_divide() {
        binary_double_op_test(|a, b| a / b, |a, b| a.div(b));
    }

    #[test]
    fn double_compare() {
        let list = test_double_short_list();
        for (i, &a) in list.iter().enumerate() {
            let fa = FloatFormat::to_big_float_f64(a);
            for (j, &b) in list.iter().enumerate() {
                let fb = FloatFormat::to_big_float_f64(b);
                assert_eq!(java_double_compare(a, b), fa.compare_to(&fb), "case #{},{}", i, j);
            }
        }
    }

    #[test]
    fn double_sqrt() {
        unary_double_op_test(|a| a.sqrt(), |a| a.sqrt());
    }

    #[test]
    fn double_floor() {
        unary_double_op_test(|a| a.floor(), |a| a.floor());
    }

    #[test]
    fn double_ceil() {
        unary_double_op_test(|a| a.ceil(), |a| a.ceil());
    }

    #[test]
    fn static_twins_leave_operands_untouched() {
        let a = FloatFormat::to_big_float_f64(1.5);
        let b = FloatFormat::to_big_float_f64(0.25);
        assert_eq!(BigFloat::add_of(&a, &b), FloatFormat::to_big_float_f64(1.75));
        assert_eq!(BigFloat::sub_of(&a, &b), FloatFormat::to_big_float_f64(1.25));
        assert_eq!(BigFloat::mul_of(&a, &b), FloatFormat::to_big_float_f64(0.375));
        assert_eq!(BigFloat::div_of(&a, &b), FloatFormat::to_big_float_f64(6.0));
        assert_eq!(BigFloat::sqrt_of(&b), FloatFormat::to_big_float_f64(0.5));
        assert_eq!(BigFloat::floor_of(&a), FloatFormat::to_big_float_f64(1.0));
        assert_eq!(BigFloat::ceil_of(&a), FloatFormat::to_big_float_f64(2.0));
        assert_eq!(BigFloat::trunc_of(&BigFloat::negate_of(&a)), FloatFormat::to_big_float_f64(-1.0));
        assert_eq!(BigFloat::abs_of(&BigFloat::negate_of(&a)), a);
        assert_eq!(BigFloat::round_of(&a), FloatFormat::to_big_float_f64(2.0));
        assert_eq!(a, FloatFormat::to_big_float_f64(1.5));
        // x - x is +0; -0 - +0 is -0
        let z = BigFloat::sub_of(&a, &a);
        assert!(z.is_zero() && z.sign() == 1);
        let nz = BigFloat::sub_of(&FloatFormat::to_big_float_f64(-0.0), &FloatFormat::to_big_float_f64(0.0));
        assert!(nz.is_zero() && nz.sign() == -1);
    }

    #[test]
    fn round_is_half_up_then_floor() {
        for (v, expect) in [(2.5, 3.0), (2.25, 2.0), (2.75, 3.0), (-2.5, -2.0), (-2.25, -2.0), (-2.75, -3.0), (0.4, 0.0)] {
            let mut b = FloatFormat::to_big_float_f64(v);
            b.round();
            assert_eq!(b, FloatFormat::to_big_float_f64(expect), "round({})", v);
        }
    }

    #[test]
    fn to_big_integer_truncates() {
        assert_eq!(FloatFormat::to_big_float_f64(2.5).to_big_integer(), BigInt::from(2));
        assert_eq!(FloatFormat::to_big_float_f64(-2.5).to_big_integer(), BigInt::from(-2));
        assert_eq!(FloatFormat::to_big_float_f64(1e20).to_big_integer(), BigInt::from(100000000000000000000u128));
    }

    #[test]
    fn to_big_decimal() {
        let bd = |s: &str| s.parse::<BigDecimal>().unwrap();
        assert_eq!(Some(BigDecimal::zero()), FloatFormat::to_big_float_f64(0.0).to_big_decimal());
        assert_eq!(Some(bd("1")), FloatFormat::to_big_float_f64(1.0).to_big_decimal());
        assert_eq!(Some(bd("-1")), FloatFormat::to_big_float_f64(-1.0).to_big_decimal());
        // new BigDecimal(double) is the exact binary value
        assert_eq!(Some(bd("0.5")), FloatFormat::to_big_float_f64(0.5).to_big_decimal());
        assert_eq!(Some(bd("2.5")), FloatFormat::to_big_float_f64(2.5).to_big_decimal());
        assert_eq!(Some(bd("-0.5")), FloatFormat::to_big_float_f64(-0.5).to_big_decimal());
        assert_eq!(Some(bd("-2.5")), FloatFormat::to_big_float_f64(-2.5).to_big_decimal());
        assert_eq!(
            Some(bd("0.1000000000000000055511151231257827021181583404541015625")),
            FloatFormat::to_big_float_f64(0.1).to_big_decimal()
        );
        let min = FloatFormat::to_big_float_f64(f64::from_bits(1)).to_big_decimal().unwrap();
        assert_eq!(min.scale(), 1074);
        assert_eq!(min.double_value(), f64::from_bits(1));
        let max = FloatFormat::to_big_float_f64(f64::MAX).to_big_decimal().unwrap();
        assert_eq!(max.scale(), 0);
        assert_eq!(max.double_value(), f64::MAX);
        assert_eq!(Some(big_positive_infinity()), FloatFormat::to_big_float_f64(f64::INFINITY).to_big_decimal());
        assert_eq!(Some(big_negative_infinity()), FloatFormat::to_big_float_f64(f64::NEG_INFINITY).to_big_decimal());
        assert_eq!(None, FloatFormat::to_big_float_f64(f64::NAN).to_big_decimal());
    }

    #[test]
    fn normal_and_denormal() {
        let bf = FloatFormat::to_big_float_f64(0.0);
        assert!(!bf.is_normal());
        assert!(!bf.is_denormal());
        let bf = FloatFormat::to_big_float_f64(f64::MIN_POSITIVE);
        assert!(bf.is_normal());
        assert!(!bf.is_denormal());
        let bf = FloatFormat::to_big_float_f64(f64::MAX);
        assert!(bf.is_normal());
        assert!(!bf.is_denormal());
        let bf = FloatFormat::to_big_float_f64(f64::from_bits(1));
        assert!(!bf.is_normal());
        assert!(bf.is_denormal());
    }

    #[test]
    fn equality_follows_java_equals() {
        let f = |d| FloatFormat::to_big_float_f64(d);
        assert_ne!(f(0.0), f(-0.0));
        assert_eq!(f(f64::NAN), f(-f64::NAN));
        assert_ne!(f(f64::INFINITY), f(f64::NEG_INFINITY));
        // same value, different precision: not equal
        assert_ne!(f(1.0), FloatFormat::to_big_float_f32(1.0));
        use std::collections::HashSet;
        let set: HashSet<BigFloat> = [f(1.0), f(1.0), f(f64::NAN), f(-f64::NAN)].into_iter().collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn display_uses_default_context() {
        // 53 fraction bits -> (int) (0.30103 * 53) = 15 significant digits
        assert_eq!(FloatFormat::to_big_float_f64(0.1).to_string(), "0.100000000000000");
        assert_eq!(FloatFormat::to_big_float_f64(-0.0).to_string(), "-0.0");
        assert_eq!(FloatFormat::to_big_float_f64(f64::INFINITY).to_string(), "+Infinity");
        assert_eq!(FloatFormat::to_big_float_f64(f64::NEG_INFINITY).to_string(), "-Infinity");
        assert_eq!(FloatFormat::to_big_float_f64(f64::NAN).to_string(), "NaN");
        let mc = MathContext::new(3, RoundingMode::HalfEven);
        assert_eq!(FloatFormat::to_big_float_f64(2.375).to_string_with_context(&mc), "2.38");
        assert_eq!(FloatFormat::to_big_float_f64(2.625).to_string_with_context(&mc), "2.62");
    }

    #[test]
    #[should_panic(expected = "scale out of bounds")]
    fn constructor_rejects_bad_scale() {
        BigFloat::new(24, 8, FloatKind::Finite, 1, BigInt::one(), 128);
    }

    #[test]
    #[should_panic(expected = "unscaled value exceeds 24 bits")]
    fn constructor_rejects_wide_unscaled() {
        BigFloat::new(24, 8, FloatKind::Finite, 1, BigInt::one() << 24u32, 0);
    }
}
