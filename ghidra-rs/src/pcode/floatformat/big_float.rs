//! Port of `ghidra.pcode.floatformat.BigFloat`, promoted to a trait because it was selected as a
//! dependency-cycle cut-point.
//!
//! The Java class is a mutable IEEE-754-style value (`FINITE`/`INFINITE`/`QUIET_NAN`/
//! `SIGNALING_NAN`) parameterized by a fraction-bit and exponent-bit width, with in-place
//! arithmetic (`add`/`sub`/`mul`/`div`/`sqrt`/`floor`/`ceil`/`trunc`/`negate`/`abs`/`round`) plus
//! static copy-and-apply twins. There is no fixed, enumerable set of implementations (unlike
//! `PointerType`'s four constants), so this port keeps the mutating/query API as object-safe
//! trait methods taking/returning `&dyn BigFloat` / `Box<dyn BigFloat>`, and models the static
//! `zero`/`infinity`/`quietNaN` constructors as trait associated functions bounded by
//! `Self: Sized` -- they cannot be called through `dyn BigFloat` (no existing instance to build
//! from), but that bound is scoped to just those three methods, so the trait remains
//! dyn-compatible for every instance method a caller on the cut edge actually needs.
//!
//! `compareTo` is provided as a default method: the Java algorithm only ever reads
//! `isNaN`/`isInfinite`/`sign`/`scale`/`unscaled`, all of which are already trait methods (mirroring
//! the package-private field reads `FloatFormat` performs on `BigFloat` in the original package),
//! so it needs no per-implementor override.
//!
//! `BigInteger` is represented as `i128`, matching the crate-wide convention established by
//! `RadixBigInteger`/`Scalar::get_big_integer`/`DataConverter` rather than pulling in an
//! arbitrary-precision dependency. `BigDecimal` is represented as `f64` (`None` standing in for
//! the Java `null` returned for NaN). `MathContext` is reduced to the two fields `BigFloat`
//! actually reads off it (precision, rounding mode). `equals`/`hashCode` (from `Object`) and the
//! `protected`/private helpers (`internalRound`, `scaleUpTo`, `upscale`, `makeZero`, `makeOne`,
//! `add0`, `sub0`, `floor0`, `ceil0`, `copyFrom`, `getLeadBitPos`) are not part of the public API
//! and are left for the eventual concrete port.
//!
//! `FloatFormat` (the other half of the original cycle, referenced only by
//! `toString(FloatFormat, boolean)`) is not yet ported, so a minimal placeholder trait lives at
//! [`crate::pcode::seam_stubs::FloatFormat`]; see `STUBS.tsv`.

use super::FloatKind;
use crate::pcode::seam_stubs::FloatFormat;

/// Mirrors the Java `BigFloat.INFINITY` constant.
pub const INFINITY: &str = "Infinity";
/// Mirrors the Java `BigFloat.POSITIVE_INFINITY` constant.
pub const POSITIVE_INFINITY: &str = "+Infinity";
/// Mirrors the Java `BigFloat.NEGATIVE_INFINITY` constant.
pub const NEGATIVE_INFINITY: &str = "-Infinity";
/// Mirrors the Java `BigFloat.NAN` constant.
pub const NAN: &str = "NaN";

/// Stand-in for `java.math.RoundingMode`, reduced to the one mode `BigFloat`'s default display
/// context uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundingMode {
    /// Round towards the nearest neighbor, resolving ties towards the even neighbor.
    HalfEven,
}

/// Stand-in for `java.math.MathContext`: just the precision and rounding mode `BigFloat` reads
/// off it when formatting a decimal string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MathContext {
    /// Number of significant decimal digits to keep.
    pub precision: u32,
    /// How to resolve a value that falls exactly between two representable results.
    pub rounding: RoundingMode,
}

/// An IEEE-754-style floating point value.
///
/// Port of the Java `class BigFloat implements Comparable<BigFloat>`.
pub trait BigFloat {
    /// Number of significant mantissa bits, including the implied leading bit where relevant.
    ///
    /// Port of the package-private `fracbits` field.
    fn fracbits(&self) -> i32;

    /// Number of bits used to represent the exponent.
    ///
    /// Port of the package-private `expbits` field.
    fn expbits(&self) -> i32;

    /// Which of `FINITE`/`INFINITE`/`QUIET_NAN`/`SIGNALING_NAN` this value currently holds.
    ///
    /// Port of the package-private `kind` field.
    fn kind(&self) -> FloatKind;

    /// The value's sign, `+1` or `-1`.
    ///
    /// Port of the package-private `sign` field.
    fn sign(&self) -> i32;

    /// The value's biased scale (only meaningful when [`kind`](BigFloat::kind) is
    /// [`FloatKind::Finite`]).
    ///
    /// Port of the package-private `scale` field.
    fn scale(&self) -> i32;

    /// The value's unscaled mantissa (only meaningful when [`kind`](BigFloat::kind) is
    /// [`FloatKind::Finite`]).
    ///
    /// Port of the package-private `unscaled` field.
    fn unscaled(&self) -> i128;

    /// Port of `BigFloat.isNormal()`.
    fn is_normal(&self) -> bool;

    /// Port of `BigFloat.isDenormal()`.
    fn is_denormal(&self) -> bool;

    /// Port of `BigFloat.isNaN()`.
    fn is_nan(&self) -> bool;

    /// Port of `BigFloat.isInfinite()`.
    fn is_infinite(&self) -> bool;

    /// Port of `BigFloat.isZero()`.
    fn is_zero(&self) -> bool;

    /// Port of `BigFloat.copy()`.
    fn copy(&self) -> Box<dyn BigFloat>;

    /// Port of `void BigFloat.add(BigFloat other)` (`this += other`).
    fn add(&mut self, other: &dyn BigFloat);

    /// Port of `void BigFloat.sub(BigFloat other)` (`this -= other`).
    fn sub(&mut self, other: &dyn BigFloat);

    /// Port of `void BigFloat.mul(BigFloat other)` (`this *= other`).
    fn mul(&mut self, other: &dyn BigFloat);

    /// Port of `void BigFloat.div(BigFloat other)` (`this /= other`).
    fn div(&mut self, other: &dyn BigFloat);

    /// Port of `void BigFloat.sqrt()` (`this = sqrt(this)`).
    fn sqrt(&mut self);

    /// Port of `void BigFloat.floor()`.
    fn floor(&mut self);

    /// Port of `void BigFloat.ceil()`.
    fn ceil(&mut self);

    /// Port of `void BigFloat.trunc()`.
    fn trunc(&mut self);

    /// Port of `void BigFloat.negate()` (`this *= -1`).
    fn negate(&mut self);

    /// Port of `void BigFloat.abs()`.
    fn abs(&mut self);

    /// Port of `void BigFloat.round()`.
    fn round(&mut self);

    /// Port of `BigFloat.toBigInteger()`.
    fn to_big_integer(&self) -> i128;

    /// Port of `BigFloat.toBigDecimal()`. Returns `None` where Java returns `null` (NaN).
    fn to_big_decimal(&self) -> Option<f64>;

    /// Port of `BigFloat.toBinaryString()`.
    fn to_binary_string(&self) -> String;

    /// Port of `BigFloat.toString()`.
    fn to_display_string(&self) -> String;

    /// Port of `BigFloat.toString(MathContext)`.
    fn to_display_string_with_context(&self, context: MathContext) -> String;

    /// Port of `BigFloat.toString(FloatFormat, boolean)`.
    fn to_display_string_with_format(&self, format: &dyn FloatFormat, compact: bool) -> String;

    /// Port of `int BigFloat.compareTo(BigFloat other)`.
    ///
    /// Provided as a default method since the Java algorithm reads only
    /// [`is_nan`](BigFloat::is_nan), [`is_infinite`](BigFloat::is_infinite),
    /// [`sign`](BigFloat::sign), [`scale`](BigFloat::scale) and [`unscaled`](BigFloat::unscaled),
    /// all already exposed above.
    fn compare_to(&self, other: &dyn BigFloat) -> i32 {
        if self.is_nan() {
            return if other.is_nan() { 0 } else { 1 };
        }
        if other.is_nan() {
            return -1;
        }
        if self.is_infinite() {
            if self.sign() < 0 {
                return if other.is_infinite() && other.sign() < 0 {
                    0
                }
                else {
                    -1
                };
            }
            return if other.is_infinite() && other.sign() > 0 {
                0
            }
            else {
                1
            };
        }
        if other.is_infinite() {
            return -other.sign();
        }
        if self.sign() != other.sign() {
            return self.sign();
        }
        let scale_cmp = self.scale() - other.scale();
        if scale_cmp != 0 {
            return scale_cmp.signum() * self.sign();
        }
        let unscaled_cmp = match self.unscaled().cmp(&other.unscaled()) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        };
        unscaled_cmp * self.sign()
    }

    /// Return the value with the given number of bits representing `sign * zero`.
    ///
    /// Port of the static `BigFloat.zero(int, int, int)` factory. Bounded by `Self: Sized`
    /// (there is no existing instance to build from), so unlike every method above it cannot be
    /// called through `dyn BigFloat` -- only through a concrete implementing type or a generic
    /// `T: BigFloat`.
    fn zero(fracbits: i32, expbits: i32, sign: i32) -> Self
    where
        Self: Sized;

    /// Return `sign * infinity` with the given number of bits.
    ///
    /// Port of the static `BigFloat.infinity(int, int, int)` factory.
    fn infinity(fracbits: i32, expbits: i32, sign: i32) -> Self
    where
        Self: Sized;

    /// Return a quiet NaN with the given number of bits.
    ///
    /// Port of the static `BigFloat.quietNaN(int, int, int)` factory.
    fn quiet_nan(fracbits: i32, expbits: i32, sign: i32) -> Self
    where
        Self: Sized;
}

/// Port of the static `BigFloat.div(BigFloat, BigFloat)` (`a / b`).
pub fn div(a: &dyn BigFloat, b: &dyn BigFloat) -> Box<dyn BigFloat> {
    let mut c = a.copy();
    c.div(b);
    c
}

/// Port of the static `BigFloat.mul(BigFloat, BigFloat)` (`a * b`).
pub fn mul(a: &dyn BigFloat, b: &dyn BigFloat) -> Box<dyn BigFloat> {
    let mut c = a.copy();
    c.mul(b);
    c
}

/// Port of the static `BigFloat.add(BigFloat, BigFloat)` (`a + b`).
pub fn add(a: &dyn BigFloat, b: &dyn BigFloat) -> Box<dyn BigFloat> {
    let mut c = a.copy();
    c.add(b);
    c
}

/// Port of the static `BigFloat.sub(BigFloat, BigFloat)` (`a - b`).
pub fn sub(a: &dyn BigFloat, b: &dyn BigFloat) -> Box<dyn BigFloat> {
    let mut c = a.copy();
    c.sub(b);
    c
}

/// Port of the static `BigFloat.sqrt(BigFloat)`.
pub fn sqrt(a: &dyn BigFloat) -> Box<dyn BigFloat> {
    let mut c = a.copy();
    c.sqrt();
    c
}

/// Port of the static `BigFloat.floor(BigFloat)`.
pub fn floor(a: &dyn BigFloat) -> Box<dyn BigFloat> {
    let mut c = a.copy();
    c.floor();
    c
}

/// Port of the static `BigFloat.ceil(BigFloat)`.
pub fn ceil(a: &dyn BigFloat) -> Box<dyn BigFloat> {
    let mut c = a.copy();
    c.ceil();
    c
}

/// Port of the static `BigFloat.trunc(BigFloat)`.
pub fn trunc(a: &dyn BigFloat) -> Box<dyn BigFloat> {
    let mut c = a.copy();
    c.trunc();
    c
}

/// Port of the static `BigFloat.negate(BigFloat)`.
pub fn negate(a: &dyn BigFloat) -> Box<dyn BigFloat> {
    let mut c = a.copy();
    c.negate();
    c
}

/// Port of the static `BigFloat.abs(BigFloat)`.
pub fn abs(a: &dyn BigFloat) -> Box<dyn BigFloat> {
    let mut c = a.copy();
    c.abs();
    c
}

/// Port of the static `BigFloat.round(BigFloat)`.
pub fn round(a: &dyn BigFloat) -> Box<dyn BigFloat> {
    let mut c = a.copy();
    c.round();
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXED_POINT_SCALE: f64 = 1_000_000.0;

    /// A fixed-point mock: `value = sign * unscaled / FIXED_POINT_SCALE` for `Finite` values,
    /// proving [`BigFloat`] is usable as a trait object while doing genuine arithmetic (as
    /// opposed to a stub that only returns constants).
    #[derive(Debug, Clone)]
    struct MockBigFloat {
        fracbits: i32,
        expbits: i32,
        kind: FloatKind,
        sign: i32,
        unscaled: i128,
        scale: i32,
    }

    fn value_of(x: &dyn BigFloat) -> f64 {
        match x.kind() {
            FloatKind::Finite => x.sign() as f64 * x.unscaled() as f64 / FIXED_POINT_SCALE,
            FloatKind::Infinite => x.sign() as f64 * f64::INFINITY,
            FloatKind::QuietNan | FloatKind::SignalingNan => f64::NAN,
        }
    }

    impl MockBigFloat {
        fn as_f64(&self) -> f64 {
            value_of(self)
        }

        fn set_from_f64(&mut self, r: f64) {
            self.kind = FloatKind::Finite;
            self.sign = if r < 0.0 { -1 } else { 1 };
            self.unscaled = (r.abs() * FIXED_POINT_SCALE).round() as i128;
            self.scale = 0;
        }
    }

    impl BigFloat for MockBigFloat {
        fn fracbits(&self) -> i32 {
            self.fracbits
        }

        fn expbits(&self) -> i32 {
            self.expbits
        }

        fn kind(&self) -> FloatKind {
            self.kind
        }

        fn sign(&self) -> i32 {
            self.sign
        }

        fn scale(&self) -> i32 {
            self.scale
        }

        fn unscaled(&self) -> i128 {
            self.unscaled
        }

        fn is_normal(&self) -> bool {
            self.kind == FloatKind::Finite && self.unscaled != 0
        }

        fn is_denormal(&self) -> bool {
            false
        }

        fn is_nan(&self) -> bool {
            matches!(self.kind, FloatKind::QuietNan | FloatKind::SignalingNan)
        }

        fn is_infinite(&self) -> bool {
            self.kind == FloatKind::Infinite
        }

        fn is_zero(&self) -> bool {
            self.kind == FloatKind::Finite && self.unscaled == 0
        }

        fn copy(&self) -> Box<dyn BigFloat> {
            Box::new(self.clone())
        }

        fn add(&mut self, other: &dyn BigFloat) {
            if self.is_nan() || other.is_nan() {
                self.kind = FloatKind::QuietNan;
                return;
            }
            if self.is_infinite() && other.is_infinite() {
                if self.sign != other.sign() {
                    self.kind = FloatKind::QuietNan;
                }
                return;
            }
            if self.is_infinite() {
                return;
            }
            if other.is_infinite() {
                self.kind = FloatKind::Infinite;
                self.sign = other.sign();
                return;
            }
            let r = self.as_f64() + value_of(other);
            self.set_from_f64(r);
        }

        fn sub(&mut self, other: &dyn BigFloat) {
            let mut negated = other.copy();
            negated.negate();
            self.add(negated.as_ref());
        }

        fn mul(&mut self, other: &dyn BigFloat) {
            if self.is_nan() || other.is_nan() {
                self.kind = FloatKind::QuietNan;
                return;
            }
            if (self.is_zero() && other.is_infinite()) || (self.is_infinite() && other.is_zero())
            {
                self.kind = FloatKind::QuietNan;
                return;
            }
            if self.is_infinite() || other.is_infinite() {
                self.sign *= other.sign();
                self.kind = FloatKind::Infinite;
                return;
            }
            let r = self.as_f64() * value_of(other);
            self.set_from_f64(r);
        }

        fn div(&mut self, other: &dyn BigFloat) {
            if self.is_nan() || other.is_nan() {
                self.kind = FloatKind::QuietNan;
                return;
            }
            if self.is_infinite() {
                if other.is_infinite() {
                    self.kind = FloatKind::QuietNan;
                }
                else {
                    self.sign *= other.sign();
                }
                return;
            }
            if other.is_zero() {
                if self.is_zero() {
                    self.kind = FloatKind::QuietNan;
                }
                else {
                    self.sign *= other.sign();
                    self.kind = FloatKind::Infinite;
                }
                return;
            }
            let r = self.as_f64() / value_of(other);
            self.set_from_f64(r);
        }

        fn sqrt(&mut self) {
            if self.is_zero() || self.is_infinite() {
                return;
            }
            if self.is_nan() || self.sign < 0 {
                self.kind = FloatKind::QuietNan;
                return;
            }
            let r = self.as_f64().sqrt();
            self.set_from_f64(r);
        }

        fn floor(&mut self) {
            if self.kind == FloatKind::Finite {
                let r = self.as_f64().floor();
                self.set_from_f64(r);
            }
        }

        fn ceil(&mut self) {
            if self.kind == FloatKind::Finite {
                let r = self.as_f64().ceil();
                self.set_from_f64(r);
            }
        }

        fn trunc(&mut self) {
            if self.kind == FloatKind::Finite {
                let r = self.as_f64().trunc();
                self.set_from_f64(r);
            }
        }

        fn negate(&mut self) {
            self.sign *= -1;
        }

        fn abs(&mut self) {
            self.sign = 1;
        }

        fn round(&mut self) {
            if self.kind == FloatKind::Finite {
                let r = self.as_f64().round();
                self.set_from_f64(r);
            }
        }

        fn to_big_integer(&self) -> i128 {
            self.as_f64().trunc() as i128
        }

        fn to_big_decimal(&self) -> Option<f64> {
            if self.is_nan() {
                None
            }
            else {
                Some(self.as_f64())
            }
        }

        fn to_binary_string(&self) -> String {
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
                    format!(
                        "{}0b{:b}",
                        if self.sign < 0 { "-" } else { "" },
                        self.unscaled
                    )
                }
            }
        }

        fn to_display_string(&self) -> String {
            match self.kind {
                FloatKind::QuietNan | FloatKind::SignalingNan => NAN.to_string(),
                FloatKind::Infinite => {
                    if self.sign < 0 {
                        NEGATIVE_INFINITY.to_string()
                    }
                    else {
                        POSITIVE_INFINITY.to_string()
                    }
                }
                FloatKind::Finite => {
                    if self.is_zero() {
                        if self.sign < 0 { "-0.0" } else { "0.0" }.to_string()
                    }
                    else {
                        self.as_f64().to_string()
                    }
                }
            }
        }

        fn to_display_string_with_context(&self, context: MathContext) -> String {
            if self.kind != FloatKind::Finite || self.is_zero() {
                return self.to_display_string();
            }
            format!("{:.*}", context.precision as usize, self.as_f64())
        }

        fn to_display_string_with_format(
            &self,
            format: &dyn FloatFormat,
            _compact: bool,
        ) -> String {
            self.to_display_string_with_context(format.get_display_context())
        }

        fn zero(fracbits: i32, expbits: i32, sign: i32) -> Self {
            MockBigFloat {
                fracbits,
                expbits,
                kind: FloatKind::Finite,
                sign,
                unscaled: 0,
                scale: 0,
            }
        }

        fn infinity(fracbits: i32, expbits: i32, sign: i32) -> Self {
            MockBigFloat {
                fracbits,
                expbits,
                kind: FloatKind::Infinite,
                sign,
                unscaled: 0,
                scale: 0,
            }
        }

        fn quiet_nan(fracbits: i32, expbits: i32, sign: i32) -> Self {
            MockBigFloat {
                fracbits,
                expbits,
                kind: FloatKind::QuietNan,
                sign,
                unscaled: 0,
                scale: 0,
            }
        }
    }

    fn finite(v: f64) -> MockBigFloat {
        let mut m = MockBigFloat::zero(24, 8, 1);
        m.set_from_f64(v);
        m
    }

    #[test]
    fn usable_as_trait_object_and_computes_a_real_sum() {
        let a: Box<dyn BigFloat> = Box::new(finite(2.5));
        let b: Box<dyn BigFloat> = Box::new(finite(1.25));
        let sum = add(a.as_ref(), b.as_ref());
        assert!((value_of(sum.as_ref()) - 3.75).abs() < 1e-9);
    }

    #[test]
    fn mul_div_round_trip() {
        let a = finite(6.0);
        let b = finite(3.0);
        let product = mul(&a, &b);
        assert!((value_of(product.as_ref()) - 18.0).abs() < 1e-9);
        let quotient = div(product.as_ref(), &b);
        assert!((value_of(quotient.as_ref()) - 6.0).abs() < 1e-9);
    }

    #[test]
    fn sub_matches_negated_add() {
        let a = finite(5.0);
        let b = finite(8.0);
        let diff = sub(&a, &b);
        assert!((value_of(diff.as_ref()) - (-3.0)).abs() < 1e-9);
    }

    #[test]
    fn sqrt_of_negative_is_nan() {
        let mut neg = finite(-4.0);
        neg.sqrt();
        assert!(neg.is_nan());

        let mut pos = finite(4.0);
        pos.sqrt();
        assert!(!pos.is_nan());
        assert!((pos.as_f64() - 2.0).abs() < 1e-9);
    }

    #[test]
    fn div_by_zero_produces_infinite_or_nan() {
        let mut a = finite(1.0);
        let zero = finite(0.0);
        a.div(&zero);
        assert!(a.is_infinite());

        let mut z = finite(0.0);
        z.div(&zero);
        assert!(z.is_nan());
    }

    #[test]
    fn compare_to_orders_nan_infinite_and_finite() {
        let nan = MockBigFloat::quiet_nan(24, 8, 1);
        let pos_inf = MockBigFloat::infinity(24, 8, 1);
        let neg_inf = MockBigFloat::infinity(24, 8, -1);
        let three = finite(3.0);
        let five = finite(5.0);

        assert_eq!(nan.compare_to(&pos_inf), 1);
        assert_eq!(pos_inf.compare_to(&nan), -1);
        assert_eq!(neg_inf.compare_to(&pos_inf), -1);
        assert_eq!(pos_inf.compare_to(&neg_inf), 1);
        assert_eq!(three.compare_to(&five), -1);
        assert_eq!(five.compare_to(&three), 1);
        assert_eq!(three.compare_to(&finite(3.0)), 0);
        assert_eq!(five.compare_to(&pos_inf), -1);
    }

    #[test]
    fn floor_ceil_trunc_and_round() {
        let mut a = finite(2.7);
        a.floor();
        assert!((a.as_f64() - 2.0).abs() < 1e-9);

        let mut b = finite(2.2);
        b.ceil();
        assert!((b.as_f64() - 3.0).abs() < 1e-9);

        let mut c = finite(-2.7);
        c.trunc();
        assert!((c.as_f64() - (-2.0)).abs() < 1e-9);

        let mut d = finite(2.6);
        d.round();
        assert!((d.as_f64() - 3.0).abs() < 1e-9);
    }

    #[test]
    fn negate_and_abs_flip_sign() {
        let mut a = finite(4.0);
        a.negate();
        assert_eq!(a.sign(), -1);
        a.abs();
        assert_eq!(a.sign(), 1);

        let boxed = negate(&finite(4.0));
        assert_eq!(boxed.sign(), -1);
        let absed = abs(boxed.as_ref());
        assert_eq!(absed.sign(), 1);
    }

    #[test]
    fn to_big_integer_truncates() {
        assert_eq!(finite(3.9).to_big_integer(), 3);
        assert_eq!(finite(-3.9).to_big_integer(), -3);
    }

    #[test]
    fn to_big_decimal_is_none_for_nan() {
        let nan = MockBigFloat::quiet_nan(24, 8, 1);
        assert!(nan.to_big_decimal().is_none());
        assert_eq!(finite(1.5).to_big_decimal(), Some(1.5));
    }

    #[test]
    fn display_strings_cover_special_and_finite_cases() {
        let nan = MockBigFloat::quiet_nan(24, 8, 1);
        let inf = MockBigFloat::infinity(24, 8, -1);
        assert_eq!(nan.to_display_string(), NAN);
        assert_eq!(inf.to_display_string(), NEGATIVE_INFINITY);
        assert_eq!(finite(0.0).to_display_string(), "0.0");
        assert!(finite(1.5).to_display_string().starts_with('1'));
    }

    #[test]
    fn to_display_string_with_context_respects_precision() {
        let value = finite(1.0 / 3.0);
        let ctx = MathContext {
            precision: 2,
            rounding: RoundingMode::HalfEven,
        };
        let s = value.to_display_string_with_context(ctx);
        assert_eq!(s, "0.33");
    }

    struct MockFloatFormat {
        context: MathContext,
    }

    impl FloatFormat for MockFloatFormat {
        fn get_display_context(&self) -> MathContext {
            self.context
        }

        fn get_encoding(&self, value: &dyn BigFloat) -> i128 {
            value.unscaled() * value.sign() as i128
        }

        fn get_big_float(&self, value: f64) -> Box<dyn BigFloat> {
            Box::new(finite(value))
        }
    }

    #[test]
    fn to_display_string_with_format_delegates_to_display_context() {
        let format = MockFloatFormat {
            context: MathContext {
                precision: 3,
                rounding: RoundingMode::HalfEven,
            },
        };
        let value = finite(1.0 / 3.0);
        assert_eq!(value.to_display_string_with_format(&format, false), "0.333");
        let encoding = format.get_encoding(&value);
        let round_tripped = format.get_big_float(value_of(&value));
        assert_eq!(format.get_encoding(round_tripped.as_ref()), encoding);
    }
}
