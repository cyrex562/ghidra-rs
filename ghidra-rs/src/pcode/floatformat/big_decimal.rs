//! The subset of `java.math.BigDecimal`, `java.math.MathContext` and `java.math.RoundingMode`
//! that [`BigFloat`](super::BigFloat) and [`FloatFormat`](super::FloatFormat) use.
//!
//! These are JDK classes, not Ghidra classes, so they have no `PORT_MANIFEST.tsv` row; they live
//! next to their only users. Only the behavior those users observe is reproduced, but that part is
//! reproduced exactly, because it decides the decimal strings Ghidra shows for float values:
//!
//! * a value is an arbitrary-precision unscaled integer and a 32-bit decimal `scale`
//!   (`value = unscaled * 10^-scale`), and equality compares both (so `2.0 != 2.00`, as in Java);
//! * [`BigDecimal::round`] implements `BigDecimal.round(MathContext)` for
//!   [`RoundingMode::HalfEven`], including the carry case (`9.99 -> 10.0`);
//! * [`Display`](std::fmt::Display) implements `BigDecimal.toString()` (scientific notation when
//!   the scale is negative or the adjusted exponent is below `-6`);
//! * [`BigDecimal::from_str`](std::str::FromStr::from_str) implements `new BigDecimal(String)`;
//! * [`BigDecimal::double_value`] / [`BigDecimal::float_value`] are correctly rounded, like the
//!   JDK's.

use std::fmt;
use std::str::FromStr;

use num_bigint::{BigInt, Sign};
use num_traits::{Signed, Zero};

/// Port of the `java.math.RoundingMode` constant `BigFloat`/`FloatFormat` use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoundingMode {
    /// Round towards the nearest neighbor, resolving ties towards the even neighbor.
    HalfEven,
}

/// Port of `java.math.MathContext`: a decimal precision plus a rounding mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MathContext {
    /// Number of significant decimal digits to keep; `0` means unlimited.
    pub precision: u32,
    /// How to resolve a value that falls exactly between two representable results.
    pub rounding: RoundingMode,
}

impl MathContext {
    /// Port of `new MathContext(int, RoundingMode)`.
    pub const fn new(precision: u32, rounding: RoundingMode) -> Self {
        Self { precision, rounding }
    }
}

/// Error returned when a string is not a valid decimal number, standing in for Java's
/// `NumberFormatException` from `new BigDecimal(String)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseBigDecimalError {
    input: String,
}

impl fmt::Display for ParseBigDecimalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not a valid decimal number: {:?}", self.input)
    }
}

impl std::error::Error for ParseBigDecimalError {}

/// An arbitrary-precision signed decimal number, `unscaled * 10^-scale`.
///
/// Port of the parts of `java.math.BigDecimal` used by the float-format code; see the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BigDecimal {
    unscaled: BigInt,
    scale: i32,
}

fn ten_pow(n: u32) -> BigInt {
    num_traits::pow(BigInt::from(10), n as usize)
}

/// Number of decimal digits in `|x|` (1 for zero), as Java's `BigDecimal.precision()` counts.
fn decimal_digits(x: &BigInt) -> u32 {
    if x.is_zero() {
        return 1;
    }
    x.magnitude().to_str_radix(10).len() as u32
}

/// `x / divisor` rounded half-even (Java's `divideAndRound` for `ROUND_HALF_EVEN`); `divisor > 0`.
fn divide_half_even(x: &BigInt, divisor: &BigInt) -> BigInt {
    let q = x / divisor; // truncates toward zero, like BigInteger.divide
    let r = x - &q * divisor;
    if r.is_zero() {
        return q;
    }
    let twice_r: BigInt = r.abs() * 2u32;
    let increment = match twice_r.cmp(divisor) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => (&q % 2u32) != BigInt::zero(),
    };
    if increment {
        if x.is_negative() {
            q - 1
        }
        else {
            q + 1
        }
    }
    else {
        q
    }
}

impl BigDecimal {
    /// Port of `new BigDecimal(BigInteger unscaledVal, int scale)`.
    pub fn new(unscaled: BigInt, scale: i32) -> Self {
        Self { unscaled, scale }
    }

    /// Port of `BigDecimal.ZERO`.
    pub fn zero() -> Self {
        Self::new(BigInt::zero(), 0)
    }

    /// Port of `new BigDecimal(BigInteger)`: an integer value with scale 0.
    pub fn from_big_int(value: BigInt) -> Self {
        Self::new(value, 0)
    }

    /// Port of `BigDecimal.unscaledValue()`.
    pub fn unscaled_value(&self) -> &BigInt {
        &self.unscaled
    }

    /// Port of `BigDecimal.scale()`.
    pub fn scale(&self) -> i32 {
        self.scale
    }

    /// Port of `BigDecimal.signum()`.
    pub fn signum(&self) -> i32 {
        match self.unscaled.sign() {
            Sign::Minus => -1,
            Sign::NoSign => 0,
            Sign::Plus => 1,
        }
    }

    /// Port of `BigDecimal.precision()`: the number of decimal digits in the unscaled value.
    pub fn precision(&self) -> u32 {
        decimal_digits(&self.unscaled)
    }

    /// Port of `BigDecimal.negate()`.
    pub fn negate(&self) -> Self {
        Self::new(-&self.unscaled, self.scale)
    }

    /// Port of `BigDecimal.setScale(int)`: only exact (scale-increasing or remainder-free) changes
    /// are allowed, as in Java.
    ///
    /// # Panics
    /// Where Java throws `ArithmeticException("Rounding necessary")`.
    pub fn set_scale(&self, new_scale: i32) -> Self {
        if new_scale == self.scale {
            return self.clone();
        }
        if new_scale > self.scale {
            let up = (new_scale as i64 - self.scale as i64) as u32;
            return Self::new(&self.unscaled * ten_pow(up), new_scale);
        }
        let down = ten_pow((self.scale as i64 - new_scale as i64) as u32);
        let q = &self.unscaled / &down;
        if &q * &down != self.unscaled {
            panic!("Rounding necessary");
        }
        Self::new(q, new_scale)
    }

    /// Port of `BigDecimal.round(MathContext)`.
    pub fn round(&self, mc: &MathContext) -> Self {
        let RoundingMode::HalfEven = mc.rounding;
        if mc.precision == 0 {
            return self.clone();
        }
        let mut unscaled = self.unscaled.clone();
        let mut scale = self.scale as i64;
        let mut digits = decimal_digits(&unscaled);
        while digits > mc.precision {
            let drop = digits - mc.precision;
            unscaled = divide_half_even(&unscaled, &ten_pow(drop));
            scale -= drop as i64;
            digits = decimal_digits(&unscaled);
        }
        Self::new(unscaled, scale as i32)
    }

    /// Port of `BigDecimal.toBigInteger()`: truncation toward zero.
    pub fn to_big_integer(&self) -> BigInt {
        if self.scale <= 0 {
            &self.unscaled * ten_pow(self.scale.unsigned_abs())
        }
        else {
            &self.unscaled / ten_pow(self.scale as u32)
        }
    }

    /// Scientific form `"<unscaled>e<-scale>"`, which Rust's float parsers read exactly.
    fn to_exponent_string(&self) -> String {
        format!("{}e{}", self.unscaled, -(self.scale as i64))
    }

    /// Port of `BigDecimal.doubleValue()`: the nearest `f64`, ties to even.
    pub fn double_value(&self) -> f64 {
        self.to_exponent_string().parse::<f64>().expect("valid decimal")
    }

    /// Port of `BigDecimal.floatValue()`: the nearest `f32`, ties to even.
    pub fn float_value(&self) -> f32 {
        self.to_exponent_string().parse::<f32>().expect("valid decimal")
    }
}

impl fmt::Display for BigDecimal {
    /// Port of `BigDecimal.toString()` (the "scientific" canonical string).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let coeff = self.unscaled.magnitude().to_str_radix(10);
        let mut out = String::new();
        if self.unscaled.is_negative() {
            out.push('-');
        }
        let len = coeff.len() as i64;
        let scale = self.scale as i64;
        let adjusted = -scale + (len - 1);
        if scale >= 0 && adjusted >= -6 {
            if scale == 0 {
                out.push_str(&coeff);
            }
            else if len > scale {
                let point = (len - scale) as usize;
                out.push_str(&coeff[..point]);
                out.push('.');
                out.push_str(&coeff[point..]);
            }
            else {
                out.push_str("0.");
                for _ in 0..(scale - len) {
                    out.push('0');
                }
                out.push_str(&coeff);
            }
        }
        else {
            out.push_str(&coeff[..1]);
            if len > 1 {
                out.push('.');
                out.push_str(&coeff[1..]);
            }
            if adjusted != 0 {
                out.push('E');
                if adjusted > 0 {
                    out.push('+');
                }
                out.push_str(&adjusted.to_string());
            }
        }
        f.write_str(&out)
    }
}

impl FromStr for BigDecimal {
    type Err = ParseBigDecimalError;

    /// Port of `new BigDecimal(String)`: an optional sign, digits with an optional decimal point
    /// (at least one digit overall), and an optional `e`/`E` exponent with optional sign.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseBigDecimalError { input: s.to_string() };
        let bytes = s.as_bytes();
        let mut i = 0;
        let mut negative = false;
        if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
            negative = bytes[i] == b'-';
            i += 1;
        }
        let mut digits = String::new();
        let mut frac_digits: i64 = 0;
        let mut seen_point = false;
        while i < bytes.len() {
            let c = bytes[i];
            if c.is_ascii_digit() {
                digits.push(c as char);
                if seen_point {
                    frac_digits += 1;
                }
            }
            else if c == b'.' && !seen_point {
                seen_point = true;
            }
            else {
                break;
            }
            i += 1;
        }
        if digits.is_empty() {
            return Err(err());
        }
        let mut exponent: i64 = 0;
        if i < bytes.len() {
            if bytes[i] != b'e' && bytes[i] != b'E' {
                return Err(err());
            }
            let exp_str = &s[i + 1..];
            let exp_digits = exp_str.strip_prefix(['+', '-']).unwrap_or(exp_str);
            if exp_digits.is_empty() || !exp_digits.bytes().all(|b| b.is_ascii_digit()) {
                return Err(err());
            }
            exponent = exp_str.parse::<i64>().map_err(|_| err())?;
        }
        let scale = frac_digits - exponent;
        if scale < i32::MIN as i64 || scale > i32::MAX as i64 {
            return Err(err());
        }
        let mut unscaled = BigInt::from_str(&digits).map_err(|_| err())?;
        if negative {
            unscaled = -unscaled;
        }
        Ok(Self::new(unscaled, scale as i32))
    }
}

impl From<i64> for BigDecimal {
    /// Port of `BigDecimal.valueOf(long)`.
    fn from(value: i64) -> Self {
        Self::new(BigInt::from(value), 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bd(s: &str) -> BigDecimal {
        s.parse().unwrap()
    }

    #[test]
    fn parse_matches_java_scale_rules() {
        assert_eq!(bd("1.50"), BigDecimal::new(BigInt::from(150), 2));
        assert_eq!(bd("-2.5E+3"), BigDecimal::new(BigInt::from(-25), -2));
        assert_eq!(bd("1e-3"), BigDecimal::new(BigInt::from(1), 3));
        assert_eq!(bd(".5"), BigDecimal::new(BigInt::from(5), 1));
        assert_eq!(bd("5."), BigDecimal::new(BigInt::from(5), 0));
        assert!("".parse::<BigDecimal>().is_err());
        assert!("1.2.3".parse::<BigDecimal>().is_err());
        assert!("1e".parse::<BigDecimal>().is_err());
        assert!("abc".parse::<BigDecimal>().is_err());
        // equality is scale-sensitive, like Java's BigDecimal.equals
        assert_ne!(bd("2.0"), bd("2.00"));
    }

    #[test]
    fn to_string_matches_java() {
        assert_eq!(bd("0").to_string(), "0");
        assert_eq!(bd("123.450").to_string(), "123.450");
        assert_eq!(bd("-0.00012").to_string(), "-0.00012");
        assert_eq!(bd("0.000001").to_string(), "0.000001");
        assert_eq!(bd("0.0000001").to_string(), "1E-7");
        assert_eq!(bd("1.2345E+10").to_string(), "1.2345E+10");
        assert_eq!(BigDecimal::new(BigInt::from(1), -309).to_string(), "1E+309");
        assert_eq!(bd("1.797693134862316E+308").to_string(), "1.797693134862316E+308");
        assert_eq!(bd("4.9E-324").to_string(), "4.9E-324");
    }

    #[test]
    fn round_half_even_including_carry() {
        let mc = |p| MathContext::new(p, RoundingMode::HalfEven);
        assert_eq!(bd("2.5").round(&mc(1)).to_string(), "2");
        assert_eq!(bd("3.5").round(&mc(1)).to_string(), "4");
        assert_eq!(bd("-2.5").round(&mc(1)).to_string(), "-2");
        assert_eq!(bd("2.51").round(&mc(1)).to_string(), "3");
        assert_eq!(bd("9.99").round(&mc(2)).to_string(), "10");
        assert_eq!(bd("9.99").round(&mc(2)), BigDecimal::new(BigInt::from(10), 0));
        assert_eq!(bd("123456").round(&mc(2)).to_string(), "1.2E+5");
        assert_eq!(bd("1.5").round(&mc(0)), bd("1.5"));
        assert_eq!(bd("1.5").round(&mc(5)), bd("1.5"));
    }

    #[test]
    fn conversions() {
        assert_eq!(bd("123.99").to_big_integer(), BigInt::from(123));
        assert_eq!(bd("-123.99").to_big_integer(), BigInt::from(-123));
        assert_eq!(bd("1.2E+3").to_big_integer(), BigInt::from(1200));
        assert_eq!(bd("0.1").double_value(), 0.1f64);
        assert_eq!(bd("0.1").float_value(), 0.1f32);
        assert_eq!(bd("1E+400").double_value(), f64::INFINITY);
        assert_eq!(bd("-1E-400").double_value(), -0.0);
        assert_eq!(bd("1.5").set_scale(3), bd("1.500"));
        assert_eq!(bd("1.500").set_scale(1), bd("1.5"));
        assert_eq!(bd("-1.5").signum(), -1);
        assert_eq!(bd("0.00").signum(), 0);
        assert_eq!(bd("-120.5").precision(), 4);
        assert_eq!(BigDecimal::from(7i64), bd("7"));
    }

    #[test]
    #[should_panic(expected = "Rounding necessary")]
    fn set_scale_refuses_to_round() {
        bd("1.55").set_scale(1);
    }
}
