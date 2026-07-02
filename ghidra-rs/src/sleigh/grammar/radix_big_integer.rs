use std::num::ParseIntError;

use rand::Rng;
use thiserror::Error as ThisError;

use super::Location;

/// Errors produced while constructing a [`RadixBigInteger`].
///
/// Mirrors the `NumberFormatException` thrown by the `BigInteger` constructors
/// that `ghidra.sleigh.grammar.RadixBigInteger` extends.
#[derive(Debug, ThisError)]
pub enum RadixBigIntegerError {
    #[error("radix {0} out of range 2..=36")]
    InvalidRadix(u32),
    #[error("invalid digits for radix {radix}")]
    InvalidDigits {
        radix: u32,
        #[source]
        source: ParseIntError,
    },
    #[error("byte array too long to represent as a 128-bit integer (max 16 bytes)")]
    ByteArrayTooLong,
    #[error("zero-length byte array")]
    EmptyByteArray,
}

fn decode_twos_complement(bytes: &[u8]) -> Result<i128, RadixBigIntegerError> {
    if bytes.is_empty() {
        return Err(RadixBigIntegerError::EmptyByteArray);
    }
    if bytes.len() > 16 {
        return Err(RadixBigIntegerError::ByteArrayTooLong);
    }
    let sign_byte = if bytes[0] & 0x80 != 0 { 0xFFu8 } else { 0x00u8 };
    let mut buf = [sign_byte; 16];
    buf[16 - bytes.len()..].copy_from_slice(bytes);
    Ok(i128::from_be_bytes(buf))
}

fn decode_unsigned(bytes: &[u8]) -> Result<u128, RadixBigIntegerError> {
    if bytes.len() > 16 {
        return Err(RadixBigIntegerError::ByteArrayTooLong);
    }
    let mut buf = [0u8; 16];
    buf[16 - bytes.len()..].copy_from_slice(bytes);
    Ok(u128::from_be_bytes(buf))
}

/// Renders `value` in `radix`, mirroring `BigInteger.toString(int)`. An out
/// of range radix silently falls back to base 10, matching the Java method.
fn to_radix_string(value: i128, radix: i32) -> String {
    let radix = if (2..=36).contains(&radix) { radix as u32 } else { 10 };
    if value == 0 {
        return "0".to_string();
    }
    let neg = value < 0;
    let mut n = value.unsigned_abs();
    let mut digits = Vec::new();
    while n > 0 {
        let d = (n % radix as u128) as u32;
        digits.push(std::char::from_digit(d, radix).unwrap());
        n /= radix as u128;
    }
    if neg {
        digits.push('-');
    }
    digits.iter().rev().collect()
}

fn mod_mul(a: u128, b: u128, m: u128) -> u128 {
    (a * b) % m
}

fn mod_pow(base: u128, mut exp: u128, m: u128) -> u128 {
    let mut result = 1u128 % m;
    let mut base = base % m;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mod_mul(result, base, m);
        }
        exp >>= 1;
        if exp > 0 {
            base = mod_mul(base, base, m);
        }
    }
    result
}

const SMALL_PRIMES: [u128; 11] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31];

/// Miller-Rabin primality test. `n` must be small enough that `a * b` cannot
/// overflow `u128` for `a, b < n` -- true for the `n <= 2^64` candidates
/// produced by [`RadixBigInteger::probable_prime`].
fn is_probable_prime(n: u128, rounds: u32, rng: &mut impl Rng) -> bool {
    if n < 2 {
        return false;
    }
    for &p in &SMALL_PRIMES {
        if n == p {
            return true;
        }
        if n % p == 0 {
            return false;
        }
    }
    let mut d = n - 1;
    let mut r = 0u32;
    while d % 2 == 0 {
        d /= 2;
        r += 1;
    }
    'rounds: for _ in 0..rounds {
        let a = rng.gen_range(2..n - 1);
        let mut x = mod_pow(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        for _ in 0..r.saturating_sub(1) {
            x = mod_mul(x, x, n);
            if x == n - 1 {
                continue 'rounds;
            }
        }
        return false;
    }
    true
}

/// A `BigInteger` that remembers the radix it was parsed in and the source
/// [`Location`] it came from.
///
/// Mirrors `ghidra.sleigh.grammar.RadixBigInteger`, which the Sleigh/ANTLR
/// grammar uses to represent integer literals. Java implements this as a
/// subclass of `java.math.BigInteger`; this crate has no arbitrary-precision
/// integer type, so the magnitude is stored as `i128`, matching the
/// established convention for `BigInteger`-backed values elsewhere in the
/// crate (see `Scalar::get_big_integer`). This comfortably covers every
/// actual caller, which narrows parsed literals down to `i64`/`u64`/`i32`.
///
/// The static `RadixBigInteger.parse(IntStream, int, Location, String, int)`
/// factory exists only to translate a `NumberFormatException` into an ANTLR
/// `RecognitionException` for the generated grammar; since this crate has no
/// ANTLR runtime bridge, [`RadixBigInteger::parse`] instead returns a
/// [`RadixBigIntegerError`] directly.
#[derive(Debug, Clone)]
pub struct RadixBigInteger {
    pub location: Location,
    value: i128,
    preferred_radix: i32,
}

impl RadixBigInteger {
    /// Mirrors the static `RadixBigInteger.parse(...)` factory used by the
    /// generated grammar, minus the ANTLR-specific error translation (see
    /// the type-level docs).
    pub fn parse(
        location: Location,
        val: &str,
        radix: u32,
    ) -> Result<Self, RadixBigIntegerError> {
        Self::with_radix(location, val, radix)
    }

    /// Mirrors `RadixBigInteger(Location, byte[])`.
    pub fn from_bytes(location: Location, val: &[u8]) -> Result<Self, RadixBigIntegerError> {
        let value = decode_twos_complement(val)?;
        Ok(Self { location, value, preferred_radix: 10 })
    }

    /// Mirrors `RadixBigInteger(Location, String)`, which parses base 10.
    pub fn from_decimal_str(location: Location, val: &str) -> Result<Self, RadixBigIntegerError> {
        Self::with_radix(location, val, 10)
    }

    /// Mirrors `RadixBigInteger(Location, int, byte[])` (signum + magnitude).
    pub fn from_signum_magnitude(
        location: Location,
        signum: i32,
        magnitude: &[u8],
    ) -> Result<Self, RadixBigIntegerError> {
        let mag = decode_unsigned(magnitude)? as i128;
        let value = match signum.cmp(&0) {
            std::cmp::Ordering::Less => -mag,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => mag,
        };
        Ok(Self { location, value, preferred_radix: 10 })
    }

    /// Mirrors `RadixBigInteger(Location, String, int)`.
    pub fn with_radix(
        location: Location,
        val: &str,
        radix: u32,
    ) -> Result<Self, RadixBigIntegerError> {
        if !(2..=36).contains(&radix) {
            return Err(RadixBigIntegerError::InvalidRadix(radix));
        }
        let value = i128::from_str_radix(val, radix)
            .map_err(|source| RadixBigIntegerError::InvalidDigits { radix, source })?;
        Ok(Self { location, value, preferred_radix: radix as i32 })
    }

    /// Mirrors `RadixBigInteger(Location, int numBits, Random rnd)`: a
    /// uniformly random value in `[0, 2^num_bits)`.
    pub fn random(location: Location, num_bits: u32, rng: &mut impl Rng) -> Self {
        assert!(num_bits <= 127, "num_bits must be <= 127 to fit in a 128-bit integer");
        let value = if num_bits == 0 {
            0
        } else {
            let mask = (1u128 << num_bits) - 1;
            (rng.gen::<u128>() & mask) as i128
        };
        Self { location, value, preferred_radix: 10 }
    }

    /// Mirrors `RadixBigInteger(Location, int bitLength, int certainty, Random rnd)`:
    /// a probable prime with exactly `bit_length` significant bits. `certainty`
    /// is used as the (clamped) number of Miller-Rabin rounds. Bounded to
    /// `bit_length <= 64` so the internal modular arithmetic cannot overflow
    /// `u128`.
    pub fn probable_prime(
        location: Location,
        bit_length: u32,
        certainty: u32,
        rng: &mut impl Rng,
    ) -> Self {
        assert!(
            (2..=64).contains(&bit_length),
            "bit_length must be between 2 and 64"
        );
        let rounds = certainty.clamp(1, 64);
        loop {
            let mut candidate = rng.gen_range(0u128..(1u128 << bit_length));
            candidate |= 1u128 << (bit_length - 1);
            candidate |= 1;
            if is_probable_prime(candidate, rounds, rng) {
                return Self { location, value: candidate as i128, preferred_radix: 10 };
            }
        }
    }

    /// The parsed magnitude. Mirrors the numeric value inherited from `BigInteger`.
    pub fn value(&self) -> i128 {
        self.value
    }

    /// Mirrors `RadixBigInteger.getPreferredRadix`.
    pub fn get_preferred_radix(&self) -> i32 {
        self.preferred_radix
    }

    /// Mirrors `RadixBigInteger.setPreferredRadix`.
    pub fn set_preferred_radix(&mut self, preferred_radix: i32) {
        self.preferred_radix = preferred_radix;
    }

    /// Mirrors `RadixBigInteger.negate`. Note that, like the Java original
    /// (which reconstructs via the `byte[]` constructor), the result's
    /// preferred radix resets to 10 regardless of `self`'s.
    pub fn negate(&self) -> Self {
        Self {
            location: self.location.clone(),
            value: -self.value,
            preferred_radix: 10,
        }
    }
}

impl std::fmt::Display for RadixBigInteger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = to_radix_string(self.value, self.preferred_radix);
        if self.preferred_radix == 16 {
            write!(f, "0x{}", s)
        } else {
            write!(f, "{}", s)
        }
    }
}

impl PartialEq for RadixBigInteger {
    fn eq(&self, other: &Self) -> bool {
        // Mirrors `BigInteger.equals`, which compares only the numeric value
        // -- `RadixBigInteger` does not override `equals()`, so its `location`
        // and `preferredRadix` fields play no part in equality.
        self.value == other.value
    }
}

impl Eq for RadixBigInteger {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn loc() -> Location {
        Location::new("test.sleigh", 1)
    }

    #[test]
    fn parses_decimal_default_radix() {
        let n = RadixBigInteger::from_decimal_str(loc(), "42").unwrap();
        assert_eq!(n.value(), 42);
        assert_eq!(n.get_preferred_radix(), 10);
        assert_eq!(n.to_string(), "42");
    }

    #[test]
    fn parses_negative_decimal() {
        let n = RadixBigInteger::from_decimal_str(loc(), "-7").unwrap();
        assert_eq!(n.value(), -7);
        assert_eq!(n.to_string(), "-7");
    }

    #[test]
    fn parses_hex_and_prefixes_display() {
        let n = RadixBigInteger::with_radix(loc(), "1a", 16).unwrap();
        assert_eq!(n.value(), 26);
        assert_eq!(n.get_preferred_radix(), 16);
        assert_eq!(n.to_string(), "0x1a");
    }

    #[test]
    fn negative_hex_display_matches_java_quirk() {
        // Java's toString() prepends "0x" to the already-signed digit string,
        // producing "0x-1a" rather than "-0x1a".
        let n = RadixBigInteger::with_radix(loc(), "-1a", 16).unwrap();
        assert_eq!(n.value(), -26);
        assert_eq!(n.to_string(), "0x-1a");
    }

    #[test]
    fn parse_matches_with_radix() {
        let n = RadixBigInteger::parse(loc(), "ff", 16).unwrap();
        assert_eq!(n.value(), 255);
    }

    #[test]
    fn parse_invalid_digits_is_error() {
        let err = RadixBigInteger::from_decimal_str(loc(), "not-a-number").unwrap_err();
        assert!(matches!(err, RadixBigIntegerError::InvalidDigits { .. }));
    }

    #[test]
    fn parse_invalid_radix_is_error() {
        let err = RadixBigInteger::with_radix(loc(), "1", 37).unwrap_err();
        assert!(matches!(err, RadixBigIntegerError::InvalidRadix(37)));
    }

    #[test]
    fn from_bytes_decodes_twos_complement() {
        let n = RadixBigInteger::from_bytes(loc(), &[0x00, 0xFF]).unwrap();
        assert_eq!(n.value(), 255);
        assert_eq!(n.get_preferred_radix(), 10);

        let neg = RadixBigInteger::from_bytes(loc(), &[0xFF]).unwrap();
        assert_eq!(neg.value(), -1);
    }

    #[test]
    fn from_bytes_rejects_empty_input() {
        let err = RadixBigInteger::from_bytes(loc(), &[]).unwrap_err();
        assert!(matches!(err, RadixBigIntegerError::EmptyByteArray));
    }

    #[test]
    fn from_bytes_rejects_oversized_input() {
        let err = RadixBigInteger::from_bytes(loc(), &[0u8; 17]).unwrap_err();
        assert!(matches!(err, RadixBigIntegerError::ByteArrayTooLong));
    }

    #[test]
    fn from_signum_magnitude_applies_sign() {
        let pos = RadixBigInteger::from_signum_magnitude(loc(), 1, &[0x2A]).unwrap();
        assert_eq!(pos.value(), 42);

        let negd = RadixBigInteger::from_signum_magnitude(loc(), -1, &[0x2A]).unwrap();
        assert_eq!(negd.value(), -42);

        let zero = RadixBigInteger::from_signum_magnitude(loc(), 0, &[]).unwrap();
        assert_eq!(zero.value(), 0);
    }

    #[test]
    fn negate_flips_sign_and_resets_radix() {
        let n = RadixBigInteger::with_radix(loc(), "1a", 16).unwrap();
        let neg = n.negate();
        assert_eq!(neg.value(), -26);
        assert_eq!(neg.get_preferred_radix(), 10);
        assert_eq!(neg.location, n.location);
    }

    #[test]
    fn set_preferred_radix_changes_display() {
        let mut n = RadixBigInteger::from_decimal_str(loc(), "255").unwrap();
        n.set_preferred_radix(16);
        assert_eq!(n.to_string(), "0xff");
    }

    #[test]
    fn equality_ignores_location_and_radix() {
        let a = RadixBigInteger::from_decimal_str(Location::new("a.sleigh", 1), "10").unwrap();
        let b = RadixBigInteger::with_radix(Location::new("b.sleigh", 2), "a", 16).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn random_respects_bit_bound() {
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..20 {
            let n = RadixBigInteger::random(loc(), 8, &mut rng);
            assert!(n.value() >= 0 && n.value() < 256);
        }
    }

    #[test]
    fn random_zero_bits_is_zero() {
        let mut rng = StdRng::seed_from_u64(2);
        let n = RadixBigInteger::random(loc(), 0, &mut rng);
        assert_eq!(n.value(), 0);
    }

    #[test]
    fn probable_prime_has_top_bit_set_and_is_prime() {
        let mut rng = StdRng::seed_from_u64(3);
        let n = RadixBigInteger::probable_prime(loc(), 16, 20, &mut rng);
        let v = n.value();
        assert!(v > 0);
        let v = v as u128;
        assert!(v >= 1u128 << 15);
        assert!(v < 1u128 << 16);
        assert_eq!(v % 2, 1);

        let mut is_prime = true;
        let mut d = 2u128;
        while d * d <= v {
            if v % d == 0 {
                is_prime = false;
                break;
            }
            d += 1;
        }
        assert!(is_prime, "{v} is not prime");
    }
}
