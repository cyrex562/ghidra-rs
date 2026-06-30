use std::fmt;
use std::hash::{Hash, Hasher};

/// Immutable integer stored in an arbitrary number of bits (0..64), along with a preferred
/// signed-ness attribute.
///
/// A bit-length of 0 is only permitted when the value is also 0.
#[derive(Clone, Copy, Debug)]
pub struct Scalar {
    /// The underlying value with bits above `bit_length` masked to zero.
    value: u64,
    bit_length: u8,
    signed: bool,
}

impl Scalar {
    /// Construct a new signed scalar.
    ///
    /// `bit_length` must be 1..=64, or 0 if `value` is also 0.
    /// Bits above `bit_length` in `value` are masked away.
    pub fn new(bit_length: u8, value: i64) -> Self {
        Self::new_with_signedness(bit_length, value, true)
    }

    /// Construct a new scalar with explicit signed-ness.
    ///
    /// `bit_length` must be 1..=64, or 0 if `value` is also 0.
    /// Bits above `bit_length` in `value` are masked away.
    pub fn new_with_signedness(bit_length: u8, value: i64, signed: bool) -> Self {
        if !(bit_length == 0 && value == 0) && (bit_length < 1 || bit_length > 64) {
            panic!("Bit length must be >= 1 and <= 64");
        }
        let masked = if bit_length == 0 {
            0u64
        } else if bit_length == 64 {
            value as u64
        } else {
            let v = value as u64;
            let shift = (64 - bit_length) as u32;
            // mirror Java: (value << unusedBits) >>> unusedBits
            (v << shift) >> shift
        };
        Self { value: masked, bit_length, signed }
    }

    /// Returns true if this scalar was created as a signed value.
    pub fn is_signed(&self) -> bool {
        self.signed
    }

    /// Returns the value sign-extended to a full `i64`.
    pub fn get_signed_value(&self) -> i64 {
        if self.bit_length == 0 || self.bit_length == 64 {
            return self.value as i64;
        }
        let shift = (64 - self.bit_length) as u32;
        // shift left to place bit_length-1 at MSB, arithmetic shift right to sign-extend
        ((self.value as i64) << shift) >> shift
    }

    /// Returns the underlying value as an unsigned `u64` (no sign extension).
    pub fn get_unsigned_value(&self) -> u64 {
        self.value
    }

    /// Returns the value in its preferred signed-ness.
    ///
    /// Equivalent to `get_signed_value()` for signed scalars and `get_unsigned_value()` cast
    /// to `i64` for unsigned scalars.
    pub fn get_value(&self) -> i64 {
        if self.signed {
            self.get_signed_value()
        } else {
            self.value as i64
        }
    }

    /// Returns the value using the given signedness, overriding the instance's preferred mode.
    pub fn get_value_with(&self, signed_override: bool) -> i64 {
        if signed_override {
            self.get_signed_value()
        } else {
            self.value as i64
        }
    }

    /// Returns the number of bits in this scalar.
    pub fn bit_length(&self) -> u8 {
        self.bit_length
    }

    /// Returns true if bit `n` (0 = LSB) is set.
    ///
    /// # Panics
    ///
    /// Panics if `n >= bit_length()`.
    pub fn test_bit(&self, n: u32) -> bool {
        if self.bit_length == 0 || n >= self.bit_length as u32 {
            panic!("bit index {} out of range for bit_length {}", n, self.bit_length);
        }
        (self.value & (1u64 << n)) != 0
    }

    /// Returns a big-endian byte array sized to hold `bit_length()` bits.
    pub fn byte_array_value(&self) -> Vec<u8> {
        if self.bit_length == 0 {
            return Vec::new();
        }
        let num_bytes = ((self.bit_length as usize - 1) / 8) + 1;
        let mut tmp = self.get_value() as u64;
        let mut data = vec![0u8; num_bytes];
        for i in (0..num_bytes).rev() {
            data[i] = tmp as u8;
            tmp >>= 8;
        }
        data
    }

    /// Returns a 128-bit signed integer representing this scalar's mathematical value,
    /// respecting its signed-ness.
    ///
    /// Equivalent to Java's `getBigInteger()`.
    ///
    /// # Panics
    ///
    /// Panics if `bit_length()` is 0.
    pub fn get_big_integer(&self) -> i128 {
        let negative = self.signed && self.test_bit(self.bit_length as u32 - 1);
        if negative {
            self.get_signed_value() as i128
        } else {
            self.value as i128
        }
    }

    /// Returns a formatted string representation of this scalar.
    ///
    /// `radix` must be 2, 8, 10, or 16. `show_sign` is forced to `false` for unsigned
    /// scalars. For non-decimal radices a leading `"-"` is emitted before `pre` when
    /// the value is negative and `show_sign` is true.
    pub fn to_string_formatted(
        &self,
        radix: u32,
        zero_padded: bool,
        show_sign: bool,
        pre: &str,
        post: &str,
    ) -> String {
        let show_sign = show_sign && self.signed;
        let mut buf = String::with_capacity(32);

        let digits: String;

        if self.bit_length == 64 && !self.signed {
            // Unsigned 64-bit: must format as u64 to avoid signed-decimal wrapping.
            digits = match radix {
                2 => format!("{:b}", self.value),
                8 => format!("{:o}", self.value),
                10 => format!("{}", self.value),
                16 => format!("{:x}", self.value),
                _ => panic!("Invalid radix: {}", radix),
            };
        } else if radix == 10 {
            let val = if show_sign {
                self.get_signed_value()
            } else {
                self.value as i64
            };
            digits = format!("{}", val);
        } else {
            let signed_val = if show_sign {
                self.get_signed_value()
            } else {
                self.value as i64
            };
            // For non-decimal output, prepend '-' before `pre`, then format the magnitude.
            let abs_val: u64 = if show_sign && signed_val < 0 {
                buf.push('-');
                // Use i128 to safely negate i64::MIN without overflow.
                (signed_val as i128).wrapping_neg() as u64
            } else {
                signed_val as u64
            };
            digits = match radix {
                2 => format!("{:b}", abs_val),
                8 => format!("{:o}", abs_val),
                16 => format!("{:x}", abs_val),
                _ => panic!("Invalid radix: {}", radix),
            };
        }

        buf.push_str(pre);
        if zero_padded {
            let num_digits = self.get_digits(radix);
            for _ in digits.len()..num_digits {
                buf.push('0');
            }
        }
        buf.push_str(&digits);
        buf.push_str(post);
        buf
    }

    fn get_digits(&self, radix: u32) -> usize {
        if self.bit_length == 0 {
            return 0;
        }
        match radix {
            2 => self.bit_length as usize,
            8 => (self.bit_length as usize - 1) / 3 + 1,
            16 => (self.bit_length as usize - 1) / 4 + 1,
            _ => 0,
        }
    }
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_formatted(16, false, true, "0x", ""))
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        let v = self.get_value();
        if v != other.get_value() {
            return false;
        }
        // For negative values where at least one operand is 64-bit, signed-ness must agree.
        if v < 0 && (self.bit_length == 64 || other.bit_length == 64) {
            return self.signed == other.signed;
        }
        true
    }
}

impl Eq for Scalar {}

// Java's hashCode() hashes `value` (the raw unsigned field), not getValue().  That
// technically violates the hash/equals contract for some edge-case pairs, but we
// preserve it here by hashing get_value() so that the Rust contract *is* upheld
// while staying as close to the Java semantics as possible.
impl Hash for Scalar {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_value().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // --- construction ---

    #[test]
    fn new_signed_masks_upper_bits() {
        let s = Scalar::new(8, 0x1FF_i64);
        assert_eq!(s.get_unsigned_value(), 0xFF);
    }

    #[test]
    fn new_with_signedness_unsigned() {
        let s = Scalar::new_with_signedness(8, 0xFF_i64, false);
        assert!(!s.is_signed());
        assert_eq!(s.get_unsigned_value(), 0xFF);
    }

    #[test]
    #[should_panic]
    fn new_invalid_bit_length() {
        let _ = Scalar::new(65, 0);
    }

    #[test]
    #[should_panic]
    fn new_zero_bitlen_nonzero_value() {
        let _ = Scalar::new(0, 1);
    }

    #[test]
    fn zero_bit_scalar_is_valid() {
        let s = Scalar::new(0, 0);
        assert_eq!(s.bit_length(), 0);
        assert_eq!(s.get_unsigned_value(), 0);
    }

    // --- get_signed_value / get_unsigned_value ---

    #[test]
    fn get_signed_value_positive() {
        let s = Scalar::new(8, 127);
        assert_eq!(s.get_signed_value(), 127);
    }

    #[test]
    fn get_signed_value_negative() {
        // 0xFF in 8-bit signed is -1
        let s = Scalar::new(8, 0xFF_i64);
        assert_eq!(s.get_signed_value(), -1);
    }

    #[test]
    fn get_signed_value_min_neg() {
        // bit 7 of 0x80 is set → -128
        let s = Scalar::new(8, 0x80_i64);
        assert_eq!(s.get_signed_value(), -128);
    }

    #[test]
    fn get_signed_value_64bit() {
        let s = Scalar::new(64, i64::MIN);
        assert_eq!(s.get_signed_value(), i64::MIN);
    }

    #[test]
    fn get_unsigned_value_always_nonneg_bits() {
        let s = Scalar::new(8, 0xFF_i64);
        assert_eq!(s.get_unsigned_value(), 255);
    }

    // --- get_value ---

    #[test]
    fn get_value_signed_returns_signed() {
        let s = Scalar::new(8, 0xFF_i64); // signed by default
        assert_eq!(s.get_value(), -1);
    }

    #[test]
    fn get_value_unsigned_returns_raw() {
        let s = Scalar::new_with_signedness(8, 0xFF_i64, false);
        assert_eq!(s.get_value(), 0xFF);
    }

    #[test]
    fn get_value_with_override() {
        let s = Scalar::new_with_signedness(8, 0xFF_i64, false);
        assert_eq!(s.get_value_with(true), -1);
        assert_eq!(s.get_value_with(false), 0xFF);
    }

    // --- test_bit ---

    #[test]
    fn test_bit_basic() {
        let s = Scalar::new(8, 0b10101010_i64);
        assert!(!s.test_bit(0));
        assert!(s.test_bit(1));
        assert!(!s.test_bit(2));
        assert!(s.test_bit(7));
    }

    #[test]
    #[should_panic]
    fn test_bit_out_of_range() {
        let s = Scalar::new(8, 0xFF_i64);
        let _ = s.test_bit(8);
    }

    #[test]
    #[should_panic]
    fn test_bit_zero_bitlen() {
        let s = Scalar::new(0, 0);
        let _ = s.test_bit(0);
    }

    // --- byte_array_value ---

    #[test]
    fn byte_array_value_one_byte() {
        let s = Scalar::new(8, 0xAB_i64);
        assert_eq!(s.byte_array_value(), vec![0xAB]);
    }

    #[test]
    fn byte_array_value_two_bytes() {
        let s = Scalar::new_with_signedness(16, 0x1234, false);
        assert_eq!(s.byte_array_value(), vec![0x12, 0x34]);
    }

    #[test]
    fn byte_array_value_signed_negative() {
        // -1 as signed 16-bit = 0xFFFF
        let s = Scalar::new(16, -1);
        assert_eq!(s.byte_array_value(), vec![0xFF, 0xFF]);
    }

    #[test]
    fn byte_array_value_zero_bitlen() {
        let s = Scalar::new(0, 0);
        assert!(s.byte_array_value().is_empty());
    }

    // --- get_big_integer ---

    #[test]
    fn get_big_integer_positive() {
        let s = Scalar::new(8, 127);
        assert_eq!(s.get_big_integer(), 127);
    }

    #[test]
    fn get_big_integer_signed_negative() {
        let s = Scalar::new(8, 0xFF_i64);
        assert_eq!(s.get_big_integer(), -1);
    }

    #[test]
    fn get_big_integer_unsigned_max_64() {
        let s = Scalar::new_with_signedness(64, -1_i64, false);
        assert_eq!(s.get_big_integer(), u64::MAX as i128);
    }

    #[test]
    fn get_big_integer_i64_min() {
        let s = Scalar::new(64, i64::MIN);
        assert_eq!(s.get_big_integer(), i64::MIN as i128);
    }

    // --- to_string_formatted ---

    #[test]
    fn display_default_positive() {
        let s = Scalar::new_with_signedness(8, 0x42, false);
        assert_eq!(format!("{}", s), "0x42");
    }

    #[test]
    fn display_default_signed_negative() {
        let s = Scalar::new(8, 0xFF_i64); // -1
        assert_eq!(format!("{}", s), "-0x1");
    }

    #[test]
    fn display_default_signed_positive() {
        let s = Scalar::new(8, 10);
        assert_eq!(format!("{}", s), "0xa");
    }

    #[test]
    fn to_string_formatted_decimal() {
        let s = Scalar::new(8, 0xFF_i64); // signed -1
        assert_eq!(s.to_string_formatted(10, false, true, "", ""), "-1");
    }

    #[test]
    fn to_string_formatted_decimal_unsigned() {
        let s = Scalar::new_with_signedness(8, 0xFF_i64, false);
        assert_eq!(s.to_string_formatted(10, false, false, "", ""), "255");
    }

    #[test]
    fn to_string_formatted_binary_zero_padded() {
        let s = Scalar::new_with_signedness(8, 5, false);
        // 5 = 0b00000101
        assert_eq!(s.to_string_formatted(2, true, false, "", ""), "00000101");
    }

    #[test]
    fn to_string_formatted_octal() {
        let s = Scalar::new_with_signedness(8, 0xFF_i64, false);
        assert_eq!(s.to_string_formatted(8, false, false, "", ""), "377");
    }

    #[test]
    fn to_string_formatted_hex_prefix_suffix() {
        let s = Scalar::new_with_signedness(16, 0xABCD, false);
        assert_eq!(s.to_string_formatted(16, false, false, "0x", "h"), "0xabcdh");
    }

    #[test]
    fn to_string_formatted_unsigned_64bit_decimal() {
        let s = Scalar::new_with_signedness(64, -1_i64, false);
        assert_eq!(
            s.to_string_formatted(10, false, false, "", ""),
            "18446744073709551615"
        );
    }

    #[test]
    fn to_string_formatted_unsigned_64bit_hex() {
        let s = Scalar::new_with_signedness(64, -1_i64, false);
        assert_eq!(
            s.to_string_formatted(16, false, false, "0x", ""),
            "0xffffffffffffffff"
        );
    }

    #[test]
    fn to_string_formatted_sign_forced_false_for_unsigned() {
        // show_sign=true is ignored for unsigned scalars
        let s = Scalar::new_with_signedness(8, 0xFF_i64, false);
        assert_eq!(s.to_string_formatted(16, false, true, "0x", ""), "0xff");
    }

    #[test]
    fn to_string_formatted_i64_min_hex() {
        let s = Scalar::new(64, i64::MIN);
        assert_eq!(
            s.to_string_formatted(16, false, true, "0x", ""),
            "-0x8000000000000000"
        );
    }

    // --- PartialEq ---

    #[test]
    fn eq_same_value_different_bitlen() {
        let a = Scalar::new(8, 0xFF_i64);  // -1
        let b = Scalar::new(16, 0xFFFF_i64); // -1
        assert_eq!(a, b);
    }

    #[test]
    fn eq_different_preferred_value() {
        let a = Scalar::new(8, 0xFF_i64);      // signed → -1
        let b = Scalar::new_with_signedness(8, 0xFF_i64, false); // unsigned → 255
        assert_ne!(a, b);
    }

    #[test]
    fn eq_64bit_negative_signed_vs_unsigned() {
        // Both have get_value() == -1, but signedness differs at 64 bits.
        let a = Scalar::new(64, -1_i64);
        let b = Scalar::new_with_signedness(64, -1_i64, false);
        assert_ne!(a, b);
    }

    #[test]
    fn eq_64bit_same_sign_same_value() {
        let a = Scalar::new(64, -42_i64);
        let b = Scalar::new(64, -42_i64);
        assert_eq!(a, b);
    }

    // --- Hash ---

    #[test]
    fn hash_equal_scalars_same_bucket() {
        let a = Scalar::new(8, 0xFF_i64);
        let b = Scalar::new(16, 0xFFFF_i64);
        assert_eq!(a, b);
        let mut set = HashSet::new();
        set.insert(a);
        // b equals a, so the set should recognise it
        assert!(set.contains(&b));
    }
}
