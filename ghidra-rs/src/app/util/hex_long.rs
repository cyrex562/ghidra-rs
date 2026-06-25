/// A wrapper around a 64-bit signed integer that displays in hexadecimal format.
///
/// Provides conversion methods compatible with Java's Number interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HexLong {
    value: i64,
}

impl HexLong {
    /// Constructs a new HexLong with the given value.
    ///
    /// # Arguments
    /// * `value` - The 64-bit signed integer value
    pub fn new(value: i64) -> Self {
        HexLong { value }
    }

    /// Returns the underlying 64-bit signed integer value.
    pub fn long_value(&self) -> i64 {
        self.value
    }

    /// Returns the value as a 64-bit floating-point number.
    pub fn double_value(&self) -> f64 {
        self.value as f64
    }

    /// Returns the value as a 32-bit floating-point number.
    pub fn float_value(&self) -> f32 {
        self.value as f32
    }

    /// Returns the value as a 32-bit signed integer, truncating if necessary.
    pub fn int_value(&self) -> i32 {
        self.value as i32
    }
}

impl std::fmt::Display for HexLong {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let hex = HexLong::new(255);
        assert_eq!(hex.long_value(), 255);
    }

    #[test]
    fn test_long_value() {
        let hex = HexLong::new(0x1234567890ABCDEF);
        assert_eq!(hex.long_value(), 0x1234567890ABCDEF);
    }

    #[test]
    fn test_double_value() {
        let hex = HexLong::new(42);
        assert_eq!(hex.double_value(), 42.0);
    }

    #[test]
    fn test_float_value() {
        let hex = HexLong::new(42);
        assert_eq!(hex.float_value(), 42.0);
    }

    #[test]
    fn test_int_value() {
        let hex = HexLong::new(0x123456789ABCDEF0);
        // Lower 32 bits: 0x9ABCDEF0, which as signed i32 is negative
        assert_eq!(hex.int_value(), (0x9ABCDEF0u32 as i32));
    }

    #[test]
    fn test_int_value_truncation() {
        let hex = HexLong::new(0x100000001);
        assert_eq!(hex.int_value(), 1);
    }

    #[test]
    fn test_display_zero() {
        let hex = HexLong::new(0);
        assert_eq!(hex.to_string(), "0x0");
    }

    #[test]
    fn test_display_positive() {
        let hex = HexLong::new(255);
        assert_eq!(hex.to_string(), "0xff");
    }

    #[test]
    fn test_display_large() {
        let hex = HexLong::new(0x1234567890ABCDEF);
        assert_eq!(hex.to_string(), "0x1234567890abcdef");
    }

    #[test]
    fn test_display_negative() {
        let hex = HexLong::new(-1);
        assert_eq!(hex.to_string(), "0xffffffffffffffff");
    }

    #[test]
    fn test_clone() {
        let original = HexLong::new(42);
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_equality() {
        let hex1 = HexLong::new(42);
        let hex2 = HexLong::new(42);
        let hex3 = HexLong::new(43);
        assert_eq!(hex1, hex2);
        assert_ne!(hex1, hex3);
    }

    #[test]
    fn test_ordering() {
        let hex1 = HexLong::new(1);
        let hex2 = HexLong::new(2);
        assert!(hex1 < hex2);
        assert!(hex2 > hex1);
    }
}
