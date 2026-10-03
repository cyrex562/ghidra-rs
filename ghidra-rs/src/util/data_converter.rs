/// Converts Java-style numeric types to and from their raw form in a byte array.
///
/// Port of `ghidra.util.DataConverter`. The Java interface has one static factory method,
/// `getInstance(boolean)`, that dispatches to the `BigEndianDataConverter` / `LittleEndianDataConverter`
/// singletons; those types are not yet ported (see `PORT_MANIFEST.tsv`), so that factory is
/// deferred until they land rather than stubbed out here.
///
/// `isBigEndian()` was a Java default method that used `instanceof BigEndianDataConverter`,
/// which has no Rust equivalent; it is a required method here so each implementor states its
/// own endianness directly.
///
/// `BigInteger` has no arbitrary-precision counterpart in this crate, so values are represented
/// as `i128`, matching the convention established by `RadixBigInteger` and `Scalar::get_big_integer`.
pub trait DataConverter {
    /// Returns true if this converter is big-endian.
    fn is_big_endian(&self) -> bool;

    /// Get the short value from the beginning of the given byte array.
    fn get_short(&self, b: &[u8]) -> i16 {
        self.get_short_at(b, 0)
    }

    /// Get the short value from the given byte array at the given offset.
    fn get_short_at(&self, b: &[u8], offset: usize) -> i16;

    /// Get the int value from the beginning of the given byte array.
    fn get_int(&self, b: &[u8]) -> i32 {
        self.get_int_at(b, 0)
    }

    /// Get the int value from the given byte array at the given offset.
    fn get_int_at(&self, b: &[u8], offset: usize) -> i32;

    /// Get the long value from the beginning of the given byte array.
    fn get_long(&self, b: &[u8]) -> i64 {
        self.get_long_at(b, 0)
    }

    /// Get the long value from the given byte array at the given offset.
    fn get_long_at(&self, b: &[u8], offset: usize) -> i64;

    /// Get the unsigned value from the beginning of the given byte array using the specified
    /// integer size (1-8), returned as a `u64`.
    fn get_value(&self, b: &[u8], size: usize) -> u64 {
        self.get_value_at(b, 0, size)
    }

    /// Get the unsigned value from the given byte array at the given offset, using the
    /// specified integer size (1-8), returned as a `u64`.
    fn get_value_at(&self, b: &[u8], offset: usize, size: usize) -> u64;

    /// Get the signed, sign-extended value from the beginning of the given byte array using the
    /// specified integer size (1-8).
    fn get_signed_value(&self, b: &[u8], size: usize) -> i64 {
        self.get_signed_value_at(b, 0, size)
    }

    /// Get the signed, sign-extended value from the given byte array at the given offset, using
    /// the specified integer size (1-8).
    fn get_signed_value_at(&self, b: &[u8], offset: usize, size: usize) -> i64 {
        let val = self.get_value_at(b, offset, size) as i64;
        let shift_bits = (8 - size) * 8;
        (val << shift_bits) >> shift_bits
    }

    /// Get the value from the beginning of the given byte array using the specified size.
    fn get_big_integer(&self, b: &[u8], size: usize, signed: bool) -> i128 {
        self.get_big_integer_at(b, 0, size, signed)
    }

    /// Get the value from the given byte array at the given offset, using the specified size.
    fn get_big_integer_at(&self, b: &[u8], offset: usize, size: usize, signed: bool) -> i128;

    // -------------------------------------------------------------------------------

    /// Converts the short value to a new array of bytes.
    fn short_to_bytes(&self, value: i16) -> Vec<u8> {
        let mut bytes = vec![0u8; 2];
        self.put_short_at(&mut bytes, 0, value);
        bytes
    }

    /// Converts the int value to a new array of bytes.
    fn int_to_bytes(&self, value: i32) -> Vec<u8> {
        let mut bytes = vec![0u8; 4];
        self.put_int_at(&mut bytes, 0, value);
        bytes
    }

    /// Converts the long value to a new array of bytes.
    fn long_to_bytes(&self, value: i64) -> Vec<u8> {
        let mut bytes = vec![0u8; 8];
        self.put_long_at(&mut bytes, 0, value);
        bytes
    }

    /// Converts the value to a new array of bytes of the given size.
    fn big_integer_to_bytes(&self, value: i128, size: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; size];
        self.put_big_integer_at(&mut bytes, 0, size, value);
        bytes
    }

    // -------------------------------------------------------------------------------

    /// Writes a short value into the beginning of a byte array.
    fn put_short(&self, b: &mut [u8], value: i16) {
        self.put_short_at(b, 0, value)
    }

    /// Writes a short value into the byte array at the given offset.
    fn put_short_at(&self, b: &mut [u8], offset: usize, value: i16);

    /// Writes an int value into the beginning of a byte array.
    fn put_int(&self, b: &mut [u8], value: i32) {
        self.put_int_at(b, 0, value)
    }

    /// Writes an int value into the byte array at the given offset.
    fn put_int_at(&self, b: &mut [u8], offset: usize, value: i32);

    /// Writes a long value into the beginning of a byte array.
    fn put_long(&self, b: &mut [u8], value: i64) {
        self.put_long_at(b, 0, value)
    }

    /// Writes a long value into the byte array at the given offset.
    fn put_long_at(&self, b: &mut [u8], offset: usize, value: i64) {
        self.put_value_at(value as u64, 8, b, offset)
    }

    /// Writes the least significant `size` bytes of `value` into the byte array at the given
    /// offset.
    fn put_value_at(&self, value: u64, size: usize, b: &mut [u8], offset: usize);

    /// Writes a value of the specified size into the beginning of a byte array.
    fn put_big_integer(&self, b: &mut [u8], size: usize, value: i128) {
        self.put_big_integer_at(b, 0, size, value)
    }

    /// Writes a value of the specified size into the byte array at the given offset.
    fn put_big_integer_at(&self, b: &mut [u8], offset: usize, size: usize, value: i128);

    // --------------------------------------------------------------------------------

    /// Converts the given value to bytes, writing them at the beginning of `b`.
    ///
    /// Alias for [`put_short`](Self::put_short) with reversed argument order, mirroring the
    /// Java `getBytes(short, byte[])` overload.
    fn encode_short(&self, value: i16, b: &mut [u8]) {
        self.put_short_at(b, 0, value)
    }

    /// Converts the given value to bytes, writing them into `b` at `offset`.
    fn encode_short_at(&self, value: i16, b: &mut [u8], offset: usize) {
        self.put_short_at(b, offset, value)
    }

    /// Converts the given value to bytes, writing them at the beginning of `b`.
    fn encode_int(&self, value: i32, b: &mut [u8]) {
        self.put_int_at(b, 0, value)
    }

    /// Converts the given value to bytes, writing them into `b` at `offset`.
    fn encode_int_at(&self, value: i32, b: &mut [u8], offset: usize) {
        self.put_int_at(b, offset, value)
    }

    /// Converts the given value to bytes, writing them at the beginning of `b`.
    fn encode_long(&self, value: i64, b: &mut [u8]) {
        self.put_long_at(b, 0, value)
    }

    /// Converts the given value to bytes, writing them into `b` at `offset`.
    fn encode_long_at(&self, value: i64, b: &mut [u8], offset: usize) {
        self.put_long_at(b, offset, value)
    }

    /// Converts the given value to bytes using the number of least significant bytes specified
    /// by `size`, writing them into `b` at `offset`.
    fn encode_value_at(&self, value: i64, size: usize, b: &mut [u8], offset: usize) {
        self.put_value_at(value as u64, size, b, offset)
    }

    /// Converts the given value to bytes using the specified size, writing them into `b` at
    /// `offset`.
    fn encode_big_integer_at(&self, value: i128, size: usize, b: &mut [u8], offset: usize) {
        self.put_big_integer_at(b, offset, size, value)
    }
}

/// Swap the least-significant bytes (based upon `size`) of `val`.
///
/// Any high-order bytes beyond `size` are 0 in the result.
pub fn swap_bytes(val: u64, size: usize) -> u64 {
    let mut val = val;
    let mut size = size;
    let mut res: u64 = 0;
    while size > 0 {
        res <<= 8;
        res |= val & 0xff;
        val >>= 8;
        size -= 1;
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal big-endian mock, enough to prove the trait is object-safe and that its default
    /// methods behave correctly.
    struct MockBigEndianConverter;

    impl DataConverter for MockBigEndianConverter {
        fn is_big_endian(&self) -> bool {
            true
        }

        fn get_short_at(&self, b: &[u8], offset: usize) -> i16 {
            i16::from_be_bytes([b[offset], b[offset + 1]])
        }

        fn get_int_at(&self, b: &[u8], offset: usize) -> i32 {
            i32::from_be_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]])
        }

        fn get_long_at(&self, b: &[u8], offset: usize) -> i64 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&b[offset..offset + 8]);
            i64::from_be_bytes(buf)
        }

        fn get_value_at(&self, b: &[u8], offset: usize, size: usize) -> u64 {
            let mut val: u64 = 0;
            for i in 0..size {
                val = (val << 8) | b[offset + i] as u64;
            }
            val
        }

        fn get_big_integer_at(&self, b: &[u8], offset: usize, size: usize, signed: bool) -> i128 {
            let unsigned = self.get_value_at(b, offset, size) as i128;
            if signed && size < 16 && size > 0 {
                let shift_bits = (16 - size) * 8;
                (unsigned << shift_bits) >> shift_bits
            }
            else {
                unsigned
            }
        }

        fn put_short_at(&self, b: &mut [u8], offset: usize, value: i16) {
            b[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
        }

        fn put_int_at(&self, b: &mut [u8], offset: usize, value: i32) {
            b[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }

        fn put_value_at(&self, value: u64, size: usize, b: &mut [u8], offset: usize) {
            for i in 0..size {
                b[offset + size - 1 - i] = (value >> (8 * i)) as u8;
            }
        }

        fn put_big_integer_at(&self, b: &mut [u8], offset: usize, size: usize, value: i128) {
            for i in 0..size {
                b[offset + size - 1 - i] = (value >> (8 * i)) as u8;
            }
        }
    }

    #[test]
    fn is_object_safe_as_trait_object() {
        let converter: Box<dyn DataConverter> = Box::new(MockBigEndianConverter);
        assert!(converter.is_big_endian());
    }

    #[test]
    fn get_short_reads_big_endian() {
        let converter = MockBigEndianConverter;
        assert_eq!(converter.get_short(&[0x01, 0x02]), 0x0102);
    }

    #[test]
    fn get_int_at_offset() {
        let converter = MockBigEndianConverter;
        let b = [0xff, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(converter.get_int_at(&b, 1), 1);
    }

    #[test]
    fn put_short_round_trips_through_get_short() {
        let converter = MockBigEndianConverter;
        let mut b = [0u8; 2];
        converter.put_short(&mut b, -1);
        assert_eq!(converter.get_short(&b), -1);
    }

    #[test]
    fn short_to_bytes_matches_put_short() {
        let converter = MockBigEndianConverter;
        assert_eq!(converter.short_to_bytes(0x0102), vec![0x01, 0x02]);
    }

    #[test]
    fn get_signed_value_sign_extends() {
        let converter = MockBigEndianConverter;
        // 0xff as a 1-byte value is -1 when signed, 255 when unsigned.
        let b = [0xff];
        assert_eq!(converter.get_value(&b, 1), 0xff);
        assert_eq!(converter.get_signed_value(&b, 1), -1);
    }

    #[test]
    fn put_long_default_delegates_to_put_value_at() {
        let converter = MockBigEndianConverter;
        let mut b = [0u8; 8];
        converter.put_long(&mut b, 0x0102030405060708);
        assert_eq!(converter.get_long(&b), 0x0102030405060708);
    }

    #[test]
    fn big_integer_round_trip_signed() {
        let converter = MockBigEndianConverter;
        let bytes = converter.big_integer_to_bytes(-1, 4);
        assert_eq!(bytes, vec![0xff, 0xff, 0xff, 0xff]);
        assert_eq!(converter.get_big_integer(&bytes, 4, true), -1);
        assert_eq!(converter.get_big_integer(&bytes, 4, false), 0xffff_ffff);
    }

    #[test]
    fn encode_short_matches_put_short() {
        let converter = MockBigEndianConverter;
        let mut a = [0u8; 2];
        let mut c = [0u8; 2];
        converter.put_short(&mut a, 0x1234);
        converter.encode_short(0x1234, &mut c);
        assert_eq!(a, c);
    }

    #[test]
    fn swap_bytes_reverses_least_significant_bytes() {
        assert_eq!(swap_bytes(0x0000_0000_0102_0304, 4), 0x0000_0000_0403_0201);
    }

    #[test]
    fn swap_bytes_zero_size_is_zero() {
        assert_eq!(swap_bytes(0xdead_beef, 0), 0);
    }
}
