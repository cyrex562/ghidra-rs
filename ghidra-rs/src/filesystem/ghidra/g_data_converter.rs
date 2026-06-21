//! Byte-order-aware conversion between byte slices and primitive integer types.
//!
//! Mirrors `mobiledevices.dmg.ghidra.GDataConverter` from the original Ghidra source.

/// Converts between byte slices and primitive integer types in a fixed byte order.
///
/// The "at-offset" variants are the required minimum; zero-offset and
/// return-by-value forms have default implementations built on them.
///
/// Mirrors the `GDataConverter` Java interface — `get_short_at` / `get_int_at` /
/// `get_long_at` sign-extend from the most-significant byte exactly as the Java
/// impls do; `get_value_at` zero-extends (matches `getValue(byte[], int, int)`).
pub trait GDataConverter {
    /// Reads a `i16` from `b` at `offset` in the implementor's byte order.
    ///
    /// # Panics
    /// Panics if `b.len() < offset + 2`.
    fn get_short_at(&self, b: &[u8], offset: usize) -> i16;

    /// Reads a `i32` from `b` at `offset`.
    ///
    /// # Panics
    /// Panics if `b.len() < offset + 4`.
    fn get_int_at(&self, b: &[u8], offset: usize) -> i32;

    /// Reads a `i64` from `b` at `offset`.
    ///
    /// # Panics
    /// Panics if `b.len() < offset + 8`.
    fn get_long_at(&self, b: &[u8], offset: usize) -> i64;

    /// Reads `size` bytes from `b` at `offset`, zero-extended into a `i64`.
    ///
    /// `size` must be 1–8. Panics if `b.len() < offset + size` or `size > 8`.
    fn get_value_at(&self, b: &[u8], offset: usize, size: usize) -> i64;

    /// Writes `value` into `b` at `offset` in the implementor's byte order.
    ///
    /// # Panics
    /// Panics if `b.len() < offset + 2`.
    fn put_short_at(&self, b: &mut [u8], offset: usize, value: i16);

    /// Writes `value` into `b` at `offset`.
    ///
    /// # Panics
    /// Panics if `b.len() < offset + 4`.
    fn put_int_at(&self, b: &mut [u8], offset: usize, value: i32);

    /// Writes `value` into `b` at `offset`.
    ///
    /// # Panics
    /// Panics if `b.len() < offset + 8`.
    fn put_long_at(&self, b: &mut [u8], offset: usize, value: i64);

    /// Writes the `size` least-significant bytes of `value` into `b` at `offset`.
    ///
    /// `size` must be 1–8. Panics if `b.len() < offset + size` or `size > 8`.
    fn put_long_sized(&self, b: &mut [u8], offset: usize, value: i64, size: usize);

    // ── zero-offset convenience defaults ────────────────────────────────────

    /// Reads a `i16` from `b` at offset 0.
    fn get_short(&self, b: &[u8]) -> i16 {
        self.get_short_at(b, 0)
    }

    /// Reads a `i32` from `b` at offset 0.
    fn get_int(&self, b: &[u8]) -> i32 {
        self.get_int_at(b, 0)
    }

    /// Reads a `i64` from `b` at offset 0.
    fn get_long(&self, b: &[u8]) -> i64 {
        self.get_long_at(b, 0)
    }

    /// Reads `size` bytes from `b` at offset 0, zero-extended into a `i64`.
    fn get_value(&self, b: &[u8], size: usize) -> i64 {
        self.get_value_at(b, 0, size)
    }

    /// Writes `value` into `b` at offset 0.
    fn put_short(&self, b: &mut [u8], value: i16) {
        self.put_short_at(b, 0, value)
    }

    /// Writes `value` into `b` at offset 0.
    fn put_int(&self, b: &mut [u8], value: i32) {
        self.put_int_at(b, 0, value)
    }

    /// Writes `value` into `b` at offset 0.
    fn put_long(&self, b: &mut [u8], value: i64) {
        self.put_long_at(b, 0, value)
    }

    // ── return-by-value convenience defaults ─────────────────────────────────

    /// Returns `value` encoded as a 2-byte array in the implementor's byte order.
    fn short_to_bytes(&self, value: i16) -> [u8; 2] {
        let mut b = [0u8; 2];
        self.put_short_at(&mut b, 0, value);
        b
    }

    /// Returns `value` encoded as a 4-byte array in the implementor's byte order.
    fn int_to_bytes(&self, value: i32) -> [u8; 4] {
        let mut b = [0u8; 4];
        self.put_int_at(&mut b, 0, value);
        b
    }

    /// Returns `value` encoded as an 8-byte array in the implementor's byte order.
    fn long_to_bytes(&self, value: i64) -> [u8; 8] {
        let mut b = [0u8; 8];
        self.put_long_at(&mut b, 0, value);
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── minimal test implementations ─────────────────────────────────────────

    struct BigEndian;

    impl GDataConverter for BigEndian {
        fn get_short_at(&self, b: &[u8], offset: usize) -> i16 {
            i16::from_be_bytes([b[offset], b[offset + 1]])
        }
        fn get_int_at(&self, b: &[u8], offset: usize) -> i32 {
            i32::from_be_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]])
        }
        fn get_long_at(&self, b: &[u8], offset: usize) -> i64 {
            i64::from_be_bytes([
                b[offset],
                b[offset + 1],
                b[offset + 2],
                b[offset + 3],
                b[offset + 4],
                b[offset + 5],
                b[offset + 6],
                b[offset + 7],
            ])
        }
        fn get_value_at(&self, b: &[u8], offset: usize, size: usize) -> i64 {
            assert!(size <= 8, "size exceeds sizeof long: {size}");
            let mut val: i64 = 0;
            for i in 0..size {
                val = (val << 8) | (b[offset + i] as i64);
            }
            val
        }
        fn put_short_at(&self, b: &mut [u8], offset: usize, value: i16) {
            b[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
        }
        fn put_int_at(&self, b: &mut [u8], offset: usize, value: i32) {
            b[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        fn put_long_at(&self, b: &mut [u8], offset: usize, value: i64) {
            b[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        fn put_long_sized(&self, b: &mut [u8], offset: usize, value: i64, size: usize) {
            assert!(size <= 8, "size exceeds sizeof long: {size}");
            let all = value.to_be_bytes();
            b[offset..offset + size].copy_from_slice(&all[8 - size..]);
        }
    }

    struct LittleEndian;

    impl GDataConverter for LittleEndian {
        fn get_short_at(&self, b: &[u8], offset: usize) -> i16 {
            i16::from_le_bytes([b[offset], b[offset + 1]])
        }
        fn get_int_at(&self, b: &[u8], offset: usize) -> i32 {
            i32::from_le_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]])
        }
        fn get_long_at(&self, b: &[u8], offset: usize) -> i64 {
            i64::from_le_bytes([
                b[offset],
                b[offset + 1],
                b[offset + 2],
                b[offset + 3],
                b[offset + 4],
                b[offset + 5],
                b[offset + 6],
                b[offset + 7],
            ])
        }
        fn get_value_at(&self, b: &[u8], offset: usize, size: usize) -> i64 {
            assert!(size <= 8, "size exceeds sizeof long: {size}");
            let mut val: i64 = 0;
            for i in (0..size).rev() {
                val = (val << 8) | (b[offset + i] as i64);
            }
            val
        }
        fn put_short_at(&self, b: &mut [u8], offset: usize, value: i16) {
            b[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        fn put_int_at(&self, b: &mut [u8], offset: usize, value: i32) {
            b[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn put_long_at(&self, b: &mut [u8], offset: usize, value: i64) {
            b[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        fn put_long_sized(&self, b: &mut [u8], offset: usize, value: i64, size: usize) {
            assert!(size <= 8, "size exceeds sizeof long: {size}");
            let all = value.to_le_bytes();
            b[offset..offset + size].copy_from_slice(&all[..size]);
        }
    }

    // ── get_short ─────────────────────────────────────────────────────────────

    #[test]
    fn get_short_be_positive() {
        assert_eq!(BigEndian.get_short(&[0x00, 0x01]), 1i16);
    }

    #[test]
    fn get_short_be_negative() {
        assert_eq!(BigEndian.get_short(&[0xFF, 0xFF]), -1i16);
    }

    #[test]
    fn get_short_le_positive() {
        assert_eq!(LittleEndian.get_short(&[0x01, 0x00]), 1i16);
    }

    #[test]
    fn get_short_le_negative() {
        assert_eq!(LittleEndian.get_short(&[0xFF, 0xFF]), -1i16);
    }

    #[test]
    fn get_short_at_offset() {
        let buf = [0x00, 0x00, 0x01, 0x02];
        assert_eq!(BigEndian.get_short_at(&buf, 2), 0x0102i16);
    }

    // ── get_int ───────────────────────────────────────────────────────────────

    #[test]
    fn get_int_be_positive() {
        assert_eq!(BigEndian.get_int(&[0x00, 0x00, 0x00, 0x07]), 7i32);
    }

    #[test]
    fn get_int_be_negative() {
        assert_eq!(BigEndian.get_int(&[0xFF, 0xFF, 0xFF, 0xFF]), -1i32);
    }

    #[test]
    fn get_int_le_positive() {
        assert_eq!(LittleEndian.get_int(&[0x05, 0x00, 0x00, 0x00]), 5i32);
    }

    #[test]
    fn get_int_at_offset() {
        let buf = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A];
        assert_eq!(BigEndian.get_int_at(&buf, 4), 10i32);
    }

    // ── get_long ──────────────────────────────────────────────────────────────

    #[test]
    fn get_long_be_positive() {
        let mut b = [0u8; 8];
        b[7] = 1;
        assert_eq!(BigEndian.get_long(&b), 1i64);
    }

    #[test]
    fn get_long_le_positive() {
        let mut b = [0u8; 8];
        b[0] = 1;
        assert_eq!(LittleEndian.get_long(&b), 1i64);
    }

    #[test]
    fn get_long_be_negative() {
        assert_eq!(BigEndian.get_long(&[0xFF; 8]), -1i64);
    }

    #[test]
    fn get_long_at_offset() {
        let mut buf = [0u8; 16];
        buf[15] = 9;
        assert_eq!(BigEndian.get_long_at(&buf, 8), 9i64);
    }

    // ── get_value (zero-extended) ─────────────────────────────────────────────

    #[test]
    fn get_value_be_single_byte() {
        assert_eq!(BigEndian.get_value(&[0xFF], 1), 0xFF);
    }

    #[test]
    fn get_value_be_two_bytes() {
        assert_eq!(BigEndian.get_value(&[0x01, 0x02], 2), 0x0102);
    }

    #[test]
    fn get_value_le_two_bytes() {
        assert_eq!(LittleEndian.get_value(&[0x02, 0x01], 2), 0x0102);
    }

    #[test]
    fn get_value_at_offset() {
        let buf = [0x00, 0x00, 0x01, 0x02, 0x03];
        assert_eq!(BigEndian.get_value_at(&buf, 2, 3), 0x010203);
    }

    // ── put_short ─────────────────────────────────────────────────────────────

    #[test]
    fn put_short_be_round_trip() {
        let mut b = [0u8; 2];
        BigEndian.put_short(&mut b, 0x0102);
        assert_eq!(b, [0x01, 0x02]);
        assert_eq!(BigEndian.get_short(&b), 0x0102);
    }

    #[test]
    fn put_short_le_round_trip() {
        let mut b = [0u8; 2];
        LittleEndian.put_short(&mut b, 0x0102);
        assert_eq!(b, [0x02, 0x01]);
        assert_eq!(LittleEndian.get_short(&b), 0x0102);
    }

    #[test]
    fn put_short_at_offset() {
        let mut b = [0u8; 4];
        BigEndian.put_short_at(&mut b, 2, 0x0304);
        assert_eq!(b, [0x00, 0x00, 0x03, 0x04]);
    }

    // ── put_int ───────────────────────────────────────────────────────────────

    #[test]
    fn put_int_be_round_trip() {
        let mut b = [0u8; 4];
        BigEndian.put_int(&mut b, 0x01020304);
        assert_eq!(b, [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(BigEndian.get_int(&b), 0x01020304);
    }

    #[test]
    fn put_int_le_round_trip() {
        let mut b = [0u8; 4];
        LittleEndian.put_int(&mut b, 0x01020304);
        assert_eq!(b, [0x04, 0x03, 0x02, 0x01]);
        assert_eq!(LittleEndian.get_int(&b), 0x01020304);
    }

    #[test]
    fn put_int_at_offset() {
        let mut b = [0u8; 8];
        BigEndian.put_int_at(&mut b, 4, 0x0A0B0C0D);
        assert_eq!(&b[4..8], &[0x0A, 0x0B, 0x0C, 0x0D]);
    }

    // ── put_long ──────────────────────────────────────────────────────────────

    #[test]
    fn put_long_be_round_trip() {
        let mut b = [0u8; 8];
        BigEndian.put_long(&mut b, 0x0102030405060708i64);
        assert_eq!(b, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(BigEndian.get_long(&b), 0x0102030405060708i64);
    }

    #[test]
    fn put_long_le_round_trip() {
        let mut b = [0u8; 8];
        LittleEndian.put_long(&mut b, 0x0102030405060708i64);
        assert_eq!(b, [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        assert_eq!(LittleEndian.get_long(&b), 0x0102030405060708i64);
    }

    #[test]
    fn put_long_at_offset() {
        let mut b = [0u8; 16];
        BigEndian.put_long_at(&mut b, 8, 0x0102030405060708i64);
        assert_eq!(&b[8..16], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    // ── put_long_sized ────────────────────────────────────────────────────────

    #[test]
    fn put_long_sized_be_writes_lsb() {
        let mut b = [0u8; 4];
        // Write the 3 LSBs of 0x00010203 in big-endian at offset 1
        BigEndian.put_long_sized(&mut b, 1, 0x00010203, 3);
        assert_eq!(b, [0x00, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn put_long_sized_le_writes_lsb() {
        let mut b = [0u8; 4];
        LittleEndian.put_long_sized(&mut b, 0, 0x00010203, 3);
        assert_eq!(&b[..3], &[0x03, 0x02, 0x01]);
    }

    #[test]
    fn put_long_sized_full_8_bytes() {
        let mut be_b = [0u8; 8];
        let mut le_b = [0u8; 8];
        BigEndian.put_long_sized(&mut be_b, 0, 0x0102030405060708i64, 8);
        LittleEndian.put_long_sized(&mut le_b, 0, 0x0102030405060708i64, 8);
        assert_eq!(BigEndian.get_long(&be_b), 0x0102030405060708i64);
        assert_eq!(LittleEndian.get_long(&le_b), 0x0102030405060708i64);
    }

    // ── return-by-value helpers ───────────────────────────────────────────────

    #[test]
    fn short_to_bytes_be() {
        assert_eq!(BigEndian.short_to_bytes(0x0102), [0x01, 0x02]);
    }

    #[test]
    fn short_to_bytes_le() {
        assert_eq!(LittleEndian.short_to_bytes(0x0102), [0x02, 0x01]);
    }

    #[test]
    fn int_to_bytes_be() {
        assert_eq!(BigEndian.int_to_bytes(0x01020304), [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn int_to_bytes_le() {
        assert_eq!(LittleEndian.int_to_bytes(0x01020304), [0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn long_to_bytes_be() {
        assert_eq!(
            BigEndian.long_to_bytes(0x0102030405060708i64),
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn long_to_bytes_le() {
        assert_eq!(
            LittleEndian.long_to_bytes(0x0102030405060708i64),
            [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }

    // ── sign-extension parity with Java ──────────────────────────────────────

    #[test]
    fn get_int_sign_extends_from_msb() {
        // Java: `int v = b[offset]` sign-extends the first byte; 0x80 → -128 → 0xFFFFFF80
        assert_eq!(BigEndian.get_int(&[0x80, 0x00, 0x00, 0x00]), i32::MIN);
    }

    #[test]
    fn get_long_sign_extends_from_msb() {
        assert_eq!(BigEndian.get_long(&[0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), i64::MIN);
    }

    #[test]
    fn get_value_does_not_sign_extend() {
        // getValue is zero-extended; 0xFF with size=1 gives 255, not -1
        assert_eq!(BigEndian.get_value(&[0xFF], 1), 0xFF);
        assert_eq!(BigEndian.get_value(&[0x80, 0x00], 2), 0x8000);
    }
}
