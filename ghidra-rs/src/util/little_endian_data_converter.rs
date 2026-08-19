//! Little-endian implementation of [`DataConverter`].
//!
//! Port of `ghidra.util.LittleEndianDataConverter`.

use super::data_converter::DataConverter;

/// Converts a byte array to Java primitives and primitives to a byte array in little endian.
///
/// A shared singleton is available via [`INSTANCE`]; prefer it over constructing new instances.
pub struct LittleEndianDataConverter;

/// Shared singleton, mirroring `LittleEndianDataConverter.INSTANCE` in the original Java source.
pub static INSTANCE: LittleEndianDataConverter = LittleEndianDataConverter;

impl DataConverter for LittleEndianDataConverter {
    fn is_big_endian(&self) -> bool {
        false
    }

    fn get_short_at(&self, b: &[u8], offset: usize) -> i16 {
        i16::from_le_bytes([b[offset], b[offset + 1]])
    }

    fn get_int_at(&self, b: &[u8], offset: usize) -> i32 {
        i32::from_le_bytes([b[offset], b[offset + 1], b[offset + 2], b[offset + 3]])
    }

    fn get_long_at(&self, b: &[u8], offset: usize) -> i64 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&b[offset..offset + 8]);
        i64::from_le_bytes(buf)
    }

    fn get_value_at(&self, b: &[u8], offset: usize, size: usize) -> u64 {
        assert!(size <= 8, "size exceeds sizeof long: {size}");
        let mut val: u64 = 0;
        for i in (0..size).rev() {
            val = (val << 8) | b[offset + i] as u64;
        }
        val
    }

    fn get_big_integer_at(&self, b: &[u8], offset: usize, size: usize, signed: bool) -> i128 {
        assert!(size <= 16, "size exceeds representable range: {size}");
        let mut val: i128 = if signed && size > 0 && (b[offset + size - 1] & 0x80) != 0 {
            -1
        }
        else {
            0
        };
        for i in (0..size).rev() {
            val = (val << 8) | b[offset + i] as i128;
        }
        val
    }

    fn put_short_at(&self, b: &mut [u8], offset: usize, value: i16) {
        b[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_int_at(&self, b: &mut [u8], offset: usize, value: i32) {
        b[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_value_at(&self, value: u64, size: usize, b: &mut [u8], offset: usize) {
        assert!(size <= 8, "size exceeds sizeof long: {size}");
        let bytes = value.to_le_bytes();
        b[offset..offset + size].copy_from_slice(&bytes[..size]);
    }

    fn put_big_integer_at(&self, b: &mut [u8], offset: usize, size: usize, value: i128) {
        assert!(size <= 16, "size exceeds representable range: {size}");
        let val_bytes = value.to_le_bytes();
        b[offset..offset + size].copy_from_slice(&val_bytes[..size]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_big_endian ─────────────────────────────────────────────────────────

    #[test]
    fn is_big_endian() {
        assert!(!INSTANCE.is_big_endian());
    }

    // ── get_short ─────────────────────────────────────────────────────────────

    #[test]
    fn get_short_positive() {
        assert_eq!(INSTANCE.get_short(&[0x01, 0x00]), 1i16);
    }

    #[test]
    fn get_short_negative() {
        assert_eq!(INSTANCE.get_short(&[0xFF, 0xFF]), -1i16);
    }

    #[test]
    fn get_short_at_offset() {
        let buf = [0x00, 0x00, 0x02, 0x01];
        assert_eq!(INSTANCE.get_short_at(&buf, 2), 0x0102i16);
    }

    // ── get_int ───────────────────────────────────────────────────────────────

    #[test]
    fn get_int_positive() {
        assert_eq!(INSTANCE.get_int(&[0x07, 0x00, 0x00, 0x00]), 7i32);
    }

    #[test]
    fn get_int_negative() {
        assert_eq!(INSTANCE.get_int(&[0xFF, 0xFF, 0xFF, 0xFF]), -1i32);
    }

    #[test]
    fn get_int_at_offset() {
        let buf = [0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00];
        assert_eq!(INSTANCE.get_int_at(&buf, 4), 10i32);
    }

    // ── get_long ──────────────────────────────────────────────────────────────

    #[test]
    fn get_long_positive() {
        let mut b = [0u8; 8];
        b[0] = 1;
        assert_eq!(INSTANCE.get_long(&b), 1i64);
    }

    #[test]
    fn get_long_negative() {
        assert_eq!(INSTANCE.get_long(&[0xFF; 8]), -1i64);
    }

    // ── get_value (zero-extended) ─────────────────────────────────────────────

    #[test]
    fn get_value_single_byte() {
        assert_eq!(INSTANCE.get_value(&[0xFF], 1), 0xFF);
    }

    #[test]
    fn get_value_does_not_sign_extend() {
        assert_eq!(INSTANCE.get_value(&[0x00, 0x80], 2), 0x8000);
    }

    #[test]
    #[should_panic(expected = "size exceeds sizeof long")]
    fn get_value_size_too_large() {
        INSTANCE.get_value_at(&[0u8; 9], 0, 9);
    }

    // ── get_big_integer ───────────────────────────────────────────────────────

    #[test]
    fn get_big_integer_unsigned_high_bit_set() {
        assert_eq!(INSTANCE.get_big_integer(&[0xFF, 0xFF], 2, false), 0xFFFF);
    }

    #[test]
    fn get_big_integer_signed_high_bit_set() {
        assert_eq!(INSTANCE.get_big_integer(&[0xFF, 0xFF], 2, true), -1);
    }

    #[test]
    fn get_big_integer_signed_positive() {
        assert_eq!(INSTANCE.get_big_integer(&[0xFF, 0x7F], 2, true), 0x7FFF);
    }

    // ── put_short ─────────────────────────────────────────────────────────────

    #[test]
    fn put_short_round_trip() {
        let mut b = [0u8; 2];
        INSTANCE.put_short(&mut b, 0x0102);
        assert_eq!(b, [0x02, 0x01]);
        assert_eq!(INSTANCE.get_short(&b), 0x0102);
    }

    #[test]
    fn put_short_at_offset() {
        let mut b = [0u8; 4];
        INSTANCE.put_short_at(&mut b, 2, 0x0304);
        assert_eq!(b, [0x00, 0x00, 0x04, 0x03]);
    }

    // ── put_int ───────────────────────────────────────────────────────────────

    #[test]
    fn put_int_round_trip() {
        let mut b = [0u8; 4];
        INSTANCE.put_int(&mut b, 0x0102_0304);
        assert_eq!(b, [0x04, 0x03, 0x02, 0x01]);
        assert_eq!(INSTANCE.get_int(&b), 0x0102_0304);
    }

    // ── put_long (default trait impl via put_value_at) ───────────────────────

    #[test]
    fn put_long_round_trip() {
        let mut b = [0u8; 8];
        INSTANCE.put_long(&mut b, 0x0102_0304_0506_0708i64);
        assert_eq!(b, [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        assert_eq!(INSTANCE.get_long(&b), 0x0102_0304_0506_0708i64);
    }

    // ── put_value ─────────────────────────────────────────────────────────────

    #[test]
    fn put_value_partial_size() {
        let mut b = [0u8; 4];
        INSTANCE.put_value_at(0x0001_0203, 3, &mut b, 1);
        assert_eq!(b, [0x00, 0x03, 0x02, 0x01]);
    }

    #[test]
    #[should_panic(expected = "size exceeds sizeof long")]
    fn put_value_size_too_large() {
        let mut b = [0u8; 9];
        INSTANCE.put_value_at(0, 9, &mut b, 0);
    }

    // ── put_big_integer ───────────────────────────────────────────────────────

    #[test]
    fn put_big_integer_round_trip_signed() {
        let mut b = [0u8; 4];
        INSTANCE.put_big_integer(&mut b, 4, -1);
        assert_eq!(b, [0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(INSTANCE.get_big_integer(&b, 4, true), -1);
        assert_eq!(INSTANCE.get_big_integer(&b, 4, false), 0xFFFF_FFFF);
    }

    #[test]
    fn put_big_integer_truncates_to_size() {
        let mut b = [0u8; 2];
        INSTANCE.put_big_integer(&mut b, 2, 0x0102);
        assert_eq!(b, [0x02, 0x01]);
    }

    // ── round trip through the shared byte-buffer convenience helpers ───────

    #[test]
    fn short_to_bytes_matches_put_short() {
        assert_eq!(INSTANCE.short_to_bytes(0x0102), vec![0x02, 0x01]);
    }

    #[test]
    fn big_integer_to_bytes_matches_put_big_integer() {
        assert_eq!(
            INSTANCE.big_integer_to_bytes(-1, 4),
            vec![0xFF, 0xFF, 0xFF, 0xFF]
        );
    }
}
