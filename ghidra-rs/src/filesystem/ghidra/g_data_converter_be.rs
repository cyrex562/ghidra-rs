//! Big-endian implementation of [`GDataConverter`].
//!
//! Mirrors `mobiledevices.dmg.ghidra.GDataConverterBE` from the original Ghidra source.

use super::g_data_converter::GDataConverter;

/// Converts between byte slices and primitive integer types using big-endian byte order.
///
/// A shared singleton is available via [`INSTANCE`].
pub struct GDataConverterBe;

/// Shared singleton, mirroring `GDataConverterBE.INSTANCE` in the original Java source.
pub static INSTANCE: GDataConverterBe = GDataConverterBe;

impl GDataConverter for GDataConverterBe {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::ghidra::g_data_converter::GDataConverter;

    // ── get_short ─────────────────────────────────────────────────────────────

    #[test]
    fn get_short_positive() {
        assert_eq!(INSTANCE.get_short(&[0x00, 0x01]), 1i16);
    }

    #[test]
    fn get_short_negative() {
        assert_eq!(INSTANCE.get_short(&[0xFF, 0xFF]), -1i16);
    }

    #[test]
    fn get_short_at_offset() {
        let buf = [0x00, 0x00, 0x01, 0x02];
        assert_eq!(INSTANCE.get_short_at(&buf, 2), 0x0102i16);
    }

    // ── get_int ───────────────────────────────────────────────────────────────

    #[test]
    fn get_int_positive() {
        assert_eq!(INSTANCE.get_int(&[0x00, 0x00, 0x00, 0x07]), 7i32);
    }

    #[test]
    fn get_int_negative() {
        assert_eq!(INSTANCE.get_int(&[0xFF, 0xFF, 0xFF, 0xFF]), -1i32);
    }

    #[test]
    fn get_int_sign_extends_msb() {
        assert_eq!(INSTANCE.get_int(&[0x80, 0x00, 0x00, 0x00]), i32::MIN);
    }

    #[test]
    fn get_int_at_offset() {
        let buf = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A];
        assert_eq!(INSTANCE.get_int_at(&buf, 4), 10i32);
    }

    // ── get_long ──────────────────────────────────────────────────────────────

    #[test]
    fn get_long_positive() {
        let mut b = [0u8; 8];
        b[7] = 1;
        assert_eq!(INSTANCE.get_long(&b), 1i64);
    }

    #[test]
    fn get_long_negative() {
        assert_eq!(INSTANCE.get_long(&[0xFF; 8]), -1i64);
    }

    #[test]
    fn get_long_sign_extends_msb() {
        assert_eq!(
            INSTANCE.get_long(&[0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            i64::MIN
        );
    }

    #[test]
    fn get_long_at_offset() {
        let mut buf = [0u8; 16];
        buf[15] = 9;
        assert_eq!(INSTANCE.get_long_at(&buf, 8), 9i64);
    }

    // ── get_value (zero-extended) ─────────────────────────────────────────────

    #[test]
    fn get_value_single_byte() {
        assert_eq!(INSTANCE.get_value(&[0xFF], 1), 0xFF);
    }

    #[test]
    fn get_value_two_bytes() {
        assert_eq!(INSTANCE.get_value(&[0x01, 0x02], 2), 0x0102);
    }

    #[test]
    fn get_value_does_not_sign_extend() {
        assert_eq!(INSTANCE.get_value(&[0x80, 0x00], 2), 0x8000);
    }

    #[test]
    fn get_value_at_offset() {
        let buf = [0x00, 0x00, 0x01, 0x02, 0x03];
        assert_eq!(INSTANCE.get_value_at(&buf, 2, 3), 0x010203);
    }

    #[test]
    #[should_panic(expected = "size exceeds sizeof long")]
    fn get_value_size_too_large() {
        INSTANCE.get_value_at(&[0u8; 9], 0, 9);
    }

    // ── put_short ─────────────────────────────────────────────────────────────

    #[test]
    fn put_short_round_trip() {
        let mut b = [0u8; 2];
        INSTANCE.put_short(&mut b, 0x0102);
        assert_eq!(b, [0x01, 0x02]);
        assert_eq!(INSTANCE.get_short(&b), 0x0102);
    }

    #[test]
    fn put_short_at_offset() {
        let mut b = [0u8; 4];
        INSTANCE.put_short_at(&mut b, 2, 0x0304);
        assert_eq!(b, [0x00, 0x00, 0x03, 0x04]);
    }

    // ── put_int ───────────────────────────────────────────────────────────────

    #[test]
    fn put_int_round_trip() {
        let mut b = [0u8; 4];
        INSTANCE.put_int(&mut b, 0x01020304);
        assert_eq!(b, [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(INSTANCE.get_int(&b), 0x01020304);
    }

    #[test]
    fn put_int_at_offset() {
        let mut b = [0u8; 8];
        INSTANCE.put_int_at(&mut b, 4, 0x0A0B0C0D);
        assert_eq!(&b[4..8], &[0x0A, 0x0B, 0x0C, 0x0D]);
    }

    // ── put_long ──────────────────────────────────────────────────────────────

    #[test]
    fn put_long_round_trip() {
        let mut b = [0u8; 8];
        INSTANCE.put_long(&mut b, 0x0102030405060708i64);
        assert_eq!(b, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(INSTANCE.get_long(&b), 0x0102030405060708i64);
    }

    #[test]
    fn put_long_at_offset() {
        let mut b = [0u8; 16];
        INSTANCE.put_long_at(&mut b, 8, 0x0102030405060708i64);
        assert_eq!(&b[8..16], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    // ── put_long_sized ────────────────────────────────────────────────────────

    #[test]
    fn put_long_sized_partial() {
        let mut b = [0u8; 4];
        INSTANCE.put_long_sized(&mut b, 1, 0x00010203, 3);
        assert_eq!(b, [0x00, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn put_long_sized_full() {
        let mut b = [0u8; 8];
        INSTANCE.put_long_sized(&mut b, 0, 0x0102030405060708i64, 8);
        assert_eq!(INSTANCE.get_long(&b), 0x0102030405060708i64);
    }

    #[test]
    #[should_panic(expected = "size exceeds sizeof long")]
    fn put_long_sized_size_too_large() {
        let mut b = [0u8; 9];
        INSTANCE.put_long_sized(&mut b, 0, 0, 9);
    }

    // ── return-by-value convenience helpers ──────────────────────────────────

    #[test]
    fn short_to_bytes() {
        assert_eq!(INSTANCE.short_to_bytes(0x0102), [0x01, 0x02]);
    }

    #[test]
    fn int_to_bytes() {
        assert_eq!(INSTANCE.int_to_bytes(0x01020304), [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn long_to_bytes() {
        assert_eq!(
            INSTANCE.long_to_bytes(0x0102030405060708i64),
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }
}
