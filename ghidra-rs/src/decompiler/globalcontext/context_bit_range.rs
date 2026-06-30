/// A bit range within a context word array, used to extract and set packed bit fields.
///
/// Bit positions are numbered MSB-first within each 32-bit word (bit 0 = MSB).
///
/// Corresponds to `ghidra.pcodeCPort.globalcontext.ContextBitRange`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextBitRange {
    word: usize,
    shift: u32,
    mask: u32,
}

impl ContextBitRange {
    /// Creates a new `ContextBitRange` covering bits `sbit..=ebit` (MSB-first, inclusive).
    pub fn new(sbit: i32, ebit: i32) -> Self {
        let word = (sbit / 32) as usize;
        let startbit = sbit - (word as i32) * 32;
        let endbit = ebit - (word as i32) * 32;
        let shift = (32 - endbit - 1) as u32;
        let mask = u32::MAX >> (startbit as u32 + shift);
        Self { word, shift, mask }
    }

    /// Stores `val` into the bit range within `vec`.
    pub fn set_value(&self, vec: &mut [i32], val: i32) {
        let w = vec[self.word] as u32;
        let cleared = w & !(self.mask << self.shift);
        let bits = (val as u32 & self.mask) << self.shift;
        vec[self.word] = (cleared | bits) as i32;
    }

    /// Returns the value stored in the bit range within `vec`.
    pub fn get_value(&self, vec: &[i32]) -> i32 {
        ((vec[self.word] as u32 >> self.shift) & self.mask) as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_bit_msb() {
        let cbr = ContextBitRange::new(0, 0);
        let mut ctx = vec![0i32];
        cbr.set_value(&mut ctx, 1);
        assert_eq!(ctx[0], i32::MIN); // 0x80000000
        assert_eq!(cbr.get_value(&ctx), 1);
    }

    #[test]
    fn single_bit_clear_msb() {
        let cbr = ContextBitRange::new(0, 0);
        let mut ctx = vec![i32::MIN];
        cbr.set_value(&mut ctx, 0);
        assert_eq!(ctx[0], 0);
        assert_eq!(cbr.get_value(&ctx), 0);
    }

    #[test]
    fn single_bit_lsb() {
        let cbr = ContextBitRange::new(31, 31);
        let mut ctx = vec![0i32];
        cbr.set_value(&mut ctx, 1);
        assert_eq!(ctx[0], 1);
        assert_eq!(cbr.get_value(&ctx), 1);
    }

    #[test]
    fn full_word() {
        let cbr = ContextBitRange::new(0, 31);
        let mut ctx = vec![0i32];
        cbr.set_value(&mut ctx, 42);
        assert_eq!(ctx[0], 42);
        assert_eq!(cbr.get_value(&ctx), 42);
    }

    #[test]
    fn upper_halfword() {
        let cbr = ContextBitRange::new(0, 15);
        let mut ctx = vec![0i32];
        cbr.set_value(&mut ctx, 0x1234);
        assert_eq!(ctx[0] as u32, 0x1234_0000);
        assert_eq!(cbr.get_value(&ctx), 0x1234);
    }

    #[test]
    fn lower_halfword() {
        let cbr = ContextBitRange::new(16, 31);
        let mut ctx = vec![0i32];
        cbr.set_value(&mut ctx, 0x5678);
        assert_eq!(ctx[0], 0x5678);
        assert_eq!(cbr.get_value(&ctx), 0x5678);
    }

    #[test]
    fn set_value_preserves_other_bits() {
        let cbr = ContextBitRange::new(0, 15); // upper 16 bits
        let mut ctx = vec![0x0000_FFFFu32 as i32];
        cbr.set_value(&mut ctx, 0xABCD);
        assert_eq!(ctx[0] as u32, 0xABCD_FFFF);
        assert_eq!(cbr.get_value(&ctx), 0xABCD);
    }

    #[test]
    fn val_clamped_to_field_width() {
        let cbr = ContextBitRange::new(28, 31); // 4-bit field
        let mut ctx = vec![0i32];
        cbr.set_value(&mut ctx, 0xFF);
        assert_eq!(cbr.get_value(&ctx), 0xF);
    }

    #[test]
    fn second_word() {
        let cbr = ContextBitRange::new(32, 63);
        let mut ctx = vec![0i32, 0i32];
        cbr.set_value(&mut ctx, 99);
        assert_eq!(ctx[0], 0);
        assert_eq!(ctx[1], 99);
        assert_eq!(cbr.get_value(&ctx), 99);
    }

    #[test]
    fn midword_field_roundtrip() {
        let cbr = ContextBitRange::new(8, 23); // 16-bit field in middle
        for &val in &[0i32, 1, 0x7FFF, 0x8000u32 as i32, 0xFFFFu32 as i32] {
            let mut ctx = vec![0i32];
            cbr.set_value(&mut ctx, val);
            assert_eq!(cbr.get_value(&ctx), val & 0xFFFF);
        }
    }
}
