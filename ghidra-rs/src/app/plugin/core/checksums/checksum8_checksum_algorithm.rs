/// 8-bit basic checksum algorithm.
///
/// Computes an 8-bit additive (or XOR) checksum over a byte slice, with optional
/// carry folding, ones-complement, and twos-complement post-processing.
///
/// Corresponds to `ghidra.app.plugin.core.checksums.Checksum8ChecksumAlgorithm`
/// and its parent `BasicChecksumAlgorithm` with `SupportedByteSize::CHECKSUM8`.
pub struct Checksum8ChecksumAlgorithm {
    checksum: Option<[u8; 1]>,
}

impl Checksum8ChecksumAlgorithm {
    pub const NAME: &'static str = "Checksum-8";

    pub fn new() -> Self {
        Self { checksum: None }
    }

    pub fn name(&self) -> &str {
        Self::NAME
    }

    /// Returns `true`; 8-bit checksums can be rendered as an unsigned decimal.
    pub fn supports_decimal(&self) -> bool {
        true
    }

    /// Returns the last computed checksum, or `None` if none has been computed yet.
    pub fn checksum(&self) -> Option<&[u8; 1]> {
        self.checksum.as_ref()
    }

    /// Resets the stored checksum to `None`.
    pub fn reset(&mut self) {
        self.checksum = None;
    }

    /// Computes the 8-bit checksum over `data` and stores it.
    ///
    /// Each byte is accumulated directly (no shift), matching the Java
    /// `BasicChecksumAlgorithm` `CHECKSUM8` branch where `next = b`.
    ///
    /// # Options
    /// - `xor`: XOR bytes into the accumulator instead of adding.
    /// - `carry`: fold the sum back into 8-bit range (carry-around addition).
    /// - `ones_comp`: apply bitwise NOT to the final sum.
    /// - `twos_comp`: negate the final sum.
    ///
    /// The result is stored as a 1-byte array, matching the Java `toArray(sum, 1)` helper.
    pub fn update_checksum(
        &mut self,
        data: &[u8],
        xor: bool,
        carry: bool,
        ones_comp: bool,
        twos_comp: bool,
    ) {
        let mut sum: u64 = 0;
        for &b in data {
            if xor {
                sum ^= b as u64;
            } else {
                sum += b as u64;
            }
        }

        if carry {
            let max: u64 = 1 << 8;
            while sum >= max {
                sum = (sum & (max - 1)) + (sum >> 8);
            }
        }

        if ones_comp {
            sum = !sum;
        } else if twos_comp {
            sum = (-(sum as i64)) as u64;
        }

        self.checksum = Some([(sum & 0xff) as u8]);
    }
}

impl Default for Checksum8ChecksumAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compute(data: &[u8], xor: bool, carry: bool, ones: bool, twos: bool) -> [u8; 1] {
        let mut alg = Checksum8ChecksumAlgorithm::new();
        alg.update_checksum(data, xor, carry, ones, twos);
        *alg.checksum().unwrap()
    }

    #[test]
    fn test_name() {
        assert_eq!(Checksum8ChecksumAlgorithm::NAME, "Checksum-8");
        assert_eq!(Checksum8ChecksumAlgorithm::new().name(), "Checksum-8");
    }

    #[test]
    fn test_supports_decimal() {
        assert!(Checksum8ChecksumAlgorithm::new().supports_decimal());
    }

    #[test]
    fn test_initial_checksum_is_none() {
        let alg = Checksum8ChecksumAlgorithm::new();
        assert!(alg.checksum().is_none());
    }

    #[test]
    fn test_reset_clears_checksum() {
        let mut alg = Checksum8ChecksumAlgorithm::new();
        alg.update_checksum(&[0x01], false, false, false, false);
        assert!(alg.checksum().is_some());
        alg.reset();
        assert!(alg.checksum().is_none());
    }

    #[test]
    fn test_empty_input() {
        // Sum over no bytes is 0 → [0x00]
        assert_eq!(compute(&[], false, false, false, false), [0x00]);
    }

    #[test]
    fn test_single_byte() {
        // Each byte is used directly without shifting
        assert_eq!(compute(&[0x42], false, false, false, false), [0x42]);
    }

    #[test]
    fn test_multiple_bytes_additive() {
        // 0x01 + 0x02 + 0x03 = 0x06
        assert_eq!(compute(&[0x01, 0x02, 0x03], false, false, false, false), [0x06]);
    }

    #[test]
    fn test_overflow_without_carry() {
        // 0xFF + 0x01 = 0x100 → truncated to low byte: 0x00
        assert_eq!(compute(&[0xFF, 0x01], false, false, false, false), [0x00]);
    }

    #[test]
    fn test_carry_with_overflow() {
        // 0xFF + 0x01 = 0x100; carry: 0x100 >= 256 → (0x00) + 1 = 0x01
        assert_eq!(compute(&[0xFF, 0x01], false, true, false, false), [0x01]);
    }

    #[test]
    fn test_carry_no_overflow() {
        // 0x7F + 0x01 = 0x80; no carry needed → [0x80]
        assert_eq!(compute(&[0x7F, 0x01], false, true, false, false), [0x80]);
    }

    #[test]
    fn test_xor_mode_cancel() {
        // 0xAB ^ 0xAB = 0x00
        assert_eq!(compute(&[0xAB, 0xAB], true, false, false, false), [0x00]);
    }

    #[test]
    fn test_xor_mode_nonzero() {
        // 0x0F ^ 0xF0 = 0xFF
        assert_eq!(compute(&[0x0F, 0xF0], true, false, false, false), [0xFF]);
    }

    #[test]
    fn test_ones_complement() {
        // sum = 0x00 → !0x00 = 0xFF (low byte)
        assert_eq!(compute(&[0x00], false, false, true, false), [0xFF]);
    }

    #[test]
    fn test_ones_complement_nonzero() {
        // sum = 0x01 → !0x01 low byte = 0xFE
        assert_eq!(compute(&[0x01], false, false, true, false), [0xFE]);
    }

    #[test]
    fn test_twos_complement() {
        // sum = 0x01 → -1i64 as u64 = 0xFFFF...FF → low byte = 0xFF
        assert_eq!(compute(&[0x01], false, false, false, true), [0xFF]);
    }

    #[test]
    fn test_twos_complement_zero() {
        // -0 = 0
        assert_eq!(compute(&[0x00], false, false, false, true), [0x00]);
    }

    #[test]
    fn test_all_zeros() {
        assert_eq!(compute(&[0x00; 8], false, false, false, false), [0x00]);
    }

    #[test]
    fn test_all_ones() {
        // 8 × 0xFF = 8 × 255 = 2040 = 0x7F8 → low byte = 0xF8
        assert_eq!(compute(&[0xFF; 8], false, false, false, false), [0xF8]);
    }
}
