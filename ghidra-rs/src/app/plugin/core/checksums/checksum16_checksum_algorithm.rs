/// 16-bit basic checksum algorithm.
///
/// Computes a 16-bit additive (or XOR) checksum over a byte slice, with optional
/// carry folding, ones-complement, and twos-complement post-processing.
///
/// Corresponds to `ghidra.app.plugin.core.checksums.Checksum16ChecksumAlgorithm`
/// and its parent `BasicChecksumAlgorithm` with `SupportedByteSize::CHECKSUM16`.
pub struct Checksum16ChecksumAlgorithm {
    checksum: Option<[u8; 2]>,
}

impl Checksum16ChecksumAlgorithm {
    pub const NAME: &'static str = "Checksum-16";

    pub fn new() -> Self {
        Self { checksum: None }
    }

    pub fn name(&self) -> &str {
        Self::NAME
    }

    /// Returns `true`; 16-bit checksums can be rendered as an unsigned decimal.
    pub fn supports_decimal(&self) -> bool {
        true
    }

    /// Returns the last computed checksum, or `None` if none has been computed yet.
    pub fn checksum(&self) -> Option<&[u8; 2]> {
        self.checksum.as_ref()
    }

    /// Resets the stored checksum to `None`.
    pub fn reset(&mut self) {
        self.checksum = None;
    }

    /// Computes the 16-bit checksum over `data` and stores it.
    ///
    /// Bytes are accumulated in big-endian pairs: even-indexed bytes become the
    /// high byte of each 16-bit unit; odd-indexed bytes become the low byte.
    ///
    /// # Options
    /// - `xor`: XOR bytes into the accumulator instead of adding.
    /// - `carry`: fold the sum back into 16-bit range (carry-around addition).
    /// - `ones_comp`: apply bitwise NOT to the final sum.
    /// - `twos_comp`: negate the final sum.
    ///
    /// The result is stored as a 2-byte **little-endian** array, matching the
    /// Java `toArray(sum, 2)` helper.
    pub fn update_checksum(
        &mut self,
        data: &[u8],
        xor: bool,
        carry: bool,
        ones_comp: bool,
        twos_comp: bool,
    ) {
        let mut sum: u64 = 0;
        for (i, &b) in data.iter().enumerate() {
            let shift = (1 - i % 2) * 8;
            let next = (b as u64) << shift;
            if xor {
                sum ^= next;
            } else {
                sum += next;
            }
        }

        if carry {
            let max: u64 = 1 << 16;
            while sum >= max {
                sum = (sum & (max - 1)) + (sum >> 16);
            }
        }

        if ones_comp {
            sum = !sum;
        } else if twos_comp {
            sum = (-(sum as i64)) as u64;
        }

        self.checksum = Some(to_le2(sum));
    }
}

impl Default for Checksum16ChecksumAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the low 16 bits of `val` as a little-endian 2-byte array.
///
/// Matches the Java `ChecksumAlgorithm.toArray(val, 2)` helper.
fn to_le2(val: u64) -> [u8; 2] {
    [(val & 0xff) as u8, ((val >> 8) & 0xff) as u8]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compute(data: &[u8], xor: bool, carry: bool, ones: bool, twos: bool) -> [u8; 2] {
        let mut alg = Checksum16ChecksumAlgorithm::new();
        alg.update_checksum(data, xor, carry, ones, twos);
        *alg.checksum().unwrap()
    }

    #[test]
    fn test_name() {
        assert_eq!(Checksum16ChecksumAlgorithm::NAME, "Checksum-16");
        assert_eq!(Checksum16ChecksumAlgorithm::new().name(), "Checksum-16");
    }

    #[test]
    fn test_supports_decimal() {
        assert!(Checksum16ChecksumAlgorithm::new().supports_decimal());
    }

    #[test]
    fn test_initial_checksum_is_none() {
        let alg = Checksum16ChecksumAlgorithm::new();
        assert!(alg.checksum().is_none());
    }

    #[test]
    fn test_reset_clears_checksum() {
        let mut alg = Checksum16ChecksumAlgorithm::new();
        alg.update_checksum(&[0x01, 0x02], false, false, false, false);
        assert!(alg.checksum().is_some());
        alg.reset();
        assert!(alg.checksum().is_none());
    }

    #[test]
    fn test_empty_input() {
        // Sum over no bytes is 0x0000 → little-endian [0x00, 0x00]
        assert_eq!(compute(&[], false, false, false, false), [0x00, 0x00]);
    }

    #[test]
    fn test_single_byte_msb() {
        // Byte 0 is even-indexed → shifted to high byte position
        // 0x12 << 8 = 0x1200 → little-endian [0x00, 0x12]
        assert_eq!(compute(&[0x12], false, false, false, false), [0x00, 0x12]);
    }

    #[test]
    fn test_two_bytes_basic() {
        // 0x12 << 8 = 0x1200, 0x34 << 0 = 0x0034; sum = 0x1234
        // little-endian: [0x34, 0x12]
        assert_eq!(compute(&[0x12, 0x34], false, false, false, false), [0x34, 0x12]);
    }

    #[test]
    fn test_four_bytes_big_endian_pairs() {
        // [0x01, 0x02, 0x03, 0x04]
        // 0x01<<8 + 0x02 + 0x03<<8 + 0x04 = 0x0100 + 0x02 + 0x0300 + 0x04 = 0x0406
        // little-endian: [0x06, 0x04]
        assert_eq!(compute(&[0x01, 0x02, 0x03, 0x04], false, false, false, false), [0x06, 0x04]);
    }

    #[test]
    fn test_xor_mode() {
        // [0x12, 0x34, 0x12, 0x34]: XOR pairs
        // 0x1200 ^ 0x34 ^ 0x1200 ^ 0x34 = 0x0000
        assert_eq!(compute(&[0x12, 0x34, 0x12, 0x34], true, false, false, false), [0x00, 0x00]);
    }

    #[test]
    fn test_xor_mode_nonzero() {
        // [0xAB, 0xCD]: 0xAB00 ^ 0x00CD = 0xABCD → little-endian [0xCD, 0xAB]
        assert_eq!(compute(&[0xAB, 0xCD], true, false, false, false), [0xCD, 0xAB]);
    }

    #[test]
    fn test_carry() {
        // Overflow: 0xFF00 + 0xFF = 0xFFFF, no carry needed
        // Sum = 0xFFFF → [0xFF, 0xFF]
        assert_eq!(compute(&[0xFF, 0xFF], false, true, false, false), [0xFF, 0xFF]);
    }

    #[test]
    fn test_carry_with_overflow() {
        // [0xFF, 0xFF, 0x00, 0x01]:
        // 0xFF00 + 0xFF + 0x0000 + 0x01 = 0x10000
        // carry: 0x10000 >= 0x10000 → (0x0000) + 1 = 0x0001
        // little-endian: [0x01, 0x00]
        assert_eq!(compute(&[0xFF, 0xFF, 0x00, 0x01], false, true, false, false), [0x01, 0x00]);
    }

    #[test]
    fn test_ones_complement() {
        // [0x00, 0x00]: sum = 0 → !0 = 0xFFFFFFFFFFFFFFFF → low 2 bytes = 0xFFFF
        // little-endian: [0xFF, 0xFF]
        assert_eq!(compute(&[0x00, 0x00], false, false, true, false), [0xFF, 0xFF]);
    }

    #[test]
    fn test_twos_complement() {
        // [0x00, 0x01]: sum = 0x0001 → -(1i64) as u64 = 0xFFFFFFFFFFFFFFFF
        // low 2 bytes little-endian: [0xFF, 0xFF]
        assert_eq!(compute(&[0x00, 0x01], false, false, false, true), [0xFF, 0xFF]);
    }

    #[test]
    fn test_all_zeros() {
        assert_eq!(compute(&[0x00; 8], false, false, false, false), [0x00, 0x00]);
    }

    #[test]
    fn test_to_le2_helper() {
        // Access via the module-private helper indirectly through update_checksum
        // 0x1234 → [0x34, 0x12]
        assert_eq!(compute(&[0x12, 0x34], false, false, false, false), [0x34, 0x12]);
        // 0x0000 → [0x00, 0x00]
        assert_eq!(compute(&[0x00, 0x00], false, false, false, false), [0x00, 0x00]);
        // 0xFFFF → [0xFF, 0xFF]
        assert_eq!(compute(&[0xFF, 0xFF], false, false, false, false), [0xFF, 0xFF]);
    }
}
