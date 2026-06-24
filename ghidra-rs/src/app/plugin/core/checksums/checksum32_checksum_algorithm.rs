/// 32-bit basic checksum algorithm.
///
/// Computes a 32-bit additive (or XOR) checksum over a byte slice, with optional
/// carry folding, ones-complement, and twos-complement post-processing.
///
/// Corresponds to `ghidra.app.plugin.core.checksums.Checksum32ChecksumAlgorithm`
/// and its parent `BasicChecksumAlgorithm` with `SupportedByteSize::CHECKSUM32`.
pub struct Checksum32ChecksumAlgorithm {
    checksum: Option<[u8; 4]>,
}

impl Checksum32ChecksumAlgorithm {
    pub const NAME: &'static str = "Checksum-32";

    pub fn new() -> Self {
        Self { checksum: None }
    }

    pub fn name(&self) -> &str {
        Self::NAME
    }

    /// Returns `true`; 32-bit checksums can be rendered as an unsigned decimal.
    pub fn supports_decimal(&self) -> bool {
        true
    }

    /// Returns the last computed checksum, or `None` if none has been computed yet.
    pub fn checksum(&self) -> Option<&[u8; 4]> {
        self.checksum.as_ref()
    }

    /// Resets the stored checksum to `None`.
    pub fn reset(&mut self) {
        self.checksum = None;
    }

    /// Computes the 32-bit checksum over `data` and stores it.
    ///
    /// Bytes are accumulated in big-endian groups of four: byte at index `i` is
    /// shifted left by `(3 - i % 4) * 8` bits before being added/XORed.
    ///
    /// # Options
    /// - `xor`: XOR bytes into the accumulator instead of adding.
    /// - `carry`: fold the sum back into 32-bit range (carry-around addition).
    /// - `ones_comp`: apply bitwise NOT to the final sum.
    /// - `twos_comp`: negate the final sum.
    ///
    /// The result is stored as a 4-byte **little-endian** array, matching the
    /// Java `toArray(sum, 4)` helper.
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
            let shift = (3 - i % 4) * 8;
            let next = (b as u64) << shift;
            if xor {
                sum ^= next;
            } else {
                sum += next;
            }
        }

        if carry {
            let max: u64 = 1 << 32;
            while sum >= max {
                sum = (sum & (max - 1)) + (sum >> 32);
            }
        }

        if ones_comp {
            sum = !sum;
        } else if twos_comp {
            sum = (-(sum as i64)) as u64;
        }

        self.checksum = Some(to_le4(sum));
    }
}

impl Default for Checksum32ChecksumAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the low 32 bits of `val` as a little-endian 4-byte array.
///
/// Matches the Java `ChecksumAlgorithm.toArray(val, 4)` helper.
fn to_le4(val: u64) -> [u8; 4] {
    [
        (val & 0xff) as u8,
        ((val >> 8) & 0xff) as u8,
        ((val >> 16) & 0xff) as u8,
        ((val >> 24) & 0xff) as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compute(data: &[u8], xor: bool, carry: bool, ones: bool, twos: bool) -> [u8; 4] {
        let mut alg = Checksum32ChecksumAlgorithm::new();
        alg.update_checksum(data, xor, carry, ones, twos);
        *alg.checksum().unwrap()
    }

    #[test]
    fn test_name() {
        assert_eq!(Checksum32ChecksumAlgorithm::NAME, "Checksum-32");
        assert_eq!(Checksum32ChecksumAlgorithm::new().name(), "Checksum-32");
    }

    #[test]
    fn test_supports_decimal() {
        assert!(Checksum32ChecksumAlgorithm::new().supports_decimal());
    }

    #[test]
    fn test_initial_checksum_is_none() {
        let alg = Checksum32ChecksumAlgorithm::new();
        assert!(alg.checksum().is_none());
    }

    #[test]
    fn test_reset_clears_checksum() {
        let mut alg = Checksum32ChecksumAlgorithm::new();
        alg.update_checksum(&[0x01, 0x02, 0x03, 0x04], false, false, false, false);
        assert!(alg.checksum().is_some());
        alg.reset();
        assert!(alg.checksum().is_none());
    }

    #[test]
    fn test_empty_input() {
        // Sum over no bytes is 0 → little-endian [0x00, 0x00, 0x00, 0x00]
        assert_eq!(compute(&[], false, false, false, false), [0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_single_byte_msb() {
        // Byte 0 is index 0 → shifted left by 24 bits
        // 0x12 << 24 = 0x12000000 → little-endian [0x00, 0x00, 0x00, 0x12]
        assert_eq!(compute(&[0x12], false, false, false, false), [0x00, 0x00, 0x00, 0x12]);
    }

    #[test]
    fn test_four_bytes_basic() {
        // [0x01, 0x02, 0x03, 0x04]:
        // 0x01<<24 + 0x02<<16 + 0x03<<8 + 0x04<<0 = 0x01020304
        // little-endian: [0x04, 0x03, 0x02, 0x01]
        assert_eq!(compute(&[0x01, 0x02, 0x03, 0x04], false, false, false, false), [0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_eight_bytes() {
        // [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]:
        // first group: 0x01020304, second group: 0x05060708
        // sum = 0x0608080C → little-endian: [0x0C, 0x08, 0x08, 0x06]
        assert_eq!(
            compute(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], false, false, false, false),
            [0x0C, 0x08, 0x08, 0x06]
        );
    }

    #[test]
    fn test_xor_mode() {
        // [0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04]: XOR of same value = 0
        assert_eq!(
            compute(&[0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04], true, false, false, false),
            [0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_xor_mode_nonzero() {
        // [0xAB, 0xCD, 0xEF, 0x12]:
        // 0xAB<<24 | 0xCD<<16 | 0xEF<<8 | 0x12 = 0xABCDEF12
        // little-endian: [0x12, 0xEF, 0xCD, 0xAB]
        assert_eq!(
            compute(&[0xAB, 0xCD, 0xEF, 0x12], true, false, false, false),
            [0x12, 0xEF, 0xCD, 0xAB]
        );
    }

    #[test]
    fn test_carry_with_overflow() {
        // [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01]:
        // sum = 0xFFFFFFFF + 0x00000001 = 0x100000000
        // carry: 0x100000000 >= 2^32 → (0x00000000) + 1 = 0x00000001
        // little-endian: [0x01, 0x00, 0x00, 0x00]
        assert_eq!(
            compute(&[0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01], false, true, false, false),
            [0x01, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_ones_complement() {
        // [0x00, 0x00, 0x00, 0x00]: sum = 0 → !0 = 0xFFFFFFFFFFFFFFFF → low 4 bytes = 0xFFFFFFFF
        // little-endian: [0xFF, 0xFF, 0xFF, 0xFF]
        assert_eq!(compute(&[0x00; 4], false, false, true, false), [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_twos_complement() {
        // [0x00, 0x00, 0x00, 0x01]: sum = 0x00000001 → -(1i64) as u64 = 0xFFFFFFFFFFFFFFFF
        // low 4 bytes little-endian: [0xFF, 0xFF, 0xFF, 0xFF]
        assert_eq!(compute(&[0x00, 0x00, 0x00, 0x01], false, false, false, true), [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_all_zeros() {
        assert_eq!(compute(&[0x00; 8], false, false, false, false), [0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_to_le4_helper() {
        // 0x01020304 → [0x04, 0x03, 0x02, 0x01]
        assert_eq!(compute(&[0x01, 0x02, 0x03, 0x04], false, false, false, false), [0x04, 0x03, 0x02, 0x01]);
        // 0x00000000 → [0x00, 0x00, 0x00, 0x00]
        assert_eq!(compute(&[0x00; 4], false, false, false, false), [0x00, 0x00, 0x00, 0x00]);
        // 0xFFFFFFFF → [0xFF, 0xFF, 0xFF, 0xFF]
        assert_eq!(compute(&[0xFF; 4], false, false, false, false), [0xFF, 0xFF, 0xFF, 0xFF]);
    }
}
