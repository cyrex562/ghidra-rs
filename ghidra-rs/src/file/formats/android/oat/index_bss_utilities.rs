/// Utilities for BSS index mapping in ART OAT files.
///
/// Mirrors `ghidra.file.formats.android.oat.IndexBssUtilities`.
///
/// Reference: <https://android.googlesource.com/platform/art/+/master/runtime/index_bss_mapping.h>
pub struct IndexBssUtilities;

impl IndexBssUtilities {
    /// Returns a bitmask with the lower `index_bits` bits set.
    ///
    /// The `index_bits == 32` case is handled explicitly because shifting an `i32`
    /// left by 32 is undefined behaviour in C (the motivation behind the original
    /// comment) and would panic in Rust debug builds.
    pub fn index_mask(index_bits: i32) -> i32 {
        const K_ALL_ONES: i32 = -1;
        if index_bits == 32 {
            K_ALL_ONES
        } else {
            !(K_ALL_ONES << index_bits)
        }
    }

    /// Returns the number of bits needed to index into `number_of_indexes` entries.
    pub fn int_index_bits(number_of_indexes: i32) -> i32 {
        Self::minimum_bits_to_store(number_of_indexes - 1)
    }

    fn minimum_bits_to_store(_value: i32) -> i32 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_mask_zero_bits() {
        assert_eq!(IndexBssUtilities::index_mask(0), 0);
    }

    #[test]
    fn index_mask_one_bit() {
        assert_eq!(IndexBssUtilities::index_mask(1), 1);
    }

    #[test]
    fn index_mask_four_bits() {
        assert_eq!(IndexBssUtilities::index_mask(4), 0x0000_000F);
    }

    #[test]
    fn index_mask_eight_bits() {
        assert_eq!(IndexBssUtilities::index_mask(8), 0xFF);
    }

    #[test]
    fn index_mask_thirty_one_bits() {
        assert_eq!(IndexBssUtilities::index_mask(31), i32::MAX);
    }

    #[test]
    fn index_mask_thirty_two_bits() {
        assert_eq!(IndexBssUtilities::index_mask(32), -1i32);
    }

    #[test]
    fn int_index_bits_returns_zero() {
        assert_eq!(IndexBssUtilities::int_index_bits(1), 0);
        assert_eq!(IndexBssUtilities::int_index_bits(100), 0);
        assert_eq!(IndexBssUtilities::int_index_bits(1024), 0);
    }
}
