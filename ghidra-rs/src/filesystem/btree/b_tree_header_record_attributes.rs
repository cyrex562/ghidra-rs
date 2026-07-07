/// Bitmask constants for `BTHeaderRec` attributes in the HFS B-tree format.
///
/// See: <https://opensource.apple.com/source/xnu/xnu-792/bsd/hfs/hfs_format.h.auto.html>
pub struct BTreeHeaderRecordAttributes;

impl BTreeHeaderRecordAttributes {
    /// The B-tree was not closed properly.
    pub const K_BT_BAD_CLOSE_MASK: u32 = 0x00000001;
    /// The B-tree uses big (extended) keys.
    pub const K_BT_BIG_KEYS_MASK: u32 = 0x00000002;
    /// The B-tree uses variable-length index keys.
    pub const K_BT_VARIABLE_INDEX_KEYS_MASK: u32 = 0x00000004;
}

#[cfg(test)]
mod tests {
    use super::BTreeHeaderRecordAttributes;

    #[test]
    fn constant_values_match_hfs_spec() {
        assert_eq!(BTreeHeaderRecordAttributes::K_BT_BAD_CLOSE_MASK, 0x00000001);
        assert_eq!(BTreeHeaderRecordAttributes::K_BT_BIG_KEYS_MASK, 0x00000002);
        assert_eq!(BTreeHeaderRecordAttributes::K_BT_VARIABLE_INDEX_KEYS_MASK, 0x00000004);
    }

    #[test]
    fn constants_are_distinct_single_bit_masks() {
        let masks = [
            BTreeHeaderRecordAttributes::K_BT_BAD_CLOSE_MASK,
            BTreeHeaderRecordAttributes::K_BT_BIG_KEYS_MASK,
            BTreeHeaderRecordAttributes::K_BT_VARIABLE_INDEX_KEYS_MASK,
        ];
        for (i, &a) in masks.iter().enumerate() {
            assert_eq!(a.count_ones(), 1, "mask at index {i} should be a single-bit value");
            for &b in masks[..i].iter() {
                assert_eq!(a & b, 0, "masks should not overlap");
            }
        }
    }

    #[test]
    fn masks_can_be_combined_and_tested() {
        let combined = BTreeHeaderRecordAttributes::K_BT_BAD_CLOSE_MASK
            | BTreeHeaderRecordAttributes::K_BT_BIG_KEYS_MASK;
        assert_ne!(combined & BTreeHeaderRecordAttributes::K_BT_BAD_CLOSE_MASK, 0);
        assert_ne!(combined & BTreeHeaderRecordAttributes::K_BT_BIG_KEYS_MASK, 0);
        assert_eq!(combined & BTreeHeaderRecordAttributes::K_BT_VARIABLE_INDEX_KEYS_MASK, 0);
    }
}
