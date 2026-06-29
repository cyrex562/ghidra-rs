/// Bitmask constants for `BTHeaderRec` attributes in the HFS B-tree format.
///
/// Mirrors `ghidra.file.formats.ios.btree.BTHeaderRecordAttributes`.
///
/// See <https://opensource.apple.com/source/xnu/xnu-792/bsd/hfs/hfs_format.h.auto.html>

/// Tree was not properly closed; on-disk state may be inconsistent.
pub const BT_BAD_CLOSE_MASK: u32 = 0x00000001;

/// Keys in this tree are stored in big-endian byte order.
pub const BT_BIG_KEYS_MASK: u32 = 0x00000002;

/// Index nodes use variable-length keys.
pub const BT_VARIABLE_INDEX_KEYS_MASK: u32 = 0x00000004;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_are_distinct_single_bits() {
        assert_eq!(BT_BAD_CLOSE_MASK.count_ones(), 1);
        assert_eq!(BT_BIG_KEYS_MASK.count_ones(), 1);
        assert_eq!(BT_VARIABLE_INDEX_KEYS_MASK.count_ones(), 1);
    }

    #[test]
    fn masks_do_not_overlap() {
        assert_eq!(BT_BAD_CLOSE_MASK & BT_BIG_KEYS_MASK, 0);
        assert_eq!(BT_BAD_CLOSE_MASK & BT_VARIABLE_INDEX_KEYS_MASK, 0);
        assert_eq!(BT_BIG_KEYS_MASK & BT_VARIABLE_INDEX_KEYS_MASK, 0);
    }

    #[test]
    fn mask_values_match_java_source() {
        assert_eq!(BT_BAD_CLOSE_MASK, 0x00000001);
        assert_eq!(BT_BIG_KEYS_MASK, 0x00000002);
        assert_eq!(BT_VARIABLE_INDEX_KEYS_MASK, 0x00000004);
    }
}
