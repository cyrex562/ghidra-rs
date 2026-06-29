/// Node-kind constants for `BTNodeDescriptor` in the HFS B-tree format.
///
/// Mirrors `ghidra.file.formats.ios.btree.BTreeNodeKinds`.
///
/// See <https://opensource.apple.com/source/xnu/xnu-792/bsd/hfs/hfs_format.h.auto.html>
/// and <https://developer.apple.com/library/archive/technotes/tn/tn1150.html>

/// Leaf node — holds actual key/data records.
pub const BT_LEAF_NODE: i8 = -1;

/// Index node — holds child pointers for tree traversal.
pub const BT_INDEX_NODE: i8 = 0;

/// Header node — holds the B-tree header record (always node 0).
pub const BT_HEADER_NODE: i8 = 1;

/// Map node — holds overflow allocation map records.
pub const BT_MAP_NODE: i8 = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_java_source() {
        assert_eq!(BT_LEAF_NODE, -1i8);
        assert_eq!(BT_INDEX_NODE, 0i8);
        assert_eq!(BT_HEADER_NODE, 1i8);
        assert_eq!(BT_MAP_NODE, 2i8);
    }

    #[test]
    fn all_values_are_distinct() {
        let kinds = [BT_LEAF_NODE, BT_INDEX_NODE, BT_HEADER_NODE, BT_MAP_NODE];
        for i in 0..kinds.len() {
            for j in (i + 1)..kinds.len() {
                assert_ne!(kinds[i], kinds[j]);
            }
        }
    }
}
