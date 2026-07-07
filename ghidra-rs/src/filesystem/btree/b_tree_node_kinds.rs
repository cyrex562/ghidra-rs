/// Node kind constants for `BTNodeDescriptor` in the HFS B-tree format.
///
/// See: <https://opensource.apple.com/source/xnu/xnu-792/bsd/hfs/hfs_format.h.auto.html>
/// See: <https://developer.apple.com/library/archive/technotes/tn/tn1150.html>
pub struct BTreeNodeKinds;

impl BTreeNodeKinds {
    /// Leaf node: holds actual key/data records.
    pub const K_BT_LEAF_NODE: i8 = -1;
    /// Index node: holds keys and child node pointers.
    pub const K_BT_INDEX_NODE: i8 = 0;
    /// Header node: first node of every B-tree; holds the header record.
    pub const K_BT_HEADER_NODE: i8 = 1;
    /// Map node: extends the node-usage bitmap beyond the header node.
    pub const K_BT_MAP_NODE: i8 = 2;
}

#[cfg(test)]
mod tests {
    use super::BTreeNodeKinds;

    #[test]
    fn constant_values_match_hfs_spec() {
        assert_eq!(BTreeNodeKinds::K_BT_LEAF_NODE, -1_i8);
        assert_eq!(BTreeNodeKinds::K_BT_INDEX_NODE, 0_i8);
        assert_eq!(BTreeNodeKinds::K_BT_HEADER_NODE, 1_i8);
        assert_eq!(BTreeNodeKinds::K_BT_MAP_NODE, 2_i8);
    }

    #[test]
    fn constants_are_distinct() {
        let kinds = [
            BTreeNodeKinds::K_BT_LEAF_NODE,
            BTreeNodeKinds::K_BT_INDEX_NODE,
            BTreeNodeKinds::K_BT_HEADER_NODE,
            BTreeNodeKinds::K_BT_MAP_NODE,
        ];
        for (i, &a) in kinds.iter().enumerate() {
            for &b in kinds[..i].iter() {
                assert_ne!(a, b, "node kind values must be unique");
            }
        }
    }
}
