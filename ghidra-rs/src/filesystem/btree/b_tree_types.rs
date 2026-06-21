/// B-tree type identifier constants for HFS B-tree structures.
pub struct BTreeTypes;

impl BTreeTypes {
    /// Control file B-tree type.
    pub const K_HFS_BTREE_TYPE: u8 = 0;
    /// User B-tree types start from this value.
    pub const K_USER_BTREE_TYPE: u8 = 128;
    /// Reserved B-tree type.
    pub const K_RESERVED_BTREE_TYPE: u8 = 255;
}

#[cfg(test)]
mod tests {
    use super::BTreeTypes;

    #[test]
    fn constant_values_match_java_source() {
        assert_eq!(BTreeTypes::K_HFS_BTREE_TYPE, 0_u8);
        assert_eq!(BTreeTypes::K_USER_BTREE_TYPE, 128_u8);
        assert_eq!(BTreeTypes::K_RESERVED_BTREE_TYPE, 255_u8);
    }

    #[test]
    fn constants_are_distinct() {
        let types = [
            BTreeTypes::K_HFS_BTREE_TYPE,
            BTreeTypes::K_USER_BTREE_TYPE,
            BTreeTypes::K_RESERVED_BTREE_TYPE,
        ];
        for (i, &a) in types.iter().enumerate() {
            for &b in types[..i].iter() {
                assert_ne!(a, b, "btree type values must be unique");
            }
        }
    }

    #[test]
    fn user_type_boundary_above_hfs() {
        assert!(BTreeTypes::K_USER_BTREE_TYPE > BTreeTypes::K_HFS_BTREE_TYPE);
    }
}
