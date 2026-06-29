/// Flattened Device Tree (FDT) constants.
///
/// Mirrors `ghidra.file.formats.dtb.FdtConstants`.

/// FDT magic value.
pub const FDT_MAGIC: u32 = 0xd00dfeed;

/// FDT magic value as a byte array.
pub const FDT_MAGIC_BYTES: [u8; 4] = [0xd0, 0x0d, 0xfe, 0xed];

/// Size in bytes of the FDT magic value.
pub const FDT_MAGIC_SIZE: u32 = 4;

/// Size in bytes of an FDT tag.
pub const FDT_TAGSIZE: u32 = 4;

/// FDT begin-node tag value.
pub const FDT_BEGIN_NODE: u32 = 0x1;

/// FDT end-node tag value.
pub const FDT_END_NODE: u32 = 0x2;

/// FDT property tag value.
pub const FDT_PROP: u32 = 0x3;

/// FDT NOP tag value.
pub const FDT_NOP: u32 = 0x4;

/// FDT end tag value.
pub const FDT_END: u32 = 0x9;

/// Size of an FDT header at version 1.
pub const FDT_V1_SIZE: u32 = 7 * 4;

/// Size of an FDT header at version 2.
pub const FDT_V2_SIZE: u32 = FDT_V1_SIZE + 4;

/// Size of an FDT header at version 3.
pub const FDT_V3_SIZE: u32 = FDT_V2_SIZE + 4;

/// Size of an FDT header at version 16 (same as version 3).
pub const FDT_V16_SIZE: u32 = FDT_V3_SIZE;

/// Size of an FDT header at version 17.
pub const FDT_V17_SIZE: u32 = FDT_V16_SIZE + 4;

/// FDT header version 1.
pub const FDT_VERSION_1: u32 = 1;

/// FDT header version 2.
pub const FDT_VERSION_2: u32 = 2;

/// FDT header version 3.
pub const FDT_VERSION_3: u32 = 3;

/// FDT header version 16.
pub const FDT_VERSION_16: u32 = 16;

/// FDT header version 17.
pub const FDT_VERSION_17: u32 = 17;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_value() {
        assert_eq!(FDT_MAGIC, 0xd00dfeed);
    }

    #[test]
    fn magic_bytes_match_magic_value() {
        let expected = FDT_MAGIC.to_be_bytes();
        assert_eq!(FDT_MAGIC_BYTES, expected);
    }

    #[test]
    fn magic_size_matches_bytes_len() {
        assert_eq!(FDT_MAGIC_SIZE as usize, FDT_MAGIC_BYTES.len());
    }

    #[test]
    fn tag_values() {
        assert_eq!(FDT_BEGIN_NODE, 0x1);
        assert_eq!(FDT_END_NODE, 0x2);
        assert_eq!(FDT_PROP, 0x3);
        assert_eq!(FDT_NOP, 0x4);
        assert_eq!(FDT_END, 0x9);
    }

    #[test]
    fn header_sizes_are_cumulative() {
        assert_eq!(FDT_V1_SIZE, 28);
        assert_eq!(FDT_V2_SIZE, FDT_V1_SIZE + 4);
        assert_eq!(FDT_V3_SIZE, FDT_V2_SIZE + 4);
        assert_eq!(FDT_V16_SIZE, FDT_V3_SIZE);
        assert_eq!(FDT_V17_SIZE, FDT_V16_SIZE + 4);
    }

    #[test]
    fn version_numbers() {
        assert_eq!(FDT_VERSION_1, 1);
        assert_eq!(FDT_VERSION_2, 2);
        assert_eq!(FDT_VERSION_3, 3);
        assert_eq!(FDT_VERSION_16, 16);
        assert_eq!(FDT_VERSION_17, 17);
    }
}
