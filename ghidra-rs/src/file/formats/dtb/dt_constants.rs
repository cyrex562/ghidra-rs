/// Device Tree (DT) constants.
///
/// Mirrors `ghidra.file.formats.dtb.DtConstants`.

/// Device Tree (DT) magic value.
pub const DT_TABLE_MAGIC: u32 = 0xd7b7ab1e;

/// Device Tree (DT) magic value as a byte array.
pub const DT_TABLE_MAGIC_BYTES: [u8; 4] = [0xd7, 0xb7, 0xab, 0x1e];

/// Size in bytes of the Device Tree (DT) magic value.
pub const DT_TABLE_MAGIC_SIZE: u32 = 4;

/// Default page size for Device Tree (DT) tables.
pub const DT_TABLE_DEFAULT_PAGE_SIZE: u32 = 2048;

/// Default version for Device Tree (DT) tables.
pub const DT_TABLE_DEFAULT_VERSION: u32 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_value() {
        assert_eq!(DT_TABLE_MAGIC, 0xd7b7ab1e);
    }

    #[test]
    fn magic_bytes_match_magic_value() {
        let expected = DT_TABLE_MAGIC.to_be_bytes();
        assert_eq!(DT_TABLE_MAGIC_BYTES, expected);
    }

    #[test]
    fn magic_size_matches_bytes_len() {
        assert_eq!(DT_TABLE_MAGIC_SIZE as usize, DT_TABLE_MAGIC_BYTES.len());
    }

    #[test]
    fn default_page_size() {
        assert_eq!(DT_TABLE_DEFAULT_PAGE_SIZE, 2048);
    }

    #[test]
    fn default_version() {
        assert_eq!(DT_TABLE_DEFAULT_VERSION, 0);
    }
}
