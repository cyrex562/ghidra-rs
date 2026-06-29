/// Magic number identifying a sparse image file header.
pub const SPARSE_HEADER_MAGIC: u32 = 0xED26FF3A;

/// Chunk type: raw data — the chunk body contains literal output blocks.
pub const CHUNK_TYPE_RAW: u16 = 0xCAC1;
/// Chunk type: fill — the chunk body contains a 4-byte pattern to repeat.
pub const CHUNK_TYPE_FILL: u16 = 0xCAC2;
/// Chunk type: don't-care — the output blocks are left uninitialized (skipped).
pub const CHUNK_TYPE_DONT_CARE: u16 = 0xCAC3;
/// Chunk type: CRC32 — the chunk body contains a CRC32 checksum of all prior output.
pub const CHUNK_TYPE_CRC32: u16 = 0xCAC4;

/// Major version number of the sparse image format supported by this implementation.
pub const MAJOR_VERSION_NUMBER: u16 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_header_magic_value() {
        assert_eq!(SPARSE_HEADER_MAGIC, 0xED26FF3A);
    }

    #[test]
    fn chunk_type_raw_value() {
        assert_eq!(CHUNK_TYPE_RAW, 0xCAC1);
    }

    #[test]
    fn chunk_type_fill_value() {
        assert_eq!(CHUNK_TYPE_FILL, 0xCAC2);
    }

    #[test]
    fn chunk_type_dont_care_value() {
        assert_eq!(CHUNK_TYPE_DONT_CARE, 0xCAC3);
    }

    #[test]
    fn chunk_type_crc32_value() {
        assert_eq!(CHUNK_TYPE_CRC32, 0xCAC4);
    }

    #[test]
    fn chunk_types_are_sequential() {
        assert_eq!(CHUNK_TYPE_FILL, CHUNK_TYPE_RAW + 1);
        assert_eq!(CHUNK_TYPE_DONT_CARE, CHUNK_TYPE_RAW + 2);
        assert_eq!(CHUNK_TYPE_CRC32, CHUNK_TYPE_RAW + 3);
    }

    #[test]
    fn major_version_number_value() {
        assert_eq!(MAJOR_VERSION_NUMBER, 1);
    }
}
