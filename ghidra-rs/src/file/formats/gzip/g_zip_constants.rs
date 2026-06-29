/// GZip format constants.
///
/// Mirrors `ghidra.file.formats.gzip.GZipConstants`.

/// Number of bytes in the GZip magic signature.
pub const MAGIC_BYTES_COUNT: u32 = 2;

/// GZip magic signature bytes (`0x1f 0x8b`).
pub const MAGIC_BYTES: [u8; 2] = [0x1f, 0x8b];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_bytes_count_matches_array_length() {
        assert_eq!(MAGIC_BYTES_COUNT as usize, MAGIC_BYTES.len());
    }

    #[test]
    fn magic_bytes_values() {
        assert_eq!(MAGIC_BYTES[0], 0x1f);
        assert_eq!(MAGIC_BYTES[1], 0x8b);
    }
}
