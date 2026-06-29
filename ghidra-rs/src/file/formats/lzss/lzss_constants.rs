/// Magic number for "comp" LZSS-compressed Apple kernelcache files.
pub const SIGNATURE_COMPRESSION: u32 = 0x636f6d70;
/// Byte representation of [`SIGNATURE_COMPRESSION`] (`comp`).
pub const SIGNATURE_COMPRESSION_BYTES: [u8; 4] = [b'c', b'o', b'm', b'p'];

/// Magic number for "lzss" LZSS-compressed data.
pub const SIGNATURE_LZSS: u32 = 0x6c7a7373;
/// Byte representation of [`SIGNATURE_LZSS`] (`lzss`).
pub const SIGNATURE_LZSS_BYTES: [u8; 4] = [b'l', b'z', b's', b's'];

/// Length of the padding region in the LZSS file header.
pub const PADDING_LENGTH: usize = 0x16c;

/// Total length of the LZSS file header:
/// four 4-byte integer fields plus the padding region.
pub const HEADER_LENGTH: usize = 4 + 4 + 4 + 4 + 4 + PADDING_LENGTH;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_compression_value() {
        assert_eq!(SIGNATURE_COMPRESSION, 0x636f6d70);
    }

    #[test]
    fn signature_compression_bytes_spell_comp() {
        assert_eq!(&SIGNATURE_COMPRESSION_BYTES, b"comp");
    }

    #[test]
    fn signature_compression_bytes_match_u32() {
        let from_bytes = u32::from_be_bytes(SIGNATURE_COMPRESSION_BYTES);
        assert_eq!(from_bytes, SIGNATURE_COMPRESSION);
    }

    #[test]
    fn signature_lzss_value() {
        assert_eq!(SIGNATURE_LZSS, 0x6c7a7373);
    }

    #[test]
    fn signature_lzss_bytes_spell_lzss() {
        assert_eq!(&SIGNATURE_LZSS_BYTES, b"lzss");
    }

    #[test]
    fn signature_lzss_bytes_match_u32() {
        let from_bytes = u32::from_be_bytes(SIGNATURE_LZSS_BYTES);
        assert_eq!(from_bytes, SIGNATURE_LZSS);
    }

    #[test]
    fn padding_length_value() {
        assert_eq!(PADDING_LENGTH, 0x16c);
        assert_eq!(PADDING_LENGTH, 364);
    }

    #[test]
    fn header_length_value() {
        assert_eq!(HEADER_LENGTH, 20 + PADDING_LENGTH);
        assert_eq!(HEADER_LENGTH, 384);
    }
}
