/// Constants for Apple iBootIm image files.
///
/// Mirrors `ghidra.file.formats.ios.ibootim.iBootImConstants`.

/// ASCII signature string (without null terminator).
pub const SIGNATURE: &str = "iBootIm";

/// Signature bytes including null terminator.
pub const SIGNATURE_BYTES: [u8; 8] = *b"iBootIm\0";

/// Length of the signature field in bytes.
pub const SIGNATURE_LENGTH: usize = 0x8;

/// Length of the header padding in bytes.
pub const PADDING_LENGTH: usize = 0x28;

/// Compression type: LZSS big-endian.
pub const COMPRESSION_LZSS_BE: u32 = 0x6c7a7373;

/// Compression type: LZSS little-endian.
pub const COMPRESSION_LZSS_LE: u32 = 0x73737a6c;

/// Pixel format: ARGB.
pub const FORMAT_ARGB: u32 = 0x61726762;

/// Pixel format: greyscale.
pub const FORMAT_GREY: u32 = 0x67726579;

/// Total length of the iBootIm header in bytes.
///
/// Layout: signature (8) + compression (4) + width (4) + height (4) +
///         format_lo (2) + format_hi (2) + padding (40).
pub const HEADER_LENGTH: usize = SIGNATURE_LENGTH + 4 + 4 + 4 + 2 + 2 + PADDING_LENGTH;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_bytes_match_string() {
        assert_eq!(&SIGNATURE_BYTES[..7], SIGNATURE.as_bytes());
        assert_eq!(SIGNATURE_BYTES[7], 0);
    }

    #[test]
    fn signature_length_matches_bytes_len() {
        assert_eq!(SIGNATURE_LENGTH, SIGNATURE_BYTES.len());
    }

    #[test]
    fn header_length_is_correct() {
        assert_eq!(HEADER_LENGTH, 64);
    }

    #[test]
    fn compression_constants_are_distinct() {
        assert_ne!(COMPRESSION_LZSS_BE, COMPRESSION_LZSS_LE);
    }

    #[test]
    fn format_constants_are_distinct() {
        assert_ne!(FORMAT_ARGB, FORMAT_GREY);
    }

    #[test]
    fn values_match_java_source() {
        assert_eq!(PADDING_LENGTH, 0x28);
        assert_eq!(COMPRESSION_LZSS_BE, 0x6c7a7373);
        assert_eq!(COMPRESSION_LZSS_LE, 0x73737a6c);
        assert_eq!(FORMAT_ARGB, 0x61726762);
        assert_eq!(FORMAT_GREY, 0x67726579);
    }
}
